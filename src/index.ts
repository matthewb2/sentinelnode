import { app, BrowserWindow, ipcMain, dialog } from 'electron';
import { exec } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import dotenv from 'dotenv';
import { runAstScan } from './engine/astScanner';
import { buildScanResult, collectSourceFiles, currentStoragePath, getDatabase, defaultStoragePath, switchDatabase } from './db';
import { WorkerPool } from './worker/workerPool';
import { ingestFeed, syncFromUrl } from './db/ingestion';
import {
  ensureUserConfig,
  loadUserConfig,
  resetDbDir,
  resolveDbDir,
  resolveDbFilePath,
  saveDbDir,
  saveLastProjectPath,
} from './userConfig';
import {
  buildWatchlist,
  checkForUpdates,
  downloadAndApplyDelta,
  fetchCveById,
  importLocalDir,
  loadMeta,
  saveMeta,
  type SyncOptions,
} from './db/cveSync';
import type { FeedVulnerabilityItem } from './db/types';
import { readSnippet } from './ai/context';
import { suggestFix, type AiFixResult } from './ai/groq';

/** .env 로드 — 개발 cwd, 앱 경로, 앱 상위 폴더 순으로 탐색 (키는 메인에만 상주) */
function loadEnv(): void {
  if (process.env.GROQ_API_KEY) return;
  const candidates = [
    path.join(process.cwd(), '.env'),
    path.join(app.getAppPath(), '.env'),
    path.join(path.dirname(app.getAppPath()), '.env'),
  ];
  for (const file of candidates) {
    try {
      if (fs.existsSync(file)) {
        dotenv.config({ path: file });
        if (process.env.GROQ_API_KEY) return;
      }
    } catch {
      // 다음 후보 시도
    }
  }
}
loadEnv();

let mainWindow: BrowserWindow | null = null;

/** assets/icon.png 탐색 — 개발(dist/../assets)·패키징(app 경로) 레이아웃 모두 대응 */
function resolveIconPath(): string | undefined {
  const candidates = [
    path.join(app.getAppPath(), 'assets', 'icon.png'),
    path.join(process.cwd(), 'assets', 'icon.png'),
    path.join(__dirname, '..', 'assets', 'icon.png'),
    path.join(process.resourcesPath ?? '', 'assets', 'icon.png'),
  ];
  for (const file of candidates) {
    try {
      if (file && fs.existsSync(file)) return file;
    } catch {
      // 다음 후보 시도
    }
  }
  return undefined;
}

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 800,
    height: 650,
    title: 'SentinelNode',
    icon: resolveIconPath(),
    backgroundColor: '#ffffff',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  // 개발 모드(ELECTRON_DEV=1)면 Vite dev 서버, 아니면 빌드된 renderer 로드
  if (process.env.ELECTRON_DEV === '1') {
    const devUrl = process.env.VITE_DEV_SERVER_URL || 'http://localhost:5173';
    mainWindow.loadURL(devUrl).catch(() => {
      mainWindow?.loadFile(path.join(__dirname, 'renderer', 'index.html'));
    });
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  } else {
    mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// 폴더 선택창 호출 — 마지막 사용 폴더를 기본 선택으로 제시, 선택 즉시 저장
ipcMain.handle('select-directory', async () => {
  const lastPath = loadUserConfig().lastProjectPath;
  const result = await dialog.showOpenDialog({
    properties: ['openDirectory'],
    ...(lastPath ? { defaultPath: lastPath } : {}),
  });
  if (result.canceled || result.filePaths.length === 0) return null;
  const picked = result.filePaths[0];
  try {
    saveLastProjectPath(picked);
  } catch {
    // 설정 저장 실패해도 선택 결과는 반환
  }
  return picked;
});

// 청크 워커 경로 (tsc 출력 dist/worker/chunkWorker.js) — 없으면 인프로세스 폴백
function resolveChunkWorkerPath(): string | null {
  const cand = path.join(__dirname, 'worker', 'chunkWorker.js');
  try {
    if (fs.existsSync(cand)) return cand;
  } catch {
    // 무시하고 폴백
  }
  return null;
}

/** 워커 풀 크기 — 1코어는 UI/메인에 양보, 2~4개로 제한 */
function resolvePoolSize(): number {
  let cores = 4;
  try {
    cores =
      typeof os.availableParallelism === 'function' ? os.availableParallelism() : (os.cpus()?.length ?? 4);
  } catch {
    cores = 4;
  }
  return Math.min(4, Math.max(2, cores - 1));
}

const SCAN_CHUNK_SIZE = 25;

// AST 스캔 실행 — 동적 작업 분산(WorkerPool): 파일 청크 큐를 병렬 워커가
// 가져가 파싱하고, 메인에서는 가벼운 집계·DB 대조만 수행한다.
let activeScan: { pool: WorkerPool; cancelled: boolean } | null = null;

ipcMain.handle('run-ast-scan', async (_, dirPath: string) => {
  if (activeScan) {
    return { success: false, error: '이미 분석이 진행 중입니다.' };
  }
  const chunkWorkerPath = resolveChunkWorkerPath();
  if (!chunkWorkerPath) {
    // 패키징 누락 등 예외 상황 폴백 (동기 블로킹 가능, 취소 불가)
    try {
      const reports = await runAstScan(dirPath);
      saveLastProjectPath(dirPath);
      return { success: true, reports };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }
  const pool = new WorkerPool(chunkWorkerPath, resolvePoolSize());
  const scan = { pool, cancelled: false };
  activeScan = scan;
  const sendProgress = (info: { phase: string; scannedFiles: number; totalFiles?: number }): void => {
    try {
      mainWindow?.webContents.send('ast-scan-progress', info);
    } catch {
      // 윈도우 종료 등 무시
    }
  };
  try {
    // 1. 파일 목록 수집 (파싱 없는 빠른 탐색)
    const files = collectSourceFiles(dirPath);
    sendProgress({ phase: 'walk', scannedFiles: files.length, totalFiles: files.length });
    // 2. 청크 큐 → 워커 풀 병렬 파싱 (일이 끝난 워커가 다음 청크를 가져감)
    const { cancelled, results } = await pool.run(files, SCAN_CHUNK_SIZE, ({ completedFiles, totalFiles }) => {
      sendProgress({ phase: 'parse', scannedFiles: completedFiles, totalFiles });
    });
    if (cancelled || scan.cancelled) {
      return { success: false, cancelled: true };
    }
    // 3. 집계·DB 대조 (메인, 파싱 없음)
    const { reports } = buildScanResult(dirPath, getDatabase(), results, {
      onProgress: (p) => sendProgress({ phase: p.phase, scannedFiles: p.scannedFiles, totalFiles: p.totalFiles }),
    });
    saveLastProjectPath(dirPath);
    return { success: true, reports };
  } catch (error: any) {
    return { success: false, error: error.message };
  } finally {
    if (activeScan === scan) activeScan = null;
    await pool.dispose().catch(() => undefined);
  }
});

// 진행 중 분석 중단 — 풀 워커 전원 종료 (집계 전이므로 DB 불일치 없음)
ipcMain.handle('cancel-ast-scan', async () => {
  const scan = activeScan;
  if (!scan) {
    return { success: false, error: '진행 중인 분석이 없습니다.' };
  }
  try {
    scan.cancelled = true;
    await scan.pool.cancel();
    return { success: true, cancelled: true };
  } catch (error: any) {
    return { success: false, error: error.message || '분석 중단에 실패했습니다.' };
  }
});

// 사용자 설정 조회 (마지막 검색 폴더 — 다음 로딩 시 기본값)
ipcMain.handle('get-user-config', async () => {
  try {
    const config = loadUserConfig();
    return {
      success: true,
      config: { ...config, dbFilePath: resolveDbFilePath(config) },
    };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

// 그래프 DB 저장 위치 조회 (폴더 + 파일 경로 + 상태)
ipcMain.handle('get-db-storage', async () => {
  try {
    const config = loadUserConfig();
    const dbFilePath = resolveDbFilePath(config);
    const db = getDatabase();
    return {
      success: true,
      dbDir: path.dirname(dbFilePath),
      dbFilePath,
      storagePath: dbFilePath,
      stats: db.stats(),
    };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

// 그래프 DB 폴더 선택 다이얼로그 (설정 메뉴에서 호출) — 현재 DB 폴더를 기본 선택으로 제시
ipcMain.handle('select-db-directory', async () => {
  const result = await dialog.showOpenDialog({
    title: '그래프 DB 저장 폴더 선택',
    properties: ['openDirectory', 'createDirectory'],
    defaultPath: resolveDbDir(loadUserConfig()),
  });
  if (result.canceled) return null;
  return result.filePaths[0];
});

// 그래프 DB 저장 폴더 변경 (설정 저장 → 새 경로로 DB 전환)
ipcMain.handle('set-db-storage', async (_, dirPath: string) => {
  try {
    if (typeof dirPath !== 'string' || dirPath.trim().length === 0) {
      return { success: false, error: 'DB 폴더 경로를 입력하세요.' };
    }
    const resolved = path.resolve(dirPath.trim());
    let exists = fs.existsSync(resolved);
    if (exists && !fs.statSync(resolved).isDirectory()) {
      return { success: false, error: '해당 경로는 폴더가 아닙니다.' };
    }
    fs.mkdirSync(resolved, { recursive: true });
    const config = saveDbDir(resolved);
    const dbFilePath = resolveDbFilePath(config);
    const db = switchDatabase(dbFilePath);
    return {
      success: true,
      config,
      dbDir: resolved,
      dbFilePath,
      storagePath: dbFilePath,
      stats: db.stats(),
    };
  } catch (error: any) {
    return { success: false, error: error.message || 'DB 폴더 변경에 실패했습니다.' };
  }
});

// 그래프 DB 저장 폴더를 기본값으로 초기화
ipcMain.handle('reset-db-storage', async () => {
  try {
    const config = resetDbDir();
    const dbFilePath = resolveDbFilePath(config);
    const db = switchDatabase(dbFilePath);
    return {
      success: true,
      config,
      dbDir: path.dirname(dbFilePath),
      dbFilePath,
      storagePath: dbFilePath,
      stats: db.stats(),
    };
  } catch (error: any) {
    return { success: false, error: error.message || 'DB 폴더 초기화에 실패했습니다.' };
  }
});

// DB 상태 조회 (노드/릴레이션 통계 + 저장 경로)
ipcMain.handle('get-db-stats', async () => {
  try {
    const db = getDatabase();
    return { success: true, stats: db.stats(), storagePath: currentStoragePath() };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

// 취약점 피드 동기화 (url 또는 직접 전달한 아이템 배열을 그래프에 적재)
ipcMain.handle('sync-vuln-feed', async (_, payload: { url?: string; items?: FeedVulnerabilityItem[] }) => {
  try {
    const db = getDatabase();
    const ingested = payload?.url
      ? await syncFromUrl(db, payload.url)
      : ingestFeed(db, payload?.items ?? []);
    return { success: true, ingested, stats: db.stats() };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

// CVE 동기화 상태 조회 (검사 시각·릴리스 태그·관심 패키지 수)
ipcMain.handle('get-sync-status', async () => {
  try {
    const storagePath = defaultStoragePath();
    const db = getDatabase();
    const meta = loadMeta(storagePath);
    return {
      success: true,
      status: { ...meta, watchlistSize: buildWatchlist(db).size },
    };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

// CVE 업데이트 확인 (cvelistV5 최신 릴리스 태그 비교, 가벼운 조회)
ipcMain.handle('check-cve-updates', async () => {
  try {
    const result = await checkForUpdates(defaultStoragePath());
    return { success: true, ...result };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

// CVE 지금 업데이트 (릴리스 델타 ZIP 다운로드 → 파싱 → 엔진 반영)
ipcMain.handle('sync-cve-now', async (_, opts?: SyncOptions) => {
  try {
    const storagePath = defaultStoragePath();
    const result = await downloadAndApplyDelta(getDatabase(), storagePath, opts ?? {});
    return { success: true, ...result, stats: getDatabase().stats() };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

// 로컬 클론(cvelistV5/cves) 디렉토리에서 가져오기
ipcMain.handle('import-cve-dir', async (_, payload?: { dirPath?: string } & SyncOptions) => {
  try {
    let dirPath = payload?.dirPath;
    if (!dirPath) {
      const picked = await dialog.showOpenDialog({ properties: ['openDirectory'] });
      if (picked.canceled || picked.filePaths.length === 0) return { success: false, error: '취소됨' };
      dirPath = picked.filePaths[0];
    }
    // cves/ 하위를 직접 지정했거나 저장소 루트를 지정한 경우 모두 수용
    const fs = await import('fs');
    const cvesDir = fs.existsSync(path.join(dirPath, 'cves'))
      ? path.join(dirPath, 'cves')
      : dirPath;
    const result = importLocalDir(getDatabase(), cvesDir, payload ?? {});
    return { success: true, ...result, stats: getDatabase().stats() };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

// CVE ID 단건 가져오기 (예: CVE-2020-28500)
ipcMain.handle('fetch-cve', async (_, cveId: string) => {
  try {
    const result = await fetchCveById(getDatabase(), cveId);
    return { success: true, ...result, stats: getDatabase().stats() };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

// 자동 업데이트 토글
ipcMain.handle('set-auto-sync', async (_, enabled: boolean) => {
  try {
    const storagePath = defaultStoragePath();
    const meta = loadMeta(storagePath);
    meta.autoSync = !!enabled;
    saveMeta(storagePath, meta);
    return { success: true, autoSync: meta.autoSync };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

// AI 수정 제안 — 취약점 리포트 + 주변 코드를 Groq에 질의해 추천 코드 반환
const aiFixCache = new Map<string, { mtimeMs: number; result: AiFixResult & { snippetStartLine: number } }>();

ipcMain.handle(
  'get-ai-fix',
  async (
    _,
    payload: {
      file: string;
      line: number;
      type: string;
      message: string;
      cveId?: string;
      severity?: string;
      package?: string;
    },
  ) => {
    try {
      if (!payload?.file || !fs.existsSync(payload.file)) {
        return { success: false, error: '원본 파일을 찾을 수 없습니다.' };
      }
      const stat = fs.statSync(payload.file);
      const cacheKey = `${payload.file}:${payload.line}`;
      const cached = aiFixCache.get(cacheKey);
      if (cached && cached.mtimeMs === stat.mtimeMs) {
        return { success: true, ...cached.result, cached: true };
      }
      const snippet = readSnippet(payload.file, payload.line);
      const result = await suggestFix({
        type: payload.type,
        message: payload.message,
        file: payload.file,
        line: payload.line,
        code: snippet.code,
        language: snippet.language,
        cveId: payload.cveId,
        severity: payload.severity,
        package: payload.package,
      });
      const withLine = { ...result, snippetStartLine: snippet.startLine };
      aiFixCache.set(cacheKey, { mtimeMs: stat.mtimeMs, result: withLine });
      if (aiFixCache.size > 50) {
        const oldest = aiFixCache.keys().next();
        if (!oldest.done) aiFixCache.delete(oldest.value);
      }
      return { success: true, ...withLine, cached: false };
    } catch (error: any) {
      const status = error?.response?.status;
      if (status === 401 || status === 403) {
        return { success: false, error: 'Groq API 키가 유효하지 않습니다. .env의 GROQ_API_KEY를 확인하세요.' };
      }
      return { success: false, error: error.message || 'AI 질의에 실패했습니다.' };
    }
  },
);

// VS Code로 열기 — 해당 파일(라인)로 이동해 사용자가 직접 수정
ipcMain.handle('open-in-vscode', async (_, payload: { file?: string; line?: number }) => {
  try {
    const target = payload?.file || loadUserConfig().lastProjectPath;
    if (!target || !fs.existsSync(target)) {
      return { success: false, error: '열 대상 경로를 찾을 수 없습니다.' };
    }
    const arg = payload?.line && payload.line > 0 ? `"${target}:${payload.line}"` : `"${target}"`;
    await new Promise<void>((resolve, reject) => {
      exec(`code -g ${arg}`, { timeout: 15000 }, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    return { success: true };
  } catch (error: any) {
    if ((error as NodeJS.ErrnoException)?.code === 'ENOENT' || /not recognized|not found/i.test(error.message)) {
      return {
        success: false,
        error: 'VS Code CLI(code 명령)를 찾을 수 없습니다. VS Code에서 F1 → "Shell Command: Install \'code\' command in PATH"를 실행하세요.',
      };
    }
    return { success: false, error: error.message || 'VS Code 실행에 실패했습니다.' };
  }
});

app.whenReady().then(() => {
  // 사용자 설정 파일 보장 (~/.sentinelnode/config.json)
  ensureUserConfig();
  createWindow();

  // 시작 시 백그라운드 검사 → 업데이트 있으면 엔진에 자동 반영 (창 표시 차단 안 함)
  void (async () => {
    try {
      const storagePath = defaultStoragePath();
      const meta = loadMeta(storagePath);
      if (!meta.autoSync) return;
      const { updateAvailable } = await checkForUpdates(storagePath);
      if (!updateAvailable) return;
      const result = await downloadAndApplyDelta(getDatabase(), storagePath);
      mainWindow?.webContents.send('cve-sync-done', {
        updated: true,
        ingested: result.ingested,
        tag: result.tag,
      });
    } catch {
      // 오프라인·API 제한 등 실패는 무시 (수동 업데이트로 가능)
    }
  })();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
