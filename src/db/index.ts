/**
 * DB 파사드 — 그래프 DB 싱글턴과 스캔 파이프라인 진입점.
 *
 * 스캔 파이프라인(Gemini 설계 ③, C 확장):
 *   파싱(JS: Babel AST / C: tree-sitter-c AST→Code 노드) → CONTAINS 적재
 *   → AST 대조(MATCHED)
 *   → 의존성 적재(package.json / C #include·vcpkg·conan → DEPENDS_ON)
 *   → CVE 대조(MATCHED) → 리포트
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { GraphStore, type DbStats } from './graphStore';
import { ensureSeedLoaded } from './ingestion';
import { matchAstNodes, matchCIncludes, matchDependencies, type CIncludeRef } from './matcher';
import { extractSourceFile, isSupportedSource, type ExtractedFile } from '../engine/fileExtractor';
import { loadUserConfig, resolveDbFilePath } from '../userConfig';
import type { MatchReport } from './types';

let store: GraphStore | null = null;
let activeStoragePath: string | null = null;

export function defaultStoragePath(): string {
  try {
    return resolveDbFilePath(loadUserConfig());
  } catch {
    return path.join(os.homedir(), '.sentinelnode', 'graph-db.json');
  }
}

/** 현재 사용 중인 DB 파일 경로 */
export function currentStoragePath(): string {
  return activeStoragePath ?? defaultStoragePath();
}

export function getDatabase(storagePath?: string): GraphStore {
  const resolved = storagePath ?? defaultStoragePath();
  if (!store || activeStoragePath !== resolved) {
    store = new GraphStore(resolved);
    activeStoragePath = resolved;
    ensureSeedLoaded(store);
    try {
      store.save();
    } catch {
      // 저장 실패는 무시 (읽기 전용 경로 등)
    }
  }
  return store;
}

/** DB 저장 위치 변경 — 싱글턴을 버리고 새 경로에서 다시 로드 */
export function switchDatabase(storagePath: string): GraphStore {
  store = new GraphStore(storagePath);
  activeStoragePath = storagePath;
  ensureSeedLoaded(store);
  store.save();
  return store;
}

/** DB 싱글턴을 버리고 디스크 스냅샷에서 다시 로드 (워커 스캔 후 동기화용) */
export function reloadDatabase(storagePath?: string): GraphStore {
  const resolved = storagePath ?? currentStoragePath();
  store = new GraphStore(resolved);
  activeStoragePath = resolved;
  ensureSeedLoaded(store);
  return store;
}

/** 테스트용: 지정 경로의 독립 DB 인스턴스 반환 */
export function createDatabase(storagePath?: string): GraphStore {
  const db = new GraphStore(storagePath);
  ensureSeedLoaded(db);
  return db;
}

export interface ScanResult {
  reports: MatchReport[];
  stats: DbStats;
}

/** C 의존성 버전 힌트 (vcpkg.json · conanfile.txt · CMakeLists.txt) */
function readCDependencyVersions(dirPath: string): Record<string, string> {
  const versions: Record<string, string> = {};
  // vcpkg.json — dependencies / overrides
  try {
    const vcpkgPath = path.join(dirPath, 'vcpkg.json');
    if (fs.existsSync(vcpkgPath)) {
      const vcpkg = JSON.parse(fs.readFileSync(vcpkgPath, 'utf-8')) as {
        dependencies?: Array<string | { name?: string; version?: string; 'version-string'?: string }>;
        overrides?: Array<{ name?: string; version?: string; 'version-string'?: string }>;
      };
      for (const dep of vcpkg.dependencies ?? []) {
        if (typeof dep === 'string') continue;
        if (dep?.name && (dep.version ?? dep['version-string'])) {
          versions[dep.name.toLowerCase()] = String(dep.version ?? dep['version-string']);
        }
      }
      for (const dep of vcpkg.overrides ?? []) {
        if (dep?.name && (dep.version ?? dep['version-string'])) {
          versions[dep.name.toLowerCase()] = String(dep.version ?? dep['version-string']);
        }
      }
    }
  } catch {
    // 손상된 vcpkg.json은 무시
  }
  // conanfile.txt — name/version[@...] 행
  try {
    const conanPath = path.join(dirPath, 'conanfile.txt');
    if (fs.existsSync(conanPath)) {
      for (const line of fs.readFileSync(conanPath, 'utf-8').split('\n')) {
        const m = line.trim().match(/^([A-Za-z0-9_][\w+.-]*)\/([^\s@#]+)/);
        if (m) versions[m[1].toLowerCase()] = m[2];
      }
    }
  } catch {
    // 무시
  }
  // CMakeLists.txt — find_package(<Pkg> <version>)
  try {
    const cmakePath = path.join(dirPath, 'CMakeLists.txt');
    if (fs.existsSync(cmakePath)) {
      const cmakeName: Record<string, string> = {
        openssl: 'openssl',
        curl: 'curl',
        libxml2: 'libxml2',
        zlib: 'zlib',
        sqlite3: 'sqlite',
        libpng: 'libpng',
        expat: 'expat',
      };
      for (const line of fs.readFileSync(cmakePath, 'utf-8').split('\n')) {
        const m = line.match(/find_package\s*\(\s*([A-Za-z0-9_]+)\s+(\d[\d.]*)/i);
        if (m && cmakeName[m[1].toLowerCase()]) {
          versions[cmakeName[m[1].toLowerCase()]] = m[2];
        }
      }
    }
  } catch {
    // 무시
  }
  return versions;
}

export interface ScanProgress {
  phase: 'walk' | 'parse' | 'match' | 'done';
  scannedFiles: number;
  totalFiles?: number;
}

export interface ScanOptions {
  onProgress?: (info: ScanProgress) => void;
}

/** 스캔 대상 소스 파일 목록 수집 (파싱 없는 빠른 탐색) */
export function collectSourceFiles(dirPath: string): string[] {
  const files: string[] = [];
  function walk(currentPath: string): void {
    const entries = fs.readdirSync(currentPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);
      if (entry.isDirectory()) {
        if (['node_modules', '.git', 'dist', 'build'].includes(entry.name)) continue;
        walk(fullPath);
      } else if (entry.isFile() && isSupportedSource(entry.name)) {
        files.push(fullPath);
      }
    }
  }
  walk(dirPath);
  return files;
}

/**
 * 집계 단계 — 추출 결과 → Code 노드 적재(CONTAINS) → AST 대조(MATCHED)
 * → 의존성 적재·CVE 대조 → 리포트. 파싱을 포함하지 않아 가볍다.
 */
export function buildScanResult(
  dirPath: string,
  db: GraphStore,
  extracted: ExtractedFile[],
  opts?: ScanOptions,
): ScanResult {
  db.clearEphemeral();
  const project = db.ensureProject(dirPath);
  let codeCounter = 0;
  const codeNodeIds: string[] = [];

  const emitCode = (
    file: string,
    line: number,
    astType: string,
    name?: string,
    member?: string,
  ): void => {
    codeCounter += 1;
    const node = db.addCodeNode({
      id: `code:${codeCounter}:${path.basename(file)}:${line}`,
      file,
      line,
      astType,
      name,
      member,
    });
    db.link('CONTAINS', project.id, node.id);
    codeNodeIds.push(node.id);
  };

  const cIncludes: CIncludeRef[] = [];
  for (const item of extracted) {
    for (const call of item.calls) {
      emitCode(item.file, call.line, 'CallExpression', call.name, call.member);
    }
    for (const secret of item.secrets) {
      emitCode(item.file, secret.line, 'VariableDeclarator', secret.name);
    }
    for (const inc of item.includes) {
      cIncludes.push({ header: inc.header, file: item.file, line: inc.line });
    }
  }

  const codeNodes = codeNodeIds
    .map((id) => db.get(id))
    .filter((n): n is Extract<NonNullable<ReturnType<GraphStore['get']>>, { kind: 'code' }> =>
      !!n && n.kind === 'code',
    );

  const reports: MatchReport[] = [...matchAstNodes(db, codeNodes)];
  try {
    opts?.onProgress?.({ phase: 'match', scannedFiles: extracted.length, totalFiles: extracted.length });
  } catch {
    // 진행률 콜백 오류는 스캔에 영향 없음
  }

  // package.json 의존성 대조
  const pkgJsonPath = path.join(dirPath, 'package.json');
  if (fs.existsSync(pkgJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
      const deps: Record<string, string> = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
      reports.push(...matchDependencies(db, project.id, deps));
    } catch {
      // 손상된 package.json은 의존성 대조만 스킵
    }
  }

  // C/C++ 의존성(#include·vcpkg·conan) ↔ CVE 대조 — JS와 동일한 방식
  if (cIncludes.length > 0) {
    reports.push(...matchCIncludes(db, project.id, cIncludes, readCDependencyVersions(dirPath)));
  }

  db.save();
  try {
    opts?.onProgress?.({ phase: 'done', scannedFiles: extracted.length, totalFiles: extracted.length });
  } catch {
    // 무시
  }
  return { reports, stats: db.stats() };
}

/** 인프로세스 스캔 (워커 풀 사용 불가 시 폴백 — 메인 스레드 차단 가능) */
export async function scanProject(
  dirPath: string,
  db: GraphStore = getDatabase(),
  opts?: ScanOptions,
): Promise<ScanResult> {
  const files = collectSourceFiles(dirPath);
  const extracted: ExtractedFile[] = [];
  let done = 0;
  for (const file of files) {
    try {
      const item = await extractSourceFile(file);
      if (item) extracted.push(item);
    } catch {
      // 파일 단위 실패 스킵
    }
    done += 1;
    if (done % 25 === 0 || done === files.length) {
      try {
        opts?.onProgress?.({ phase: 'parse', scannedFiles: done, totalFiles: files.length });
      } catch {
        // 무시
      }
    }
  }
  return buildScanResult(dirPath, db, extracted, opts);
}
