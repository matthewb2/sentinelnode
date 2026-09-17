/**
 * CVE 동기화 서비스 — cvelistV5(GitHub) 기반 구조화 Ingestion.
 *
 * 소스 구조:
 *   ① 로컬 클론 디렉토리 … cves/<년도>/<배치>/CVE-*.json 재귀 탐색 (git clone/pull은 사용자가 수행)
 *   ② Releases 델타/베이스라인 ZIP … 다운로드 후 압축 내 JSON 파싱
 *   ③ 단건 조회 … raw.githubusercontent.com 경유 CVE-ID.json fetch
 *
 * 전체(수십만 건)를 무조건 적재하지 않고, 스캔 엔진과 직결되는
 * watchlist(시드 패키지 + 스캔된 의존성) 기준으로 필터링하여 반영한다.
 * 진행 상태·마지막 동기화 정보는 graph-db.json 옆 meta.json에 보관한다.
 */
import * as fs from 'fs';
import * as path from 'path';
import axios from 'axios';
import AdmZip from 'adm-zip';
import { parseCveV5Record, parseCveV5Text, looksLikeNpmName } from './cveV5';
import { ingestFeed } from './ingestion';
import type { GraphStore } from './graphStore';
import type { FeedVulnerabilityItem } from './types';

export const CVE_REPO = 'CVEProject/cvelistV5';
export const CVE_RAW_BASE = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves';

export interface SyncMeta {
  lastCheckAt: string | null;
  lastSyncAt: string | null;
  lastReleaseTag: string | null;
  updateAvailable: boolean;
  latestTag: string | null;
  autoSync: boolean;
  ingestedTotal: number;
  lastSource: string | null;
}

export interface SyncStatus extends SyncMeta {
  watchlistSize: number;
}

export interface SyncOptions {
  /** 최대 적재 레코드 수 (과적재 방지, 기본 5000) */
  maxRecords?: number;
  /** 지정 시 이 패키지(소문자)만 적재. 미지정 시 watchlist 기준 */
  packageFilter?: string[];
  /** true면 npm명 형태가 아닌 제품도 적재 */
  includeNonNpm?: boolean;
}

export interface SyncResult {
  scanned: number;
  ingested: number;
  skipped: number;
  source: string;
}

const DEFAULT_META: SyncMeta = {
  lastCheckAt: null,
  lastSyncAt: null,
  lastReleaseTag: null,
  updateAvailable: false,
  latestTag: null,
  autoSync: true,
  ingestedTotal: 0,
  lastSource: null,
};

export function metaPathFor(storagePath: string): string {
  return path.join(path.dirname(storagePath), 'cve-sync-meta.json');
}

export function loadMeta(storagePath: string): SyncMeta {
  try {
    const p = metaPathFor(storagePath);
    if (!fs.existsSync(p)) return { ...DEFAULT_META };
    return { ...DEFAULT_META, ...JSON.parse(fs.readFileSync(p, 'utf-8')) };
  } catch {
    return { ...DEFAULT_META };
  }
}

export function saveMeta(storagePath: string, meta: SyncMeta): void {
  fs.mkdirSync(path.dirname(storagePath), { recursive: true });
  fs.writeFileSync(metaPathFor(storagePath), JSON.stringify(meta, null, 2), 'utf-8');
}

/** 엔진과 직결되는 관심 패키지: 시드 취약점 패키지 + 스캔된 의존성 */
export function buildWatchlist(store: GraphStore): Set<string> {
  const set = new Set<string>();
  for (const v of store.allVulnerabilities()) {
    if (v.affectedPackage) set.add(v.affectedPackage.toLowerCase());
  }
  for (const rel of store.traverseAll('DEPENDS_ON')) {
    const pkg = store.get(rel.to);
    if (pkg && pkg.kind === 'package') set.add(pkg.name.toLowerCase());
  }
  return set;
}

function acceptItem(
  item: FeedVulnerabilityItem,
  watch: Set<string> | null,
  includeNonNpm: boolean,
): boolean {
  if (!item.affectedPackage) return false;
  const name = item.affectedPackage.toLowerCase();
  if (watch) return watch.has(name);
  if (!includeNonNpm && !looksLikeNpmName(name)) return false;
  return true;
}

function ingestBatch(
  store: GraphStore,
  batch: FeedVulnerabilityItem[],
  opts: SyncOptions,
): { ingested: number; skipped: number } {
  const max = opts.maxRecords ?? 5000;
  const filter = opts.packageFilter?.map((p) => p.toLowerCase());
  // 명시 필터 > watchlist(비어 있으면 전체 npm 범위) 순으로 적용
  const watch: Set<string> | null = filter ? new Set(filter) : buildWatchlist(store);
  const includeNonNpm = opts.includeNonNpm ?? watch.size === 0;
  const accepted: FeedVulnerabilityItem[] = [];
  let skipped = 0;
  for (const item of batch) {
    if (accepted.length >= max) {
      skipped += 1;
      continue;
    }
    if (acceptItem(item, watch.size > 0 ? watch : null, includeNonNpm)) {
      accepted.push(item);
    } else {
      skipped += 1;
    }
  }
  const ingested = ingestFeed(store, accepted);
  return { ingested, skipped };
}

// ── ① 로컬 클론 디렉토리 가져오기 (cves/년도/배치/CVE-*.json, 재귀 탐색) ──
export function importLocalDir(
  store: GraphStore,
  cvesDir: string,
  opts: SyncOptions = {},
): SyncResult {
  const batch: FeedVulnerabilityItem[] = [];
  let scanned = 0;
  const max = (opts.maxRecords ?? 5000) * 4; // 필터 전 스캔 상한
  let overLimit = false;

  function walk(dir: string): void {
    if (overLimit || !fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (overLimit) return;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile() && /^CVE-.*\.json$/i.test(entry.name)) {
        scanned += 1;
        if (scanned > max) {
          overLimit = true;
          return;
        }
        try {
          batch.push(...parseCveV5Text(fs.readFileSync(full, 'utf-8')));
        } catch {
          // 손상 파일 스킵
        }
      }
    }
  }

  walk(cvesDir);
  const { ingested, skipped } = ingestBatch(store, batch, opts);
  return { scanned, ingested, skipped, source: `local:${cvesDir}` };
}

// ── ② ZIP (Releases 델타/베이스라인) 가져오기 ──
export function importZip(
  store: GraphStore,
  zipPath: string,
  opts: SyncOptions = {},
): SyncResult {
  const zip = new AdmZip(zipPath);
  const batch: FeedVulnerabilityItem[] = [];
  let scanned = 0;
  const max = (opts.maxRecords ?? 5000) * 4;

  for (const entry of zip.getEntries()) {
    if (entry.isDirectory || !/\.json$/i.test(entry.entryName)) continue;
    // cves/ 경로가 아닌 메타 파일(README 등) 제외
    if (!/(^|\/)cves\//i.test(entry.entryName) && !/^CVE-.*\.json$/i.test(path.basename(entry.entryName))) {
      continue;
    }
    scanned += 1;
    if (scanned > max) break;
    try {
      batch.push(...parseCveV5Text(zip.readAsText(entry)));
    } catch {
      // 손상 엔트리 스킵
    }
  }
  const { ingested, skipped } = ingestBatch(store, batch, opts);
  return { scanned, ingested, skipped, source: `zip:${path.basename(zipPath)}` };
}

// ── ③ 단건 조회 ──
// cvelistV5 실제 배치 구조(cves/년도/Nxxx/CVE-ID.json) 우선,
// 실패 시 MITRE CVE API로 폴백
export function cveBatchDir(cveId: string): string {
  const seq = parseInt(cveId.split('-')[2] ?? '0', 10);
  return `${Math.floor(seq / 1000)}xxx`;
}

export async function fetchCveById(store: GraphStore, cveId: string): Promise<SyncResult> {
  const id = cveId.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d+$/.test(id)) throw new Error(`CVE ID 형식이 아닙니다: ${cveId}`);
  const year = id.split('-')[1];
  const tried: string[] = [];
  let recordText: string | null = null;

  const rawUrl = `${CVE_RAW_BASE}/${year}/${cveBatchDir(id)}/${id}.json`;
  tried.push(rawUrl);
  try {
    const res = await axios.get(rawUrl, { timeout: 15000, responseType: 'text' });
    recordText = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
  } catch {
    // MITRE 폴백으로 계속
  }

  if (recordText === null) {
    const mitreUrl = `https://cveawg.mitre.org/api/cve/${id}`;
    tried.push(mitreUrl);
    try {
      const res = await axios.get(mitreUrl, { timeout: 15000, responseType: 'text' });
      recordText = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
    } catch (err: any) {
      const status = err?.response?.status;
      throw new Error(
        `${id} 조회 실패 (HTTP ${status ?? '연결 오류'}). 시도 경로: ${tried.join(' / ')}`,
      );
    }
  }

  const items = parseCveV5Text(recordText);
  if (items.length === 0) throw new Error(`${id} 레코드를 해석할 수 없습니다.`);
  const { ingested, skipped } = ingestBatch(store, items, { includeNonNpm: true, maxRecords: 50 });
  return { scanned: items.length, ingested, skipped, source: `cve:${id}` };
}

// ── 업데이트 검사 (가벼운 Releases 조회, 실패 허용) ──
export async function fetchLatestReleaseTag(): Promise<string | null> {
  const res = await axios.get(`https://api.github.com/repos/${CVE_REPO}/releases/latest`, {
    timeout: 10000,
    headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'SentinelNode' },
  });
  const tag = (res.data as any)?.tag_name;
  return typeof tag === 'string' ? tag : null;
}

export async function checkForUpdates(storagePath: string): Promise<{ updateAvailable: boolean; latestTag: string | null }> {
  const meta = loadMeta(storagePath);
  try {
    const latestTag = await fetchLatestReleaseTag();
    meta.lastCheckAt = new Date().toISOString();
    meta.latestTag = latestTag;
    meta.updateAvailable = !!latestTag && meta.lastReleaseTag !== latestTag;
    saveMeta(storagePath, meta);
    return { updateAvailable: meta.updateAvailable, latestTag };
  } catch {
    meta.lastCheckAt = new Date().toISOString();
    saveMeta(storagePath, meta);
    return { updateAvailable: false, latestTag: meta.latestTag };
  }
}

/** 델타 asset URL 탐색 → 다운로드 → 엔진 반영 */
export async function downloadAndApplyDelta(
  store: GraphStore,
  storagePath: string,
  opts: SyncOptions = {},
): Promise<SyncResult & { tag: string | null }> {
  const rel = await axios.get(`https://api.github.com/repos/${CVE_REPO}/releases/latest`, {
    timeout: 15000,
    headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'SentinelNode' },
  });
  const assets: Array<{ name?: string; browser_download_url?: string }> = (rel.data as any)?.assets ?? [];
  const tag = (rel.data as any)?.tag_name ?? null;
  const delta =
    assets.find((a) => /delta.*\.zip$/i.test(a.name ?? '')) ??
    assets.find((a) => /\.zip$/i.test(a.name ?? ''));
  if (!delta?.browser_download_url) throw new Error('릴리스에서 델타 압축파일을 찾지 못했습니다.');

  const tmpDir = path.join(path.dirname(storagePath), 'tmp');
  fs.mkdirSync(tmpDir, { recursive: true });
  const zipPath = path.join(tmpDir, delta.name ?? 'cve-delta.zip');
  const writer = fs.createWriteStream(zipPath);
  const resp = await axios.get(delta.browser_download_url, { timeout: 60000, responseType: 'stream' });
  await new Promise<void>((resolve, reject) => {
    (resp.data as NodeJS.ReadableStream).pipe(writer);
    writer.on('finish', () => resolve());
    writer.on('error', reject);
  });

  const result = importZip(store, zipPath, opts);
  try {
    fs.unlinkSync(zipPath);
  } catch {
    // 임시 파일 정리 실패 무시
  }
  const meta = loadMeta(storagePath);
  meta.lastSyncAt = new Date().toISOString();
  meta.lastReleaseTag = typeof tag === 'string' ? tag : meta.lastReleaseTag;
  meta.updateAvailable = false;
  meta.ingestedTotal += result.ingested;
  meta.lastSource = result.source;
  saveMeta(storagePath, meta);
  return { ...result, tag };
}

/** 시작 시 자동 흐름: 검사 → 업데이트 있으면 델타 반영(실패해도 시작 차단 안 함) */
export async function runStartupSync(
  store: GraphStore,
  storagePath: string,
): Promise<{ checked: boolean; updated: boolean; ingested: number }> {
  const meta = loadMeta(storagePath);
  if (!meta.autoSync) return { checked: false, updated: false, ingested: 0 };
  try {
    const { updateAvailable } = await checkForUpdates(storagePath);
    if (!updateAvailable) return { checked: true, updated: false, ingested: 0 };
    const result = await downloadAndApplyDelta(store, storagePath);
    return { checked: true, updated: true, ingested: result.ingested };
  } catch {
    return { checked: true, updated: false, ingested: 0 };
  }
}
