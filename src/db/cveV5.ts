/**
 * CVE JSON v5 파서 — 공식 CVEProgram/cvelistV5 레코드(cves/년도/CVE-ID.json)를
 * 그래프 DB 스키마(FeedVulnerabilityItem)로 정규화한다.
 *
 * 참조 포맷: CVE JSON 5.x (cveMetadata + containers.cna/adp)
 */
import type { FeedVulnerabilityItem, Severity } from './types';

interface CveV5Version {
  version?: string;
  status?: string;
  lessThan?: string;
  lessThanOrEqual?: string;
  versionType?: string;
}

interface CveV5Affected {
  product?: string;
  vendor?: string;
  packageName?: string;
  versions?: CveV5Version[];
}

interface CveV5Metrics {
  cvssV3_1?: { baseScore?: number; baseSeverity?: string };
  cvssV3_0?: { baseScore?: number; baseSeverity?: string };
  cvssV4_0?: { baseScore?: number };
  [key: string]: any;
}

interface CveV5Container {
  affected?: CveV5Affected[];
  descriptions?: Array<{ lang?: string; value?: string }>;
  references?: Array<{ url?: string }>;
  metrics?: CveV5Metrics[];
}

interface CveV5Record {
  cveMetadata?: { cveId?: string; state?: string; dateUpdated?: string };
  containers?: { cna?: CveV5Container; adp?: CveV5Container[] };
}

function pickDescription(cna: CveV5Container | undefined): string | undefined {
  const descs: Array<{ lang?: string; value?: string }> | undefined = cna?.descriptions;
  if (!Array.isArray(descs)) return undefined;
  return (
    descs.find((d) => d.lang === 'en' && d.value)?.value ??
    descs.find((d) => d.value)?.value
  );
}

function pickSeverity(cna: CveV5Container | undefined, adp: CveV5Container[]): Severity {
  const pools = [cna, ...(Array.isArray(adp) ? adp : [])];
  for (const c of pools) {
    for (const m of c?.metrics ?? []) {
      const cvss = m?.cvssV3_1 ?? m?.cvssV3_0;
      const sev = String(cvss?.baseSeverity ?? '').toLowerCase();
      if (['critical', 'high', 'medium', 'low'].includes(sev)) return sev as Severity;
      if (typeof cvss?.baseScore === 'number') return scoreToSeverity(cvss.baseScore);
      if (typeof m?.cvssV4_0?.baseScore === 'number') return scoreToSeverity(m.cvssV4_0.baseScore);
      // 기타 스키마(cvssV2 등)의 baseScore 폴백
      for (const v of Object.values(m ?? {})) {
        const s = (v as any)?.baseScore;
        if (typeof s === 'number') return scoreToSeverity(s);
      }
    }
  }
  return 'medium';
}

function scoreToSeverity(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

/** versions[] → semver range (semver.satisfies 호환). 범위 없음이면 undefined */
export function versionsToRange(versions?: CveV5Version[]): string | undefined {
  if (!Array.isArray(versions) || versions.length === 0) return undefined;
  const affected = versions.filter((v) => (v.status ?? 'affected') === 'affected');
  if (affected.length === 0) return undefined;

  const parts: string[] = [];
  for (const v of affected) {
    const base = (v.version ?? '').trim();
    const upper = (v.lessThan ?? v.lessThanOrEqual ?? '').trim();
    const isUnspecified = !base || base === '0' || base.toLowerCase() === 'unspecified';
    if (isUnspecified && upper && upper !== '*') {
      parts.push(`<${upper}`);
    } else if (!isUnspecified && upper && upper !== '*') {
      parts.push(`>=${base} <${upper}`);
    } else if (!isUnspecified) {
      parts.push(`=${base}`);
    }
  }
  return parts.length > 0 ? parts.join(' || ') : undefined;
}

/** npm 패키지명처럼 보이는지 판별 (watchlist 필터 보조용) */
export function looksLikeNpmName(name: string): boolean {
  return /^(@[a-z0-9~][a-z0-9._~-]*\/)?[a-z0-9~][a-z0-9._~-]*$/i.test(name.trim());
}

function normalizePackageName(raw: string): string {
  return raw.trim().toLowerCase();
}

/**
 * CVE v5 레코드 1건을 제품(affected[])별로 FeedVulnerabilityItem 배열로 분해.
 * REJECTED 상태 레코드는 빈 배열 반환.
 */
export function parseCveV5Record(record: CveV5Record): FeedVulnerabilityItem[] {
  const cveId = record?.cveMetadata?.cveId;
  if (!cveId) return [];
  if (record?.cveMetadata?.state === 'REJECTED') return [];

  const cna = record?.containers?.cna;
  const adp = record?.containers?.adp;
  const affected: CveV5Affected[] = [...(cna?.affected ?? [])];
  for (const a of adp ?? []) affected.push(...(a?.affected ?? []));
  if (affected.length === 0) return [];

  const description = pickDescription(cna) ?? cveId;
  const severity = pickSeverity(cna, adp ?? []);
  const references = (cna?.references ?? []).map((r) => r.url).filter((u): u is string => !!u);

  const items: FeedVulnerabilityItem[] = [];
  for (const entry of affected) {
    const rawName = entry.packageName ?? entry.product;
    if (!rawName) continue;
    items.push({
      cveId,
      title: `${rawName} ${cveId}`,
      description,
      severity,
      affectedPackage: normalizePackageName(rawName),
      versionRange: versionsToRange(entry.versions),
      references,
    });
  }
  return items;
}

/** JSON 문자열 1건을 안전하게 파싱 (실패 시 빈 배열) */
export function parseCveV5Text(jsonText: string): FeedVulnerabilityItem[] {
  try {
    return parseCveV5Record(JSON.parse(jsonText));
  } catch {
    return [];
  }
}
