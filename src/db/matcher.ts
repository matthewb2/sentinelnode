/**
 * Scanner & Matching Engine — 그래프 탐색(Graph Traversal) 기반 대조.
 *
 * ① AST 대조: Code 노드의 (astType, name, member)를 순회하며
 *    Vulnerability 노드의 astSignature와 일치하면 MATCHED 릴레이션 생성.
 * ② 의존성 대조: Project -DEPENDS_ON-> Package와
 *    Vulnerability -AFFECTS-> Package를 조인 후 semver 버전 범위 검사.
 */
import * as semver from 'semver';
import type { GraphStore } from './graphStore';
import type { CodeNode, MatchReport, Severity, VulnerabilityNode } from './types';

/** 패키지당 의존성 CVE 리포트 상한 (대규모 DB 리포트 폭증 방지) */
export const MAX_DEP_REPORTS_PER_PACKAGE = 100;

/** versionRange 문자열 → 파싱된 Range 캐시 (대조 시 반복 파싱 방지) */
const rangeCache = new Map<string, semver.Range | null>();

function cachedRange(range: string): semver.Range | null {
  const hit = rangeCache.get(range);
  if (hit !== undefined) return hit;
  let parsed: semver.Range | null = null;
  try {
    parsed = new semver.Range(range);
  } catch {
    parsed = null;
  }
  rangeCache.set(range, parsed);
  // 메모리 폭증 방지 (고유 range가 수만 개일 경우 오래된 항목 정리)
  if (rangeCache.size > 5000) {
    const oldest = rangeCache.keys().next();
    if (!oldest.done) rangeCache.delete(oldest.value);
  }
  return parsed;
}

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** 적중 목록을 심각도순으로 정렬하고 상한까지 잘라 리포트로 변환 */
function drainBySeverity(
  buckets: Map<Severity, VulnerabilityNode[]>,
  take: (vuln: VulnerabilityNode) => void,
  max: number,
): void {
  let count = 0;
  for (const sev of SEVERITY_ORDER) {
    for (const vuln of buckets.get(sev) ?? []) {
      if (count >= max) return;
      take(vuln);
      count += 1;
    }
  }
}

function bucketize(buckets: Map<Severity, VulnerabilityNode[]>, vuln: VulnerabilityNode): void {
  const list = buckets.get(vuln.severity);
  if (list) list.push(vuln);
  else buckets.set(vuln.severity, [vuln]);
}

function matchAstSignature(code: CodeNode, vuln: VulnerabilityNode): boolean {
  const sig = vuln.astSignature;
  if (!sig) return false;
  if (sig.calleeName && code.astType === 'CallExpression' && code.name === sig.calleeName) {
    return true;
  }
  if (
    sig.memberName &&
    code.member === sig.memberName &&
    (code.astType === 'CallExpression' || code.astType === 'MemberExpression')
  ) {
    return true;
  }
  if (
    sig.identifierNames &&
    code.astType === 'VariableDeclarator' &&
    code.name &&
    sig.identifierNames.includes(code.name.toLowerCase())
  ) {
    return true;
  }
  return false;
}

function toReport(
  file: string,
  line: number,
  vuln: VulnerabilityNode,
  extra?: Partial<MatchReport>,
): MatchReport {
  return {
    file,
    line,
    type: vuln.title,
    message: vuln.cveId ? `${vuln.description} (${vuln.cveId})` : vuln.description,
    cveId: vuln.cveId,
    severity: vuln.severity,
    ...extra,
  };
}

/** ① AST 노드 ↔ 취약점 패턴 노드 대조 */
export function matchAstNodes(store: GraphStore, codeNodes: CodeNode[]): MatchReport[] {
  const reports: MatchReport[] = [];
  const vulns = store.allVulnerabilities().filter((v) => v.astSignature);
  for (const code of codeNodes) {
    for (const vuln of vulns) {
      if (matchAstSignature(code, vuln)) {
        store.link('MATCHED', code.id, vuln.id, { file: code.file, line: code.line });
        reports.push(toReport(code.file, code.line, vuln));
      }
    }
  }
  return reports;
}

/** ② 의존성(Project -DEPENDS_ON-> Package) ↔ 취약점(AFFECTS) 대조 */
export function matchDependencies(
  store: GraphStore,
  projectId: string,
  dependencies: Record<string, string>,
): MatchReport[] {
  const reports: MatchReport[] = [];
  for (const [name, rawVersion] of Object.entries(dependencies)) {
    const version = semver.coerce(rawVersion)?.version;
    const pkg = store.ensurePackage(name, version ?? rawVersion);
    store.link('DEPENDS_ON', projectId, pkg.id, { version: version ?? rawVersion });

    const hits = new Map<Severity, VulnerabilityNode[]>();
    for (const vuln of store.findVulnerabilitiesByPackage(name)) {
      if (!vuln.versionRange || !version) continue;
      const range = cachedRange(vuln.versionRange);
      if (!range) continue;
      let hit = false;
      try {
        hit = semver.satisfies(version, range, { includePrerelease: false });
      } catch {
        hit = false;
      }
      if (hit) bucketize(hits, vuln);
    }
    // 심각도순·패키지당 상한 적용 (대규모 DB 리포트 폭증 방지)
    drainBySeverity(hits, (vuln) => {
      store.link('MATCHED', pkg.id, vuln.id, { version: version as string });
      reports.push(
        toReport(
          'package.json',
          0,
          vuln,
          { package: `${name}@${version}`, file: 'package.json', line: 0 },
        ),
      );
    }, MAX_DEP_REPORTS_PER_PACKAGE);
  }
  return reports;
}

// ── C/C++ include → CVE 패키지 대조 (JS 의존성 대조와 동일한 방식) ──

export interface CIncludeRef {
  header: string;
  file: string;
  line: number;
}

const HEADER_TO_PACKAGE: Array<[RegExp, string]> = [
  [/^openssl\//i, 'openssl'],
  [/^curl\//i, 'curl'],
  [/^(libxml\/|libxml2\/)/i, 'libxml2'],
  [/^libssh\//i, 'libssh'],
  [/^libgit2/i, 'libgit2'],
  [/^gnutls\//i, 'gnutls'],
  [/^nss\//i, 'nss'],
  [/^libarchive\//i, 'libarchive'],
  [/^libav(codec|format|util)\//i, 'ffmpeg'],
  [/^png\.h$|^libpng.*\.h$/i, 'libpng'],
  [/^jpeglib\.h$|^jerror\.h$/i, 'libjpeg-turbo'],
  [/^sqlite3?\.h$/i, 'sqlite'],
  [/^zlib\.h$/i, 'zlib'],
  [/^expat\.h$|^libexpat\//i, 'expat'],
  [/^pcre2?\.h$/i, 'pcre'],
];

/** `#include` 헤더 → CVE 제품명(affectedPackage 소문자) 매핑 */
export function headerToPackage(header: string): string {
  const h = header.trim();
  for (const [re, pkg] of HEADER_TO_PACKAGE) {
    if (re.test(h)) return pkg;
  }
  const first = h.split('/')[0].replace(/\.(h|hpp)$/i, '');
  return (first || h).toLowerCase();
}

/**
 * C/C++ `#include` ↔ CVE 대조.
 * 설치 버전(vcpkg/conan 등)을 알면 semver로 정밀 대조하고,
 * 버전을 모르면 의심 후보로 보고한다(심각도순 상한 적용).
 */
export function matchCIncludes(
  store: GraphStore,
  projectId: string,
  includes: CIncludeRef[],
  versions: Record<string, string> = {},
  maxSuspected = 100,
): MatchReport[] {
  const reports: MatchReport[] = [];
  const byPackage = new Map<string, CIncludeRef>();
  for (const inc of includes) {
    const pkg = headerToPackage(inc.header);
    if (!byPackage.has(pkg)) byPackage.set(pkg, inc);
  }

  const suspected = new Map<Severity, Array<{ vuln: VulnerabilityNode; ref: CIncludeRef; pkg: string }>>();

  const pushSuspected = (entry: { vuln: VulnerabilityNode; ref: CIncludeRef; pkg: string }): void => {
    const list = suspected.get(entry.vuln.severity);
    if (list) list.push(entry);
    else suspected.set(entry.vuln.severity, [entry]);
  };

  for (const [pkg, ref] of byPackage) {
    const rawVersion = versions[pkg];
    const version = rawVersion ? (semver.coerce(rawVersion)?.version ?? rawVersion) : undefined;
    const pkgNode = store.ensurePackage(pkg, version ?? rawVersion);
    store.link('DEPENDS_ON', projectId, pkgNode.id, { version: version ?? rawVersion ?? 'unknown' });

    const preciseHits = new Map<Severity, VulnerabilityNode[]>();
    for (const vuln of store.findVulnerabilitiesByPackage(pkg)) {
      if (version && vuln.versionRange) {
        const range = cachedRange(vuln.versionRange);
        if (!range) continue;
        let hit = false;
        try {
          hit = semver.satisfies(version, range, { includePrerelease: false });
        } catch {
          hit = false;
        }
        if (hit) bucketize(preciseHits, vuln);
      } else {
        pushSuspected({ vuln, ref, pkg });
      }
    }
    // 정밀 적중도 패키지당 상한 적용
    drainBySeverity(preciseHits, (vuln) => {
      store.link('MATCHED', pkgNode.id, vuln.id, { version: version as string });
      reports.push(
        toReport(ref.file, ref.line, vuln, { package: `${pkg}@${version}` }),
      );
    }, MAX_DEP_REPORTS_PER_PACKAGE);
  }

  // 의심 후보는 심각도 버킷 순서대로 상한까지만 (전체 정렬 O(V log V) 회피)
  let taken = 0;
  for (const sev of SEVERITY_ORDER) {
    for (const { vuln, ref, pkg } of suspected.get(sev) ?? []) {
      if (taken >= maxSuspected) break;
      store.link('MATCHED', `pkg:${pkg}`, vuln.id, { version: 'unknown' });
      reports.push(
        toReport(ref.file, ref.line, vuln, {
          package: `${pkg}@unknown`,
          message: `${vuln.description} (설치 버전 미확인 — #include <${ref.header}> 기준 의심)`,
        }),
      );
      taken += 1;
    }
    if (taken >= maxSuspected) break;
  }
  return reports;
}
