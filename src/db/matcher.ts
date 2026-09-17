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
import type { CodeNode, MatchReport, VulnerabilityNode } from './types';

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

    for (const vuln of store.findVulnerabilitiesByPackage(name)) {
      if (!vuln.versionRange || !version) continue;
      let hit = false;
      try {
        hit = semver.satisfies(version, vuln.versionRange, { includePrerelease: false });
      } catch {
        hit = false;
      }
      if (hit) {
        store.link('MATCHED', pkg.id, vuln.id, { version });
        reports.push(
          toReport(
            'package.json',
            0,
            vuln,
            { package: `${name}@${version}`, file: 'package.json', line: 0 },
          ),
        );
      }
    }
  }
  return reports;
}
