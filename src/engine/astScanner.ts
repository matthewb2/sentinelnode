import { scanProject } from '../db';
import type { MatchReport } from '../db/types';

export interface AstVulnerabilityReport {
  file: string;
  line: number;
  type: string;
  message: string;
  cveId?: string;
  severity?: MatchReport['severity'];
  package?: string;
}

/**
 * 대상 디렉토리를 그래프 DB 파이프라인으로 스캔.
 * 파싱(AST→Code 노드) → 취약점 패턴 대조 → 의존성 CVE 대조 → 리포트.
 */
export function runAstScan(dirPath: string): AstVulnerabilityReport[] {
  return scanProject(dirPath).reports;
}
