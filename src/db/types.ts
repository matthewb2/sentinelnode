/**
 * SentinelNode Node-based Database — Property Graph 스키마
 *
 * Gemini 아키텍처 설계 기준:
 *   [Vulnerability Node] --AFFECTS--> [Package]
 *   [Code/AST Node] --MATCHED--> [Vulnerability Node]
 *   [Project Node] --DEPENDS_ON--> [Package Node]
 *   [Project Node] --CONTAINS--> [Code/AST Node]
 */

// ── 노드 종류 ──────────────────────────────────────────────
export type NodeKind =
  | 'vulnerability' // 취약점 패턴 / CVE 노드
  | 'package' // npm 패키지(의존성) 노드
  | 'code' // 소스코드 AST 노드
  | 'project'; // 스캔 대상 프로젝트 노드

// ── 릴레이션 종류 ──────────────────────────────────────────
export type RelationType =
  | 'AFFECTS' // Vulnerability -AFFECTS-> Package (해당 패키지·버전에 영향)
  | 'DEPENDS_ON' // Project -DEPENDS_ON-> Package
  | 'CONTAINS' // Project -CONTAINS-> Code
  | 'MATCHED'; // Code -MATCHED-> Vulnerability (대조 적중)

// ── 심각도 ─────────────────────────────────────────────────
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// ── 취약점 노드 ────────────────────────────────────────────
export interface VulnerabilityNode {
  kind: 'vulnerability';
  /** 내부 고유 ID (예: VULN-001) */
  id: string;
  /** CVE ID (예: CVE-2020-28500). 로컬 패턴은 undefined */
  cveId?: string;
  /** 탐지명 (기존 리포트 type과 호환) */
  title: string;
  description: string;
  severity: Severity;
  /** 영향 받는 패키지 (AST 패턴형은 undefined) */
  affectedPackage?: string;
  /** 영향 받는 버전 범위 (semver range, 예: "<4.17.21") */
  versionRange?: string;
  /**
   * AST 서명 — 소스코드 노드와 대조하는 패턴 조건.
   * calleeName이 있으면 CallExpression 호출명 매칭,
   * memberName이 있으면 a.b 형태 멤버 호출 매칭,
   * identifierNames가 있으면 변수명 매칭에 사용.
   */
  astSignature?: {
    calleeName?: string;
    memberName?: string;
    identifierNames?: string[];
  };
  references: string[];
  updatedAt: string;
}

// ── 패키지 노드 ────────────────────────────────────────────
export interface PackageNode {
  kind: 'package';
  id: string; // `pkg:<name>` (예: pkg:lodash)
  name: string;
  version?: string;
}

// ── 코드(AST) 노드 ─────────────────────────────────────────
export interface CodeNode {
  kind: 'code';
  id: string;
  file: string;
  line: number;
  /** Babel AST 노드 타입 (CallExpression, VariableDeclarator 등) */
  astType: string;
  /** 호출/식별자 명 (eval, innerHTML 등) */
  name?: string;
  /** 멤버 접근명 (child_process.exec 등) */
  member?: string;
}

// ── 프로젝트 노드 ──────────────────────────────────────────
export interface ProjectNode {
  kind: 'project';
  id: string; // `project:<절대경로>`
  rootPath: string;
  scannedAt: string;
}

export type GraphNode = VulnerabilityNode | PackageNode | CodeNode | ProjectNode;

// ── 릴레이션 ───────────────────────────────────────────────
export interface GraphRelation {
  id: string;
  type: RelationType;
  from: string;
  to: string;
  /** MATCHED 적중 시점의 파일/라인 스냅샷 등 */
  props?: Record<string, string | number>;
}

// ── 영속화 포맷 ────────────────────────────────────────────
export interface GraphSnapshot {
  version: 1;
  nodes: GraphNode[];
  relations: GraphRelation[];
}

// ── 외부 피드 정규화 입력 (NVD / GitHub Advisory 공통 최소형) ──
export interface FeedVulnerabilityItem {
  cveId?: string;
  title: string;
  description?: string;
  severity?: Severity;
  affectedPackage?: string;
  versionRange?: string;
  references?: string[];
  astSignature?: VulnerabilityNode['astSignature'];
}

// ── 대조 결과 리포트 (기존 UI 리포트와 호환, CVE/심각도 확장) ──
export interface MatchReport {
  file: string;
  line: number;
  type: string;
  message: string;
  cveId?: string;
  severity?: Severity;
  package?: string;
}
