/**
 * GraphStore — Electron 로컬용 파일 기반 Property Graph 저장소.
 *
 * 외부 Neo4j 서버 없이 JSON 스냅샷으로 영속화하며,
 * Vulnerability / Package / Code / Project 노드와
 * AFFECTS / DEPENDS_ON / CONTAINS / MATCHED 릴레이션을 관리한다.
 */
import * as fs from 'fs';
import * as path from 'path';
import type {
  CodeNode,
  GraphNode,
  GraphRelation,
  GraphSnapshot,
  PackageNode,
  ProjectNode,
  RelationType,
  VulnerabilityNode,
} from './types';

export interface DbStats {
  vulnerabilities: number;
  packages: number;
  codeNodes: number;
  projects: number;
  relations: number;
}

export class GraphStore {
  private nodes = new Map<string, GraphNode>();
  private relations = new Map<string, GraphRelation>();
  private relationCounter = 0;

  constructor(private storagePath?: string) {
    if (storagePath) this.load();
  }

  // ── 영속화 ───────────────────────────────────────────────
  load(): void {
    if (!this.storagePath || !fs.existsSync(this.storagePath)) return;
    try {
      const raw = fs.readFileSync(this.storagePath, 'utf-8');
      const snap = JSON.parse(raw) as GraphSnapshot;
      if (snap.version !== 1 || !Array.isArray(snap.nodes)) return;
      this.nodes = new Map(snap.nodes.map((n) => [n.id, n]));
      this.relations = new Map((snap.relations ?? []).map((r) => [r.id, r]));
      this.relationCounter = this.relations.size;
    } catch {
      // 손상된 스냅샷은 무시하고 빈 DB로 시작
    }
  }

  save(): void {
    if (!this.storagePath) return;
    fs.mkdirSync(path.dirname(this.storagePath), { recursive: true });
    const snap: GraphSnapshot = {
      version: 1,
      nodes: [...this.nodes.values()],
      relations: [...this.relations.values()],
    };
    fs.writeFileSync(this.storagePath, JSON.stringify(snap, null, 2), 'utf-8');
  }

  // ── 노드 CRUD ────────────────────────────────────────────
  upsert(node: GraphNode): GraphNode {
    this.nodes.set(node.id, node);
    return node;
  }

  get(id: string): GraphNode | undefined {
    return this.nodes.get(id);
  }

  getVulnerability(id: string): VulnerabilityNode | undefined {
    const n = this.nodes.get(id);
    return n && n.kind === 'vulnerability' ? (n as VulnerabilityNode) : undefined;
  }

  allVulnerabilities(): VulnerabilityNode[] {
    return [...this.nodes.values()].filter(
      (n): n is VulnerabilityNode => n.kind === 'vulnerability',
    );
  }

  /** 패키지명 기준 취약점 조회 (DEPENDS_ON 대조용) */
  findVulnerabilitiesByPackage(packageName: string): VulnerabilityNode[] {
    const name = packageName.toLowerCase();
    return this.allVulnerabilities().filter(
      (v) => v.affectedPackage?.toLowerCase() === name,
    );
  }

  clearEphemeral(): void {
    // 스캔 결과물(code/project/MATCHED·CONTAINS·DEPENDS_ON)만 제거하고
    // 취약점 지식(Vulnerability·Package·AFFECTS)은 유지
    for (const [id, node] of this.nodes) {
      if (node.kind === 'code' || node.kind === 'project') this.nodes.delete(id);
    }
    for (const [id, rel] of this.relations) {
      if (rel.type !== 'AFFECTS') this.relations.delete(id);
    }
  }

  // ── 릴레이션 ─────────────────────────────────────────────
  link(type: RelationType, from: string, to: string, props?: GraphRelation['props']): GraphRelation {
    // 중복 릴레이션 방지
    for (const rel of this.relations.values()) {
      if (rel.type === type && rel.from === from && rel.to === to) return rel;
    }
    this.relationCounter += 1;
    const rel: GraphRelation = { id: `r${this.relationCounter}`, type, from, to, props };
    this.relations.set(rel.id, rel);
    return rel;
  }

  /** Graph Traversal: 특정 노드에서 출발하는 릴레이션 탐색 */
  traverse(fromId: string, type?: RelationType): GraphRelation[] {
    return [...this.relations.values()].filter(
      (r) => r.from === fromId && (!type || r.type === type),
    );
  }

  traverseIncoming(toId: string, type?: RelationType): GraphRelation[] {
    return [...this.relations.values()].filter(
      (r) => r.to === toId && (!type || r.type === type),
    );
  }

  /** 전체 릴레이션 조회 (watchlist 구축 등 전체 그래프 스캔용) */
  traverseAll(type?: RelationType): GraphRelation[] {
    return type
      ? [...this.relations.values()].filter((r) => r.type === type)
      : [...this.relations.values()];
  }

  // ── 헬퍼 팩토리 ──────────────────────────────────────────
  ensurePackage(name: string, version?: string): PackageNode {
    const id = `pkg:${name.toLowerCase()}`;
    const existing = this.nodes.get(id) as PackageNode | undefined;
    if (existing && existing.kind === 'package') {
      if (version) existing.version = version;
      return existing;
    }
    const node: PackageNode = { kind: 'package', id, name, version };
    this.nodes.set(id, node);
    return node;
  }

  addCodeNode(node: Omit<CodeNode, 'kind'>): CodeNode {
    const full: CodeNode = { kind: 'code', ...node };
    this.nodes.set(full.id, full);
    return full;
  }

  ensureProject(rootPath: string): ProjectNode {
    const id = `project:${rootPath}`;
    const node: ProjectNode = {
      kind: 'project',
      id,
      rootPath,
      scannedAt: new Date().toISOString(),
    };
    this.nodes.set(id, node);
    return node;
  }

  stats(): DbStats {
    let vulnerabilities = 0;
    let packages = 0;
    let codeNodes = 0;
    let projects = 0;
    for (const n of this.nodes.values()) {
      if (n.kind === 'vulnerability') vulnerabilities += 1;
      else if (n.kind === 'package') packages += 1;
      else if (n.kind === 'code') codeNodes += 1;
      else if (n.kind === 'project') projects += 1;
    }
    return { vulnerabilities, packages, codeNodes, projects, relations: this.relations.size };
  }
}
