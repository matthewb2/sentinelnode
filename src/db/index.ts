/**
 * DB 파사드 — 그래프 DB 싱글턴과 스캔 파이프라인 진입점.
 *
 * 스캔 파이프라인(Gemini 설계 ③):
 *   파싱(AST→Code 노드) → CONTAINS 적재 → AST 대조(MATCHED)
 *   → package.json 의존성 적재(DEPENDS_ON) → CVE 대조(MATCHED) → 리포트
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as parser from '@babel/parser';
import traverse from '@babel/traverse';
import { GraphStore, type DbStats } from './graphStore';
import { ensureSeedLoaded } from './ingestion';
import { matchAstNodes, matchDependencies } from './matcher';
import type { MatchReport } from './types';

let store: GraphStore | null = null;

export function defaultStoragePath(): string {
  return path.join(os.homedir(), '.sentinelnode', 'graph-db.json');
}

export function getDatabase(storagePath = defaultStoragePath()): GraphStore {
  if (!store) {
    store = new GraphStore(storagePath);
    ensureSeedLoaded(store);
  }
  return store;
}

/** 테스트용: 지정 경로의 독립 DB 인스턴스 반환 */
export function createDatabase(storagePath?: string): GraphStore {
  const db = new GraphStore(storagePath);
  ensureSeedLoaded(db);
  return db;
}

const SECRET_NAMES = new Set(['password', 'secret', 'privatekey', 'api_key', 'apikey', 'token']);

function calleeInfo(callee: any): { name?: string; member?: string } {
  if (!callee) return {};
  if (callee.type === 'Identifier') return { name: callee.name };
  if (callee.type === 'MemberExpression' && callee.property) {
    const member =
      callee.property.type === 'Identifier' ? callee.property.name : String(callee.property.value ?? '');
    const obj =
      callee.object?.type === 'Identifier' ? callee.object.name : undefined;
    return { name: obj ? `${obj}.${member}` : member, member };
  }
  return {};
}

export interface ScanResult {
  reports: MatchReport[];
  stats: DbStats;
}

export function scanProject(dirPath: string, db: GraphStore = getDatabase()): ScanResult {
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

  function walk(currentPath: string): void {
    const entries = fs.readdirSync(currentPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);
      if (entry.isDirectory()) {
        if (['node_modules', '.git', 'dist', 'build'].includes(entry.name)) continue;
        walk(fullPath);
      } else if (entry.isFile() && /\.(ts|tsx|js|jsx)$/.test(entry.name)) {
        const code = fs.readFileSync(fullPath, 'utf-8');
        let ast: any;
        try {
          ast = parser.parse(code, { sourceType: 'module', plugins: ['typescript', 'jsx'] });
        } catch {
          continue; // 문법 오류 파일 스킵
        }
        traverse(ast, {
          CallExpression(p: any) {
            const info = calleeInfo(p.node.callee);
            emitCode(fullPath, p.node.loc?.start.line ?? 0, 'CallExpression', info.name, info.member);
          },
          NewExpression(p: any) {
            const info = calleeInfo(p.node.callee);
            emitCode(fullPath, p.node.loc?.start.line ?? 0, 'CallExpression', info.name, info.member);
          },
          MemberExpression(p: any) {
            const prop = p.node.property;
            const member = prop?.type === 'Identifier' ? prop.name : String(prop?.value ?? '');
            if (member) {
              emitCode(fullPath, p.node.loc?.start.line ?? 0, 'MemberExpression', undefined, member);
            }
          },
          VariableDeclarator(p: any) {
            if (
              p.node.id.type === 'Identifier' &&
              SECRET_NAMES.has(p.node.id.name.toLowerCase()) &&
              p.node.init?.type === 'StringLiteral'
            ) {
              emitCode(
                fullPath,
                p.node.loc?.start.line ?? 0,
                'VariableDeclarator',
                p.node.id.name.toLowerCase(),
              );
            }
          },
        });
      }
    }
  }

  walk(dirPath);

  const codeNodes = codeNodeIds
    .map((id) => db.get(id))
    .filter((n): n is Extract<NonNullable<ReturnType<GraphStore['get']>>, { kind: 'code' }> =>
      !!n && n.kind === 'code',
    );

  const reports: MatchReport[] = [...matchAstNodes(db, codeNodes)];

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

  db.save();
  return { reports, stats: db.stats() };
}
