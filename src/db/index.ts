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
import * as parser from '@babel/parser';
import traverse from '@babel/traverse';
import { GraphStore, type DbStats } from './graphStore';
import { ensureSeedLoaded } from './ingestion';
import { matchAstNodes, matchCIncludes, matchDependencies, type CIncludeRef } from './matcher';
import { isCSource, parseCSource } from '../engine/cScanner';
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

export async function scanProject(dirPath: string, db: GraphStore = getDatabase()): Promise<ScanResult> {
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

  const cFiles: string[] = [];
  const cIncludes: CIncludeRef[] = [];

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
      } else if (entry.isFile() && isCSource(entry.name)) {
        cFiles.push(fullPath);
      }
    }
  }

  walk(dirPath);

  // C/C++ 파일 — tree-sitter-c 파싱 → JS와 동일한 CodeNode 스키마로 적재
  for (const cFile of cFiles) {
    let code: string;
    try {
      code = fs.readFileSync(cFile, 'utf-8');
    } catch {
      continue;
    }
    let parsed;
    try {
      parsed = await parseCSource(code, cFile);
    } catch {
      continue;
    }
    for (const call of parsed.calls) {
      emitCode(cFile, call.line, 'CallExpression', call.name, call.member);
    }
    for (const secret of parsed.secrets) {
      emitCode(cFile, secret.line, 'VariableDeclarator', secret.name);
    }
    for (const inc of parsed.includes) {
      cIncludes.push({ header: inc.header, file: cFile, line: inc.line });
    }
  }

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

  // C/C++ 의존성(#include·vcpkg·conan) ↔ CVE 대조 — JS와 동일한 방식
  if (cIncludes.length > 0) {
    reports.push(...matchCIncludes(db, project.id, cIncludes, readCDependencyVersions(dirPath)));
  }

  db.save();
  return { reports, stats: db.stats() };
}
