/**
 * C/C++ 스캐너 — tree-sitter-c(tree-sitter-cpp) WASM 파서 기반 호출·include 추출.
 *
 * JS 파이프라인과 동일한 CodeNode 스키마(CallExpression / VariableDeclarator)를
 * 방출하므로 기존 matcher(matchAstNodes)가 그대로 대조한다.
 * WASM 로드 실패 시 정규식 폴백으로 동일 형태를 추출한다.
 */
import * as fs from 'fs';
import * as path from 'path';
import Parser from 'web-tree-sitter';

export interface CCallSite {
  name: string;
  member?: string;
  line: number;
}

export interface CInclude {
  header: string;
  line: number;
}

export interface CParseResult {
  calls: CCallSite[];
  includes: CInclude[];
  secrets: CCallSite[];
  /** true면 tree-sitter 파서 사용, false면 정규식 폴백 */
  treeSitter: boolean;
}

export const C_SOURCE_RE = /\.(c|h|cpp|hpp|cc|hh|cxx)$/i;

export function isCSource(fileName: string): boolean {
  return C_SOURCE_RE.test(fileName);
}

function langKind(fileName: string): 'c' | 'cpp' {
  return /\.(cpp|hpp|cc|hh|cxx)$/i.test(fileName) ? 'cpp' : 'c';
}

const SECRET_NORM = new Set(['password', 'secret', 'privatekey', 'apikey', 'token']);

function normIdent(name: string): string {
  return name.toLowerCase().replace(/[_-]+/g, '');
}

// ── WASM 경로 탐색 (개발 node_modules · assets 복사본 · 패키징 경로) ──
function wasmCandidates(kind: 'c' | 'cpp'): string[] {
  const file = kind === 'c' ? 'tree-sitter-c.wasm' : 'tree-sitter-cpp.wasm';
  const here = __dirname;
  return [
    path.join(process.cwd(), 'node_modules', 'tree-sitter-wasms', 'out', file),
    path.join(process.cwd(), 'assets', file),
    path.join(here, '..', '..', 'node_modules', 'tree-sitter-wasms', 'out', file),
    path.join(here, '..', '..', 'assets', file),
    path.join(here, '..', 'assets', file),
  ];
}

let initPromise: Promise<void> | null = null;
let langC: any = null;
let langCpp: any = null;

function ensureInit(): Promise<void> {
  if (!initPromise) {
    const p: Promise<void> = (Parser as any).init();
    initPromise = p;
    p.catch(() => {
      initPromise = null;
    });
    return p;
  }
  return initPromise;
}

async function loadLang(kind: 'c' | 'cpp'): Promise<any> {
  await ensureInit();
  if (kind === 'c' && langC) return langC;
  if (kind === 'cpp' && langCpp) return langCpp;
  const errs: string[] = [];
  for (const cand of wasmCandidates(kind)) {
    try {
      if (!fs.existsSync(cand)) continue;
      const lang = await (Parser as any).Language.load(cand);
      if (kind === 'c') langC = lang;
      else langCpp = lang;
      return lang;
    } catch (err: any) {
      errs.push(`${cand}: ${err?.message ?? err}`);
    }
  }
  throw new Error(`tree-sitter-${kind} wasm 로드 실패 (${errs.join(' / ') || '후보 없음'})`);
}

function nodeText(node: any): string {
  if (typeof node?.text === 'string') return node.text;
  return '';
}

function lineOf(node: any): number {
  const row = node?.startPosition?.row;
  return typeof row === 'number' ? row + 1 : 0;
}

function eachNode(root: any, visit: (n: any) => void): void {
  const stack: any[] = [root];
  while (stack.length > 0) {
    const n = stack.pop();
    if (!n) continue;
    visit(n);
    const count = typeof n.childCount === 'number' ? n.childCount : 0;
    for (let i = count - 1; i >= 0; i -= 1) {
      try {
        const c = n.child(i);
        if (c) stack.push(c);
      } catch {
        // 손상 노드 무시
      }
    }
  }
}

/** tree-sitter 트리에서 호출·include·하드코딩 시크릿 추출 */
function extractFromTree(root: any): { calls: CCallSite[]; includes: CInclude[]; secrets: CCallSite[] } {
  const calls: CCallSite[] = [];
  const includes: CInclude[] = [];
  const secrets: CCallSite[] = [];
  const secretSeen = new Set<string>();

  eachNode(root, (n) => {
    const type = n?.type as string | undefined;
    if (type === 'call_expression') {
      const fn = n.childByFieldName ? n.childByFieldName('function') : n.namedChildren?.[0];
      if (!fn) return;
      const line = lineOf(fn);
      if (fn.type === 'identifier') {
        const name = nodeText(fn);
        if (name) calls.push({ name, line });
      } else if (fn.type === 'field_expression') {
        const field = fn.childByFieldName ? fn.childByFieldName('field') : null;
        const member = field ? nodeText(field) : undefined;
        const full = nodeText(fn);
        if (full || member) calls.push({ name: full || member as string, member, line });
      } else {
        const name = nodeText(fn).split('(')[0].trim();
        if (name && /^[A-Za-z_]\w*$/.test(name)) calls.push({ name, line });
      }
    } else if (type === 'preproc_include') {
      const raw = nodeText(n);
      const m = raw.match(/#\s*include\s*[<"]([^>"]+)[>"]/);
      if (m) includes.push({ header: m[1].trim(), line: lineOf(n) });
    } else if (type === 'declaration' || type === 'assignment_expression') {
      const raw = nodeText(n);
      // 선언: char *password = "..." / assignment: password = "..."
      const idMatch =
        type === 'declaration'
          ? raw.match(/([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)?=\s*"/)
          : raw.match(/^\s*([A-Za-z_]\w*)\s*=\s*"/);
      if (idMatch && normIdent(idMatch[1]) && SECRET_NORM.has(normIdent(idMatch[1]))) {
        const key = `${lineOf(n)}:${idMatch[1].toLowerCase()}`;
        if (!secretSeen.has(key)) {
          secretSeen.add(key);
          secrets.push({ name: idMatch[1].toLowerCase(), line: lineOf(n) });
        }
      }
    }
  });

  return { calls, includes, secrets };
}

// ── 정규식 폴백 (WASM 사용 불가 시) ──
function extractFallback(code: string): { calls: CCallSite[]; includes: CInclude[]; secrets: CCallSite[] } {
  const calls: CCallSite[] = [];
  const includes: CInclude[] = [];
  const secrets: CCallSite[] = [];
  const lines = code.split('\n');
  const callRe = /([A-Za-z_]\w*(?:\s*(?:\.|->)\s*[A-Za-z_]\w*)?)\s*\(/g;
  const keywords = new Set([
    'if', 'for', 'while', 'switch', 'return', 'sizeof', 'typedef', 'struct', 'union', 'enum',
  ]);
  lines.forEach((text, idx) => {
    const line = idx + 1;
    const trimmed = text.trim();
    if (/^#\s*include\s*[<"]/.test(trimmed)) {
      const m = trimmed.match(/^#\s*include\s*[<"]([^>"]+)[>"]/);
      if (m) includes.push({ header: m[1].trim(), line });
      return;
    }
    if (trimmed.startsWith('#') || trimmed.startsWith('//')) return;
    callRe.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = callRe.exec(text)) !== null) {
      const rawName = m[1].replace(/\s+/g, '');
      const base = rawName.split(/\.|->/).pop() as string;
      if (keywords.has(base)) continue;
      const member = /(\.|->)/.test(rawName) ? base : undefined;
      calls.push({ name: rawName, member, line });
    }
    const s = text.match(/([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)?=\s*"/);
    if (s && SECRET_NORM.has(normIdent(s[1]))) {
      secrets.push({ name: s[1].toLowerCase(), line });
    }
  });
  return { calls, includes, secrets };
}

/** C/C++ 소스 파싱 — tree-sitter 우선, 실패 시 정규식 폴백 */
export async function parseCSource(code: string, fileName: string): Promise<CParseResult> {
  const kind = langKind(fileName);
  try {
    const lang = await loadLang(kind);
    const parser = new (Parser as any)();
    parser.setLanguage(lang);
    const tree = parser.parse(code);
    const { calls, includes, secrets } = extractFromTree(tree.rootNode);
    return { calls, includes, secrets, treeSitter: true };
  } catch {
    const { calls, includes, secrets } = extractFallback(code);
    return { calls, includes, secrets, treeSitter: false };
  }
}

/** 파일 경로 기준 파싱 (동기 파일 읽기 + 비동기 파싱) */
export async function parseCFile(filePath: string): Promise<CParseResult> {
  const code = fs.readFileSync(filePath, 'utf-8');
  return parseCSource(code, filePath);
}
