/**
 * 소스 파일 추출기 — JS(Babel)/C(tree-sitter-c) 파싱을 CodeNode 호환 형태로 추출.
 * 워커 풀의 청크 워커와 인프로세스 폴백이 공유하는 단일 추출 로직이다.
 */
import * as fs from 'fs';
import * as parser from '@babel/parser';
import traverse from '@babel/traverse';
import { isCSource, parseCSource } from './cScanner';

export interface ExtractedCall {
  name?: string;
  member?: string;
  line: number;
}

export interface ExtractedInclude {
  header: string;
  line: number;
}

export interface ExtractedFile {
  file: string;
  calls: ExtractedCall[];
  secrets: ExtractedCall[];
  includes: ExtractedInclude[];
}

export const JS_SOURCE_RE = /\.(ts|tsx|js|jsx)$/;

export function isSupportedSource(fileName: string): boolean {
  return JS_SOURCE_RE.test(fileName) || isCSource(fileName);
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

function extractJs(fullPath: string, code: string): ExtractedFile | null {
  let ast: any;
  try {
    ast = parser.parse(code, { sourceType: 'module', plugins: ['typescript', 'jsx'] });
  } catch {
    return null; // 문법 오류 파일 스킵
  }
  const calls: ExtractedCall[] = [];
  const secrets: ExtractedCall[] = [];
  traverse(ast, {
    CallExpression(p: any) {
      const info = calleeInfo(p.node.callee);
      calls.push({ name: info.name, member: info.member, line: p.node.loc?.start.line ?? 0 });
    },
    NewExpression(p: any) {
      const info = calleeInfo(p.node.callee);
      calls.push({ name: info.name, member: info.member, line: p.node.loc?.start.line ?? 0 });
    },
    MemberExpression(p: any) {
      const prop = p.node.property;
      const member = prop?.type === 'Identifier' ? prop.name : String(prop?.value ?? '');
      if (member) {
        calls.push({ member, line: p.node.loc?.start.line ?? 0 });
      }
    },
    VariableDeclarator(p: any) {
      if (
        p.node.id.type === 'Identifier' &&
        SECRET_NAMES.has(p.node.id.name.toLowerCase()) &&
        p.node.init?.type === 'StringLiteral'
      ) {
        secrets.push({ name: p.node.id.name.toLowerCase(), line: p.node.loc?.start.line ?? 0 });
      }
    },
  });
  return { file: fullPath, calls, secrets, includes: [] };
}

/** 단일 소스 파일 파싱 → 추출 결과 (지원 외·실패 시 null) */
export async function extractSourceFile(fullPath: string): Promise<ExtractedFile | null> {
  if (!isSupportedSource(fullPath)) return null;
  let code: string;
  try {
    code = fs.readFileSync(fullPath, 'utf-8');
  } catch {
    return null;
  }
  if (JS_SOURCE_RE.test(fullPath)) {
    return extractJs(fullPath, code);
  }
  try {
    const parsed = await parseCSource(code, fullPath);
    return { file: fullPath, calls: parsed.calls, secrets: parsed.secrets, includes: parsed.includes };
  } catch {
    return null;
  }
}
