/**
 * AI 질의용 코드 컨텍스트 — 취약점 위치 주변 소스코드 발췌.
 * 파일 전체가 아닌 스니펫만 AI에 전달한다.
 */
import * as fs from 'fs';

export interface CodeSnippet {
  code: string;
  startLine: number;
  language: string;
}

const EXT_TO_LANG: Record<string, string> = {
  '.ts': 'typescript',
  '.tsx': 'tsx',
  '.js': 'javascript',
  '.jsx': 'jsx',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.c': 'c',
  '.h': 'c',
  '.cpp': 'cpp',
  '.hpp': 'cpp',
  '.cc': 'cpp',
  '.hh': 'cpp',
  '.cxx': 'cpp',
};

export function languageOf(file: string): string {
  const ext = file.slice(file.lastIndexOf('.')).toLowerCase();
  return EXT_TO_LANG[ext] ?? 'javascript';
}

/** line(1-based) 전후 radius 줄을 발췌. package.json 등은 파일 전체(최대 60줄) */
export function readSnippet(file: string, line: number, radius = 20): CodeSnippet {
  const raw = fs.readFileSync(file, 'utf-8');
  const lines = raw.split('\n');
  const language = languageOf(file);
  if (line <= 0) {
    return { code: lines.slice(0, 60).join('\n'), startLine: 1, language };
  }
  const start = Math.max(1, line - radius);
  const end = Math.min(lines.length, line + radius);
  const numbered = lines
    .slice(start - 1, end)
    .map((text, i) => `${start + i}: ${text}`)
    .join('\n');
  return { code: numbered, startLine: start, language };
}
