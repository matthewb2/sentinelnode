/**
 * AI 수정 제안 — Groq API (OpenAI 호환 엔드포인트) 연동.
 *
 * .env의 GROQ_API_KEY는 메인 프로세스에서만 사용되며
 * 렌더러(UI)에는 절대 노출되지 않는다.
 */
import axios from 'axios';

export interface AiFixInput {
  type: string;
  message: string;
  file: string;
  line: number;
  /** 취약점 주변 소스코드 스니펫 */
  code: string;
  language: string;
  cveId?: string;
  severity?: string;
  package?: string;
}

export interface AiFixResult {
  fixedCode: string;
  explanation: string;
}

const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';

export function getGroqModel(): string {
  // llama-3.3-70b-versatile는 Groq에서 퇴역(404) — 현재 제공 모델로 교체.
  // GROQ_MODEL 환경변수로 언제든 변경 가능.
  return process.env.GROQ_MODEL || 'openai/gpt-oss-120b';
}

export function hasGroqApiKey(): boolean {
  return !!process.env.GROQ_API_KEY;
}

export function buildPrompt(input: AiFixInput): string {
  const cveLine = input.cveId ? `\n- CVE: ${input.cveId}` : '';
  const pkgLine = input.package ? `\n- 영향 패키지: ${input.package}` : '';
  return [
    '다음은 정적 분석(AST 스캔)으로 발견된 소스코드 취약점이다.',
    `취약점 유형: ${input.type}`,
    `설명: ${input.message}`,
    `파일: ${input.file} (라인 ${input.line})`,
    `언어: ${input.language}${cveLine}${pkgLine}`,
    '',
    '취약한 코드 스니펫:',
    '```' + input.language,
    input.code,
    '```',
    '',
    '위 취약점을 제거하는 올바른 수정 코드를 제시하라.',
    '반드시 아래 JSON 형식으로만 답하라 (마크다운 코드펜스 없이 순수 JSON):',
    '{"fixedCode": "<스니펫 전체를 대체하는 수정된 코드>", "explanation": "<한국어 설명 2~4문장: 왜 취약한지, 수정 코드가 어떻게 해결하는지>"}',
  ].join('\n');
}

/** Groq에 질의해 수정 코드를 받는다. 키 없음·API 오류 시 throw */
export async function suggestFix(input: AiFixInput): Promise<AiFixResult> {
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) {
    throw new Error('GROQ_API_KEY가 .env에 설정되어 있지 않습니다.');
  }
  const res = await axios.post(
    GROQ_URL,
    {
      model: getGroqModel(),
      temperature: 0.2,
      max_tokens: 2048,
      response_format: { type: 'json_object' },
      messages: [
        {
          role: 'system',
          content:
            '보안 코드 리뷰 전문가다. 항상 JSON {"fixedCode","explanation"} 형식으로만 답하고, explanation은 한국어로 작성한다.',
        },
        { role: 'user', content: buildPrompt(input) },
      ],
    },
    {
      timeout: 60000,
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    },
  );
  const content = res.data?.choices?.[0]?.message?.content;
  if (typeof content !== 'string' || content.length === 0) {
    throw new Error('AI 응답이 비어 있습니다.');
  }
  return parseFixContent(content);
}

function parseFixContent(content: string): AiFixResult {
  const candidates = [content, ...extractFencedCode(content)];
  for (const text of candidates) {
    try {
      const parsed = JSON.parse(text);
      if (typeof parsed?.fixedCode === 'string' && typeof parsed?.explanation === 'string') {
        return { fixedCode: parsed.fixedCode, explanation: parsed.explanation };
      }
    } catch {
      // 다음 후보 시도
    }
  }
  // 모델이 JSON 지시를 안 지킨 경우 폴백: 첫 코드펜스 → 수정 코드, 나머지 → 설명
  const fences = extractFencedCode(content);
  if (fences.length > 0) {
    const explanation = content
      .replace(/```[\s\S]*?```/g, '')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 1000);
    return {
      fixedCode: fences[0],
      explanation: explanation || '취약점을 제거한 수정 코드입니다.',
    };
  }
  throw new Error('AI 응답(JSON) 파싱에 실패했습니다.');
}

function extractFencedCode(content: string): string[] {
  const out: string[] = [];
  const re = /```(?:\w+)?\s*([\s\S]*?)```/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    const code = m[1].trim();
    if (code) out.push(code);
  }
  return out;
}
