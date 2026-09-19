/**
 * 청크 워커 — WorkerPool이 파일 경로 청크를 전달하면 파싱만 수행하고 반환.
 * DB 접근 없음(집계·저장은 메인 프로세스가 담당하므로 동시성 문제 없음).
 *
 * 수신: { type: 'scan', chunkId: number, files: string[] }
 * 송신: { type: 'chunk-done', chunkId, results: ExtractedFile[] }
 *       { type: 'chunk-error', chunkId, error: string }
 */
import { parentPort } from 'worker_threads';
import { extractSourceFile, type ExtractedFile } from '../engine/fileExtractor';

interface ScanMessage {
  type: string;
  chunkId?: number;
  files?: string[];
}

async function scanChunk(chunkId: number, files: string[]): Promise<ExtractedFile[]> {
  const results: ExtractedFile[] = [];
  for (const file of files) {
    try {
      const extracted = await extractSourceFile(file);
      if (extracted) results.push(extracted);
    } catch {
      // 파일 단위 실패는 스킵 (청크 전체는 계속 처리)
    }
  }
  return results;
}

if (!parentPort) {
  throw new Error('청크 워커는 worker_threads에서만 실행됩니다.');
}

const port = parentPort;
port.on('message', (msg: ScanMessage) => {
  if (!msg || msg.type !== 'scan' || typeof msg.chunkId !== 'number' || !Array.isArray(msg.files)) {
    return;
  }
  const { chunkId, files } = msg as { chunkId: number; files: string[] };
  scanChunk(chunkId, files).then(
    (results) => {
      try {
        port.postMessage({ type: 'chunk-done', chunkId, results });
      } catch {
        // 전송 실패 무시 (풀이 종료 중일 수 있음)
      }
    },
    (err: unknown) => {
      try {
        port.postMessage({
          type: 'chunk-error',
          chunkId,
          error: (err as Error)?.message ?? String(err),
        });
      } catch {
        // 무시
      }
    },
  );
});
