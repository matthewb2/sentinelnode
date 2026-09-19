/**
 * CVE 가져오기 전용 워커 — 로컬 클론(cvelistV5/cves) 탐색·파싱·적재를
 * Electron 메인 스레드와 분리해 UI 멈춤을 방지한다.
 * workerData: { cvesDir, storagePath, opts } (함수 전달 불가 → 순수 데이터만)
 * 완료 시 { type: 'done', scanned, ingested, skipped, source }.
 * 진행 중 { type: 'progress', scanned } 송신.
 */
import { parentPort, workerData } from 'worker_threads';
import { createDatabase } from '../db';
import { importLocalDir, type SyncOptions } from '../db/cveSync';

interface ImportWorkerData {
  cvesDir: string;
  storagePath: string;
  opts?: SyncOptions;
}

async function main(): Promise<void> {
  if (!parentPort) throw new Error('가져오기 워커는 worker_threads에서만 실행됩니다.');
  const port = parentPort;
  const { cvesDir, storagePath, opts } = workerData as ImportWorkerData;
  if (typeof cvesDir !== 'string' || cvesDir.length === 0) {
    throw new Error('CVE 폴더가 지정되지 않았습니다.');
  }
  // 메인 싱글턴과 독립된 DB 인스턴스 (파일 기반이므로 결과는 디스크에 영속화)
  const db = createDatabase(storagePath);
  const { maxRecords, packageFilter, includeNonNpm } = opts ?? {};
  const result = importLocalDir(
    db,
    cvesDir,
    {
      maxRecords,
      packageFilter,
      includeNonNpm,
      onProgress: ({ scanned }) => {
        try {
          port.postMessage({ type: 'progress', scanned });
        } catch {
          // 진행률 전송 실패 무시
        }
      },
    },
  );
  port.postMessage({ type: 'done', ...result });
}

main().catch((err: unknown) => {
  try {
    parentPort?.postMessage({ type: 'error', error: (err as Error)?.message ?? String(err) });
  } catch {
    // 무시
  }
  process.exitCode = 1;
});
