/**
 * WorkerPool — 동적 작업 분산 풀.
 * 고정된 수의 워커를 미리 생성하고 파일 청크를 큐에 쌓아두면,
 * 일을 마친 워커가 다음 청크를 가져가 처리한다.
 * (파일 수·크기가 불균일해도 병목 최소화)
 */
import { Worker } from 'worker_threads';
import type { ExtractedFile } from '../engine/fileExtractor';

export interface PoolChunk {
  chunkId: number;
  files: string[];
}

export interface PoolResult {
  cancelled: boolean;
  results: ExtractedFile[];
}

interface WorkerState {
  worker: Worker;
  busy: boolean;
  chunkId: number | null;
  alive: boolean;
}

export function splitChunks(files: string[], chunkSize: number): PoolChunk[] {
  const size = Math.max(1, chunkSize);
  const chunks: PoolChunk[] = [];
  for (let i = 0; i < files.length; i += size) {
    chunks.push({ chunkId: chunks.length, files: files.slice(i, i + size) });
  }
  return chunks;
}

const MAX_RETRY = 1;

export class WorkerPool {
  private states: WorkerState[] = [];
  private queue: PoolChunk[] = [];
  private chunkFiles = new Map<number, string[]>();
  private results: ExtractedFile[] = [];
  private retries = new Map<number, number>();
  private completedFiles = 0;
  private totalFiles = 0;
  private settled = false;
  private cancelled = false;
  private resolveRun: ((r: PoolResult) => void) | null = null;
  private rejectRun: ((e: Error) => void) | null = null;
  private onProgress:
    | ((info: { completedFiles: number; totalFiles: number }) => void)
    | null = null;

  constructor(
    private workerPath: string,
    private poolSize: number,
  ) {}

  /** 풀 스캔 실행 — 청크 큐를 워커들에 동적 분배 */
  run(
    files: string[],
    chunkSize: number,
    onProgress?: (info: { completedFiles: number; totalFiles: number }) => void,
  ): Promise<PoolResult> {
    if (this.resolveRun) {
      return Promise.reject(new Error('WorkerPool은 동시에 하나의 작업만 실행합니다.'));
    }
    const chunks = splitChunks(files, chunkSize);
    this.queue = [...chunks];
    this.chunkFiles = new Map(chunks.map((c) => [c.chunkId, c.files]));
    this.results = [];
    this.retries = new Map();
    this.completedFiles = 0;
    this.totalFiles = files.length;
    this.settled = false;
    this.cancelled = false;
    this.onProgress = onProgress ?? null;

    return new Promise<PoolResult>((resolve, reject) => {
      this.resolveRun = resolve;
      this.rejectRun = reject;
      try {
        // 첫 실행에만 워커 생성, 이후 재사용
        if (this.states.length === 0) {
          for (let i = 0; i < this.poolSize; i += 1) {
            this.states.push(this.spawn());
          }
        } else {
          for (const st of this.states) {
            st.busy = false;
            st.chunkId = null;
          }
        }
      } catch (err) {
        this.finishReject(err as Error);
        return;
      }
      if (this.queue.length === 0) {
        this.finishResolve({ cancelled: false, results: [] });
        return;
      }
      this.report();
      for (const st of this.states) this.dispatch(st);
    });
  }

  /** 진행 중 작업 취소 — 워커 전원 종료 후 cancelled로 해제 */
  async cancel(): Promise<void> {
    if (!this.resolveRun || this.settled) return;
    this.cancelled = true;
    const workers = this.states.map((s) => {
      s.alive = false;
      return s.worker;
    });
    this.states = [];
    await Promise.all(workers.map((w) => w.terminate().catch(() => 0)));
    this.finishResolve({ cancelled: true, results: [] });
  }

  /** 풀 종료 — 워커 전원 해제 */
  async dispose(): Promise<void> {
    this.resolveRun = null;
    this.rejectRun = null;
    this.settled = true;
    const workers = this.states.map((s) => {
      s.alive = false;
      return s.worker;
    });
    this.states = [];
    await Promise.all(workers.map((w) => w.terminate().catch(() => 0)));
  }

  private spawn(): WorkerState {
    const worker = new Worker(this.workerPath);
    const st: WorkerState = { worker, busy: false, chunkId: null, alive: true };
    worker.on('message', (msg: any) => this.handleMessage(st, msg));
    worker.on('error', () => this.handleWorkerDeath(st, '워커 오류'));
    worker.on('exit', (code) => {
      if (st.alive && code !== 0) this.handleWorkerDeath(st, `워커 비정상 종료 (${code})`);
    });
    return st;
  }

  private dispatch(st: WorkerState): void {
    if (this.settled || this.cancelled || !st.alive || st.busy) return;
    const chunk = this.queue.shift();
    if (!chunk) {
      this.checkDone();
      return;
    }
    st.busy = true;
    st.chunkId = chunk.chunkId;
    try {
      st.worker.postMessage({ type: 'scan', chunkId: chunk.chunkId, files: chunk.files });
    } catch {
      // 전송 실패 시 큐에 되돌림
      st.busy = false;
      st.chunkId = null;
      this.queue.unshift(chunk);
      this.checkDone();
    }
  }

  private handleMessage(st: WorkerState, msg: any): void {
    if (this.settled || this.cancelled) return;
    if (msg?.type === 'chunk-done') {
      const chunkId = msg.chunkId as number;
      const results = (msg.results ?? []) as ExtractedFile[];
      this.results.push(...results);
      this.completedFiles += this.chunkFiles.get(chunkId)?.length ?? 0;
      st.busy = false;
      st.chunkId = null;
      this.report();
      this.dispatch(st);
      this.checkDone();
    } else if (msg?.type === 'chunk-error') {
      this.retryChunk(st, msg.chunkId as number, new Error(msg.error || '청크 처리 실패'));
    }
  }

  private retryChunk(st: WorkerState, chunkId: number, err: Error): void {
    st.busy = false;
    st.chunkId = null;
    const tried = this.retries.get(chunkId) ?? 0;
    const files = this.chunkFiles.get(chunkId);
    if (tried < MAX_RETRY && files) {
      this.retries.set(chunkId, tried + 1);
      this.queue.unshift({ chunkId, files });
      this.dispatch(st);
    } else {
      this.finishReject(err);
    }
  }

  private handleWorkerDeath(st: WorkerState, reason: string): void {
    if (this.settled || this.cancelled) return;
    st.alive = false;
    const idx = this.states.indexOf(st);
    if (idx >= 0) this.states.splice(idx, 1);
    // 처리 중이던 청크는 1회 재시도
    const chunkId = st.chunkId;
    if (chunkId !== null) {
      const tried = this.retries.get(chunkId) ?? 0;
      const files = this.chunkFiles.get(chunkId);
      if (tried < MAX_RETRY && files) {
        this.retries.set(chunkId, tried + 1);
        this.queue.unshift({ chunkId, files });
      } else {
        this.finishReject(new Error(reason));
        return;
      }
    }
    // 풀 크기 유지 — 교체 워커 투입 후 남은 큐 계속 처리
    try {
      const replacement = this.spawn();
      this.states.push(replacement);
      for (const s of this.states) this.dispatch(s);
      this.checkDone();
    } catch (err) {
      this.finishReject(err as Error);
    }
  }

  private checkDone(): void {
    if (this.settled || this.cancelled) return;
    const busy = this.states.some((s) => s.busy);
    if (this.queue.length === 0 && !busy) {
      this.finishResolve({ cancelled: false, results: this.results });
    }
  }

  private report(): void {
    try {
      this.onProgress?.({ completedFiles: this.completedFiles, totalFiles: this.totalFiles });
    } catch {
      // 진행률 콜백 오류 무시
    }
  }

  private finishResolve(r: PoolResult): void {
    if (this.settled) return;
    this.settled = true;
    const resolve = this.resolveRun;
    this.resolveRun = null;
    this.rejectRun = null;
    if (r.cancelled) {
      for (const st of this.states) {
        st.alive = false;
        void st.worker.terminate().catch(() => 0);
      }
      this.states = [];
    } else {
      for (const st of this.states) {
        st.busy = false;
        st.chunkId = null;
      }
    }
    resolve?.(r);
  }

  private finishReject(err: Error): void {
    if (this.settled) return;
    this.settled = true;
    const reject = this.rejectRun;
    this.resolveRun = null;
    this.rejectRun = null;
    for (const st of this.states) {
      st.alive = false;
      void st.worker.terminate().catch(() => 0);
    }
    this.states = [];
    reject?.(err);
  }
}
