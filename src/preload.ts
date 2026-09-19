import { contextBridge, ipcRenderer } from 'electron';
import type { DbStats } from './db/graphStore';
import type { FeedVulnerabilityItem } from './db/types';
import type { SyncMeta, SyncOptions, SyncResult } from './db/cveSync';

export interface SyncStatus extends SyncMeta {
  watchlistSize: number;
}

type IpcOk<T extends object> = { success: true } & T;
type IpcFail = { success: false; error: string };

contextBridge.exposeInMainWorld('sentinelAPI', {
  selectDirectory: () => ipcRenderer.invoke('select-directory'),
  runAstScan: (dirPath: string) => ipcRenderer.invoke('run-ast-scan', dirPath),
  cancelAstScan: () =>
    ipcRenderer.invoke('cancel-ast-scan') as Promise<
      { success: true; cancelled: true } | { success: false; error: string }
    >,
  getDbStats: () =>
    ipcRenderer.invoke('get-db-stats') as Promise<
      { success: true; stats: DbStats; storagePath: string } | { success: false; error: string }
    >,
  syncVulnFeed: (payload: { url?: string; items?: FeedVulnerabilityItem[] }) =>
    ipcRenderer.invoke('sync-vuln-feed', payload),
  // CVE 동기화 (cvelistV5)
  getSyncStatus: () =>
    ipcRenderer.invoke('get-sync-status') as Promise<IpcOk<{ status: SyncStatus }> | IpcFail>,
  checkCveUpdates: () =>
    ipcRenderer.invoke('check-cve-updates') as Promise<
      IpcOk<{ updateAvailable: boolean; latestTag: string | null }> | IpcFail
    >,
  syncCveNow: (opts?: SyncOptions) =>
    ipcRenderer.invoke('sync-cve-now', opts) as Promise<
      IpcOk<SyncResult & { tag: string | null; stats: DbStats }> | IpcFail
    >,
  importCveDir: (payload?: { dirPath?: string } & SyncOptions) =>
    ipcRenderer.invoke('import-cve-dir', payload) as Promise<
      IpcOk<SyncResult & { stats: DbStats }> | IpcFail
    >,
  fetchCve: (cveId: string) =>
    ipcRenderer.invoke('fetch-cve', cveId) as Promise<
      IpcOk<SyncResult & { stats: DbStats }> | IpcFail
    >,
  setAutoSync: (enabled: boolean) => ipcRenderer.invoke('set-auto-sync', enabled),
  getAiFix: (payload: {
    file: string;
    line: number;
    type: string;
    message: string;
    cveId?: string;
    severity?: string;
    package?: string;
  }) =>
    ipcRenderer.invoke('get-ai-fix', payload) as Promise<
      | { success: true; fixedCode: string; explanation: string; snippetStartLine: number; cached: boolean }
      | { success: false; error: string }
    >,
  openInVscode: (payload: { file?: string; line?: number }) =>
    ipcRenderer.invoke('open-in-vscode', payload) as Promise<
      { success: true } | { success: false; error: string }
    >,
  getUserConfig: () =>
    ipcRenderer.invoke('get-user-config') as Promise<
      | {
          success: true;
          config: { lastProjectPath: string | null; updatedAt: string | null; dbDir: string | null; dbFilePath: string };
        }
      | { success: false; error: string }
    >,
  getDbStorage: () =>
    ipcRenderer.invoke('get-db-storage') as Promise<
      | { success: true; dbDir: string; dbFilePath: string; storagePath: string; stats: DbStats }
      | { success: false; error: string }
    >,
  selectDbDirectory: () => ipcRenderer.invoke('select-db-directory') as Promise<string | null>,
  setDbStorage: (dirPath: string) =>
    ipcRenderer.invoke('set-db-storage', dirPath) as Promise<
      | { success: true; dbDir: string; dbFilePath: string; storagePath: string; stats: DbStats }
      | { success: false; error: string }
    >,
  resetDbStorage: () =>
    ipcRenderer.invoke('reset-db-storage') as Promise<
      | { success: true; dbDir: string; dbFilePath: string; storagePath: string; stats: DbStats }
      | { success: false; error: string }
    >,
  onCveSyncDone: (cb: (info: { updated: boolean; ingested: number; tag: string | null }) => void) => {
    const listener = (_: unknown, info: { updated: boolean; ingested: number; tag: string | null }) =>
      cb(info);
    ipcRenderer.on('cve-sync-done', listener);
    return () => ipcRenderer.removeListener('cve-sync-done', listener);
  },
  onScanProgress: (
    cb: (info: { phase: string; scannedFiles: number; totalFiles?: number }) => void,
  ) => {
    const listener = (_: unknown, info: { phase: string; scannedFiles: number; totalFiles?: number }) =>
      cb(info);
    ipcRenderer.on('ast-scan-progress', listener);
    return () => ipcRenderer.removeListener('ast-scan-progress', listener);
  },
});
