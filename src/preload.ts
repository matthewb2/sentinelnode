import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('sentinelAPI', {
  selectDirectory: () => ipcRenderer.invoke('select-directory'),
  runAstScan: (dirPath: string) => ipcRenderer.invoke('run-ast-scan', dirPath),
});