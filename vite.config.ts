import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// UI 개발 서버용 Vite 설정 (root: src, 진입점: src/index.html)
export default defineConfig({
  plugins: [react()],
  root: 'src',
  base: './',
  server: {
    port: 5173,
    strictPort: true,
  },
  build: {
    outDir: '../dist/renderer',
    emptyOutDir: true,
  },
});
