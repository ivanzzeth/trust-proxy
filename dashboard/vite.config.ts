import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'node:path';

// Builds to dashboard/dist; the trust-proxy backend serves it at :9096.
// Dev server proxies /api to the running backend so `pnpm dev` works live.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  build: { outDir: 'dist' },
  server: {
    port: 3100,
    proxy: {
      '/api': 'http://127.0.0.1:9096',
    },
  },
});
