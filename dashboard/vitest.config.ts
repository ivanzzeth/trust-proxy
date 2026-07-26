import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'node:path';

// Frontend tests run in jsdom against mocked API calls: the point is to catch a
// page rendering nothing because the wire shape moved, which tsc cannot see.
export default defineConfig({
  plugins: [react()],
  resolve: { alias: { '@': path.resolve(__dirname, './src') } },
  test: { environment: 'jsdom', globals: false, css: false },
});
