import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// base './' so built assets load under our backend's "/" host.
// Dev server proxies /api to the running backend (trust-proxy serve).
export default defineConfig({
  base: './',
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:9096',
    },
  },
})
