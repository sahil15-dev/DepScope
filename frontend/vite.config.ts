import tailwind from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

const api = { target: 'http://127.0.0.1:8000', changeOrigin: true }
const loopback = {
  host: '127.0.0.1',
  strictPort: true,
  proxy: { '/api/': api, '/openapi.json': api },
}

export default defineConfig({
  plugins: [react(), tailwind()],
  server: { ...loopback, port: 5173 },
  preview: { ...loopback, port: 4173 },
  build: { license: { fileName: 'assets/third-party-licenses.md' } },
  test: { environment: 'jsdom', setupFiles: ['./tests/setup.ts'] },
})
