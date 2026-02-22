import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'
import fs from 'fs'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    https: {
      cert: fs.readFileSync(path.resolve(__dirname, '../docker/nginx/certs/localhost+2.pem')),
      key: fs.readFileSync(path.resolve(__dirname, '../docker/nginx/certs/localhost+2-key.pem')),
    },
    proxy: {
      '/api': {
        target: 'https://localhost:3000',
        secure: false,
      },
      '/health': {
        target: 'https://localhost:3000',
        secure: false,
      },
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
})
