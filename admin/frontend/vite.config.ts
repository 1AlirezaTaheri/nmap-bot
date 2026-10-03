import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'

// base '/admin/' because FastAPI serves the SPA under that prefix.
export default defineConfig({
  plugins: [react()],
  base: '/admin/',
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      output: {
        // Split the heavy libraries out of the app bundle so a code change
        // does not invalidate ~500 kB of vendor JS in the browser cache.
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
          charts: ['recharts'],
          query: ['@tanstack/react-query'],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      // `npm run dev` talks to a locally running admin API.
      '/api': { target: 'http://127.0.0.1:8080', changeOrigin: true },
    },
  },
})