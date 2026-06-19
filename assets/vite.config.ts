import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

export default defineConfig({
  base: '/assets/',
  plugins: [react()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  build: {
    outDir: '../priv/static/assets',
    emptyOutDir: false,
    manifest: 'manifest.json',
    rollupOptions: {
      input: resolve(__dirname, 'src/main.tsx'),
      output: {
        entryFileNames: 'js/[name]-[hash].js',
        chunkFileNames: 'js/[name]-[hash].js',
        assetFileNames: (assetInfo) => {
          if (assetInfo.name?.endsWith('.css')) {
            return 'css/[name]-[hash][extname]'
          }
          return 'assets/[name]-[hash][extname]'
        },
      },
    },
  },
  server: {
    origin: 'http://localhost:5173',
    hmr: {
      host: 'localhost',
      protocol: 'ws',
    },
  },
})
