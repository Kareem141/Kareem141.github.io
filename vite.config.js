import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'assets/js',
    emptyOutDir: false,
    rollupOptions: {
      input: 'src/liquid-ether-entry.jsx',
      output: {
        entryFileNames: 'liquid-ether.js',
        assetFileNames: 'liquid-ether.[ext]'
      }
    }
  }
});