import { defineConfig } from 'vite';
import { fileURLToPath, URL } from 'node:url';

const viewerCsp = "default-src 'self'; connect-src 'none'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'";

export default defineConfig(({ mode }) => {
  const demo = mode === 'demo';
  return {
    base: './',
    plugins: demo ? [{ name: 'offline-viewer-csp', transformIndexHtml: () => [{ tag: 'meta', attrs: { 'http-equiv': 'Content-Security-Policy', content: viewerCsp }, injectTo: 'head-prepend' }] }] : [],
    resolve: { alias: {
      '@adapter': fileURLToPath(new URL(`./src/data/demoAdapter.ts`, import.meta.url)),
      '@reset': fileURLToPath(new URL(`./src/screens/RecordedReset.tsx`, import.meta.url)),
    } },
    build: { outDir: demo ? 'dist-demo' : 'dist', sourcemap: false, modulePreload: { polyfill: false },
      rollupOptions: { output: { manualChunks: id => /\/node_modules\/(react|react-dom|scheduler)\//.test(id) ? 'react-runtime' : undefined } } },
  };
});
