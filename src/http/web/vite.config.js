import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Inline bundled CSS into <head> so the stylesheet arrives in the same
// response as the document — no render-blocking <link> round-trip.  The
// SPA is single-page; there's no shared cache to lose.  Identical to
// Dyson's pattern.
function inlineCss() {
  return {
    name: 'warden-inline-css',
    apply: 'build',
    enforce: 'post',
    transformIndexHtml: {
      order: 'post',
      handler(html, ctx) {
        if (!ctx || !ctx.bundle) return html;
        let out = html;
        for (const [fileName, chunk] of Object.entries(ctx.bundle)) {
          if (chunk.type !== 'asset' || !fileName.endsWith('.css')) continue;
          const source = typeof chunk.source === 'string'
            ? chunk.source
            : Buffer.from(chunk.source).toString('utf8');
          const escaped = fileName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const linkRe = new RegExp(`\\s*<link[^>]*href="[^"]*${escaped}"[^>]*>`, 'g');
          if (linkRe.test(out)) {
            out = out.replace(linkRe, `<style>${source}</style>`);
            delete ctx.bundle[fileName];
          }
        }
        return out;
      },
    },
  };
}

// Dev server proxies the warden HTTP server running on :8080 so the
// frontend can be iterated with HMR while talking to a real backend.
// Production build emits to ./dist, which build.rs bakes into the Rust
// binary via include_bytes!.
export default defineConfig({
  plugins: [react(), inlineCss()],
  test: {
    environment: 'jsdom',
  },
  server: {
    port: 5173,
    proxy: {
      '/v1': { target: 'http://127.0.0.1:8080', changeOrigin: false },
      '/llm': { target: 'http://127.0.0.1:8080', changeOrigin: false },
      '/auth': { target: 'http://127.0.0.1:8080', changeOrigin: false },
      '/healthz': { target: 'http://127.0.0.1:8080', changeOrigin: false },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    cssTarget: 'safari14',
    rollupOptions: {
      output: {
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
});
