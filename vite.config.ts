import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { markdownAssetProofPlugin } from './tests/support/markdownAssetRegistry';

export const MARKDOWN_SPIKE_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "script-src-attr 'none'",
  "style-src 'self'",
  "style-src-attr 'none'",
  "img-src 'self'",
  "font-src 'self'",
  "connect-src 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  "child-src 'none'",
  "worker-src 'none'",
  "media-src 'none'",
  "manifest-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

const markdownAssetFixture = readFileSync(
  fileURLToPath(new URL('./tests/fixtures/markdown/safe-local.png', import.meta.url)),
);

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'piui-markdown-browser-proof',
      transformIndexHtml: {
        order: 'post',
        handler(html) {
          return html.replace(/\s*<script type="module" src="\/@vite\/client"><\/script>\s*/, '\n');
        },
      },
    },
    markdownAssetProofPlugin(markdownAssetFixture),
  ],
  clearScreen: false,
  server: {
    host: '127.0.0.1',
    port: 1420,
    strictPort: true,
    hmr: false,
    ws: false,
    headers: {
      'Content-Security-Policy': MARKDOWN_SPIKE_CSP,
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
    },
  },
  envPrefix: ['VITE_', 'TAURI_'],
  build: {
    target: 'safari15',
    minify: 'oxc',
    sourcemap: false,
  },
});
