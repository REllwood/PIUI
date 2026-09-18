import { readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, resolve } from 'node:path';
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

const a26ModuleKinds = new Set([
  'a26-engine-javascript',
  'a26-engine-oniguruma',
  'a26-hostile-fixture',
  'a26-lang-bash',
  'a26-lang-css',
  'a26-lang-html',
  'a26-lang-javascript',
  'a26-lang-json',
  'a26-lang-markdown',
  'a26-lang-rust',
  'a26-lang-tsx',
  'a26-lang-typescript',
  'a26-shiki-core',
  'a26-theme-github-dark-default',
  'a26-wasm-module',
]);

function canonicalReceiptJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'number'
    || typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalReceiptJson).join(',')}]`;
  if (!value || typeof value !== 'object') throw new Error('A.26 provenance value is invalid');
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => (
    `${JSON.stringify(key)}:${canonicalReceiptJson(record[key])}`
  )).join(',')}}`;
}

function a26KindsForModule(moduleId: string): string[] {
  const path = moduleId.replaceAll('\\', '/').split('?')[0];
  const kinds = new Set<string>();
  if (path.endsWith('/tests/fixtures/markdown/hostile.md')) kinds.add('a26-hostile-fixture');
  if (path.endsWith('/shiki/dist/core.mjs') || path.includes('/@shikijs/core/')) {
    kinds.add('a26-shiki-core');
  }
  if (path.endsWith('/shiki/dist/engine-javascript.mjs')
    || path.includes('/@shikijs/engine-javascript/')) {
    kinds.add('a26-engine-javascript');
  }
  if (path.endsWith('/shiki/dist/engine-oniguruma.mjs')
    || path.includes('/@shikijs/engine-oniguruma/')) {
    kinds.add('a26-engine-oniguruma');
  }
  if (path.endsWith('/shiki/dist/themes/github-dark-default.mjs')
    || path.endsWith('/@shikijs/themes/dist/github-dark-default.mjs')) {
    kinds.add('a26-theme-github-dark-default');
  }
  for (const language of [
    'bash',
    'css',
    'html',
    'javascript',
    'json',
    'markdown',
    'rust',
    'tsx',
    'typescript',
  ]) {
    if (path.endsWith(`/shiki/dist/langs/${language}.mjs`)
      || path.endsWith(`/@shikijs/langs/dist/${language}.mjs`)) {
      kinds.add(`a26-lang-${language}`);
    }
  }
  if (/\.wasm(?:$|[?#])/iu.test(moduleId)
    || path.includes('/wasm-inlined/')
    || path.includes('/onig.wasm')) kinds.add('a26-wasm-module');
  const result = [...kinds].sort();
  if (result.some((kind) => !a26ModuleKinds.has(kind))) {
    throw new Error('A.26 provenance module kind is invalid');
  }
  return result;
}

function a26ProvenancePath(): string | undefined {
  const path = process.env.PIUI_A26_MODULE_PROVENANCE_PATH;
  if (path === undefined) return undefined;
  const temporary = process.env.TMPDIR;
  if (typeof temporary !== 'string'
    || !isAbsolute(path)
    || dirname(path) !== resolve(temporary)
    || !/^a26-module-provenance-[0-9a-f]{32}\.json$/u.test(basename(path))) {
    throw new Error('A.26 provenance output path is invalid');
  }
  return path;
}

function a26ModuleProvenancePlugin() {
  const path = a26ProvenancePath();
  return {
    name: 'piui-a26-module-provenance',
    apply: 'build' as const,
    writeBundle(_options: unknown, output: Record<string, unknown>) {
      if (path === undefined) return;
      const chunks = Object.values(output)
        .filter((entry): entry is Record<string, unknown> => (
          entry !== null
          && typeof entry === 'object'
          && 'type' in entry
          && entry.type === 'chunk'
        ))
        .map((entry) => {
          const metadata = entry.viteMetadata as Readonly<{
            importedAssets?: ReadonlySet<string>;
            importedCss?: ReadonlySet<string>;
          }> | undefined;
          const moduleKinds = new Set<string>();
          for (const moduleId of Object.keys(entry.modules as Record<string, unknown>)) {
            for (const kind of a26KindsForModule(moduleId)) moduleKinds.add(kind);
          }
          const sorted = (values: Iterable<string>) => [...new Set(values)].sort();
          return {
            assets: sorted([
              ...((entry.referencedFiles as string[] | undefined) ?? []),
              ...(metadata?.importedAssets ?? []),
            ]),
            css: sorted(metadata?.importedCss ?? []),
            dynamicImports: sorted(entry.dynamicImports as string[]),
            fileName: entry.fileName,
            imports: sorted(entry.imports as string[]),
            isEntry: entry.isEntry,
            moduleKinds: sorted(moduleKinds),
          };
        })
        .sort((left, right) => String(left.fileName).localeCompare(String(right.fileName), 'en'));
      const receipt = { chunks, schemaVersion: 1 };
      writeFileSync(path, `${canonicalReceiptJson(receipt)}\n`, {
        encoding: 'utf8',
        flag: 'wx',
        mode: 0o600,
      });
    },
  };
}

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
    a26ModuleProvenancePlugin(),
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
