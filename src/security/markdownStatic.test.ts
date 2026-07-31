import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '../..');
const componentPath = resolve(root, 'src/security/SafeMarkdownSpike.tsx');
const policyPath = resolve(root, 'src/security/markdownPolicy.ts');
const highlighterPath = resolve(root, 'src/security/shikiHighlighter.ts');
const viteConfigPath = resolve(root, 'vite.config.ts');
const tauriConfigPath = resolve(root, 'src-tauri/tauri.conf.json');
const capabilityPath = resolve(root, 'src-tauri/capabilities/default.json');

function source(path: string): string {
  return readFileSync(path, 'utf8');
}

describe('Markdown static containment', () => {
  it('has no raw-HTML sink, Shiki HTML path, Tauri import or parser-prop spread', () => {
    const securitySource = `${source(componentPath)}\n${source(policyPath)}\n${source(highlighterPath)}`;
    const forbidden = [
      ['dangerous HTML React property', 'dangerously' + 'SetInnerHTML'],
      ['raw HTML plugin', 'rehype' + '-raw'],
      ['DOM HTML parser', 'DOM' + 'Parser'],
      ['HTML fragment parser', 'createContextual' + 'Fragment'],
      ['Shiki HTML API', 'codeTo' + 'Html'],
      ['Tauri API import', '@tauri-apps/' + 'api'],
      ['generic native invocation', 'invo' + "ke("],
      ['browser popup', 'window.' + 'open'],
    ] as const;
    for (const [label, value] of forbidden) {
      expect(securitySource, label).not.toContain(value);
    }
    expect(securitySource).not.toMatch(/\{\s*\.\.\./);
    expect(securitySource).not.toMatch(/\b(?:node|props|rest)\s*[,}]/);
  });

  it('keeps raw HTML sinks out of every React source file', () => {
    const directories = [resolve(root, 'src'), resolve(root, 'tests/e2e')];
    const queue = [...directories];
    while (queue.length > 0) {
      const directory = queue.pop();
      if (!directory) break;
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const path = resolve(directory, entry.name);
        if (entry.isDirectory()) queue.push(path);
        else if (/\.(?:tsx|ts)$/.test(entry.name) && !entry.name.endsWith('.test.ts')) {
          expect(source(path), path).not.toContain('dangerously' + 'SetInnerHTML');
        }
      }
    }
  });

  it('pins exact deny-by-default Tauri and Vite CSPs without broad exceptions', () => {
    const config = JSON.parse(source(tauriConfigPath)) as {
      app: { withGlobalTauri?: boolean; security: { csp: string } };
    };
    expect(config.app.withGlobalTauri).toBe(false);
    const common = [
      "default-src 'none'",
      "script-src 'self'",
      "script-src-attr 'none'",
      "style-src 'self'",
      "style-src-attr 'none'",
    ];
    const tail = [
      "object-src 'none'",
      "frame-src 'none'",
      "child-src 'none'",
      "worker-src 'none'",
      "media-src 'none'",
      "manifest-src 'none'",
      "base-uri 'none'",
      "form-action 'none'",
      "frame-ancestors 'none'",
    ];
    const tauriCsp = [
      ...common,
      "img-src 'self' piui-raster:",
      "font-src 'self'",
      'connect-src ipc: http://ipc.localhost',
      ...tail,
    ].join('; ');
    const viteCsp = [
      ...common,
      "img-src 'self'",
      "font-src 'self'",
      "connect-src 'none'",
      ...tail,
    ].join('; ');
    expect(config.app.security.csp).toBe(tauriCsp);
    expect(source(viteConfigPath)).toContain(`export const MARKDOWN_SPIKE_CSP = [`);
    for (const directive of [
      ...common,
      "img-src 'self'",
      "font-src 'self'",
      "connect-src 'none'",
      ...tail,
    ]) {
      expect(source(viteConfigPath)).toContain(JSON.stringify(directive));
    }
    for (const broadening of [
      "'unsafe-inline'",
      "'unsafe-eval'",
      'wasm-unsafe-eval',
      'https:',
      'data:',
      'blob:',
      'asset:',
      'file:',
      '*',
    ]) {
      expect(tauriCsp).not.toContain(broadening);
      expect(viteCsp).not.toContain(broadening);
    }
  });

  it('does not grant a shell, opener, filesystem, HTTP or generic Markdown command', () => {
    const capability = JSON.parse(source(capabilityPath)) as { permissions: unknown };
    expect(capability.permissions).toEqual(['core:default']);
    const encoded = JSON.stringify(capability).toLowerCase();
    for (const forbidden of ['shell', 'opener', 'filesystem', 'fs:', 'http:', 'markdown']) {
      expect(encoded).not.toContain(forbidden);
    }
  });
});
