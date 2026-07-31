import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseA26Preparation } from './MarkdownProbe';

const capability = 'piui-asset-0123456789abcdef0123456789abcdef';
const preparation = {
  schemaVersion: 1,
  testMode: true,
  engine: 'javascript-regex',
  wasmModules: 0,
  ownerWebviewLabel: 'main',
  hostileFixtureSha256: 'a'.repeat(64),
  rasterFixtureSha256: 'b'.repeat(64),
  asset: {
    capability,
    url: 'piui-raster://localhost/__piui_markdown_asset__/0123456789abcdef0123456789abcdef.png',
    mime: 'image/png',
    byteLength: 68,
    expiresAt: 2_000,
  },
};

describe('A.26 packaged Markdown route contract', () => {
  it('accepts only the exact native preparation schema and custom raster descriptor', () => {
    expect(parseA26Preparation(preparation, 1_000)).toEqual(preparation);
    expect(Object.isFrozen(parseA26Preparation(preparation, 1_000))).toBe(true);

    for (const malformed of [
      { ...preparation, engine: 'oniguruma-wasm' },
      { ...preparation, wasmModules: 1 },
      { ...preparation, ownerWebviewLabel: 'secondary' },
      { ...preparation, additional: true },
      { ...preparation, hostileFixtureSha256: 'not-a-digest' },
      { ...preparation, asset: { ...preparation.asset, expiresAt: 1_000 } },
      { ...preparation, asset: { ...preparation.asset, url: 'https://asset.invalid/image.png' } },
      { ...preparation, asset: { ...preparation.asset, additional: true } },
    ]) {
      expect(parseA26Preparation(malformed, 1_000)).toBeNull();
    }
  });

  it('keeps a visible, accessible loading state for fixture and renderer waits', () => {
    const source = readFileSync(new URL('./MarkdownProbe.tsx', import.meta.url), 'utf8');
    expect(source).toContain('role="status"');
    expect(source).toContain('aria-busy={busy}');
    expect(source).toContain('markdown-probe__spinner');
    expect(source).toContain('Preparing the fixed hostile fixture…');
    expect(source).toContain('Rendering and checking the raster and syntax highlighter…');
    expect(source).toContain("invoke<unknown>('a26_markdown_prepare')");
    expect(source).toContain('let fixedPreparation: Promise<');
    expect(source).toContain('window.setInterval(markReadyWhenComplete, 50)');
    expect(source).toContain('window.clearInterval(poll)');
  });
});
