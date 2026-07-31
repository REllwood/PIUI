import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const source = readFileSync(new URL('./a26MarkdownPrelude.ts', import.meta.url), 'utf8');

describe('A.26 architecture-only browser prelude', () => {
  it('is compile-time feature-gated and stores only bounded counts and booleans', () => {
    expect(source).toContain("import.meta.env.VITE_PIUI_A26_MARKDOWN_TEST === '1'");
    expect(source).toContain('performance.getEntriesByType');
    expect(source).toContain("document.addEventListener('securitypolicyviolation'");
    expect(source).toContain("window.addEventListener('unhandledrejection'");
    expect(source).not.toContain('localStorage');
    expect(source).not.toContain('sessionStorage');
    expect(source).not.toContain('outerHTML');
  });

  it('pins only the one-shot custom raster path as a non-application resource', () => {
    expect(source).toContain('piui-raster:\\\/\\\/localhost');
    for (const broadening of ['data:', 'blob:', 'file:', 'https?:', 'piui-raster:*']) {
      expect(source).not.toContain(broadening);
    }
  });
});
