import { describe, expect, it, vi } from 'vitest';
import { MAX_HIGHLIGHT_BYTES } from './markdownPolicy';
import {
  MAX_HIGHLIGHT_JOBS,
  MAX_HIGHLIGHT_RENDER_NODES_PER_BLOCK,
  MAX_HIGHLIGHT_RENDER_NODES_TOTAL,
  createHighlightJobRegistry,
  highlightCode,
  highlightRenderNodeCount,
  resolveHighlightLanguage,
  type FixedHighlighterLoader,
  type FixedHighlightResult,
} from './shikiHighlighter';

describe('bounded token-only highlighting', () => {
  it('uses a fixed language allow-list and never calls the loader for inline, unknown or oversized code', async () => {
    const loader = vi.fn<FixedHighlighterLoader>();
    expect(resolveHighlightLanguage('tsx')).toBe('tsx');
    expect(resolveHighlightLanguage('TSX')).toBeNull();
    expect(resolveHighlightLanguage('../typescript')).toBeNull();
    expect(await highlightCode('inline', undefined, loader)).toBeNull();
    expect(await highlightCode('unknown', 'not-enabled', loader)).toBeNull();
    expect(await highlightCode('x'.repeat(MAX_HIGHLIGHT_BYTES), 'typescript', loader)).toBeNull();
    expect(loader).not.toHaveBeenCalled();
  });

  it('maps scope explanations to fixed classes while preserving hostile token text exactly', async () => {
    const hostile = '</span><script>window.hostile=true</script>';
    const loader: FixedHighlighterLoader = async () => ({
      codeToTokens: () => ({
        tokens: [[
          {
            content: 'const',
            explanation: [{ content: 'const', scopes: [{ scopeName: 'keyword.control.ts' }] }],
          },
          { content: ` value = ${hostile}` },
        ]],
      }),
    });
    const result = await highlightCode(`const value = ${hostile}`, 'ts', loader);
    expect(result).toEqual({
      language: 'typescript',
      lines: [[
        { content: 'const', className: 'tok-keyword' },
        { content: ` value = ${hostile}`, className: null },
      ]],
    });
    expect(JSON.stringify(result)).not.toContain('style=');
  });

  it('surfaces loader rejection to the renderer plain-text fallback without retrying here', async () => {
    const loader = vi.fn<FixedHighlighterLoader>().mockRejectedValue(new Error('synthetic import failure'));
    await expect(highlightCode('const safe = true', 'ts', loader)).rejects.toThrow(
      'synthetic import failure',
    );
    expect(loader).toHaveBeenCalledTimes(1);
  });

  it('loads the pinned JavaScript-regex Shiki core and returns token data, not HTML', async () => {
    const result = await highlightCode('const answer: number = 42', 'typescript');
    expect(result?.language).toBe('typescript');
    expect(result?.lines.flatMap((line) => line.map((token) => token.content)).join('')).toBe(
      'const answer: number = 42',
    );
    expect(result?.lines.flat().some((token) => token.className !== null)).toBe(true);
  });

  it('counts multiline newline text nodes at the exact and one-over per-block rendering budget', async () => {
    const lineCount = MAX_HIGHLIGHT_RENDER_NODES_PER_BLOCK / 2;
    const tokensAtLimit = Array.from({ length: lineCount }, (_, index) => (
      index === 0 ? [{ content: 'x' }] : []
    ));
    const exactLoader: FixedHighlighterLoader = async () => ({
      codeToTokens: () => ({ tokens: tokensAtLimit }),
    });
    const exact = await highlightCode('bounded input', 'ts', exactLoader);
    expect(exact?.lines).toHaveLength(lineCount);

    const oneOverLoader: FixedHighlighterLoader = async () => ({
      codeToTokens: () => ({
        tokens: tokensAtLimit.map((line, index) => (
          index === 0 ? [...line, { content: 'one-over' }] : line
        )),
      }),
    });
    expect(await highlightCode('bounded input', 'ts', oneOverLoader)).toBeNull();
  });

  it('charges both the span and text child for every styled token', async () => {
    const styledCount = (MAX_HIGHLIGHT_RENDER_NODES_PER_BLOCK - 2) / 2;
    const styled = () => ({
      content: 'x',
      explanation: [{ scopes: [{ scopeName: 'comment.line' }] }],
    });
    const exactLoader: FixedHighlighterLoader = async () => ({
      codeToTokens: () => ({
        tokens: [[...Array.from({ length: styledCount }, styled), { content: 'plain' }]],
      }),
    });
    const exact = await highlightCode('bounded styled input', 'ts', exactLoader);
    expect(exact).not.toBeNull();
    expect(highlightRenderNodeCount(exact!)).toBe(MAX_HIGHLIGHT_RENDER_NODES_PER_BLOCK);

    const oneOverLoader: FixedHighlighterLoader = async () => ({
      codeToTokens: () => ({
        tokens: [[...Array.from({ length: styledCount + 1 }, styled), { content: 'plain' }]],
      }),
    });
    expect(await highlightCode('bounded styled input', 'ts', oneOverLoader)).toBeNull();
  });

  it('deduplicates Strict Mode effect replay by message owner and exact language/code', async () => {
    const fixed: FixedHighlightResult = {
      language: 'typescript',
      lines: [[{ content: 'const safe = true', className: null }]],
    };
    const tokenise = vi.fn(async () => fixed);
    const registry = createHighlightJobRegistry(tokenise);
    const first = registry.request('react-block-1', 'const safe = true', 'ts');
    const strictReplay = registry.request('react-block-1', 'const safe = true', 'ts');
    expect(strictReplay).toBe(first);
    await expect(first).resolves.toMatchObject({ result: fixed, reason: null });
    expect(tokenise).toHaveBeenCalledTimes(1);

    await registry.request('react-block-2', 'const safe = true', 'ts');
    expect(tokenise, 'identical blocks share the exact tokenisation promise').toHaveBeenCalledTimes(1);
  });

  it('counts multiline newline text nodes at the exact and one-over aggregate rendering budget', async () => {
    const lineCount = MAX_HIGHLIGHT_RENDER_NODES_PER_BLOCK / 2;
    const fixed: FixedHighlightResult = {
      language: 'typescript',
      lines: Array.from({ length: lineCount }, (_, index) => (
        index === 0 ? [{ content: 'x', className: null }] : []
      )),
    };
    const registry = createHighlightJobRegistry(async () => fixed);
    const acceptedBlocks = MAX_HIGHLIGHT_RENDER_NODES_TOTAL / MAX_HIGHLIGHT_RENDER_NODES_PER_BLOCK;
    for (let index = 0; index < acceptedBlocks; index += 1) {
      await expect(registry.request(`owner-${index}`, `code-${index}`, 'ts'))
        .resolves.toMatchObject({ result: fixed, reason: null });
    }
    await expect(registry.request('aggregate-over', 'aggregate-over', 'ts')).resolves.toMatchObject({
      result: null,
      reason: 'Plain code: message highlight rendering budget reached.',
    });
  });

  it('falls back at the fixed highlight job budget', async () => {
    const jobRegistry = createHighlightJobRegistry(async () => ({
      language: 'typescript',
      lines: [[{ content: 'x', className: null }]],
    }));
    for (let index = 0; index < MAX_HIGHLIGHT_JOBS; index += 1) {
      await expect(jobRegistry.request(`job-${index}`, `x${index}`, 'ts'))
        .resolves.toMatchObject({ reason: null });
    }
    await expect(jobRegistry.request('job-over', 'over', 'ts')).resolves.toMatchObject({
      result: null,
      reason: 'Plain code: message highlight work budget reached.',
    });
  });
});
