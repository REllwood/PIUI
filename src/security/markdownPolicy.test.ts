import { describe, expect, it } from 'vitest';
import {
  MAX_ACTIVE_DESTINATION_SCALARS,
  MAX_ASSET_BYTES,
  MAX_CODE_BLOCKS,
  MAX_CODE_BLOCK_UTF16,
  MAX_CODE_TOTAL_UTF16,
  MAX_DIRECT_CHILDREN,
  MAX_HIGHLIGHT_BYTES,
  MAX_HIGHLIGHT_LINES,
  MAX_LINKS_AND_IMAGES,
  MAX_LOGICAL_LINE_UTF16,
  MAX_MARKDOWN_UTF16,
  MAX_MARKDOWN_UTF8,
  MAX_PARSER_DEPTH,
  MAX_PARSER_ELEMENTS,
  MAX_RAW_AUDIT_SNIPPETS,
  MAX_RAW_AUDIT_SNIPPET_UTF16,
  MAX_RAW_AUDIT_TOTAL_UTF16,
  boundedAltText,
  extractRawHtmlAudit,
  highlightLineCount,
  isOpaqueAssetCapability,
  isWithinHighlightBounds,
  isWithinMarkdownUtf8Limit,
  normaliseUntrustedText,
  prepareMarkdown,
  safeMarkdownUrlTransform,
  validateExternalHttps,
  utf8Length,
  validateOpaqueAssetDescriptor,
  type OpaqueAssetDescriptor,
} from './markdownPolicy';

const validCapability = 'piui-asset-0123456789abcdef0123456789abcdef';
const validOrigin = 'http://127.0.0.1:1420';
const validAsset: OpaqueAssetDescriptor = {
  url: `${validOrigin}/__piui_markdown_asset__/0123456789abcdef0123456789abcdef.png`,
  mime: 'image/png',
  byteLength: 68,
  expiresAt: 2_000,
};

describe('external HTTPS policy', () => {
  it.each([
    '',
    ' https://safe.example.invalid/',
    'https://safe.example.invalid/ ',
    'HTTPS://safe.example.invalid/',
    'http://safe.example.invalid/',
    '//safe.example.invalid/',
    '/relative',
    'relative',
    '#fragment',
    'javascript:alert(1)',
    'java\tscript:alert(1)',
    'java\nscript:alert(1)',
    'java\u00a0script:alert(1)',
    'java\u200bscript:alert(1)',
    'java\u202escript:alert(1)',
    'java&#x73;cript&#x3a;alert(1)',
    'java&amp;#x73;cript&amp;#x3a;alert(1)',
    '%6aavascript%3aalert(1)',
    '%256aavascript%253aalert(1)',
    'https:%2f%2fsafe.example.invalid/',
    'https://safe%2eexample.invalid/',
    'https://safe.example.invalid/%2e%2e/file',
    'https://safe.example.invalid/#fragment',
    'https://user@safe.example.invalid/',
    'https://user:pass@safe.example.invalid/',
    'https://safe.example.invalid:444/',
    'https://safe.example.invalid\\@evil.example.invalid/',
    'https://127.0.0.1/',
    'https://localhost/',
    'https://safe.example.invalid./',
    'https://ｓａｆｅ.example.invalid/',
    'file:///synthetic/private/file',
    'data:text/html,probe',
    'blob:https://safe.example.invalid/id',
    'asset://localhost/synthetic',
    'tauri://localhost/host_status',
    'ipc://localhost/bridge_send',
    'vbscript:msgbox(1)',
    'piui-command:host_status',
    `https://safe.example.invalid/${'a'.repeat(MAX_ACTIVE_DESTINATION_SCALARS)}`,
  ])('rejects %j', (candidate) => {
    expect(validateExternalHttps(candidate)).toBeNull();
  });

  it('returns only a branded canonical target for a strict absolute HTTPS URL', () => {
    const target = validateExternalHttps('https://SAFE.example.invalid:443/guide?q=visible');
    expect(target).toMatchObject({
      canonicalUrl: 'https://safe.example.invalid/guide?q=visible',
      displayOrigin: 'https://safe.example.invalid',
    });
    expect(Object.isFrozen(target)).toBe(true);
  });

  it('uses the same pure transform for parser links and denies every other URL property', () => {
    expect(safeMarkdownUrlTransform('https://safe.example.invalid', 'href')).toBe(
      'https://safe.example.invalid/',
    );
    expect(safeMarkdownUrlTransform('javascript:alert(1)', 'href')).toBeUndefined();
    expect(safeMarkdownUrlTransform(validCapability, 'src')).toBe(validCapability);
    expect(safeMarkdownUrlTransform('https://image.example.invalid/x.png', 'src')).toBeUndefined();
    expect(safeMarkdownUrlTransform('https://safe.example.invalid', 'poster')).toBeUndefined();
  });
});

describe('opaque local asset policy', () => {
  it('accepts only the exact lowercase host-minted capability grammar', () => {
    expect(isOpaqueAssetCapability(validCapability)).toBe(true);
    for (const candidate of [
      'piui-asset-0123456789ABCDEF0123456789ABCDEF',
      'piui-asset-0123',
      'piui-asset-0123456789abcdef0123456789abcdef/extra',
      'asset:0123456789abcdef0123456789abcdef',
      '/synthetic/private/image.png',
    ]) {
      expect(isOpaqueAssetCapability(candidate)).toBe(false);
    }
  });

  it('accepts only exact raster MIME/path pairs at the byte and expiry boundaries', () => {
    const cases = [
      ['image/png', 'png'],
      ['image/jpeg', 'jpg'],
      ['image/webp', 'webp'],
    ] as const;
    for (const [mime, extension] of cases) {
      const descriptor = {
        ...validAsset,
        mime,
        url: `${validOrigin}/__piui_markdown_asset__/0123456789abcdef0123456789abcdef.${extension}`,
        byteLength: MAX_ASSET_BYTES,
        expiresAt: 1_001,
      };
      expect(validateOpaqueAssetDescriptor(validCapability, descriptor, 1_000, validOrigin)).toEqual({
        url: descriptor.url,
        mime,
        byteLength: MAX_ASSET_BYTES,
      });
      expect(validateOpaqueAssetDescriptor(validCapability, descriptor, 1_001, validOrigin)).toBeNull();
      expect(
        validateOpaqueAssetDescriptor(
          validCapability,
          { ...descriptor, byteLength: MAX_ASSET_BYTES + 1 },
          1_000,
          validOrigin,
        ),
      ).toBeNull();
    }

    expect(
      validateOpaqueAssetDescriptor(validCapability, { ...validAsset, byteLength: 1 }, 1_000, validOrigin),
    ).not.toBeNull();
    expect(
      validateOpaqueAssetDescriptor(validCapability, { ...validAsset, byteLength: 0 }, 1_000, validOrigin),
    ).toBeNull();
  });

  it('fails closed for runtime-forged MIME, time, origin and path data', () => {
    const forgedMime = { ...validAsset, mime: 'image/svg+xml' } as unknown as OpaqueAssetDescriptor;
    for (const [descriptor, now, origin] of [
      [forgedMime, 1_000, validOrigin],
      [{ ...validAsset, url: 'https://asset-probe.invalid/image.png' }, 1_000, validOrigin],
      [{ ...validAsset, url: `${validOrigin}/synthetic/private/image.png` }, 1_000, validOrigin],
      [{ ...validAsset, url: `${validAsset.url}?substituted=1` }, 1_000, validOrigin],
      [validAsset, Number.NaN, validOrigin],
      [validAsset, 1_000, `${validOrigin}/not-an-origin`],
    ] as const) {
      expect(validateOpaqueAssetDescriptor(validCapability, descriptor, now, origin)).toBeNull();
    }
  });
});

describe('pre-parser resource bounds', () => {
  it('normalises invalid surrogates and display-affecting controls', () => {
    expect(normaliseUntrustedText(`safe\ud800\u0000\u202etext`)).toBe('safe���text');
    expect(boundedAltText('  local\u0000   image  ')).toBe('local� image');
  });

  it('keeps ordinary bounded GFM eligible for parsing', () => {
    const prepared = prepareMarkdown('# Heading\n\n| A | B |\n| - | - |\n| 1 | 2 |');
    expect(prepared.mode).toBe('markdown');
    expect(prepared.shortened).toBe(false);
  });

  it('bypasses parsing for source, line, destination-count, depth, complexity and code bounds', () => {
    const cases = [
      `${'a'.repeat(10_000)}\n`.repeat(26) + 'a'.repeat(2_145),
      'a'.repeat(MAX_LOGICAL_LINE_UTF16 + 1),
      Array.from({ length: MAX_LINKS_AND_IMAGES + 1 }, (_, index) => `[x${index}](relative)`).join('\n'),
      `${'> '.repeat(33)}nested`,
      '*'.repeat(10_001),
      `\`\`\`text\n${'c'.repeat(MAX_CODE_BLOCK_UTF16 + 1)}\n\`\`\``,
    ];
    expect(cases[0].length).toBeGreaterThan(MAX_MARKDOWN_UTF16);
    for (const candidate of cases) {
      const prepared = prepareMarkdown(candidate);
      expect(prepared.mode).toBe('plain');
      expect(prepared.notice).toBe('Content shortened for safety.');
      expect(prepared.source.length).toBeLessThanOrEqual(65_536);
    }
  });

  it('enforces exact link and fenced-code aggregate limits before parsing', () => {
    const exactLinks = Array.from(
      { length: MAX_LINKS_AND_IMAGES },
      (_, index) => `[link ${index}](https://safe.example.invalid/${index})`,
    ).join('\n');
    const tooManyBlocks = Array.from({ length: 65 }, () => '```text\nsafe\n```').join('\n');
    const tooMuchCode = Array.from(
      { length: 5 },
      () => `\`\`\`text\n${'c'.repeat(16_000)}\n${'d'.repeat(15_998)}\n\`\`\``,
    ).join('\n');
    expect(prepareMarkdown(exactLinks).mode).toBe('markdown');
    expect(prepareMarkdown(`${exactLinks}\n[one too many](relative)`).mode).toBe('plain');
    expect(prepareMarkdown(tooManyBlocks).mode).toBe('plain');
    expect(prepareMarkdown(tooMuchCode).mode).toBe('plain');
  });

  it('allows the exact source-unit cap when all subordinate limits pass', () => {
    const chunk = `${'a'.repeat(16_000)}\n`;
    const repeated = chunk.repeat(Math.floor(MAX_MARKDOWN_UTF16 / chunk.length));
    const exact = repeated + 'a'.repeat(MAX_MARKDOWN_UTF16 - repeated.length);
    expect(exact.length).toBe(MAX_MARKDOWN_UTF16);
    expect(prepareMarkdown(exact).mode).toBe('markdown');
    expect(prepareMarkdown(`${exact}a`).mode).toBe('plain');
  });

  it('locks exact and one-over UTF-8, logical-line, element, depth and child boundaries', () => {
    expect(utf8Length('a'.repeat(MAX_MARKDOWN_UTF8))).toBe(MAX_MARKDOWN_UTF8);
    expect(isWithinMarkdownUtf8Limit('a'.repeat(MAX_MARKDOWN_UTF8))).toBe(true);
    expect(utf8Length(`${'a'.repeat(MAX_MARKDOWN_UTF8)}a`)).toBe(MAX_MARKDOWN_UTF8 + 1);
    expect(isWithinMarkdownUtf8Limit(`${'a'.repeat(MAX_MARKDOWN_UTF8)}a`)).toBe(false);

    expect(prepareMarkdown('a'.repeat(MAX_LOGICAL_LINE_UTF16)).mode).toBe('markdown');
    expect(prepareMarkdown('a'.repeat(MAX_LOGICAL_LINE_UTF16 + 1)).mode).toBe('plain');

    expect(prepareMarkdown('*'.repeat(MAX_PARSER_ELEMENTS - 2)).mode).toBe('markdown');
    expect(prepareMarkdown('*'.repeat(MAX_PARSER_ELEMENTS - 1)).mode).toBe('plain');

    expect(prepareMarkdown(`${'> '.repeat(MAX_PARSER_DEPTH)}safe`).mode).toBe('markdown');
    expect(prepareMarkdown(`${'> '.repeat(MAX_PARSER_DEPTH + 1)}safe`).mode).toBe('plain');

    const exactChildren = Array.from({ length: MAX_DIRECT_CHILDREN }, () => 'safe').join('\n');
    expect(prepareMarkdown(exactChildren).mode).toBe('markdown');
    expect(prepareMarkdown(`${exactChildren}\nsafe`).mode).toBe('plain');
  });

  it('locks exact and one-over fenced code block, aggregate and block-count boundaries', () => {
    const payload = (countedUnits: number) => {
      const lines: string[] = [];
      let remaining = countedUnits;
      while (remaining > 0) {
        const lineLength = Math.min(8_000, Math.max(0, remaining - 1));
        lines.push('c'.repeat(lineLength));
        remaining -= lineLength + 1;
      }
      return lines.join('\n');
    };
    const block = (countedUnits: number) => `\`\`\`text\n${payload(countedUnits)}\n\`\`\``;

    expect(prepareMarkdown(block(MAX_CODE_BLOCK_UTF16)).mode).toBe('markdown');
    expect(prepareMarkdown(block(MAX_CODE_BLOCK_UTF16 + 1)).mode).toBe('plain');

    const exactAggregate = Array.from(
      { length: MAX_CODE_TOTAL_UTF16 / MAX_CODE_BLOCK_UTF16 },
      () => block(MAX_CODE_BLOCK_UTF16),
    ).join('\n');
    const overAggregate = `${exactAggregate}\n${block(1)}`;
    expect(prepareMarkdown(exactAggregate).mode).toBe('markdown');
    expect(prepareMarkdown(overAggregate).mode).toBe('plain');

    const exactBlocks = Array.from({ length: MAX_CODE_BLOCKS }, () => block(1)).join('\n');
    expect(prepareMarkdown(exactBlocks).mode).toBe('markdown');
    expect(prepareMarkdown(`${exactBlocks}\n${block(1)}`).mode).toBe('plain');
  });

  it('locks space-indented code limits and sends every tab-bearing source to bounded fallback', () => {
    const payloadLines = (countedUnits: number) => {
      const lines: string[] = [];
      let remaining = countedUnits;
      while (remaining > 0) {
        const lineLength = Math.min(8_000, Math.max(0, remaining - 1));
        lines.push('c'.repeat(lineLength));
        remaining -= lineLength + 1;
      }
      return lines;
    };
    const indentedBlock = (countedUnits: number, prefix = '    ') =>
      payloadLines(countedUnits).map((line) => `${prefix}${line}`).join('\n');
    const separate = (blocks: readonly string[]) => blocks.join('\n\nprose separator\n\n');

    expect(prepareMarkdown(indentedBlock(MAX_CODE_BLOCK_UTF16)).mode).toBe('markdown');
    expect(prepareMarkdown(indentedBlock(MAX_CODE_BLOCK_UTF16 + 1)).mode).toBe('plain');
    expect(prepareMarkdown(indentedBlock(MAX_CODE_BLOCK_UTF16, '\t'))).toMatchObject({
      mode: 'plain',
      notice: 'Content shortened for safety.',
    });
    expect(prepareMarkdown('ordinary\tprose')).toMatchObject({
      mode: 'plain',
      notice: 'Content shortened for safety.',
    });

    const exactAggregate = separate(Array.from(
      { length: MAX_CODE_TOTAL_UTF16 / MAX_CODE_BLOCK_UTF16 },
      () => indentedBlock(MAX_CODE_BLOCK_UTF16),
    ));
    expect(prepareMarkdown(exactAggregate).mode).toBe('markdown');
    expect(prepareMarkdown(`${exactAggregate}\n\nprose separator\n\n    x`).mode).toBe('plain');

    const exactBlocks = separate(Array.from(
      { length: MAX_CODE_BLOCKS },
      () => '    x',
    ));
    expect(prepareMarkdown(exactBlocks).mode).toBe('markdown');
    expect(prepareMarkdown(`${exactBlocks}\n\nprose separator\n\n\tx`).mode).toBe('plain');
  });

  it('accounts for quoted and listed code before parsing', () => {
    const payloadLines = (countedUnits: number) => {
      const lines: string[] = [];
      let remaining = countedUnits;
      while (remaining > 0) {
        const lineLength = Math.min(8_000, Math.max(0, remaining - 1));
        lines.push('c'.repeat(lineLength));
        remaining -= lineLength + 1;
      }
      return lines;
    };
    const quotedFence = (countedUnits: number) => [
      '> > ```text',
      ...payloadLines(countedUnits).map((line) => `> > ${line}`),
      '> > ```',
    ].join('\n');
    const listedIndent = (countedUnits: number) => payloadLines(countedUnits).map(
      (line, index) => index === 0 ? `-     ${line}` : `      ${line}`,
    ).join('\n');
    const quotedIndent = (countedUnits: number, indentation = '    ') => payloadLines(countedUnits)
      .map((line) => `> ${indentation}${line}`)
      .join('\n');
    for (const block of [
      quotedFence(MAX_CODE_BLOCK_UTF16),
      listedIndent(MAX_CODE_BLOCK_UTF16),
      quotedIndent(MAX_CODE_BLOCK_UTF16),
    ]) {
      const prepared = prepareMarkdown(block);
      expect(prepared.mode).toBe('markdown');
      expect(prepared.source).toBe(block);
    }
    for (const block of [
      quotedFence(MAX_CODE_BLOCK_UTF16 + 1),
      listedIndent(MAX_CODE_BLOCK_UTF16 + 1),
      quotedIndent(MAX_CODE_BLOCK_UTF16 + 1),
    ]) {
      expect(prepareMarkdown(block)).toMatchObject({
        mode: 'plain',
        notice: 'Content shortened for safety.',
      });
    }
  });

  it('fails closed before parsing tab-bearing quote and list containers', () => {
    const payload = 'c'.repeat(8_000);
    for (const source of [
      '>\t```ts\n>\tx\n>\t```',
      `>\t  ${payload}`,
      `>    \t${payload}`,
      `-\t${payload}`,
      `> -\t\`\`\`ts\n>   ${payload}\n>   \`\`\``,
      `> 1.\t\`\`\`ts\n>    ${payload}\n>    \`\`\``,
      `- outer\n\t\`\`\`ts\n\tx\n\t\`\`\``,
    ]) {
      expect(prepareMarkdown(source)).toMatchObject({
        mode: 'plain',
        notice: 'Content shortened for safety.',
      });
    }
  });

  it('locks nested list-and-quote per-block, aggregate and block-count boundaries', () => {
    const payloadLines = (countedUnits: number) => {
      const lines: string[] = [];
      let remaining = countedUnits;
      while (remaining > 0) {
        const lineLength = Math.min(8_000, Math.max(0, remaining - 1));
        lines.push('c'.repeat(lineLength));
        remaining -= lineLength + 1;
      }
      return lines;
    };
    const block = (countedUnits: number) => [
      '- > ```text',
      ...payloadLines(countedUnits).map((line) => `  > ${line}`),
      '  > ```',
    ].join('\n');
    const separate = (blocks: readonly string[]) => blocks.join('\n\nprose separator\n\n');

    const exactBlock = block(MAX_CODE_BLOCK_UTF16);
    expect(prepareMarkdown(exactBlock)).toMatchObject({ mode: 'markdown', source: exactBlock });
    expect(prepareMarkdown(block(MAX_CODE_BLOCK_UTF16 + 1)).mode).toBe('plain');

    const exactAggregate = separate(Array.from(
      { length: MAX_CODE_TOTAL_UTF16 / MAX_CODE_BLOCK_UTF16 },
      () => block(MAX_CODE_BLOCK_UTF16),
    ));
    expect(prepareMarkdown(exactAggregate).mode).toBe('markdown');
    const overAggregate = `${exactAggregate}\n\nprose separator\n\n${block(1)}`;
    const aggregateFallback = prepareMarkdown(overAggregate);
    expect(aggregateFallback).toMatchObject({
      mode: 'plain',
      shortened: true,
      notice: 'Content shortened for safety.',
    });
    expect(aggregateFallback.source.length).toBeLessThanOrEqual(65_536);

    const exactBlocks = separate(Array.from({ length: MAX_CODE_BLOCKS }, () => block(1)));
    expect(prepareMarkdown(exactBlocks).mode).toBe('markdown');
    expect(prepareMarkdown(`${exactBlocks}\n\nprose separator\n\n${block(1)}`).mode).toBe('plain');
  });

  it('audits HTML, custom-tag and CDATA candidates with bounded excerpts including late source', () => {
    const late = `${'ordinary prose '.repeat(800)}<late-probe onclick="hostile">late</late-probe>`;
    const lateCdata = `${'late CDATA filler '.repeat(600)}<![CDATA[<img src="/late-cdata-canary.png">]]>`;
    const source = [
      '<a href="/same-origin-canary">anchor</a>',
      '<div onclick="hostile">division</div>',
      '<picture><source srcset="/source-canary"></picture>',
      '<custom-element hostile="true">custom</custom-element>',
      '<![CDATA[<img src="/early-cdata-canary.png">]]>',
      late,
      lateCdata,
    ].join('\n');
    expect(source.lastIndexOf('<![CDATA[')).toBeGreaterThan(MAX_RAW_AUDIT_TOTAL_UTF16);
    const prepared = prepareMarkdown(source);
    expect(prepared.rawHtmlOmitted).toBe(true);
    const auditText = prepared.rawHtmlAudit.excerpts.join('\n\n');
    for (const expected of [
      '<a href=',
      '<div onclick=',
      '<picture>',
      '<source srcset=',
      '<custom-element',
      '<![CDATA[<img src="/early-cdata-canary.png">]]>',
      '<late-probe',
      '<![CDATA[<img src="/late-cdata-canary.png">]]>',
    ]) {
      expect(auditText).toContain(expected);
    }
    expect(auditText.length).toBeLessThanOrEqual(MAX_RAW_AUDIT_TOTAL_UTF16);

    const unterminated = extractRawHtmlAudit('<![CDATA[/synthetic/private/unterminated-cdata-canary');
    expect(unterminated.candidateCount).toBe(1);
    expect(unterminated.excerpts.join('')).toContain('unterminated-cdata-canary');

    const terminated = extractRawHtmlAudit(
      '<![CDATA[/synthetic/private/terminated-cdata-canary]]>'
      + 'x'.repeat(65)
      + 'post-terminator-canary',
    );
    expect(terminated.excerpts.join('')).toContain('terminated-cdata-canary]]>');
    expect(terminated.excerpts.join('')).not.toContain('post-terminator-canary');

    const many = extractRawHtmlAudit(Array.from(
      { length: MAX_RAW_AUDIT_SNIPPETS + 20 },
      (_, index) => `<probe-${index}>value</probe-${index}>`,
    ).join('\n'));
    expect(many.excerpts.length).toBeLessThanOrEqual(MAX_RAW_AUDIT_SNIPPETS);
    expect(many.excerpts.every((excerpt) => excerpt.length <= MAX_RAW_AUDIT_SNIPPET_UTF16)).toBe(true);
    expect(many.excerpts.join('\n\n').length).toBeLessThanOrEqual(MAX_RAW_AUDIT_TOTAL_UTF16);
    expect(many.shortened).toBe(true);
  });

  it('locks exact highlighting byte and line cut-offs', () => {
    expect(isWithinHighlightBounds('a'.repeat(MAX_HIGHLIGHT_BYTES - 1))).toBe(true);
    expect(isWithinHighlightBounds('a'.repeat(MAX_HIGHLIGHT_BYTES))).toBe(false);
    expect(highlightLineCount(Array.from({ length: MAX_HIGHLIGHT_LINES - 1 }, () => 'x').join('\n')))
      .toBe(MAX_HIGHLIGHT_LINES - 1);
    expect(
      isWithinHighlightBounds(Array.from({ length: MAX_HIGHLIGHT_LINES - 1 }, () => 'x').join('\n')),
    ).toBe(true);
    expect(
      isWithinHighlightBounds(Array.from({ length: MAX_HIGHLIGHT_LINES }, () => 'x').join('\n')),
    ).toBe(false);
  });
});
