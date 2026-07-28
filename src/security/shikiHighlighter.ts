import {
  isWithinHighlightBounds,
  MAX_LOGICAL_LINE_UTF16,
} from './markdownPolicy';

export const HIGHLIGHT_LANGUAGE_ALIASES = Object.freeze({
  bash: 'bash',
  css: 'css',
  html: 'html',
  javascript: 'javascript',
  js: 'javascript',
  json: 'json',
  markdown: 'markdown',
  md: 'markdown',
  rust: 'rust',
  rs: 'rust',
  shell: 'bash',
  sh: 'bash',
  ts: 'typescript',
  tsx: 'tsx',
  typescript: 'typescript',
});

export type HighlightLanguage = (typeof HIGHLIGHT_LANGUAGE_ALIASES)[keyof typeof HIGHLIGHT_LANGUAGE_ALIASES];
export type FixedTokenClass =
  | 'tok-attribute'
  | 'tok-comment'
  | 'tok-constant'
  | 'tok-function'
  | 'tok-invalid'
  | 'tok-keyword'
  | 'tok-number'
  | 'tok-parameter'
  | 'tok-string'
  | 'tok-tag'
  | 'tok-type'
  | 'tok-variable';

export type FixedHighlightToken = Readonly<{
  content: string;
  className: FixedTokenClass | null;
}>;

export type FixedHighlightLine = readonly FixedHighlightToken[];
export type FixedHighlightResult = Readonly<{
  language: HighlightLanguage;
  lines: readonly FixedHighlightLine[];
}>;

export const MAX_HIGHLIGHT_RENDER_NODES_PER_BLOCK = 2_000;
export const MAX_HIGHLIGHT_RENDER_NODES_TOTAL = 10_000;
export const MAX_HIGHLIGHT_JOBS = 64;
export const MAX_HIGHLIGHT_WORK_UTF16_PER_BLOCK = 32_768;
export const MAX_HIGHLIGHT_WORK_UTF16_TOTAL = 65_536;

export type HighlightJobOutcome = Readonly<{
  result: FixedHighlightResult | null;
  reason: string | null;
}>;

export type HighlightFunction = (
  code: string,
  languageName: string | undefined,
) => Promise<FixedHighlightResult | null>;

export type HighlightJobRegistry = Readonly<{
  request: (
    ownerId: string,
    code: string,
    languageName: string | undefined,
  ) => Promise<HighlightJobOutcome>;
}>;

type ShikiToken = Readonly<{
  content: string;
  explanation?: readonly Readonly<{
    scopes: readonly Readonly<{ scopeName: string }>[];
  }>[];
}>;

type FixedHighlighter = Readonly<{
  codeToTokens: (
    code: string,
    options: Readonly<{
      lang: HighlightLanguage;
      theme: 'github-dark-default';
      includeExplanation: 'scopeName';
      tokenizeMaxLineLength: number;
      tokenizeTimeLimit: number;
    }>,
  ) => Readonly<{ tokens: readonly (readonly ShikiToken[])[] }>;
}>;

export type FixedHighlighterLoader = () => Promise<FixedHighlighter>;

let highlighterPromise: Promise<FixedHighlighter> | null = null;

/**
 * Shiki exposes stable TextMate scope explanations from `codeToTokens`. This
 * adapter deliberately ignores token colours, inline styles, attributes and
 * HTML, and maps only recognised scope prefixes to a closed CSS class set.
 */
function classForScopes(scopes: readonly string[]): FixedTokenClass | null {
  const joined = scopes.join(' ');
  if (/\binvalid\b/.test(joined)) return 'tok-invalid';
  if (/\bcomment\b/.test(joined)) return 'tok-comment';
  if (/\bstring\b|\bregexp\b/.test(joined)) return 'tok-string';
  if (/\bconstant\.numeric\b/.test(joined)) return 'tok-number';
  if (/\bentity\.name\.tag\b/.test(joined)) return 'tok-tag';
  if (/\bentity\.other\.attribute-name\b/.test(joined)) return 'tok-attribute';
  if (/\bentity\.name\.(?:function|method)\b|\bsupport\.function\b/.test(joined)) {
    return 'tok-function';
  }
  if (/\bentity\.name\.(?:type|class|struct|enum|trait)\b|\bsupport\.type\b/.test(joined)) {
    return 'tok-type';
  }
  if (/\bvariable\.parameter\b/.test(joined)) return 'tok-parameter';
  if (/\bkeyword\b|\bstorage\.(?:type|modifier)\b/.test(joined)) return 'tok-keyword';
  if (/\bconstant\b/.test(joined)) return 'tok-constant';
  if (/\bvariable\b/.test(joined)) return 'tok-variable';
  return null;
}

export function resolveHighlightLanguage(value: string | undefined): HighlightLanguage | null {
  if (!value || !/^[a-z][a-z0-9-]{0,31}$/.test(value)) return null;
  return HIGHLIGHT_LANGUAGE_ALIASES[value as keyof typeof HIGHLIGHT_LANGUAGE_ALIASES] ?? null;
}

export async function loadFixedHighlighter(): Promise<FixedHighlighter> {
  if (!highlighterPromise) {
    highlighterPromise = (async () => {
      const [
        core,
        engine,
        theme,
        bash,
        css,
        html,
        javascript,
        json,
        markdown,
        rust,
        tsx,
        typescript,
      ] = await Promise.all([
        import('shiki/core'),
        import('shiki/engine/javascript'),
        import('shiki/themes/github-dark-default.mjs'),
        import('shiki/langs/bash.mjs'),
        import('shiki/langs/css.mjs'),
        import('shiki/langs/html.mjs'),
        import('shiki/langs/javascript.mjs'),
        import('shiki/langs/json.mjs'),
        import('shiki/langs/markdown.mjs'),
        import('shiki/langs/rust.mjs'),
        import('shiki/langs/tsx.mjs'),
        import('shiki/langs/typescript.mjs'),
      ]);
      return core.createHighlighterCore({
        engine: engine.createJavaScriptRegexEngine(),
        themes: [theme.default],
        langs: [
          ...bash.default,
          ...css.default,
          ...html.default,
          ...javascript.default,
          ...json.default,
          ...markdown.default,
          ...rust.default,
          ...tsx.default,
          ...typescript.default,
        ],
      }) as Promise<FixedHighlighter>;
    })().catch((error: unknown) => {
      highlighterPromise = null;
      throw error;
    });
  }
  return highlighterPromise;
}

export function highlightRenderNodeCount(result: FixedHighlightResult): number {
  const newlineTextNodes = Math.max(0, result.lines.length - 1);
  return result.lines.reduce(
    (total, line) => total + 1 + line.reduce(
      (lineTotal, token) => lineTotal + (token.className === null ? 1 : 2),
      0,
    ),
    newlineTextNodes,
  );
}

export async function highlightCode(
  code: string,
  languageName: string | undefined,
  loader: FixedHighlighterLoader = loadFixedHighlighter,
): Promise<FixedHighlightResult | null> {
  const language = resolveHighlightLanguage(languageName);
  if (
    !language ||
    !isWithinHighlightBounds(code) ||
    code.length > MAX_HIGHLIGHT_WORK_UTF16_PER_BLOCK
  ) {
    return null;
  }

  const highlighter = await loader();
  const result = highlighter.codeToTokens(code, {
    lang: language,
    theme: 'github-dark-default',
    includeExplanation: 'scopeName',
    tokenizeMaxLineLength: MAX_LOGICAL_LINE_UTF16,
    tokenizeTimeLimit: 2_000,
  });
  const lines: FixedHighlightLine[] = [];
  let renderNodes = result.tokens.length + Math.max(0, result.tokens.length - 1);
  if (renderNodes > MAX_HIGHLIGHT_RENDER_NODES_PER_BLOCK) return null;

  for (const line of result.tokens) {
    const fixedLine: FixedHighlightToken[] = [];
    for (const token of line) {
      const scopes = token.explanation?.flatMap((entry) =>
        entry.scopes.map((scope) => scope.scopeName),
      ) ?? [];
      const className = classForScopes(scopes);
      renderNodes += className === null ? 1 : 2;
      if (renderNodes > MAX_HIGHLIGHT_RENDER_NODES_PER_BLOCK) return null;
      fixedLine.push(Object.freeze({
        content: token.content,
        className,
      }));
    }
    lines.push(Object.freeze(fixedLine));
  }

  return Object.freeze({
    language,
    lines: Object.freeze(lines),
  });
}

export function createHighlightJobRegistry(
  highlight: HighlightFunction = highlightCode,
): HighlightJobRegistry {
  const ownerJobs = new Map<string, Promise<HighlightJobOutcome>>();
  const tokenisationJobs = new Map<string, Promise<FixedHighlightResult | null>>();
  let reservedWorkUnits = 0;
  let acceptedRenderNodes = 0;

  return Object.freeze({
    request(ownerId, code, languageName) {
      const existingOwner = ownerJobs.get(ownerId);
      if (existingOwner) return existingOwner;

      const language = resolveHighlightLanguage(languageName);
      if (
        !language ||
        ownerJobs.size >= MAX_HIGHLIGHT_JOBS ||
        code.length > MAX_HIGHLIGHT_WORK_UTF16_PER_BLOCK ||
        reservedWorkUnits + code.length > MAX_HIGHLIGHT_WORK_UTF16_TOTAL
      ) {
        return Promise.resolve(Object.freeze({
          result: null,
          reason: 'Plain code: message highlight work budget reached.',
        }));
      }

      reservedWorkUnits += code.length;
      const tokenisationKey = JSON.stringify([language, code]);
      let tokenisation = tokenisationJobs.get(tokenisationKey);
      if (!tokenisation) {
        tokenisation = Promise.resolve().then(() => highlight(code, language));
        tokenisationJobs.set(tokenisationKey, tokenisation);
      }
      const job = tokenisation.then((result): HighlightJobOutcome => {
        if (!result) {
          return Object.freeze({
            result: null,
            reason: 'Plain code: per-block highlight rendering budget reached.',
          });
        }
        const renderNodes = highlightRenderNodeCount(result);
        if (
          renderNodes > MAX_HIGHLIGHT_RENDER_NODES_PER_BLOCK ||
          acceptedRenderNodes + renderNodes > MAX_HIGHLIGHT_RENDER_NODES_TOTAL
        ) {
          return Object.freeze({
            result: null,
            reason: 'Plain code: message highlight rendering budget reached.',
          });
        }
        acceptedRenderNodes += renderNodes;
        return Object.freeze({ result, reason: null });
      });
      ownerJobs.set(ownerId, job);
      return job;
    },
  });
}
