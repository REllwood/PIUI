import {
  createContext,
  useContext,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
} from 'react';
import ReactMarkdown, { type AllowElement, type Components } from 'react-markdown';
import remarkGfm from 'remark-gfm';
import hostileFixture from '../../tests/fixtures/markdown/hostile.md?raw';
import {
  MAX_CODE_BLOCKS,
  MAX_CODE_BLOCK_UTF16,
  MAX_CODE_TOTAL_UTF16,
  MAX_DIRECT_CHILDREN,
  MAX_HIGHLIGHT_BYTES,
  MAX_HIGHLIGHT_LINES,
  MAX_LINKS_AND_IMAGES,
  MAX_PARSER_DEPTH,
  MAX_PARSER_ELEMENTS,
  boundedAltText,
  highlightLineCount,
  isOpaqueAssetCapability,
  isRasterMime,
  isWithinHighlightBounds,
  prepareMarkdown,
  safeMarkdownUrlTransform,
  utf8Length,
  validateExternalHttps,
  validateOpaqueAssetDescriptor,
  type OpaqueAssetDescriptor,
  type ValidatedExternalTarget,
} from './markdownPolicy';
import {
  createHighlightJobRegistry,
  resolveHighlightLanguage,
  type FixedHighlightResult,
  type HighlightJobRegistry,
} from './shikiHighlighter';

export type SafeMarkdownSpikeProps = Readonly<{
  markdown: string;
  assetRegistry: ReadonlyMap<string, OpaqueAssetDescriptor>;
  openExternal: (target: ValidatedExternalTarget) => void;
  complete?: boolean;
  applicationOrigin?: string;
}>;

type MarkdownAuthority = Readonly<{
  assetRegistry: ReadonlyMap<string, OpaqueAssetDescriptor>;
  openExternal: (target: ValidatedExternalTarget) => void;
  complete: boolean;
  applicationOrigin: string;
  highlightJobs: HighlightJobRegistry;
}>;

type MarkdownHarnessAsset = Readonly<{
  capability: string;
  url: string;
  mime: unknown;
  byteLength: number;
  expiresAt: number;
}>;

type MarkdownHarness = Readonly<{
  markdown?: string;
  assets?: readonly MarkdownHarnessAsset[];
  complete?: boolean;
  openExternal?: (canonicalUrl: string) => void;
}>;

declare global {
  interface Window {
    __PIUI_MARKDOWN_HARNESS__?: MarkdownHarness;
  }
}

const AuthorityContext = createContext<MarkdownAuthority | null>(null);
const remarkPlugins = [remarkGfm];

const allowedElements = [
  'p',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'em',
  'strong',
  'del',
  'ul',
  'ol',
  'li',
  'blockquote',
  'hr',
  'br',
  'a',
  'img',
  'pre',
  'code',
  'table',
  'thead',
  'tbody',
  'tr',
  'th',
  'td',
  'input',
] as const;

function Paragraph({ children }: { children?: ReactNode }) {
  return <p>{children}</p>;
}

function HeadingTwo({ children }: { children?: ReactNode }) {
  return <h2>{children}</h2>;
}

function HeadingThree({ children }: { children?: ReactNode }) {
  return <h3>{children}</h3>;
}

function HeadingFour({ children }: { children?: ReactNode }) {
  return <h4>{children}</h4>;
}

function HeadingFive({ children }: { children?: ReactNode }) {
  return <h5>{children}</h5>;
}

function HeadingSix({ children }: { children?: ReactNode }) {
  return <h6>{children}</h6>;
}

function Emphasis({ children }: { children?: ReactNode }) {
  return <em>{children}</em>;
}

function Strong({ children }: { children?: ReactNode }) {
  return <strong>{children}</strong>;
}

function Deleted({ children }: { children?: ReactNode }) {
  return <del>{children}</del>;
}

function UnorderedList({ children }: { children?: ReactNode }) {
  return <ul>{children}</ul>;
}

function OrderedList({ children }: { children?: ReactNode }) {
  return <ol>{children}</ol>;
}

function ListItem({ children }: { children?: ReactNode }) {
  return <li>{children}</li>;
}

function BlockQuote({ children }: { children?: ReactNode }) {
  return <blockquote>{children}</blockquote>;
}

function ThematicBreak() {
  return <hr />;
}

function LineBreak() {
  return <br />;
}

function SafeExternalLink({ children, href }: { children?: ReactNode; href?: string }) {
  const authority = useContext(AuthorityContext);
  const descriptionId = `external-destination-${useId().replace(/:/g, '')}`;
  const target = typeof href === 'string' ? validateExternalHttps(href) : null;
  if (!authority || !target) {
    return (
      <span className="markdown__blocked-link">
        <span>{children}</span>
        <span className="markdown__blocked-label">Link blocked for safety</span>
      </span>
    );
  }

  const activate = (event: ReactMouseEvent<HTMLButtonElement>) => {
    if (!event.isTrusted) return;
    const revalidated = validateExternalHttps(target.canonicalUrl);
    if (revalidated) authority.openExternal(revalidated);
  };

  return (
    <span className="markdown__external-link">
      <button
        type="button"
        className="markdown__link-button"
        aria-describedby={descriptionId}
        onClick={activate}
      >
        {children}
      </button>
      <span id={descriptionId} className="markdown__external-disclosure">
        HTTPS destination: {target.canonicalUrl} · opens in your browser
      </span>
    </span>
  );
}

function OmittedAsset({ alt }: { alt?: string }) {
  const description = boundedAltText(alt);
  return (
    <span className="markdown__asset-omitted" role="note">
      <span aria-hidden="true">◇</span>
      <span>{description || 'No image description was provided'}</span>
      <span className="markdown__asset-reason">Image omitted for safety</span>
    </span>
  );
}

function SafeOpaqueImage({ src, alt }: { src?: string; alt?: string }) {
  const authority = useContext(AuthorityContext);
  if (!authority || typeof src !== 'string' || !isOpaqueAssetCapability(src)) {
    return <OmittedAsset alt={alt} />;
  }

  const validated = validateOpaqueAssetDescriptor(
    src,
    authority.assetRegistry.get(src),
    Date.now(),
    authority.applicationOrigin,
  );
  const description = boundedAltText(alt);
  if (!validated || !description) return <OmittedAsset alt={alt} />;

  return (
    <span className="markdown__asset-card">
      <img
        className="markdown__asset-image"
        src={validated.url}
        alt={description}
        loading="lazy"
        decoding="async"
      />
      <span className="markdown__asset-meta">Registered local image · {validated.mime}</span>
    </span>
  );
}

function useOverflowFocus<T extends HTMLElement>() {
  const elementRef = useRef<T>(null);
  const [overflowing, setOverflowing] = useState(false);

  useLayoutEffect(() => {
    const element = elementRef.current;
    if (!element) return;
    const measure = () => {
      setOverflowing(
        element.scrollWidth > element.clientWidth || element.scrollHeight > element.clientHeight,
      );
    };
    measure();
    const resizeObserver = new ResizeObserver(measure);
    const contentObserver = new MutationObserver(measure);
    resizeObserver.observe(element);
    contentObserver.observe(element, { childList: true, characterData: true, subtree: true });
    window.addEventListener('resize', measure);
    return () => {
      resizeObserver.disconnect();
      contentObserver.disconnect();
      window.removeEventListener('resize', measure);
    };
  }, []);

  return { elementRef, overflowing } as const;
}

function CodeBlock({ children }: { children?: ReactNode }) {
  const { elementRef, overflowing } = useOverflowFocus<HTMLPreElement>();
  return (
    <pre
      ref={elementRef}
      className="markdown__code-block"
      role={overflowing ? 'region' : undefined}
      tabIndex={overflowing ? 0 : undefined}
      aria-label={overflowing ? 'Scrollable code block' : undefined}
    >
      {children}
    </pre>
  );
}

function highlightedLines(result: FixedHighlightResult) {
  return result.lines.map((line, lineIndex) => (
    <span className="markdown__token-line" key={`line-${lineIndex}`}>
      {line.map((token, tokenIndex) => (
        token.className ? (
          <span className={token.className} key={`token-${lineIndex}-${tokenIndex}`}>
            {token.content}
          </span>
        ) : (
          token.content
        )
      ))}
      {lineIndex < result.lines.length - 1 ? '\n' : null}
    </span>
  ));
}

function SafeCode({ children, className }: { children?: ReactNode; className?: string }) {
  const authority = useContext(AuthorityContext);
  const ownerId = useId();
  const rawText = textFromReactChildren(children);
  const languageName = className?.match(/^language-([a-zA-Z0-9-]{1,64})$/)?.[1];
  const isBlock = typeof languageName === 'string';
  const text = isBlock && rawText?.endsWith('\n') ? rawText.slice(0, -1) : rawText;
  const language = resolveHighlightLanguage(languageName);
  const eligible = Boolean(authority?.complete && isBlock && text !== null && language && isWithinHighlightBounds(text));
  const highlightJobs = authority?.highlightJobs;
  const [highlighted, setHighlighted] = useState<FixedHighlightResult | null>(null);
  const [budgetReason, setBudgetReason] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let active = true;
    setHighlighted(null);
    setBudgetReason(null);
    setFailed(false);
    if (!eligible || text === null || !highlightJobs) return () => { active = false; };
    void highlightJobs.request(ownerId, text, languageName)
      .then((outcome) => {
        if (!active) return;
        setHighlighted(outcome.result);
        setBudgetReason(outcome.reason);
      })
      .catch(() => {
        if (active) setFailed(true);
      });
    return () => {
      active = false;
    };
  }, [eligible, highlightJobs, languageName, ownerId, text]);

  if (text === null) return <code>[Unsupported code omitted]</code>;
  if (!isBlock) return <code>{text}</code>;

  let reason: string | null = null;
  if (!authority?.complete) reason = 'Plain code: message is incomplete.';
  else if (!language) reason = 'Plain code: language is not enabled.';
  else if (utf8Length(text) >= MAX_HIGHLIGHT_BYTES) {
    reason = `Plain code: ${MAX_HIGHLIGHT_BYTES.toLocaleString('en-AU')} byte highlight limit reached.`;
  } else if (highlightLineCount(text) >= MAX_HIGHLIGHT_LINES) {
    reason = `Plain code: ${MAX_HIGHLIGHT_LINES.toLocaleString('en-AU')} line highlight limit reached.`;
  } else if (budgetReason) reason = budgetReason;
  else if (failed) reason = 'Plain code: syntax highlighting was unavailable.';
  const highlighting = eligible && !highlighted && !budgetReason && !failed;

  return (
    <code
      data-highlight-status={highlighted ? 'tokens' : 'plain'}
      data-language={language ?? 'plain'}
      aria-busy={highlighting}
    >
      {highlighting ? (
        <span className="markdown__code-loading" role="status">
          <span className="markdown-probe__spinner" aria-hidden="true" />
          Preparing syntax highlighting…
        </span>
      ) : null}
      {reason ? <span className="markdown__code-reason">{reason}</span> : null}
      {highlighted ? highlightedLines(highlighted) : text}
    </code>
  );
}

function SafeTable({ children }: { children?: ReactNode }) {
  const { elementRef, overflowing } = useOverflowFocus<HTMLDivElement>();
  return (
    <div
      ref={elementRef}
      className="markdown__table-scroll"
      role={overflowing ? 'region' : undefined}
      aria-label={overflowing ? 'Scrollable Markdown table' : undefined}
      tabIndex={overflowing ? 0 : undefined}
    >
      <table>{children}</table>
    </div>
  );
}

function TableHead({ children }: { children?: ReactNode }) {
  return <thead>{children}</thead>;
}

function TableBody({ children }: { children?: ReactNode }) {
  return <tbody>{children}</tbody>;
}

function TableRow({ children }: { children?: ReactNode }) {
  return <tr>{children}</tr>;
}

function TableHeader({ children }: { children?: ReactNode }) {
  return <th>{children}</th>;
}

function TableCell({ children }: { children?: ReactNode }) {
  return <td>{children}</td>;
}

function SafeTaskInput({ checked, type }: { checked?: boolean; type?: string }) {
  if (type !== 'checkbox') return <span>[Unsupported input omitted]</span>;
  return (
    <input
      type="checkbox"
      checked={checked === true}
      readOnly
      disabled
      aria-label={checked === true ? 'Completed task' : 'Incomplete task'}
    />
  );
}

function textFromReactChildren(children: ReactNode): string | null {
  if (children === null || children === undefined || typeof children === 'boolean') return '';
  if (typeof children === 'string' || typeof children === 'number') return String(children);
  if (Array.isArray(children)) {
    let result = '';
    for (const child of children) {
      const text = textFromReactChildren(child);
      if (text === null) return null;
      result += text;
    }
    return result;
  }
  return null;
}

const safeComponents: Components = {
  p: Paragraph,
  h1: HeadingTwo,
  h2: HeadingThree,
  h3: HeadingFour,
  h4: HeadingFive,
  h5: HeadingSix,
  h6: HeadingSix,
  em: Emphasis,
  strong: Strong,
  del: Deleted,
  ul: UnorderedList,
  ol: OrderedList,
  li: ListItem,
  blockquote: BlockQuote,
  hr: ThematicBreak,
  br: LineBreak,
  a: SafeExternalLink,
  img: SafeOpaqueImage,
  pre: CodeBlock,
  code: SafeCode,
  table: SafeTable,
  thead: TableHead,
  tbody: TableBody,
  tr: TableRow,
  th: TableHeader,
  td: TableCell,
  input: SafeTaskInput,
};

function createParserOutputGuard(): AllowElement {
  let currentRoot: object | null = null;
  let elementCount = 0;
  let activeDestinations = 0;
  let codeBlocks = 0;
  let totalCodeUnits = 0;
  let depths = new WeakMap<object, number>();

  return (element, index, parent) => {
    if (parent?.type === 'root' && currentRoot !== parent) {
      currentRoot = parent;
      elementCount = 0;
      activeDestinations = 0;
      codeBlocks = 0;
      totalCodeUnits = 0;
      depths = new WeakMap<object, number>();
    }

    elementCount += 1;
    const parentDepth = parent && parent.type === 'element' ? (depths.get(parent) ?? 0) : 0;
    const depth = parentDepth + 1;
    depths.set(element, depth);

    if (
      elementCount > MAX_PARSER_ELEMENTS ||
      depth > MAX_PARSER_DEPTH ||
      index >= MAX_DIRECT_CHILDREN
    ) {
      return false;
    }

    if (element.tagName === 'a' || element.tagName === 'img') {
      activeDestinations += 1;
      if (activeDestinations > MAX_LINKS_AND_IMAGES) return false;
    }

    if (element.tagName === 'pre') {
      codeBlocks += 1;
      const codeChild = element.children.length === 1 && element.children[0].type === 'element'
        ? element.children[0]
        : null;
      if (!codeChild || codeChild.tagName !== 'code') return false;
      let codeUnits = 0;
      for (const child of codeChild.children) {
        if (child.type !== 'text') return false;
        codeUnits += child.value.length;
      }
      totalCodeUnits += codeUnits;
      if (
        codeBlocks > MAX_CODE_BLOCKS ||
        codeUnits > MAX_CODE_BLOCK_UTF16 ||
        totalCodeUnits > MAX_CODE_TOTAL_UTF16
      ) {
        return false;
      }
    }

    return true;
  };
}

function scrollPlainFallback(event: ReactKeyboardEvent<HTMLPreElement>): void {
  if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
  event.preventDefault();
  event.currentTarget.scrollLeft += event.key === 'ArrowRight' ? 48 : -48;
}

export function SafeMarkdownSpike({
  markdown,
  assetRegistry,
  openExternal,
  complete = true,
  applicationOrigin = window.location.origin,
}: SafeMarkdownSpikeProps) {
  const prepared = prepareMarkdown(markdown);
  const highlightJobs = useMemo(() => createHighlightJobRegistry(), [markdown]);
  const authority: MarkdownAuthority = useMemo(() => Object.freeze({
    assetRegistry,
    openExternal,
    complete,
    applicationOrigin,
    highlightJobs,
  }), [applicationOrigin, assetRegistry, complete, highlightJobs, openExternal]);

  return (
    <main className="markdown-spike" aria-labelledby="markdown-spike-title">
      <header className="markdown-spike__header">
        <p className="markdown-spike__eyebrow">Containment proof</p>
        <h1 id="markdown-spike-title">Safe Markdown architecture spike</h1>
        <p>
          Untrusted prose can present text, but it receives no navigation, network or native command authority.
        </p>
      </header>
      <section className="markdown-spike__surface" aria-label="Contained Markdown message">
        {prepared.rawHtmlOmitted ? (
          <details className="markdown__raw-audit" open>
            <summary>
              Raw HTML-like input preserved as inert audit excerpts · {prepared.rawHtmlAudit.candidateCount}
            </summary>
            <pre role="region" tabIndex={0} aria-label="Inert raw Markdown source">
              {prepared.rawHtmlAudit.excerpts.join('\n\n')}
            </pre>
            {prepared.rawHtmlAudit.shortened ? (
              <p>Additional raw HTML candidates were omitted from the bounded audit.</p>
            ) : null}
          </details>
        ) : null}
        {prepared.notice ? (
          <p className="markdown__safety-notice" role="status">
            {prepared.notice}
          </p>
        ) : null}
        {prepared.mode === 'plain' ? (
          <pre
            className="markdown__plain-fallback"
            data-testid="markdown-plain-fallback"
            role="region"
            aria-label="Plain text safety preview"
            tabIndex={0}
            onKeyDown={scrollPlainFallback}
          >
            {prepared.source}
          </pre>
        ) : (
          <article className="markdown__prose">
            <AuthorityContext.Provider value={authority}>
              <ReactMarkdown
                remarkPlugins={remarkPlugins}
                skipHtml
                allowedElements={allowedElements}
                allowElement={createParserOutputGuard()}
                unwrapDisallowed={false}
                urlTransform={safeMarkdownUrlTransform}
                components={safeComponents}
              >
                {prepared.source}
              </ReactMarkdown>
            </AuthorityContext.Provider>
          </article>
        )}
      </section>
      <footer className="markdown-spike__footer">
        Browser containment evidence only · packaged WKWebView proof remains A.26
      </footer>
    </main>
  );
}

export function SafeMarkdownSpikeRoute() {
  const harness = window.__PIUI_MARKDOWN_HARNESS__;
  const assets = new Map<string, OpaqueAssetDescriptor>();
  for (const candidate of harness?.assets ?? []) {
    if (!isOpaqueAssetCapability(candidate.capability) || !isRasterMime(candidate.mime)) continue;
    assets.set(
      candidate.capability,
      Object.freeze({
        url: candidate.url,
        mime: candidate.mime,
        byteLength: candidate.byteLength,
        expiresAt: candidate.expiresAt,
      }),
    );
  }

  const openExternal = (target: ValidatedExternalTarget) => {
    harness?.openExternal?.(target.canonicalUrl);
  };

  return (
    <SafeMarkdownSpike
      markdown={harness?.markdown ?? hostileFixture}
      assetRegistry={assets}
      openExternal={openExternal}
      complete={harness?.complete ?? true}
    />
  );
}
