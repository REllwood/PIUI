export const MAX_MARKDOWN_UTF16 = 262_144;
export const MAX_MARKDOWN_UTF8 = 1_048_576;
export const MAX_LOGICAL_LINE_UTF16 = 16_384;
export const MAX_ACTIVE_DESTINATION_SCALARS = 2_048;
export const MAX_LINKS_AND_IMAGES = 256;
export const MAX_CODE_BLOCK_UTF16 = 32_768;
export const MAX_CODE_TOTAL_UTF16 = 131_072;
export const MAX_CODE_BLOCKS = 64;
export const MAX_PARSER_ELEMENTS = 10_000;
export const MAX_PARSER_DEPTH = 32;
export const MAX_DIRECT_CHILDREN = 2_000;
export const MAX_PLAIN_PREVIEW_UTF16 = 65_536;
export const MAX_ASSET_BYTES = 10 * 1_048_576;
export const MAX_ASSET_TTL_MS = 5 * 60_000;
export const MAX_ASSET_DIMENSION = 4_096;
export const MAX_ASSET_PIXELS = 16_777_216;
export const MAX_ASSET_ALT_UTF16 = 512;
export const MAX_HIGHLIGHT_BYTES = 262_144;
export const MAX_HIGHLIGHT_LINES = 2_000;
export const MAX_RAW_AUDIT_SNIPPETS = 64;
export const MAX_RAW_AUDIT_SNIPPET_UTF16 = 256;
export const MAX_RAW_AUDIT_TOTAL_UTF16 = 8_192;

const OPAQUE_ASSET_PATTERN = /^piui-asset-[0-9a-f]{32}$/;
const OPAQUE_RASTER_PROTOCOL = 'piui-raster:';
const OPAQUE_RASTER_HOST = 'localhost';
const SAFE_EXTERNAL_HOST_PATTERN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const FORBIDDEN_URI_CHARACTERS = /[\u0000-\u0020\u007f-\u009f\u00a0\u1680\u2000-\u200f\u2028-\u202f\u205f-\u206f\u3000\ufeff]/u;
const GLOBAL_UNSAFE_FORMAT_CHARACTERS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/u;
const MARKDOWN_PUNCTUATION = /[!#()*+\-<>[\]_`{|}~]/g;
const RAW_HTML_CANDIDATE = /<!--|<!\[CDATA\[|<![A-Za-z]|<\?|<\/?[A-Za-z][A-Za-z0-9:-]*(?=[\t\n\f />])/g;
const RAW_HTML_CONTEXT_UTF16 = 64;
const MAX_RAW_HTML_SEGMENT_SCAN_UTF16 = 208;

const externalTargetBrand: unique symbol = Symbol('ValidatedExternalTarget');

export type ValidatedExternalTarget = Readonly<{
  canonicalUrl: string;
  displayOrigin: string;
  [externalTargetBrand]: true;
}>;

export const RASTER_MIME_TYPES = ['image/png', 'image/jpeg', 'image/webp'] as const;
export type RasterMime = (typeof RASTER_MIME_TYPES)[number];

export type OpaqueAssetDescriptor = Readonly<{
  url: string;
  mime: RasterMime;
  byteLength: number;
  expiresAt: number;
}>;

export type ValidatedOpaqueAsset = Readonly<{
  url: string;
  mime: OpaqueAssetDescriptor['mime'];
  byteLength: number;
}>;

export type RawHtmlAudit = Readonly<{
  candidateCount: number;
  excerpts: readonly string[];
  shortened: boolean;
}>;

export type PreparedMarkdown = Readonly<{
  mode: 'markdown' | 'plain';
  source: string;
  rawHtmlOmitted: boolean;
  rawHtmlAudit: RawHtmlAudit;
  shortened: boolean;
  notice: string | null;
}>;

export function normaliseUntrustedText(value: string): string {
  let result = '';
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        result += value[index] + value[index + 1];
        index += 1;
      } else {
        result += '\ufffd';
      }
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      result += '\ufffd';
    } else if (GLOBAL_UNSAFE_FORMAT_CHARACTERS.test(value[index])) {
      result += '\ufffd';
    } else {
      result += value[index];
    }
  }
  return result;
}

export function truncateUtf16(value: string, maximumUnits: number): string {
  if (maximumUnits <= 0) return '';
  if (value.length <= maximumUnits) return value;
  let end = maximumUnits;
  const last = value.charCodeAt(end - 1);
  const next = value.charCodeAt(end);
  if (last >= 0xd800 && last <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) {
    end -= 1;
  }
  return value.slice(0, end);
}

export function utf8Length(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

export function isWithinMarkdownUtf8Limit(value: string): boolean {
  return utf8Length(value) <= MAX_MARKDOWN_UTF8;
}

export function isRasterMime(value: unknown): value is RasterMime {
  return typeof value === 'string' && (RASTER_MIME_TYPES as readonly string[]).includes(value);
}

export function highlightLineCount(value: string): number {
  return value.length === 0 ? 1 : value.split('\n').length;
}

export function isWithinHighlightBounds(value: string): boolean {
  return utf8Length(value) < MAX_HIGHLIGHT_BYTES && highlightLineCount(value) < MAX_HIGHLIGHT_LINES;
}

export function extractRawHtmlAudit(source: string): RawHtmlAudit {
  const candidates = source.matchAll(RAW_HTML_CANDIDATE);
  const excerpts: string[] = [];
  let candidateCount = 0;
  let totalUnits = 0;

  for (const candidate of candidates) {
    const candidateIndex = candidate.index;
    candidateCount += 1;
    if (candidateIndex === undefined || excerpts.length >= MAX_RAW_AUDIT_SNIPPETS) continue;

    const scan = source.slice(
      candidateIndex,
      candidateIndex + MAX_RAW_HTML_SEGMENT_SCAN_UTF16,
    );
    const terminatorText = candidate[0] === '<!--'
      ? '-->'
      : candidate[0] === '<![CDATA['
        ? ']]>'
        : '>';
    const terminator = scan.indexOf(terminatorText);
    const segmentEnd = terminator >= 0
      ? candidateIndex + terminator + terminatorText.length
      : candidateIndex + candidate[0].length;
    const excerptStart = Math.max(0, candidateIndex - RAW_HTML_CONTEXT_UTF16);
    const excerptEnd = Math.min(source.length, segmentEnd + RAW_HTML_CONTEXT_UTF16);
    const heading = `[Raw HTML candidate at UTF-16 offset ${candidateIndex}]\n`;
    const separatorUnits = excerpts.length > 0 ? 2 : 0;
    const available = Math.min(
      MAX_RAW_AUDIT_SNIPPET_UTF16,
      MAX_RAW_AUDIT_TOTAL_UTF16 - totalUnits - separatorUnits,
    );
    if (available <= heading.length) continue;
    const excerpt = heading + truncateUtf16(
      source.slice(excerptStart, excerptEnd),
      available - heading.length,
    );
    excerpts.push(excerpt);
    totalUnits += separatorUnits + excerpt.length;
  }

  return Object.freeze({
    candidateCount,
    excerpts: Object.freeze(excerpts),
    shortened: candidateCount > excerpts.length,
  });
}

function plainFallback(source: string, rawHtmlAudit: RawHtmlAudit): PreparedMarkdown {
  return Object.freeze({
    mode: 'plain',
    source: truncateUtf16(source, MAX_PLAIN_PREVIEW_UTF16),
    rawHtmlOmitted: rawHtmlAudit.candidateCount > 0,
    rawHtmlAudit,
    shortened: true,
    notice: 'Content shortened for safety.',
  });
}

function countPotentialLinksAndImages(source: string): number {
  let explicitDestinations = 0;
  const withoutExplicitDestinations = source.replace(
    /!?\[[^\]\n]{0,512}\][ \t]*(?:\([^\n)]*\)|\[[^\]\n]{0,512}\])/g,
    () => {
      explicitDestinations += 1;
      return '';
    },
  );
  const bareDestinations = withoutExplicitDestinations.match(/(?:https?:\/\/|www\.)/gi)?.length ?? 0;
  return explicitDestinations + bareDestinations;
}

function exceedsConservativeDepth(source: string): boolean {
  for (const line of source.split('\n')) {
    const quoteDepth = line.match(/^(?: {0,3}>[ \t]?)+/)?.[0].match(/>/g)?.length ?? 0;
    const indentationDepth = Math.floor((line.match(/^[ \t]*/)?.[0].replace(/\t/g, '    ').length ?? 0) / 2);
    if (quoteDepth + indentationDepth > MAX_PARSER_DEPTH) return true;
  }

  let inlineDepth = 0;
  for (const character of source) {
    if (character === '[' || character === '(' || character === '{') inlineDepth += 1;
    else if (character === ']' || character === ')' || character === '}') {
      inlineDepth = Math.max(0, inlineDepth - 1);
    }
    if (inlineDepth > MAX_PARSER_DEPTH) return true;
  }
  return false;
}

type CodeScannerContainer =
  | Readonly<{ kind: 'quote' }>
  | Readonly<{ kind: 'list'; continuationColumns: number }>;

type CodeScannerLine = Readonly<{
  content: string;
  containers: readonly CodeScannerContainer[];
  withinContainerLimit: boolean;
}>;

/**
 * Removes only bounded, syntactically visible CommonMark container markers
 * from the scanner's view. The returned content is never used for rendering.
 */
function normaliseCodeScannerOpeningLine(line: string): CodeScannerLine {
  const containers: CodeScannerContainer[] = [];
  let cursor = 0;

  while (containers.length < MAX_PARSER_DEPTH) {
    let marker = cursor;
    let leadingSpaces = 0;
    while (leadingSpaces < 3 && line[marker] === ' ') {
      marker += 1;
      leadingSpaces += 1;
    }

    if (line[marker] === '>') {
      cursor = marker + 1;
      if (line[cursor] === ' ' || line[cursor] === '\t') cursor += 1;
      containers.push(Object.freeze({ kind: 'quote' }));
      continue;
    }

    const listMarker = line.slice(marker).match(/^(?:[*+-]|\d{1,9}[.)])(?=[ \t]|$)/)?.[0];
    if (!listMarker) break;

    const afterMarker = marker + listMarker.length;
    if (afterMarker === line.length) {
      cursor = afterMarker;
      containers.push(Object.freeze({
        kind: 'list',
        continuationColumns: leadingSpaces + listMarker.length + 1,
      }));
      continue;
    }

    let paddingUnits = 1;
    let paddingColumns = 1;
    if (line[afterMarker] === ' ') {
      let spaces = 0;
      while (line[afterMarker + spaces] === ' ') spaces += 1;
      if (spaces <= 4 && line[afterMarker + spaces] !== '\t') {
        paddingUnits = spaces;
        paddingColumns = spaces;
      }
    } else if (line[afterMarker] === '\t') {
      const markerColumn = leadingSpaces + listMarker.length;
      paddingColumns = 4 - (markerColumn % 4);
    }
    cursor = afterMarker + paddingUnits;
    containers.push(Object.freeze({
      kind: 'list',
      continuationColumns: leadingSpaces + listMarker.length + paddingColumns,
    }));
  }

  const remainingContainer = /^(?: {0,3}>| {0,3}(?:[*+-]|\d{1,9}[.)])(?=[ \t]|$))/.test(
    line.slice(cursor),
  );
  return Object.freeze({
    content: line.slice(cursor),
    containers: Object.freeze(containers),
    withinContainerLimit: containers.length < MAX_PARSER_DEPTH || !remainingContainer,
  });
}

function removeScannerIndentColumns(line: string, columns: number): string | null {
  let consumedColumns = 0;
  let cursor = 0;
  while (consumedColumns < columns) {
    if (line[cursor] === ' ') {
      consumedColumns += 1;
      cursor += 1;
    } else if (line[cursor] === '\t') {
      consumedColumns += 4 - (consumedColumns % 4);
      cursor += 1;
    } else {
      return null;
    }
  }
  return ' '.repeat(consumedColumns - columns) + line.slice(cursor);
}

function normaliseCodeScannerContinuationLine(
  line: string,
  containers: readonly CodeScannerContainer[],
): string | null {
  let content = line;
  for (const container of containers) {
    if (container.kind === 'list') {
      const remainder = removeScannerIndentColumns(content, container.continuationColumns);
      if (remainder === null) return line.trim().length === 0 ? '' : null;
      content = remainder;
      continue;
    }

    let marker = 0;
    while (marker < 3 && content[marker] === ' ') marker += 1;
    if (content[marker] !== '>') return line.trim().length === 0 ? '' : null;
    marker += 1;
    if (content[marker] === ' ' || content[marker] === '\t') marker += 1;
    content = content.slice(marker);
  }
  return content;
}

function codeBlockLimitsPass(source: string): boolean {
  const lines = source.split('\n');
  // CommonMark tab stops retain physical columns across open containers and
  // continuation lines. This architecture proof deliberately sends any tab-
  // bearing Markdown to the bounded plain-text path rather than approximating
  // parser column state and risking a pre-parser code-budget mismatch.
  if (source.includes('\t')) return false;
  let fenceCharacter = '';
  let fenceLength = 0;
  let fenceContainers: readonly CodeScannerContainer[] = [];
  let inIndentedBlock = false;
  let indentedContainers: readonly CodeScannerContainer[] = [];
  let currentUnits = 0;
  let totalUnits = 0;
  let blocks = 0;
  let pendingBlankLines = 0;

  const startBlock = () => {
    blocks += 1;
    currentUnits = 0;
    return blocks <= MAX_CODE_BLOCKS;
  };
  const addUnits = (units: number) => {
    currentUnits += units;
    totalUnits += units;
    return currentUnits <= MAX_CODE_BLOCK_UTF16 && totalUnits <= MAX_CODE_TOTAL_UTF16;
  };
  const closeFence = () => {
    fenceCharacter = '';
    fenceLength = 0;
    fenceContainers = [];
    currentUnits = 0;
  };
  const closeIndentedBlock = () => {
    inIndentedBlock = false;
    indentedContainers = [];
    currentUnits = 0;
    pendingBlankLines = 0;
  };

  for (const rawLine of lines) {
    if (fenceCharacter) {
      const line = normaliseCodeScannerContinuationLine(rawLine, fenceContainers);
      if (line !== null) {
        const closing = line.match(/^ {0,3}(`{3,}|~{3,})[ \t]*$/);
        if (closing && closing[1][0] === fenceCharacter && closing[1].length >= fenceLength) {
          closeFence();
        } else if (!addUnits(line.length + 1)) {
          return false;
        }
        continue;
      }
      closeFence();
    }

    if (inIndentedBlock) {
      const line = normaliseCodeScannerContinuationLine(rawLine, indentedContainers);
      if (line !== null && line.trim().length === 0) {
        pendingBlankLines += 1;
        continue;
      }
      const indentedContent = line === null ? null : removeScannerIndentColumns(line, 4);
      if (indentedContent !== null) {
        if (!addUnits(pendingBlankLines + indentedContent.length + 1)) return false;
        pendingBlankLines = 0;
        continue;
      }
      closeIndentedBlock();
    }

    const scannerLine = normaliseCodeScannerOpeningLine(rawLine);
    if (!scannerLine.withinContainerLimit) return false;
    const fence = scannerLine.content.match(/^ {0,3}(`{3,}|~{3,})/);
    if (fence) {
      if (!startBlock()) return false;
      fenceCharacter = fence[1][0];
      fenceLength = fence[1].length;
      fenceContainers = scannerLine.containers;
      continue;
    }

    const indentedContent = removeScannerIndentColumns(scannerLine.content, 4);
    if (indentedContent !== null && scannerLine.content.trim().length > 0) {
      if (!startBlock()) return false;
      inIndentedBlock = true;
      indentedContainers = scannerLine.containers;
      if (!addUnits(indentedContent.length + 1)) return false;
    }
  }

  return true;
}

export function prepareMarkdown(untrustedSource: string): PreparedMarkdown {
  if (untrustedSource.length > MAX_MARKDOWN_UTF16) {
    const preview = normaliseUntrustedText(
      truncateUtf16(untrustedSource, MAX_PLAIN_PREVIEW_UTF16),
    );
    return plainFallback(preview, extractRawHtmlAudit(preview));
  }

  const source = normaliseUntrustedText(untrustedSource);
  const rawHtmlAudit = extractRawHtmlAudit(source);
  const rawHtmlOmitted = rawHtmlAudit.candidateCount > 0;

  if (!isWithinMarkdownUtf8Limit(source)) {
    return plainFallback(source, rawHtmlAudit);
  }

  const lines = source.split('\n');
  if (
    lines.length > MAX_DIRECT_CHILDREN ||
    lines.some((line) => line.length > MAX_LOGICAL_LINE_UTF16)
  ) {
    return plainFallback(source, rawHtmlAudit);
  }

  const punctuationCount = source.match(MARKDOWN_PUNCTUATION)?.length ?? 0;
  const conservativeElementEstimate = lines.length * 2 + punctuationCount;
  if (
    conservativeElementEstimate > MAX_PARSER_ELEMENTS ||
    countPotentialLinksAndImages(source) > MAX_LINKS_AND_IMAGES ||
    exceedsConservativeDepth(source) ||
    !codeBlockLimitsPass(source)
  ) {
    return plainFallback(source, rawHtmlAudit);
  }

  return Object.freeze({
    mode: 'markdown',
    source,
    rawHtmlOmitted,
    rawHtmlAudit,
    shortened: false,
    notice: null,
  });
}

export function validateExternalHttps(value: string): ValidatedExternalTarget | null {
  if (
    !value ||
    value.length > MAX_ACTIVE_DESTINATION_SCALARS * 2 ||
    Array.from(value).length > MAX_ACTIVE_DESTINATION_SCALARS
  ) {
    return null;
  }
  if (value !== value.trim() || FORBIDDEN_URI_CHARACTERS.test(value)) return null;
  if (!/^[\x21-\x7e]+$/.test(value)) return null;
  if (!value.startsWith('https://')) return null;
  if (value.includes('%') || value.includes('&') || value.includes('\\') || value.includes('#')) {
    return null;
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }

  if (
    parsed.protocol !== 'https:' ||
    !parsed.hostname ||
    !SAFE_EXTERNAL_HOST_PATTERN.test(parsed.hostname) ||
    parsed.hostname.endsWith('.') ||
    parsed.username ||
    parsed.password ||
    (parsed.port && parsed.port !== '443')
  ) {
    return null;
  }

  const canonicalUrl = parsed.toString();
  if (canonicalUrl.length > MAX_ACTIVE_DESTINATION_SCALARS) return null;
  return Object.freeze({
    canonicalUrl,
    displayOrigin: parsed.origin,
    [externalTargetBrand]: true as const,
  });
}

export function isOpaqueAssetCapability(value: string): boolean {
  return OPAQUE_ASSET_PATTERN.test(value);
}

export function safeMarkdownUrlTransform(value: string, key: string): string | undefined {
  if (key === 'href') return validateExternalHttps(value)?.canonicalUrl;
  if (key === 'src' && isOpaqueAssetCapability(value)) return value;
  return undefined;
}

function assetExtension(mime: RasterMime): string {
  if (mime === 'image/png') return 'png';
  if (mime === 'image/jpeg') return 'jpg';
  return 'webp';
}

export function validateOpaqueAssetDescriptor(
  capability: string,
  descriptor: OpaqueAssetDescriptor | undefined,
  now: number,
  applicationOrigin: string,
): ValidatedOpaqueAsset | null {
  if (
    !isOpaqueAssetCapability(capability) ||
    !descriptor ||
    !isRasterMime(descriptor.mime) ||
    !Number.isSafeInteger(now) ||
    !Number.isSafeInteger(descriptor.byteLength) ||
    descriptor.byteLength < 1 ||
    descriptor.byteLength > MAX_ASSET_BYTES ||
    !Number.isSafeInteger(descriptor.expiresAt) ||
    descriptor.expiresAt <= now ||
    descriptor.expiresAt - now > MAX_ASSET_TTL_MS
  ) {
    return null;
  }

  let expectedOrigin: URL;
  let resolved: URL;
  try {
    expectedOrigin = new URL(applicationOrigin);
    resolved = new URL(descriptor.url);
  } catch {
    return null;
  }
  if (!['http:', 'https:', 'tauri:'].includes(expectedOrigin.protocol)) {
    return null;
  }

  const token = capability.slice('piui-asset-'.length);
  const expectedPath = `/__piui_markdown_asset__/${token}.${assetExtension(descriptor.mime)}`;
  const nativeRasterProtocol = applicationOrigin === 'tauri://localhost'
    && expectedOrigin.protocol === 'tauri:'
    && expectedOrigin.hostname === 'localhost'
    && expectedOrigin.port === ''
    && expectedOrigin.pathname === ''
    && expectedOrigin.search === ''
    && expectedOrigin.hash === ''
    && expectedOrigin.username === ''
    && expectedOrigin.password === ''
    && resolved.protocol === OPAQUE_RASTER_PROTOCOL
    && resolved.hostname === OPAQUE_RASTER_HOST
    && resolved.port === '';
  const browserProofProtocol = ['http:', 'https:'].includes(expectedOrigin.protocol)
    && expectedOrigin.origin !== 'null'
    && applicationOrigin === expectedOrigin.origin
    && resolved.origin === expectedOrigin.origin;
  if (
    (!nativeRasterProtocol && !browserProofProtocol) ||
    resolved.pathname !== expectedPath ||
    resolved.search ||
    resolved.hash ||
    resolved.username ||
    resolved.password
  ) {
    return null;
  }

  return Object.freeze({
    url: resolved.toString(),
    mime: descriptor.mime,
    byteLength: descriptor.byteLength,
  });
}

export function boundedAltText(value: string | undefined): string {
  const normalised = normaliseUntrustedText(value ?? '').replace(/\s+/g, ' ').trim();
  return truncateUtf16(normalised, MAX_ASSET_ALT_UTF16);
}
