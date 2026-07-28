import { randomBytes } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Plugin } from 'vite';
import {
  MAX_ASSET_BYTES,
  MAX_ASSET_DIMENSION,
  MAX_ASSET_PIXELS,
  isRasterMime,
  type RasterMime,
} from '../../src/security/markdownPolicy';

export const MARKDOWN_ASSET_PREFIX = '/__piui_markdown_asset__/';
export const MARKDOWN_ASSET_REGISTER_PATH = '/__piui_markdown_asset_register__';
export const MARKDOWN_ASSET_SCOPE = 'markdown-raster-v1';
const TEST_ORIGIN = 'http://127.0.0.1:1420';
const MAX_REGISTRATION_BODY_BYTES = 4_096;
const MAX_TTL_MS = 30_000;

type RasterInspection = Readonly<{
  mime: RasterMime;
  byteLength: number;
  width: number;
  height: number;
}>;

type RegistryRecord = Readonly<{
  capability: string;
  path: string;
  scope: typeof MARKDOWN_ASSET_SCOPE;
  bytes: Buffer;
  inspection: RasterInspection;
  expiresAt: number;
}>;

export type RegisteredMarkdownAsset = Readonly<{
  capability: string;
  descriptor: Readonly<{
    url: string;
    mime: RasterMime;
    byteLength: number;
    expiresAt: number;
  }>;
}>;

function dimensionsPass(width: number, height: number): boolean {
  return (
    Number.isSafeInteger(width) &&
    Number.isSafeInteger(height) &&
    width >= 1 &&
    height >= 1 &&
    width <= MAX_ASSET_DIMENSION &&
    height <= MAX_ASSET_DIMENSION &&
    width * height <= MAX_ASSET_PIXELS
  );
}

function inspectPng(bytes: Buffer): { width: number; height: number } | null {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (bytes.length < 33 || !bytes.subarray(0, 8).equals(signature)) return null;
  let offset = 8;
  let width = 0;
  let height = 0;
  let sawHeader = false;
  let sawEnd = false;
  let chunks = 0;
  while (offset + 12 <= bytes.length && chunks < 1_024) {
    const length = bytes.readUInt32BE(offset);
    const chunkEnd = offset + 12 + length;
    if (chunkEnd > bytes.length) return null;
    const type = bytes.toString('ascii', offset + 4, offset + 8);
    if (!sawHeader) {
      if (type !== 'IHDR' || length !== 13) return null;
      width = bytes.readUInt32BE(offset + 8);
      height = bytes.readUInt32BE(offset + 12);
      sawHeader = true;
    }
    offset = chunkEnd;
    chunks += 1;
    if (type === 'IEND') {
      if (length !== 0 || offset !== bytes.length) return null;
      sawEnd = true;
      break;
    }
  }
  return sawHeader && sawEnd && dimensionsPass(width, height) ? { width, height } : null;
}

function inspectJpeg(bytes: Buffer): { width: number; height: number } | null {
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return null;
  let offset = 2;
  let dimensions: { width: number; height: number } | null = null;
  while (offset < bytes.length) {
    while (offset < bytes.length && bytes[offset] === 0xff) offset += 1;
    if (offset >= bytes.length) return null;
    const marker = bytes[offset];
    offset += 1;
    if (marker === 0xd9) return dimensions;
    if (marker === 0xda) {
      return bytes[bytes.length - 2] === 0xff && bytes[bytes.length - 1] === 0xd9
        ? dimensions
        : null;
    }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
    if (offset + 2 > bytes.length) return null;
    const length = bytes.readUInt16BE(offset);
    if (length < 2 || offset + length > bytes.length) return null;
    const isStartOfFrame =
      marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker);
    if (isStartOfFrame) {
      if (length < 7) return null;
      const height = bytes.readUInt16BE(offset + 3);
      const width = bytes.readUInt16BE(offset + 5);
      if (!dimensionsPass(width, height)) return null;
      dimensions = { width, height };
    }
    offset += length;
  }
  return null;
}

function inspectWebp(bytes: Buffer): { width: number; height: number } | null {
  if (
    bytes.length < 30 ||
    bytes.toString('ascii', 0, 4) !== 'RIFF' ||
    bytes.readUInt32LE(4) !== bytes.length - 8 ||
    bytes.toString('ascii', 8, 12) !== 'WEBP'
  ) {
    return null;
  }
  const format = bytes.toString('ascii', 12, 16);
  let width = 0;
  let height = 0;
  if (format === 'VP8X') {
    width = bytes.readUIntLE(24, 3) + 1;
    height = bytes.readUIntLE(27, 3) + 1;
  } else if (format === 'VP8L') {
    if (bytes[20] !== 0x2f) return null;
    const bits = bytes.readUInt32LE(21);
    width = (bits & 0x3fff) + 1;
    height = ((bits >>> 14) & 0x3fff) + 1;
  } else {
    return null;
  }
  return dimensionsPass(width, height) ? { width, height } : null;
}

export function inspectRaster(bytes: Buffer, claimedMime: unknown): RasterInspection | null {
  if (bytes.byteLength < 1 || bytes.byteLength > MAX_ASSET_BYTES || !isRasterMime(claimedMime)) {
    return null;
  }
  const dimensions =
    claimedMime === 'image/png'
      ? inspectPng(bytes)
      : claimedMime === 'image/jpeg'
        ? inspectJpeg(bytes)
        : inspectWebp(bytes);
  if (!dimensions) return null;
  return Object.freeze({
    mime: claimedMime,
    byteLength: bytes.byteLength,
    width: dimensions.width,
    height: dimensions.height,
  });
}

function extensionForMime(mime: RasterMime): string {
  if (mime === 'image/png') return 'png';
  if (mime === 'image/jpeg') return 'jpg';
  return 'webp';
}

export class MarkdownAssetRegistry {
  readonly #records = new Map<string, RegistryRecord>();

  register(
    bytes: Buffer,
    claimedMime: unknown,
    ttlMs: number,
    now = Date.now(),
  ): RegisteredMarkdownAsset | null {
    const inspection = inspectRaster(bytes, claimedMime);
    if (
      !inspection ||
      !Number.isSafeInteger(ttlMs) ||
      ttlMs < 1 ||
      ttlMs > MAX_TTL_MS ||
      !Number.isFinite(now)
    ) {
      return null;
    }
    const expiresAt = now + ttlMs;
    if (!Number.isSafeInteger(expiresAt)) return null;

    let token = '';
    let capability = '';
    do {
      token = randomBytes(16).toString('hex');
      capability = `piui-asset-${token}`;
    } while (this.#records.has(capability));

    const path = `${MARKDOWN_ASSET_PREFIX}${token}.${extensionForMime(inspection.mime)}`;
    this.#records.set(
      capability,
      Object.freeze({
        capability,
        path,
        scope: MARKDOWN_ASSET_SCOPE,
        bytes: Buffer.from(bytes),
        inspection,
        expiresAt,
      }),
    );
    return Object.freeze({
      capability,
      descriptor: Object.freeze({
        url: `${TEST_ORIGIN}${path}`,
        mime: inspection.mime,
        byteLength: inspection.byteLength,
        expiresAt,
      }),
    });
  }

  consume(path: string, scope: string, now = Date.now()): RegistryRecord | null {
    const record = [...this.#records.values()].find((candidate) => candidate.path === path);
    if (!record || scope !== MARKDOWN_ASSET_SCOPE || record.scope !== scope) return null;
    if (!Number.isFinite(now) || record.expiresAt <= now) {
      this.#records.delete(record.capability);
      return null;
    }
    const reinspection = inspectRaster(record.bytes, record.inspection.mime);
    if (
      !reinspection ||
      reinspection.byteLength !== record.inspection.byteLength ||
      reinspection.width !== record.inspection.width ||
      reinspection.height !== record.inspection.height
    ) {
      this.#records.delete(record.capability);
      return null;
    }
    this.#records.delete(record.capability);
    return record;
  }
}

function safeHeaders(response: ServerResponse) {
  response.setHeader('Cache-Control', 'no-store, max-age=0');
  response.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; sandbox");
  response.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('X-Content-Type-Options', 'nosniff');
}

function reject(response: ServerResponse, statusCode: number) {
  response.statusCode = statusCode;
  safeHeaders(response);
  response.setHeader('Content-Type', 'text/plain; charset=utf-8');
  response.setHeader('Content-Length', '0');
  response.end();
}

async function readRegistrationBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.byteLength;
    if (length > MAX_REGISTRATION_BODY_BYTES) throw new Error('body too large');
    chunks.push(bytes);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
}

export function markdownAssetProofPlugin(safeFixture: Buffer): Plugin {
  const registry = new MarkdownAssetRegistry();
  return {
    name: 'piui-markdown-test-asset-registry',
    apply: 'serve',
    configureServer(server) {
      server.middlewares.use(async (request, response, next) => {
        const rawTarget = request.url ?? '/';
        let parsedTarget: URL;
        try {
          parsedTarget = new URL(rawTarget, TEST_ORIGIN);
        } catch {
          next();
          return;
        }
        const requestPath = parsedTarget.pathname;
        const isAssetAuthorityTarget =
          requestPath === MARKDOWN_ASSET_REGISTER_PATH ||
          requestPath.startsWith(MARKDOWN_ASSET_PREFIX);
        if (
          isAssetAuthorityTarget &&
          (
            rawTarget !== requestPath ||
            parsedTarget.origin !== TEST_ORIGIN ||
            parsedTarget.search.length > 0 ||
            parsedTarget.hash.length > 0
          )
        ) {
          reject(response, 404);
          return;
        }

        if (requestPath === MARKDOWN_ASSET_REGISTER_PATH) {
          if (
            request.method !== 'POST' ||
            request.headers['content-type'] !== 'application/json' ||
            request.headers['x-piui-markdown-proof'] !== 'register'
          ) {
            reject(response, 405);
            return;
          }
          try {
            const body = await readRegistrationBody(request) as {
              fixture?: unknown;
              mime?: unknown;
              scope?: unknown;
              ttlMs?: unknown;
            };
            if (body.scope !== MARKDOWN_ASSET_SCOPE || typeof body.ttlMs !== 'number') {
              reject(response, 400);
              return;
            }
            const bytes = body.fixture === 'oversized'
              ? Buffer.alloc(MAX_ASSET_BYTES + 1)
              : body.fixture === 'safe-local'
                ? safeFixture
                : null;
            if (!bytes) {
              reject(response, 400);
              return;
            }
            const registered = registry.register(bytes, body.mime, body.ttlMs);
            if (!registered) {
              reject(response, 400);
              return;
            }
            const encoded = Buffer.from(JSON.stringify(registered));
            response.statusCode = 201;
            safeHeaders(response);
            response.setHeader('Content-Type', 'application/json; charset=utf-8');
            response.setHeader('Content-Length', String(encoded.byteLength));
            response.end(encoded);
          } catch {
            reject(response, 400);
          }
          return;
        }

        if (!requestPath.startsWith(MARKDOWN_ASSET_PREFIX)) {
          next();
          return;
        }
        if (request.method !== 'GET') {
          reject(response, 405);
          return;
        }
        const record = registry.consume(requestPath, MARKDOWN_ASSET_SCOPE);
        if (!record) {
          reject(response, 404);
          return;
        }
        response.statusCode = 200;
        safeHeaders(response);
        response.setHeader('Content-Type', record.inspection.mime);
        response.setHeader('Content-Length', String(record.bytes.byteLength));
        response.setHeader('Content-Disposition', 'inline');
        response.end(record.bytes);
      });
    },
  };
}
