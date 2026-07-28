import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { MAX_ASSET_BYTES, MAX_ASSET_DIMENSION } from '../../src/security/markdownPolicy';
import {
  MARKDOWN_ASSET_SCOPE,
  MarkdownAssetRegistry,
  inspectRaster,
} from './markdownAssetRegistry';

const fixture = readFileSync(resolve(import.meta.dirname, '../fixtures/markdown/safe-local.png'));

describe('test-host authoritative raster registry', () => {
  it('verifies exact raster signature, MIME, byte and dimension policy before minting', () => {
    expect(inspectRaster(fixture, 'image/png')).toMatchObject({
      mime: 'image/png',
      byteLength: fixture.byteLength,
      width: 1,
      height: 1,
    });
    expect(inspectRaster(fixture, 'image/jpeg')).toBeNull();
    expect(inspectRaster(fixture, 'image/webp')).toBeNull();
    const jpeg = Buffer.from([
      0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0x01, 0x00, 0x01,
      0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x00, 0x03, 0x11, 0x00, 0xff, 0xd9,
    ]);
    expect(inspectRaster(jpeg, 'image/jpeg')).toMatchObject({ width: 1, height: 1 });
    const webp = Buffer.alloc(30);
    webp.write('RIFF', 0, 'ascii');
    webp.writeUInt32LE(22, 4);
    webp.write('WEBPVP8X', 8, 'ascii');
    webp.writeUInt32LE(10, 16);
    expect(inspectRaster(webp, 'image/webp')).toMatchObject({ width: 1, height: 1 });
    expect(inspectRaster(fixture, 'image/svg+xml')).toBeNull();
    expect(inspectRaster(Buffer.alloc(0), 'image/png')).toBeNull();
    const ancillaryLength = MAX_ASSET_BYTES - fixture.byteLength;
    const ancillary = Buffer.alloc(ancillaryLength);
    ancillary.writeUInt32BE(ancillaryLength - 12, 0);
    ancillary.write('tEXt', 4, 'ascii');
    const exactMaximum = Buffer.concat([
      fixture.subarray(0, fixture.byteLength - 12),
      ancillary,
      fixture.subarray(fixture.byteLength - 12),
    ]);
    expect(exactMaximum.byteLength).toBe(MAX_ASSET_BYTES);
    expect(inspectRaster(exactMaximum, 'image/png')?.byteLength).toBe(MAX_ASSET_BYTES);
    expect(inspectRaster(Buffer.concat([exactMaximum, Buffer.from([0])]), 'image/png')).toBeNull();

    const exactDimensions = Buffer.from(fixture);
    exactDimensions.writeUInt32BE(MAX_ASSET_DIMENSION, 16);
    exactDimensions.writeUInt32BE(MAX_ASSET_DIMENSION, 20);
    expect(inspectRaster(exactDimensions, 'image/png')).toMatchObject({
      width: MAX_ASSET_DIMENSION,
      height: MAX_ASSET_DIMENSION,
    });
    const oversizedDimensions = Buffer.from(fixture);
    oversizedDimensions.writeUInt32BE(MAX_ASSET_DIMENSION + 1, 16);
    expect(inspectRaster(oversizedDimensions, 'image/png')).toBeNull();
  });

  it('mints random 128-bit scoped capabilities and validates exact path, current expiry and one use', () => {
    const registry = new MarkdownAssetRegistry();
    const first = registry.register(fixture, 'image/png', 1_000, 5_000);
    const second = registry.register(fixture, 'image/png', 1_000, 5_000);
    expect(first?.capability).toMatch(/^piui-asset-[0-9a-f]{32}$/);
    expect(second?.capability).toMatch(/^piui-asset-[0-9a-f]{32}$/);
    expect(first?.capability).not.toBe(second?.capability);

    const path = new URL(first?.descriptor.url ?? '').pathname;
    expect(registry.consume(`${path}.substituted`, MARKDOWN_ASSET_SCOPE, 5_999)).toBeNull();
    expect(registry.consume(`${path}?substituted=1`, MARKDOWN_ASSET_SCOPE, 5_999)).toBeNull();
    expect(registry.consume(`${path}#substituted`, MARKDOWN_ASSET_SCOPE, 5_999)).toBeNull();
    expect(registry.consume(path, 'wrong-scope', 5_999)).toBeNull();
    expect(registry.consume(path, MARKDOWN_ASSET_SCOPE, 5_999)).toMatchObject({ path });
    expect(registry.consume(path, MARKDOWN_ASSET_SCOPE, 5_999)).toBeNull();
  });

  it('rejects expiry at the exact current time and invalid registration limits', () => {
    const registry = new MarkdownAssetRegistry();
    const expiring = registry.register(fixture, 'image/png', 1, 10_000);
    const path = new URL(expiring?.descriptor.url ?? '').pathname;
    expect(registry.consume(path, MARKDOWN_ASSET_SCOPE, 10_001)).toBeNull();
    expect(registry.register(fixture, 'image/png', 0, 10_000)).toBeNull();
    expect(registry.register(fixture, 'image/svg+xml', 1_000, 10_000)).toBeNull();
  });
});
