import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { assertPublicSdk, publicSdkMetadata, REQUIRED_PUBLIC_CAPABILITIES } from '../src/pi/public-sdk';

function sourceFiles(path: string): string[] {
  return readdirSync(path).flatMap((entry) => {
    const target = join(path, entry);
    return statSync(target).isDirectory() ? sourceFiles(target) : target.endsWith('.ts') ? [target] : [];
  });
}

describe('public Pi SDK adapter', () => {
  it('loads the exact pinned package-root SDK and required probes', () => {
    expect(assertPublicSdk).not.toThrow();
    const metadata = publicSdkMetadata();
    expect(metadata.piVersion).toBe('0.82.0');
    expect(metadata.nodeVersion).toMatch(/^22\./);
    expect(Object.values(REQUIRED_PUBLIC_CAPABILITIES).every(Boolean)).toBe(true);
  });

  it('contains no Pi deep import', () => {
    const source = sourceFiles(resolve(import.meta.dirname, '../src')).map((file) => readFileSync(file, 'utf8')).join('\n');
    expect(source).not.toMatch(/@earendil-works\/pi-coding-agent\//);
    expect(source.match(/from ['"]@earendil-works\/pi-coding-agent['"]/g)).toHaveLength(1);
  });
});
