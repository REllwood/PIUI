import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

function hex(source: string, name: string): string {
  const value = source.match(new RegExp(`--${name}:\\s*(#[0-9a-f]{6})`, 'u'))?.[1];
  if (!value) throw new Error(`missing-${name}`);
  return value;
}

function contrast(left: string, right: string): number {
  const luminance = (colour: string) => {
    const values = [1, 3, 5].map(
      (index) => Number.parseInt(colour.slice(index, index + 2), 16) / 255,
    );
    const [red = 0, green = 0, blue = 0] = values.map((value) =>
      value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4,
    );
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
  };
  const values = [luminance(left), luminance(right)].sort((a, b) => b - a);
  return ((values[0] ?? 0) + 0.05) / ((values[1] ?? 0) + 0.05);
}

describe('Luminous Graphite tokens', () => {
  const dark = readFileSync(resolve(import.meta.dirname, 'theme-dark.css'), 'utf8');
  const light = readFileSync(resolve(import.meta.dirname, 'theme-light.css'), 'utf8');
  const tokens = readFileSync(resolve(import.meta.dirname, 'tokens.css'), 'utf8');

  it('keeps the 44px target and six-pixel plane gutter', () => {
    expect(tokens).toContain('--target: 44px');
    expect(tokens).toContain('--gutter: 6px');
  });

  it.each([
    ['dark', dark],
    ['light', light],
  ])('%s theme meets text and focus contrast thresholds', (_, source) => {
    expect(contrast(hex(source, 'text'), hex(source, 'surface'))).toBeGreaterThanOrEqual(4.5);
    expect(contrast(hex(source, 'text-muted'), hex(source, 'surface'))).toBeGreaterThanOrEqual(4.5);
    expect(contrast(hex(source, 'focus'), hex(source, 'surface'))).toBeGreaterThanOrEqual(3);
    expect(contrast(hex(source, 'primary-on'), hex(source, 'primary'))).toBeGreaterThanOrEqual(4.5);
  });
});
