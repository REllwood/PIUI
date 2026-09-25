import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  TEXT_COALESCE_MAX_BYTES,
  TEXT_COALESCE_MAX_DELAY_MS,
  TextDeltaCoalescer,
} from '../src/pi/text-coalescer';

function wellFormed(text: string): boolean {
  return !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(text);
}

describe('TextDeltaCoalescer', () => {
  let emitted: string[];
  let coalescer: TextDeltaCoalescer;

  beforeEach(() => {
    vi.useFakeTimers();
    emitted = [];
    coalescer = new TextDeltaCoalescer((text) => emitted.push(text));
  });

  afterEach(() => {
    coalescer.dispose();
    vi.useRealTimers();
  });

  it('emits one event per 32 ms window rather than one per token', () => {
    for (const token of ['Hel', 'lo', ', ', 'wor', 'ld']) coalescer.push(token);
    vi.advanceTimersByTime(TEXT_COALESCE_MAX_DELAY_MS - 1);
    expect(emitted).toEqual([]);
    vi.advanceTimersByTime(1);
    expect(emitted).toEqual(['Hello, world']);
    coalescer.push('!');
    vi.advanceTimersByTime(TEXT_COALESCE_MAX_DELAY_MS);
    expect(emitted).toEqual(['Hello, world', '!']);
  });

  it('emits as soon as 4 KiB of UTF-8 is waiting', () => {
    coalescer.push('x'.repeat(TEXT_COALESCE_MAX_BYTES - 2));
    expect(emitted).toEqual([]);
    coalescer.push('é');
    expect(emitted).toEqual([`${'x'.repeat(TEXT_COALESCE_MAX_BYTES - 2)}é`]);
  });

  it('flushes everything waiting on demand and drops it on dispose', () => {
    coalescer.push('before tool');
    coalescer.flush();
    expect(emitted).toEqual(['before tool']);
    coalescer.flush();
    coalescer.push('abandoned');
    coalescer.dispose();
    vi.advanceTimersByTime(TEXT_COALESCE_MAX_DELAY_MS * 2);
    expect(emitted).toEqual(['before tool']);
  });

  it('never ends a timed or size flush between the halves of a surrogate pair', () => {
    const grin = '😀';
    coalescer.push(`a${grin[0]}`);
    vi.advanceTimersByTime(TEXT_COALESCE_MAX_DELAY_MS);
    expect(emitted).toEqual(['a']);
    coalescer.push(`${grin[1]}b`);
    vi.advanceTimersByTime(TEXT_COALESCE_MAX_DELAY_MS);
    expect(emitted).toEqual(['a', `${grin}b`]);

    coalescer.push(`${'x'.repeat(TEXT_COALESCE_MAX_BYTES)}${grin[0]}`);
    expect(emitted.at(-1)).toBe('x'.repeat(TEXT_COALESCE_MAX_BYTES));
    coalescer.push(grin[1] ?? '');
    coalescer.flush();
    expect(emitted.at(-1)).toBe(grin);
    expect(emitted.every(wellFormed)).toBe(true);
  });

  it('still delivers an unpaired high surrogate on the final flush', () => {
    coalescer.push('\ud83d');
    vi.advanceTimersByTime(TEXT_COALESCE_MAX_DELAY_MS);
    expect(emitted).toEqual([]);
    coalescer.flush();
    expect(emitted).toEqual(['\ud83d']);
  });
});
