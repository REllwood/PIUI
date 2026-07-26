import { describe, expect, it } from 'vitest';
import { ProtocolDecoder } from '@piui/protocol/codec';
import { SidecarRouter } from '../src/bridge/router';

const BMP = 'x';
const ASTRAL = '😀';

describe('SidecarRouter Unicode snapshot bounds', () => {
  it.each([
    {
      name: 'normalises short lone high and low surrogates',
      input: `a\ud800b\udc00c`,
      expected: 'a�b�c',
      truncated: undefined,
    },
    {
      name: 'normalises a lone high surrogate at the exact boundary',
      input: BMP.repeat(8_191) + '\ud800',
      expected: BMP.repeat(8_191) + '�',
      truncated: undefined,
    },
    {
      name: 'normalises a lone low surrogate at the exact boundary',
      input: BMP.repeat(8_191) + '\udc00',
      expected: BMP.repeat(8_191) + '�',
      truncated: undefined,
    },
    {
      name: 'drops an astral code point that would straddle the boundary',
      input: BMP.repeat(8_191) + ASTRAL,
      expected: BMP.repeat(8_191),
      truncated: true,
    },
    {
      name: 'retains an astral code point ending exactly at the boundary',
      input: BMP.repeat(8_190) + ASTRAL,
      expected: BMP.repeat(8_190) + ASTRAL,
      truncated: undefined,
    },
    {
      name: 'retains the complete boundary astral and drops following text',
      input: BMP.repeat(8_190) + ASTRAL + BMP,
      expected: BMP.repeat(8_190) + ASTRAL,
      truncated: true,
    },
  ])('$name', ({ input, expected, truncated }) => {
    const router = new SidecarRouter();
    router.next(
      'event',
      'delta',
      { eventType: 'stream.delta', text: input },
      'web-stream-unicode-1',
    );
    const snapshotSequence = router.currentSequence;
    const response = router.next(
      'response',
      'snapshot',
      { snapshot: { sequence: snapshotSequence, state: router.currentState } },
      'web-snapshot-unicode-1',
    );

    const decoded = new ProtocolDecoder().decode(`${JSON.stringify(response)}\n`);
    const snapshot = decoded.payload.snapshot as {
      state: { streams: Record<string, { text: string; truncated?: true }> };
    };
    const stream = snapshot.state.streams['web-stream-unicode-1'];
    expect(stream.text).toBe(expected);
    expect(stream.text.length).toBeLessThanOrEqual(8_192);
    expect(stream.truncated).toBe(truncated);
    const finalUnit = stream.text.charCodeAt(stream.text.length - 1);
    expect(finalUnit >= 0xd800 && finalUnit <= 0xdbff).toBe(false);
  });
});
