import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  A28_TRANSCRIPT,
  A28_TRANSCRIPT_COUNT,
  nextA28TranscriptIndex,
} from './AccessibilityProbe';
import {
  A28_HUMAN_WITNESS_READY_EVENT,
  assertA28HumanWitnessLease,
} from './a28WitnessContract';

describe('A.28 fixed transcript accessibility contract', () => {
  it('has exactly 100 stable, ordered and named rows', () => {
    expect(A28_TRANSCRIPT_COUNT).toBe(100);
    expect(A28_TRANSCRIPT).toHaveLength(100);
    expect(new Set(A28_TRANSCRIPT.map((item) => item.id)).size).toBe(100);
    expect(A28_TRANSCRIPT[0]).toMatchObject({ id: 'a28-transcript-row-1', ordinal: 1 });
    expect(A28_TRANSCRIPT[99]).toMatchObject({ id: 'a28-transcript-row-100', ordinal: 100 });
    expect(A28_TRANSCRIPT.every((item) => item.text.length > 0)).toBe(true);
  });

  it('bounds Arrow, Home, End and Page navigation', () => {
    expect(nextA28TranscriptIndex(0, 'ArrowUp')).toBe(0);
    expect(nextA28TranscriptIndex(0, 'ArrowDown')).toBe(1);
    expect(nextA28TranscriptIndex(50, 'Home')).toBe(0);
    expect(nextA28TranscriptIndex(50, 'End')).toBe(99);
    expect(nextA28TranscriptIndex(95, 'PageDown')).toBe(99);
    expect(nextA28TranscriptIndex(4, 'PageUp')).toBe(0);
    expect(nextA28TranscriptIndex(40, 'Tab')).toBeNull();
    expect(nextA28TranscriptIndex(-1, 'ArrowDown')).toBeNull();
  });

  it('keeps visible preparation and explicit virtual/non-virtual semantics', () => {
    const source = readFileSync(new URL('./AccessibilityProbe.tsx', import.meta.url), 'utf8');
    expect(source).toContain('useVirtualizer');
    expect(source).toContain('aria-busy={busy}');
    expect(source).toContain('role="status"');
    expect(source).toContain('a28-probe__spinner');
    expect(source).toContain('Prepare accessibility fixture');
    expect(source).toContain('Preparing the accessibility transcript…');
    expect(source).toContain('aria-posinset={item.ordinal}');
    expect(source).toContain('aria-setsize={A28_TRANSCRIPT_COUNT}');
    expect(source).toContain('Virtualised transcript');
    expect(source).toContain('Accessible transcript');
    expect(source).toContain("setFocusedIndex(index)");
  });

  it('shows only a strict safe retained-human lease with a waiting indicator', () => {
    const nonce = 'd'.repeat(64);
    const lease = {
      applicationPid: 1234,
      automationTwinFingerprint: 'a'.repeat(64),
      evidenceDirectory: `.forge/evidence/architecture-accessibility/${nonce}`,
      macosVersion: '15.6.1',
      productionFingerprint: 'b'.repeat(64),
      schemaVersion: 1,
      sourceDigest: 'c'.repeat(64),
      startedAt: '2026-07-31T12:00:00.000Z',
      state: 'waiting-for-human',
      witnessNonce: nonce,
    };
    expect(A28_HUMAN_WITNESS_READY_EVENT).toBe('piui:a28-human-witness-ready');
    expect(assertA28HumanWitnessLease(lease)).toEqual(lease);
    for (const changed of [
      { ...lease, evidenceDirectory: '/private/witness' },
      { ...lease, applicationPid: 1 },
      { ...lease, activationNonce: 'e'.repeat(64) },
    ]) {
      expect(() => assertA28HumanWitnessLease(changed))
        .toThrow('a28-human-witness-lease-rejected');
    }

    const source = readFileSync(new URL('./AccessibilityProbe.tsx', import.meta.url), 'utf8');
    expect(source).toContain('data-a28-human-witness=""');
    expect(source).toContain('aria-busy="true"');
    expect(source).toContain('<progress aria-label="Waiting for human VoiceOver evidence" />');
    expect(source).toContain('Exact packaged twin retained');
    expect(source).toContain('Complete all four VoiceOver checks');
    expect(source).not.toContain('PIUI_ARCHITECTURE_TEST_NONCE');
  });
});
