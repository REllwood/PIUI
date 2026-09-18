import { describe, expect, it } from 'vitest';
import { validateOAuthReturn } from '../../sidecar/src/credentials/oauth';

describe('OAuth return binding', () => {
  it('accepts one exact bounded state and rejects replay, mismatch and malformed values', () => {
    const expected = 'A_secure_state_value_0123456789abcdef';
    const consumed = new Set<string>();
    expect(validateOAuthReturn(expected, expected, consumed)).toBe(true);
    expect(validateOAuthReturn(expected, expected, consumed)).toBe(false);
    expect(
      validateOAuthReturn(expected, 'B_secure_state_value_0123456789abcdef', consumed),
    ).toBe(false);
    expect(validateOAuthReturn('short', 'short', new Set())).toBe(false);
    expect(validateOAuthReturn(`${'x'.repeat(128)}!`, `${'x'.repeat(128)}!`, new Set())).toBe(
      false,
    );
  });
});
