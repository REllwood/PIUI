import { describe, expect, it } from 'vitest';
import { redactForDisplay, safeError } from './errors';

describe('safe errors', () => {
  it('falls back without reflecting unknown internal codes', () => {
    expect(safeError('internal-secret-path')).toEqual(safeError('unknown'));
  });

  it('redacts credential values, query secrets and home names', () => {
    const value = redactForDisplay(
      'authorization: Bearer-canary /Users/example/work?code=oauth-canary&state=state-canary',
    );
    expect(value).toContain('authorization=[redacted]');
    expect(value).toContain('/Users/[home]');
    expect(value).toContain('code=[redacted]');
    expect(value).toContain('state=[redacted]');
    expect(value).not.toContain('Bearer-canary');
    expect(value).not.toContain('/Users/example');
    expect(value).not.toContain('oauth-canary');
  });
});
