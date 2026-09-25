import { describe, expect, it } from 'vitest';
import {
  GENERIC_PRODUCT_ERROR,
  productErrorCode,
  productErrorCopy,
  productErrorMessage,
  redactForDisplay,
  safeError,
} from './errors';

describe('product error codes', () => {
  const required = [
    'session-busy',
    'session-turn-active',
    'session-generation-stale',
    'session-external-change',
    'session-file-unavailable',
    'session-recovery-required',
    'provider-model-unavailable',
    'provider-not-connected',
    'workspace-not-trusted',
    'workspace-disconnected',
    'resource-risk-acknowledgement-required',
    'resource-package-manager-unavailable',
    'resource-offline-unavailable',
    'turn-retry-stale',
    'change-undo-revoked',
    'product-operation-failed',
  ];

  it('gives every common code its own plain-English copy with a next step', () => {
    const generic = productErrorCopy(GENERIC_PRODUCT_ERROR);
    for (const code of required) {
      const copy = productErrorCopy(code);
      expect(copy.code, code).toBe(code);
      expect(copy.message, code).toMatch(/\.$/u);
      expect(copy.recovery, code).toMatch(/\.$/u);
      expect(`${copy.title} ${copy.message} ${copy.recovery}`, code).not.toContain(code);
      if (code !== GENERIC_PRODUCT_ERROR) expect(copy.message, code).not.toBe(generic.message);
    }
  });

  it.each([
    [
      'session-workspace-untrusted',
      'This conversation’s project is no longer trusted the way it was when it started. Trust the project again in Settings, under Projects & trust. PIUI then reloads your sessions.',
    ],
    [
      'host-stream-deadline-exceeded',
      'Pi’s reply took longer than PIUI can wait for. Try again.',
    ],
    [
      'host-stream-limit-exceeded',
      'Pi’s reply was longer than PIUI can show. Ask for a shorter answer, or split the task into smaller steps.',
    ],
    [
      'host-stream-interrupted',
      'The connection to Pi was interrupted before the reply finished. Reconnect to Pi, then try again.',
    ],
  ])('explains %s with its next step', (code, expected) => {
    expect(productErrorCopy(code).code).toBe(code);
    expect(productErrorMessage(code, 'Fallback that must not be used.')).toBe(expected);
    // Stream terminals arrive as bare codes, like any other product rejection.
    expect(productErrorMessage(new Error(code))).toBe(expected);
  });

  it('reads codes from Tauri string rejections, errors and coded objects', () => {
    expect(productErrorCode('session-busy')).toBe('session-busy');
    expect(productErrorCode(new Error('workspace-not-trusted'))).toBe('workspace-not-trusted');
    expect(productErrorCode({ code: 'turn-retry-stale' })).toBe('turn-retry-stale');
  });

  it('treats malformed or free-text rejections as the generic failure', () => {
    for (const value of [
      'Session file /Users/example/.pi/session.jsonl is locked',
      'X',
      'ab',
      `a${'b'.repeat(64)}`,
      'Session-Busy',
      { code: 42 },
      null,
      undefined,
    ]) {
      expect(productErrorCode(value)).toBe(GENERIC_PRODUCT_ERROR);
    }
  });

  it('falls back to generic copy for unknown codes without reflecting them', () => {
    const copy = productErrorCopy('internal-secret-code');
    expect(copy.code).toBe(GENERIC_PRODUCT_ERROR);
    expect(JSON.stringify(copy)).not.toContain('internal-secret-code');
    expect(productErrorMessage('internal-secret-code', 'The session was not renamed.')).toBe(
      'The session was not renamed.',
    );
    expect(productErrorMessage('session-busy', 'The session was not renamed.')).toBe(
      'Pi is still finishing other work in this conversation. Wait a moment, then try again.',
    );
  });
});

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
