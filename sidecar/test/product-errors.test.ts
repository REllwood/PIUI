import { describe, expect, it } from 'vitest';
import { HostRequestError } from '../src/bridge/host-requests';
import { productOperationError } from '../src/bridge/product-errors';

describe('product operation errors', () => {
  it('forwards bounded product codes with a sensible category', () => {
    expect(productOperationError(new Error('session-busy'))).toEqual({
      category: 'conflict',
      message: 'session-busy',
      retryable: true,
    });
    expect(productOperationError(new Error('session-generation-stale'))).toEqual({
      category: 'conflict',
      message: 'session-generation-stale',
      retryable: false,
    });
    expect(productOperationError(new Error('session-external-change'))).toMatchObject({
      category: 'conflict',
      retryable: false,
    });
    expect(productOperationError(new Error('provider-model-unavailable'))).toEqual({
      category: 'unavailable',
      message: 'provider-model-unavailable',
      retryable: true,
    });
    expect(productOperationError(new Error('product-request-rejected'))).toEqual({
      category: 'invalid-request',
      message: 'product-request-rejected',
      retryable: false,
    });
  });

  it('uses the host request code rather than its display text', () => {
    expect(productOperationError(new HostRequestError('credential-request-timeout'))).toMatchObject({
      message: 'credential-request-timeout',
    });
  });

  it('never forwards free text, paths or unbounded values', () => {
    for (const error of [
      new Error("ENOENT: no such file or directory, stat '/Users/someone/.pi/agent/x.jsonl'"),
      new Error('Authentication failed for "anthropic".'),
      new Error('ab'),
      new Error(`a${'b'.repeat(64)}`),
      new Error('Session-Busy'),
      new Error('session_busy'),
      'session-busy',
      undefined,
    ]) {
      expect(productOperationError(error)).toEqual({
        category: 'unavailable',
        message: 'product-operation-failed',
        retryable: true,
      });
    }
  });
});
