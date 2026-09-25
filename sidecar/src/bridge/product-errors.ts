import type { ProtocolError } from '@piui/protocol';
import { HostRequestError } from './host-requests.js';

const PRODUCT_ERROR_CODE = /^[a-z][a-z0-9-]{2,63}$/u;
const FALLBACK_CODE = 'product-operation-failed';

/**
 * Projects a failed `product.*` request onto the wire. Only a bare, bounded
 * kebab-case code thrown by PIUI or Pi crosses the boundary, so the host can
 * tell a busy or stale session from an outage. Anything else (Node errors,
 * paths, provider or credential text) collapses to product-operation-failed.
 */
export function productOperationError(error: unknown): ProtocolError {
  if (error instanceof HostRequestError) {
    return { category: error.category, message: error.code, retryable: error.retryable };
  }
  const code =
    error instanceof Error && PRODUCT_ERROR_CODE.test(error.message) ? error.message : FALLBACK_CODE;
  if (code === 'product-request-rejected') {
    return { category: 'invalid-request', message: code, retryable: false };
  }
  // Busy work finishes by itself; stale or externally changed state needs the
  // host to refresh before it tries again.
  if (code.endsWith('-busy') || code === 'session-turn-active') {
    return { category: 'conflict', message: code, retryable: true };
  }
  if (code.endsWith('-stale') || code.endsWith('-conflict') || code === 'session-external-change') {
    return { category: 'conflict', message: code, retryable: false };
  }
  return { category: 'unavailable', message: code, retryable: true };
}
