export type ErrorCode =
  | 'bridge-unavailable'
  | 'provider-offline'
  | 'authentication-expired'
  | 'workspace-inaccessible'
  | 'session-changed-externally'
  | 'save-conflict'
  | 'approval-unconfirmed'
  | 'update-verification-failed'
  | 'unknown';

export type SafeError = Readonly<{
  code: ErrorCode;
  title: string;
  message: string;
  recovery: string;
}>;

const safeErrors: Record<ErrorCode, SafeError> = {
  'bridge-unavailable': {
    code: 'bridge-unavailable',
    title: 'Local helper unavailable',
    message: 'PIUI cannot reach its local helper. Your conversation and draft remain on this Mac.',
    recovery: 'Try reconnecting. If that does not work, open Diagnostics before restarting PIUI.',
  },
  'provider-offline': {
    code: 'provider-offline',
    title: 'Provider is offline',
    message: 'The provider could not be reached. Existing work is still available.',
    recovery: 'Check your connection and try again. Unsent text remains in the composer.',
  },
  'authentication-expired': {
    code: 'authentication-expired',
    title: 'Sign-in expired',
    message: 'The provider did not confirm sign-in in time.',
    recovery: 'Start sign-in again. PIUI has not stored the unfinished sign-in details.',
  },
  'workspace-inaccessible': {
    code: 'workspace-inaccessible',
    title: 'Project is unavailable',
    message: 'PIUI no longer has access to the selected project folder.',
    recovery: 'Choose the folder again or select another project.',
  },
  'session-changed-externally': {
    code: 'session-changed-externally',
    title: 'Session changed elsewhere',
    message: 'Sending is paused because this session changed outside the current PIUI window.',
    recovery: 'Reload the latest session or open your draft on a new branch.',
  },
  'save-conflict': {
    code: 'save-conflict',
    title: 'Settings changed elsewhere',
    message: 'Your edits were not overwritten, but the saved settings are newer.',
    recovery: 'Review the latest values, then retry your save.',
  },
  'approval-unconfirmed': {
    code: 'approval-unconfirmed',
    title: 'Decision not confirmed',
    message:
      'PIUI did not receive acknowledgement for that decision, so the action remains blocked.',
    recovery: 'Retry the same decision or deny the request.',
  },
  'update-verification-failed': {
    code: 'update-verification-failed',
    title: 'Update could not be verified',
    message: 'PIUI did not install the update because its signature could not be verified.',
    recovery: 'Keep using this version and review Diagnostics before checking again.',
  },
  unknown: {
    code: 'unknown',
    title: 'Something did not finish',
    message: 'PIUI could not confirm that operation.',
    recovery: 'Try again or copy a safe report from Diagnostics.',
  },
};

export function safeError(code: string): SafeError {
  return safeErrors[code as ErrorCode] ?? safeErrors.unknown;
}

export type ProductErrorCopy = Readonly<{
  title: string;
  message: string;
  recovery: string;
}>;

// Product commands reject with a stable code such as `session-busy`; anything else is
// treated as `product-operation-failed` so raw host text never reaches the screen.
const PRODUCT_ERROR_CODE = /^[a-z][a-z0-9-]{2,63}$/u;
export const GENERIC_PRODUCT_ERROR = 'product-operation-failed';

const genericProductError: ProductErrorCopy = Object.freeze({
  title: 'Something did not finish',
  message: 'PIUI could not complete that action.',
  recovery: 'Try again. If it keeps happening, open Diagnostics.',
});

const productErrors: Readonly<Record<string, ProductErrorCopy>> = Object.freeze({
  'session-busy': {
    title: 'Conversation is busy',
    message: 'Pi is still finishing other work in this conversation.',
    recovery: 'Wait a moment, then try again.',
  },
  'session-turn-active': {
    title: 'Pi is working',
    message: 'This cannot change while Pi is responding.',
    recovery: 'Stop the current turn or wait for it to finish, then try again.',
  },
  'turn-active': {
    title: 'Pi is working',
    message: 'This cannot change while Pi is responding.',
    recovery: 'Stop the current turn or wait for it to finish, then try again.',
  },
  'operation-busy': {
    title: 'Another action is running',
    message: 'PIUI is still finishing another action.',
    recovery: 'Wait for it to finish, then try again.',
  },
  'session-generation-stale': {
    title: 'Conversation has moved on',
    message: 'This conversation changed after PIUI last loaded it.',
    recovery: 'Reopen it from Sessions to load the latest version, then try again.',
  },
  'session-external-change': {
    title: 'Session changed elsewhere',
    message: 'This session was changed outside this PIUI window.',
    recovery: 'Reload the latest session, or open a branch to keep your draft.',
  },
  'session-file-unavailable': {
    title: 'Session file unavailable',
    message: 'PIUI could not read this session’s file.',
    recovery: 'Check the project folder is still available, then reopen the session from Sessions.',
  },
  'session-recovery-required': {
    title: 'Session needs recovery',
    message: 'This session needs to be recovered before it can continue.',
    recovery: 'Open Diagnostics, or start a new conversation to keep working.',
  },
  'provider-model-unavailable': {
    title: 'Model unavailable',
    message: 'The chosen model is not available from this provider right now.',
    recovery: 'Choose another model, then try again.',
  },
  'provider-not-connected': {
    title: 'Provider not connected',
    message: 'No provider account is connected for this conversation.',
    recovery: 'Connect a provider in Settings, then try again.',
  },
  'workspace-not-trusted': {
    title: 'Project not trusted',
    message: 'Pi cannot work in this project until you trust it.',
    recovery: 'Review and trust the project in Settings, under Projects & trust.',
  },
  'workspace-disconnected': {
    title: 'Project unavailable',
    message: 'PIUI no longer has access to this project folder.',
    recovery: 'Choose the project folder again to renew access.',
  },
  'resource-risk-acknowledgement-required': {
    title: 'Review needed first',
    message: 'This executable resource needs your acknowledgement before it can be enabled.',
    recovery: 'Read the warning, then choose Review and enable again.',
  },
  'resource-package-manager-unavailable': {
    title: 'Package manager unavailable',
    message: 'Pi’s package manager could not be started.',
    recovery: 'Check Diagnostics, then try again.',
  },
  'resource-offline-unavailable': {
    title: 'You are offline',
    message: 'This needs an internet connection.',
    recovery: 'Reconnect this Mac to the internet, then try again.',
  },
  'turn-retry-stale': {
    title: 'Retry no longer available',
    message: 'The last message cannot be retried because the conversation has moved on.',
    recovery: 'Send your message again as a new turn.',
  },
  'turn-terminal-timeout': {
    title: 'No reply from Pi',
    message: 'Pi stopped reporting progress on this turn, so PIUI has stopped waiting.',
    recovery: 'Send your message again. If it keeps happening, open Diagnostics.',
  },
  'turn-events-overflowed': {
    title: 'Turn could not be followed',
    message: 'Pi sent more updates than PIUI could safely hold, so the turn was stopped.',
    recovery: 'Send your message again.',
  },
  'change-undo-revoked': {
    title: 'Undo no longer available',
    message: 'This change can no longer be undone safely because the file has changed since.',
    recovery: 'Review the file and correct it by hand, or ask Pi to help.',
  },
  [GENERIC_PRODUCT_ERROR]: genericProductError,
});

function rawErrorCode(error: unknown): string | null {
  if (typeof error === 'string') return error;
  if (error instanceof Error) return error.message;
  if (error !== null && typeof error === 'object' && 'code' in error) {
    const { code } = error as { code: unknown };
    return typeof code === 'string' ? code : null;
  }
  return null;
}

export function productErrorCode(error: unknown): string {
  const code = rawErrorCode(error);
  return code !== null && PRODUCT_ERROR_CODE.test(code) ? code : GENERIC_PRODUCT_ERROR;
}

// Unknown codes get the generic copy and are never reflected on screen.
export function productErrorCopy(error: unknown): ProductErrorCopy & { code: string } {
  const code = productErrorCode(error);
  const copy = productErrors[code];
  return copy
    ? Object.freeze({ code, ...copy })
    : Object.freeze({ code: GENERIC_PRODUCT_ERROR, ...genericProductError });
}

// A sentence pair for inline status text. Callers may pass the context-specific copy
// they already show for failures that carry no recognised code.
export function productErrorMessage(error: unknown, fallback?: string): string {
  const copy = productErrorCopy(error);
  if (copy.code === GENERIC_PRODUCT_ERROR && fallback) return fallback;
  return `${copy.message} ${copy.recovery}`;
}

export function redactForDisplay(value: string): string {
  return value
    .replace(
      /((?:api[_-]?key|authorization|cookie|set-cookie|token|secret|password|client[_-]?secret))\s*[:=]\s*(?:bearer\s+)?(?:"[^"]*"|'[^']*'|[^\s,;]*)/giu,
      '$1=[redacted]',
    )
    .replace(/\bbearer\s+[A-Za-z0-9._~+/=-]+/giu, 'Bearer [redacted]')
    .replace(/\/Users\/[^/\s]+/gu, '/Users/[home]')
    .replace(/([?&](?:code|state|token|key)=)[^&\s]+/giu, '$1[redacted]');
}
