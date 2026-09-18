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
