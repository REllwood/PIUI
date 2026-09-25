import type {
  ApprovalDecision,
  ApprovalRequest,
  QueueItem,
  TurnStatus,
  UpdateState,
} from './types';

export type AuthState =
  | Readonly<{ status: 'disconnected' }>
  | Readonly<{ status: 'opening-browser'; providerId: string }>
  | Readonly<{ status: 'waiting'; providerId: string; expiresAt: number }>
  | Readonly<{ status: 'validated'; providerId: string; accountLabel: string }>
  | Readonly<{ status: 'cancelled' | 'expired' | 'invalid' | 'offline'; providerId: string }>;

export type AuthEvent =
  | Readonly<{ type: 'start'; providerId: string }>
  | Readonly<{ type: 'browser-opened'; expiresAt: number }>
  | Readonly<{ type: 'validated'; accountLabel: string }>
  | Readonly<{ type: 'cancel' | 'expire' | 'reject' | 'offline' }>
  | Readonly<{ type: 'reset' }>;

export function reduceAuth(state: AuthState, event: AuthEvent): AuthState {
  if (event.type === 'reset') return { status: 'disconnected' };
  if (event.type === 'start') return { status: 'opening-browser', providerId: event.providerId };
  if (!('providerId' in state)) return state;
  if (event.type === 'browser-opened' && state.status === 'opening-browser') {
    return { status: 'waiting', providerId: state.providerId, expiresAt: event.expiresAt };
  }
  if (
    event.type === 'validated' &&
    (state.status === 'waiting' || state.status === 'opening-browser')
  ) {
    return { status: 'validated', providerId: state.providerId, accountLabel: event.accountLabel };
  }
  if (event.type === 'cancel') return { status: 'cancelled', providerId: state.providerId };
  if (event.type === 'expire') return { status: 'expired', providerId: state.providerId };
  if (event.type === 'reject') return { status: 'invalid', providerId: state.providerId };
  if (event.type === 'offline') return { status: 'offline', providerId: state.providerId };
  return state;
}

const ACTIVE_TURN_STATUSES: ReadonlySet<TurnStatus> = new Set([
  'sending',
  'streaming',
  'tool-running',
  'stop-requested',
  'cancel-too-late',
]);

export function isTurnActive(status: TurnStatus): boolean {
  return ACTIVE_TURN_STATUSES.has(status);
}

const turnTransitions: Readonly<Record<TurnStatus, readonly TurnStatus[]>> = {
  idle: ['sending', 'offline-queued'],
  sending: ['streaming', 'failed', 'stop-requested'],
  streaming: ['tool-running', 'stop-requested', 'failed', 'complete'],
  'tool-running': ['streaming', 'stop-requested', 'failed', 'complete'],
  'stop-requested': ['stopped', 'cancel-too-late', 'failed'],
  stopped: ['sending', 'idle'],
  'cancel-too-late': ['streaming', 'tool-running', 'complete', 'failed'],
  failed: ['sending', 'idle'],
  complete: ['sending', 'idle'],
  'offline-queued': ['sending', 'idle'],
};

export function transitionTurn(current: TurnStatus, next: TurnStatus): TurnStatus {
  return turnTransitions[current].includes(next) ? next : current;
}

export function createQueueItem(localId: string, text: string): QueueItem {
  return { localId, text: text.trim(), state: 'persisting' };
}

export function acknowledgeQueueItem(
  items: readonly QueueItem[],
  localId: string,
): readonly QueueItem[] {
  const nextNumber = Math.max(0, ...items.map((item) => item.number ?? 0)) + 1;
  return items.map((item) =>
    item.localId === localId
      ? { ...item, number: nextNumber, state: 'acknowledged' as const }
      : item,
  );
}

export function failQueueItem(items: readonly QueueItem[], localId: string): readonly QueueItem[] {
  return items.map((item) =>
    item.localId === localId ? { ...item, number: undefined, state: 'failed' as const } : item,
  );
}

export function submitApproval(
  request: ApprovalRequest,
  decision: ApprovalDecision,
  decisionId: string,
): ApprovalRequest {
  if (request.state !== 'awaiting' && request.state !== 'unacknowledged') return request;
  if (request.decisionId !== decisionId || !request.permittedDecisions.includes(decision))
    return request;
  if (decision === 'approve-project' && !request.rememberedScopeEligible) return request;
  return { ...request, state: 'submitting' };
}

export function canActivateUpdates(update: UpdateState): boolean {
  return update.endpointConfigured && update.publicKeyConfigured;
}

export function requestUpdateCheck(update: UpdateState): UpdateState {
  if (!canActivateUpdates(update)) {
    return {
      ...update,
      status: 'disabled',
      message:
        'Updates remain disabled until an HTTPS endpoint and public verification key are configured.',
    };
  }
  return { ...update, status: 'checking', message: 'Checking for a signed update…' };
}
