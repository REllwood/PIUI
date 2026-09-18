import { describe, expect, it } from 'vitest';
import {
  acknowledgeQueueItem,
  canActivateUpdates,
  createQueueItem,
  failQueueItem,
  reduceAuth,
  requestUpdateCheck,
  submitApproval,
  transitionTurn,
} from './machines';
import type { ApprovalRequest, UpdateState } from './types';

describe('domain state machines', () => {
  it('rejects illegal turn transitions and accepts terminal recovery', () => {
    expect(transitionTurn('idle', 'complete')).toBe('idle');
    expect(transitionTurn('streaming', 'complete')).toBe('complete');
    expect(transitionTurn('failed', 'sending')).toBe('sending');
  });

  it('preserves queue identity while acknowledgement assigns one ordering number', () => {
    const first = createQueueItem('local-1', ' first ');
    const second = createQueueItem('local-2', 'second');
    const acknowledged = acknowledgeQueueItem([first, second], 'local-1');
    expect(acknowledged[0]).toMatchObject({ text: 'first', state: 'acknowledged', number: 1 });
    expect(failQueueItem(acknowledged, 'local-2')[1]).toMatchObject({ state: 'failed' });
  });

  it('requires exact decision authority for approvals', () => {
    const request: ApprovalRequest = {
      id: 'approval-1',
      decisionId: 'decision-1',
      state: 'awaiting',
      action: 'Read',
      target: 'file',
      reason: 'Needed for context',
      dataLeavingMac: 'None',
      impact: 'Read-only',
      reversible: true,
      permittedDecisions: ['deny', 'approve-once'],
      rememberedScopeEligible: false,
    };
    expect(submitApproval(request, 'approve-once', 'forged')).toBe(request);
    expect(submitApproval(request, 'approve-project', 'decision-1')).toBe(request);
    expect(submitApproval(request, 'approve-once', 'decision-1').state).toBe('submitting');
  });

  it('models subscription sign-in expiry without retaining a validated account', () => {
    const opening = reduceAuth({ status: 'disconnected' }, { type: 'start', providerId: 'p' });
    const waiting = reduceAuth(opening, { type: 'browser-opened', expiresAt: 100 });
    expect(reduceAuth(waiting, { type: 'expire' })).toEqual({ status: 'expired', providerId: 'p' });
  });

  it('keeps updating disabled until both release prerequisites exist', () => {
    const disabled: UpdateState = {
      status: 'disabled',
      endpointConfigured: false,
      publicKeyConfigured: false,
      message: '',
    };
    expect(canActivateUpdates(disabled)).toBe(false);
    expect(requestUpdateCheck(disabled).status).toBe('disabled');
    expect(
      requestUpdateCheck({ ...disabled, endpointConfigured: true, publicKeyConfigured: true })
        .status,
    ).toBe('checking');
  });
});
