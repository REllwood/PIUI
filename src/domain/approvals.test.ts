import { describe, expect, it } from 'vitest';
import { reconcileApprovals } from './approvals';
import type { ApprovalRequest } from './types';

function approval(overrides: Partial<ApprovalRequest> = {}): ApprovalRequest {
  return {
    id: 'approval-1',
    decisionId: 'decision-1',
    revision: 1,
    state: 'awaiting',
    action: 'Run command',
    target: 'pnpm test',
    reason: 'Pi requested this exact action for the current turn.',
    dataLeavingMac: 'This approval covers the displayed local action only.',
    impact: 'The action is limited to the displayed target and current request.',
    reversible: true,
    expiresAt: '2026-09-25T02:00:00.000Z',
    permittedDecisions: ['approve-once', 'deny'],
    rememberedScopeEligible: false,
    scopeIds: [],
    ...overrides,
  };
}

describe('approval polling', () => {
  it('returns the current list when a poll finds nothing new', () => {
    const current = [approval()];
    // A later poll derives a later expiry from the same remaining time.
    const polled = [approval({ expiresAt: '2026-09-25T02:00:00.750Z' })];
    expect(reconcileApprovals(current, polled)).toBe(current);
  });

  it('keeps the first derived expiry for the same revision', () => {
    const current = [approval()];
    const next = reconcileApprovals(current, [
      approval({ state: 'policy-check', expiresAt: '2026-09-25T02:00:01.500Z' }),
    ]);
    expect(next).not.toBe(current);
    expect(next[0]?.expiresAt).toBe('2026-09-25T02:00:00.000Z');
  });

  it('takes the new expiry when the host revises the approval', () => {
    const next = reconcileApprovals(
      [approval()],
      [approval({ revision: 2, expiresAt: '2026-09-25T02:05:00.000Z' })],
    );
    expect(next[0]?.expiresAt).toBe('2026-09-25T02:05:00.000Z');
  });

  it('reports added and removed approvals', () => {
    const current = [approval()];
    expect(reconcileApprovals(current, [])).toEqual([]);
    const added = reconcileApprovals(current, [approval(), approval({ id: 'approval-2' })]);
    expect(added).toHaveLength(2);
    expect(added[0]).toBe(current[0]);
  });
});
