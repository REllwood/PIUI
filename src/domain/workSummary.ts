import { isTurnActive } from './machines';
import type { ActivityEvent, ActivityState, TurnStatus } from './types';

const IN_PROGRESS_ACTIVITY: ReadonlySet<ActivityState> = new Set([
  'running',
  'waiting',
  'cancelling',
]);

export function isActivityInProgress(state: ActivityState): boolean {
  return IN_PROGRESS_ACTIVITY.has(state);
}

// The work summary must never claim completion while a tool or the turn is still going.
export function workSummaryLabel(
  activity: readonly ActivityEvent[],
  approvalPending: boolean,
  turnStatus: TurnStatus,
): string {
  if (approvalPending) return 'Waiting for your approval';
  const inProgress = activity.filter((item) => isActivityInProgress(item.state)).length;
  if (inProgress > 0) return `${inProgress} running`;
  if (isTurnActive(turnStatus)) return 'Pi is working';
  return 'Work complete';
}
