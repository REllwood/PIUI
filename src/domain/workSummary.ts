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

// The event a person most needs to see in a short trace: the latest one waiting on them,
// then the latest one still in progress, then simply the latest.
export function focalActivityId(activity: readonly ActivityEvent[]): string | null {
  let inProgress: ActivityEvent | undefined;
  for (let index = activity.length - 1; index >= 0; index -= 1) {
    const event = activity[index];
    if (!event) continue;
    if (event.state === 'waiting') return event.id;
    if (!inProgress && isActivityInProgress(event.state)) inProgress = event;
  }
  return (inProgress ?? activity.at(-1))?.id ?? null;
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
