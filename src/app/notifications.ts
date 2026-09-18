export type NotificationIntent = Readonly<{
  kind: 'approval-waiting' | 'work-complete';
  contextLabel: string;
  opensPiuiOnly: true;
}>;

export function notificationIntent(
  kind: NotificationIntent['kind'],
  contextLabel: string,
): NotificationIntent {
  return Object.freeze({ kind, contextLabel: contextLabel.slice(0, 120), opensPiuiOnly: true });
}

export function notificationMayChangeApproval(): false {
  return false;
}
