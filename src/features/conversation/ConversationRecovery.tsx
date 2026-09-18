import { Icon } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import type { ConnectionState } from '../../domain/types';

export function ConversationRecovery({
  state,
  busy,
  failureReason,
  onReconnect,
  onReload,
  onBranch,
}: Readonly<{
  state: ConnectionState;
  busy: boolean;
  failureReason?: string | null;
  onReconnect: () => Promise<void>;
  onReload: () => Promise<void>;
  onBranch: () => Promise<void>;
}>) {
  if (state === 'ready') return null;
  const copy = {
    restoring: [
      'Restoring your local session',
      'Conversation history is being checked before sending is enabled.',
    ],
    offline: ['You are offline', 'Existing messages remain available and your draft will be kept.'],
    reconnecting: ['Reconnecting local helper', 'PIUI is restoring the private local connection.'],
    'restart-offered': [
      'Local helper stopped',
      'Restart the helper to continue. Your history and draft are retained.',
    ],
    'restart-failed': [
      'Local helper could not restart',
      // The reason is a fixed host string with no path or payload in it, so it
      // can be named here instead of leaving the failure unexplained.
      failureReason
        ? `Reported reason: ${failureReason}. Open Diagnostics for a safe report and recovery steps.`
        : 'Open Diagnostics for a safe report and recovery steps.',
    ],
    'external-change': [
      'Session changed elsewhere',
      'Sending is paused. Reload the latest session or open a branch to preserve this draft.',
    ],
  }[state];
  return (
    <aside className="conversation-recovery" role="status">
      <Icon name={state === 'external-change' ? 'branch' : 'warning'} />
      <div>
        <strong>{copy[0]}</strong>
        <span>{copy[1]}</span>
      </div>
      {state === 'external-change' ? (
        <>
          <button type="button" className="button" onClick={() => void onReload()} disabled={busy}>
            {busy ? <LoadingLabel>Reloading…</LoadingLabel> : 'Reload latest'}
          </button>
          <button
            type="button"
            className="button button--primary"
            onClick={() => void onBranch()}
            disabled={busy}
          >
            {busy ? <LoadingLabel>Opening…</LoadingLabel> : 'Open a branch'}
          </button>
        </>
      ) : (
        <button type="button" className="button" onClick={() => void onReconnect()} disabled={busy}>
          {busy ? (
            <LoadingLabel>Reconnecting…</LoadingLabel>
          ) : (
            <>
              <Icon name="refresh" />
              Reconnect
            </>
          )}
        </button>
      )}
    </aside>
  );
}
