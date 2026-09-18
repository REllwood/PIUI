import { Icon } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { StatusPill } from '../../components/primitives/StatusPill';

export function ConversationHeader({
  title,
  branch,
  busy,
  unavailable,
  onBranch,
  onExport,
}: Readonly<{
  title: string;
  branch?: string;
  busy: 'session' | 'export' | null;
  unavailable: boolean;
  onBranch: () => Promise<void>;
  onExport: () => Promise<void>;
}>) {
  return (
    <header className="conversation-header">
      <div>
        <h1>{title}</h1>
        <div className="conversation-header__meta">
          {branch ? (
            <StatusPill>
              <Icon name="branch" />
              {branch}
            </StatusPill>
          ) : null}
          <span>Saved on this Mac</span>
        </div>
      </div>
      <div className="conversation-header__actions">
        <button
          type="button"
          className="button button--quiet"
          aria-label={busy === 'session' ? 'Branching session' : 'Branch session'}
          disabled={busy !== null || unavailable}
          onClick={() => void onBranch()}
        >
          {busy === 'session' ? (
            <LoadingLabel>Branching…</LoadingLabel>
          ) : (
            <>
              <Icon name="branch" />
              <span className="conversation-header__action-label">Branch</span>
            </>
          )}
        </button>
        <button
          type="button"
          className="button button--quiet"
          aria-label={busy === 'export' ? 'Exporting session' : 'Export session'}
          disabled={busy !== null || unavailable}
          onClick={() => void onExport()}
        >
          {busy === 'export' ? (
            <LoadingLabel>Exporting…</LoadingLabel>
          ) : (
            <>
              <Icon name="download" />
              <span className="conversation-header__action-label">Export</span>
            </>
          )}
        </button>
      </div>
    </header>
  );
}
