import { DiffView } from '../../components/diff/DiffView';
import { Icon } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { countLabel } from '../../domain/copy';
import type { FileChange } from '../../domain/types';

export function DiffReview({
  change,
  busy,
  onUndo,
  onReveal,
  onClose,
}: Readonly<{
  change: FileChange;
  busy: boolean;
  onUndo: () => Promise<void>;
  onReveal: () => Promise<void>;
  onClose?: () => void;
}>) {
  return (
    <section className="diff-review" aria-label="Change review">
      <header className="context-detail__header">
        <div>
          <p className="ui-label">Change review</p>
          <h2>
            {countLabel(change.additions, 'addition')}, {countLabel(change.deletions, 'deletion')}
          </h2>
        </div>
        {onClose ? (
          <button
            type="button"
            className="icon-button"
            onClick={onClose}
            aria-label="Close change review"
          >
            <Icon name="close" />
          </button>
        ) : null}
      </header>
      <DiffView change={change} />
      <footer className="diff-review__footer">
        <button
          type="button"
          className="button"
          disabled={busy || change.undo !== 'safe'}
          onClick={() => void onUndo()}
          title={
            change.undo === 'revoked'
              ? 'Undo is unavailable because the file changed after this operation.'
              : undefined
          }
        >
          {busy && change.undo === 'submitting' ? (
            <LoadingLabel>Undoing…</LoadingLabel>
          ) : change.undo === 'complete' ? (
            'Change undone'
          ) : (
            'Undo this change'
          )}
        </button>
        <button
          type="button"
          className="button button--quiet"
          disabled={busy || change.state === 'deleted'}
          onClick={() => void onReveal()}
        >
          {busy && change.undo !== 'submitting' ? (
            <LoadingLabel>Opening…</LoadingLabel>
          ) : (
            <>
              <Icon name="folder" />
              Reveal in Finder
            </>
          )}
        </button>
        <p>
          Undo remains available only while the current file matches the recorded post-change
          identity.
        </p>
      </footer>
    </section>
  );
}
