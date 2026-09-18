import type { QueueItem } from '../../domain/types';
import { Icon } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';

export function ComposerQueue({
  items,
  onRemove,
  onRetry,
  action,
}: Readonly<{
  items: readonly QueueItem[];
  onRemove: (id: string) => Promise<void>;
  onRetry: (id: string) => Promise<void>;
  action: Readonly<{ id: string; kind: 'retry' | 'remove' }> | null;
}>) {
  if (items.length === 0) return null;
  return (
    <ol className="composer-queue" aria-label="Queued follow-ups">
      {items.map((item) => (
        <li key={item.localId} data-state={item.state}>
          <span className="composer-queue__number">{item.number ?? '—'}</span>
          <span className="composer-queue__text">{item.text}</span>
          <span className="composer-queue__state">
            {item.state === 'persisting' ? (
              <LoadingLabel>Saving…</LoadingLabel>
            ) : item.state === 'failed' ? (
              'Not saved'
            ) : (
              item.state
            )}
          </span>
          {item.state === 'failed' ? (
            <button
              type="button"
              className="button button--quiet"
              disabled={action !== null}
              onClick={() => void onRetry(item.localId)}
            >
              {action?.id === item.localId && action.kind === 'retry' ? (
                <LoadingLabel>Retrying…</LoadingLabel>
              ) : (
                'Retry'
              )}
            </button>
          ) : null}
          <button
            type="button"
            className="icon-button"
            disabled={action !== null}
            onClick={() => void onRemove(item.localId)}
            aria-label={`Remove queued prompt ${item.number ?? ''}`}
          >
            {action?.id === item.localId && action.kind === 'remove' ? (
              <LoadingLabel>Removing…</LoadingLabel>
            ) : (
              <Icon name="close" />
            )}
          </button>
        </li>
      ))}
    </ol>
  );
}
