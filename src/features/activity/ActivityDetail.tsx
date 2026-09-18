import { useState } from 'react';
import { Icon } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { StatusPill } from '../../components/primitives/StatusPill';
import type { ActivityEvent } from '../../domain/types';

function toneForState(state: ActivityEvent['state']): 'work' | 'warning' | 'success' | 'danger' {
  if (state === 'running' || state === 'cancelling') return 'work';
  if (state === 'waiting' || state === 'too-late') return 'warning';
  if (state === 'complete') return 'success';
  return 'danger';
}

export function ActivityDetail({
  event,
  onClose,
  onCancel,
}: Readonly<{ event: ActivityEvent; onClose?: () => void; onCancel: () => Promise<void> }>) {
  const [cancelling, setCancelling] = useState(false);
  const cancel = async () => {
    if (cancelling) return;
    setCancelling(true);
    try {
      await onCancel();
    } finally {
      setCancelling(false);
    }
  };
  return (
    <section className="context-detail" aria-labelledby={`activity-detail-${event.id}`}>
      <header className="context-detail__header">
        <div>
          <p className="ui-label">Work detail</p>
          <h2 id={`activity-detail-${event.id}`}>
            {event.verb} {event.target}
          </h2>
        </div>
        {onClose ? (
          <button
            type="button"
            className="icon-button"
            onClick={onClose}
            aria-label="Close activity detail"
          >
            <Icon name="close" />
          </button>
        ) : null}
      </header>
      <StatusPill tone={toneForState(event.state)}>
        {event.state} · {event.elapsed}
      </StatusPill>
      <p>{event.summary}</p>
      <dl className="detail-list">
        <div>
          <dt>Action</dt>
          <dd>{event.verb}</dd>
        </div>
        <div>
          <dt>Target</dt>
          <dd>{event.target}</dd>
        </div>
        <div>
          <dt>State</dt>
          <dd>{event.state}</dd>
        </div>
        <div>
          <dt>Evidence</dt>
          <dd>{event.evidence ?? 'No additional output was recorded.'}</dd>
        </div>
      </dl>
      {event.state === 'running' ? (
        <button
          type="button"
          className="button"
          disabled={cancelling}
          onClick={() => void cancel()}
        >
          {cancelling ? (
            <LoadingLabel>Cancelling safely…</LoadingLabel>
          ) : (
            <>
              <Icon name="stop" />
              Cancel safely
            </>
          )}
        </button>
      ) : null}
    </section>
  );
}
