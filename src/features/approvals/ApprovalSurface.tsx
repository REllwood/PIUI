import { Icon } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { StatusPill } from '../../components/primitives/StatusPill';
import type { ApprovalDecision, ApprovalRequest } from '../../domain/types';

export function ApprovalSurface({
  request,
  offline,
  busy,
  onDecision,
  onClose,
}: Readonly<{
  request: ApprovalRequest;
  offline: boolean;
  busy: boolean;
  onDecision: (decision: ApprovalDecision) => Promise<void>;
  onClose?: () => void;
}>) {
  const waiting = request.state === 'awaiting' || request.state === 'unacknowledged';
  return (
    <section className="approval-surface" aria-labelledby={`approval-${request.id}`}>
      <header className="context-detail__header">
        <div>
          <p className="ui-label">Approval needed</p>
          <h2 id={`approval-${request.id}`}>{request.action}</h2>
        </div>
        {onClose ? (
          <button
            type="button"
            className="icon-button"
            onClick={onClose}
            aria-label="Close approval"
          >
            <Icon name="close" />
          </button>
        ) : null}
      </header>
      <StatusPill
        tone={
          request.state === 'approved'
            ? 'success'
            : request.state === 'denied'
              ? 'danger'
              : 'warning'
        }
      >
        {request.state === 'unacknowledged' ? 'Decision not confirmed' : request.state}
      </StatusPill>
      <dl className="detail-list">
        <div>
          <dt>Target</dt>
          <dd>{request.target}</dd>
        </div>
        <div>
          <dt>Why</dt>
          <dd>{request.reason}</dd>
        </div>
        <div>
          <dt>Data leaving this Mac</dt>
          <dd>{request.dataLeavingMac}</dd>
        </div>
        <div>
          <dt>Impact</dt>
          <dd>{request.impact}</dd>
        </div>
        <div>
          <dt>Reversible</dt>
          <dd>{request.reversible ? 'Yes' : 'No'}</dd>
        </div>
      </dl>
      {offline ? (
        <p className="inline-notice" data-tone="warning">
          PIUI is offline. Approval is disabled, but you can still deny this request.
        </p>
      ) : null}
      {waiting ? (
        <div className="approval-surface__actions">
          <button
            type="button"
            className="button"
            onClick={() => void onDecision('deny')}
            disabled={busy}
          >
            {busy ? <LoadingLabel>Recording decision…</LoadingLabel> : 'Deny'}
          </button>
          {request.rememberedScopeEligible &&
          request.permittedDecisions.includes('approve-project') ? (
            <button
              type="button"
              className="button"
              onClick={() => void onDecision('approve-project')}
              disabled={busy || offline}
            >
              Approve for this project
            </button>
          ) : null}
          <button
            type="button"
            className="button button--primary"
            onClick={() => void onDecision('approve-once')}
            disabled={busy || offline}
          >
            {busy ? <LoadingLabel>Recording decision…</LoadingLabel> : 'Approve once'}
          </button>
        </div>
      ) : (
        <p
          className="inline-notice"
          data-tone={request.state === 'approved' ? 'success' : 'neutral'}
        >
          This request is {request.state}. No further decision is available.
        </p>
      )}
    </section>
  );
}
