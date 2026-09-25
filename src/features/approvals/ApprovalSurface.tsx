import { useId } from 'react';
import { Icon } from '../../components/icons/Icon';
import { visibleSubjectText } from '../../domain/approvals';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { StatusPill } from '../../components/primitives/StatusPill';
import type { ApprovalDecision, ApprovalRequest, ApprovalSubject } from '../../domain/types';

// Plain text only: the subject names exactly what would run or change, so it is never
// interpreted as Markdown or HTML, and hidden characters are made visible.
function SubjectBlock({ subject }: Readonly<{ subject: ApprovalSubject }>) {
  const labelId = useId();
  return (
    <div className="approval-subject">
      <h3 id={labelId} className="approval-subject__label">
        {subject.label}
      </h3>
      <pre
        className="approval-subject__text"
        role="region"
        aria-labelledby={labelId}
        tabIndex={0}
        dir="ltr"
      >
        {visibleSubjectText(subject.text)}
      </pre>
      {subject.truncated ? (
        // Kept to one line beside the decision so it fits the minimum window.
        <p className="approval-subject__note">
          Shortened. Deny if you need to see the full {subject.label.toLowerCase()} first.
        </p>
      ) : null}
    </div>
  );
}

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
  const subject = request.subject ?? null;
  const titleId = `approval-${request.id}`;
  return (
    <section className="approval-surface" aria-labelledby={titleId}>
      <header className="context-detail__header">
        <div>
          <p className="ui-label">Approval needed</p>
          <h2 id={titleId}>{request.action}</h2>
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
        // The decision bar stays pinned in view at every window size, and always shows what
        // would run beside the buttons, so nothing can be approved unseen. It follows the
        // details in reading and tab order: what runs, then Deny, then approve.
        <div className="approval-decision" role="group" aria-labelledby={titleId}>
          {subject ? (
            <SubjectBlock subject={subject} />
          ) : (
            // Repeats the heading for sighted people; the group is already named by it.
            <p className="approval-decision__title" aria-hidden="true">
              {request.action}
            </p>
          )}
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
        </div>
      ) : (
        <>
          {subject ? <SubjectBlock subject={subject} /> : null}
          <p
            className="inline-notice"
            data-tone={request.state === 'approved' ? 'success' : 'neutral'}
          >
            This request is {request.state}. No further decision is available.
          </p>
        </>
      )}
    </section>
  );
}
