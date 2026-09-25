import { useEffect, useMemo, useRef, useState } from 'react';
import { BottomActionPlane } from '../../app/BottomActionPlane';
import { useProduct } from '../../app/ProductContext';
import { isTurnActive } from '../../domain/machines';
import { thinkingLabel } from '../../domain/thinking';
import { workSummaryLabel } from '../../domain/workSummary';
import { Icon } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { WorkTrace } from '../../components/work-trace/WorkTrace';
import { ApprovalSurface } from '../approvals/ApprovalSurface';
import { DiffReview } from '../changes/DiffReview';
import { Composer } from '../composer/Composer';
import { useComposerDraftAdoption } from '../composer/ComposerDrafts';
import { ModelPicker } from '../composer/ModelPicker';
import { ResourcePicker } from '../composer/ResourcePicker';
import { ConversationWelcome } from './ConversationWelcome';
import { ActivityDetail } from '../activity/ActivityDetail';
import { ConversationHeader } from './ConversationHeader';
import { ConversationRecovery } from './ConversationRecovery';
import { TranscriptViewport } from './TranscriptViewport';
import './conversation.css';

type ContextKind = 'approval' | 'change' | 'activity' | null;

export function ConversationRoute({ approvalRequest = 0 }: Readonly<{ approvalRequest?: number }>) {
  const product = useProduct();
  const { snapshot } = product;
  const session = snapshot.sessions.find((candidate) => candidate.id === snapshot.activeSessionId);
  const pendingApproval = snapshot.approvals.find(
    (approval) => approval.state === 'awaiting' || approval.state === 'unacknowledged',
  );
  const selectedChange =
    snapshot.changes.find((change) => change.id === product.selectedChangeId) ??
    snapshot.changes[0];
  const [contextKind, setContextKind] = useState<ContextKind>(
    pendingApproval ? 'approval' : 'change',
  );
  useEffect(() => {
    if (approvalRequest > 0) setContextKind('approval');
  }, [approvalRequest]);
  const adoptDraft = useComposerDraftAdoption();
  const sessionId = session?.id ?? null;
  const previousSessionId = useRef<string | null>(sessionId);
  // A draft typed before any conversation existed belongs to the session the person just started,
  // so hand it over the moment one appears. Moving between existing sessions leaves drafts alone.
  useEffect(() => {
    const previous = previousSessionId.current;
    previousSessionId.current = sessionId;
    if (previous === null && sessionId !== null) adoptDraft('unassigned', sessionId);
  }, [adoptDraft, sessionId]);
  const empty = snapshot.messages.length === 0;
  const hasWork = snapshot.activity.length > 0;
  const providerId = product.settings.find((setting) => setting.key === 'model.provider')?.value;
  const modelId = product.settings.find((setting) => setting.key === 'model.id')?.value;
  const reasoning = product.settings.find((setting) => setting.key === 'reasoning.level')?.value;
  const provider = snapshot.providers.find((candidate) => candidate.id === providerId);
  const model = provider?.models.find((candidate) => candidate.id === modelId);
  const reasoningLabel = thinkingLabel(reasoning);
  const modelLabel = `${model?.name ?? 'Model unavailable'} · ${
    reasoningLabel ? `${reasoningLabel} thinking` : 'Default reasoning'
  }`;
  const runComposerCommand = async (command: string): Promise<boolean> => {
    if (command === '/compact' && session) {
      await product.compactSession(session.id);
      return true;
    }
    if (command === '/diagnose') {
      await product.runDiagnostics();
      product.openSettings('diagnostics');
      return true;
    }
    if (command === '/review') {
      if (snapshot.changes[0]) {
        product.setSelectedChangeId(snapshot.changes[0].id);
        setContextKind('change');
      }
      return true;
    }
    if (command === '/new') {
      return product.createSession();
    }
    if (command === '/sessions') {
      product.setRoute('sessions');
      return true;
    }
    return false;
  };
  const context = useMemo(() => {
    if (contextKind === 'approval' && pendingApproval)
      return (
        <ApprovalSurface
          request={pendingApproval}
          offline={snapshot.connection !== 'ready'}
          busy={product.activeOperation === 'approval'}
          onDecision={(decision) => product.decideApproval(pendingApproval.id, decision)}
          onClose={() => setContextKind(null)}
        />
      );
    if (contextKind === 'activity' && product.selectedActivity)
      return (
        <ActivityDetail
          event={product.selectedActivity}
          onClose={() => setContextKind(null)}
          onCancel={product.stop}
        />
      );
    if (contextKind === 'change' && selectedChange)
      return (
        <DiffReview
          change={selectedChange}
          busy={product.activeOperation === 'change'}
          onUndo={() => product.undoChange(selectedChange.id)}
          onReveal={() => product.revealChange(selectedChange.id)}
          onClose={() => setContextKind(null)}
        />
      );
    return null;
  }, [contextKind, pendingApproval, product, selectedChange, snapshot.connection]);

  return (
    <div className="conversation-route">
      <ConversationRecovery
        state={snapshot.connection}
        busy={product.activeOperation === 'diagnostics' || product.activeOperation === 'session'}
        failureReason={product.helperFailure}
        onReconnect={product.reconnect}
        onReload={() => (session ? product.resumeSession(session.id) : Promise.resolve())}
        onBranch={() => (session ? product.branchSession(session.id) : Promise.resolve())}
      />
      <div className="conversation-stage" data-context={Boolean(context)}>
        <section className="conversation-plane" aria-label="Conversation" data-empty={empty}>
          {!empty ? (
            <ConversationHeader
              title={session?.title ?? 'New conversation'}
              branch={session?.branch}
              busy={
                product.activeOperation === 'session'
                  ? 'session'
                  : product.activeOperation === 'export'
                    ? 'export'
                    : null
              }
              unavailable={!session || isTurnActive(snapshot.turnStatus)}
              onBranch={() => (session ? product.branchSession(session.id) : Promise.resolve())}
              onExport={async () => {
                if (session) await product.exportSession(session.id);
              }}
            />
          ) : null}
          {empty ? (
            <ConversationWelcome draftKey={session?.id ?? 'unassigned'} />
          ) : (
            <TranscriptViewport messages={snapshot.messages} />
          )}
          {hasWork && !empty ? (
            <details className="conversation-work" open aria-label="Current work summary">
              <summary>
                <span>
                  <Icon name="activity" />
                  Pi’s work
                </span>
                <span>
                  {workSummaryLabel(
                    snapshot.activity,
                    Boolean(pendingApproval),
                    snapshot.turnStatus,
                  )}
                  <Icon name="chevron-down" />
                </span>
              </summary>
              <WorkTrace
                events={snapshot.activity.slice(-3)}
                onSelect={(event) => {
                  product.setSelectedActivity(event);
                  setContextKind('activity');
                }}
              />
            </details>
          ) : null}
        </section>
        {context ? (
          <aside className="context-plane" aria-label="Context review">
            {context}
          </aside>
        ) : null}
      </div>
      {pendingApproval || selectedChange || hasWork ? (
        <div className="context-switcher" role="group" aria-label="Context views">
          <span className="context-switcher__label">Review</span>
          {pendingApproval ? (
            <button
              type="button"
              className="button"
              data-active={contextKind === 'approval'}
              aria-pressed={contextKind === 'approval' && Boolean(context)}
              onClick={() => setContextKind('approval')}
            >
              <Icon name="shield" />
              Approval needed
            </button>
          ) : null}
          {selectedChange ? (
            <button
              type="button"
              className="button"
              data-active={contextKind === 'change'}
              aria-pressed={contextKind === 'change' && Boolean(context)}
              onClick={() => setContextKind('change')}
            >
              <Icon name="file" />
              Changes · {snapshot.changes.length}
            </button>
          ) : null}
          {hasWork ? (
            <button
              type="button"
              className="button"
              data-active={contextKind === 'activity'}
              aria-pressed={contextKind === 'activity' && Boolean(context)}
              onClick={() => {
                const event = product.selectedActivity ?? snapshot.activity.at(-1) ?? null;
                product.setSelectedActivity(event);
                setContextKind('activity');
              }}
            >
              <Icon name="activity" />
              Activity
            </button>
          ) : null}
        </div>
      ) : null}
      <BottomActionPlane>
        {snapshot.turnStatus === 'failed' ? (
          <div className="turn-recovery" role="status">
            <span>The last turn failed. The conversation and draft remain local.</span>
            <button
              type="button"
              className="button"
              onClick={() => void product.retryLastTurn()}
              disabled={product.activeOperation !== null || snapshot.connection !== 'ready'}
              title={
                snapshot.connection === 'external-change'
                  ? 'Reload the latest session or open a branch before retrying.'
                  : undefined
              }
            >
              {product.activeOperation === 'send' ? (
                <LoadingLabel>Retrying…</LoadingLabel>
              ) : (
                'Retry last message'
              )}
            </button>
          </div>
        ) : null}
        <Composer
          key={session?.id ?? 'unassigned'}
          draftKey={session?.id ?? 'unassigned'}
          resources={snapshot.resources}
          modelControl={<ModelPicker />}
          extraControl={<ResourcePicker draftKey={session?.id ?? 'unassigned'} />}
          workspace={snapshot.workspace}
          turnStatus={snapshot.turnStatus}
          queueItems={snapshot.queue}
          busy={
            product.activeOperation === 'send' ||
            product.activeOperation === 'stop' ||
            product.activeOperation === 'queue'
          }
          connectionReady={snapshot.connection === 'ready'}
          sessionReady={Boolean(session)}
          onSend={product.send}
          onStop={product.stop}
          onQueue={product.queue}
          onRetryQueueItem={product.retryQueueItem}
          onRemoveQueueItem={product.removeQueueItem}
          onDiscoverFiles={product.discoverFiles}
          onCommand={runComposerCommand}
          modelLabel={modelLabel}
        />
      </BottomActionPlane>
    </div>
  );
}
