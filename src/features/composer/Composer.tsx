import {
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from 'react';
import { Icon } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { isTurnActive } from '../../domain/machines';
import type { QueueItem, ResourceRecord, TurnStatus, WorkspaceReference } from '../../domain/types';
import { ComposerQueue } from './ComposerQueue';
import { useComposerDraft } from './ComposerDrafts';
import { removeNativeAttachment, selectNativeAttachment } from '../../platform/native';

const commands = [
  { command: '/review', description: 'Review the current changes' },
  { command: '/compact', description: 'Compact the current session' },
  { command: '/diagnose', description: 'Check the local environment' },
  { command: '/new', description: 'Start a new conversation' },
  { command: '/sessions', description: 'Open the session library' },
];

export function Composer({
  draftKey = 'default',
  workspace,
  turnStatus,
  queueItems,
  busy,
  connectionReady,
  sessionReady,
  onSend,
  onStop,
  onQueue,
  onRetryQueueItem,
  onRemoveQueueItem,
  onDiscoverFiles,
  onCommand,
  modelLabel,
  modelControl,
  extraControl,
  resources = [],
}: Readonly<{
  draftKey?: string;
  workspace: WorkspaceReference | null;
  turnStatus: TurnStatus;
  queueItems: readonly QueueItem[];
  busy: boolean;
  connectionReady: boolean;
  sessionReady: boolean;
  onSend: (text: string, attachmentCapabilities?: readonly string[]) => Promise<boolean>;
  onStop: () => Promise<void>;
  onQueue: (text: string) => Promise<boolean>;
  onRetryQueueItem: (id: string) => Promise<boolean>;
  onRemoveQueueItem: (id: string) => Promise<void>;
  onDiscoverFiles: (query: string) => Promise<readonly string[]>;
  onCommand: (command: string) => Promise<boolean>;
  modelLabel: string;
  modelControl?: ReactNode;
  extraControl?: ReactNode;
  resources?: readonly ResourceRecord[];
}>) {
  const {
    draft: savedDraft,
    setText: setDraft,
    setAttachment,
    acknowledgeSubmission,
  } = useComposerDraft(draftKey);
  const { text: draft, attachment, attachmentState } = savedDraft;
  const submitting = useRef(false);
  const [sending, setSending] = useState(false);
  const [fileSuggestions, setFileSuggestions] = useState<readonly string[]>([]);
  const [discoveringFiles, setDiscoveringFiles] = useState(false);
  const [fileDiscoveryFailed, setFileDiscoveryFailed] = useState(false);
  const [dismissedSuggestionsFor, setDismissedSuggestionsFor] = useState('');
  const [activeSuggestion, setActiveSuggestion] = useState(0);
  const [commandRunning, setCommandRunning] = useState(false);
  const [composerError, setComposerError] = useState<string | null>(null);
  const [queueAction, setQueueAction] = useState<Readonly<{
    id: string;
    kind: 'retry' | 'remove';
  }> | null>(null);
  const descriptionId = useId();
  const running = isTurnActive(turnStatus);
  const currentWord = draft.split(/\s/u).at(-1) ?? '';
  useEffect(() => {
    let active = true;
    if (!currentWord.startsWith('@') || currentWord === dismissedSuggestionsFor) {
      setFileSuggestions([]);
      setDiscoveringFiles(false);
      return () => {
        active = false;
      };
    }
    setFileSuggestions([]);
    setFileDiscoveryFailed(false);
    setDiscoveringFiles(true);
    void onDiscoverFiles(currentWord.slice(1))
      .then((files) => {
        if (active) setFileSuggestions(files);
      })
      .catch(() => {
        if (active) {
          setFileSuggestions([]);
          setFileDiscoveryFailed(true);
        }
      })
      .finally(() => {
        if (active) setDiscoveringFiles(false);
      });
    return () => {
      active = false;
    };
  }, [currentWord, dismissedSuggestionsFor, onDiscoverFiles]);
  const suggestions = useMemo(() => {
    if (currentWord === dismissedSuggestionsFor) return [];
    if (currentWord.startsWith('@'))
      return fileSuggestions.map((label) => ({ label: `@${label}`, detail: 'Project file' }));
    if (currentWord.startsWith('/')) {
      const available = commands.map((item) => ({
        label: item.command,
        detail: item.description,
      }));
      const labels = new Set(available.map((item) => item.label));
      for (const resource of resources) {
        if (!resource.enabled || !['skill', 'prompt'].includes(resource.kind)) continue;
        if (!resource.name || /\s/u.test(resource.name)) continue;
        const label = resource.kind === 'skill' ? `/skill:${resource.name}` : `/${resource.name}`;
        if (labels.has(label)) continue;
        labels.add(label);
        available.push({
          label,
          detail: `${resource.kind === 'skill' ? 'Skill' : 'Prompt'} · ${resource.description}`,
        });
      }
      return available.filter((item) => item.label.startsWith(currentWord));
    }
    return [];
  }, [currentWord, dismissedSuggestionsFor, fileSuggestions, resources]);
  useEffect(() => setActiveSuggestion(0), [currentWord, suggestions.length]);
  const localCommand = commands.find((candidate) => candidate.command === draft.trim());
  const sendDisabledReason = localCommand
    ? null
    : !workspace
      ? 'Choose a project before sending.'
      : !connectionReady
        ? 'Reconnect the local helper before sending.'
        : !sessionReady
          ? 'Connect a provider before sending.'
          : attachmentState === 'picking'
            ? 'Wait for the image picker to close.'
            : !draft.trim()
              ? 'Write a message first.'
              : null;

  const insertSuggestion = (label: string) => {
    const precedingText = draft.slice(0, draft.length - currentWord.length);
    setDraft(`${precedingText}${label} `);
  };

  const send = async () => {
    if (sendDisabledReason || running || busy || commandRunning || submitting.current) return;
    const submitted = savedDraft;
    submitting.current = true;
    setComposerError(null);
    if (localCommand) {
      setCommandRunning(true);
      try {
        if (await onCommand(localCommand.command)) acknowledgeSubmission(submitted, false);
      } catch {
        setComposerError('That command could not be completed. Your draft has been kept.');
      } finally {
        setCommandRunning(false);
        submitting.current = false;
      }
      return;
    }
    setSending(true);
    try {
      const accepted = await onSend(
        submitted.text,
        submitted.attachment ? [submitted.attachment.capabilityId] : [],
      );
      if (accepted) acknowledgeSubmission(submitted);
    } catch {
      setComposerError('The message was not accepted. Your draft has been kept.');
    } finally {
      submitting.current = false;
      setSending(false);
    }
  };

  const queue = async () => {
    if (!draft.trim() || busy) return;
    const queued = savedDraft;
    setComposerError(null);
    try {
      if (await onQueue(queued.text)) acknowledgeSubmission(queued, false);
      else setComposerError('The follow-up was not acknowledged. Your draft has been kept.');
    } catch {
      setComposerError('The follow-up was not acknowledged. Your draft has been kept.');
    }
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.nativeEvent.isComposing || event.nativeEvent.keyCode === 229) return;
    if (suggestions.length > 0) {
      if (event.key === 'ArrowDown') {
        event.preventDefault();
        setActiveSuggestion((current) => (current + 1) % suggestions.length);
        return;
      }
      if (event.key === 'ArrowUp') {
        event.preventDefault();
        setActiveSuggestion((current) => (current - 1 + suggestions.length) % suggestions.length);
        return;
      }
      if (event.key === 'Escape') {
        event.preventDefault();
        setDismissedSuggestionsFor(currentWord);
        setFileSuggestions([]);
        return;
      }
      if ((event.key === 'Enter' || event.key === 'Tab') && !event.shiftKey && !event.metaKey) {
        event.preventDefault();
        const selected = suggestions[activeSuggestion];
        if (selected) insertSuggestion(selected.label);
        return;
      }
    }
    if (event.key === 'Enter' && !event.shiftKey && !event.metaKey) {
      event.preventDefault();
      if (running) void queue();
      else void send();
    }
  };

  const handleAttachment = async () => {
    setAttachment(attachment, 'picking');
    try {
      const selected = await selectNativeAttachment();
      // Cancelling the native picker keeps the image already in this draft.
      setAttachment(selected ?? attachment);
    } catch {
      setAttachment(attachment, attachment ? 'attached' : 'failed');
    }
  };

  const removeAttachment = async () => {
    const capabilityId = attachment?.capabilityId;
    setAttachment(null);
    if (capabilityId) {
      try {
        await removeNativeAttachment(capabilityId);
      } catch {
        // The opaque capability is already absent from the UI and expires in
        // the native registry; no raw path or stale capability is retained.
      }
    }
  };

  const removeQueueItem = async (localId: string) => {
    if (queueAction) return;
    setQueueAction({ id: localId, kind: 'remove' });
    try {
      await onRemoveQueueItem(localId);
    } catch {
      setComposerError(
        'The queued follow-up could not be removed. Its previous state is retained.',
      );
    } finally {
      setQueueAction(null);
    }
  };

  const retryQueueItem = async (localId: string) => {
    if (queueAction) return;
    setQueueAction({ id: localId, kind: 'retry' });
    try {
      if (!(await onRetryQueueItem(localId))) {
        setComposerError(
          'The queued follow-up was not acknowledged. It remains available to retry.',
        );
      }
    } catch {
      setComposerError('The queued follow-up was not acknowledged. It remains available to retry.');
    } finally {
      setQueueAction(null);
    }
  };

  return (
    <form
      className="composer"
      onSubmit={(event) => {
        event.preventDefault();
        void send();
      }}
      aria-label="Message composer"
    >
      <ComposerQueue
        items={queueItems}
        onRemove={removeQueueItem}
        onRetry={retryQueueItem}
        action={queueAction}
      />
      {attachmentState !== 'idle' ? (
        <div className="attachment-chip" data-state={attachmentState}>
          {attachmentState === 'picking' ? <LoadingLabel>Choosing image…</LoadingLabel> : null}
          {attachmentState === 'attached' && attachment ? (
            <>
              <Icon name="file" />
              <span>{attachment.fileLabel} · ready</span>
            </>
          ) : null}
          {attachmentState === 'failed' ? <span>That image could not be attached.</span> : null}
          <button
            type="button"
            className="icon-button"
            onClick={() => void removeAttachment()}
            disabled={attachmentState === 'picking' || sending || busy}
            aria-label="Remove attachment"
          >
            <Icon name="close" />
          </button>
        </div>
      ) : null}
      <div className="composer__body">
        <span className="composer__orb" data-running={running} aria-hidden="true" />
        <div className="composer__input-wrap">
          <label className="sr-only" htmlFor="piui-composer">
            Message Pi
          </label>
          <textarea
            id="piui-composer"
            className="composer__input"
            value={draft}
            onChange={(event) => {
              setDraft(event.target.value);
              setComposerError(null);
            }}
            onKeyDown={handleKeyDown}
            placeholder="Ask Pi to help with this project…"
            aria-describedby={descriptionId}
            aria-autocomplete="list"
            aria-controls={
              suggestions.length > 0 || discoveringFiles
                ? `${descriptionId}-suggestions`
                : undefined
            }
            aria-activedescendant={
              suggestions.length > 0 ? `${descriptionId}-suggestion-${activeSuggestion}` : undefined
            }
          />
          <span id={descriptionId} className="sr-only">
            Enter sends. Shift Enter adds a new line. Type at to find a project file or slash for
            commands.
          </span>
          {suggestions.length > 0 ? (
            <div
              id={`${descriptionId}-suggestions`}
              className="composer-suggestions"
              role="listbox"
              aria-label="Composer suggestions"
            >
              {suggestions.map((suggestion, index) => (
                <div
                  key={suggestion.label}
                  id={`${descriptionId}-suggestion-${index}`}
                  role="option"
                  aria-selected={index === activeSuggestion}
                  onMouseEnter={() => setActiveSuggestion(index)}
                  onMouseDown={(event) => {
                    event.preventDefault();
                    insertSuggestion(suggestion.label);
                  }}
                >
                  <strong>{suggestion.label}</strong>
                  <span>{suggestion.detail}</span>
                </div>
              ))}
            </div>
          ) : null}
          {discoveringFiles ? (
            <div
              id={`${descriptionId}-suggestions`}
              className="composer-suggestions composer-suggestions--loading"
              role="status"
            >
              <LoadingLabel>Finding project files…</LoadingLabel>
            </div>
          ) : null}
          {fileDiscoveryFailed && currentWord.startsWith('@') ? (
            <div className="composer-suggestion-status" role="status">
              Project-file suggestions are unavailable. You can keep typing the path.
            </div>
          ) : null}
        </div>
        <div className="composer__actions">
          <button
            type="button"
            className="icon-button"
            onClick={() => void handleAttachment()}
            disabled={attachmentState === 'picking' || sending || busy}
            aria-label="Attach an image"
          >
            <Icon name="paperclip" />
          </button>
          {running ? (
            <>
              {draft.trim() ? (
                <button
                  type="button"
                  className="button"
                  onClick={() => void queue()}
                  disabled={busy}
                  title="Pi will receive this message after the current work finishes."
                >
                  {busy ? <LoadingLabel>Saving…</LoadingLabel> : 'Add follow-up'}
                </button>
              ) : null}
              <button
                type="button"
                className="button button--primary"
                onClick={() => void onStop()}
                disabled={busy || turnStatus === 'stop-requested'}
              >
                {busy || turnStatus === 'stop-requested' ? (
                  <LoadingLabel>Stopping…</LoadingLabel>
                ) : (
                  <>
                    <Icon name="stop" />
                    Stop
                  </>
                )}
              </button>
            </>
          ) : (
            <button
              type="submit"
              className="button button--primary"
              disabled={Boolean(sendDisabledReason) || busy || commandRunning || sending}
              aria-describedby={sendDisabledReason ? `${descriptionId}-disabled` : undefined}
            >
              {busy || commandRunning || sending ? (
                <LoadingLabel>{commandRunning ? 'Running command…' : 'Sending…'}</LoadingLabel>
              ) : (
                <>
                  <Icon name="send" />
                  Send
                </>
              )}
            </button>
          )}
        </div>
      </div>
      <footer className="composer__footer">
        <span>{workspace ? `Working in ${workspace.name}` : 'No project selected'}</span>
        {modelControl ?? <span>{modelLabel}</span>}
        {extraControl}
        <span className="composer__hint">
          {running ? 'Enter queues a follow-up' : 'Enter to send'} · Shift Enter for a new line
        </span>
        {sendDisabledReason ? (
          <span
            className={
              sendDisabledReason === 'Write a message first.'
                ? 'sr-only'
                : 'composer__disabled-reason'
            }
            id={`${descriptionId}-disabled`}
          >
            {sendDisabledReason}
          </span>
        ) : null}
      </footer>
      {composerError ? (
        <div className="composer__error" role="alert">
          {composerError}
        </div>
      ) : null}
    </form>
  );
}
