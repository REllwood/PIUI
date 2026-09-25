import { useEffect, useMemo, useState } from 'react';
import { useProduct } from '../../app/ProductContext';
import { Icon } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { StatusPill } from '../../components/primitives/StatusPill';
import { isTurnActive } from '../../domain/machines';
import type { SessionSummary } from '../../domain/types';
import './supporting-routes.css';

export function SessionsRoute() {
  const product = useProduct();
  const { snapshot } = product;
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<'all' | 'active' | 'branches'>('all');
  const [selectedId, setSelectedId] = useState(snapshot.sessions[0]?.id ?? '');
  const [operation, setOperation] = useState<
    'continue' | 'branch' | 'export' | 'rename' | 'compact' | 'trash' | null
  >(null);
  const [titleDraft, setTitleDraft] = useState('');
  const [actionError, setActionError] = useState<string | null>(null);
  const turnBusy = isTurnActive(snapshot.turnStatus);
  const canCreate =
    snapshot.workspace?.trust === 'trusted' &&
    snapshot.providers.some((provider) => provider.connected);
  const sessions = useMemo(
    () =>
      snapshot.sessions.filter(
        (session) =>
          (filter === 'all' ||
            (filter === 'active' && session.id === snapshot.activeSessionId) ||
            (filter === 'branches' && Boolean(session.branch))) &&
          [session.title, session.project, session.status, session.branch].some((value) =>
            value?.toLowerCase().includes(query.toLowerCase()),
          ),
      ),
    [filter, query, snapshot.activeSessionId, snapshot.sessions],
  );
  const selected = sessions.find((session) => session.id === selectedId) ?? sessions[0];
  useEffect(() => setTitleDraft(selected?.title ?? ''), [selected?.id, selected?.title]);

  const continueSession = async () => {
    if (!selected || operation) return;
    setOperation('continue');
    setActionError(null);
    try {
      await product.resumeSession(selected.id);
    } catch {
      setActionError('The session could not be opened. Its existing state is unchanged.');
    } finally {
      setOperation(null);
    }
  };

  const create = async () => {
    setActionError(null);
    try {
      if (!(await product.createSession())) {
        setActionError('Choose and trust a project, then connect a provider before creating a conversation.');
      }
    } catch {
      setActionError('A new conversation could not be created.');
    }
  };

  const branch = async () => {
    if (!selected || operation) return;
    setOperation('branch');
    setActionError(null);
    try {
      await product.branchSession(selected.id);
    } catch {
      setActionError('The branch could not be opened. The source session is unchanged.');
    } finally {
      setOperation(null);
    }
  };

  const exportSession = async () => {
    if (!selected || operation) return;
    setOperation('export');
    setActionError(null);
    try {
      await product.exportSession(selected.id);
    } catch {
      setActionError('The session export was not completed.');
    } finally {
      setOperation(null);
    }
  };

  const rename = async () => {
    if (!selected || operation || !titleDraft.trim() || titleDraft.trim() === selected.title)
      return;
    setOperation('rename');
    setActionError(null);
    try {
      await product.renameSession(selected.id, titleDraft);
    } catch {
      setActionError('The session name was not changed.');
    } finally {
      setOperation(null);
    }
  };

  const compact = async () => {
    if (!selected || operation || selected.id !== snapshot.activeSessionId) return;
    setOperation('compact');
    setActionError(null);
    try {
      await product.compactSession(selected.id);
    } catch {
      setActionError('The session was not compacted. Its prior history is retained.');
    } finally {
      setOperation(null);
    }
  };

  const trash = async () => {
    if (!selected || operation || selected.id === snapshot.activeSessionId) return;
    if (
      !window.confirm(
        `Move “${selected.title}” to the macOS Trash? PIUI will re-check the exact inactive session file before moving it.`,
      )
    )
      return;
    setOperation('trash');
    setActionError(null);
    try {
      await product.trashSession(selected.id);
      setSelectedId('');
    } catch {
      setActionError('The named session was not moved to Trash.');
    } finally {
      setOperation(null);
    }
  };

  return (
    <main className="supporting-route sessions-route" aria-labelledby="sessions-title">
      <header className="route-heading">
        <div>
          <p className="ui-label">Local session library</p>
          <h1 id="sessions-title">Sessions</h1>
          <p>Find, preview and safely continue Pi’s authoritative sessions.</p>
        </div>
        <button
          type="button"
          className="button button--primary"
          onClick={() => void create()}
          disabled={product.activeOperation !== null || turnBusy || !canCreate}
          title={
            canCreate
              ? undefined
              : 'Choose and trust a project, then connect a provider first.'
          }
        >
          {product.activeOperation === 'session' ? (
            <LoadingLabel>Creating…</LoadingLabel>
          ) : (
            <>
              <Icon name="plus" />
              New conversation
            </>
          )}
        </button>
      </header>
      <div className="supporting-route__stage">
        <section className="route-list-plane" aria-label="Session list">
          <label className="search-field">
            <Icon name="search" />
            <span className="sr-only">Search sessions</span>
            <input
              id="session-search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search sessions, projects or branches"
            />
          </label>
          <div className="filter-row" aria-label="Session filters">
            <button
              type="button"
              className="filter-chip"
              aria-pressed={filter === 'all'}
              onClick={() => setFilter('all')}
            >
              All
            </button>
            <button
              type="button"
              className="filter-chip"
              aria-pressed={filter === 'active'}
              onClick={() => setFilter('active')}
            >
              Active
            </button>
            <button
              type="button"
              className="filter-chip"
              aria-pressed={filter === 'branches'}
              onClick={() => setFilter('branches')}
            >
              Branches
            </button>
          </div>
          {sessions.length > 0 ? (
            <ol className="session-list">
              {sessions.map((session) => (
                <SessionRow
                  key={session.id}
                  session={session}
                  selected={selected?.id === session.id}
                  onSelect={() => setSelectedId(session.id)}
                />
              ))}
            </ol>
          ) : (
            <div className="empty-state">
              <Icon name="sessions" />
              <h2>No sessions match</h2>
              <p>Try a different title, project or branch.</p>
              <button
                type="button"
                className="button"
                onClick={() => {
                  setQuery('');
                  setFilter('all');
                }}
              >
                Clear filters
              </button>
            </div>
          )}
        </section>
        <section className="route-detail-plane" aria-label="Session preview">
          {selected ? (
            <>
              <header className="detail-heading">
                <div>
                  <p className="ui-label">Read-only preview</p>
                  <h2>{selected.title}</h2>
                  <p>
                    {selected.project} · {selected.updatedAt}
                  </p>
                </div>
                <StatusPill
                  tone={
                    selected.status === 'failed'
                      ? 'danger'
                      : selected.status === 'active'
                        ? 'work'
                        : 'success'
                  }
                >
                  {selected.status}
                </StatusPill>
              </header>
              <div className="session-preview">
                <div className="session-preview__light" aria-hidden="true" />
                <Icon name="conversation" />
                <p>{selected.preview}</p>
                <dl className="detail-list">
                  <div>
                    <dt>Project</dt>
                    <dd>{selected.project}</dd>
                  </div>
                  <div>
                    <dt>Branch</dt>
                    <dd>{selected.branch ?? 'Default'}</dd>
                  </div>
                  <div>
                    <dt>Generation</dt>
                    <dd className="ui-mono">{selected.generation}</dd>
                  </div>
                  <div>
                    <dt>Live events</dt>
                    <dd>Not attached to this historical preview</dd>
                  </div>
                </dl>
                <label className="session-title-editor">
                  <span>Session name</span>
                  <span>
                    <input
                      value={titleDraft}
                      maxLength={160}
                      onChange={(event) => setTitleDraft(event.target.value)}
                    />
                    <button
                      type="button"
                      className="button"
                      onClick={() => void rename()}
                      disabled={
                        operation !== null || turnBusy ||
                        !titleDraft.trim() ||
                        titleDraft.trim() === selected.title
                      }
                    >
                      {operation === 'rename' ? <LoadingLabel>Saving…</LoadingLabel> : 'Rename'}
                    </button>
                  </span>
                </label>
              </div>
              <footer className="route-action-bar">
                <button
                  type="button"
                  className="button button--primary"
                  onClick={() => void continueSession()}
                  disabled={operation !== null || turnBusy || selected.id === snapshot.activeSessionId}
                >
                  {operation === 'continue' ? (
                    <LoadingLabel>Opening…</LoadingLabel>
                  ) : selected.id === snapshot.activeSessionId ? (
                    'Current session'
                  ) : (
                    'Continue session'
                  )}
                </button>
                <button
                  type="button"
                  className="button"
                  onClick={() => void exportSession()}
                  disabled={operation !== null || turnBusy}
                >
                  {operation === 'export' ? (
                    <LoadingLabel>Preparing export…</LoadingLabel>
                  ) : (
                    <>
                      <Icon name="download" />
                      Export session
                    </>
                  )}
                </button>
                <button
                  type="button"
                  className="button"
                  onClick={() => void branch()}
                  disabled={operation !== null || turnBusy}
                >
                  {operation === 'branch' ? (
                    <LoadingLabel>Opening branch…</LoadingLabel>
                  ) : (
                    <>
                      <Icon name="branch" />
                      Open a branch
                    </>
                  )}
                </button>
                <button
                  type="button"
                  className="button"
                  onClick={() => void compact()}
                  disabled={operation !== null || turnBusy || selected.id !== snapshot.activeSessionId}
                  title={
                    selected.id === snapshot.activeSessionId
                      ? 'Create a labelled Pi compaction entry.'
                      : 'Open this session before compacting it.'
                  }
                >
                  {operation === 'compact' ? (
                    <LoadingLabel>Compacting…</LoadingLabel>
                  ) : (
                    'Compact history'
                  )}
                </button>
                <button
                  type="button"
                  className="button button--danger"
                  onClick={() => void trash()}
                  disabled={operation !== null || turnBusy || selected.id === snapshot.activeSessionId}
                  title={
                    selected.id === snapshot.activeSessionId
                      ? 'The active session cannot be moved to Trash.'
                      : 'Move this exact inactive session to the macOS Trash.'
                  }
                >
                  {operation === 'trash' ? (
                    <LoadingLabel>Moving to Trash…</LoadingLabel>
                  ) : (
                    'Move to Trash'
                  )}
                </button>
              </footer>
              {turnBusy ? (
                <p className="disabled-reason-block" role="status">
                  Stop the active turn before changing, exporting or switching sessions.
                </p>
              ) : null}
              {actionError ? <p role="alert">{actionError}</p> : null}
            </>
          ) : (
            <div className="empty-state">
              <Icon name="sessions" />
              <h2>Select a session</h2>
              <p>A read-only preview will appear here.</p>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}

function SessionRow({
  session,
  selected,
  onSelect,
}: Readonly<{ session: SessionSummary; selected: boolean; onSelect: () => void }>) {
  return (
    <li>
      <button
        type="button"
        className="session-row"
        aria-current={selected ? 'true' : undefined}
        onClick={onSelect}
      >
        <span className="session-row__icon">
          <Icon name={session.branch ? 'branch' : 'conversation'} />
        </span>
        <span>
          <strong>{session.title}</strong>
          <small>
            {session.project} · {session.updatedAt}
          </small>
          <em>{session.preview}</em>
        </span>
        <Icon name="chevron-right" />
      </button>
    </li>
  );
}
