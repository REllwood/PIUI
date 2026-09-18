import { useEffect, useRef, useState } from 'react';
import type { RouteId } from '../domain/types';
import { Icon, type IconName } from '../components/icons/Icon';
import { LoadingLabel } from '../components/primitives/LoadingLabel';
import { StatusPill } from '../components/primitives/StatusPill';
import { useProduct } from './ProductContext';

const routes: readonly Readonly<{ id: RouteId; label: string; icon: IconName }>[] = [
  { id: 'conversation', label: 'Conversation', icon: 'conversation' },
  { id: 'sessions', label: 'Sessions', icon: 'sessions' },
  { id: 'activity', label: 'Activity', icon: 'activity' },
  { id: 'settings', label: 'Settings', icon: 'settings' },
];

export function NavigationPlane({
  open,
  compact = false,
  onClose,
}: Readonly<{ open: boolean; compact?: boolean; onClose: () => void }>) {
  const panel = useRef<HTMLElement>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const { snapshot, route, setRoute, mode, activeOperation, createSession, resumeSession } =
    useProduct();
  const [creating, setCreating] = useState(false);
  const [openingSessionId, setOpeningSessionId] = useState<string | null>(null);
  const turnRunning = ['sending', 'streaming', 'tool-running', 'stop-requested', 'cancel-too-late'].includes(
    snapshot.turnStatus,
  );
  const canCreate =
    snapshot.workspace?.trust === 'trusted' &&
    snapshot.providers.some((provider) => provider.connected && provider.models.length > 0) &&
    !turnRunning &&
    activeOperation === null;
  useEffect(() => {
    if (!open || !compact) return;
    const previous = document.activeElement;
    const element = panel.current;
    element?.querySelector<HTMLButtonElement>('button:not(:disabled)')?.focus();
    const trap = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== 'Tab') return;
      const controls = Array.from(
        element?.querySelectorAll<HTMLElement>('button:not(:disabled), [tabindex="0"]') ?? [],
      );
      if (!controls.length) return;
      const index = controls.indexOf(document.activeElement as HTMLElement);
      if (event.shiftKey && index <= 0) {
        event.preventDefault();
        controls.at(-1)?.focus();
      } else if (!event.shiftKey && index === controls.length - 1) {
        event.preventDefault();
        controls[0]?.focus();
      }
    };
    element?.addEventListener('keydown', trap);
    return () => {
      element?.removeEventListener('keydown', trap);
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus();
    };
  }, [compact, onClose, open]);
  const create = async () => {
    if (creating || !canCreate) return;
    setCreating(true);
    setNotice(null);
    try {
      if (await createSession()) {
        setRoute('conversation');
        onClose();
      }
    } catch {
      setNotice('The conversation could not be created. Please try again.');
    } finally {
      setCreating(false);
    }
  };
  const openSession = async (sessionId: string) => {
    if (openingSessionId || turnRunning || activeOperation !== null) return;
    setOpeningSessionId(sessionId);
    setNotice(null);
    try {
      await resumeSession(sessionId);
      setRoute('conversation');
      onClose();
    } catch {
      setNotice('This conversation could not be opened. Please try again.');
    } finally {
      setOpeningSessionId(null);
    }
  };
  return (
    <aside
      ref={panel}
      className="navigation-plane"
      data-open={open}
      aria-label="Workspace navigation"
      inert={compact && !open}
    >
      <header className="navigation-plane__brand" data-tauri-drag-region>
        <span className="brand-mark" aria-hidden="true">
          π
        </span>
        <span>
          <strong>PIUI</strong>
          <small>Your ideas, with Pi</small>
        </span>
        <button
          type="button"
          className="icon-button navigation-plane__close"
          onClick={onClose}
          aria-label="Close navigation"
        >
          <Icon name="close" />
        </button>
      </header>
      <div className="navigation-plane__new">
        <button
          type="button"
          className="button navigation-new-button"
          onClick={() => void create()}
          disabled={creating || !canCreate}
          title={
            canCreate
              ? 'New conversation · ⌘N'
              : 'Choose and trust a project, then connect a provider when no work is running.'
          }
        >
          {creating ? (
            <LoadingLabel>Creating…</LoadingLabel>
          ) : (
            <>
              <Icon name="plus" />
              <span>New conversation</span>
              <kbd>⌘N</kbd>
            </>
          )}
        </button>
      </div>
      <nav className="navigation-plane__routes" aria-label="PIUI">
        {routes.map((item) => (
          <button
            key={item.id}
            type="button"
            className="navigation-plane__route"
            aria-current={route === item.id ? 'page' : undefined}
            onClick={() => {
              setRoute(item.id);
              onClose();
            }}
          >
            <Icon name={item.icon} />
            <span>{item.label}</span>
            {item.id === 'activity' &&
            snapshot.activity.some((event) => event.state === 'running') ? (
              <span className="navigation-plane__live" aria-label="Work running" />
            ) : null}
          </button>
        ))}
      </nav>
      <section className="navigation-plane__history" aria-labelledby="recent-title" tabIndex={0}>
        <div className="navigation-plane__section-heading">
          <h2 id="recent-title">Recent conversations</h2>
        </div>
        {snapshot.sessions.length === 0 ? (
          <p className="navigation-plane__empty">Your conversations will appear here.</p>
        ) : null}
        {notice ? (
          <p className="navigation-plane__notice" role="alert">
            {notice}
          </p>
        ) : null}
        <ol>
          {snapshot.sessions.slice(0, 4).map((session) => (
            <li key={session.id}>
              <button
                type="button"
                aria-current={snapshot.activeSessionId === session.id ? 'true' : undefined}
                disabled={
                  turnRunning || activeOperation !== null || openingSessionId !== null || creating
                }
                onClick={() => void openSession(session.id)}
              >
                {openingSessionId === session.id ? (
                  <LoadingLabel>{`Opening ${session.title}…`}</LoadingLabel>
                ) : (
                  <>
                    <strong>{session.title}</strong>
                    <span>{session.updatedAt}</span>
                  </>
                )}
              </button>
            </li>
          ))}
        </ol>
      </section>
      <footer className="navigation-plane__project">
        <span className="navigation-plane__project-icon">
          <Icon name="folder" />
        </span>
        <span>
          <strong>{snapshot.workspace?.name ?? 'No project selected'}</strong>
          <small>{snapshot.workspace?.displayPath ?? 'Choose a local folder'}</small>
        </span>
        {snapshot.workspace?.trust === 'trusted' ? (
          <StatusPill tone="success">Trusted</StatusPill>
        ) : null}
        {mode === 'advanced' ? <StatusPill tone="work">Advanced</StatusPill> : null}
      </footer>
    </aside>
  );
}
