import { Icon } from '../components/icons/Icon';
import { StatusPill } from '../components/primitives/StatusPill';
import { LoadingLabel } from '../components/primitives/LoadingLabel';
import { useProduct } from './ProductContext';

export function MainToolbar({
  onOpenNavigation,
  onSearch,
  onOpenCommands,
  onChooseProject,
  onOpenApprovals,
}: Readonly<{
  onOpenNavigation: () => void;
  onSearch: () => void;
  onOpenCommands: () => void;
  onChooseProject: () => void;
  onOpenApprovals: () => void;
}>) {
  const { snapshot, route, mode, activeOperation } = useProduct();
  const running = [
    'sending',
    'streaming',
    'tool-running',
    'stop-requested',
    'cancel-too-late',
  ].includes(snapshot.turnStatus);
  const pending = snapshot.approvals.filter(
    (approval) => approval.state === 'awaiting' || approval.state === 'unacknowledged',
  ).length;
  return (
    <header className="main-toolbar" aria-label="Workspace toolbar" data-tauri-drag-region>
      <button
        type="button"
        className="icon-button main-toolbar__menu"
        onClick={onOpenNavigation}
        aria-label="Open navigation"
      >
        <Icon name="menu" />
      </button>
      <button
        type="button"
        className="main-toolbar__scope"
        onClick={onChooseProject}
        aria-label={activeOperation === 'project' ? 'Choosing project' : 'Choose project'}
        title={
          running
            ? 'Finish or stop the current work before switching projects.'
            : 'Choose a project · ⌘⇧O'
        }
        disabled={activeOperation !== null || running}
      >
        <span className="scope-light" data-state={snapshot.connection} aria-hidden="true" />
        {activeOperation === 'project' ? (
          <LoadingLabel>Choosing project…</LoadingLabel>
        ) : (
          <>
            <strong>{snapshot.workspace?.name ?? 'Choose a project'}</strong>
            <Icon name="chevron-down" />
          </>
        )}
      </button>
      <div className="main-toolbar__centre">
        <span>{route[0].toUpperCase() + route.slice(1)}</span>
        {mode === 'advanced' ? <StatusPill tone="work">Advanced</StatusPill> : null}
      </div>
      <div className="main-toolbar__actions">
        {pending > 0 ? (
          <button
            type="button"
            className="approval-toolbar-button"
            aria-label={`Open ${pending} pending approval${pending === 1 ? '' : 's'}`}
            onClick={onOpenApprovals}
          >
            <Icon name="shield" />
            <span className="approval-toolbar-button__label">Approval needed · {pending}</span>
          </button>
        ) : null}
        <button type="button" className="icon-button" aria-label="Search" onClick={onSearch}>
          <Icon name="search" />
        </button>
        <button
          type="button"
          className="toolbar-command-button"
          aria-label="More workspace actions"
          onClick={onOpenCommands}
        >
          <span>Commands</span>
          <kbd>⌘K</kbd>
        </button>
      </div>
    </header>
  );
}
