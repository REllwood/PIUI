import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
import { Icon, type IconName } from '../components/icons/Icon';
import { APP_COMMANDS, type AppCommandId } from './commands';

const details: Record<AppCommandId, { icon: IconName; description: string }> = {
  'new-conversation': { icon: 'plus', description: 'Start fresh in your current project' },
  'open-command-menu': { icon: 'search', description: 'Find an action' },
  'choose-project': { icon: 'folder', description: 'Choose a folder on your Mac' },
  'open-sessions': { icon: 'sessions', description: 'Find and continue a previous conversation' },
  'toggle-navigation': { icon: 'menu', description: 'Show or hide workspace navigation' },
  'open-settings': { icon: 'settings', description: 'Accounts, appearance and preferences' },
  'stop-turn': { icon: 'stop', description: 'Ask Pi to stop its current work' },
  'alternate-send': { icon: 'send', description: 'Send your message to Pi' },
  'close-window': { icon: 'close', description: 'Close this workspace window' },
};

export function CommandMenu({
  open,
  onClose,
  onCommand,
  commandEnabled,
}: Readonly<{
  open: boolean;
  onClose: () => void;
  onCommand: (command: AppCommandId) => void;
  commandEnabled: (command: AppCommandId) => boolean;
}>) {
  const dialog = useRef<HTMLDialogElement>(null);
  const search = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState('');
  const commands = APP_COMMANDS.filter(
    (command) =>
      command.id !== 'open-command-menu' &&
      command.id !== 'alternate-send' &&
      `${command.label} ${details[command.id].description}`
        .toLowerCase()
        .includes(query.trim().toLowerCase()),
  );

  useEffect(() => {
    const element = dialog.current;
    if (!open || !element) return;
    const previous = document.activeElement;
    setQuery('');
    element.showModal();
    search.current?.focus();
    return () => {
      element.close();
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus();
    };
  }, [open]);

  const navigate = (event: KeyboardEvent<HTMLDialogElement>) => {
    if (event.nativeEvent.isComposing) return;
    if (event.key === 'Tab') {
      const controls = Array.from(
        dialog.current?.querySelectorAll<HTMLElement>(
          'input:not(:disabled), button:not(:disabled)',
        ) ?? [],
      );
      const index = controls.indexOf(document.activeElement as HTMLElement);
      if (event.shiftKey && index <= 0) {
        event.preventDefault();
        controls.at(-1)?.focus();
      } else if (!event.shiftKey && index === controls.length - 1) {
        event.preventDefault();
        controls[0]?.focus();
      }
      return;
    }
    if (!['ArrowDown', 'ArrowUp', 'Enter'].includes(event.key)) return;
    const buttons = Array.from(
      dialog.current?.querySelectorAll<HTMLButtonElement>('[data-command]:not(:disabled)') ?? [],
    );
    if (event.key === 'Enter') {
      if (event.target === search.current) {
        event.preventDefault();
        buttons[0]?.click();
      }
      return;
    }
    if (buttons.length === 0) return;
    event.preventDefault();
    const current = buttons.indexOf(document.activeElement as HTMLButtonElement);
    const next =
      event.key === 'ArrowDown'
        ? (current + 1) % buttons.length
        : (current <= 0 ? buttons.length : current) - 1;
    buttons[next]?.focus();
  };

  return (
    <dialog
      ref={dialog}
      className="command-menu"
      aria-labelledby="command-menu-title"
      onCancel={onClose}
      onKeyDown={navigate}
      onClick={(event) => {
        if (event.target !== event.currentTarget) return;
        const rect = event.currentTarget.getBoundingClientRect();
        if (
          event.clientX < rect.left ||
          event.clientX > rect.right ||
          event.clientY < rect.top ||
          event.clientY > rect.bottom
        )
          onClose();
      }}
    >
      <header className="command-menu__search">
        <Icon name="search" />
        <label className="sr-only" htmlFor="command-search" id="command-menu-title">
          Search commands
        </label>
        <input
          ref={search}
          id="command-search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="What would you like to do?"
          autoComplete="off"
          spellCheck={false}
        />
        <button
          type="button"
          className="icon-button"
          onClick={onClose}
          aria-label="Close command menu"
        >
          <Icon name="close" />
        </button>
      </header>
      <div className="command-menu__results" aria-label="Commands">
        <p className="command-menu__label">{query ? 'Matching actions' : 'Workspace actions'}</p>
        {commands.map((command) => (
          <button
            type="button"
            data-command={command.id}
            key={command.id}
            disabled={!commandEnabled(command.id)}
            onClick={() => {
              onClose();
              onCommand(command.id);
            }}
          >
            <span className="command-menu__icon">
              <Icon name={details[command.id].icon} />
            </span>
            <span className="command-menu__copy">
              <strong>{command.label}</strong>
              <small>{details[command.id].description}</small>
            </span>
            <kbd>
              ⌘{command.shift ? '⇧' : ''}
              {command.alt ? '⌥' : ''}
              {command.key.toUpperCase()}
            </kbd>
          </button>
        ))}
        {commands.length === 0 ? (
          <p className="command-menu__empty" role="status">
            No actions found. Try “project”, “conversation” or “settings”.
          </p>
        ) : null}
      </div>
      <footer className="command-menu__footer">
        <span>
          <kbd>↑</kbd>
          <kbd>↓</kbd> to move
        </span>
        <span>
          <kbd>↵</kbd> to select
        </span>
        <span>
          <kbd>esc</kbd> to close
        </span>
      </footer>
    </dialog>
  );
}
