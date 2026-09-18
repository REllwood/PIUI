import type { RouteId } from '../domain/types';

export type AppCommandId =
  | 'new-conversation'
  | 'open-command-menu'
  | 'choose-project'
  | 'open-sessions'
  | 'toggle-navigation'
  | 'open-settings'
  | 'stop-turn'
  | 'alternate-send'
  | 'close-window';

export type AppCommand = Readonly<{
  id: AppCommandId;
  label: string;
  key: string;
  shift?: boolean;
  alt?: boolean;
  route?: RouteId;
}>;

export const APP_COMMANDS: readonly AppCommand[] = Object.freeze([
  { id: 'new-conversation', label: 'New conversation', key: 'n' },
  { id: 'open-command-menu', label: 'Open commands', key: 'k' },
  { id: 'choose-project', label: 'Choose project', key: 'o', shift: true },
  { id: 'open-sessions', label: 'Open Sessions', key: 's', shift: true, route: 'sessions' },
  { id: 'toggle-navigation', label: 'Toggle workspace drawer', key: 's', alt: true },
  { id: 'open-settings', label: 'Open Settings', key: ',', route: 'settings' },
  { id: 'stop-turn', label: 'Stop current turn', key: '.' },
  { id: 'alternate-send', label: 'Send from composer', key: 'Enter' },
  { id: 'close-window', label: 'Close window', key: 'w' },
]);

export function commandForKeyboardEvent(
  event: Pick<KeyboardEvent, 'key' | 'metaKey' | 'shiftKey' | 'altKey' | 'ctrlKey'>,
): AppCommand | null {
  if (!event.metaKey || event.ctrlKey) return null;
  return (
    APP_COMMANDS.find(
      (command) =>
        command.key.toLowerCase() === event.key.toLowerCase() &&
        Boolean(command.shift) === event.shiftKey &&
        Boolean(command.alt) === event.altKey,
    ) ?? null
  );
}

export function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return target.matches('input, textarea, select, [contenteditable="true"], [role="textbox"]');
}
