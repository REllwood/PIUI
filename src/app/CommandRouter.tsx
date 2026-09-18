import { useEffect } from 'react';
import { commandForKeyboardEvent, isEditableTarget, type AppCommandId } from './commands';

export function CommandRouter({
  onCommand,
}: Readonly<{ onCommand: (command: AppCommandId) => void }>) {
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.defaultPrevented || (event.target instanceof Element && event.target.closest('dialog[open]'))) return;
      if (event.isComposing || event.keyCode === 229) return;
      const command = commandForKeyboardEvent(event);
      if (!command) return;
      if (
        isEditableTarget(event.target) &&
        command.id !== 'open-command-menu' &&
        command.id !== 'alternate-send' &&
        command.id !== 'stop-turn'
      )
        return;
      event.preventDefault();
      onCommand(command.id);
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onCommand]);
  return null;
}
