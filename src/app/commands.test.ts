// @vitest-environment jsdom

import { describe, expect, it } from 'vitest';
import { APP_COMMANDS, commandForKeyboardEvent, isEditableTarget } from './commands';

describe('application commands', () => {
  it('has unique modifier and key combinations', () => {
    const combinations = APP_COMMANDS.map(
      (command) => `${Boolean(command.shift)}:${Boolean(command.alt)}:${command.key.toLowerCase()}`,
    );
    expect(new Set(combinations).size).toBe(combinations.length);
  });

  it('requires Command and matches exact modifiers', () => {
    expect(
      commandForKeyboardEvent({
        key: 's',
        metaKey: true,
        shiftKey: true,
        altKey: false,
        ctrlKey: false,
      })?.id,
    ).toBe('open-sessions');
    expect(
      commandForKeyboardEvent({
        key: 's',
        metaKey: true,
        shiftKey: false,
        altKey: true,
        ctrlKey: false,
      })?.id,
    ).toBe('toggle-navigation');
    expect(
      commandForKeyboardEvent({
        key: 's',
        metaKey: false,
        shiftKey: true,
        altKey: false,
        ctrlKey: false,
      }),
    ).toBeNull();
  });

  it('recognises every editable surface', () => {
    for (const element of [
      document.createElement('input'),
      document.createElement('textarea'),
      document.createElement('select'),
    ]) {
      expect(isEditableTarget(element)).toBe(true);
    }
    const editable = document.createElement('div');
    editable.setAttribute('contenteditable', 'true');
    expect(isEditableTarget(editable)).toBe(true);
    expect(isEditableTarget(document.createElement('button'))).toBe(false);
  });
});
