// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { useConfirmation } from './ModalDialog';

let confirmFn: ReturnType<typeof useConfirmation>[0] | undefined;

function Harness() {
  const [confirm, confirmation] = useConfirmation();
  confirmFn = confirm;
  return (
    <div className="piui">
      <button type="button">Remove</button>
      {confirmation}
    </div>
  );
}

beforeEach(() => {
  // jsdom does not implement the native dialog's modal methods.
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.setAttribute('open', '');
    },
  });
  Object.defineProperty(HTMLDialogElement.prototype, 'close', {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.removeAttribute('open');
    },
  });
});

afterEach(() => {
  cleanup();
  confirmFn = undefined;
});

const request = {
  title: 'Remove “fixture”?',
  message: 'Its package files will be removed.',
  confirmLabel: 'Remove',
  tone: 'danger' as const,
};

describe('in-app confirmation', () => {
  it('asks in an accessible alert dialog with the cautious choice focused', async () => {
    render(<Harness />);
    const trigger = screen.getByRole('button', { name: 'Remove' });
    trigger.focus();
    let answer: Promise<boolean> | undefined;
    act(() => {
      answer = confirmFn?.(request);
    });
    const dialog = screen.getByRole('alertdialog', { name: 'Remove “fixture”?' });
    expect(dialog.getAttribute('aria-describedby')).toBeTruthy();
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Cancel' }));
    act(() => {
      fireEvent.click(screen.getAllByRole('button', { name: 'Remove' }).at(-1) as HTMLElement);
    });
    await expect(answer).resolves.toBe(true);
    expect(screen.queryByRole('alertdialog')).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });

  it('resolves false when cancelled with Escape', async () => {
    render(<Harness />);
    let answer: Promise<boolean> | undefined;
    act(() => {
      answer = confirmFn?.(request);
    });
    act(() => {
      fireEvent(screen.getByRole('alertdialog'), new Event('cancel', { cancelable: true }));
    });
    await expect(answer).resolves.toBe(false);
    expect(screen.queryByRole('alertdialog')).toBeNull();
  });

  it('declines a pending question when its owner unmounts', async () => {
    const { unmount } = render(<Harness />);
    let answer: Promise<boolean> | undefined;
    act(() => {
      answer = confirmFn?.(request);
    });
    unmount();
    await expect(answer).resolves.toBe(false);
  });
});
