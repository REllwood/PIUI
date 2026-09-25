// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ProductContextValue } from '../../app/ProductContext';
import { emptyProductSnapshot } from '../../domain/fixtures';
import { ModelPicker } from './ModelPicker';

type PickerProduct = Pick<
  ProductContextValue,
  'snapshot' | 'settings' | 'saveSettings' | 'activeOperation' | 'openSettings'
>;

let product: PickerProduct;

vi.mock('../../app/ProductContext', () => ({ useProduct: () => product }));

beforeEach(() => {
  // jsdom does not implement the native dialog's opening/closing methods.
  // Native focus trapping and Escape handling require browser verification.
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
      this.dispatchEvent(new Event('close'));
    },
  });
  product = {
    snapshot: {
      ...emptyProductSnapshot,
      activeSessionId: 'session-1',
      providers: [
        {
          id: 'harbour',
          name: 'Harbour',
          detail: '',
          connected: true,
          methods: [],
          models: [
            { id: 'everyday', name: 'Everyday', reasoning: false, acceptsImages: true },
            { id: 'thorough', name: 'Thorough', reasoning: true, acceptsImages: true },
          ],
        },
        {
          id: 'summit',
          name: 'Summit',
          detail: '',
          connected: true,
          methods: [],
          models: [{ id: 'focus', name: 'Focus', reasoning: true, acceptsImages: false }],
        },
        {
          id: 'offline',
          name: 'Offline',
          detail: '',
          connected: false,
          methods: [],
          models: [{ id: 'hidden', name: 'Hidden model', reasoning: false, acceptsImages: false }],
        },
      ],
    },
    settings: [
      { key: 'model.provider', value: 'harbour', scope: 'project', revision: 3, origin: 'Project' },
      { key: 'model.id', value: 'thorough', scope: 'global', revision: 7, origin: 'Global' },
      { key: 'reasoning.level', value: 'medium', scope: 'project', revision: 2, origin: 'Project' },
    ],
    activeOperation: null,
    saveSettings: vi.fn().mockResolvedValue(undefined),
    openSettings: vi.fn(),
  };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function openPicker() {
  render(
    <div className="piui">
      <ModelPicker />
    </div>,
  );
  const trigger = screen.getByRole('button', { name: 'Choose model: Thorough, Balanced thinking' });
  fireEvent.click(trigger);
  return trigger;
}

describe('composer model picker', () => {
  it('searches connected models by provider and focuses search on opening', () => {
    openPicker();
    const search = screen.getByRole('searchbox', { name: 'Search models' });
    expect(document.activeElement).toBe(search);
    expect(screen.queryByRole('radio', { name: /Hidden model/ })).toBeNull();
    fireEvent.change(search, { target: { value: 'summit' } });
    expect(screen.getAllByRole('radio')).toHaveLength(1);
    expect(screen.getByRole('radio', { name: /Focus/ })).toBeTruthy();
    fireEvent.change(search, { target: { value: 'unavailable' } });
    expect(screen.getByRole('status').textContent).toContain('No models match');
  });

  it('saves changed model settings together with their individual revisions and scopes', async () => {
    openPicker();
    fireEvent.click(screen.getByRole('radio', { name: /Focus/ }));
    fireEvent.change(screen.getByRole('combobox', { name: 'Thinking' }), {
      target: { value: 'high' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save choice' }));
    await waitFor(() =>
      expect(product.saveSettings).toHaveBeenCalledWith([
        { key: 'model.provider', value: 'summit', scope: 'project', expectedRevision: 3 },
        { key: 'model.id', value: 'focus', scope: 'global', expectedRevision: 7 },
        { key: 'reasoning.level', value: 'high', scope: 'project', expectedRevision: 2 },
      ]),
    );
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('keeps thinking out of a non-reasoning model change and does not resave unchanged provider', async () => {
    openPicker();
    fireEvent.click(screen.getByRole('radio', { name: /Everyday/ }));
    expect(screen.queryByRole('combobox', { name: 'Thinking' })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Save choice' }));
    await waitFor(() =>
      expect(product.saveSettings).toHaveBeenCalledWith([
        { key: 'model.id', value: 'everyday', scope: 'global', expectedRevision: 7 },
      ]),
    );
  });

  it('shows progress until acknowledgement and retains the draft after a failed save', async () => {
    let rejectSave: ((error: Error) => void) | undefined;
    product = {
      ...product,
      saveSettings: vi.fn(
        () =>
          new Promise<void>((_resolve, reject) => {
            rejectSave = reject;
          }),
      ),
    };
    openPicker();
    fireEvent.change(screen.getByRole('combobox', { name: 'Thinking' }), {
      target: { value: 'high' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save choice' }));
    expect(screen.getByRole('button', { name: 'Saving…' }).hasAttribute('disabled')).toBe(true);
    expect(screen.getByRole('dialog').getAttribute('aria-busy')).toBe('true');
    expect(
      screen.getByRole('button', { name: 'Close model picker' }).hasAttribute('disabled'),
    ).toBe(true);
    fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true }));
    expect(screen.getByRole('dialog')).toBeTruthy();
    await act(async () => rejectSave?.(new Error('setting-save-conflict')));
    expect(screen.getByRole('alert').textContent).toContain('could not be fully saved');
    expect((screen.getByRole('combobox', { name: 'Thinking' }) as HTMLSelectElement).value).toBe(
      'high',
    );
    expect(screen.getByRole('button', { name: 'Save choice' }).hasAttribute('disabled')).toBe(
      false,
    );
  });

  it.each([
    ['minimal', 'Minimal'],
    ['max', 'Maximum'],
  ])('shows a saved %s thinking level as itself', (value, label) => {
    product = {
      ...product,
      settings: product.settings.map((setting) =>
        setting.key === 'reasoning.level' ? { ...setting, value } : setting,
      ),
    };
    render(<ModelPicker />);
    fireEvent.click(
      screen.getByRole('button', { name: `Choose model: Thorough, ${label} thinking` }),
    );
    const select = screen.getByRole('combobox', { name: 'Thinking' }) as HTMLSelectElement;
    expect(select.value).toBe(value);
    expect(Array.from(select.options).map((option) => option.textContent)).toContain(label);
  });

  it('explains a coded rejection in plain English with a next step', async () => {
    product = {
      ...product,
      // Tauri rejects product commands with the bare code string.
      saveSettings: vi.fn().mockRejectedValue('provider-model-unavailable'),
    };
    openPicker();
    fireEvent.click(screen.getByRole('radio', { name: /Focus/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Save choice' }));
    await waitFor(() =>
      expect(screen.getByRole('alert').textContent).toBe(
        'The chosen model is not available from this provider right now. Choose another model, then try again.',
      ),
    );
  });

  it('restores trigger focus when dismissed without saving', () => {
    const trigger = openPicker();
    fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.activeElement).toBe(trigger);
    expect(product.saveSettings).not.toHaveBeenCalled();
  });

  it('prevents changing model during a turn or another operation', () => {
    product = { ...product, snapshot: { ...product.snapshot, turnStatus: 'streaming' } };
    const { rerender } = render(<ModelPicker />);
    expect(
      screen
        .getByRole('button', { name: 'Choose model: Thorough, Balanced thinking' })
        .hasAttribute('disabled'),
    ).toBe(true);
    product = {
      ...product,
      snapshot: { ...product.snapshot, turnStatus: 'idle' },
      activeOperation: 'session',
    };
    rerender(<ModelPicker />);
    expect(
      screen
        .getByRole('button', { name: 'Choose model: Thorough, Balanced thinking' })
        .hasAttribute('disabled'),
    ).toBe(true);
  });

  it('routes a disconnected user to provider settings without inventing a selected model', () => {
    product = {
      ...product,
      snapshot: { ...emptyProductSnapshot },
      settings: [],
    };
    render(<ModelPicker />);
    fireEvent.click(screen.getByRole('button', { name: 'Choose a model' }));
    fireEvent.click(screen.getByRole('button', { name: 'Connect a provider' }));
    expect(product.openSettings).toHaveBeenCalledWith('providers');
    expect(product.saveSettings).not.toHaveBeenCalled();
  });
});
