// @vitest-environment jsdom

import { cleanup, createEvent, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ProductContextValue } from '../../app/ProductContext';
import { emptyProductSnapshot } from '../../domain/fixtures';
import type { ResourceRecord } from '../../domain/types';
import { ComposerDraftProvider, useComposerDraft } from './ComposerDrafts';
import { ResourcePicker } from './ResourcePicker';

let product: Pick<ProductContextValue, 'snapshot' | 'setMode' | 'openSettings'>;

vi.mock('../../app/ProductContext', () => ({ useProduct: () => product }));

function resource(
  name: string,
  kind: ResourceRecord['kind'],
  overrides: Partial<ResourceRecord> = {},
): ResourceRecord {
  return {
    id: `${kind}-${name}`,
    name,
    kind,
    description: `Useful ${name} guidance`,
    version: '1',
    source: 'project',
    enabled: true,
    executable: false,
    trusted: true,
    operations: [],
    ...overrides,
  };
}

beforeEach(() => {
  // Native dialog focus trapping is verified in the browser; jsdom needs
  // opening/closing shims for the component's selection and focus behaviour.
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
      resources: [resource('explain', 'skill'), resource('plan', 'prompt')],
    },
    setMode: vi.fn(),
    openSettings: vi.fn(),
  };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function DraftField() {
  const { draft, setText } = useComposerDraft('conversation');
  return (
    <textarea
      id="piui-composer"
      aria-label="Message Pi"
      value={draft.text}
      onChange={(event) => setText(event.target.value)}
    />
  );
}

function openPicker() {
  const onSubmit = vi.fn((event) => event.preventDefault());
  render(
    <ComposerDraftProvider>
      <form onSubmit={onSubmit}>
        <DraftField />
        <ResourcePicker draftKey="conversation" />
        <button type="submit">Send</button>
      </form>
    </ComposerDraftProvider>,
  );
  const trigger = screen.getByRole('button', { name: 'Skills & prompts' });
  fireEvent.click(trigger);
  return { trigger, onSubmit };
}

describe('skills and prompts picker', () => {
  it('searches only enabled non-executable skills and prompts', () => {
    product = {
      ...product,
      snapshot: {
        ...product.snapshot,
        resources: [
          ...product.snapshot.resources,
          resource('disabled skill', 'skill', { enabled: false }),
          resource('package', 'package'),
          resource('extension', 'extension'),
          resource('executable skill', 'skill', { executable: true }),
        ],
      },
    };
    openPicker();
    const search = screen.getByRole('searchbox', { name: 'Search skills and prompts' });
    expect(document.activeElement).toBe(search);
    expect(screen.getByRole('button', { name: 'explain' })).toBeTruthy();
    expect(
      screen.queryByRole('button', { name: /disabled skill|package|extension|executable skill/ }),
    ).toBeNull();
    fireEvent.change(search, { target: { value: 'prompt' } });
    expect(screen.getByRole('button', { name: 'plan' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'explain' })).toBeNull();
    fireEvent.change(search, { target: { value: 'something missing' } });
    expect(screen.getByRole('status').textContent).toContain('No matches');
    fireEvent.click(screen.getByRole('button', { name: 'Clear search' }));
    expect((search as HTMLInputElement).value).toBe('');
  });

  it('adds a skill before the existing draft and focuses the composer without sending', () => {
    const { onSubmit } = openPicker();
    const composer = screen.getByRole('textbox', { name: 'Message Pi' });
    fireEvent.change(composer, {
      target: { value: 'Help me understand this.\n\nKeep these details.' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'explain' }));
    expect((composer as HTMLTextAreaElement).value).toBe(
      '/skill:explain Help me understand this.\n\nKeep these details.',
    );
    expect(document.activeElement).toBe(composer);
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('inserts a prompt and avoids duplicating the same selected invocation', () => {
    const { trigger } = openPicker();
    const composer = screen.getByRole('textbox', { name: 'Message Pi' });
    fireEvent.click(screen.getByRole('button', { name: 'plan' }));
    expect((composer as HTMLTextAreaElement).value).toBe('/plan ');
    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole('button', { name: 'plan' }));
    expect((composer as HTMLTextAreaElement).value).toBe('/plan ');
  });

  it('restores trigger focus on Escape cancellation and preserves the draft', () => {
    const { trigger } = openPicker();
    const composer = screen.getByRole('textbox', { name: 'Message Pi' });
    fireEvent.change(composer, { target: { value: 'An unsent idea' } });
    fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true }));
    expect(document.activeElement).toBe(trigger);
    expect(screen.queryByRole('dialog')).toBeNull();
    expect((composer as HTMLTextAreaElement).value).toBe('An unsent idea');
  });

  it('prevents Enter and Command Enter in the picker from submitting the composer', () => {
    const { onSubmit } = openPicker();
    const search = screen.getByRole('searchbox', { name: 'Search skills and prompts' });
    for (const metaKey of [false, true]) {
      const event = createEvent.keyDown(search, { key: 'Enter', metaKey, cancelable: true });
      fireEvent(search, event);
      expect(event.defaultPrevented).toBe(true);
    }
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog')).toBeTruthy();
  });

  it('explains an empty catalogue and explicitly opens Advanced resources', () => {
    product = { ...product, snapshot: { ...emptyProductSnapshot } };
    openPicker();
    expect(screen.getByText('A little help you can reuse')).toBeTruthy();
    expect(screen.getByText(/No skills or prompts are enabled/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Open Advanced resources' }));
    expect(product.setMode).toHaveBeenCalledWith('advanced');
    expect(product.openSettings).toHaveBeenCalledWith('resources');
    expect(vi.mocked(product.setMode).mock.invocationCallOrder[0]).toBeLessThan(
      vi.mocked(product.openSettings).mock.invocationCallOrder[0] ?? Infinity,
    );
  });

  it('discloses command-name conflicts without inserting an unintended PIUI command', () => {
    product = {
      ...product,
      snapshot: { ...product.snapshot, resources: [resource('compact', 'prompt')] },
    };
    openPicker();
    const choice = screen.getByRole('button', { name: 'compact' });
    expect(choice.hasAttribute('disabled')).toBe(true);
    expect(choice.textContent).toContain('already used by a PIUI command');
    fireEvent.click(choice);
    expect((screen.getByRole('textbox') as HTMLTextAreaElement).value).toBe('');
  });
});
