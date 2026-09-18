// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, renderHook, screen } from '@testing-library/react';
import { useState, type ComponentProps, type ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CommandRouter } from '../../app/CommandRouter';
import type { ResourceRecord } from '../../domain/types';
import { Composer } from './Composer';
import {
  ComposerDraftProvider,
  useComposerDraft,
  useComposerDraftAdoption,
} from './ComposerDrafts';

vi.mock('../../platform/native', () => ({
  selectNativeAttachment: vi.fn().mockResolvedValue(null),
  removeNativeAttachment: vi.fn().mockResolvedValue(undefined),
}));

afterEach(cleanup);

const attachment = {
  capabilityId: 'attachment-capability',
  fileLabel: 'screen.png',
  mime: 'image/png' as const,
  byteLength: 420,
};

function wrapper({ children }: Readonly<{ children: ReactNode }>) {
  return <ComposerDraftProvider>{children}</ComposerDraftProvider>;
}

function DraftEditor({ session }: Readonly<{ session: string }>) {
  const { draft, setText, setAttachment } = useComposerDraft(session);
  return (
    <>
      <input
        aria-label="Draft text"
        value={draft.text}
        onChange={(event) => setText(event.target.value)}
      />
      <button onClick={() => setAttachment(attachment)}>Attach fixture</button>
      <output>{draft.attachment?.fileLabel ?? 'No attachment'}</output>
    </>
  );
}

function DraftNavigation() {
  const [showConversation, setShowConversation] = useState(true);
  const [session, setSession] = useState('one');
  return (
    <ComposerDraftProvider>
      <button onClick={() => setShowConversation((current) => !current)}>Toggle route</button>
      <button onClick={() => setSession((current) => (current === 'one' ? 'two' : 'one'))}>
        Switch session
      </button>
      {showConversation ? <DraftEditor session={session} /> : <p>Settings</p>}
    </ComposerDraftProvider>
  );
}

function useAdoptableDraft(session: string) {
  return { ...useComposerDraft(session), adopt: useComposerDraftAdoption() };
}

function composerProps(
  overrides: Partial<ComponentProps<typeof Composer>> = {},
): ComponentProps<typeof Composer> {
  return {
    draftKey: 'session-one',
    workspace: {
      capabilityId: 'project-capability',
      name: 'Project',
      displayPath: 'Documents / Project',
      trust: 'trusted',
      lastOpenedAt: 'Today',
    },
    turnStatus: 'idle',
    queueItems: [],
    busy: false,
    connectionReady: true,
    sessionReady: true,
    onSend: vi.fn().mockResolvedValue(true),
    onStop: vi.fn().mockResolvedValue(undefined),
    onQueue: vi.fn().mockResolvedValue(true),
    onRetryQueueItem: vi.fn().mockResolvedValue(true),
    onRemoveQueueItem: vi.fn().mockResolvedValue(undefined),
    onDiscoverFiles: vi.fn().mockResolvedValue([]),
    onCommand: vi.fn().mockResolvedValue(true),
    modelLabel: 'Test model',
    ...overrides,
  };
}

describe('conversation drafts', () => {
  it('retains text and attachment across route unmounts and isolates different sessions', () => {
    render(<DraftNavigation />);
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'Keep this idea' } });
    fireEvent.click(screen.getByRole('button', { name: 'Attach fixture' }));
    fireEvent.click(screen.getByRole('button', { name: 'Toggle route' }));
    expect(screen.queryByRole('textbox')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Toggle route' }));
    expect((screen.getByRole('textbox') as HTMLInputElement).value).toBe('Keep this idea');
    expect(screen.getByText('screen.png')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Switch session' }));
    expect((screen.getByRole('textbox') as HTMLInputElement).value).toBe('');
    expect(screen.getByText('No attachment')).toBeTruthy();
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'Separate idea' } });
    fireEvent.click(screen.getByRole('button', { name: 'Switch session' }));
    expect((screen.getByRole('textbox') as HTMLInputElement).value).toBe('Keep this idea');
    expect(screen.getByText('screen.png')).toBeTruthy();
  });

  it('does not clear text edited back to its submitted value while an acknowledgement waits', () => {
    const { result } = renderHook(() => useComposerDraft('one'), { wrapper });
    act(() => result.current.setText('Please review'));
    act(() => result.current.setAttachment(attachment));
    const submitted = result.current.draft;
    act(() => result.current.setText('Different idea'));
    act(() => result.current.setText('Please review'));
    act(() => result.current.acknowledgeSubmission(submitted));
    expect(result.current.draft.text).toBe('Please review');
    expect(result.current.draft.attachment).toBeNull();
  });

  it('clears only the submitted session when the user switches while acknowledgement waits', () => {
    const { result, rerender } = renderHook(({ session }) => useComposerDraft(session), {
      initialProps: { session: 'one' },
      wrapper,
    });
    act(() => result.current.setText('Sent from one'));
    const submitted = result.current.draft;
    const acknowledge = result.current.acknowledgeSubmission;
    rerender({ session: 'two' });
    act(() => result.current.setText('Still writing two'));
    act(() => acknowledge(submitted));
    expect(result.current.draft.text).toBe('Still writing two');
    rerender({ session: 'one' });
    expect(result.current.draft.text).toBe('');
  });

  it('keeps a replacement attachment when an earlier message is acknowledged', () => {
    const { result } = renderHook(() => useComposerDraft('one'), { wrapper });
    act(() => result.current.setText('Inspect this image'));
    act(() => result.current.setAttachment(attachment));
    const submitted = result.current.draft;
    const replacement = { ...attachment, capabilityId: 'replacement', fileLabel: 'new.png' };
    act(() => result.current.setAttachment(replacement));
    act(() => result.current.acknowledgeSubmission(submitted));
    expect(result.current.draft.text).toBe('');
    expect(result.current.draft.attachment).toEqual(replacement);
    expect(result.current.draft.attachmentState).toBe('attached');
  });

  it('hands a draft typed before the conversation existed to the new session', () => {
    const { result, rerender } = renderHook(({ session }) => useAdoptableDraft(session), {
      initialProps: { session: 'unassigned' },
      wrapper,
    });
    act(() => result.current.setText('Start here'));
    act(() => result.current.setAttachment(attachment));
    const stranded = result.current.draft;
    act(() => result.current.adopt('unassigned', 'session-one'));
    rerender({ session: 'session-one' });
    expect(result.current.draft.text).toBe('Start here');
    expect(result.current.draft.attachment).toEqual(attachment);
    expect(result.current.draft.textRevision).toBe(stranded.textRevision);
    expect(result.current.draft.attachmentRevision).toBe(stranded.attachmentRevision);
    rerender({ session: 'unassigned' });
    expect(result.current.draft.text).toBe('');
    expect(result.current.draft.attachment).toBeNull();
  });

  it('leaves a session that already holds its own draft untouched', () => {
    const { result, rerender } = renderHook(({ session }) => useAdoptableDraft(session), {
      initialProps: { session: 'unassigned' },
      wrapper,
    });
    act(() => result.current.setText('Typed before the session existed'));
    rerender({ session: 'session-one' });
    act(() => result.current.setText('Already writing here'));
    act(() => result.current.adopt('unassigned', 'session-one'));
    expect(result.current.draft.text).toBe('Already writing here');
    rerender({ session: 'unassigned' });
    expect(result.current.draft.text).toBe('Typed before the session existed');
  });

  it('shows send progress and preserves edits made while the send waits', async () => {
    let acknowledge: (value: boolean) => void = () => undefined;
    const pending = new Promise<boolean>((resolve) => {
      acknowledge = resolve;
    });
    const onSend = vi.fn().mockReturnValue(pending);
    render(<Composer {...composerProps({ onSend })} />, { wrapper });
    const editor = screen.getByRole('textbox', { name: 'Message Pi' });
    fireEvent.change(editor, { target: { value: 'First message' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send' }));
    expect(screen.getByRole('button', { name: 'Sending…' }).hasAttribute('disabled')).toBe(true);
    fireEvent.change(editor, { target: { value: 'My next idea' } });
    await act(async () => {
      acknowledge(true);
      await pending;
    });
    expect(onSend).toHaveBeenCalledWith('First message', []);
    expect((editor as HTMLTextAreaElement).value).toBe('My next idea');
  });

  it('leaves Enter with the input method while a character is being composed', () => {
    const onSend = vi.fn().mockResolvedValue(true);
    render(<Composer {...composerProps({ onSend })} />, { wrapper });
    const editor = screen.getByRole('textbox', { name: 'Message Pi' });
    fireEvent.change(editor, { target: { value: '日本語' } });
    fireEvent.keyDown(editor, { key: 'Enter', isComposing: true });
    fireEvent.keyDown(editor, { key: 'Enter', keyCode: 229 });
    expect(onSend).not.toHaveBeenCalled();
    expect((editor as HTMLTextAreaElement).value).toBe('日本語');
  });

  it('preserves paragraphs when inserting a suggestion into a longer draft', () => {
    render(<Composer {...composerProps()} />, { wrapper });
    const editor = screen.getByRole('textbox', { name: 'Message Pi' });
    fireEvent.change(editor, { target: { value: 'Please explain this command:\n\n/rev' } });
    fireEvent.mouseDown(screen.getByRole('option', { name: /\/review/ }));
    expect((editor as HTMLTextAreaElement).value).toBe('Please explain this command:\n\n/review ');
  });

  it('offers enabled Pi skills and prompts and inserts them without sending', async () => {
    const resource = (
      kind: 'skill' | 'prompt',
      name: string,
      enabled: boolean,
    ): ResourceRecord => ({
      id: name,
      kind,
      name,
      enabled,
      description: 'A useful project resource',
      version: '1',
      source: 'project',
      trusted: true,
      executable: false,
      operations: [],
    });
    const props = composerProps({
      resources: [
        resource('skill', 'explain', true),
        resource('prompt', 'check', true),
        resource('skill', 'disabled', false),
      ],
    });
    render(<Composer {...props} />, { wrapper });
    const editor = screen.getByRole('textbox', { name: 'Message Pi' });
    fireEvent.change(editor, { target: { value: '/' } });
    expect(screen.getByRole('option', { name: /\/review/ })).toBeTruthy();
    expect(screen.getByRole('option', { name: /\/check/ })).toBeTruthy();
    expect(screen.queryByRole('option', { name: /disabled/ })).toBeNull();
    fireEvent.mouseDown(screen.getByRole('option', { name: /\/skill:explain/ }));
    expect((editor as HTMLTextAreaElement).value).toBe('/skill:explain ');
    expect(props.onSend).not.toHaveBeenCalled();
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Send' })));
    expect(props.onSend).toHaveBeenCalledWith('/skill:explain ', []);
    expect(props.onCommand).not.toHaveBeenCalled();
  });

  it('opens commands from the composer but ignores composition keyboard events', () => {
    const onCommand = vi.fn();
    render(
      <>
        <CommandRouter onCommand={onCommand} />
        <textarea aria-label="Editor" />
      </>,
    );
    const editor = screen.getByRole('textbox');
    fireEvent.keyDown(editor, { key: 'k', metaKey: true });
    expect(onCommand).toHaveBeenCalledWith('open-command-menu');
    fireEvent.keyDown(editor, { key: 'Enter', metaKey: true, isComposing: true });
    expect(onCommand).toHaveBeenCalledTimes(1);
  });
});
