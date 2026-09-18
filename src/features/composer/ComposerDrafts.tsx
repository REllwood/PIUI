import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
  type SetStateAction,
} from 'react';
import type { NativeAttachment } from '../../platform/native';

export type ComposerAttachmentState = 'idle' | 'picking' | 'attached' | 'failed';

export type ComposerDraft = Readonly<{
  text: string;
  attachment: NativeAttachment | null;
  attachmentState: ComposerAttachmentState;
  textRevision: number;
  attachmentRevision: number;
}>;

const emptyDraft: ComposerDraft = Object.freeze({
  text: '',
  attachment: null,
  attachmentState: 'idle',
  textRevision: 0,
  attachmentRevision: 0,
});

type DraftUpdate = (current: ComposerDraft) => ComposerDraft;

type DraftActions = Readonly<{
  update: (key: string, update: DraftUpdate) => void;
  adopt: (fromKey: string, toKey: string) => void;
}>;

/** Drafts and the actions that change them are separate so movers do not re-render on typing. */
const ComposerDraftContext = createContext<ReadonlyMap<string, ComposerDraft> | null>(null);
const ComposerDraftActionContext = createContext<DraftActions | null>(null);

function carriesWork(draft: ComposerDraft | undefined): draft is ComposerDraft {
  return draft !== undefined && (draft.text !== '' || draft.attachment !== null);
}

/** Keeps unsent text and opaque attachments in memory while routes change. */
export function ComposerDraftProvider({ children }: Readonly<{ children: ReactNode }>) {
  const [drafts, setDrafts] = useState<ReadonlyMap<string, ComposerDraft>>(() => new Map());
  const update = useCallback((key: string, change: DraftUpdate) => {
    setDrafts((current) => {
      const previous = current.get(key) ?? emptyDraft;
      const next = change(previous);
      if (next === previous) return current;
      const updated = new Map(current);
      updated.set(key, next);
      return updated;
    });
  }, []);
  // Text typed before a conversation exists is held under a placeholder key. Move it onto the
  // session that now owns it, revisions and all, rather than stranding it out of view.
  const adopt = useCallback((fromKey: string, toKey: string) => {
    if (fromKey === toKey) return;
    setDrafts((current) => {
      const source = current.get(fromKey);
      if (!carriesWork(source) || carriesWork(current.get(toKey))) return current;
      const updated = new Map(current);
      updated.delete(fromKey);
      updated.set(toKey, source);
      return updated;
    });
  }, []);
  const actions = useMemo(() => ({ update, adopt }), [adopt, update]);
  return (
    <ComposerDraftContext.Provider value={drafts}>
      <ComposerDraftActionContext.Provider value={actions}>
        {children}
      </ComposerDraftActionContext.Provider>
    </ComposerDraftContext.Provider>
  );
}

/** Exposes draft adoption without subscribing the caller to every keystroke. */
export function useComposerDraftAdoption() {
  const actions = useContext(ComposerDraftActionContext);
  if (!actions) throw new Error('Composer drafts require ComposerDraftProvider.');
  return actions.adopt;
}

export function useComposerDraft(draftKey: string) {
  const drafts = useContext(ComposerDraftContext);
  const actions = useContext(ComposerDraftActionContext);
  if (!drafts || !actions) throw new Error('Composer drafts require ComposerDraftProvider.');
  const { update } = actions;
  const setText = useCallback(
    (value: SetStateAction<string>) => {
      update(draftKey, (current) => {
        const text = typeof value === 'function' ? value(current.text) : value;
        return text === current.text
          ? current
          : { ...current, text, textRevision: current.textRevision + 1 };
      });
    },
    [draftKey, update],
  );
  const setAttachment = useCallback(
    (
      attachment: NativeAttachment | null,
      attachmentState: ComposerAttachmentState = attachment ? 'attached' : 'idle',
    ) => {
      update(draftKey, (current) => ({
        ...current,
        attachment,
        attachmentState,
        attachmentRevision: current.attachmentRevision + 1,
      }));
    },
    [draftKey, update],
  );
  const acknowledgeSubmission = useCallback(
    (submitted: ComposerDraft, includeAttachment = true) => {
      update(draftKey, (current) => {
        const clearText = current.textRevision === submitted.textRevision;
        const clearAttachment =
          includeAttachment && current.attachmentRevision === submitted.attachmentRevision;
        if (!clearText && !clearAttachment) return current;
        return {
          ...current,
          ...(clearText ? { text: '', textRevision: current.textRevision + 1 } : {}),
          ...(clearAttachment
            ? {
                attachment: null,
                attachmentState: 'idle' as const,
                attachmentRevision: current.attachmentRevision + 1,
              }
            : {}),
        };
      });
    },
    [draftKey, update],
  );
  return {
    draft: drafts.get(draftKey) ?? emptyDraft,
    setText,
    setAttachment,
    acknowledgeSubmission,
  };
}
