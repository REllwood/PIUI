import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { useProduct } from '../../app/ProductContext';
import { Icon } from '../../components/icons/Icon';
import type { ResourceRecord } from '../../domain/types';
import { useComposerDraft } from './ComposerDrafts';
import './resource-picker.css';

const reservedPromptNames = new Set(['review', 'compact', 'diagnose', 'new', 'sessions']);

function unavailableReason(resource: ResourceRecord): string | null {
  if (!resource.name || /\s/u.test(resource.name) || resource.name.startsWith('/'))
    return 'This name cannot be used as a message shortcut.';
  if (resource.kind === 'prompt' && reservedPromptNames.has(resource.name))
    return 'This name is already used by a PIUI command. Rename the prompt to use it here.';
  return null;
}

export function ResourcePicker({ draftKey }: Readonly<{ draftKey: string }>) {
  const product = useProduct();
  const { setText } = useComposerDraft(draftKey);
  const dialogRef = useRef<HTMLDialogElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const focusDestination = useRef<'trigger' | 'composer' | 'none'>('trigger');
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const titleId = useId();
  const descriptionId = useId();
  const resources = useMemo(
    () =>
      product.snapshot.resources.filter(
        (resource) =>
          resource.enabled &&
          !resource.executable &&
          (resource.kind === 'skill' || resource.kind === 'prompt'),
      ),
    [product.snapshot.resources],
  );
  const matches = useMemo(() => {
    const search = query.trim().toLocaleLowerCase('en-AU');
    return resources.filter((resource) =>
      `${resource.name} ${resource.description} ${resource.kind}`
        .toLocaleLowerCase('en-AU')
        .includes(search),
    );
  }, [query, resources]);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      dialog.showModal();
      searchRef.current?.focus();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open]);

  const restoreFocus = () => {
    if (focusDestination.current === 'trigger') triggerRef.current?.focus();
    if (focusDestination.current === 'composer') {
      const composer = document.querySelector<HTMLTextAreaElement>('#piui-composer');
      composer?.focus();
      composer?.setSelectionRange(composer.value.length, composer.value.length);
    }
  };

  const close = (destination: 'trigger' | 'composer' | 'none' = 'trigger') => {
    focusDestination.current = destination;
    setOpen(false);
    dialogRef.current?.close();
    restoreFocus();
  };

  const insert = (resource: ResourceRecord) => {
    if (unavailableReason(resource)) return;
    const invocation = resource.kind === 'skill' ? `/skill:${resource.name}` : `/${resource.name}`;
    setText((current) => {
      if (current === invocation) return `${invocation} `;
      if (current.startsWith(`${invocation} `)) return current;
      // Pi expands resources only at the start of a prompt. Keep every existing
      // character as the request following the resource invocation.
      return `${invocation} ${current}`;
    });
    close('composer');
  };

  const openResources = () => {
    close('none');
    product.setMode('advanced');
    product.openSettings('resources');
  };

  return (
    <div className="resource-picker">
      <button
        ref={triggerRef}
        type="button"
        className="resource-picker__trigger"
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => {
          focusDestination.current = 'trigger';
          setQuery('');
          setOpen(true);
        }}
      >
        <Icon name="file" width={15} height={15} />
        <span>Skills &amp; prompts</span>
      </button>
      <dialog
        ref={dialogRef}
        className="resource-picker__dialog"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        onCancel={(event) => {
          event.preventDefault();
          close();
        }}
        onClose={() => {
          setOpen(false);
          restoreFocus();
        }}
        onKeyDown={(event) => {
          if (event.key === 'Enter' && (event.target === searchRef.current || event.metaKey)) {
            event.preventDefault();
            event.stopPropagation();
          }
        }}
        onPointerDown={(event) => {
          if (event.target !== event.currentTarget) return;
          const bounds = event.currentTarget.getBoundingClientRect();
          if (
            event.clientX < bounds.left ||
            event.clientX > bounds.right ||
            event.clientY < bounds.top ||
            event.clientY > bounds.bottom
          )
            close();
        }}
      >
        <header className="resource-picker__heading">
          <div>
            <h2 id={titleId}>Skills &amp; prompts</h2>
            <p id={descriptionId}>Give Pi reusable instructions for your next message.</p>
          </div>
          <button
            type="button"
            className="icon-button"
            aria-label="Close skills and prompts"
            onClick={() => close()}
          >
            <Icon name="close" width={18} height={18} />
          </button>
        </header>
        {resources.length > 0 ? (
          <>
            <label className="resource-picker__search">
              <Icon name="search" width={18} height={18} />
              <span className="sr-only">Search skills and prompts</span>
              <input
                ref={searchRef}
                type="search"
                placeholder="Find something to help with your work…"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                autoComplete="off"
              />
            </label>
            <div className="resource-picker__choices">
              {(['skill', 'prompt'] as const).map((kind) => {
                const group = matches.filter((resource) => resource.kind === kind);
                if (group.length === 0) return null;
                return (
                  <section className="resource-picker__group" key={kind}>
                    <h3>{kind === 'skill' ? 'Skills' : 'Prompts'}</h3>
                    <ul>
                      {group.map((resource, index) => {
                        const reason = unavailableReason(resource);
                        const choiceId = `${titleId}-${kind}-${index}`;
                        return (
                          <li key={resource.id}>
                            <button
                              type="button"
                              className="resource-picker__choice"
                              aria-labelledby={`${choiceId}-name`}
                              aria-describedby={`${choiceId}-description${reason ? ` ${choiceId}-reason` : ''}`}
                              disabled={Boolean(reason)}
                              onClick={() => insert(resource)}
                            >
                              <span className="resource-picker__choice-copy">
                                <strong id={`${choiceId}-name`}>{resource.name}</strong>
                                <span id={`${choiceId}-description`}>
                                  {resource.description ||
                                    (kind === 'skill'
                                      ? 'Reusable guidance for a particular kind of work.'
                                      : 'A saved starting point for your message.')}
                                </span>
                                {reason && (
                                  <span
                                    id={`${choiceId}-reason`}
                                    className="resource-picker__unavailable"
                                  >
                                    {reason}
                                  </span>
                                )}
                              </span>
                              {!reason && <Icon name="chevron-right" width={17} height={17} />}
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  </section>
                );
              })}
              {matches.length === 0 && (
                <div className="resource-picker__empty" role="status">
                  <strong>No matches</strong>
                  <p>Try a name or describe the kind of help you need.</p>
                  <button
                    type="button"
                    className="button button--quiet"
                    onClick={() => setQuery('')}
                  >
                    Clear search
                  </button>
                </div>
              )}
            </div>
            <p className="resource-picker__note">
              Choose one to add it to your draft. You can edit your message before sending.
            </p>
          </>
        ) : (
          <div className="resource-picker__empty">
            <strong>A little help you can reuse</strong>
            <p>Skills teach Pi how to approach a task. Prompts save instructions you use often.</p>
            <p>
              No skills or prompts are enabled for this conversation yet. You can manage them in
              Advanced resources.
            </p>
          </div>
        )}
        <footer className="resource-picker__footer">
          <button type="button" className="button button--quiet" onClick={openResources}>
            Open Advanced resources
          </button>
          <button type="button" className="button" onClick={() => close()}>
            Done
          </button>
        </footer>
      </dialog>
    </div>
  );
}
