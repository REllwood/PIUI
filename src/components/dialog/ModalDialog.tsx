import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
  type RefObject,
} from 'react';
import './dialog.css';

// A native modal <dialog> with the focus handling PIUI's other sheets use: the chosen
// control takes focus on opening, Tab stays inside, Escape dismisses, and focus returns
// to whatever opened it. It works in WKWebView, where window.confirm may not appear.
export function ModalDialog({
  title,
  labelledBy,
  description,
  role = 'dialog',
  className,
  initialFocus,
  onDismiss,
  children,
}: Readonly<{
  // Either a visible title, or the id of a heading the content already provides.
  title?: string;
  labelledBy?: string;
  description?: string;
  role?: 'dialog' | 'alertdialog';
  className?: string;
  initialFocus?: RefObject<HTMLElement | null>;
  onDismiss: () => void;
  children: ReactNode;
}>) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const descriptionId = useId();
  const dismiss = useRef(onDismiss);
  useEffect(() => {
    dismiss.current = onDismiss;
  });

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return undefined;
    const previous = document.activeElement;
    if (!dialog.open) dialog.showModal();
    (initialFocus?.current ?? dialog.querySelector<HTMLElement>('button:not(:disabled)'))?.focus();
    return () => {
      if (dialog.open) dialog.close();
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus();
    };
    // The dialog opens once per mount; later prop changes must not steal focus again.
  }, []);

  const trapFocus = (event: KeyboardEvent<HTMLDialogElement>) => {
    if (event.key !== 'Tab') return;
    const controls = Array.from(
      event.currentTarget.querySelectorAll<HTMLElement>(
        'button, input, select, textarea, a[href], [tabindex]',
      ),
    ).filter(
      (control) =>
        control.tabIndex >= 0 &&
        !control.matches(':disabled') &&
        control.getClientRects().length > 0,
    );
    const first = controls[0];
    const last = controls.at(-1);
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last?.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first?.focus();
    }
  };

  return (
    <dialog
      ref={dialogRef}
      className={`modal-dialog${className ? ` ${className}` : ''}`}
      role={role}
      aria-labelledby={labelledBy ?? titleId}
      aria-describedby={description ? descriptionId : undefined}
      onCancel={(event) => {
        event.preventDefault();
        dismiss.current();
      }}
      onKeyDown={trapFocus}
    >
      {title ? (
        <h2 id={titleId} className="modal-dialog__title">
          {title}
        </h2>
      ) : null}
      {description ? (
        <p id={descriptionId} className="modal-dialog__description">
          {description}
        </p>
      ) : null}
      {children}
    </dialog>
  );
}

export type ConfirmationRequest = Readonly<{
  title: string;
  message: string;
  confirmLabel: string;
  cancelLabel?: string;
  tone?: 'danger' | 'primary';
}>;

function ConfirmationDialog({
  request,
  onSettle,
}: Readonly<{ request: ConfirmationRequest; onSettle: (confirmed: boolean) => void }>) {
  // The cautious choice has focus, so a stray Return never confirms.
  const cancelRef = useRef<HTMLButtonElement>(null);
  return (
    <ModalDialog
      title={request.title}
      description={request.message}
      role="alertdialog"
      initialFocus={cancelRef}
      onDismiss={() => onSettle(false)}
    >
      <div className="modal-dialog__actions">
        <button ref={cancelRef} type="button" className="button" onClick={() => onSettle(false)}>
          {request.cancelLabel ?? 'Cancel'}
        </button>
        <button
          type="button"
          className={`button ${request.tone === 'danger' ? 'button--danger' : 'button--primary'}`}
          onClick={() => onSettle(true)}
        >
          {request.confirmLabel}
        </button>
      </div>
    </ModalDialog>
  );
}

type PendingConfirmation = Readonly<{
  id: number;
  request: ConfirmationRequest;
  resolve: (confirmed: boolean) => void;
}>;

// An in-app replacement for window.confirm: `confirm` resolves true or false once the
// person chooses, and the returned element must be rendered by the caller.
export function useConfirmation(): readonly [
  (request: ConfirmationRequest) => Promise<boolean>,
  ReactNode,
] {
  const [pending, setPending] = useState<PendingConfirmation | null>(null);
  const pendingRef = useRef<PendingConfirmation | null>(null);
  const nextId = useRef(0);

  const confirm = useCallback(
    (request: ConfirmationRequest) =>
      new Promise<boolean>((resolve) => {
        pendingRef.current?.resolve(false);
        nextId.current += 1;
        const next = { id: nextId.current, request, resolve };
        pendingRef.current = next;
        setPending(next);
      }),
    [],
  );

  const settle = useCallback((confirmed: boolean) => {
    const current = pendingRef.current;
    pendingRef.current = null;
    setPending(null);
    current?.resolve(confirmed);
  }, []);

  useEffect(
    () => () => {
      pendingRef.current?.resolve(false);
      pendingRef.current = null;
    },
    [],
  );

  // A superseding request mounts a fresh dialog so focus moves to its own controls.
  const dialog = pending ? (
    <ConfirmationDialog key={pending.id} request={pending.request} onSettle={settle} />
  ) : null;
  return [confirm, dialog] as const;
}
