import { invoke } from '@tauri-apps/api/core';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { useCallback, useEffect, useRef, useState } from 'react';

export const A27_LIFECYCLE_ROUTE = 'lifecycle-packaged';
export const A27_LIFECYCLE_TEST_ACTIVE =
  import.meta.env.VITE_PIUI_A27_LIFECYCLE_TEST === '1';

export type LifecyclePhase =
  | 'ready'
  | 'starting'
  | 'running'
  | 'preparing-approval'
  | 'approval-waiting'
  | 'forcing-sidecar-death'
  | 'recovering'
  | 'recovered'
  | 'restarting'
  | 'awaiting-close'
  | 'awaiting-reopen'
  | 'resuming'
  | 'ready-to-quit'
  | 'quitting'
  | 'failed';

export type LifecycleSnapshot = Readonly<{
  schemaVersion: 1;
  phase: LifecyclePhase;
  busy: boolean;
  message: string;
}>;

type LifecycleAction =
  | 'run'
  | 'recover'
  | 'restart'
  | 'close'
  | 'resume'
  | 'quit'
  | 'wait'
  | 'failed';

const exactSnapshotKeys = ['busy', 'message', 'phase', 'schemaVersion'] as const;
const lifecyclePhases = new Set<LifecyclePhase>([
  'ready',
  'starting',
  'running',
  'preparing-approval',
  'approval-waiting',
  'forcing-sidecar-death',
  'recovering',
  'recovered',
  'restarting',
  'awaiting-close',
  'awaiting-reopen',
  'resuming',
  'ready-to-quit',
  'quitting',
  'failed',
]);

export function assertLifecycleSnapshot(value: unknown): LifecycleSnapshot {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('lifecycle-snapshot-rejected');
  }
  const snapshot = value as Record<string, unknown>;
  if (
    JSON.stringify(Object.keys(snapshot).sort()) !== JSON.stringify([...exactSnapshotKeys].sort())
    || snapshot.schemaVersion !== 1
    || typeof snapshot.phase !== 'string'
    || !lifecyclePhases.has(snapshot.phase as LifecyclePhase)
    || typeof snapshot.busy !== 'boolean'
    || typeof snapshot.message !== 'string'
    || snapshot.message.length < 1
    || snapshot.message.length > 160
  ) {
    throw new Error('lifecycle-snapshot-rejected');
  }
  return Object.freeze({
    schemaVersion: 1,
    phase: snapshot.phase as LifecyclePhase,
    busy: snapshot.busy,
    message: snapshot.message,
  });
}

export function actionForLifecyclePhase(phase: LifecyclePhase): LifecycleAction {
  if (phase === 'ready') return 'run';
  if (phase === 'running') return 'recover';
  if (phase === 'recovered') return 'restart';
  if (phase === 'awaiting-close') return 'close';
  if (phase === 'awaiting-reopen' || phase === 'resuming') return 'resume';
  if (phase === 'ready-to-quit') return 'quit';
  if (phase === 'failed') return 'failed';
  return 'wait';
}

async function invokeSnapshot(command: string): Promise<LifecycleSnapshot> {
  return assertLifecycleSnapshot(await invoke<unknown>(command));
}

function nextPaint(): Promise<void> {
  return new Promise((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  });
}

function pause(milliseconds: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

export function LifecycleProbe() {
  const mounted = useRef(true);
  const inFlight = useRef(false);
  const primaryButton = useRef<HTMLButtonElement>(null);
  const [snapshot, setSnapshot] = useState<LifecycleSnapshot>({
    schemaVersion: 1,
    phase: 'starting',
    busy: true,
    message: 'Restoring lifecycle verification…',
  });

  const apply = useCallback((next: LifecycleSnapshot) => {
    if (mounted.current) setSnapshot(next);
    return next;
  }, []);

  const showBusy = useCallback((phase: LifecyclePhase, message: string) => {
    if (!mounted.current) return;
    setSnapshot({ schemaVersion: 1, phase, busy: true, message });
  }, []);

  const fail = useCallback(() => {
    if (!mounted.current) return;
    setSnapshot({
      schemaVersion: 1,
      phase: 'failed',
      busy: false,
      message: 'Lifecycle verification failed. No success evidence was published.',
    });
  }, []);

  const resumeAfterReopen = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      await nextPaint();
      apply(await invokeSnapshot('a27_resume_after_reopen'));
    } catch {
      fail();
    } finally {
      inFlight.current = false;
      requestAnimationFrame(() => primaryButton.current?.focus({ preventScroll: true }));
    }
  }, [apply, fail]);

  useEffect(() => {
    mounted.current = true;
    let cancelled = false;
    void invokeSnapshot('a27_lifecycle_snapshot')
      .then((restored) => {
        if (cancelled) return;
        apply(restored);
        if (actionForLifecyclePhase(restored.phase) === 'resume') {
          void resumeAfterReopen();
        }
      })
      .catch(() => {
        if (!cancelled) fail();
      });
    return () => {
      cancelled = true;
      mounted.current = false;
    };
  }, [apply, fail, resumeAfterReopen]);

  const runLifecycle = useCallback(async () => {
    if (inFlight.current || actionForLifecyclePhase(snapshot.phase) !== 'run') return;
    inFlight.current = true;
    setSnapshot({
      schemaVersion: 1,
      phase: 'starting',
      busy: true,
      message: 'Starting the isolated helper and checking duplicate prevention…',
    });
    try {
      await nextPaint();
      apply(await invokeSnapshot('a27_observe_duplicate_start'));
    } catch {
      fail();
    } finally {
      inFlight.current = false;
      requestAnimationFrame(() => primaryButton.current?.focus({ preventScroll: true }));
    }
  }, [apply, fail, snapshot.phase]);

  const recoverLifecycle = useCallback(async () => {
    if (inFlight.current || actionForLifecyclePhase(snapshot.phase) !== 'recover') return;
    inFlight.current = true;
    try {
      showBusy('preparing-approval', 'Preparing one isolated waiting approval…');
      await nextPaint();
      apply(await invokeSnapshot('a27_prepare_waiting_approval'));
      showBusy('forcing-sidecar-death', 'Stopping the helper unexpectedly…');
      await nextPaint();
      apply(await invokeSnapshot('a27_force_sidecar_death'));
      await nextPaint();
      apply(await invokeSnapshot('a27_recover_after_death'));
    } catch {
      fail();
    } finally {
      inFlight.current = false;
      requestAnimationFrame(() => primaryButton.current?.focus({ preventScroll: true }));
    }
  }, [apply, fail, showBusy, snapshot.phase]);

  const restartLifecycle = useCallback(async () => {
    if (inFlight.current || actionForLifecyclePhase(snapshot.phase) !== 'restart') return;
    inFlight.current = true;
    try {
      showBusy('restarting', 'Verifying an explicit helper restart…');
      await nextPaint();
      apply(await invokeSnapshot('a27_user_restart'));
    } catch {
      fail();
    } finally {
      inFlight.current = false;
      requestAnimationFrame(() => primaryButton.current?.focus({ preventScroll: true }));
    }
  }, [apply, fail, showBusy, snapshot.phase]);

  const closeAndReopen = useCallback(async () => {
    if (inFlight.current || actionForLifecyclePhase(snapshot.phase) !== 'close') return;
    inFlight.current = true;
    showBusy('awaiting-close', 'Closing the last window and stopping the helper…');
    try {
      await nextPaint();
      await getCurrentWindow().close();
    } catch {
      fail();
      inFlight.current = false;
    }
  }, [fail, showBusy, snapshot.phase]);

  const quitAndVerify = useCallback(async () => {
    if (inFlight.current || actionForLifecyclePhase(snapshot.phase) !== 'quit') return;
    inFlight.current = true;
    setSnapshot({
      schemaVersion: 1,
      phase: 'quitting',
      busy: true,
      message: 'Quitting and verifying process, descriptor and lock cleanup…',
    });
    try {
      await nextPaint();
      apply(await invokeSnapshot('a27_request_quit'));
      // A successful request terminates the process. If native cleanup fails,
      // ExitRequested is prevented and the persisted failure becomes visible
      // here instead of leaving a permanent, unexplained busy state.
      for (;;) {
        await pause(100);
        const current = apply(await invokeSnapshot('a27_lifecycle_snapshot'));
        if (current.phase === 'failed') throw new Error('lifecycle-quit-rejected');
      }
    } catch {
      fail();
      inFlight.current = false;
    }
  }, [apply, fail, snapshot.phase]);

  const action = actionForLifecyclePhase(snapshot.phase);
  const buttonLabel: Partial<Record<LifecycleAction, string>> = {
    run: 'Start lifecycle verification',
    recover: 'Verify crash recovery',
    restart: 'Verify explicit restart',
    close: 'Close and verify reopen',
    quit: 'Quit and verify cleanup',
  };
  const disabled = snapshot.busy || buttonLabel[action] === undefined;
  const engage = {
    run: runLifecycle,
    recover: recoverLifecycle,
    restart: restartLifecycle,
    close: closeAndReopen,
    quit: quitAndVerify,
  }[action as 'run' | 'recover' | 'restart' | 'close' | 'quit'];

  return (
    <main
      className="gate lifecycle-probe"
      aria-labelledby="lifecycle-title"
      aria-busy={snapshot.busy}
      data-lifecycle-phase={snapshot.phase}
    >
      <section className="gate__card">
        <p className="gate__eyebrow">Packaged lifecycle proof</p>
        <h1 id="lifecycle-title">Verify helper recovery and cleanup</h1>
        <p className="gate__summary">
          This architecture-only flow checks duplicate-start prevention, crash recovery, explicit
          restart, last-window close and final quit against one isolated application instance.
        </p>
        <button
          ref={primaryButton}
          type="button"
          autoFocus
          disabled={disabled}
          onClick={engage}
        >
          {snapshot.busy ? snapshot.message : (buttonLabel[action] ?? 'Lifecycle verification unavailable')}
        </button>
        {snapshot.busy ? (
          <progress
            aria-label={snapshot.message}
            className="lifecycle-probe__progress"
          />
        ) : null}
        <p role="status" aria-live="polite" className="lifecycle-probe__status">
          {snapshot.message}
        </p>
      </section>
    </main>
  );
}
