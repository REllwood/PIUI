import { invoke } from '@tauri-apps/api/core';
import { useCallback, useEffect, useRef, useState } from 'react';

type CredentialSheetResult = {
  credentialReference: string | null;
  savedState: 'saved' | 'cancelled';
  validationState: 'saved-not-validated' | 'not-run';
  accountLabel: string;
};

type CredentialLifecycleStatus = {
  state: 'pending' | 'passed' | 'failed';
};

const runPackagedLifecycle = import.meta.env.VITE_PIUI_A23_CREDENTIAL_TEST === '1';

function cancellablePause(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new DOMException('A.23 probe cancelled', 'AbortError'));
      return;
    }
    const timer = window.setTimeout(() => {
      signal.removeEventListener('abort', cancel);
      resolve();
    }, milliseconds);
    const cancel = () => {
      window.clearTimeout(timer);
      reject(new DOMException('A.23 probe cancelled', 'AbortError'));
    };
    signal.addEventListener('abort', cancel, { once: true });
  });
}

async function waitForPackagedLifecycle(
  signal: AbortSignal,
): Promise<void> {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    if (signal.aborted) throw new DOMException('A.23 probe cancelled', 'AbortError');
    const status = await invoke<CredentialLifecycleStatus>('credential_lifecycle_status');
    if (status.state === 'passed') return;
    if (status.state !== 'pending') throw new Error('credential-lifecycle-failed');
    await cancellablePause(250, signal);
  }
  throw new Error('credential-lifecycle-timeout');
}

async function waitForExternalTermination(signal: AbortSignal): Promise<never> {
  await new Promise<void>((_, reject) => {
    if (signal.aborted) {
      reject(new DOMException('A.23 probe cancelled', 'AbortError'));
      return;
    }
    signal.addEventListener(
      'abort',
      () => reject(new DOMException('A.23 probe cancelled', 'AbortError')),
      { once: true },
    );
  });
  throw new Error('a23-external-termination-returned');
}

const request = {
  providerId: 'a23.fixture-provider',
  providerLabel: 'Example provider',
  accountLabel: 'Architecture gate account',
} as const;

export function CredentialProbe() {
  const button = useRef<HTMLButtonElement>(null);
  const mounted = useRef(true);
  const inFlight = useRef(false);
  const activeProbe = useRef<AbortController | null>(null);
  const [busy, setBusy] = useState(false);
  const [busyLabel, setBusyLabel] = useState('Preparing…');
  const [result, setResult] = useState<CredentialSheetResult | null>(null);
  const [status, setStatus] = useState(
    'Ready to test the optional API-key fallback.',
  );

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      activeProbe.current?.abort();
      activeProbe.current = null;
    };
  }, []);

  const presentSheet = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    const controller = new AbortController();
    activeProbe.current = controller;
    setBusy(true);
    setBusyLabel('Preparing…');
    setResult(null);
    setStatus(
      runPackagedLifecycle
        ? 'Preparing the isolated credential lifecycle.'
        : 'Preparing the native credential sheet.',
    );

    let stage: 'service' | 'sheet' | 'lifecycle' | 'finalising' = 'service';
    try {
      if (runPackagedLifecycle) await invoke('sidecar_start');
      if (!mounted.current) return;
      stage = 'sheet';
      setBusyLabel('Credential sheet open…');
      setStatus('Credential sheet open.');
      const nextResult = await invoke<CredentialSheetResult>('present_credential_sheet', { request });
      if (!mounted.current) return;
      setResult(nextResult);
      if (nextResult.savedState === 'saved' && runPackagedLifecycle) {
        stage = 'lifecycle';
        setBusyLabel('Verifying credential lifecycle…');
        setStatus('Verifying the packaged credential lifecycle.');
        await waitForPackagedLifecycle(controller.signal);
        if (!mounted.current) return;
        stage = 'finalising';
        setBusyLabel('Finalising…');
        setStatus('Finalising external cleanup and credential leak checks.');
        await waitForExternalTermination(controller.signal);
      } else {
        setStatus(
          nextResult.savedState === 'saved'
            ? 'Credential saved in Keychain. Provider validation has not run.'
            : 'Credential entry cancelled. Nothing was saved.',
        );
      }
    } catch (error) {
      if (!mounted.current) return;
      if (stage === 'lifecycle' || stage === 'finalising') {
        setStatus(
          'Packaged credential verification did not complete. The isolated cleanup will run before the probe exits.',
        );
      } else if (stage === 'service') {
        setStatus('The local credential service is unavailable. Try again.');
      } else {
        setStatus(
          error === 'native-credential-sheet-unsupported'
            ? 'Native credential entry is not supported on this platform.'
            : 'The native credential sheet is unavailable. Try again.',
        );
      }
    } finally {
      if (runPackagedLifecycle) {
        if (mounted.current) {
          setBusy(true);
          setBusyLabel('Finalising…');
        } else {
          inFlight.current = false;
        }
      } else {
        inFlight.current = false;
      }
      if (mounted.current && !runPackagedLifecycle) {
        setBusy(false);
        requestAnimationFrame(() => {
          if (mounted.current) button.current?.focus({ preventScroll: true });
        });
      }
      if (activeProbe.current === controller && !runPackagedLifecycle) {
        activeProbe.current = null;
      }
    }
  }, []);

  return (
    <main className="gate credential-probe" aria-labelledby="credential-title">
      <section className="gate__card">
        <p className="gate__eyebrow">Optional API-key fallback probe</p>
        <h1 id="credential-title">Test native API-key entry</h1>
        <p className="gate__summary">
          PIUI's final onboarding prioritises existing provider subscriptions such as ChatGPT
          Plus/Pro for Codex. This architecture-only page verifies that optional API-key entry and
          reveal stay in a protected macOS sheet while the WebView receives safe metadata only.
        </p>
        <button ref={button} type="button" autoFocus disabled={busy} onClick={presentSheet}>
          {busy ? busyLabel : 'Test API-key fallback'}
        </button>
        <p role="status" aria-live="polite" className="credential-probe__status">
          {status}
        </p>
        {result ? (
          <dl className="gate__status" aria-label="Credential sheet result">
            <div>
              <dt>Credential reference</dt>
              <dd>{result.credentialReference ?? 'None'}</dd>
            </div>
            <div>
              <dt>Saved state</dt>
              <dd>{result.savedState}</dd>
            </div>
            <div>
              <dt>Validation state</dt>
              <dd>{result.validationState}</dd>
            </div>
            <div>
              <dt>Account label</dt>
              <dd>{result.accountLabel}</dd>
            </div>
          </dl>
        ) : null}
      </section>
    </main>
  );
}
