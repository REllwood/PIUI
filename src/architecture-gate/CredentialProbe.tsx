import { invoke } from '@tauri-apps/api/core';
import { useCallback, useEffect, useRef, useState } from 'react';

type CredentialSheetResult = {
  credentialReference: string | null;
  savedState: 'saved' | 'cancelled';
  validationState: 'saved-not-validated' | 'not-run';
  accountLabel: string;
};

const request = {
  providerLabel: 'Example provider',
  accountLabel: 'Architecture gate account',
} as const;

export function CredentialProbe() {
  const button = useRef<HTMLButtonElement>(null);
  const mounted = useRef(true);
  const inFlight = useRef(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<CredentialSheetResult | null>(null);
  const [status, setStatus] = useState(
    'Ready to open the protected macOS credential sheet.',
  );

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const presentSheet = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setResult(null);
    setStatus('Credential sheet open.');

    try {
      const nextResult = await invoke<CredentialSheetResult>(
        'present_credential_sheet',
        { request },
      );
      if (!mounted.current) return;
      setResult(nextResult);
      setStatus(
        nextResult.savedState === 'saved'
          ? 'Credential saved in Keychain. Provider validation has not run.'
          : 'Credential entry cancelled. Nothing was saved.',
      );
    } catch (error) {
      if (!mounted.current) return;
      setStatus(
        error === 'native-credential-sheet-unsupported'
          ? 'Native credential entry is not supported on this platform.'
          : 'The native credential sheet is unavailable. Try again.',
      );
    } finally {
      inFlight.current = false;
      if (mounted.current) {
        setBusy(false);
        requestAnimationFrame(() => {
          if (mounted.current) button.current?.focus({ preventScroll: true });
        });
      }
    }
  }, []);

  return (
    <main className="gate credential-probe" aria-labelledby="credential-title">
      <section className="gate__card">
        <p className="gate__eyebrow">Native secret boundary</p>
        <h1 id="credential-title">Credential sheet probe</h1>
        <p className="gate__summary">
          API key entry, paste and reveal stay in a protected macOS sheet. This page receives safe
          credential metadata only.
        </p>
        <button ref={button} type="button" autoFocus disabled={busy} onClick={presentSheet}>
          {busy ? 'Credential sheet open…' : 'Add API key'}
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
