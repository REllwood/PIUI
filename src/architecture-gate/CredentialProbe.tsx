import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
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
const A23_TAURI_EVENT = 'piui://stream-probe';
const MAX_DOM_STRING_CODE_UNITS = 32_768;
const MAX_EVENT_PAYLOAD_BYTES = 16_384;
const MAX_FORM_CONTROLS = 256;
const MAX_FORM_VALUE_CODE_UNITS = 8_192;
const MAX_STORAGE_ENTRIES = 256;
const MAX_STORAGE_FIELD_CODE_UNITS = 16_384;
const MAX_TAURI_EVENTS = 128;
const MAX_URL_CODE_UNITS = 2_048;
const MAX_WEBVIEW_AUDIT_BYTES = 49_152;

type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | {
      [key: string]: JsonValue;
    };

type TauriEventObservation = {
  sequence: number;
  event: typeof A23_TAURI_EVENT;
  payload: JsonValue;
};

function boundedString(value: string, maximumCodeUnits: number): string {
  if (value.length > maximumCodeUnits) throw new Error('a23-webview-audit-limit');
  return value;
}

function captureJsonValue(value: unknown): JsonValue {
  const serialised = JSON.stringify(value);
  if (serialised === undefined || serialised.length > MAX_EVENT_PAYLOAD_BYTES) {
    throw new Error('a23-webview-audit-limit');
  }
  const encoded = new TextEncoder().encode(serialised);
  try {
    if (encoded.byteLength > MAX_EVENT_PAYLOAD_BYTES) {
      throw new Error('a23-webview-audit-limit');
    }
    return JSON.parse(serialised) as JsonValue;
  } finally {
    encoded.fill(0);
  }
}

function captureStorage(storage: Storage): Array<{ key: string; value: string }> {
  const initialLength = storage.length;
  if (initialLength > MAX_STORAGE_ENTRIES) throw new Error('a23-webview-audit-limit');
  const entries: Array<{ key: string; value: string }> = [];
  const observedKeys = new Set<string>();
  for (let index = 0; index < initialLength; index += 1) {
    const key = storage.key(index);
    if (key === null || observedKeys.has(key)) throw new Error('a23-webview-audit-changed');
    const value = storage.getItem(key);
    if (value === null) throw new Error('a23-webview-audit-changed');
    observedKeys.add(key);
    entries.push({
      key: boundedString(key, MAX_STORAGE_FIELD_CODE_UNITS),
      value: boundedString(value, MAX_STORAGE_FIELD_CODE_UNITS),
    });
  }
  entries.sort((left, right) => (left.key < right.key ? -1 : left.key > right.key ? 1 : 0));
  if (
    storage.length !== initialLength ||
    entries.some(({ key, value }) => storage.getItem(key) !== value)
  ) {
    throw new Error('a23-webview-audit-changed');
  }
  return entries;
}

function captureFormControls() {
  const controls = [
    ...document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>(
      'input, textarea, select',
    ),
  ];
  if (controls.length > MAX_FORM_CONTROLS) throw new Error('a23-webview-audit-limit');
  return controls.map((control, index) => {
    const selectedValues =
      control instanceof HTMLSelectElement
        ? [...control.selectedOptions].map(({ value }) =>
            boundedString(value, MAX_FORM_VALUE_CODE_UNITS),
          )
        : [];
    if (selectedValues.length > MAX_STORAGE_ENTRIES) {
      throw new Error('a23-webview-audit-limit');
    }
    return {
      index,
      tag: control.tagName.toLowerCase(),
      inputType: control instanceof HTMLInputElement ? control.type : '',
      name: boundedString(control.name, MAX_FORM_VALUE_CODE_UNITS),
      value: boundedString(control.value, MAX_FORM_VALUE_CODE_UNITS),
      checked: control instanceof HTMLInputElement ? control.checked : false,
      selectedValues,
    };
  });
}

function captureDocumentLightDomBoundary() {
  const iframeElementCount = document.querySelectorAll('iframe').length;
  const frameElementCount = document.querySelectorAll('frame').length;
  const observableOpenShadowRootCount = [...document.querySelectorAll<Element>('*')].reduce(
    (count, element) => count + (element.shadowRoot === null ? 0 : 1),
    0,
  );
  if (iframeElementCount !== 0 || frameElementCount !== 0 || observableOpenShadowRootCount !== 0) {
    throw new Error('a23-webview-audit-scope');
  }
  return {
    frameElementCount,
    iframeElementCount,
    observableOpenShadowRootCount,
  } as const;
}

class A23WebViewSurfaceCapture {
  private readonly tauriEvents: TauriEventObservation[] = [];
  private eventCaptureFailed = false;

  observeTauriEvent(payload: unknown): void {
    if (this.tauriEvents.length >= MAX_TAURI_EVENTS) {
      this.eventCaptureFailed = true;
      return;
    }
    try {
      this.tauriEvents.push({
        sequence: this.tauriEvents.length + 1,
        event: A23_TAURI_EVENT,
        payload: captureJsonValue(payload),
      });
    } catch {
      this.eventCaptureFailed = true;
    }
  }

  capture() {
    if (this.eventCaptureFailed) throw new Error('a23-webview-audit-limit');
    const documentElement = document.documentElement;
    const lightDomBoundary = captureDocumentLightDomBoundary();
    const outerHtml = boundedString(documentElement.outerHTML, MAX_DOM_STRING_CODE_UNITS);
    const snapshot = {
      schemaVersion: 1,
      scope: 'credential-probe-webview-surfaces',
      observation: {
        authority: 'trusted-webview-self-serialised-self-attested',
        hostValidation: 'native-boundary-closed-schema-and-canary-scan',
        independentLiveBrowserInspection: 'not-performed-not-claimed',
      },
      coverage: {
        arbitraryJavascriptHeap: 'not-enumerable-not-claimed',
        childBrowsingContexts: 'iframe-and-frame-elements-zero-observed',
        documentDom: 'bounded-document-light-dom-only',
        shadowRoots: 'observable-open-zero-closed-not-observable-not-claimed',
        webStorage: 'complete-local-and-session-at-capture-trusted-self-attested',
        tauriEvents: {
          event: A23_TAURI_EVENT,
          nativeAdmission: 'rust-recorded-after-native-queue-admission',
          webviewDelivery: 'trusted-self-attested',
        },
      },
      document: {
        outerHtml,
        bodyTextContent: boundedString(document.body?.textContent ?? '', MAX_DOM_STRING_CODE_UNITS),
        textContent: boundedString(documentElement.textContent ?? '', MAX_DOM_STRING_CODE_UNITS),
        formControls: captureFormControls(),
        visibilityState: document.visibilityState,
        url: boundedString(window.location.href, MAX_URL_CODE_UNITS),
        ...lightDomBoundary,
      },
      storage: {
        local: captureStorage(window.localStorage),
        session: captureStorage(window.sessionStorage),
      },
      tauriEvents: this.tauriEvents.map((observation) => ({ ...observation })),
    } as const;
    if (documentElement.outerHTML !== outerHtml) throw new Error('a23-webview-audit-changed');
    captureDocumentLightDomBoundary();
    const encoded = new TextEncoder().encode(JSON.stringify(snapshot));
    try {
      if (encoded.byteLength > MAX_WEBVIEW_AUDIT_BYTES) {
        throw new Error('a23-webview-audit-limit');
      }
    } finally {
      encoded.fill(0);
    }
    return snapshot;
  }
}

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

function nextAnimationFrame(signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new DOMException('A.23 probe cancelled', 'AbortError'));
      return;
    }
    const frame = window.requestAnimationFrame(() => {
      signal.removeEventListener('abort', cancel);
      resolve();
    });
    const cancel = () => {
      window.cancelAnimationFrame(frame);
      reject(new DOMException('A.23 probe cancelled', 'AbortError'));
    };
    signal.addEventListener('abort', cancel, { once: true });
  });
}

async function waitForPackagedLifecycle(signal: AbortSignal): Promise<void> {
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
  const [status, setStatus] = useState('Ready to test the optional API-key fallback.');

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

    let stopListening: (() => void) | undefined;
    const surfaceCapture = runPackagedLifecycle ? new A23WebViewSurfaceCapture() : undefined;
    let stage: 'service' | 'sheet' | 'lifecycle' | 'webview' | 'finalising' = 'service';
    try {
      if (runPackagedLifecycle && surfaceCapture) {
        stopListening = await listen<JsonValue>(A23_TAURI_EVENT, ({ payload }) => {
          surfaceCapture.observeTauriEvent(payload);
        });
        await invoke('sidecar_start');
      }
      if (!mounted.current) return;
      stage = 'sheet';
      setBusyLabel('Credential sheet open…');
      setStatus('Credential sheet open.');
      const nextResult = await invoke<CredentialSheetResult>('present_credential_sheet', {
        request,
      });
      if (!mounted.current) return;
      setResult(nextResult);
      if (nextResult.savedState === 'saved' && runPackagedLifecycle) {
        stage = 'lifecycle';
        setBusyLabel('Verifying credential lifecycle…');
        setStatus('Verifying the packaged credential lifecycle.');
        await waitForPackagedLifecycle(controller.signal);
        if (!mounted.current) return;
        stage = 'webview';
        setBusyLabel('Capturing WebView surfaces…');
        setStatus('Capturing bounded WebView state and event payloads.');
        await nextAnimationFrame(controller.signal);
        if (!mounted.current || !surfaceCapture) return;
        const auditStatus = await invoke<CredentialLifecycleStatus>('credential_lifecycle_status', {
          webviewAudit: surfaceCapture.capture(),
        });
        if (auditStatus.state !== 'passed') throw new Error('credential-webview-audit-failed');
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
      if (stage === 'lifecycle' || stage === 'webview' || stage === 'finalising') {
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
      stopListening?.();
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
