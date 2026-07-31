import { invoke } from '@tauri-apps/api/core';

/**
 * Retained for historical comparison only. This WebView-authored recorder is
 * deliberately not imported by the A.23 probe and is not acceptance evidence.
 * The formal gate records the native Tauri invoke/event boundary in Rust.
 */

export const A23_OBSERVED_TAURI_EVENTS = ['piui://stream-probe'] as const;

const MAX_COMMANDS = 256;
const MAX_APP_EVENTS = 128;
const MAX_FORM_CONTROLS = 256;
const MAX_STORAGE_ENTRIES = 256;
const MAX_SNAPSHOT_BYTES = 262_144;

type JsonValue = null | boolean | number | string | JsonValue[] | {
  [key: string]: JsonValue;
};

type CommandObservation = {
  sequence: number;
  command: 'sidecar_start' | 'present_credential_sheet' | 'credential_lifecycle_status';
  input: JsonValue;
  result: JsonValue;
  error: JsonValue;
};

type AppEventObservation = {
  sequence: number;
  event: typeof A23_OBSERVED_TAURI_EVENTS[number];
  payload: JsonValue;
};

type SnapshotReceipt = {
  schemaVersion: 1;
  state: 'captured';
};

function snapshotValue(value: unknown): JsonValue {
  const observable = value instanceof Error
    ? { name: value.name, message: value.message, stack: value.stack ?? null }
    : value === undefined ? { type: 'undefined' } : value;
  const encoded = JSON.stringify(observable);
  if (encoded === undefined) return { type: 'undefined' };
  return JSON.parse(encoded) as JsonValue;
}

function storageEntries(storage: Storage): Array<{ key: string; value: string }> {
  if (storage.length > MAX_STORAGE_ENTRIES) throw new Error('a23-webview-snapshot-overflow');
  const entries: Array<{ key: string; value: string }> = [];
  for (let index = 0; index < storage.length; index += 1) {
    const key = storage.key(index);
    if (key === null) throw new Error('a23-webview-storage-changed');
    const value = storage.getItem(key);
    if (value === null) throw new Error('a23-webview-storage-changed');
    entries.push({ key, value });
  }
  return entries;
}

function formControls(): Array<{
  index: number;
  tag: string;
  inputType: string;
  name: string;
  value: string;
  checked: boolean;
  selectedValues: string[];
}> {
  const controls = [...document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>(
    'input, textarea, select',
  )];
  if (controls.length > MAX_FORM_CONTROLS) throw new Error('a23-webview-snapshot-overflow');
  return controls.map((control, index) => ({
    index,
    tag: control.tagName.toLowerCase(),
    inputType: control instanceof HTMLInputElement ? control.type : '',
    name: control.name,
    value: control.value,
    checked: control instanceof HTMLInputElement ? control.checked : false,
    selectedValues: control instanceof HTMLSelectElement
      ? [...control.selectedOptions].map(({ value }) => value)
      : [],
  }));
}

export class A23WebViewEvidenceRecorder {
  private readonly commands: CommandObservation[] = [];
  private readonly appEvents: AppEventObservation[] = [];
  private appEventOverflow = false;

  async invoke<T>(
    command: CommandObservation['command'],
    input?: Record<string, unknown>,
  ): Promise<T> {
    if (this.commands.length >= MAX_COMMANDS) throw new Error('a23-webview-snapshot-overflow');
    const observation: CommandObservation = {
      sequence: this.commands.length + 1,
      command,
      input: snapshotValue(input),
      result: null,
      error: null,
    };
    try {
      const result = await invoke<T>(command, input);
      observation.result = snapshotValue(result);
      return result;
    } catch (error) {
      observation.error = snapshotValue(error);
      throw error;
    } finally {
      this.commands.push(observation);
    }
  }

  observeAppEvent(event: AppEventObservation['event'], payload: unknown): void {
    if (this.appEvents.length >= MAX_APP_EVENTS) {
      this.appEventOverflow = true;
      return;
    }
    this.appEvents.push({
      sequence: this.appEvents.length + 1,
      event,
      payload: snapshotValue(payload),
    });
  }

  async capture(): Promise<void> {
    if (this.appEventOverflow) throw new Error('a23-webview-snapshot-overflow');
    const snapshot = {
      schemaVersion: 1,
      scope: 'credential-probe-webview-surfaces',
      coverage: {
        arbitraryJavascriptHeap: 'not-claimed',
        document: 'outer-html-inner-text-text-content-form-controls',
        storage: 'local-and-session-storage',
        commands: 'credential-probe-invoke-inputs-results-errors',
        appEvents: [...A23_OBSERVED_TAURI_EVENTS],
      },
      document: {
        outerHtml: document.documentElement.outerHTML,
        innerText: document.body?.innerText ?? '',
        textContent: document.documentElement.textContent ?? '',
        visibilityState: document.visibilityState,
        url: window.location.href,
        formControls: formControls(),
      },
      storage: {
        local: storageEntries(window.localStorage),
        session: storageEntries(window.sessionStorage),
      },
      commands: this.commands,
      appEvents: this.appEvents,
      submission: {
        command: 'credential_webview_snapshot',
        input: 'all-other-fields-in-this-record',
        result: 'file-created-before-command-response',
        error: null,
      },
    } as const;
    const encoded = new TextEncoder().encode(JSON.stringify(snapshot));
    if (encoded.byteLength >= MAX_SNAPSHOT_BYTES) {
      encoded.fill(0);
      throw new Error('a23-webview-snapshot-overflow');
    }
    encoded.fill(0);
    const receipt = await invoke<SnapshotReceipt>('credential_webview_snapshot', { snapshot });
    if (receipt.schemaVersion !== 1 || receipt.state !== 'captured') {
      throw new Error('a23-webview-snapshot-rejected');
    }
  }
}
