import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import {
  closeSync,
  constants,
  lstatSync,
  mkdirSync,
  openSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { chmod, lstat, mkdtemp, open, readFile, readdir, realpath, rm } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { dirname, relative, resolve, sep } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { isDeepStrictEqual } from 'node:util';
import {
  ProcessLedger,
  runOwnedCommand,
  waitForChildSpawn,
} from './a21-gate-support.mjs';
import {
  ARCHITECTURE_VARIANT_DEFINITION_SHA256,
  canonicalArchitectureJson,
} from './architecture-gate-schema.mjs';
import {
  assertPrivateExecutableLease,
  capturePrivateExecutable,
} from './private-executable-lease.mjs';
import { scanSecretCanary } from './scan-secret-canary.mjs';

const PROVIDER_ID = 'a23.fixture-provider';
const APP_PROCESS_NAME = 'PIUI A23 Architecture Test';
const MAX_SAFE_OUTPUT = 65_536;
const MAX_NATIVE_EVIDENCE_BYTES = 262_144;
const MAX_RAW_CAPTURE_BYTES = 262_144;
const MAX_WEBVIEW_AUDIT_BYTES = 49_152;
const MAX_WEBVIEW_DOM_STRING_CODE_UNITS = 32_768;
const MAX_WEBVIEW_EVENT_PAYLOAD_BYTES = 16_384;
const MAX_WEBVIEW_FORM_CONTROLS = 256;
const MAX_WEBVIEW_FORM_VALUE_CODE_UNITS = 8_192;
const MAX_WEBVIEW_STORAGE_ENTRIES = 256;
const MAX_WEBVIEW_STORAGE_FIELD_CODE_UNITS = 16_384;
const MAX_WEBVIEW_TAURI_EVENTS = 128;
const MAX_WEBVIEW_URL_CODE_UNITS = 2_048;
const PRIVATE_CHANNEL_OCCURRENCES = 4;
const PUBLICATION_PENDING_CODE = 'PIUI_A23_PUBLICATION_PENDING';
const A23_MAINTENANCE_TIMEOUT_MS = 120_000;
const A23_NATIVE_SHEET_TIMEOUT_MS = 120_000;
const SHA256 = /^[0-9a-f]{64}$/;
const A23_TAURI_EVENT = 'piui://stream-probe';
export const A23_MAINTENANCE_FAILURE_CODES = Object.freeze([
  'arguments',
  'cleanup-index-readback',
  'cleanup-operation',
  'input',
  'inspect-index-readback',
  'inspect-label-readback',
  'inspect-secret-readback',
  'invariant',
  'output',
  'repository',
  'seed-index-material',
  'seed-index-readback',
  'seed-index-write',
  'seed-label-readback',
  'seed-secret-create',
  'seed-secret-material',
  'seed-secret-readback',
]);
export const A23_MAINTENANCE_EXECUTION_FAILURE_CLASSES = Object.freeze([
  'deadline',
  'descendant-survivor',
  'identity-observation',
  'output-bound',
  'parent-cutoff',
  'start',
  'unclassified',
]);
export const A23_NATIVE_SHEET_FAILURE_CODES = Object.freeze([
  'accessibility-denied',
  'apple-events-denied',
  'application-unavailable',
  'automation-failed',
  'automation-privilege-denied',
  'event-timeout',
  'probe-button-unavailable',
  'process-identity-ambiguous',
  'process-identity-mismatch',
  'save-button-unavailable',
  'script-error',
  'test-value-button-unavailable',
  'ui-object-unavailable',
  'window-unavailable',
]);
const A23_NATIVE_SHEET_SYSTEM_FAILURES = Object.freeze(new Map([
  [-25_211, 'accessibility-denied'],
  [-1_743, 'apple-events-denied'],
  [-600, 'application-unavailable'],
  [-10_000, 'automation-failed'],
  [-10_004, 'automation-privilege-denied'],
  [-1_712, 'event-timeout'],
  [-2_700, 'script-error'],
  [-1_719, 'ui-object-unavailable'],
  [-1_728, 'ui-object-unavailable'],
]));
export const A23_ACCEPTED_HOST_MODE_PHASE_PREFIXES = Object.freeze([
  'accepted-host-creator-cleanup',
  'accepted-host-creator-inspection',
  'accepted-host-creator-seed',
  'accepted-host-final-cleanup',
  'accepted-host-final-inspection',
]);
export const A23_ACCEPTED_HOST_MODE_PHASE_SUFFIXES = Object.freeze([
  'boundary-before',
  'execution',
  ...A23_MAINTENANCE_EXECUTION_FAILURE_CLASSES.map((failureClass) => (
    `execution-failure-${failureClass}`
  )),
  'identity-after',
  'output-validation',
  ...A23_MAINTENANCE_FAILURE_CODES.map((code) => `failure-${code}`),
]);
export const A23_PROBE_PHASES = Object.freeze([
  'accepted-host-creator-cleanup-proof',
  'accepted-host-creator-injected-failure',
  'accepted-host-final-cleanup',
  'accessibility-capture',
  'boundary-validation',
  'canary-scan',
  'candidate-launch',
  'candidate-ledger',
  'candidate-termination',
  'cleanup',
  'cleanup-candidate-termination',
  'cleanup-keychain',
  'cleanup-workspace',
  'evidence-finalisation',
  'helper-precheck-cleanup',
  'helper-precheck-cleanup-boundary-before',
  'helper-precheck-cleanup-execution',
  ...A23_MAINTENANCE_EXECUTION_FAILURE_CLASSES.map((failureClass) => (
    `helper-precheck-cleanup-execution-failure-${failureClass}`
  )),
  'helper-precheck-cleanup-failure-process',
  'helper-precheck-cleanup-identity-after',
  'helper-precheck-cleanup-output-validation',
  ...A23_MAINTENANCE_FAILURE_CODES.map((code) => (
    `helper-precheck-cleanup-failure-${code}`
  )),
  'lifecycle-result',
  'native-boundary-validation',
  'native-sheet-automation',
  ...A23_MAINTENANCE_EXECUTION_FAILURE_CLASSES.map((failureClass) => (
    `native-sheet-automation-execution-failure-${failureClass}`
  )),
  'native-sheet-automation-failure-process',
  ...A23_NATIVE_SHEET_FAILURE_CODES.map((code) => (
    `native-sheet-automation-failure-${code}`
  )),
  'native-sheet-automation-identity-after',
  'native-sheet-automation-output-validation',
  'transcript-validation',
  'workspace-preparation',
  ...A23_ACCEPTED_HOST_MODE_PHASE_PREFIXES.flatMap((prefix) => (
    A23_ACCEPTED_HOST_MODE_PHASE_SUFFIXES.map((suffix) => `${prefix}-${suffix}`)
  )),
]);
const A23_PROBE_PHASE_SET = new Set(A23_PROBE_PHASES);
export const A23_PROCESS_TOPOLOGY = Object.freeze({
  HOST_ONLY: 'host-only',
  HOST_AND_NODE: 'host-and-node',
});
const WRITABLE_RUNTIME_KEYS = Object.freeze([
  'artefacts',
  'cache',
  'config',
  'data',
  'home',
  'temporary',
  'working',
]);
const RESULT_KEYS = [
  'initialGet',
  'logoutDelete',
  'postDeleteMiss',
  'postRefreshGet',
  'privateChannelQuiesced',
  'refreshReads',
  'refreshWrites',
  'schemaVersion',
  'status',
];
const EVIDENCE_KEYS = [
  'bundleFingerprint',
  'cleanup',
  'credentialCleanupHelper',
  'execution',
  'keychain',
  'lifecycle',
  'namespaceIsolation',
  'nativeSheet',
  'privateChannel',
  'publicSurfaces',
  'schemaVersion',
  'status',
];
const CLEANUP_HELPER_IDENTITY_KEYS = Object.freeze([
  'buildRecipeSha256',
  'executableSha256',
  'executableSize',
  'helperSourceSha256',
  'schemaVersion',
  'sourceDigest',
  'toolchainContextSha256',
  'toolchainReceiptSha256',
  'variantDefinitionSha256',
]);
const A23_CLEANUP_HELPER_OVERLAY_TOKEN = '<credential-variant-overlay>';
const A23_CLEANUP_HELPER_BUILD_OVERLAY_TOKEN = '<authenticated-build-overlay>';
const A23_CLEANUP_HELPER_TAURI_ENTRY_TOKEN = '<direct-tauri-entry>';
export const A23_CLEANUP_HELPER_BUILD_ARGUMENT_TAIL = Object.freeze([
  'build',
  '--target',
  'aarch64-apple-darwin',
  '--bundles',
  'app',
  '--no-sign',
  '--config',
  A23_CLEANUP_HELPER_BUILD_OVERLAY_TOKEN,
  '--features',
  'a23-credential-test',
  '--config',
]);
export const A23_CLEANUP_HELPER_BUILD_RECIPE = Object.freeze({
  arguments: Object.freeze([
    A23_CLEANUP_HELPER_TAURI_ENTRY_TOKEN,
    ...A23_CLEANUP_HELPER_BUILD_ARGUMENT_TAIL,
    A23_CLEANUP_HELPER_OVERLAY_TOKEN,
  ]),
  cargoProfile: 'release',
  command: 'authenticated-private-node-direct-tauri-entry',
  executableName: 'credential-cleanup-harness',
  outputPath:
    'src-tauri/target/aarch64-apple-darwin/release/credential-cleanup-harness',
  schemaVersion: 1,
  sourcePath: 'src-tauri/src/bin/credential-cleanup-harness.rs',
  target: 'aarch64-apple-darwin',
  variantDefinitionSha256:
    ARCHITECTURE_VARIANT_DEFINITION_SHA256['credential-twin'],
});
export const A23_CLEANUP_HELPER_BUILD_RECIPE_SHA256 = createHash('sha256')
  .update(Buffer.from(`${canonicalArchitectureJson(A23_CLEANUP_HELPER_BUILD_RECIPE)}\n`, 'utf8'))
  .digest('hex');

function assertCandidatePid(candidatePid) {
  if (!Number.isSafeInteger(candidatePid) || candidatePid < 2) fail();
}

function nativeSheetScript(candidatePid) {
  assertCandidatePid(candidatePid);
  return `
tell application "System Events"
  set appProcess to missing value
  set candidatePID to ${candidatePid}
  repeat 300 times
    set matchingProcesses to every application process whose unix id is candidatePID
    if (count of matchingProcesses) is 1 then
      set exactProcess to item 1 of matchingProcesses
      if name of exactProcess is not "${APP_PROCESS_NAME}" then error "a23-process-identity-mismatch"
      if unix id of exactProcess is not candidatePID then error "a23-process-identity-mismatch"
      set appProcess to exactProcess
      exit repeat
    end if
    if (count of matchingProcesses) is greater than 1 then error "a23-process-identity-ambiguous"
    delay 0.1
  end repeat
  if appProcess is missing value then error "a23-window-unavailable"
  tell appProcess
    set clickedProbe to false
    repeat 300 times
      try
        set frontmost to true
      end try
      if exists window 1 then
        repeat with candidate in (entire contents of window 1)
          try
            if role of candidate is "AXButton" and name of candidate is "Test API-key fallback" then
              click candidate
              set clickedProbe to true
              exit repeat
            end if
          end try
        end repeat
      end if
      if clickedProbe then exit repeat
      delay 0.1
    end repeat
    if not clickedProbe then error "a23-probe-button-unavailable"
    set clickedInsert to false
    repeat 300 times
      if exists window 1 then
        repeat with candidate in (entire contents of window 1)
          try
            if role of candidate is "AXButton" and name of candidate is "Insert test value" then
              click candidate
              set clickedInsert to true
              exit repeat
            end if
          end try
        end repeat
      end if
      if clickedInsert then exit repeat
      delay 0.1
    end repeat
    if not clickedInsert then error "a23-test-value-button-unavailable"
    set clickedSave to false
    repeat 100 times
      if exists window 1 then
        repeat with candidate in (entire contents of window 1)
          try
            if role of candidate is "AXButton" and name of candidate is "Save" and enabled of candidate then
              click candidate
              set clickedSave to true
              exit repeat
            end if
          end try
        end repeat
      end if
      if clickedSave then exit repeat
      delay 0.1
    end repeat
    if not clickedSave then error "a23-save-button-unavailable"
    if name of appProcess is not "${APP_PROCESS_NAME}" then error "a23-process-identity-mismatch"
    if unix id of appProcess is not candidatePID then error "a23-process-identity-mismatch"
  end tell
end tell
return "native-sheet-saved"
`;
}

function accessibilityControlStateScript(candidatePid) {
  assertCandidatePid(candidatePid);
  return `
tell application "System Events"
  set candidatePID to ${candidatePid}
  set matchingProcesses to every application process whose unix id is candidatePID
  if (count of matchingProcesses) is not 1 then error "a23-process-identity-unavailable"
  set appProcess to item 1 of matchingProcesses
  if name of appProcess is not "${APP_PROCESS_NAME}" then error "a23-process-identity-mismatch"
  if unix id of appProcess is not candidatePID then error "a23-process-identity-mismatch"
  tell appProcess
    if not (exists window 1) then error "a23-window-unavailable"
    set safeState to ""
    repeat with candidate in (entire contents of window 1)
      try
        set candidateRole to role of candidate
        set candidateName to name of candidate
        if candidateName is missing value then set candidateName to ""
        set candidateEnabled to "unknown"
        try
          if enabled of candidate then
            set candidateEnabled to "true"
          else
            set candidateEnabled to "false"
          end if
        end try
        set safeState to safeState & candidateRole & tab & candidateName & tab & candidateEnabled & linefeed
      end try
    end repeat
    if name of appProcess is not "${APP_PROCESS_NAME}" then error "a23-process-identity-mismatch"
    if unix id of appProcess is not candidatePID then error "a23-process-identity-mismatch"
    return safeState
  end tell
end tell
`;
}

function fail() {
  throw new Error('A.23 packaged credential probe rejected');
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || !isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort())) fail();
}

function parseOneLine(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 3 || bytes.length > MAX_SAFE_OUTPUT) fail();
  const text = bytes.toString('utf8');
  if (Buffer.byteLength(text) !== bytes.length || !/^[^\r\n]+\n$/.test(text)) fail();
  try { return JSON.parse(text.slice(0, -1)); } catch { fail(); }
}

function parseLifecycleResult(bytes) {
  const value = parseOneLine(bytes);
  exactKeys(value, RESULT_KEYS);
  const expected = {
    schemaVersion: 1,
    status: 'pass',
    initialGet: 1,
    refreshReads: 1,
    refreshWrites: 1,
    postRefreshGet: 1,
    logoutDelete: 1,
    postDeleteMiss: 1,
    privateChannelQuiesced: true,
  };
  if (!isDeepStrictEqual(value, expected)) fail();
  return Object.freeze(expected);
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactCanaryPaths(value, canary, path = [], found = []) {
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    try {
      if (bytes.equals(canary)) found.push(path.join('.'));
    } finally {
      bytes.fill(0);
    }
    return found;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      exactCanaryPaths(value[index], canary, [...path, String(index)], found);
    }
  } else if (isRecord(value)) {
    for (const [key, entry] of Object.entries(value)) {
      exactCanaryPaths(entry, canary, [...path, key], found);
    }
  }
  return found;
}

export function parsePrivateChannelTranscript(bytes, canary) {
  if (!Buffer.isBuffer(bytes) || !Buffer.isBuffer(canary)
    || bytes.length < 32 || bytes.length > MAX_RAW_CAPTURE_BYTES
    || !bytes.subarray(0, 16).equals(Buffer.from('PIUI-A23-RAW-V1\n', 'ascii'))) fail();
  const frames = [];
  let offset = 16;
  while (offset < bytes.length) {
    const headerEnd = bytes.indexOf(0x0a, offset);
    if (headerEnd < 0 || headerEnd - offset > 32) fail();
    const header = bytes.subarray(offset, headerEnd).toString('ascii');
    const match = /^([SH]) ([1-9][0-9]{0,6})$/.exec(header);
    if (!match) fail();
    const length = Number(match[2]);
    const bodyStart = headerEnd + 1;
    const bodyEnd = bodyStart + length;
    if (length > 1_048_576 || bodyEnd > bytes.length) fail();
    const raw = bytes.subarray(bodyStart, bodyEnd);
    const envelope = parseOneLine(raw);
    frames.push(Object.freeze({ direction: match[1], envelope }));
    offset = bodyEnd;
  }
  if (offset !== bytes.length || frames.length !== 12) fail();

  const methods = [
    'credential.get', 'credential.get', 'credential.set',
    'credential.get', 'credential.remove', 'credential.get',
  ];
  let sidecarSequence = -1;
  let hostSequence = -1;
  const observedIds = new Set();
  const allCanaryPaths = [];
  for (let pair = 0; pair < methods.length; pair += 1) {
    const requestFrame = frames[pair * 2];
    const responseFrame = frames[pair * 2 + 1];
    if (requestFrame.direction !== 'S' || responseFrame.direction !== 'H') fail();
    const request = requestFrame.envelope;
    const response = responseFrame.envelope;
    exactKeys(request, ['id', 'kind', 'payload', 'sequence', 'version']);
    exactKeys(response, ['correlationId', 'id', 'kind', 'payload', 'sequence', 'version']);
    if (request.version !== 1 || request.kind !== 'host-request'
      || response.version !== 1 || response.kind !== 'host-response'
      || !Number.isSafeInteger(request.sequence) || request.sequence <= sidecarSequence
      || !Number.isSafeInteger(response.sequence) || response.sequence <= hostSequence
      || typeof request.id !== 'string' || request.id.length < 1
      || typeof response.id !== 'string' || response.id.length < 1
      || observedIds.has(request.id) || observedIds.has(response.id)
      || response.correlationId !== request.id || !isRecord(request.payload)
      || !isRecord(response.payload)) fail();
    sidecarSequence = request.sequence;
    hostSequence = response.sequence;
    observedIds.add(request.id);
    observedIds.add(response.id);
    const method = methods[pair];
    const requestKeys = method === 'credential.set'
      ? ['credential', 'method', 'providerId']
      : ['method', 'providerId'];
    exactKeys(request.payload, requestKeys);
    if (request.payload.method !== method || request.payload.providerId !== PROVIDER_ID) fail();

    if (method === 'credential.get' && pair < 4) {
      exactKeys(response.payload, ['credential', 'found']);
      const credential = response.payload.credential;
      if (response.payload.found !== true || !isRecord(credential)
        || credential.type !== 'api_key' || typeof credential.key !== 'string') fail();
      if (pair < 2) exactKeys(credential, ['key', 'type']);
      else {
        exactKeys(credential, ['env', 'key', 'type']);
        exactKeys(credential.env, ['PIUI_A23_REFRESHED']);
        if (credential.env.PIUI_A23_REFRESHED !== '1') fail();
      }
    } else if (method === 'credential.set') {
      exactKeys(request.payload.credential, ['env', 'key', 'type']);
      exactKeys(request.payload.credential.env, ['PIUI_A23_REFRESHED']);
      if (request.payload.credential.type !== 'api_key'
        || request.payload.credential.env.PIUI_A23_REFRESHED !== '1') fail();
      exactKeys(response.payload, ['stored']);
      if (response.payload.stored !== true) fail();
    } else if (method === 'credential.remove') {
      exactKeys(response.payload, ['removed']);
      if (response.payload.removed !== true) fail();
    } else {
      exactKeys(response.payload, ['found']);
      if (response.payload.found !== false) fail();
    }
    for (const path of exactCanaryPaths(request, canary)) {
      allCanaryPaths.push(`frame-${pair * 2}.${path}`);
    }
    for (const path of exactCanaryPaths(response, canary)) {
      allCanaryPaths.push(`frame-${pair * 2 + 1}.${path}`);
    }
  }
  const expectedCanaryPaths = [
    'frame-1.payload.credential.key',
    'frame-3.payload.credential.key',
    'frame-4.payload.credential.key',
    'frame-7.payload.credential.key',
  ];
  if (!isDeepStrictEqual(allCanaryPaths, expectedCanaryPaths)) fail();
  return Object.freeze({ frames: frames.length, canaryOccurrences: allCanaryPaths.length });
}

function assertBoundedString(value, maximumCodeUnits) {
  if (typeof value !== 'string' || value.length > maximumCodeUnits) fail();
}

function assertBoundedJson(value, budget = { nodes: 0 }, depth = 0) {
  budget.nodes += 1;
  if (budget.nodes > 4_096 || depth > 16) fail();
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail();
    return;
  }
  if (typeof value === 'string') {
    assertBoundedString(value, MAX_WEBVIEW_EVENT_PAYLOAD_BYTES);
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 512) fail();
    for (const item of value) assertBoundedJson(item, budget, depth + 1);
    return;
  }
  if (!isRecord(value) || Object.keys(value).length > 256) fail();
  for (const [key, item] of Object.entries(value)) {
    assertBoundedString(key, 256);
    assertBoundedJson(item, budget, depth + 1);
  }
}

function assertJsonByteLimit(value, maximumBytes) {
  let encoded;
  try {
    encoded = Buffer.from(JSON.stringify(value), 'utf8');
  } catch {
    fail();
  }
  try {
    if (encoded.length > maximumBytes) fail();
  } finally {
    encoded.fill(0);
  }
}

function parseNativeTauriEvent(record) {
  exactKeys(record, [
    'boundary', 'bytesUtf8', 'event', 'record', 'schemaVersion', 'sequence',
  ]);
  if (record.event !== A23_TAURI_EVENT
    || record.boundary !== 'piui-stream-probe-native-queue-admission') fail();
  assertBoundedString(record.bytesUtf8, MAX_SAFE_OUTPUT);
  let envelope;
  try {
    envelope = JSON.parse(record.bytesUtf8);
  } catch {
    fail();
  }
  if (!isRecord(envelope)
    || envelope.version !== 1
    || !['event', 'ack'].includes(envelope.kind)
    || typeof envelope.id !== 'string'
    || envelope.id.length < 1
    || envelope.id.length > 256
    || !Number.isSafeInteger(envelope.sequence)
    || envelope.sequence < 1
    || !isRecord(envelope.payload)) fail();
  const requiredKeys = ['id', 'kind', 'payload', 'sequence', 'version'];
  const optionalKeys = new Set(['correlationId', 'decisionId', 'error']);
  if (requiredKeys.some((key) => !Object.hasOwn(envelope, key))
    || Object.keys(envelope).some((key) => (
      !requiredKeys.includes(key) && !optionalKeys.has(key)
    ))) fail();
  for (const key of ['correlationId', 'decisionId']) {
    if (Object.hasOwn(envelope, key)) {
      assertBoundedString(envelope[key], 256);
      if (envelope[key].length < 1) fail();
    }
  }
  assertBoundedJson(envelope.payload);
  if (Object.hasOwn(envelope, 'error')) assertBoundedJson(envelope.error);
  assertJsonByteLimit(envelope.payload, MAX_WEBVIEW_EVENT_PAYLOAD_BYTES);
  return envelope;
}

function assertWebViewStorage(entries) {
  if (!Array.isArray(entries) || entries.length > MAX_WEBVIEW_STORAGE_ENTRIES) fail();
  let previousKey;
  for (const entry of entries) {
    exactKeys(entry, ['key', 'value']);
    assertBoundedString(entry.key, MAX_WEBVIEW_STORAGE_FIELD_CODE_UNITS);
    assertBoundedString(entry.value, MAX_WEBVIEW_STORAGE_FIELD_CODE_UNITS);
    if (previousKey !== undefined && previousKey >= entry.key) fail();
    previousKey = entry.key;
  }
}

function assertWebViewAudit(snapshot, nativeEvents) {
  exactKeys(snapshot, [
    'coverage', 'document', 'observation', 'schemaVersion', 'scope', 'storage', 'tauriEvents',
  ]);
  if (snapshot.schemaVersion !== 1
    || snapshot.scope !== 'credential-probe-webview-surfaces') fail();
  exactKeys(snapshot.observation, [
    'authority', 'hostValidation', 'independentLiveBrowserInspection',
  ]);
  if (!isDeepStrictEqual(snapshot.observation, {
    authority: 'trusted-webview-self-serialised-self-attested',
    hostValidation: 'native-boundary-closed-schema-and-canary-scan',
    independentLiveBrowserInspection: 'not-performed-not-claimed',
  })) fail();
  exactKeys(snapshot.coverage, [
    'arbitraryJavascriptHeap', 'childBrowsingContexts', 'documentDom',
    'shadowRoots', 'tauriEvents', 'webStorage',
  ]);
  if (!isDeepStrictEqual(snapshot.coverage, {
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
  })) fail();
  exactKeys(snapshot.document, [
    'bodyTextContent', 'formControls', 'frameElementCount', 'iframeElementCount',
    'observableOpenShadowRootCount', 'outerHtml', 'textContent', 'url', 'visibilityState',
  ]);
  assertBoundedString(snapshot.document.outerHtml, MAX_WEBVIEW_DOM_STRING_CODE_UNITS);
  assertBoundedString(snapshot.document.bodyTextContent, MAX_WEBVIEW_DOM_STRING_CODE_UNITS);
  assertBoundedString(snapshot.document.textContent, MAX_WEBVIEW_DOM_STRING_CODE_UNITS);
  assertBoundedString(snapshot.document.url, MAX_WEBVIEW_URL_CODE_UNITS);
  if (!snapshot.document.outerHtml.toLowerCase().includes('<html')
    || snapshot.document.frameElementCount !== 0
    || snapshot.document.iframeElementCount !== 0
    || snapshot.document.observableOpenShadowRootCount !== 0
    || !['hidden', 'visible'].includes(snapshot.document.visibilityState)) fail();
  let parsedUrl;
  try {
    parsedUrl = new URL(snapshot.document.url);
  } catch {
    fail();
  }
  if (!['http:', 'https:', 'tauri:'].includes(parsedUrl.protocol)
    || parsedUrl.username !== ''
    || parsedUrl.password !== ''
    || parsedUrl.hash !== ''
    || parsedUrl.search !== '?spike=credential'
    || !parsedUrl.pathname.endsWith('/index.html')) fail();
  if (!Array.isArray(snapshot.document.formControls)
    || snapshot.document.formControls.length > MAX_WEBVIEW_FORM_CONTROLS) fail();
  snapshot.document.formControls.forEach((control, index) => {
    exactKeys(control, [
      'checked', 'index', 'inputType', 'name', 'selectedValues', 'tag', 'value',
    ]);
    if (control.index !== index
      || !['input', 'select', 'textarea'].includes(control.tag)
      || typeof control.checked !== 'boolean'
      || !Array.isArray(control.selectedValues)
      || control.selectedValues.length > MAX_WEBVIEW_STORAGE_ENTRIES) fail();
    assertBoundedString(control.inputType, 128);
    assertBoundedString(control.name, MAX_WEBVIEW_FORM_VALUE_CODE_UNITS);
    assertBoundedString(control.value, MAX_WEBVIEW_FORM_VALUE_CODE_UNITS);
    for (const value of control.selectedValues) {
      assertBoundedString(value, MAX_WEBVIEW_FORM_VALUE_CODE_UNITS);
    }
  });
  exactKeys(snapshot.storage, ['local', 'session']);
  assertWebViewStorage(snapshot.storage.local);
  assertWebViewStorage(snapshot.storage.session);
  if (!Array.isArray(snapshot.tauriEvents)
    || snapshot.tauriEvents.length > MAX_WEBVIEW_TAURI_EVENTS
    || snapshot.tauriEvents.length !== nativeEvents.length) fail();
  snapshot.tauriEvents.forEach((observation, index) => {
    exactKeys(observation, ['event', 'payload', 'sequence']);
    if (observation.sequence !== index + 1
      || observation.event !== A23_TAURI_EVENT) fail();
    assertBoundedJson(observation.payload);
    assertJsonByteLimit(observation.payload, MAX_WEBVIEW_EVENT_PAYLOAD_BYTES);
    if (!isDeepStrictEqual(observation.payload, nativeEvents[index])) fail();
  });
  assertJsonByteLimit(snapshot, MAX_WEBVIEW_AUDIT_BYTES);
}

export function parseNativeBoundaryEvidence(
  bytes,
  runNonce,
  candidatePid,
  hostIdentity,
  canary,
) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 3 || bytes.length > MAX_NATIVE_EVIDENCE_BYTES
    || !Buffer.isBuffer(canary)
    || !/^PIUI_A23_[0-9a-f]{48}$/.test(canary.toString('ascii'))
    || typeof runNonce !== 'string' || !/^[0-9a-f]{32}$/.test(runNonce)) fail();
  if (bytes.includes(canary)) fail();
  const lines = bytes.toString('utf8').split('\n');
  if (lines.pop() !== '' || lines.length < 9) fail();
  const records = lines.map((line) => {
    if (!line || Buffer.byteLength(line, 'utf8') > MAX_SAFE_OUTPUT) fail();
    try { return JSON.parse(line); } catch { fail(); }
  });
  records.forEach((record, index) => {
    if (!isRecord(record) || record.schemaVersion !== 1 || record.sequence !== index + 1) fail();
  });
  const header = records[0];
  exactKeys(header, [
    'coverage', 'executable', 'processId', 'record', 'runNonce',
    'schemaVersion', 'sequence',
  ]);
  exactKeys(header.executable, ['bytes', 'device', 'inode']);
  exactKeys(header.coverage, [
    'arbitraryJavascriptHeap', 'documentDom', 'invokeInputs',
    'invokeResults', 'rustEvents', 'webStorage',
  ]);
  if (header.record !== 'header' || header.runNonce !== runNonce
    || header.processId !== candidatePid
    || header.executable.device !== hostIdentity.dev
    || header.executable.inode !== hostIdentity.ino
    || header.executable.bytes !== hostIdentity.bytes
    || !isDeepStrictEqual(header.coverage, {
      invokeInputs: 'all-native-handler-entries',
      invokeResults: 'closed-a23-command-set',
      rustEvents: 'piui-stream-probe-native-queue-admission',
      documentDom: 'not-claimed',
      webStorage: 'not-claimed',
      arbitraryJavascriptHeap: 'not-claimed',
    })) fail();

  const pairs = [];
  const nativeEvents = [];
  let pendingEntry;
  for (const record of records.slice(1)) {
    if (record.record === 'rust-event') {
      nativeEvents.push(parseNativeTauriEvent(record));
      if (nativeEvents.length > MAX_WEBVIEW_TAURI_EVENTS) fail();
    } else if (record.record === 'invoke-entry') {
      if (pendingEntry) fail();
      exactKeys(record, ['command', 'input', 'record', 'schemaVersion', 'sequence']);
      pendingEntry = record;
    } else if (record.record === 'invoke-result') {
      if (!pendingEntry || record.command !== pendingEntry.command) fail();
      exactKeys(record, ['command', 'record', 'result', 'schemaVersion', 'sequence']);
      pairs.push(Object.freeze({ entry: pendingEntry, result: record }));
      pendingEntry = undefined;
    } else {
      fail();
    }
  }
  if (pendingEntry || pairs.length < 4) fail();

  const start = pairs[0];
  if (start.entry.command !== 'sidecar_start'
    || !isDeepStrictEqual(start.entry.input, {})
    || start.result.result?.running !== true
    || start.result.result?.failed !== false) fail();
  const sheet = pairs[1];
  if (sheet.entry.command !== 'present_credential_sheet') fail();
  exactKeys(sheet.entry.input, ['request']);
  if (!isDeepStrictEqual(sheet.entry.input.request, {
    providerId: PROVIDER_ID,
    providerLabel: 'Example provider',
    accountLabel: 'Architecture gate account',
  })) fail();
  exactKeys(sheet.result.result, [
    'accountLabel', 'credentialReference', 'savedState', 'validationState',
  ]);
  if (sheet.result.result.savedState !== 'saved'
    || sheet.result.result.validationState !== 'saved-not-validated'
    || sheet.result.result.accountLabel !== 'Architecture gate account'
    || typeof sheet.result.result.credentialReference !== 'string') fail();

  const statusPairs = pairs.slice(2);
  const auditPair = statusPairs.at(-1);
  const pollingPairs = statusPairs.slice(0, -1);
  if (!auditPair || pollingPairs.length < 1
    || auditPair.entry.command !== 'credential_lifecycle_status'
    || auditPair.result.result?.state !== 'passed') fail();
  exactKeys(auditPair.entry.input, ['webviewAudit']);
  for (let index = 0; index < pollingPairs.length; index += 1) {
    const pair = pollingPairs[index];
    if (pair.entry.command !== 'credential_lifecycle_status'
      || !isDeepStrictEqual(pair.entry.input, {})
      || !['pending', 'passed'].includes(pair.result.result?.state)
      || (index + 1 === pollingPairs.length) !== (pair.result.result.state === 'passed')) fail();
  }
  assertWebViewAudit(auditPair.entry.input.webviewAudit, nativeEvents);
  return Object.freeze({ records: records.length, events: nativeEvents.length });
}

export function parseAccessibilityControlState(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > MAX_SAFE_OUTPUT) fail();
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail();
  }
  if (!text.endsWith('\n')) fail();
  const rows = text.slice(0, -1).split('\n').map((line) => {
    const fields = line.split('\t');
    if (fields.length !== 3 || !/^AX[A-Za-z]+$/.test(fields[0])
      || !['true', 'false', 'unknown'].includes(fields[2])
      || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(fields[1])) fail();
    return Object.freeze({ role: fields[0], name: fields[1], enabled: fields[2] });
  });
  const finalisingButtons = rows.filter((row) => row.role === 'AXButton'
    && row.name === 'Finalising…' && row.enabled === 'false');
  const finalisingStatuses = rows.filter((row) =>
    row.name === 'Finalising external cleanup and credential leak checks.');
  const forbiddenOpenSheetNames = new Set([
    'API key', 'Cancel', 'Insert test value', 'Save', 'Test API-key fallback',
  ]);
  if (rows.some((row) => forbiddenOpenSheetNames.has(row.name))) fail();
  if (finalisingButtons.length === 1 && finalisingStatuses.length === 1) {
    return Object.freeze({
      state: 'final', controls: rows.length, finalisingButtons: 1, finalisingStatuses: 1,
    });
  }
  const capturingButtons = rows.filter((row) => row.role === 'AXButton'
    && row.name === 'Capturing WebView surfaces…' && row.enabled === 'false');
  const capturingStatuses = rows.filter((row) =>
    row.name === 'Capturing bounded WebView state and event payloads.');
  if (capturingButtons.length === 1 && capturingStatuses.length === 1
    && finalisingButtons.length === 0 && finalisingStatuses.length === 0) {
    return Object.freeze({ state: 'pending', controls: rows.length });
  }
  const verifyingButtons = rows.filter((row) => row.role === 'AXButton'
    && row.name === 'Verifying credential lifecycle…' && row.enabled === 'false');
  const verifyingStatuses = rows.filter((row) =>
    row.name === 'Verifying the packaged credential lifecycle.');
  if (verifyingButtons.length === 1 && verifyingStatuses.length === 1
    && finalisingButtons.length === 0 && finalisingStatuses.length === 0) {
    return Object.freeze({ state: 'pending', controls: rows.length });
  }
  fail();
}

function parseCleanup(bytes) {
  const value = parseOneLine(bytes);
  exactKeys(value, ['cleanupSucceeded', 'indexAbsent', 'schemaVersion']);
  if (!isDeepStrictEqual(value, {
    schemaVersion: 1,
    cleanupSucceeded: true,
    indexAbsent: true,
  })) fail();
}

function parseCleanupFixtureSeed(bytes) {
  const value = parseOneLine(bytes);
  exactKeys(value, ['fixtureSeeded', 'indexPresent', 'schemaVersion']);
  if (!isDeepStrictEqual(value, {
    schemaVersion: 1,
    fixtureSeeded: true,
    indexPresent: true,
  })) fail();
}

function parseCleanupFixtureInspection(bytes) {
  const value = parseOneLine(bytes);
  exactKeys(value, [
    'fixtureAbsent', 'indexAbsent', 'labelAbsent', 'schemaVersion', 'secretAbsent',
  ]);
  if (!isDeepStrictEqual(value, {
    schemaVersion: 1,
    fixtureAbsent: true,
    indexAbsent: true,
    secretAbsent: true,
    labelAbsent: true,
  })) fail();
}

export function assertA23CleanupHelperIdentity(value, expectedLease) {
  exactKeys(value, CLEANUP_HELPER_IDENTITY_KEYS);
  if (value.schemaVersion !== 1
    || !Number.isSafeInteger(value.executableSize)
    || value.executableSize < 1
    || value.executableSize > 128 * 1_048_576
    || !SHA256.test(value.executableSha256)
    || value.buildRecipeSha256 !== A23_CLEANUP_HELPER_BUILD_RECIPE_SHA256
    || !SHA256.test(value.helperSourceSha256)
    || !SHA256.test(value.sourceDigest)
    || !SHA256.test(value.toolchainContextSha256)
    || !SHA256.test(value.toolchainReceiptSha256)
    || !SHA256.test(value.variantDefinitionSha256)) fail();
  if (expectedLease !== undefined
    && (!expectedLease
      || typeof expectedLease !== 'object'
      || Array.isArray(expectedLease)
      || value.executableSize !== expectedLease.size
      || value.executableSha256 !== expectedLease.sha256)) fail();
  return Object.freeze({ ...value });
}

export function createA23CleanupHelperIdentity({
  buildArguments,
  formalBuildOverlayPath,
  frozenSourceDigest,
  helper,
  helperSourceSha256,
  tauriEntry,
  toolchainContextSha256,
  toolchainReceiptSha256,
  variantOverlayPath,
  variantDefinitionSha256,
}) {
  if (typeof tauriEntry !== 'string'
    || resolve(tauriEntry) !== tauriEntry
    || typeof formalBuildOverlayPath !== 'string'
    || resolve(formalBuildOverlayPath) !== formalBuildOverlayPath
    || typeof variantOverlayPath !== 'string'
    || resolve(variantOverlayPath) !== variantOverlayPath
    || new Set([tauriEntry, formalBuildOverlayPath, variantOverlayPath]).size !== 3
    || /[\0\r\n]/u.test(tauriEntry + formalBuildOverlayPath + variantOverlayPath)
    || variantDefinitionSha256
      !== ARCHITECTURE_VARIANT_DEFINITION_SHA256['credential-twin']
    || !Array.isArray(buildArguments)
    || !isDeepStrictEqual(buildArguments, [
      tauriEntry,
      ...A23_CLEANUP_HELPER_BUILD_ARGUMENT_TAIL.map((argument) => (
        argument === A23_CLEANUP_HELPER_BUILD_OVERLAY_TOKEN
          ? formalBuildOverlayPath
          : argument
      )),
      variantOverlayPath,
    ])) fail();
  return assertA23CleanupHelperIdentity({
    buildRecipeSha256: A23_CLEANUP_HELPER_BUILD_RECIPE_SHA256,
    executableSha256: helper?.sha256,
    executableSize: helper?.size,
    helperSourceSha256,
    schemaVersion: 1,
    sourceDigest: frozenSourceDigest,
    toolchainContextSha256,
    toolchainReceiptSha256,
    variantDefinitionSha256,
  }, helper);
}

export function assertSafeCredentialEvidence(
  value,
  generatedOutputsRequired = false,
  expectedFingerprint,
  expectedCleanupHelper,
) {
  if (typeof expectedFingerprint !== 'string' || !SHA256.test(expectedFingerprint)) fail();
  exactKeys(value, generatedOutputsRequired
    ? [...EVIDENCE_KEYS, 'generatedOutputsRemoved']
    : EVIDENCE_KEYS);
  if (value.bundleFingerprint !== expectedFingerprint) fail();
  exactKeys(value.lifecycle, [
    'initialGet', 'logoutDelete', 'postDeleteMiss', 'postRefreshGet',
    'refreshReads', 'refreshWrites',
  ]);
  exactKeys(value.privateChannel, [
    'authorisedFiles', 'authorisedOccurrences', 'quiescedBeforeScan',
    'rawFrames', 'unauthorisedOccurrences',
  ]);
  exactKeys(value.publicSurfaces, [
    'accessibilityControls', 'arbitraryJavascriptHeap', 'childBrowsingContexts',
    'documentDom', 'logsAndCrashArtefacts', 'nativeInvokeBoundary',
    'ordinaryAppData', 'rustEventBoundary', 'shadowRoots', 'webStorage',
    'webViewInspectionAuthority',
  ]);
  exactKeys(value.cleanup, [
    'credentialInputDescriptorClosed', 'helperExecutionResidual',
    'keychainEntriesRemoved', 'keychainIndexRemoved',
    'ownedProcessesRemoved', 'privateCapturesRemoved', 'runnerIsolateRemoved',
  ]);
  const credentialCleanupHelper = assertA23CleanupHelperIdentity(
    value.credentialCleanupHelper,
    expectedCleanupHelper,
  );
  const expected = {
    schemaVersion: 1,
    status: 'pass',
    bundleFingerprint: expectedFingerprint,
    credentialCleanupHelper,
    execution: 'genuine-packaged-app',
    namespaceIsolation: 'isolated-test-keychain',
    nativeSheet: 'appkit-accessibility-driven',
    keychain: 'stored-refreshed-deleted',
    lifecycle: {
      initialGet: 1,
      refreshReads: 1,
      refreshWrites: 1,
      postRefreshGet: 1,
      logoutDelete: 1,
      postDeleteMiss: 1,
    },
    privateChannel: {
      authorisedFiles: 1,
      authorisedOccurrences: PRIVATE_CHANNEL_OCCURRENCES,
      unauthorisedOccurrences: 0,
      quiescedBeforeScan: true,
      rawFrames: 12,
    },
    publicSurfaces: {
      accessibilityControls: 'runner-owned-after-quiescence-scanned',
      nativeInvokeBoundary: 'all-entries-and-expected-results-scanned',
      rustEventBoundary: 'piui-stream-probe-native-admission-and-trusted-webview-self-attested-delivery-host-scanned',
      webViewInspectionAuthority: 'trusted-webview-self-serialised-self-attested-not-independent-live-browser-inspection',
      documentDom: 'bounded-document-light-dom-native-boundary-host-scanned',
      childBrowsingContexts: 'trusted-webview-self-attested-zero-iframe-and-frame-elements',
      shadowRoots: 'trusted-webview-self-attested-zero-observable-open-closed-not-observable-not-claimed',
      webStorage: 'bounded-local-and-session-native-boundary-host-scanned',
      arbitraryJavascriptHeap: 'not-enumerable-not-claimed',
      logsAndCrashArtefacts: 'isolated-runtime-and-owned-stdio-only',
      ordinaryAppData: 'isolated-runtime-only',
    },
    cleanup: {
      credentialInputDescriptorClosed: true,
      helperExecutionResidual: 'private-precheck-and-same-accepted-host-creator-cleanup-keychain-sandboxed',
      keychainEntriesRemoved: true,
      keychainIndexRemoved: true,
      ownedProcessesRemoved: true,
      privateCapturesRemoved: true,
      runnerIsolateRemoved: true,
    },
    ...(generatedOutputsRequired ? { generatedOutputsRemoved: true } : {}),
  };
  if (!isDeepStrictEqual(value, expected)) fail();
  return Object.freeze(value);
}

export function parsePackagedCredentialEvidence(bytes, expectedFingerprint) {
  return assertSafeCredentialEvidence(parseOneLine(bytes), true, expectedFingerprint);
}

function privateWorkspace() {
  const root = realpathSync(tmpdir());
  const workspace = lstatSync(root);
  if (!workspace.isDirectory() || workspace.isSymbolicLink()
    || (workspace.mode & 0o077) !== 0
    || workspace.uid !== process.getuid()) fail();
  return mkdtemp(resolve(root, 'piui-a23-runtime-')).then(async (path) => {
    await chmod(path, 0o700);
    return realpath(path);
  });
}

function createRuntimeDirectories(root) {
  const runtime = Object.freeze({
    artefacts: resolve(root, 'artefacts'),
    cache: resolve(root, 'cache'),
    config: resolve(root, 'config'),
    data: resolve(root, 'data'),
    home: resolve(root, 'home'),
    temporary: resolve(root, 'tmp'),
    working: resolve(root, 'cwd'),
  });
  for (const path of [...writableRuntimeRoots(runtime),
    resolve(runtime.home, 'Library/Logs/DiagnosticReports')]) {
    mkdirSync(path, { recursive: true, mode: 0o700 });
  }
  for (const path of writableRuntimeRoots(runtime)) {
    const item = lstatSync(path);
    if (!item.isDirectory() || item.isSymbolicLink() || item.uid !== process.getuid()
      || (item.mode & 0o077) !== 0) fail();
  }
  return runtime;
}

function writableRuntimeRoots(runtime) {
  return WRITABLE_RUNTIME_KEYS.map((key) => runtime[key]);
}

function runtimeEnvironment(runtime, paths, namespace, runNonce) {
  return {
    HOME: runtime.home,
    CFFIXED_USER_HOME: runtime.home,
    TMPDIR: `${runtime.temporary}/`,
    XDG_CACHE_HOME: runtime.cache,
    XDG_CONFIG_HOME: runtime.config,
    XDG_DATA_HOME: runtime.data,
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    LANG: 'en_AU.UTF-8',
    LC_ALL: 'en_AU.UTF-8',
    PIUI_A23_TEST_NAMESPACE: namespace,
    PIUI_A23_CAPTURE_PATH: paths.capture,
    PIUI_A23_RESULT_PATH: paths.result,
    PIUI_A23_TRIGGER_PATH: paths.trigger,
    PIUI_A23_NATIVE_EVIDENCE_PATH: paths.nativeBoundary,
    PIUI_A23_RUN_NONCE: runNonce,
  };
}

function seatbeltPath(path) {
  return path.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
}

function seatbeltRegexPath(path) {
  if (typeof path !== 'string'
    || !path.startsWith('/')
    || resolve(path) !== path
    || /[\0\r\n"]/u.test(path)) fail();
  return path.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

const A23_ALLOWED_MACH_SERVICES = Object.freeze([
  'com.apple.CARenderServer',
  'com.apple.CoreDisplay.Notification',
  'com.apple.CoreDisplay.master',
  'com.apple.SecurityServer',
  'com.apple.appsleep',
  'com.apple.cfprefsd.agent',
  'com.apple.cfprefsd.daemon',
  'com.apple.dock.fullscreen',
  'com.apple.dock.server',
  'com.apple.fonts',
  'com.apple.lsd.mapdb',
  'com.apple.securityd.xpc',
  'com.apple.system.opendirectoryd.libinfo',
  'com.apple.window_proxies',
  'com.apple.windowserver.active',
]);
const A23_CREDENTIAL_BROKER_MACH_SERVICES = Object.freeze([
  'com.apple.SecurityServer',
  'com.apple.cfprefsd.agent',
  'com.apple.cfprefsd.daemon',
  'com.apple.securityd.xpc',
  'com.apple.system.opendirectoryd.libinfo',
]);

export function credentialKeychainPath() {
  const home = resolve(homedir());
  if (!home.startsWith('/Users/')
    || home.split('/').length !== 3
    || /[\0\r\n]/u.test(home)) fail();
  return resolve(home, 'Library/Keychains/login.keychain-db');
}

function assertCredentialKeychainBoundary() {
  const path = credentialKeychainPath();
  const item = lstatSync(path, { bigint: true });
  if (!item.isFile()
    || item.isSymbolicLink()
    || item.nlink !== 1n
    || item.uid !== BigInt(process.getuid())
    || (item.mode & 0o022n) !== 0n
    || item.size < 1n
    || item.size > 64n * 1_048_576n
    || realpathSync(path) !== path) fail();
  return path;
}

export function credentialCleanupSandbox(helperPath) {
  if (typeof helperPath !== 'string'
    || !helperPath.startsWith('/')
    || resolve(helperPath) !== helperPath
    || /[\0\r\n]/u.test(helperPath)) fail();
  const keychainPath = credentialKeychainPath();
  const keychainDirectory = dirname(keychainPath);
  const keychainDirectoryRegex = seatbeltRegexPath(keychainDirectory);
  const helper = seatbeltPath(helperPath);
  const ancestors = sandboxPathAncestors([helperPath])
    .map((path) => `  (allow file-read-metadata file-test-existence (literal "${seatbeltPath(path)}"))`)
    .join('\n');
  const keychainRules = sandboxPathAncestors([keychainPath])
    .map((path) => `      (literal "${seatbeltPath(path)}")`)
    .join('\n');
  const brokers = A23_CREDENTIAL_BROKER_MACH_SERVICES
    .map((name) => `      (global-name "${name}")`)
    .join('\n');
  return `(version 1)
  (deny default)
  (import "dyld-support.sb")
  (deny network*)
  (deny appleevent-send)
  (with-filter (process-path "/usr/bin/sandbox-exec")
    (allow process-exec (literal "${helper}")))
  (with-filter (process-path "${helper}")
    (allow sysctl-read
      (sysctl-name "hw.pagesize_compat")
      (sysctl-name "security.mac.sandbox.sentinel"))
    (allow mach-lookup
${brokers})
    (allow file-read-metadata file-test-existence
${keychainRules})
    (allow file-read* file-write* file-test-existence
      (literal "${seatbeltPath(keychainPath)}")
      (regex #"^${keychainDirectoryRegex}/\\.[A-Za-z0-9_]+$")
      (regex #"^${keychainDirectoryRegex}/login\\.keychain-db\\.sb-[-A-Za-z0-9_]+$")))
${ancestors}
  (allow file-read* file-test-existence file-map-executable
    (literal "${helper}")
    (subpath "/Library/Apple/System/Library")
    (subpath "/System/Library")
    (subpath "/usr/lib"))`;
}

const A23_ALLOWED_WEBKIT_SERVICES = Object.freeze([
  'com.apple.WebKit.GPU',
  'com.apple.WebKit.Networking',
  'com.apple.WebKit.WebContent',
  'com.apple.WebKit.WebContent.EnhancedSecurity',
]);

function sandboxPathAncestors(paths) {
  const ancestors = new Set(['/']);
  for (const candidate of paths) {
    for (let current = dirname(candidate);; current = dirname(current)) {
      ancestors.add(current);
      if (current === dirname(current)) break;
    }
  }
  return [...ancestors].sort();
}

export function credentialProbeSandbox(runtime, bundle, options = {}) {
  const optionKeys = isRecord(options) ? Reflect.ownKeys(options) : [];
  if (!isRecord(options)
    || optionKeys.some((key) => key !== 'allowCredentialBrokers')
    || (optionKeys.length === 1
      && typeof options.allowCredentialBrokers !== 'boolean')) fail();
  const allowCredentialBrokers = optionKeys.length === 0
    ? true
    : options.allowCredentialBrokers;
  const keychainPath = allowCredentialBrokers ? credentialKeychainPath() : undefined;
  const runtimeRoots = writableRuntimeRoots(runtime);
  const confinedPaths = [
    bundle.appPath,
    bundle.hostPath,
    bundle.nodePath,
    ...runtimeRoots,
  ];
  if (confinedPaths.some((path) => typeof path !== 'string' || !path.startsWith('/')
    || /[\0\r\n]/.test(path))) fail();
  const ancestors = sandboxPathAncestors(confinedPaths)
    .map((path) => `  (allow file-read-metadata file-test-existence (literal "${seatbeltPath(path)}"))`)
    .join('\n');
  const readableRuntime = runtimeRoots
    .map((path) => `  (allow file-read* file-test-existence (subpath "${seatbeltPath(path)}"))`)
    .join('\n');
  const writableRuntime = runtimeRoots
    .map((path) => `  (allow file-write* (subpath "${seatbeltPath(path)}"))`)
    .join('\n');
  const machServices = A23_ALLOWED_MACH_SERVICES
    .filter((name) => (
      allowCredentialBrokers || !A23_CREDENTIAL_BROKER_MACH_SERVICES.includes(name)
    ))
    .map((name) => `    (global-name "${name}")`)
    .join('\n');
  const webkitServices = A23_ALLOWED_WEBKIT_SERVICES
    .map((name) => `    (xpc-service-name "${name}")`)
    .join('\n');
  const credentialKeychainRules = keychainPath
    ? `\n    (allow file-read-metadata file-test-existence\n${sandboxPathAncestors([keychainPath])
      .map((path) => `      (literal "${seatbeltPath(path)}")`)
      .join('\n')})\n    (allow file-read* file-test-existence\n      (literal "${seatbeltPath(keychainPath)}"))`
    : '';
  return `(version 1)
  (deny default)
  (import "dyld-support.sb")
  (deny network*)
  (deny appleevent-send)
  (deny mach-lookup
    (global-name "com.apple.coreservices.appleevents")
    (global-name "com.apple.pasteboard.1")
    (global-name "com.apple.pbs.fetch_services")
    (local-name "com.apple.CFPasteboardClient"))
  (with-filter (process-path "/usr/bin/sandbox-exec")
    (allow process-exec (literal "${seatbeltPath(bundle.hostPath)}")))
  (with-filter (process-path "${seatbeltPath(bundle.hostPath)}")
    (allow process-fork)
    (allow process-exec (literal "${seatbeltPath(bundle.nodePath)}"))
    (allow signal (target self) (target children))
    (allow process-info* (target self) (target children))
    (allow mach-lookup
${machServices})
    (allow mach-lookup
${webkitServices})
${credentialKeychainRules}
    (allow generic-issue-extension
      (extension-class "com.apple.webkit.mach-bootstrap"))
    (allow iokit-issue-extension
      (extension-class "com.apple.webkit.extension.iokit"))
    (allow mach-issue-extension
      (extension-class "com.apple.webkit.extension.mach"))
    (allow iokit-open-service
      (iokit-registry-entry-class "IOAccelerator" "IOFramebuffer" "IOSurfaceRoot"))
    (allow iokit-get-properties
      (iokit-registry-entry-class "IOAccelerator" "IOFramebuffer" "IOSurfaceRoot"))
    (allow iokit-open-user-client
      (iokit-connection "IOAccelerator")
      (iokit-user-client-class
        "AGXDeviceUserClient"
        "IOAccelerationUserClient"
        "IOFramebufferSharedUserClient"
        "IOSurfaceAcceleratorClient"
        "IOSurfaceRootUserClient"
        "IOSurfaceSendRight")))
  (with-filter (process-path "${seatbeltPath(bundle.nodePath)}")
    (allow dynamic-code-generation)
    (allow signal (target self))
    (allow process-info* (target self)))
${ancestors}
  (allow file-read* file-test-existence file-map-executable
    (subpath "${seatbeltPath(bundle.appPath)}")
    (literal "${seatbeltPath(bundle.hostPath)}")
    (literal "${seatbeltPath(bundle.nodePath)}"))
${readableRuntime}
  (allow file-read* file-test-existence file-map-executable
    (subpath "/Library/Apple/System/Library/Frameworks")
    (subpath "/Library/Apple/System/Library/PrivateFrameworks")
    (subpath "/Library/Apple/usr/lib")
    (subpath "/Library/GPUBundles")
    (subpath "/System/Library/Frameworks")
    (subpath "/System/Library/PrivateFrameworks")
    (subpath "/System/Library/SubFrameworks")
    (subpath "/usr/lib"))
  (allow file-read* file-test-existence
    (subpath "/Library/Fonts")
    (subpath "/System/Library/CoreServices")
    (subpath "/System/Library/Fonts")
    (subpath "/private/var/db/CVMS")
    (subpath "/private/var/db/timezone")
    (subpath "/usr/share/zoneinfo")
    (literal "/System/Library/OpenSSL/openssl.cnf")
    (literal "/private/etc/localtime")
    (literal "/dev/null")
    (literal "/dev/random")
    (literal "/dev/urandom")
    (literal "/dev/zero"))
${writableRuntime}
  (allow file-link (subpath "${seatbeltPath(runtime.artefacts)}"))
  (allow file-write-data (literal "/dev/null") (literal "/dev/zero"))
  (allow sysctl-read)`;
}

async function runInputCommand(
  command,
  input,
  label,
  timeoutMs = 30_000,
  signal,
  args = [],
) {
  const result = await executeInputCommand(command, input, label, timeoutMs, signal, args);
  if (result.status !== 0 || result.signal !== null || result.forcedCleanup) fail();
  return result;
}

async function executeInputCommand(
  command,
  input,
  label,
  timeoutMs,
  signal,
  args,
) {
  return runOwnedCommand({
    command,
    args,
    cwd: '/',
    env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'en_AU.UTF-8' },
    input,
    timeoutMs,
    maxOutputBytes: MAX_SAFE_OUTPUT,
    label,
    signal,
  });
}

export function parseA23MaintenanceFailure(bytes) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 1
    || bytes.length > 96
    || bytes.at(-1) !== 0x0a
    || bytes.includes(0x00)
    || bytes.includes(0x0d)
    || bytes.subarray(0, -1).includes(0x0a)) return undefined;
  const match = bytes.toString('utf8').match(
    /^A23_MAINTENANCE_FAILURE=([a-z][a-z0-9-]{0,63})\n$/u,
  );
  return match && A23_MAINTENANCE_FAILURE_CODES.includes(match[1])
    ? match[1]
    : undefined;
}

export function parseA23NativeSheetFailure(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 4_096 || bytes.includes(0x00)) {
    return undefined;
  }
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
  const matches = A23_NATIVE_SHEET_FAILURE_CODES.filter((code) => (
    text.includes(`a23-${code}`)
  ));
  if (matches.length === 1) return matches[0];
  if (matches.length > 1) return undefined;
  const numericCodes = [...text.matchAll(/\((-?[0-9]{1,6})\)/gu)]
    .map((match) => Number(match[1]));
  const systemMatches = [...new Set(numericCodes
    .map((code) => A23_NATIVE_SHEET_SYSTEM_FAILURES.get(code))
    .filter((code) => code !== undefined))];
  return systemMatches.length === 1 ? systemMatches[0] : undefined;
}

export function classifyA23MaintenanceExecutionFailure(error, label) {
  if (typeof label !== 'string' || label.length < 1 || /[\0\r\n]/u.test(label)) {
    return 'unclassified';
  }
  const message = error instanceof Error ? error.message : undefined;
  const classifications = new Map([
    [`${label} exceeded its deadline`, 'deadline'],
    [`${label} left a recorded descendant survivor`, 'descendant-survivor'],
    [`${label} descendant identity observation failed`, 'identity-observation'],
    [`${label} exceeded its output bound`, 'output-bound'],
    [`${label} was cut off by its parent`, 'parent-cutoff'],
    [`${label} could not be started`, 'start'],
  ]);
  return classifications.get(message) ?? 'unclassified';
}

async function sha256File(path) {
  const bytes = await readFile(path);
  try {
    return createHash('sha256').update(bytes).digest('hex');
  } finally {
    bytes.fill(0);
  }
}

async function cleanKeychain(helper, namespace, signal, reportPhase) {
  if (reportPhase !== undefined && typeof reportPhase !== 'function') fail();
  reportPhase?.('helper-precheck-cleanup-boundary-before');
  assertCredentialKeychainBoundary();
  await assertPrivateExecutableLease(helper);
  const input = Buffer.from(`${namespace}\n`, 'utf8');
  try {
    await assertPrivateExecutableLease(helper);
    reportPhase?.('helper-precheck-cleanup-execution');
    const label = 'A.23 isolated Keychain cleanup';
    let result;
    try {
      result = await executeInputCommand(
        '/usr/bin/sandbox-exec',
        input,
        label,
        A23_MAINTENANCE_TIMEOUT_MS,
        signal,
        ['-p', credentialCleanupSandbox(helper.path), helper.path],
      );
    } catch (error) {
      const failureClass = classifyA23MaintenanceExecutionFailure(error, label);
      reportPhase?.(`helper-precheck-cleanup-execution-failure-${failureClass}`);
      throw error;
    }
    if (result.status !== 0 || result.signal !== null || result.forcedCleanup) {
      const failureCode = result.status === 1
        && result.signal === null
        && !result.forcedCleanup
        ? parseA23MaintenanceFailure(result.stderr)
        : undefined;
      reportPhase?.(failureCode === undefined
        ? 'helper-precheck-cleanup-failure-process'
        : `helper-precheck-cleanup-failure-${failureCode}`);
      fail();
    }
    reportPhase?.('helper-precheck-cleanup-output-validation');
    if (result.stderr.length !== 0) fail();
    parseCleanup(result.stdout);
    reportPhase?.('helper-precheck-cleanup-identity-after');
    await assertPrivateExecutableLease(helper);
    assertCredentialKeychainBoundary();
  } finally {
    input.fill(0);
  }
}

async function runAcceptedHostKeychainMode(
  bundle,
  namespace,
  mode,
  parseEvidence,
  label,
  signal,
  reportPhase,
  phasePrefix,
) {
  if (!/^a23-[0-9a-f]{32}$/u.test(namespace)
    || ![
      '--a23-cleanup',
      '--a23-inspect-cleanup-fixture',
      '--a23-seed-cleanup-fixture',
    ].includes(mode)
    || typeof parseEvidence !== 'function'
    || typeof label !== 'string'
    || label.length < 1
    || ((reportPhase === undefined) !== (phasePrefix === undefined))
    || (reportPhase !== undefined && typeof reportPhase !== 'function')
    || (phasePrefix !== undefined
      && !A23_ACCEPTED_HOST_MODE_PHASE_PREFIXES.includes(phasePrefix))) fail();
  reportPhase?.(`${phasePrefix}-boundary-before`);
  assertCredentialKeychainBoundary();
  await assertAcceptedBundleIdentity(bundle);
  const input = Buffer.from(`${namespace}\n`, 'utf8');
  try {
    reportPhase?.(`${phasePrefix}-execution`);
    let result;
    try {
      result = await executeInputCommand(
        '/usr/bin/sandbox-exec',
        input,
        label,
        A23_MAINTENANCE_TIMEOUT_MS,
        signal,
        [
          '-p',
          credentialCleanupSandbox(bundle.hostPath),
          bundle.hostPath,
          mode,
        ],
      );
    } catch (error) {
      const failureClass = classifyA23MaintenanceExecutionFailure(error, label);
      reportPhase?.(`${phasePrefix}-execution-failure-${failureClass}`);
      throw error;
    }
    if (result.status !== 0 || result.signal !== null || result.forcedCleanup) {
      const failureCode = result.status === 1
        && result.signal === null
        && !result.forcedCleanup
        ? parseA23MaintenanceFailure(result.stderr)
        : undefined;
      if (failureCode !== undefined) {
        reportPhase?.(`${phasePrefix}-failure-${failureCode}`);
      }
      fail();
    }
    reportPhase?.(`${phasePrefix}-output-validation`);
    if (result.stderr.length !== 0) fail();
    parseEvidence(result.stdout);
    reportPhase?.(`${phasePrefix}-identity-after`);
    await assertAcceptedBundleIdentity(bundle);
    assertCredentialKeychainBoundary();
  } finally {
    input.fill(0);
  }
}

async function cleanKeychainWithAcceptedHost(
  bundle,
  namespace,
  signal,
  reportPhase,
  phasePrefix,
) {
  await runAcceptedHostKeychainMode(
    bundle,
    namespace,
    '--a23-cleanup',
    parseCleanup,
    'A.23 same accepted-host Keychain cleanup',
    signal,
    reportPhase,
    phasePrefix,
  );
}

async function inspectAcceptedHostCleanupFixture(
  bundle,
  namespace,
  signal,
  reportPhase,
  phasePrefix,
) {
  await runAcceptedHostKeychainMode(
    bundle,
    namespace,
    '--a23-inspect-cleanup-fixture',
    parseCleanupFixtureInspection,
    'A.23 same accepted-host Keychain cleanup inspection',
    signal,
    reportPhase,
    phasePrefix,
  );
}

async function proveAcceptedHostCreatorCleanup(bundle, namespace, signal, outerReportPhase) {
  let currentProofPhase;
  const reportPhase = (phase) => {
    currentProofPhase = phase;
    outerReportPhase(phase);
  };
  const injectedFailure = new Error('A.23 injected post-creation cleanup proof');
  let primaryFailure;
  let primaryFailurePhase;
  let cleanupFailure;
  try {
    await runAcceptedHostKeychainMode(
      bundle,
      namespace,
      '--a23-seed-cleanup-fixture',
      parseCleanupFixtureSeed,
      'A.23 same accepted-host Keychain cleanup seed',
      signal,
      reportPhase,
      'accepted-host-creator-seed',
    );
    reportPhase('accepted-host-creator-injected-failure');
    throw injectedFailure;
  } catch (error) {
    primaryFailure = error;
    primaryFailurePhase = currentProofPhase;
  } finally {
    try {
      await cleanKeychainWithAcceptedHost(
        bundle,
        namespace,
        signal,
        reportPhase,
        'accepted-host-creator-cleanup',
      );
    } catch (error) {
      cleanupFailure = error;
    }
  }
  if (cleanupFailure) {
    throw primaryFailure === injectedFailure
      ? cleanupFailure
      : new AggregateError(
        [primaryFailure, cleanupFailure],
        'A.23 creator cleanup proof and cleanup failed',
      );
  }
  if (primaryFailure !== injectedFailure) {
    reportPhase(primaryFailurePhase);
    throw primaryFailure;
  }
  await inspectAcceptedHostCleanupFixture(
    bundle,
    namespace,
    signal,
    reportPhase,
    'accepted-host-creator-inspection',
  );
}

async function initialiseLedger(child, bundle, root, signal) {
  const ledger = new ProcessLedger({
    bundleRoot: bundle.appPath,
    isolateRoot: root,
    hostPath: bundle.hostPath,
    nodePath: bundle.nodePath,
  });
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (signal?.aborted) fail();
    try {
      await ledger.initialise(child.pid);
      return ledger;
    } catch {
      await sleep(20);
    }
  }
  fail();
}

async function assertAcceptedBundleIdentity(bundle) {
  if (typeof bundle?.fingerprint !== 'string' || !SHA256.test(bundle.fingerprint)
    || typeof bundle.hostPath !== 'string' || !bundle.hostIdentity
    || typeof bundle.hostIdentity.sha256 !== 'string'
    || !SHA256.test(bundle.hostIdentity.sha256)) fail();
  const host = await lstat(bundle.hostPath);
  if (!host.isFile() || host.isSymbolicLink() || host.nlink !== 1
    || host.dev !== bundle.hostIdentity.dev || host.ino !== bundle.hostIdentity.ino
    || host.size !== bundle.hostIdentity.bytes
    || await sha256File(bundle.hostPath) !== bundle.hostIdentity.sha256) fail();
}

export async function assertAcceptedCandidateProcess(
  ledger,
  candidatePid,
  bundle,
  expectedTopology,
) {
  if (!Object.values(A23_PROCESS_TOPOLOGY).includes(expectedTopology)) fail();
  assertCandidatePid(candidatePid);
  if (ledger.rootPid !== candidatePid) fail();
  await assertAcceptedBundleIdentity(bundle);
  const live = await ledger.sample();
  const hosts = live.filter((entry) => entry.executable === bundle.hostPath);
  const nodes = live.filter((entry) => entry.executable === bundle.nodePath);
  const expectedNodeCount = expectedTopology === A23_PROCESS_TOPOLOGY.HOST_AND_NODE ? 1 : 0;
  if (hosts.length !== 1
    || hosts[0]?.pid !== candidatePid
    || nodes.length !== expectedNodeCount
    || live.length !== 1 + expectedNodeCount) fail();
}

async function waitForResult(path, ledger, candidatePid, bundle, signal) {
  const deadline = Date.now() + 70_000;
  while (Date.now() < deadline) {
    if (signal?.aborted) fail();
    await assertAcceptedCandidateProcess(
      ledger,
      candidatePid,
      bundle,
      A23_PROCESS_TOPOLOGY.HOST_AND_NODE,
    );
    const result = await readPublishedLifecycleResult(path);
    if (result) return result;
    await sleep(100);
  }
  fail();
}

export async function terminateUnledgeredRoot(child) {
  if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
  // This path exists only before the pre-click ledger is initialised, when the
  // feature route cannot yet have started its sidecar. The ChildProcess handle
  // remains bound to the unreaped exact child, so its PID cannot have been
  // recycled while exitCode and signalCode are both null.
  const exited = new Promise((resolveExit, rejectExit) => {
    child.once('exit', resolveExit);
    child.once('error', rejectExit);
  });
  child.kill('SIGTERM');
  await Promise.race([exited, sleep(2_000)]);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill('SIGKILL');
    await Promise.race([exited, sleep(2_000)]);
  }
  if (child.exitCode === null && child.signalCode === null) fail();
}

export async function readPublishedLifecycleResult(path) {
  try {
    const bytes = await readStablePrivateFile(path, 512);
    try {
      return parseLifecycleResult(bytes);
    } finally {
      bytes.fill(0);
    }
  } catch (error) {
    if (error?.code === 'ENOENT' || error?.code === PUBLICATION_PENDING_CODE) return undefined;
    throw error;
  }
}

function isOwnerPrivateRegularFile(item, maximumBytes, expectedLinks) {
  return item.isFile()
    && item.uid === process.getuid()
    && [0o400, 0o600].includes(item.mode & 0o777)
    && item.size <= maximumBytes
    && item.nlink === expectedLinks;
}

export async function readStablePrivateFile(path, maximumBytes) {
  let handle;
  const bytes = Buffer.alloc(maximumBytes + 1);
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    if (isOwnerPrivateRegularFile(before, maximumBytes, 2)) {
      const pending = new Error('A.23 lifecycle publication pending');
      pending.code = PUBLICATION_PENDING_CODE;
      throw pending;
    }
    if (!isOwnerPrivateRegularFile(before, maximumBytes, 1)) fail();
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    const after = await handle.stat();
    const pathAfter = await lstat(path);
    if (!isOwnerPrivateRegularFile(after, maximumBytes, 1)
      || after.dev !== before.dev || after.ino !== before.ino
      || after.size !== before.size || after.mtimeMs !== before.mtimeMs
      || after.ctimeMs !== before.ctimeMs || after.mode !== before.mode
      || after.uid !== before.uid || bytesRead !== before.size
      || pathAfter.isSymbolicLink()
      || !isOwnerPrivateRegularFile(pathAfter, maximumBytes, 1)
      || pathAfter.dev !== after.dev || pathAfter.ino !== after.ino
      || pathAfter.size !== after.size || pathAfter.mtimeMs !== after.mtimeMs
      || pathAfter.ctimeMs !== after.ctimeMs || pathAfter.mode !== after.mode
      || pathAfter.uid !== after.uid) fail();
    return Buffer.from(bytes.subarray(0, bytesRead));
  } finally {
    bytes.fill(0);
    await handle?.close();
  }
}

export async function waitForFinalAccessibilityState({ capture, assertIdentity, pause = sleep }) {
  if (typeof capture !== 'function' || typeof assertIdentity !== 'function'
    || typeof pause !== 'function') fail();
  for (let attempt = 0; attempt < 20; attempt += 1) {
    await assertIdentity();
    const bytes = await capture();
    if (!Buffer.isBuffer(bytes)) fail();
    const parsed = parseAccessibilityControlState(bytes);
    if (parsed.state === 'final') {
      await assertIdentity();
      return bytes;
    }
    bytes.fill(0);
    await pause(100);
  }
  fail();
}

async function writeSafeAccessibilityCapture(artefactRoot, candidatePid, ledger, bundle, signal) {
  const assertIdentity = () => assertAcceptedCandidateProcess(
    ledger,
    candidatePid,
    bundle,
    A23_PROCESS_TOPOLOGY.HOST_AND_NODE,
  );
  const bytes = await waitForFinalAccessibilityState({
    assertIdentity,
    capture: async () => {
      const script = Buffer.from(accessibilityControlStateScript(candidatePid), 'utf8');
      try {
        const result = await runInputCommand(
          '/usr/bin/osascript',
          script,
          'A.23 WebView accessibility capture',
          3_000,
          signal,
        );
        if (result.stderr.length !== 0) fail();
        return result.stdout;
      } finally {
        script.fill(0);
      }
    },
  });
  try {
    writeFileSync(resolve(artefactRoot, 'accessibility-controls.txt'), bytes, {
      flag: 'wx',
      mode: 0o600,
    });
  } finally {
    bytes.fill(0);
  }
}

async function removeWorkspace(path) {
  const canonical = await realpath(path);
  const temporary = await realpath(tmpdir());
  const rel = relative(temporary, canonical);
  const item = await lstat(canonical);
  if (!/^piui-a23-runtime-[A-Za-z0-9]+$/.test(rel)
    || rel.includes(sep) || !item.isDirectory() || item.isSymbolicLink()
    || item.uid !== process.getuid() || (item.mode & 0o077) !== 0) fail();
  await rm(canonical, { recursive: true, force: true, maxRetries: 4, retryDelay: 50 });
  try {
    await lstat(canonical);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  fail();
}

export async function captureCredentialCleanupHarness(sourceRoot, controlRoot) {
  const sourcePath = resolve(
    sourceRoot,
    'src-tauri/target/aarch64-apple-darwin/release/credential-cleanup-harness',
  );
  return capturePrivateExecutable({
    controlRoot,
    executableName: 'credential-cleanup-harness',
    sourcePath,
  });
}

function runtimeCanaryBuffer() {
  const random = randomBytes(24);
  const alphabet = Buffer.from('0123456789abcdef', 'ascii');
  const prefix = Buffer.from('PIUI_A23_', 'ascii');
  let canary;
  try {
    canary = Buffer.alloc(prefix.length + random.length * 2);
    prefix.copy(canary);
    for (let index = 0; index < random.length; index += 1) {
      canary[prefix.length + index * 2] = alphabet[random[index] >> 4];
      canary[prefix.length + index * 2 + 1] = alphabet[random[index] & 0x0f];
    }
    return canary;
  } catch (error) {
    canary?.fill(0);
    throw error;
  } finally {
    random.fill(0);
    alphabet.fill(0);
    prefix.fill(0);
  }
}

export async function executeAuthoritativeCredentialProbe(
  bundle,
  helper,
  { cleanupHelperIdentity, onPhase, signal } = {},
) {
  if (onPhase !== undefined && typeof onPhase !== 'function') fail();
  let currentPhase;
  let failurePhase;
  const reportPhase = (phase) => {
    if (!A23_PROBE_PHASE_SET.has(phase)) fail();
    currentPhase = phase;
    onPhase?.(phase);
  };
  reportPhase('boundary-validation');
  assertCredentialKeychainBoundary();
  await assertAcceptedBundleIdentity(bundle);
  await assertPrivateExecutableLease(helper);
  const cleanupHelper = assertA23CleanupHelperIdentity(cleanupHelperIdentity, helper);

  reportPhase('workspace-preparation');
  const root = await privateWorkspace();
  let namespace;
  let runNonce;
  let canary;
  let runtime;
  let artefactRoot;
  let paths;
  let child;
  let ledger;
  let failure;
  let lifecycle;
  let scanner;
  let credentialInputDescriptorClosed = false;
  let keychainCleaned = false;
  let candidateTerminationProven = true;
  let acceptedHostCreatorCleanupProved = false;
  try {
    namespace = `a23-${randomBytes(16).toString('hex')}`;
    runNonce = randomBytes(16).toString('hex');
    canary = runtimeCanaryBuffer();
    runtime = createRuntimeDirectories(root);
    artefactRoot = runtime.artefacts;
    paths = Object.freeze({
      capture: resolve(artefactRoot, 'private-channel.raw'),
      result: resolve(artefactRoot, 'lifecycle-result.json'),
      trigger: resolve(artefactRoot, 'credential-saved.trigger'),
      nativeBoundary: resolve(artefactRoot, 'native-boundary.jsonl'),
      stdout: resolve(artefactRoot, 'app.stdout.log'),
      stderr: resolve(artefactRoot, 'app.stderr.log'),
    });
    reportPhase('helper-precheck-cleanup');
    await cleanKeychain(helper, namespace, signal, reportPhase);
    reportPhase('accepted-host-creator-cleanup-proof');
    await proveAcceptedHostCreatorCleanup(bundle, namespace, signal, reportPhase);
    acceptedHostCreatorCleanupProved = true;
    reportPhase('candidate-launch');
    const stdout = openSync(
      paths.stdout,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
      0o600,
    );
    try {
      const stderr = openSync(
        paths.stderr,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
        0o600,
      );
      try {
        assertCredentialKeychainBoundary();
        child = spawn('/usr/bin/sandbox-exec', [
          '-p',
          credentialProbeSandbox(runtime, bundle),
          bundle.hostPath,
        ], {
          cwd: runtime.working,
          env: runtimeEnvironment(runtime, paths, namespace, runNonce),
          detached: true,
          stdio: ['ignore', stdout, stderr, 'ignore', 'ignore', 'ignore', 'pipe'],
        });
        candidateTerminationProven = false;
        await waitForChildSpawn(child);
        const credentialInput = child.stdio[6];
        if (!credentialInput || typeof credentialInput.end !== 'function') fail();
        const inheritedCanary = Buffer.from(canary);
        try {
          await new Promise((resolveWrite, rejectWrite) => {
            credentialInput.once('error', rejectWrite);
            credentialInput.end(inheritedCanary, resolveWrite);
          });
          credentialInputDescriptorClosed = true;
        } finally {
          inheritedCanary.fill(0);
        }
      } finally {
        closeSync(stderr);
      }
    } finally {
      closeSync(stdout);
    }
    reportPhase('candidate-ledger');
    ledger = await initialiseLedger(child, bundle, root, signal);
    const candidatePid = child.pid;
    await assertAcceptedCandidateProcess(
      ledger,
      candidatePid,
      bundle,
      A23_PROCESS_TOPOLOGY.HOST_ONLY,
    );

    reportPhase('native-sheet-automation');
    const script = Buffer.from(nativeSheetScript(candidatePid), 'utf8');
    try {
      const label = 'A.23 native credential sheet automation';
      let automation;
      try {
        automation = await executeInputCommand(
          '/usr/bin/osascript',
          script,
          label,
          A23_NATIVE_SHEET_TIMEOUT_MS,
          signal,
          [],
        );
      } catch (error) {
        const failureClass = classifyA23MaintenanceExecutionFailure(error, label);
        reportPhase(`native-sheet-automation-execution-failure-${failureClass}`);
        throw error;
      }
      if (automation.status !== 0 || automation.signal !== null || automation.forcedCleanup) {
        const failureCode = automation.status !== 0
          && automation.signal === null
          && !automation.forcedCleanup
          ? parseA23NativeSheetFailure(automation.stderr)
          : undefined;
        reportPhase(failureCode === undefined
          ? 'native-sheet-automation-failure-process'
          : `native-sheet-automation-failure-${failureCode}`);
        fail();
      }
      reportPhase('native-sheet-automation-output-validation');
      if (automation.stderr.length !== 0
        || automation.stdout.toString('utf8').trim() !== 'native-sheet-saved') fail();
      reportPhase('native-sheet-automation-identity-after');
      await assertAcceptedCandidateProcess(
        ledger,
        candidatePid,
        bundle,
        A23_PROCESS_TOPOLOGY.HOST_AND_NODE,
      );
    } finally {
      script.fill(0);
    }

    reportPhase('lifecycle-result');
    lifecycle = await waitForResult(paths.result, ledger, candidatePid, bundle, signal);
    reportPhase('accessibility-capture');
    await writeSafeAccessibilityCapture(artefactRoot, candidatePid, ledger, bundle, signal);
    reportPhase('candidate-termination');
    const cleanup = await ledger.terminate();
    ledger = undefined;
    child = undefined;
    candidateTerminationProven = true;
    if (cleanup.forced) fail();
    await chmod(paths.capture, 0o400);
    await chmod(paths.nativeBoundary, 0o400);
    reportPhase('transcript-validation');
    const transcriptBytes = await readStablePrivateFile(paths.capture, MAX_RAW_CAPTURE_BYTES);
    try {
      parsePrivateChannelTranscript(transcriptBytes, canary);
    } finally {
      transcriptBytes.fill(0);
    }
    reportPhase('native-boundary-validation');
    const nativeBoundaryBytes = await readStablePrivateFile(
      paths.nativeBoundary,
      MAX_NATIVE_EVIDENCE_BYTES,
    );
    try {
      parseNativeBoundaryEvidence(
        nativeBoundaryBytes,
        runNonce,
        candidatePid,
        bundle.hostIdentity,
        canary,
      );
    } finally {
      nativeBoundaryBytes.fill(0);
    }

    reportPhase('accepted-host-final-cleanup');
    await cleanKeychainWithAcceptedHost(
      bundle,
      namespace,
      signal,
      reportPhase,
      'accepted-host-final-cleanup',
    );
    await inspectAcceptedHostCleanupFixture(
      bundle,
      namespace,
      signal,
      reportPhase,
      'accepted-host-final-inspection',
    );
    keychainCleaned = true;
    reportPhase('canary-scan');
    scanner = await scanSecretCanary({
      workspace: root,
      roots: writableRuntimeRoots(runtime),
      authorised: [{ path: paths.capture, count: PRIVATE_CHANNEL_OCCURRENCES }],
      canary,
    });
    if (scanner.authorisedFiles !== 1
      || scanner.authorisedOccurrences !== PRIVATE_CHANNEL_OCCURRENCES
      || scanner.unauthorisedOccurrences !== 0) fail();
    assertCredentialKeychainBoundary();
  } catch (error) {
    failure = error;
    failurePhase = currentPhase;
  } finally {
    const cleanupErrors = [];
    let cleanupFailurePhase;
    const recordCleanupFailure = (phase, error) => {
      cleanupFailurePhase ??= phase;
      cleanupErrors.push(error);
    };
    if (ledger) {
      try {
        await ledger.terminate();
        ledger = undefined;
        child = undefined;
        candidateTerminationProven = true;
      } catch (error) {
        recordCleanupFailure('cleanup-candidate-termination', error);
        try {
          await terminateUnledgeredRoot(child);
          child = undefined;
        } catch (rootError) {
          recordCleanupFailure('cleanup-candidate-termination', rootError);
        }
        try {
          await ledger.terminate();
          ledger = undefined;
          child = undefined;
          candidateTerminationProven = true;
        } catch (retryError) {
          recordCleanupFailure('cleanup-candidate-termination', retryError);
        }
      }
    }
    if (!ledger && child?.pid) {
      try {
        await terminateUnledgeredRoot(child);
        child = undefined;
        candidateTerminationProven = true;
      } catch (error) {
        recordCleanupFailure('cleanup-candidate-termination', error);
      }
    }
    if (namespace && !keychainCleaned) {
      if (!candidateTerminationProven) {
        recordCleanupFailure(
          'cleanup-candidate-termination',
          new Error('A.23 candidate termination was not proven before cleanup'),
        );
      } else {
        try {
          await cleanKeychainWithAcceptedHost(bundle, namespace);
          await inspectAcceptedHostCleanupFixture(bundle, namespace);
          keychainCleaned = true;
        } catch (error) {
          recordCleanupFailure('cleanup-keychain', error);
        }
      }
    }
    canary?.fill(0);
    try {
      await removeWorkspace(root);
    } catch (error) {
      recordCleanupFailure('cleanup-workspace', error);
    }
    if (cleanupErrors.length) {
      const primaryFailure = failure;
      const cleanupFailure = new AggregateError(cleanupErrors, 'A.23 cleanup failed');
      failure = failure
        ? new AggregateError([failure, cleanupFailure], 'A.23 probe and cleanup failed')
        : cleanupFailure;
      reportPhase(primaryFailure && failurePhase
        ? failurePhase
        : cleanupFailurePhase ?? 'cleanup');
    } else if (failure && failurePhase) {
      reportPhase(failurePhase);
    }
  }
  if (failure) throw failure;
  reportPhase('evidence-finalisation');
  if (!lifecycle
    || !scanner
    || !credentialInputDescriptorClosed
    || !keychainCleaned
    || !candidateTerminationProven
    || !acceptedHostCreatorCleanupProved) {
    throw new Error('A.23 packaged credential probe rejected');
  }
  return assertSafeCredentialEvidence({
    schemaVersion: 1,
    status: 'pass',
    bundleFingerprint: bundle.fingerprint,
    credentialCleanupHelper: cleanupHelper,
    execution: 'genuine-packaged-app',
    namespaceIsolation: 'isolated-test-keychain',
    nativeSheet: 'appkit-accessibility-driven',
    keychain: 'stored-refreshed-deleted',
    lifecycle: Object.freeze({
      initialGet: lifecycle.initialGet,
      refreshReads: lifecycle.refreshReads,
      refreshWrites: lifecycle.refreshWrites,
      postRefreshGet: lifecycle.postRefreshGet,
      logoutDelete: lifecycle.logoutDelete,
      postDeleteMiss: lifecycle.postDeleteMiss,
    }),
    privateChannel: Object.freeze({
      authorisedFiles: scanner.authorisedFiles,
      authorisedOccurrences: scanner.authorisedOccurrences,
      unauthorisedOccurrences: scanner.unauthorisedOccurrences,
      quiescedBeforeScan: lifecycle.privateChannelQuiesced,
      rawFrames: 12,
    }),
    publicSurfaces: Object.freeze({
      accessibilityControls: 'runner-owned-after-quiescence-scanned',
      nativeInvokeBoundary: 'all-entries-and-expected-results-scanned',
      rustEventBoundary: 'piui-stream-probe-native-admission-and-trusted-webview-self-attested-delivery-host-scanned',
      webViewInspectionAuthority: 'trusted-webview-self-serialised-self-attested-not-independent-live-browser-inspection',
      documentDom: 'bounded-document-light-dom-native-boundary-host-scanned',
      childBrowsingContexts: 'trusted-webview-self-attested-zero-iframe-and-frame-elements',
      shadowRoots: 'trusted-webview-self-attested-zero-observable-open-closed-not-observable-not-claimed',
      webStorage: 'bounded-local-and-session-native-boundary-host-scanned',
      arbitraryJavascriptHeap: 'not-enumerable-not-claimed',
      logsAndCrashArtefacts: 'isolated-runtime-and-owned-stdio-only',
      ordinaryAppData: 'isolated-runtime-only',
    }),
    cleanup: Object.freeze({
      credentialInputDescriptorClosed,
      helperExecutionResidual: 'private-precheck-and-same-accepted-host-creator-cleanup-keychain-sandboxed',
      keychainEntriesRemoved: keychainCleaned,
      keychainIndexRemoved: keychainCleaned,
      ownedProcessesRemoved: true,
      privateCapturesRemoved: true,
      runnerIsolateRemoved: true,
    }),
  }, false, bundle.fingerprint, cleanupHelper);
}
