import { randomBytes, randomInt } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import {
  closeSync,
  constants,
  openSync,
} from 'node:fs';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  realpath,
  rm,
} from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import {
  dirname,
  resolve,
} from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { revalidateBundle } from '../tests/packaged/bundle-inspection.mjs';
import {
  ProcessLedger,
  installParentCutoffs,
  runOwnedCommand,
  terminateRecordedProcessGroupsWithoutObservation,
  waitForChildSpawn,
} from './a21-gate-support.mjs';
import {
  APPLE_TOOLCHAIN_PATHS,
  appleToolchainBuildEnvironment,
  captureAppleToolchainAuthority,
  releaseAppleToolchainAuthority,
  revalidateAppleToolchainAuthority,
} from './apple-toolchain-trust.mjs';
import {
  assertPrivateExecutableLease,
  capturePrivateExecutable,
  releasePrivateExecutableLeaseForRemoval,
} from './private-executable-lease.mjs';
import { credentialProbeSandbox } from './run-packaged-credential-probe.mjs';
import {
  A27_EXPECTED_EVIDENCE,
  A27_NATIVE_EVIDENCE_KEYS,
  LifecycleObservation,
  assertHostOwnsLockDescriptor,
  assertLifecycleNetworkBoundaryFromListing,
  assertOwnershipLockContended,
  assertOwnershipLockReleased,
  closeLifecycleOwnershipDescriptor,
  openLifecycleOwnershipDescriptor,
  readNativeLifecycleWitness,
  waitForOwnedProcessesToExit,
} from './assert-process-cleanup.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ACTIVATION_MODE = 'a27-lifecycle';
const ACTIVATION_PORT_MIN = 49_152;
const ACTIVATION_PORT_MAX = 65_535;
const SHA256 = /^[0-9a-f]{64}$/u;
const SESSION_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ELEMENT_KEY = 'element-6066-11e4-a52e-4f735466cecf';
const MAX_EVIDENCE_BYTES = 65_536;
const MAX_HTTP_BYTES = 262_144;
const REJECTED = 'A.27 packaged lifecycle probe rejected';
const FORCED_CLEANUP_COMPLETE = 'Packaged runtime required forced cleanup';

function seatbeltPath(path) {
  return path.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
}

function sandboxPathAncestors(paths) {
  const ancestors = new Set(['/']);
  for (const path of paths) {
    for (let current = dirname(path);; current = dirname(current)) {
      ancestors.add(current);
      if (current === dirname(current)) break;
    }
  }
  return [...ancestors].sort(
    (left, right) => Buffer.from(left).compare(Buffer.from(right)),
  );
}

export function a27RuntimeSandbox({ activation, bundle, isolate }) {
  if (!isRecord(activation)
    || !Number.isSafeInteger(activation.port)
    || activation.port < ACTIVATION_PORT_MIN
    || activation.port > ACTIVATION_PORT_MAX) fail();
  const profile = credentialProbeSandbox({
    artefacts: resolve(isolate, 'agent'),
    cache: resolve(isolate, 'cache'),
    config: resolve(isolate, 'config'),
    data: resolve(isolate, 'data'),
    home: resolve(isolate, 'home'),
    temporary: resolve(isolate, 'tmp'),
    working: isolate,
  }, bundle, { allowCredentialBrokers: false });
  const controlRoot = seatbeltPath(resolve(isolate, 'control'));
  return `${profile}
  (deny file-read* file-test-existence file-map-executable (subpath "${controlRoot}"))
  (deny file-write* (subpath "${controlRoot}"))
  (deny process-exec (subpath "${controlRoot}"))
  (deny file-write* (subpath "${seatbeltPath(bundle.appPath)}"))
  (allow network-inbound (local tcp "localhost:${activation.port}"))
  (allow network-outbound (remote tcp "localhost:${activation.port}"))`;
}

export function a27ReopenHelperSandbox(helperPath) {
  if (typeof helperPath !== 'string'
    || !helperPath.startsWith('/')
    || resolve(helperPath) !== helperPath
    || /[\0\r\n]/u.test(helperPath)) fail();
  const helper = seatbeltPath(helperPath);
  const ancestors = sandboxPathAncestors([helperPath])
    .map((path) => `  (allow file-read-metadata file-test-existence (literal "${seatbeltPath(path)}"))`)
    .join('\n');
  return `(version 1)
  (deny default)
  (import "dyld-support.sb")
  (deny network*)
  (with-filter (process-path "/usr/bin/sandbox-exec")
    (allow process-exec (literal "${helper}")))
  (with-filter (process-path "${helper}")
    (allow appleevent-send)
    (allow mach-lookup
      (global-name "com.apple.coreservices.appleevents")
      (global-name "com.apple.coreservices.launchservicesd")
      (global-name "com.apple.lsd.mapdb")
      (global-name "com.apple.tccd")
      (global-name "com.apple.tccd.system")))
${ancestors}
  (allow file-read* file-test-existence file-map-executable
    (literal "${helper}")
    (subpath "/Library/Apple/System/Library")
    (subpath "/System/Library")
    (subpath "/usr/lib"))`;
}

const CORE_PRE_CLEANUP_KEYS = Object.freeze(
  Object.keys(A27_EXPECTED_EVIDENCE)
    .filter((key) => key !== 'generatedOutputsRemoved'),
);
const EXTERNAL_PRE_CLEANUP_KEYS = Object.freeze(
  CORE_PRE_CLEANUP_KEYS.filter((key) => !A27_NATIVE_EVIDENCE_KEYS.includes(key)),
);
export const A27_IDENTITY_EVIDENCE_KEYS = Object.freeze([
  'automationFingerprint',
  'controlledDeltaSha256',
  'productionFingerprint',
  'sameFrozenSource',
  'sourceDigest',
]);
const PRE_CLEANUP_KEYS = Object.freeze([
  ...CORE_PRE_CLEANUP_KEYS,
  'identity',
]);
const PACKAGED_EVIDENCE_KEYS = Object.freeze([
  ...Object.keys(A27_EXPECTED_EVIDENCE),
  'identity',
]);
const LIFECYCLE_SNAPSHOT_KEYS = Object.freeze([
  'busy',
  'buttonDisabled',
  'buttonLabel',
  'message',
  'phase',
  'progressVisible',
  'schemaVersion',
]);
const LIFECYCLE_PHASES = Object.freeze(new Set([
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
]));
const BUSY_PHASE_BY_BUTTON_LABEL = Object.freeze({
  'Start lifecycle verification': 'starting',
  'Verify crash recovery': 'preparing-approval',
  'Verify explicit restart': 'restarting',
  'Close and verify reopen': 'awaiting-close',
  'Quit and verify cleanup': 'quitting',
});
const WAIT_PHASES_BY_TARGET = Object.freeze({
  ready: Object.freeze(new Set(['starting'])),
  running: Object.freeze(new Set(['starting'])),
  recovered: Object.freeze(new Set([
    'preparing-approval',
    'approval-waiting',
    'forcing-sidecar-death',
    'recovering',
  ])),
  'awaiting-close': Object.freeze(new Set(['restarting'])),
  'ready-to-quit': Object.freeze(new Set(['starting', 'awaiting-reopen', 'resuming'])),
});
export const A27_REOPEN_HELPER_SOURCE = String.raw`
#include <ApplicationServices/ApplicationServices.h>
#include <Carbon/Carbon.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/types.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    return 64;
  }
  errno = 0;
  char *end = NULL;
  const long parsed = strtol(argv[1], &end, 10);
  if (errno != 0 || end == argv[1] || *end != '\0' || parsed < 2 || parsed > INT_MAX) {
    return 64;
  }

  ProcessSerialNumber process = { 0, 0 };
  OSStatus status = GetProcessForPID((pid_t)parsed, &process);
  if (status != noErr) {
    return 65;
  }

  AEAddressDesc target = { typeNull, NULL };
  AppleEvent event = { typeNull, NULL };
  status = AECreateDesc(typeProcessSerialNumber, &process, sizeof(process), &target);
  if (status == noErr) {
    status = AECreateAppleEvent(
      kCoreEventClass,
      kAEReopenApplication,
      &target,
      kAutoGenerateReturnID,
      kAnyTransactionID,
      &event
    );
  }
  if (status == noErr) {
    status = AESendMessage(
      &event,
      NULL,
      kAENoReply | kAENeverInteract,
      kAEDefaultTimeout
    );
  }
  if (event.descriptorType != typeNull) {
    AEDisposeDesc(&event);
  }
  if (target.descriptorType != typeNull) {
    AEDisposeDesc(&target);
  }
  return status == noErr ? 0 : 66;
}
`;

function fail() {
  throw new Error(REJECTED);
}

export class A27ForcedCleanupCompleteError extends Error {
  constructor(cause) {
    super('A.27 forced process cleanup completed with verified empty identity observation', {
      cause,
    });
    this.name = 'A27ForcedCleanupCompleteError';
    this.code = 'PIUI_A27_FORCED_CLEANUP_COMPLETE';
  }
}

export class A27RuntimeProcessLedger extends ProcessLedger {
  async terminate() {
    try {
      return await super.terminate();
    } catch (error) {
      if (!(error instanceof Error) || error.message !== FORCED_CLEANUP_COMPLETE) {
        throw error;
      }
      const live = await this.sample();
      if (!Array.isArray(live) || live.length !== 0) throw error;
      throw new A27ForcedCleanupCompleteError(error);
    }
  }
}

async function confirmA27LedgerAbsence(ledger) {
  try {
    const cleanup = await ledger.terminate();
    if (!isRecord(cleanup) || typeof cleanup.forced !== 'boolean') fail();
    return Object.freeze({ forced: cleanup.forced });
  } catch (error) {
    if (error instanceof A27ForcedCleanupCompleteError) {
      return Object.freeze({ completion: error, forced: true });
    }
    if (error?.code === 'PIUI_PROCESS_GROUP_IDENTITY_AMBIGUOUS') throw error;
    let live;
    try {
      live = await ledger.sample();
    } catch (verificationError) {
      throw new AggregateError(
        [error, verificationError],
        'A.27 ledger cleanup and empty-identity verification failed',
      );
    }
    if (!Array.isArray(live) || live.length !== 0) throw error;
    return Object.freeze({ cleanupFailure: error, forced: false, verifiedEmpty: true });
  }
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, expected) {
  if (!isRecord(value)
    || !isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort())) fail();
}

function exactSha(value) {
  if (typeof value !== 'string' || !SHA256.test(value)) fail();
}

function parseOneLine(bytes) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 3
    || bytes.length > MAX_EVIDENCE_BYTES
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
    || bytes.includes(0x00)) fail();
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, -1));
  } catch {
    fail();
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail();
  }
  return value;
}

function validPid(value) {
  return Number.isSafeInteger(value) && value > 1;
}

function expectedValueSubset(keys) {
  return Object.freeze(Object.fromEntries(
    keys.map((key) => [key, A27_EXPECTED_EVIDENCE[key]]),
  ));
}

function assertExpectedSubset(value, keys) {
  exactKeys(value, keys);
  for (const key of keys) {
    const expected = A27_EXPECTED_EVIDENCE[key];
    if (typeof value[key] !== typeof expected || value[key] !== expected) fail();
    if (typeof value[key] === 'number'
      && (!Number.isSafeInteger(value[key]) || value[key] < 0)) fail();
  }
}

export function assertA27IdentityEvidence(value) {
  exactKeys(value, A27_IDENTITY_EVIDENCE_KEYS);
  exactSha(value.sourceDigest);
  exactSha(value.productionFingerprint);
  exactSha(value.automationFingerprint);
  exactSha(value.controlledDeltaSha256);
  if (value.sameFrozenSource !== true
    || value.productionFingerprint === value.automationFingerprint) fail();
  return Object.freeze({ ...value });
}

export function assertPreCleanupLifecycleEvidence(value) {
  exactKeys(value, PRE_CLEANUP_KEYS);
  const core = Object.fromEntries(
    CORE_PRE_CLEANUP_KEYS.map((key) => [key, value[key]]),
  );
  assertExpectedSubset(core, CORE_PRE_CLEANUP_KEYS);
  return Object.freeze({
    ...core,
    identity: assertA27IdentityEvidence(value.identity),
  });
}

export function parsePackagedLifecycleEvidence(bytes) {
  const value = parseOneLine(bytes);
  exactKeys(value, PACKAGED_EVIDENCE_KEYS);
  const core = Object.fromEntries(
    Object.keys(A27_EXPECTED_EVIDENCE).map((key) => [key, value[key]]),
  );
  assertExpectedSubset(core, Object.keys(A27_EXPECTED_EVIDENCE));
  return Object.freeze({
    ...core,
    identity: assertA27IdentityEvidence(value.identity),
  });
}

export function finaliseLifecycleEvidence(preCleanupEvidence) {
  const accepted = assertPreCleanupLifecycleEvidence(preCleanupEvidence);
  return parsePackagedLifecycleEvidence(Buffer.from(`${JSON.stringify({
    ...accepted,
    generatedOutputsRemoved: true,
  })}\n`, 'utf8'));
}

export function validateA27ActivationEnvironment(environment) {
  exactKeys(environment, [
    'PIUI_ARCHITECTURE_TEST_MODE',
    'PIUI_ARCHITECTURE_TEST_NONCE',
    'PIUI_ARCHITECTURE_TEST_PORT',
  ]);
  if (environment.PIUI_ARCHITECTURE_TEST_MODE !== ACTIVATION_MODE
    || typeof environment.PIUI_ARCHITECTURE_TEST_NONCE !== 'string'
    || !SHA256.test(environment.PIUI_ARCHITECTURE_TEST_NONCE)
    || typeof environment.PIUI_ARCHITECTURE_TEST_PORT !== 'string'
    || !/^[0-9]{5}$/u.test(environment.PIUI_ARCHITECTURE_TEST_PORT)) fail();
  const port = Number(environment.PIUI_ARCHITECTURE_TEST_PORT);
  if (!Number.isSafeInteger(port)
    || port < ACTIVATION_PORT_MIN
    || port > ACTIVATION_PORT_MAX
    || String(port) !== environment.PIUI_ARCHITECTURE_TEST_PORT) fail();
  return Object.freeze({
    mode: ACTIVATION_MODE,
    nonce: environment.PIUI_ARCHITECTURE_TEST_NONCE,
    port,
  });
}

function inspectNetworkListing(pid) {
  if (!validPid(pid)) fail();
  const result = spawnSync(
    '/usr/sbin/lsof',
    ['-nP', '-a', '-p', String(pid), '-i', '-Ts', '-FpfPnT'],
    {
      encoding: 'utf8',
      env: { PATH: '/usr/bin:/bin' },
      timeout: 5_000,
    },
  );
  if (result.error || result.signal || ![0, 1].includes(result.status)
    || typeof result.stdout !== 'string' || result.stderr !== '') fail();
  return result.stdout;
}

/**
 * The host can legitimately have no socket during its first startup samples.
 * Once the feature-only driver appears, every later live-host sample is
 * checked against the exact loopback listener/accepted-connection policy.
 * Sidecars are always required to have an empty network listing.
 */
export function createA27LifecycleNetworkPolicy({
  driverPort,
  hostPid,
  listingForPid = inspectNetworkListing,
}) {
  if (!validPid(hostPid)
    || !Number.isSafeInteger(driverPort)
    || driverPort < ACTIVATION_PORT_MIN
    || driverPort > ACTIVATION_PORT_MAX
    || typeof listingForPid !== 'function') fail();
  let listenerObserved = false;
  const policy = (pid) => {
    if (!validPid(pid)) fail();
    const listing = listingForPid(pid);
    if (typeof listing !== 'string') fail();
    if (pid === hostPid && listing.trim() === '' && !listenerObserved) return 0;
    const observed = assertLifecycleNetworkBoundaryFromListing({
      pid,
      hostPid,
      driverPort,
      listing,
    });
    if (pid === hostPid) listenerObserved = true;
    return observed;
  };
  Object.defineProperty(policy, 'listenerObserved', {
    enumerable: true,
    get: () => listenerObserved,
  });
  return policy;
}

function assertLifecycleSnapshot(value, expected = {}) {
  exactKeys(value, LIFECYCLE_SNAPSHOT_KEYS);
  const {
    busy,
    buttonDisabled,
    buttonLabel,
    message,
    phase,
    progressVisible,
    schemaVersion,
  } = value;
  if (schemaVersion !== 1
    || typeof phase !== 'string'
    || !LIFECYCLE_PHASES.has(phase)
    || typeof busy !== 'boolean'
    || typeof message !== 'string'
    || message.length < 1
    || message.length > 160
    || typeof buttonLabel !== 'string'
    || buttonLabel.length < 1
    || buttonLabel.length > 180
    || typeof buttonDisabled !== 'boolean'
    || typeof progressVisible !== 'boolean'
    || buttonDisabled !== busy
    || progressVisible !== busy
    || (expected.phase !== undefined && phase !== expected.phase)
    || (expected.busy !== undefined && busy !== expected.busy)
    || (expected.buttonLabel !== undefined && buttonLabel !== expected.buttonLabel)) fail();
  return Object.freeze({ ...value });
}

export function assertA27LoadingObservation(value, expectedPhase) {
  if (typeof expectedPhase !== 'string' || !LIFECYCLE_PHASES.has(expectedPhase)) fail();
  const observed = assertLifecycleSnapshot(value, {
    busy: true,
    phase: expectedPhase,
  });
  if (observed.buttonLabel !== observed.message) fail();
  return observed;
}

const SNAPSHOT_SCRIPT = String.raw`
const main = document.querySelector('main[data-lifecycle-phase]');
if (main === null) return null;
const button = main?.querySelector('button');
const status = main?.querySelector('[role="status"]');
if (!(main instanceof HTMLElement)
  || !(button instanceof HTMLButtonElement)
  || !(status instanceof HTMLElement)) {
  throw new Error('a27-lifecycle-dom-unavailable');
}
return {
  schemaVersion: 1,
  phase: main.getAttribute('data-lifecycle-phase'),
  busy: main.getAttribute('aria-busy') === 'true',
  message: (status.textContent || '').trim(),
  buttonLabel: (button.textContent || '').trim(),
  buttonDisabled: button.disabled,
  progressVisible: main.querySelector('progress') !== null,
};`;

export const A27_OBSERVE_LOADING_AND_CLICK_SCRIPT = String.raw`
const button = arguments[0];
const expectedIdleLabel = arguments[1];
const expectedBusyPhase = arguments[2];
const complete = arguments[arguments.length - 1];
if (!(button instanceof HTMLButtonElement)
  || typeof expectedIdleLabel !== 'string'
  || typeof expectedBusyPhase !== 'string'
  || button.disabled
  || (button.textContent || '').trim() !== expectedIdleLabel) {
  complete({ rejected: true });
  return;
}
const main = button.closest('main[data-lifecycle-phase]');
const status = main?.querySelector('[role="status"]');
if (!(main instanceof HTMLElement) || !(status instanceof HTMLElement)) {
  complete({ rejected: true });
  return;
}
let settled = false;
let observer;
let timeout;
const finish = (value) => {
  if (settled) return;
  settled = true;
  observer?.disconnect();
  clearTimeout(timeout);
  complete(value);
};
const inspect = () => {
  const progress = main.querySelector('progress');
  const message = (status.textContent || '').trim();
  const buttonLabel = (button.textContent || '').trim();
  const phase = main.getAttribute('data-lifecycle-phase');
  const busy = main.getAttribute('aria-busy') === 'true';
  if (!busy) return;
  if (phase !== expectedBusyPhase
    || !button.disabled
    || !(progress instanceof HTMLProgressElement)
    || message.length < 1
    || buttonLabel !== message
    || progress.getAttribute('aria-label') !== message) {
    finish({ rejected: true });
    return;
  }
  finish({
    schemaVersion: 1,
    phase,
    busy,
    message,
    buttonLabel,
    buttonDisabled: button.disabled,
    progressVisible: true,
  });
};
observer = new MutationObserver(inspect);
observer.observe(main, {
  attributes: true,
  attributeFilter: ['aria-busy', 'data-lifecycle-phase', 'disabled', 'aria-label'],
  childList: true,
  characterData: true,
  subtree: true,
});
timeout = setTimeout(() => finish({ rejected: true }), 5000);
button.click();
inspect();`;

async function readBoundedResponse(response) {
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length < 2 || bytes.length > MAX_HTTP_BYTES) fail();
  return bytes;
}

class A27WebDriverClient {
  constructor(port, signal) {
    if (!Number.isSafeInteger(port)
      || port < ACTIVATION_PORT_MIN
      || port > ACTIVATION_PORT_MAX) fail();
    this.baseUrl = `http://127.0.0.1:${port}`;
    this.signal = signal;
    this.sessionId = undefined;
    this.loadingTransitionsObserved = 0;
  }

  async request(method, path, body, timeoutMs = 35_000) {
    const timeout = AbortSignal.timeout(timeoutMs);
    const signal = this.signal
      ? AbortSignal.any([this.signal, timeout])
      : timeout;
    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      redirect: 'error',
      headers: {
        accept: 'application/json',
        connection: 'close',
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    });
    const declaredLength = response.headers.get('content-length');
    if ((declaredLength !== null
      && (!/^(?:0|[1-9][0-9]{0,6})$/u.test(declaredLength)
        || Number(declaredLength) > MAX_HTTP_BYTES))
      || !response.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
      fail();
    }
    const bytes = await readBoundedResponse(response);
    const text = bytes.toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(bytes)) fail();
    let payload;
    try {
      payload = JSON.parse(text);
    } catch {
      fail();
    }
    exactKeys(payload, ['value']);
    if (!response.ok) fail();
    return payload.value;
  }

  async waitUntilReady() {
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
      if (this.signal?.aborted) fail();
      try {
        const status = await this.request('GET', '/status', undefined, 2_000);
        exactKeys(status, ['message', 'ready']);
        if (status.ready === true && typeof status.message === 'string') return;
      } catch {
        // The exact listener is allowed a bounded startup interval.
      }
      await sleep(50, undefined, this.signal ? { signal: this.signal } : undefined);
    }
    fail();
  }

  async createSession() {
    if (this.sessionId !== undefined) fail();
    const value = await this.request('POST', '/session', {
      capabilities: { alwaysMatch: {}, firstMatch: [{}] },
    });
    exactKeys(value, ['capabilities', 'sessionId']);
    if (typeof value.sessionId !== 'string'
      || !SESSION_ID.test(value.sessionId)
      || !isRecord(value.capabilities)) fail();
    this.sessionId = value.sessionId;
  }

  async execute(script, args = []) {
    if (!this.sessionId
      || typeof script !== 'string'
      || script.length < 1
      || script.length > MAX_EVIDENCE_BYTES
      || !Array.isArray(args)
      || args.length > 8) fail();
    return this.request(
      'POST',
      `/session/${this.sessionId}/execute/sync`,
      { script, args },
      40_000,
    );
  }

  async executeAsync(script, args = []) {
    if (!this.sessionId
      || typeof script !== 'string'
      || script.length < 1
      || script.length > MAX_EVIDENCE_BYTES
      || !Array.isArray(args)
      || args.length > 8) fail();
    return this.request(
      'POST',
      `/session/${this.sessionId}/execute/async`,
      { script, args },
      10_000,
    );
  }

  async snapshot(expected) {
    const value = await this.execute(SNAPSHOT_SCRIPT);
    if (value === null) return null;
    return assertLifecycleSnapshot(value, expected);
  }

  async findPrimaryButton() {
    if (!this.sessionId) fail();
    const value = await this.request(
      'POST',
      `/session/${this.sessionId}/element`,
      { using: 'css selector', value: 'main[data-lifecycle-phase] button' },
    );
    exactKeys(value, [ELEMENT_KEY]);
    if (typeof value[ELEMENT_KEY] !== 'string'
      || value[ELEMENT_KEY].length < 1
      || value[ELEMENT_KEY].length > 512) fail();
    return value[ELEMENT_KEY];
  }

  async clickPrimary(expectedLabel) {
    const idle = await this.snapshot({
      busy: false,
      buttonLabel: expectedLabel,
    });
    if (!idle) fail();
    const element = await this.findPrimaryButton();
    const expectedBusyPhase = BUSY_PHASE_BY_BUTTON_LABEL[expectedLabel];
    if (typeof expectedBusyPhase !== 'string') fail();
    const value = await this.executeAsync(
      A27_OBSERVE_LOADING_AND_CLICK_SCRIPT,
      [{ [ELEMENT_KEY]: element }, expectedLabel, expectedBusyPhase],
    );
    assertA27LoadingObservation(value, expectedBusyPhase);
    this.loadingTransitionsObserved += 1;
  }

  async deleteSession() {
    if (!this.sessionId) fail();
    const value = await this.request('DELETE', `/session/${this.sessionId}`);
    if (value !== null) fail();
    this.sessionId = undefined;
  }
}

export async function waitForA27IdlePhase(
  client,
  phase,
  buttonLabel,
  signal,
  {
    maxSamples = 1_200,
    now = Date.now,
    pause = sleep,
    timeoutMs = 30_000,
  } = {},
) {
  const allowedWaitPhases = WAIT_PHASES_BY_TARGET[phase];
  if (!client
    || typeof client.snapshot !== 'function'
    || !(allowedWaitPhases instanceof Set)
    || typeof buttonLabel !== 'string'
    || buttonLabel.length < 1
    || buttonLabel.length > 180
    || !Number.isSafeInteger(maxSamples)
    || maxSamples < 1
    || typeof now !== 'function'
    || typeof pause !== 'function'
    || !Number.isSafeInteger(timeoutMs)
    || timeoutMs < 1) fail();
  const deadline = now() + timeoutMs;
  for (let sample = 0; sample < maxSamples && now() < deadline; sample += 1) {
    if (signal?.aborted) fail();
    const observed = await client.snapshot();
    if (observed === null) {
      await pause(25, undefined, signal ? { signal } : undefined);
      continue;
    }
    if (!observed.busy
      && observed.phase === phase
      && observed.buttonLabel === buttonLabel) return observed;
    if (!observed.busy
      || observed.phase === 'failed'
      || !allowedWaitPhases.has(observed.phase)) fail();
    await pause(25, undefined, signal ? { signal } : undefined);
  }
  fail();
}

function validateExecutionInput(input) {
  exactKeys(input, [
    'automationBundle',
    'controlledDeltaSha256',
    'productionBundle',
    'signal',
    'sourceDigest',
  ]);
  exactSha(input.sourceDigest);
  exactSha(input.controlledDeltaSha256);
  if (!isRecord(input.productionBundle)
    || !isRecord(input.automationBundle)
    || typeof input.productionBundle.appPath !== 'string'
    || typeof input.productionBundle.hostPath !== 'string'
    || typeof input.productionBundle.nodePath !== 'string'
    || typeof input.automationBundle.appPath !== 'string'
    || typeof input.automationBundle.hostPath !== 'string'
    || typeof input.automationBundle.nodePath !== 'string') fail();
  exactSha(input.productionBundle.fingerprint);
  exactSha(input.automationBundle.fingerprint);
  if (input.productionBundle.fingerprint === input.automationBundle.fingerprint
    || (input.signal !== undefined && !(input.signal instanceof AbortSignal))) fail();
}

function transactionFailure(primary, cleanupFailures, message) {
  if (cleanupFailures.length === 0) return primary;
  return new AggregateError([primary, ...cleanupFailures], message);
}

export async function createA27RuntimeIsolate(dependencies = {}) {
  const {
    chmodPath = chmod,
    makeDirectory = mkdir,
    makeTemporaryDirectory = mkdtemp,
    removeTree = rm,
    resolveRealPath = realpath,
  } = dependencies;
  const requested = await makeTemporaryDirectory(resolve(tmpdir(), 'piui-a27-runtime-'));
  try {
    await chmodPath(requested, 0o700);
    const isolate = await resolveRealPath(requested);
    for (const name of [
      'agent',
      'cache',
      'config',
      'data',
      'home',
      'sessions',
      'tmp',
      'workspace',
    ]) {
      await makeDirectory(resolve(isolate, name), { mode: 0o700 });
    }
    return isolate;
  } catch (error) {
    const cleanupFailures = [];
    try {
      await removeTree(requested, { recursive: true, force: false });
    } catch (cleanupError) {
      cleanupFailures.push(cleanupError);
    }
    throw transactionFailure(error, cleanupFailures, 'A.27 isolate setup and cleanup failed');
  }
}

function runtimeEnvironment(isolate, activation, witnessPath) {
  const environment = {
    HOME: resolve(isolate, 'home'),
    CFFIXED_USER_HOME: resolve(isolate, 'home'),
    TMPDIR: `${resolve(isolate, 'tmp')}/`,
    XDG_CACHE_HOME: resolve(isolate, 'cache'),
    XDG_CONFIG_HOME: resolve(isolate, 'config'),
    XDG_DATA_HOME: resolve(isolate, 'data'),
    PIUI_AGENT_ROOT: resolve(isolate, 'agent'),
    PIUI_SESSION_ROOT: resolve(isolate, 'sessions'),
    PIUI_A27_WORKSPACE_ROOT: resolve(isolate, 'workspace'),
    PIUI_A27_EXIT_WITNESS_PATH: witnessPath,
    PIUI_ARCHITECTURE_TEST_MODE: ACTIVATION_MODE,
    PIUI_ARCHITECTURE_TEST_NONCE: activation.nonce,
    PIUI_ARCHITECTURE_TEST_PORT: String(activation.port),
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    LANG: 'en_AU.UTF-8',
    LC_ALL: 'en_AU.UTF-8',
    RUST_BACKTRACE: '0',
  };
  validateA27ActivationEnvironment({
    PIUI_ARCHITECTURE_TEST_MODE: environment.PIUI_ARCHITECTURE_TEST_MODE,
    PIUI_ARCHITECTURE_TEST_NONCE: environment.PIUI_ARCHITECTURE_TEST_NONCE,
    PIUI_ARCHITECTURE_TEST_PORT: environment.PIUI_ARCHITECTURE_TEST_PORT,
  });
  return environment;
}

async function compileReopenHelper(isolate, signal) {
  const output = resolve(isolate, 'tmp', 'reopen-exact-application.compiled');
  const authority = captureAppleToolchainAuthority();
  let result;
  try {
    result = await runOwnedCommand({
      command: APPLE_TOOLCHAIN_PATHS.clang,
      args: [
        '-std=c17',
        '-Wall',
        '-Wextra',
        '-Werror',
        '-Wno-deprecated-declarations',
        '-isysroot',
        APPLE_TOOLCHAIN_PATHS.sdk,
        '-x',
        'c',
        '-',
        '-framework',
        'ApplicationServices',
        '-framework',
        'Carbon',
        '-o',
        output,
      ],
      cwd: resolve(isolate, 'tmp'),
      env: {
        ...appleToolchainBuildEnvironment(),
        PATH: `${APPLE_TOOLCHAIN_PATHS.bin}:/usr/bin:/bin`,
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
        TMPDIR: `${resolve(isolate, 'tmp')}/`,
      },
      timeoutMs: 30_000,
      maxOutputBytes: MAX_EVIDENCE_BYTES,
      input: Buffer.from(A27_REOPEN_HELPER_SOURCE, 'utf8'),
      signal,
      label: 'A.27 exact-PID reopen helper compilation',
    });
  } finally {
    try {
      revalidateAppleToolchainAuthority(authority);
    } finally {
      releaseAppleToolchainAuthority(authority);
    }
  }
  if (result.status !== 0
    || result.signal !== null
    || result.stdout.length !== 0
    || result.stderr.length !== 0
    || result.forcedCleanup) fail();
  return capturePrivateExecutable({
    controlRoot: resolve(isolate, 'control'),
    executableName: 'reopen-exact-application',
    sourcePath: output,
  });
}

async function canBind(port) {
  return new Promise((resolveBind) => {
    const server = createServer();
    server.unref();
    server.once('error', () => resolveBind(false));
    server.listen({ host: '127.0.0.1', port, exclusive: true }, () => {
      server.close((error) => resolveBind(error === undefined));
    });
  });
}

async function randomFreeHighPort() {
  for (let attempt = 0; attempt < 128; attempt += 1) {
    const candidate = randomInt(ACTIVATION_PORT_MIN, ACTIVATION_PORT_MAX + 1);
    if (await canBind(candidate)) return candidate;
  }
  fail();
}

async function initialiseLedger(ledger, rootPid, signal) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (signal?.aborted) fail();
    try {
      await ledger.initialise(rootPid);
      return;
    } catch {
      await sleep(25, undefined, signal ? { signal } : undefined);
    }
  }
  fail();
}

async function waitForExactListener(runtime, signal) {
  const deadline = Date.now() + 30_000;
  let stable = 0;
  while (Date.now() < deadline) {
    if (signal?.aborted) fail();
    const live = await runtime.ledger.sample();
    if (live.length !== 1
      || live[0].pid !== runtime.childPid
      || live[0].executable !== runtime.bundle.hostPath) fail();
    if (runtime.networkPolicy.listenerObserved) {
      stable += 1;
      if (stable === 5) return;
    } else {
      stable = 0;
    }
    await sleep(50, undefined, signal ? { signal } : undefined);
  }
  fail();
}

export async function launchA27Runtime(bundle, activation, signal, dependencies = {}) {
  if (!isRecord(bundle)
    || typeof bundle.appPath !== 'string'
    || typeof bundle.hostPath !== 'string'
    || typeof bundle.nodePath !== 'string'
    || signal?.aborted) fail();
  const {
    assertLockContended = assertOwnershipLockContended,
    assertLockDescriptor = assertHostOwnsLockDescriptor,
    closeLog = closeSync,
    closeOwnershipDescriptor = closeLifecycleOwnershipDescriptor,
    compileHelper = compileReopenHelper,
    createIsolate = createA27RuntimeIsolate,
    createLedger = (options) => new A27RuntimeProcessLedger(options),
    createNetworkPolicy = createA27LifecycleNetworkPolicy,
    initialiseProcessLedger = initialiseLedger,
    makeOwnershipDescriptor = openLifecycleOwnershipDescriptor,
    openLog = openSync,
    removeTree = rm,
    spawnProcess = spawn,
    terminateGroups = terminateRecordedProcessGroupsWithoutObservation,
    waitForListener = waitForExactListener,
    waitForSpawn = waitForChildSpawn,
  } = dependencies;
  let isolate;
  let stdoutPath;
  let stderrPath;
  let witnessPath;
  let lockPath;
  let stdoutFd;
  let stderrFd;
  let descriptor;
  let child;
  let spawnConfirmed = false;
  let ledger;
  let helper;
  let runtime;
  let setupFailure;
  const cleanupFailures = [];
  try {
    isolate = await createIsolate();
    stdoutPath = resolve(isolate, 'stdout.log');
    stderrPath = resolve(isolate, 'stderr.log');
    witnessPath = resolve(isolate, 'exit-witness.json');
    lockPath = resolve(isolate, 'application.lock');
    helper = await compileHelper(isolate, signal);
    descriptor = makeOwnershipDescriptor(lockPath);
    stdoutFd = openLog(
      stdoutPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
      0o600,
    );
    stderrFd = openLog(
      stderrPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
      0o600,
    );
    child = spawnProcess('/usr/bin/sandbox-exec', [
      '-p',
      a27RuntimeSandbox({ activation, bundle, isolate }),
      bundle.hostPath,
    ], {
      cwd: isolate,
      env: runtimeEnvironment(isolate, activation, witnessPath),
      detached: true,
      stdio: ['ignore', stdoutFd, stderrFd, descriptor.fd],
    });
    await waitForSpawn(child);
    spawnConfirmed = true;
    if (!validPid(child.pid)) fail();
    closeOwnershipDescriptor(descriptor);
    const networkPolicy = createNetworkPolicy({
      driverPort: activation.port,
      hostPid: child.pid,
    });
    ledger = createLedger({
      hostPath: bundle.hostPath,
      nodePath: bundle.nodePath,
      networkChecker: networkPolicy,
    });
    await initialiseProcessLedger(ledger, child.pid, signal);
    runtime = {
      activation,
      bundle,
      child,
      childPid: child.pid,
      helper,
      helperPath: typeof helper === 'string' ? helper : helper.path,
      isolate,
      ledger,
      lockPath,
      networkPolicy,
      removed: false,
      stderrPath,
      stdoutPath,
      witnessPath,
    };
    await waitForListener(runtime, signal);
    assertLockDescriptor(child.pid, descriptor, lockPath);
    assertLockContended(lockPath);
  } catch (error) {
    setupFailure = error;
  } finally {
    if (descriptor && !descriptor.closed) {
      try {
        closeOwnershipDescriptor(descriptor);
      } catch (error) {
        cleanupFailures.push(error);
      }
    }
    for (const descriptorFd of [stdoutFd, stderrFd]) {
      if (descriptorFd === undefined) continue;
      try {
        closeLog(descriptorFd);
      } catch (error) {
        cleanupFailures.push(error);
      }
    }
  }

  if (!setupFailure && cleanupFailures.length === 0) return runtime;
  const primary = setupFailure ?? new Error('A.27 launch descriptor cleanup failed');
  let ownershipConfirmed = child === undefined
    || (!spawnConfirmed && !validPid(child.pid));
  if (ledger) {
    try {
      const cleanup = await confirmA27LedgerAbsence(ledger);
      ownershipConfirmed = true;
      if (cleanup.cleanupFailure) cleanupFailures.push(cleanup.cleanupFailure);
    } catch (error) {
      cleanupFailures.push(error);
      if (error?.code !== 'PIUI_PROCESS_GROUP_IDENTITY_AMBIGUOUS') {
        try {
          await terminateGroups([child.pid, ...ledger.groups]);
        } catch (emergencyError) {
          cleanupFailures.push(emergencyError);
        }
      }
    }
  } else if (validPid(child?.pid)) {
    try {
      await terminateGroups([child.pid]);
    } catch (error) {
      cleanupFailures.push(error);
    }
  }
  if (isolate && ownershipConfirmed) {
    let releasedHelper;
    try {
      if (helper && typeof helper === 'object') {
        await releasePrivateExecutableLeaseForRemoval(helper);
        releasedHelper = helper;
      }
      await removeTree(isolate, { recursive: true, force: false });
    } catch (error) {
      if (releasedHelper) {
        try {
          await chmod(releasedHelper.controlRoot.path, 0o500);
        } catch (restoreError) {
          cleanupFailures.push(restoreError);
        }
      }
      cleanupFailures.push(error);
    }
  }
  throw transactionFailure(primary, cleanupFailures, 'A.27 runtime launch and cleanup failed');
}

function a27SidecarIdentity(sidecar) {
  return `${sidecar?.pid}:${sidecar?.pgid}:${sidecar?.start}:${sidecar?.command}`;
}

export async function waitForA27GenerationProcess({
  generation,
  maxSamples = 400,
  nodePath,
  now = Date.now,
  observation,
  observedSidecarIdentities,
  pause = sleep,
  sample,
  signal,
  timeoutMs = 10_000,
}) {
  if (!Number.isSafeInteger(generation)
    || generation < 1
    || generation > 4
    || !Number.isSafeInteger(maxSamples)
    || maxSamples < 1
    || typeof nodePath !== 'string'
    || !nodePath.startsWith('/')
    || typeof now !== 'function'
    || !observation
    || typeof observation.observe !== 'function'
    || typeof observation.observeGeneration !== 'function'
    || !(observedSidecarIdentities instanceof Set)
    || typeof pause !== 'function'
    || typeof sample !== 'function'
    || !Number.isSafeInteger(timeoutMs)
    || timeoutMs < 1) fail();
  const deadline = now() + timeoutMs;
  for (let attempt = 0; attempt < maxSamples && now() < deadline; attempt += 1) {
    if (signal?.aborted) fail();
    const live = await sample();
    if (!Array.isArray(live)) fail();
    const sidecars = live.filter((entry) => entry?.executable === nodePath);
    if (sidecars.length === 0) {
      // An exact host-only topology is the sole valid start transition.
      observation.observe(live, 0);
    } else if (sidecars.length === 1) {
      const sidecar = sidecars[0];
      const identity = a27SidecarIdentity(sidecar);
      if (observedSidecarIdentities.has(identity)) {
        // A previously witnessed sidecar may still be stopping. Its exact
        // topology and network/descriptor policy remain mandatory.
        observation.observe(live, 1);
      } else {
        observation.observeGeneration({ generation, pid: sidecar.pid }, live);
        observedSidecarIdentities.add(identity);
        return;
      }
    } else {
      // Invoke the authoritative topology observer before rejecting so a
      // duplicate sample can never be reclassified as an ordinary wait.
      observation.observe(live, 1);
      fail();
    }
    await pause(25, undefined, signal ? { signal } : undefined);
  }
  fail();
}

async function waitForGeneration({
  client,
  generation,
  observation,
  observedSidecarIdentities,
  phase,
  buttonLabel,
  runtime,
  signal,
}) {
  await waitForA27IdlePhase(client, phase, buttonLabel, signal);
  await waitForA27GenerationProcess({
    generation,
    nodePath: runtime.bundle.nodePath,
    observation,
    observedSidecarIdentities,
    sample: () => runtime.ledger.sample(),
    signal,
  });
}

export async function waitForA27HostOnlyProcess({
  maxSamples = 400,
  nodePath,
  now = Date.now,
  observation,
  observedSidecarIdentities,
  pause = sleep,
  sample,
  signal,
  stableSamples = 3,
  timeoutMs = 10_000,
}) {
  if (!Number.isSafeInteger(maxSamples)
    || maxSamples < 1
    || typeof nodePath !== 'string'
    || !nodePath.startsWith('/')
    || typeof now !== 'function'
    || !observation
    || typeof observation.observe !== 'function'
    || !(observedSidecarIdentities instanceof Set)
    || typeof pause !== 'function'
    || typeof sample !== 'function'
    || !Number.isSafeInteger(stableSamples)
    || stableSamples < 1
    || !Number.isSafeInteger(timeoutMs)
    || timeoutMs < 1) fail();
  const deadline = now() + timeoutMs;
  let stable = 0;
  for (let attempt = 0; attempt < maxSamples && now() < deadline; attempt += 1) {
    if (signal?.aborted) fail();
    const live = await sample();
    if (!Array.isArray(live)) fail();
    const sidecars = live.filter((entry) => entry?.executable === nodePath);
    if (sidecars.length === 0) {
      observation.observe(live, 0);
      stable += 1;
      if (stable === stableSamples) return;
    } else if (sidecars.length === 1) {
      observation.observe(live, 1);
      if (!observedSidecarIdentities.has(a27SidecarIdentity(sidecars[0]))) fail();
      stable = 0;
    } else {
      observation.observe(live, 1);
      fail();
    }
    await pause(25, undefined, signal ? { signal } : undefined);
  }
  fail();
}

async function waitForHostOnly(
  runtime,
  observation,
  observedSidecarIdentities,
  signal,
) {
  await waitForA27HostOnlyProcess({
    nodePath: runtime.bundle.nodePath,
    observation,
    observedSidecarIdentities,
    sample: () => runtime.ledger.sample(),
    signal,
  });
}

async function sendExactPidReopen(runtime, signal) {
  await assertPrivateExecutableLease(runtime.helper);
  const result = await runOwnedCommand({
    command: '/usr/bin/sandbox-exec',
    args: [
      '-p',
      a27ReopenHelperSandbox(runtime.helper.path),
      runtime.helper.path,
      String(runtime.childPid),
    ],
    cwd: runtime.isolate,
    env: {
      PATH: '/usr/bin:/bin',
      LANG: 'en_AU.UTF-8',
      LC_ALL: 'en_AU.UTF-8',
    },
    timeoutMs: 10_000,
    maxOutputBytes: MAX_EVIDENCE_BYTES,
    signal,
    label: 'A.27 exact-PID reopen Apple event',
  });
  if (result.status !== 0
    || result.signal !== null
    || result.stdout.length !== 0
    || result.stderr.length !== 0
    || result.forcedCleanup) fail();
  await assertPrivateExecutableLease(runtime.helper);
}

async function inspectRuntimeLogs(runtime) {
  for (const path of [runtime.stdoutPath, runtime.stderrPath]) {
    const item = await lstat(path);
    if (!item.isFile()
      || item.isSymbolicLink()
      || item.nlink !== 1
      || item.size > MAX_EVIDENCE_BYTES
      || (item.mode & 0o777) !== 0o600
      || (typeof process.getuid === 'function' && item.uid !== process.getuid())) fail();
  }
}

async function removeRuntime(runtime) {
  await inspectRuntimeLogs(runtime);
  let releasedHelper;
  if (runtime.helper !== undefined) {
    await releasePrivateExecutableLeaseForRemoval(runtime.helper);
    releasedHelper = runtime.helper;
  }
  try {
    await rm(runtime.isolate, { recursive: true, force: false });
  } catch (error) {
    if (releasedHelper) await chmod(releasedHelper.controlRoot.path, 0o500);
    throw error;
  }
  runtime.removed = true;
}

export async function terminateFailedRuntime(runtime) {
  const cleanupFailures = [];
  let ownershipConfirmed = false;
  try {
    const cleanup = await confirmA27LedgerAbsence(runtime.ledger);
    ownershipConfirmed = true;
    if (cleanup.cleanupFailure) cleanupFailures.push(cleanup.cleanupFailure);
  } catch (error) {
    cleanupFailures.push(error);
  }
  if (ownershipConfirmed && !runtime.removed) {
    try {
      await removeRuntime(runtime);
    } catch (error) {
      cleanupFailures.push(error);
    }
  }
  if (cleanupFailures.length === 1) throw cleanupFailures[0];
  if (cleanupFailures.length > 1) {
    throw new AggregateError(cleanupFailures, 'A.27 failed-runtime cleanup failed');
  }
}

async function executeLifecycleObservation(bundle, activation, signal) {
  const runtime = await launchA27Runtime(bundle, activation, signal);
  const observation = new LifecycleObservation({
    hostPath: bundle.hostPath,
    nodePath: bundle.nodePath,
    hostPid: runtime.childPid,
  });
  const observedSidecarIdentities = new Set();
  let firstClient;
  let secondClient;
  let nativeEvidence;
  let externalObservation;
  let gracefulCompletion = false;
  let failure;
  try {
    firstClient = new A27WebDriverClient(activation.port, signal);
    await firstClient.waitUntilReady();
    await firstClient.createSession();
    await waitForA27IdlePhase(
      firstClient,
      'ready',
      'Start lifecycle verification',
      signal,
    );

    await firstClient.clickPrimary('Start lifecycle verification');
    await waitForGeneration({
      client: firstClient,
      generation: 1,
      observation,
      observedSidecarIdentities,
      phase: 'running',
      buttonLabel: 'Verify crash recovery',
      runtime,
      signal,
    });

    await firstClient.clickPrimary('Verify crash recovery');
    await waitForGeneration({
      client: firstClient,
      generation: 2,
      observation,
      observedSidecarIdentities,
      phase: 'recovered',
      buttonLabel: 'Verify explicit restart',
      runtime,
      signal,
    });

    await firstClient.clickPrimary('Verify explicit restart');
    await waitForGeneration({
      client: firstClient,
      generation: 3,
      observation,
      observedSidecarIdentities,
      phase: 'awaiting-close',
      buttonLabel: 'Close and verify reopen',
      runtime,
      signal,
    });

    await firstClient.clickPrimary('Close and verify reopen');
    await waitForHostOnly(runtime, observation, observedSidecarIdentities, signal);
    assertOwnershipLockContended(runtime.lockPath);
    if (firstClient.loadingTransitionsObserved !== 4) fail();
    await firstClient.deleteSession();

    await sendExactPidReopen(runtime, signal);
    secondClient = new A27WebDriverClient(activation.port, signal);
    await secondClient.waitUntilReady();
    await secondClient.createSession();
    await waitForGeneration({
      client: secondClient,
      generation: 4,
      observation,
      observedSidecarIdentities,
      phase: 'ready-to-quit',
      buttonLabel: 'Quit and verify cleanup',
      runtime,
      signal,
    });

    await secondClient.clickPrimary('Quit and verify cleanup');
    if (secondClient.loadingTransitionsObserved !== 1) fail();
    await waitForOwnedProcessesToExit(runtime.ledger, { timeoutMs: 12_000 });
    const liveBeforeRemoval = await runtime.ledger.sample();
    if (!Array.isArray(liveBeforeRemoval) || liveBeforeRemoval.length !== 0) fail();
    if (!(await canBind(activation.port))) fail();
    assertOwnershipLockReleased(runtime.lockPath);
    nativeEvidence = await readNativeLifecycleWitness(runtime.witnessPath);
    externalObservation = observation.evidence();
    await removeRuntime(runtime);
    if (!runtime.removed) fail();
    gracefulCompletion = true;
  } catch (error) {
    failure = error;
  } finally {
    if (!gracefulCompletion && !runtime.removed) {
      try {
        await terminateFailedRuntime(runtime);
      } catch (error) {
        failure = failure
          ? new AggregateError([failure, error], 'A.27 observation and cleanup failed')
          : error;
      }
    }
  }
  if (failure) throw failure;
  if (!gracefulCompletion
    || !nativeEvidence
    || !externalObservation
    || !runtime.removed) fail();
  return Object.freeze({
    externalObservation,
    nativeEvidence,
  });
}

export async function executeAuthoritativeLifecycleProbe(input) {
  validateExecutionInput(input);
  const {
    automationBundle,
    controlledDeltaSha256,
    productionBundle,
    signal,
    sourceDigest,
  } = input;
  await revalidateBundle(productionBundle);
  await revalidateBundle(automationBundle);
  const activation = Object.freeze({
    nonce: randomBytes(32).toString('hex'),
    port: await randomFreeHighPort(),
  });
  validateA27ActivationEnvironment({
    PIUI_ARCHITECTURE_TEST_MODE: ACTIVATION_MODE,
    PIUI_ARCHITECTURE_TEST_NONCE: activation.nonce,
    PIUI_ARCHITECTURE_TEST_PORT: String(activation.port),
  });

  const observed = await executeLifecycleObservation(
    automationBundle,
    activation,
    signal,
  );
  await revalidateBundle(productionBundle);
  await revalidateBundle(automationBundle);

  assertExpectedSubset(observed.nativeEvidence, A27_NATIVE_EVIDENCE_KEYS);
  const external = {
    ...expectedValueSubset(EXTERNAL_PRE_CLEANUP_KEYS),
    ...observed.externalObservation,
  };
  assertExpectedSubset(external, EXTERNAL_PRE_CLEANUP_KEYS);
  if (!SHA256.test(sourceDigest)
    || !SHA256.test(controlledDeltaSha256)
    || productionBundle.fingerprint === automationBundle.fingerprint) fail();
  return assertPreCleanupLifecycleEvidence({
    ...observed.nativeEvidence,
    ...external,
    identity: {
      sourceDigest,
      productionFingerprint: productionBundle.fingerprint,
      automationFingerprint: automationBundle.fingerprint,
      controlledDeltaSha256,
      sameFrozenSource: true,
    },
  });
}

export async function runAuthoritativeA27Command() {
  const cutoffs = installParentCutoffs();
  try {
    const result = await runOwnedCommand({
      command: process.execPath,
      args: [resolve(root, 'scripts/package-spike.mjs'), '--authoritative-a27'],
      cwd: root,
      env: {
        HOME: process.env.HOME,
        PATH: process.env.PATH,
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
      },
      timeoutMs: 45 * 60_000,
      maxOutputBytes: MAX_EVIDENCE_BYTES,
      signal: cutoffs.signal,
      label: 'A.27 packaged lifecycle command',
    });
    if (result.status !== 0
      || result.signal !== null
      || result.stderr.length !== 0
      || result.forcedCleanup) fail();
    return parsePackagedLifecycleEvidence(result.stdout);
  } finally {
    cutoffs.dispose();
  }
}

if (process.argv[1]
  && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const evidence = await runAuthoritativeA27Command();
    process.stdout.write(`${JSON.stringify(evidence)}\n`);
  } catch {
    process.stderr.write(`${REJECTED}\n`);
    process.exitCode = 1;
  }
}
