import { createHash, randomBytes, randomInt } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import {
  closeSync,
  constants,
  existsSync,
  openSync,
  realpathSync,
} from 'node:fs';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  realpath,
  rm,
} from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import {
  basename,
  dirname,
  resolve,
} from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { revalidateBundle } from '../tests/packaged/bundle-inspection.mjs';
import {
  ProcessLedger,
  authoriseAuthenticatedNodeSandboxProfile,
  assertNoNetwork,
  executableForPid,
  observeProcesses,
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
import {
  assertA28HumanWitnessLease,
  parseA28AccessibilityTreeEvidence,
  parseA28VoiceOverChecksums,
  parseA28VoiceOverCompletion,
  parseA28VoiceOverEvidence,
} from './a28-accessibility-evidence.mjs';
import {
  assertA28ComparedVoiceOverEvidence,
  createA28FinalConsumerContext,
  executeA28FinalConsumerCeremony,
  releaseA28FinalConsumerContext,
} from './a28-final-consumer.mjs';
import {
  A28_OFFICIAL_NODE_SIGNING_IDENTITY,
  createA28InstalledWitnessCeremony,
} from './a28-installed-witness-ceremony.mjs';
import {
  canonicalArchitectureJson,
  sha256Bytes,
} from './architecture-gate-schema.mjs';
import {
  createLifecycleNetworkChecker,
} from './assert-process-cleanup.mjs';
import { credentialProbeSandbox } from './run-packaged-credential-probe.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ACTIVATION_MODE = 'a28-accessibility';
const PORT_MIN = 49_152;
const PORT_MAX = 65_535;
const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_EVIDENCE_BYTES = 65_536;
const MAX_WDIO_OUTPUT_BYTES = 2 * 1024 * 1024;
const HUMAN_WITNESS_TIMEOUT_MS = 30 * 60_000;
const EXPECTED_TAURI_SERVICE_VERSION = '1.2.0';
const EXPECTED_WDIO_VERSION = '9.27.1';
const A28_AUTOMATION_BUNDLE_ID = 'au.com.piui.desktop.architecture-test';
const BLOCKED_PACKAGE_STDERR =
  'A.21 package gate failed: A.28 accessibility proof blocked\n';
const FORCED_CLEANUP_COMPLETE = 'Packaged runtime required forced cleanup';
const DEFAULT_HUMAN_EVIDENCE_ROOT = resolve(
  root,
  '.forge/evidence/architecture-accessibility',
);
const A28_RUN_EVIDENCE_FILES = Object.freeze([
  'ax-ready.json',
  'ax-release.json',
  'dom-evidence.json',
  'human-ready.json',
  'human-visible.json',
]);
const FINAL_CONSUMER_ANCHOR_KEYS = Object.freeze([
  'architectureBootstrapPinsSha256',
  'architectureBootstrapReceiptSha256',
  'authenticatedToolchainContextSha256',
  'authenticatedToolchainReceiptSha256',
  'dependencyInventorySha256',
  'dependencyLeaseSha256',
  'frozenSourceInventorySha256',
  'frozenSourceLeaseSha256',
  'packageChildContextLeaseSha256',
  'packageChildContextSha256',
  'sourceInputLeaseSha256',
  'toolInputInventorySha256',
  'toolInputLeaseSha256',
]);

function seatbeltPath(path) {
  return path.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
}

function assertSandboxPath(path) {
  if (typeof path !== 'string'
    || !path.startsWith('/')
    || /[\0\r\n]/u.test(path)
    || resolve(path) !== path) fail();
  return path;
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

function runnerRuntimeFiles(runnerPath) {
  const executableDirectory = dirname(runnerPath);
  const pending = [runnerPath];
  const inspected = new Set();
  const files = new Set([runnerPath]);
  const authority = captureAppleToolchainAuthority();
  try {
    while (pending.length > 0) {
      const current = pending.shift();
      if (inspected.has(current)) continue;
      inspected.add(current);
      if (inspected.size > 256) fail();
      const result = spawnSync(APPLE_TOOLCHAIN_PATHS.otool, ['-L', current], {
        encoding: 'utf8',
        env: { PATH: `${APPLE_TOOLCHAIN_PATHS.bin}:/usr/bin:/bin` },
        maxBuffer: 1_048_576,
      });
      revalidateAppleToolchainAuthority(authority);
      if (result.status !== 0 || result.signal !== null || result.stderr.length !== 0) fail();
      for (const line of result.stdout.split('\n').slice(1)) {
        if (line.length === 0) continue;
        const match = /^\t(.+?) \(compatibility version [^)]+\)$/u.exec(line);
        if (!match) fail();
        let dependency = match[1];
        if (dependency.startsWith('@loader_path/')) {
          dependency = resolve(dirname(current), dependency.slice('@loader_path/'.length));
        } else if (dependency.startsWith('@executable_path/')) {
          dependency = resolve(
            executableDirectory,
            dependency.slice('@executable_path/'.length),
          );
        } else if (dependency.startsWith('@rpath/')) {
          dependency = resolve(dirname(current), dependency.slice('@rpath/'.length));
        }
        assertSandboxPath(dependency);
        if (dependency.startsWith('/System/')
          || dependency.startsWith('/usr/lib/')
          || dependency.startsWith('/Library/Apple/')) continue;
        if (!existsSync(dependency)) fail();
        const canonical = realpathSync(dependency);
        const canonicalParentEntry = resolve(
          realpathSync(dirname(dependency)),
          basename(dependency),
        );
        assertSandboxPath(canonical);
        assertSandboxPath(canonicalParentEntry);
        files.add(dependency);
        files.add(canonical);
        files.add(canonicalParentEntry);
        if (!inspected.has(canonical)) pending.push(canonical);
      }
    }
  } finally {
    try {
      revalidateAppleToolchainAuthority(authority);
    } finally {
      releaseAppleToolchainAuthority(authority);
    }
  }
  return [...files].sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
}

function a28RuntimeRoots(runRoot, exposeRoot) {
  return Object.freeze({
    artefacts: resolve(runRoot, 'agent'),
    cache: resolve(runRoot, 'cache'),
    config: resolve(runRoot, 'config'),
    data: resolve(runRoot, 'data'),
    home: resolve(runRoot, 'home'),
    temporary: resolve(runRoot, 'tmp'),
    working: exposeRoot ? runRoot : resolve(runRoot, 'sessions'),
  });
}

export function a28NegativeRuntimeSandbox({ bundle, isolate }) {
  const profile = credentialProbeSandbox(
    a28RuntimeRoots(isolate, true),
    bundle,
    { allowCredentialBrokers: false },
  );
  return `${profile}
  (deny file-write* (subpath "${seatbeltPath(bundle.appPath)}"))`;
}

export function a28WdioSandbox({
  bundle,
  controlRoot,
  evidenceRoot,
  port,
  repositoryRoot,
  runRoot,
  runnerPath,
}) {
  for (const path of [controlRoot, evidenceRoot, repositoryRoot, runRoot, runnerPath]) {
    assertSandboxPath(path);
  }
  if (!Number.isSafeInteger(port) || port < PORT_MIN || port > PORT_MAX) fail();
  const profile = credentialProbeSandbox(
    a28RuntimeRoots(runRoot, false),
    bundle,
    { allowCredentialBrokers: false },
  );
  const runnerFiles = runnerRuntimeFiles(runnerPath);
  const runnerFileRules = runnerFiles
    .map((path) => `(literal "${seatbeltPath(path)}")`)
    .join(' ');
  const runnerTraversalRules = sandboxPathAncestors([
    repositoryRoot,
    ...runnerFiles,
  ]).map((path) => (
    `(allow file-read* file-test-existence (literal "${seatbeltPath(path)}"))`
  )).join('\n  ');
  const runEvidence = A28_RUN_EVIDENCE_FILES
    .map((name) => `(literal "${seatbeltPath(resolve(runRoot, name))}")`)
    .join(' ');
  const control = seatbeltPath(controlRoot);
  return `${profile}
  (deny file-write* (subpath "${seatbeltPath(bundle.appPath)}"))
  (deny file-read* file-test-existence (subpath "${seatbeltPath(evidenceRoot)}"))
  (deny file-write* (subpath "${seatbeltPath(evidenceRoot)}"))
  (deny file-write* (subpath "${seatbeltPath(repositoryRoot)}"))
  (allow network-inbound (local tcp4 "localhost:${port}"))
  (allow network-outbound (remote tcp4 "localhost:${port}"))
  ${runnerTraversalRules}
  (allow file-read* file-test-existence file-map-executable
    ${runnerFileRules})
  (with-filter (process-path "/usr/bin/sandbox-exec")
    (allow process-exec (literal "${seatbeltPath(runnerPath)}")))
  (with-filter (process-path "${seatbeltPath(runnerPath)}")
    (allow process-fork)
    (allow process-exec
      (literal "${seatbeltPath(runnerPath)}")
      (literal "${seatbeltPath(bundle.hostPath)}"))
    (allow signal (target self) (target children))
    (allow process-info* (target self) (target children))
    (allow dynamic-code-generation)
    (allow file-read* file-test-existence file-map-executable
      ${runnerFileRules}
      (subpath "${seatbeltPath(repositoryRoot)}"))
    (allow file-write* (subpath "${seatbeltPath(runRoot)}"))
    (allow file-link (subpath "${seatbeltPath(runRoot)}")))
  (with-filter (process-path "${seatbeltPath(bundle.hostPath)}")
    (deny file-read* file-test-existence ${runEvidence})
    (deny file-write* ${runEvidence}))
  (deny file-read* file-test-existence file-map-executable (subpath "${control}"))
  (deny file-write* (subpath "${control}"))
  (deny process-exec (subpath "${control}"))`;
}

export function a28AccessibilityHelperSandbox(helperPath) {
  assertSandboxPath(helperPath);
  const helper = seatbeltPath(helperPath);
  const ancestors = sandboxPathAncestors([helperPath])
    .map((path) => `  (allow file-read-metadata file-test-existence (literal "${seatbeltPath(path)}"))`)
    .join('\n');
  return `(version 1)
  (deny default)
  (import "dyld-support.sb")
  (deny network*)
  (deny appleevent-send)
  (with-filter (process-path "/usr/bin/sandbox-exec")
    (allow process-exec (literal "${helper}")))
  (with-filter (process-path "${helper}")
    (allow mach-lookup
      (global-name "com.apple.axserver")
      (global-name "com.apple.tccd")
      (global-name "com.apple.tccd.system")
      (local-name-prefix "com.apple.axserver")))
${ancestors}
  (allow file-read* file-test-existence file-map-executable
    (literal "${helper}")
    (subpath "/Library/Apple/System/Library")
    (subpath "/System/Library")
    (subpath "/usr/lib"))`;
}

const TOP_LEVEL_KEYS = Object.freeze([
  'accessibilityTree',
  'automation',
  'cleanup',
  'driver',
  'identity',
  'limitations',
  'schemaVersion',
  'status',
  'voiceOver',
]);
const IDENTITY_KEYS = Object.freeze([
  'automationFingerprint',
  'controlledDeltaSha256',
  'productionFingerprint',
  'sameFrozenSource',
  'sourceDigest',
]);
const DRIVER_KEYS = Object.freeze([
  'activatedTwinIpv4LoopbackListeners',
  'activatedTwinOtherListeners',
  'cleanupListeners',
  'dormantTwinListeners',
  'ipv4LoopbackOnly',
  'productionHostileActivationListeners',
  'randomHighPort',
  'stableSelectionCount',
  'webdriverSessions',
]);
const AUTOMATION_KEYS = Object.freeze([
  'accessibleOrderedRowsObserved',
  'appearances',
  'ariaPositionErrors',
  'arrowTransitions',
  'duplicateRows',
  'focusRetentionChecks',
  'focusRetentionFailures',
  'homeEndTransitions',
  'loadingIndicatorObserved',
  'missingRows',
  'modes',
  'nameErrors',
  'outOfOrderRows',
  'pageTransitions',
  'roleErrors',
  'transcriptItems',
  'virtualOrderedRowsObserved',
]);
const DOM_EVIDENCE_KEYS = Object.freeze([
  ...AUTOMATION_KEYS,
  'schemaVersion',
  'stableSelectionCount',
  'webdriverSessions',
]);
const ACCESSIBILITY_TREE_KEYS = Object.freeze([
  'bounded',
  'exactPid',
  'focusErrors',
  'focusedRowOrdinal',
  'focusedRows',
  'listRoles',
  'nameErrors',
  'nodesVisited',
  'observedTranscriptRows',
  'orderErrors',
  'roleErrors',
  'trusted',
]);
const LIMITATION_KEYS = Object.freeze([
  'automationConformanceEquivalence',
  'voiceOverAutomationEquivalence',
  'wcagConformance',
]);
const CLEANUP_KEYS = Object.freeze([
  'bundlesRevalidated',
  'listenerRemoved',
  'ownedProcessesAfterCleanup',
  'runnerIsolateRemoved',
  'webdriverSessionDeleted',
]);

export class A28AccessibilityBlockedError extends Error {
  constructor(reason) {
    super(`A.28 accessibility proof blocked: ${reason}`);
    this.name = 'A28AccessibilityBlockedError';
    this.code = 'PIUI_A28_ACCESSIBILITY_BLOCKED';
    this.reason = reason;
  }
}

function fail() {
  throw new Error('A.28 packaged accessibility probe rejected');
}

export class A28ForcedCleanupCompleteError extends Error {
  constructor(cause) {
    super('A.28 forced process cleanup completed with verified empty identity observation', {
      cause,
    });
    this.name = 'A28ForcedCleanupCompleteError';
    this.code = 'PIUI_A28_FORCED_CLEANUP_COMPLETE';
  }
}

export class A28RuntimeProcessLedger extends ProcessLedger {
  async terminate() {
    try {
      return await super.terminate();
    } catch (error) {
      if (!(error instanceof Error) || error.message !== FORCED_CLEANUP_COMPLETE) {
        throw error;
      }
      const live = await this.sample();
      if (!Array.isArray(live) || live.length !== 0) throw error;
      throw new A28ForcedCleanupCompleteError(error);
    }
  }
}

async function confirmA28LedgerAbsence(ledger) {
  try {
    const cleanup = await ledger.terminate();
    if (!isRecord(cleanup) || typeof cleanup.forced !== 'boolean') fail();
    return Object.freeze({ forced: cleanup.forced });
  } catch (error) {
    if (error instanceof A28ForcedCleanupCompleteError) {
      return Object.freeze({ completion: error, forced: true });
    }
    if (error?.code === 'PIUI_PROCESS_GROUP_IDENTITY_AMBIGUOUS') throw error;
    let live;
    try {
      live = await ledger.sample();
    } catch (verificationError) {
      throw new AggregateError(
        [error, verificationError],
        'A.28 ledger cleanup and empty-identity verification failed',
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

function exactInteger(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail();
}

function parseCanonicalOneLine(bytes, maximumBytes = MAX_EVIDENCE_BYTES) {
  if (!Buffer.isBuffer(bytes)
    || !Number.isSafeInteger(maximumBytes)
    || maximumBytes < 3
    || bytes.length < 3
    || bytes.length > maximumBytes
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
  if (canonicalArchitectureJson(value) !== text) fail();
  return value;
}

export function validateA28ActivationEnvironment(environment) {
  if (!isRecord(environment)) fail();
  const activationKeys = [
    'PIUI_ARCHITECTURE_TEST_MODE',
    'PIUI_ARCHITECTURE_TEST_NONCE',
    'PIUI_ARCHITECTURE_TEST_PORT',
  ];
  const present = activationKeys.filter((key) =>
    Object.hasOwn(environment, key) && environment[key] !== undefined);
  if (present.length !== activationKeys.length
    || environment.PIUI_ARCHITECTURE_TEST_MODE !== ACTIVATION_MODE
    || typeof environment.PIUI_ARCHITECTURE_TEST_NONCE !== 'string'
    || !SHA256.test(environment.PIUI_ARCHITECTURE_TEST_NONCE)
    || typeof environment.PIUI_ARCHITECTURE_TEST_PORT !== 'string'
    || !/^[0-9]{5}$/u.test(environment.PIUI_ARCHITECTURE_TEST_PORT)) fail();
  const port = Number(environment.PIUI_ARCHITECTURE_TEST_PORT);
  if (!Number.isSafeInteger(port)
    || port < PORT_MIN
    || port > PORT_MAX
    || String(port) !== environment.PIUI_ARCHITECTURE_TEST_PORT) fail();
  return Object.freeze({
    mode: ACTIVATION_MODE,
    nonce: environment.PIUI_ARCHITECTURE_TEST_NONCE,
    port,
  });
}

export function assertA28DomEvidence(value) {
  exactKeys(value, DOM_EVIDENCE_KEYS);
  if (value.schemaVersion !== 1
    || value.transcriptItems !== 100
    || value.appearances !== 2
    || value.modes !== 2
    || value.virtualOrderedRowsObserved !== 100
    || value.accessibleOrderedRowsObserved !== 100
    || value.missingRows !== 0
    || value.duplicateRows !== 0
    || value.outOfOrderRows !== 0
    || value.ariaPositionErrors !== 0
    || value.roleErrors !== 0
    || value.nameErrors !== 0
    || value.focusRetentionChecks !== 4
    || value.focusRetentionFailures !== 0
    || value.loadingIndicatorObserved !== true
    || value.webdriverSessions !== 1) fail();
  exactInteger(value.arrowTransitions, 1, 200);
  exactInteger(value.homeEndTransitions, 1, 20);
  exactInteger(value.pageTransitions, 1, 20);
  exactInteger(value.stableSelectionCount, 1, 1_000);
  return Object.freeze({ ...value });
}

export function parseA28DomEvidence(bytes) {
  return assertA28DomEvidence(parseCanonicalOneLine(bytes));
}

function assertIdentity(value) {
  exactKeys(value, IDENTITY_KEYS);
  exactSha(value.sourceDigest);
  exactSha(value.productionFingerprint);
  exactSha(value.automationFingerprint);
  exactSha(value.controlledDeltaSha256);
  if (value.sameFrozenSource !== true
    || value.productionFingerprint === value.automationFingerprint) fail();
  return Object.freeze({ ...value });
}

function assertDriver(value) {
  exactKeys(value, DRIVER_KEYS);
  if (value.productionHostileActivationListeners !== 0
    || value.dormantTwinListeners !== 0
    || value.activatedTwinIpv4LoopbackListeners !== 1
    || value.activatedTwinOtherListeners !== 0
    || value.cleanupListeners !== 0
    || value.ipv4LoopbackOnly !== true
    || value.randomHighPort !== true
    || value.webdriverSessions !== 1) fail();
  exactInteger(value.stableSelectionCount, 1, 1_000);
  return Object.freeze({ ...value });
}

function assertAutomation(value) {
  exactKeys(value, AUTOMATION_KEYS);
  assertA28DomEvidence({
    ...value,
    schemaVersion: 1,
    stableSelectionCount: 1,
    webdriverSessions: 1,
  });
  return Object.freeze({ ...value });
}

function assertAccessibilityTree(value) {
  exactKeys(value, ACCESSIBILITY_TREE_KEYS);
  if (value.trusted !== true
    || value.exactPid !== true
    || value.bounded !== true
    || value.roleErrors !== 0
    || value.nameErrors !== 0
    || value.orderErrors !== 0
    || value.focusErrors !== 0
    || value.focusedRows !== 1) fail();
  exactInteger(value.nodesVisited, 1, 4_096);
  exactInteger(value.listRoles, 1, 64);
  exactInteger(value.observedTranscriptRows, 1, 100);
  exactInteger(value.focusedRowOrdinal, 1, 100);
  return Object.freeze({ ...value });
}

function assertVoiceOver(value) {
  return assertA28ComparedVoiceOverEvidence(value);
}

function assertLimitations(value) {
  exactKeys(value, LIMITATION_KEYS);
  if (!isDeepStrictEqual(value, {
    automationConformanceEquivalence: 'not-claimed',
    voiceOverAutomationEquivalence: 'not-claimed',
    wcagConformance: 'not-claimed',
  })) fail();
  return Object.freeze({ ...value });
}

function assertCleanup(value) {
  exactKeys(value, CLEANUP_KEYS);
  if (!isDeepStrictEqual(value, {
    bundlesRevalidated: true,
    webdriverSessionDeleted: true,
    listenerRemoved: true,
    runnerIsolateRemoved: true,
    ownedProcessesAfterCleanup: 0,
  })) fail();
  return Object.freeze({ ...value });
}

export function assertA28AccessibilityEvidence(value) {
  exactKeys(value, TOP_LEVEL_KEYS);
  if (value.schemaVersion !== 1 || value.status !== 'pass') fail();
  return Object.freeze({
    schemaVersion: 1,
    status: 'pass',
    identity: assertIdentity(value.identity),
    driver: assertDriver(value.driver),
    automation: assertAutomation(value.automation),
    accessibilityTree: assertAccessibilityTree(value.accessibilityTree),
    voiceOver: assertVoiceOver(value.voiceOver),
    limitations: assertLimitations(value.limitations),
    cleanup: assertCleanup(value.cleanup),
  });
}

export function parseA28AccessibilityEvidence(bytes) {
  return assertA28AccessibilityEvidence(parseCanonicalOneLine(bytes));
}

function listenerNames(pid) {
  const result = spawnSync(
    '/usr/sbin/lsof',
    ['-nP', '-a', '-p', String(pid), '-iTCP', '-sTCP:LISTEN', '-Fn'],
    {
      encoding: 'utf8',
      env: { PATH: '/usr/bin:/bin' },
      timeout: 5_000,
    },
  );
  if (result.error || result.signal || ![0, 1].includes(result.status)) fail();
  return result.stdout
    .split('\n')
    .filter((line) => line.startsWith('n'))
    .map((line) => line.slice(1));
}

function listenerInventory(live, expectedPort) {
  const names = live.flatMap((entry) => listenerNames(entry.pid));
  const exactName = expectedPort === undefined
    ? undefined
    : `127.0.0.1:${expectedPort}`;
  return Object.freeze({
    exact: exactName === undefined
      ? 0
      : names.filter((name) => name === exactName).length,
    other: names.filter((name) => name !== exactName).length,
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

async function randomFreeHighPort(excluded = new Set()) {
  for (let attempt = 0; attempt < 128; attempt += 1) {
    const port = randomInt(PORT_MIN, PORT_MAX + 1);
    if (!excluded.has(port) && await canBind(port)) return port;
  }
  fail();
}

function transactionFailure(primary, cleanupFailures, message) {
  if (cleanupFailures.length === 0) return primary;
  return new AggregateError([primary, ...cleanupFailures], message);
}

export async function createA28RuntimeIsolate(prefix, dependencies = {}) {
  const {
    chmodPath = chmod,
    makeDirectory = mkdir,
    makeTemporaryDirectory = mkdtemp,
    removeTree = rm,
    resolveRealPath = realpath,
  } = dependencies;
  const requested = await makeTemporaryDirectory(resolve(tmpdir(), prefix));
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
    throw transactionFailure(error, cleanupFailures, 'A.28 isolate setup and cleanup failed');
  }
}

function runtimeEnvironment(isolate, activation) {
  const environment = {
    HOME: resolve(isolate, 'home'),
    CFFIXED_USER_HOME: resolve(isolate, 'home'),
    TMPDIR: `${resolve(isolate, 'tmp')}/`,
    XDG_CACHE_HOME: resolve(isolate, 'cache'),
    XDG_CONFIG_HOME: resolve(isolate, 'config'),
    XDG_DATA_HOME: resolve(isolate, 'data'),
    PIUI_AGENT_ROOT: resolve(isolate, 'agent'),
    PIUI_SESSION_ROOT: resolve(isolate, 'sessions'),
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    LANG: 'en_AU.UTF-8',
    LC_ALL: 'en_AU.UTF-8',
    RUST_BACKTRACE: '0',
  };
  if (!activation) return environment;
  return {
    ...environment,
    PIUI_ARCHITECTURE_TEST_MODE: ACTIVATION_MODE,
    PIUI_ARCHITECTURE_TEST_NONCE: activation.nonce,
    PIUI_ARCHITECTURE_TEST_PORT: String(activation.port),
    TAURI_WEBDRIVER_PORT: String(activation.legacyPort),
    WDIO_EMBEDDED_SERVER: 'true',
  };
}

async function initialiseNegativeLedger(ledger, childPid, signal) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (signal?.aborted) fail();
    try {
      await ledger.initialise(childPid);
      return;
    } catch {
      await sleep(25, undefined, signal ? { signal } : undefined);
    }
  }
  fail();
}

export async function launchA28NegativeRuntime(
  bundle,
  activation,
  signal,
  dependencies = {},
) {
  if (!isRecord(bundle)
    || typeof bundle.appPath !== 'string'
    || typeof bundle.hostPath !== 'string'
    || typeof bundle.nodePath !== 'string'
    || signal?.aborted) fail();
  const {
    closeLog = closeSync,
    createIsolate = createA28RuntimeIsolate,
    createLedger = (options) => new A28RuntimeProcessLedger(options),
    initialiseLedger = initialiseNegativeLedger,
    openLog = openSync,
    removeTree = rm,
    spawnProcess = spawn,
    terminateGroups = terminateRecordedProcessGroupsWithoutObservation,
    waitForSpawn = waitForChildSpawn,
  } = dependencies;
  let isolate;
  let stdoutPath;
  let stderrPath;
  let stdoutFd;
  let stderrFd;
  let child;
  let spawnConfirmed = false;
  let ledger;
  let runtime;
  let setupFailure;
  const cleanupFailures = [];
  try {
    isolate = await createIsolate('piui-a28-negative-');
    stdoutPath = resolve(isolate, 'stdout.log');
    stderrPath = resolve(isolate, 'stderr.log');
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
      a28NegativeRuntimeSandbox({ bundle, isolate }),
      bundle.hostPath,
    ], {
      cwd: isolate,
      env: runtimeEnvironment(isolate, activation),
      detached: true,
      stdio: ['ignore', stdoutFd, stderrFd],
    });
    await waitForSpawn(child);
    spawnConfirmed = true;
    if (!Number.isSafeInteger(child.pid) || child.pid < 2) fail();
    ledger = createLedger({
      hostPath: bundle.hostPath,
      nodePath: bundle.nodePath,
      networkChecker: assertNoNetwork,
    });
    await initialiseLedger(ledger, child.pid, signal);
    runtime = {
      childPid: child.pid,
      isolate,
      ledger,
      removed: false,
      stderrPath,
      stdoutPath,
    };
  } catch (error) {
    setupFailure = error;
  } finally {
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
  const primary = setupFailure ?? new Error('A.28 launch descriptor cleanup failed');
  let ownershipConfirmed = child === undefined
    || (!spawnConfirmed
      && (!Number.isSafeInteger(child.pid) || child.pid < 2));
  if (ledger) {
    try {
      const cleanup = await confirmA28LedgerAbsence(ledger);
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
  } else if (Number.isSafeInteger(child?.pid) && child.pid >= 2) {
    try {
      await terminateGroups([child.pid]);
    } catch (error) {
      cleanupFailures.push(error);
    }
  }
  if (isolate && ownershipConfirmed) {
    try {
      await removeTree(isolate, { recursive: true, force: false });
    } catch (error) {
      cleanupFailures.push(error);
    }
  }
  throw transactionFailure(primary, cleanupFailures, 'A.28 runtime launch and cleanup failed');
}

async function assertNoListenerStability(runtime, signal) {
  for (let index = 0; index < 15; index += 1) {
    if (signal?.aborted) fail();
    const live = await runtime.ledger.sample();
    if (!runtime.ledger.hasLiveHost(live)
      || !isDeepStrictEqual(listenerInventory(live), { exact: 0, other: 0 })) fail();
    await sleep(100);
  }
  return 0;
}

export async function terminateA28NegativeRuntime(runtime) {
  const cleanupFailures = [];
  let ownershipConfirmed = false;
  try {
    const cleanup = await confirmA28LedgerAbsence(runtime.ledger);
    ownershipConfirmed = true;
    if (cleanup.cleanupFailure) cleanupFailures.push(cleanup.cleanupFailure);
    if (cleanup.forced) {
      cleanupFailures.push(
        cleanup.completion ?? new A28ForcedCleanupCompleteError(),
      );
    }
  } catch (error) {
    cleanupFailures.push(error);
  }
  try {
    for (const path of [runtime.stdoutPath, runtime.stderrPath]) {
      const item = await lstat(path);
      if (!item.isFile()
        || item.isSymbolicLink()
        || item.nlink !== 1
        || item.size > MAX_EVIDENCE_BYTES
        || (item.mode & 0o777) !== 0o600) fail();
    }
  } catch (error) {
    cleanupFailures.push(error);
  }
  if (ownershipConfirmed) {
    try {
      await rm(runtime.isolate, { recursive: true, force: false });
      runtime.removed = true;
    } catch (error) {
      cleanupFailures.push(error);
    }
  }
  if (cleanupFailures.length === 1) throw cleanupFailures[0];
  if (cleanupFailures.length > 1) {
    throw new AggregateError(cleanupFailures, 'A.28 negative-runtime cleanup failed');
  }
}

async function runListenerNegative(bundle, activation, signal) {
  const runtime = await launchA28NegativeRuntime(bundle, activation, signal);
  let count;
  let failure;
  try {
    count = await assertNoListenerStability(runtime, signal);
  } catch (error) {
    failure = error;
  } finally {
    try {
      await terminateA28NegativeRuntime(runtime);
    } catch (error) {
      failure = failure
        ? new AggregateError([failure, error], 'A.28 negative observation and cleanup failed')
        : error;
    }
  }
  if (failure) throw failure;
  if (count !== 0 || !runtime.removed) fail();
  return count;
}

function assertStableFileMetadata(item, maximumBytes, privateMode) {
  if (!item.isFile()
    || item.isSymbolicLink?.()
    || item.nlink !== 1
    || item.size < 3
    || item.size > maximumBytes
    || (item.mode & 0o7000) !== 0
    || (privateMode
      ? (item.mode & 0o777) !== 0o600
      : (item.mode & 0o022) !== 0)
    || (typeof process.getuid === 'function' && item.uid !== process.getuid())) fail();
}

async function readStableFileObservation(path, maximumBytes, privateMode) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    assertStableFileMetadata(before, maximumBytes, privateMode);
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const pathname = await lstat(path);
    assertStableFileMetadata(after, maximumBytes, privateMode);
    assertStableFileMetadata(pathname, maximumBytes, privateMode);
    if (before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
      || pathname.dev !== before.dev
      || pathname.ino !== before.ino
      || pathname.size !== before.size
      || pathname.mtimeMs !== before.mtimeMs
      || bytes.length !== before.size) fail();
    return Object.freeze({
      bytes,
      identity: Object.freeze({
        dev: before.dev,
        ino: before.ino,
      }),
    });
  } finally {
    await handle?.close();
  }
}

async function readStableFile(path, maximumBytes, privateMode) {
  return (await readStableFileObservation(path, maximumBytes, privateMode)).bytes;
}

function leaseFilePin(observation) {
  return Object.freeze({
    canonicalLine: observation.bytes.toString('utf8'),
    identity: observation.identity,
  });
}

export function assertA28PinnedLeaseObservation(pin, observation) {
  exactKeys(pin, ['canonicalLine', 'identity']);
  exactKeys(pin.identity, ['dev', 'ino']);
  exactKeys(observation, ['bytes', 'identity']);
  exactKeys(observation.identity, ['dev', 'ino']);
  if (typeof pin.canonicalLine !== 'string'
    || !Buffer.isBuffer(observation.bytes)
    || !isDeepStrictEqual(pin.identity, observation.identity)
    || pin.canonicalLine !== observation.bytes.toString('utf8')) fail();
  return true;
}

function requestedHumanEvidenceRoot() {
  const configured = process.env.PIUI_A28_HUMAN_EVIDENCE_ROOT;
  if (configured !== undefined
    && (configured.length === 0
      || configured.includes('\0')
      || configured.includes('\r')
      || configured.includes('\n')
      || resolve(configured) !== configured)) fail();
  return configured ?? DEFAULT_HUMAN_EVIDENCE_ROOT;
}

async function assertHumanEvidenceRoot() {
  const configured = process.env.PIUI_A28_HUMAN_EVIDENCE_ROOT;
  const requested = requestedHumanEvidenceRoot();
  if (configured === undefined) {
    await mkdir(requested, { recursive: true, mode: 0o700 });
  }
  const canonical = await realpath(requested);
  const item = await lstat(requested);
  if (canonical !== requested
    || !item.isDirectory()
    || item.isSymbolicLink()
    || (item.mode & 0o7000) !== 0
    || (item.mode & 0o022) !== 0
    || (typeof process.getuid === 'function' && item.uid !== process.getuid())) fail();
  return Object.freeze({
    dev: item.dev,
    ino: item.ino,
    path: requested,
  });
}

async function assertHumanEvidenceRootIdentity(rootIdentity) {
  const item = await lstat(rootIdentity.path);
  const canonical = await realpath(rootIdentity.path);
  if (canonical !== rootIdentity.path
    || !item.isDirectory()
    || item.isSymbolicLink()
    || item.dev !== rootIdentity.dev
    || item.ino !== rootIdentity.ino
    || (item.mode & 0o7000) !== 0
    || (item.mode & 0o022) !== 0
    || (typeof process.getuid === 'function' && item.uid !== process.getuid())) fail();
}

async function assertHumanWitnessDirectory(witness) {
  await assertHumanEvidenceRootIdentity(witness.rootIdentity);
  const item = await lstat(witness.evidenceRoot);
  const canonical = await realpath(witness.evidenceRoot);
  if (canonical !== witness.evidenceRoot
    || dirname(witness.evidenceRoot) !== witness.rootIdentity.path
    || !item.isDirectory()
    || item.isSymbolicLink()
    || item.dev !== witness.directoryIdentity.dev
    || item.ino !== witness.directoryIdentity.ino
    || (item.mode & 0o7000) !== 0
    || (item.mode & 0o777) !== 0o700
    || (typeof process.getuid === 'function' && item.uid !== process.getuid())) fail();
}

async function publishPrivateCanonical(path, value) {
  const bytes = Buffer.from(`${canonicalArchitectureJson(value)}\n`, 'utf8');
  if (bytes.length < 3 || bytes.length > MAX_EVIDENCE_BYTES) fail();
  const handle = await open(
    path,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function macosProductVersion() {
  const result = spawnSync(
    '/usr/bin/sw_vers',
    ['-productVersion'],
    {
      encoding: 'utf8',
      env: { PATH: '/usr/bin:/bin' },
      timeout: 5_000,
    },
  );
  const version = result.stdout.trim();
  if (result.error
    || result.status !== 0
    || result.signal
    || result.stderr !== ''
    || !/^\d{1,3}\.\d{1,3}(?:\.\d{1,3})?$/u.test(version)) fail();
  return version;
}

async function createHumanWitnessLease(identity, applicationPid) {
  if (!Number.isSafeInteger(applicationPid) || applicationPid < 2) fail();
  const rootIdentity = await assertHumanEvidenceRoot();
  const witnessNonce = randomBytes(32).toString('hex');
  exactSha(witnessNonce);
  const evidenceRoot = resolve(rootIdentity.path, witnessNonce);
  if (dirname(evidenceRoot) !== rootIdentity.path) fail();
  try {
    await mkdir(evidenceRoot, { mode: 0o700 });
  } catch (error) {
    if (error?.code === 'EEXIST') fail();
    throw error;
  }
  const canonical = await realpath(evidenceRoot);
  const item = await lstat(evidenceRoot);
  if (canonical !== evidenceRoot
    || !item.isDirectory()
    || item.isSymbolicLink()
    || (item.mode & 0o7000) !== 0
    || (item.mode & 0o777) !== 0o700
    || (typeof process.getuid === 'function' && item.uid !== process.getuid())) fail();
  const lease = assertA28HumanWitnessLease({
    applicationPid,
    automationTwinFingerprint: identity.automationFingerprint,
    evidenceDirectory:
      `.forge/evidence/architecture-accessibility/${witnessNonce}`,
    macosVersion: macosProductVersion(),
    productionFingerprint: identity.productionFingerprint,
    schemaVersion: 1,
    sourceDigest: identity.sourceDigest,
    startedAt: new Date().toISOString(),
    state: 'waiting-for-human',
    witnessNonce,
  });
  const leasePath = resolve(evidenceRoot, 'lease.json');
  await publishPrivateCanonical(leasePath, lease);
  const leaseObservation = await readStableFileObservation(
    leasePath,
    MAX_EVIDENCE_BYTES,
    true,
  );
  const acceptedLease = assertA28HumanWitnessLease(
    parseCanonicalOneLine(leaseObservation.bytes),
  );
  if (!isDeepStrictEqual(acceptedLease, lease)) fail();
  const witness = Object.freeze({
    directoryIdentity: Object.freeze({ dev: item.dev, ino: item.ino }),
    evidenceRoot,
    lease,
    leaseFilePin: leaseFilePin(leaseObservation),
    leasePath,
    rootIdentity,
  });
  await assertHumanWitnessDirectory(witness);
  return witness;
}

async function assertHumanWitnessLeaseFile(witness) {
  const observation = await readStableFileObservation(
    witness.leasePath,
    MAX_EVIDENCE_BYTES,
    true,
  );
  assertA28PinnedLeaseObservation(witness.leaseFilePin, observation);
  const acceptedLease = assertA28HumanWitnessLease(
    parseCanonicalOneLine(observation.bytes),
  );
  if (!isDeepStrictEqual(acceptedLease, witness.lease)) fail();
}

async function assertSealedHumanWitness(witness) {
  await assertHumanEvidenceRootIdentity(witness.rootIdentity);
  const directory = await lstat(witness.evidenceRoot);
  if (!directory.isDirectory()
    || directory.isSymbolicLink()
    || directory.dev !== witness.directoryIdentity.dev
    || directory.ino !== witness.directoryIdentity.ino
    || (directory.mode & 0o777) !== 0o500) fail();
  for (const name of ['lease.json', 'voiceover.json', 'completion.json', 'checksums.json']) {
    const item = await lstat(resolve(witness.evidenceRoot, name));
    if (!item.isFile()
      || item.isSymbolicLink()
      || item.nlink !== 1
      || (item.mode & 0o777) !== 0o400) fail();
  }
}

async function sealHumanWitness(witness) {
  await assertHumanWitnessDirectory(witness);
  await assertHumanWitnessLeaseFile(witness);
  const paths = [
    witness.leasePath,
    resolve(witness.evidenceRoot, 'voiceover.json'),
    resolve(witness.evidenceRoot, 'completion.json'),
    resolve(witness.evidenceRoot, 'checksums.json'),
  ];
  const observations = await Promise.all(paths.map(
    (path) => readStableFileObservation(path, MAX_EVIDENCE_BYTES, false),
  ));
  for (const path of paths) await chmod(path, 0o400);
  await chmod(witness.evidenceRoot, 0o500);
  const directory = await lstat(witness.evidenceRoot);
  if (!directory.isDirectory()
    || directory.isSymbolicLink()
    || directory.dev !== witness.directoryIdentity.dev
    || directory.ino !== witness.directoryIdentity.ino
    || (directory.mode & 0o777) !== 0o500) fail();
  for (const [index, path] of paths.entries()) {
    let handle;
    try {
      handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      const before = await handle.stat();
      const bytes = await handle.readFile();
      const after = await handle.stat();
      const pathname = await lstat(path);
      if (!before.isFile()
        || before.isSymbolicLink()
        || before.nlink !== 1
        || (before.mode & 0o777) !== 0o400
        || before.dev !== observations[index].identity.dev
        || before.ino !== observations[index].identity.ino
        || before.dev !== after.dev
        || before.ino !== after.ino
        || before.size !== after.size
        || before.mtimeMs !== after.mtimeMs
        || pathname.dev !== before.dev
        || pathname.ino !== before.ino
        || pathname.size !== before.size
        || pathname.mtimeMs !== before.mtimeMs
        || !bytes.equals(observations[index].bytes)) fail();
    } finally {
      await handle?.close();
    }
  }
  await assertSealedHumanWitness(witness);
}

async function validateHumanEvidence(identity, witness, assertRetainedHost) {
  if (typeof assertRetainedHost !== 'function') fail();
  await assertHumanWitnessDirectory(witness);
  await assertHumanWitnessLeaseFile(witness);
  let voiceOverBytes;
  let completionBytes;
  try {
    [voiceOverBytes, completionBytes] = await Promise.all([
      readStableFile(
        resolve(witness.evidenceRoot, 'voiceover.json'),
        MAX_EVIDENCE_BYTES,
        false,
      ),
      readStableFile(
        resolve(witness.evidenceRoot, 'completion.json'),
        MAX_EVIDENCE_BYTES,
        false,
      ),
    ]);
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw new A28AccessibilityBlockedError('human VoiceOver evidence is incomplete');
    }
    throw error;
  }
  const voiceOver = parseA28VoiceOverEvidence(voiceOverBytes);
  if (voiceOver.macosVersion !== witness.lease.macosVersion
    || Date.parse(voiceOver.observedAt) < Date.parse(witness.lease.startedAt)) fail();
  parseA28VoiceOverCompletion(completionBytes, {
    applicationPid: witness.lease.applicationPid,
    witnessNonce: witness.lease.witnessNonce,
  });
  const checksums = {
    automationTwinFingerprint: identity.automationFingerprint,
    productionFingerprint: identity.productionFingerprint,
    schemaVersion: 1,
    sourceDigest: identity.sourceDigest,
    voiceOverSha256: sha256Bytes(voiceOverBytes),
  };
  await assertRetainedHost();
  const checksumsPath = resolve(witness.evidenceRoot, 'checksums.json');
  await publishPrivateCanonical(checksumsPath, checksums);
  const [stableVoiceOver, stableCompletion, checksumsBytes] = await Promise.all([
    readStableFile(
      resolve(witness.evidenceRoot, 'voiceover.json'),
      MAX_EVIDENCE_BYTES,
      false,
    ),
    readStableFile(
      resolve(witness.evidenceRoot, 'completion.json'),
      MAX_EVIDENCE_BYTES,
      false,
    ),
    readStableFile(checksumsPath, MAX_EVIDENCE_BYTES, true),
  ]);
  if (!stableVoiceOver.equals(voiceOverBytes)
    || !stableCompletion.equals(completionBytes)) fail();
  parseA28VoiceOverChecksums(checksumsBytes, {
    automationTwinFingerprint: identity.automationFingerprint,
    productionFingerprint: identity.productionFingerprint,
    sourceDigest: identity.sourceDigest,
    voiceOverBytes: stableVoiceOver,
  });
  await assertRetainedHost();
  await assertHumanWitnessDirectory(witness);
  await assertHumanWitnessLeaseFile(witness);
  const accepted = Object.freeze({
    evidenceValidated: true,
    checksumsValidated: true,
    // Legacy user-owned files remain useful diagnostics but never carry the
    // formal human-witness authority.
    humanWitnessed: false,
    modesChecked: voiceOver.checks.length,
    blockingDefects: voiceOver.checks.reduce(
      (count, check) => count + check.blockingDefects.length,
      0,
    ),
  });
  await sealHumanWitness(witness);
  return accepted;
}

async function readPackageVersion(packageName, expectedVersion) {
  const packagePath = resolve(root, 'node_modules', packageName, 'package.json');
  const bytes = await readFile(packagePath);
  if (bytes.length < 3 || bytes.length > MAX_EVIDENCE_BYTES) fail();
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail();
  }
  if (!isRecord(manifest)
    || manifest.name !== packageName
    || manifest.version !== expectedVersion) fail();
  return manifest.version;
}

async function assertExactWdioInstall() {
  await Promise.all([
    readPackageVersion('@wdio/tauri-service', EXPECTED_TAURI_SERVICE_VERSION),
    readPackageVersion('@wdio/cli', EXPECTED_WDIO_VERSION),
    readPackageVersion('@wdio/globals', EXPECTED_WDIO_VERSION),
    readPackageVersion('@wdio/local-runner', EXPECTED_WDIO_VERSION),
    readPackageVersion('@wdio/mocha-framework', EXPECTED_WDIO_VERSION),
    readPackageVersion('@wdio/spec-reporter', EXPECTED_WDIO_VERSION),
  ]);
  const cliPath = await realpath(resolve(root, 'node_modules/@wdio/cli/bin/wdio.js'));
  const item = await lstat(cliPath);
  if (!item.isFile() || item.isSymbolicLink() || item.size < 1 || item.size > MAX_EVIDENCE_BYTES) {
    fail();
  }
  return cliPath;
}

function exactHostPids(hostPath) {
  const name = basename(hostPath);
  const candidates = observeProcesses().filter((row) => row.command.includes(name));
  const pids = [];
  for (const row of candidates) {
    try {
      if (executableForPid(row.pid) === hostPath) pids.push(row.pid);
    } catch {
      const stillLive = observeProcesses().some((candidate) =>
        candidate.pid === row.pid && candidate.start === row.start);
      if (stillLive) fail();
    }
  }
  return Object.freeze([...new Set(pids)].sort((left, right) => left - right));
}

async function waitForExactHost(hostPath, signal) {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    if (signal?.aborted) fail();
    const pids = exactHostPids(hostPath);
    if (pids.length > 1) fail();
    if (pids.length === 1) return pids[0];
    await sleep(25, undefined, signal ? { signal } : undefined);
  }
  fail();
}

async function waitForFile(path, signal) {
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    if (signal?.aborted) fail();
    try {
      await lstat(path);
      return;
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    await sleep(25, undefined, signal ? { signal } : undefined);
  }
  fail();
}

async function waitForExactActiveListener(ledger, port, signal) {
  const deadline = Date.now() + 30_000;
  let stable = 0;
  while (Date.now() < deadline) {
    if (signal?.aborted) fail();
    const live = await ledger.sample();
    if (!ledger.hasLiveHost(live)) fail();
    const inventory = listenerInventory(live, port);
    if (isDeepStrictEqual(inventory, { exact: 1, other: 0 })) {
      stable += 1;
      if (stable === 5) return inventory;
    } else if (inventory.exact > 1 || inventory.other > 0) {
      fail();
    } else {
      stable = 0;
    }
    await sleep(50, undefined, signal ? { signal } : undefined);
  }
  fail();
}

async function compileAccessibilityHelper(runRoot, signal) {
  const output = resolve(runRoot, 'tmp', 'inspect-accessibility.compiled');
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
        '-isysroot',
        APPLE_TOOLCHAIN_PATHS.sdk,
        '-framework',
        'ApplicationServices',
        '-framework',
        'CoreFoundation',
        resolve(root, 'scripts/inspect-a28-accessibility.c'),
        '-o',
        output,
      ],
      cwd: resolve(runRoot, 'tmp'),
      env: {
        ...appleToolchainBuildEnvironment(),
        PATH: `${APPLE_TOOLCHAIN_PATHS.bin}:/usr/bin:/bin`,
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
        TMPDIR: `${resolve(runRoot, 'tmp')}/`,
      },
      timeoutMs: 30_000,
      maxOutputBytes: MAX_EVIDENCE_BYTES,
      signal,
      label: 'A.28 accessibility helper compilation',
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
    controlRoot: resolve(runRoot, 'control'),
    executableName: 'inspect-accessibility',
    sourcePath: output,
  });
}

export function classifyA28AccessibilityHelperResult(result, expectedPid) {
  if (!isRecord(result)
    || !Buffer.isBuffer(result.stdout)
    || !Buffer.isBuffer(result.stderr)
    || !Number.isSafeInteger(expectedPid)
    || expectedPid < 2) fail();
  if (result.status === 77
    && result.signal === null
    && result.stdout.length === 0
    && result.stderr.toString('utf8')
      === 'A.28 accessibility permission is required.\n') {
    throw new A28AccessibilityBlockedError('macOS Accessibility permission is missing');
  }
  if (result.status !== 0
    || result.signal !== null
    || result.stderr.length !== 0
    || result.forcedCleanup === true) fail();
  return parseA28AccessibilityTreeEvidence(result.stdout, expectedPid);
}

async function inspectAccessibilityTree(helper, expectedPid, runRoot, signal) {
  await assertPrivateExecutableLease(helper);
  const result = await runOwnedCommand({
    command: '/usr/bin/sandbox-exec',
    args: [
      '-p',
      a28AccessibilityHelperSandbox(helper.path),
      helper.path,
      String(expectedPid),
    ],
    cwd: runRoot,
    env: {
      PATH: '/usr/bin:/bin',
      LANG: 'en_AU.UTF-8',
      LC_ALL: 'en_AU.UTF-8',
    },
    timeoutMs: 15_000,
    maxOutputBytes: MAX_EVIDENCE_BYTES,
    signal,
    label: 'A.28 native accessibility-tree inspection',
  });
  const accepted = classifyA28AccessibilityHelperResult(result, expectedPid);
  await assertPrivateExecutableLease(helper);
  return accepted;
}

async function publishAxRelease(path, nonce) {
  const handle = await open(
    path,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    await handle.writeFile(Buffer.from(`${canonicalArchitectureJson({
      nonce,
      schemaVersion: 1,
      state: 'ax-complete',
    })}\n`, 'utf8'));
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function assertCoordinationEvidence(bytes, nonce, expectedState) {
  const value = parseCanonicalOneLine(bytes, 1_024);
  exactKeys(value, ['nonce', 'schemaVersion', 'state']);
  if (value.schemaVersion !== 1
    || value.nonce !== nonce
    || value.state !== expectedState) fail();
}

function assertHumanVisibleEvidence(bytes, witnessNonce) {
  const value = parseCanonicalOneLine(bytes, 1_024);
  exactKeys(value, ['schemaVersion', 'state', 'witnessNonce']);
  if (value.schemaVersion !== 1
    || value.state !== 'human-visible'
    || value.witnessNonce !== witnessNonce) fail();
}

async function assertExactRetainedHumanWitnessHost({
  bundle,
  hostLedger,
  hostPid,
  port,
}) {
  const live = await hostLedger.sample();
  if (live.length !== 1
    || live[0].pid !== hostPid
    || live[0].executable !== bundle.hostPath
    || !isDeepStrictEqual(
      listenerInventory(live, port),
      { exact: 1, other: 0 },
    )
    || !isDeepStrictEqual(exactHostPids(bundle.hostPath), [hostPid])) fail();
}

async function waitForHumanWitness({
  bundle,
  hostLedger,
  hostPid,
  humanReadyPath,
  humanVisiblePath,
  identity,
  port,
  signal,
  wdioPromise,
}) {
  const witness = await createHumanWitnessLease(identity, hostPid);
  await publishPrivateCanonical(humanReadyPath, witness.lease);
  const wdioOutcome = wdioPromise.then(
    (result) => ({ result, type: 'exit' }),
    (error) => ({ error, type: 'error' }),
  );
  const visibleOutcome = await Promise.race([
    waitForFile(humanVisiblePath, signal)
      .then(() => ({ type: 'visible' })),
    wdioOutcome,
  ]);
  if (visibleOutcome.type !== 'visible') fail();
  assertHumanVisibleEvidence(
    await readStableFile(humanVisiblePath, 1_024, true),
    witness.lease.witnessNonce,
  );
  await assertHumanWitnessDirectory(witness);
  await assertExactRetainedHumanWitnessHost({
    bundle,
    hostLedger,
    hostPid,
    port,
  });

  const completionPath = resolve(witness.evidenceRoot, 'completion.json');
  const deadline = Date.now() + HUMAN_WITNESS_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (signal?.aborted) fail();
    await assertHumanWitnessDirectory(witness);
    await assertExactRetainedHumanWitnessHost({
      bundle,
      hostLedger,
      hostPid,
      port,
    });
    try {
      const item = await lstat(completionPath);
      if (!item.isFile() || item.isSymbolicLink() || item.nlink !== 1) fail();
      const voiceOver = await validateHumanEvidence(
        identity,
        witness,
        () => assertExactRetainedHumanWitnessHost({
          bundle,
          hostLedger,
          hostPid,
          port,
        }),
      );
      await assertSealedHumanWitness(witness);
      await assertExactRetainedHumanWitnessHost({
        bundle,
        hostLedger,
        hostPid,
        port,
      });
      return voiceOver;
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    const outcome = await Promise.race([
      sleep(250, undefined, signal ? { signal } : undefined)
        .then(() => ({ type: 'tick' })),
      wdioOutcome,
    ]);
    if (outcome.type !== 'tick') fail();
  }
  throw new A28AccessibilityBlockedError(
    'human VoiceOver evidence was not completed within 30 minutes',
  );
}

async function holdWdioForFormalWitness({
  bundle,
  hostLedger,
  hostPid,
  humanReadyPath,
  humanVisiblePath,
  identity,
  port,
  signal,
  wdioPromise,
}) {
  const diagnostic = await createHumanWitnessLease(identity, hostPid);
  await publishPrivateCanonical(humanReadyPath, diagnostic.lease);
  const outcome = await Promise.race([
    waitForFile(humanVisiblePath, signal).then(() => ({ type: 'visible' })),
    wdioPromise.then(
      () => ({ type: 'exit' }),
      () => ({ type: 'error' }),
    ),
  ]);
  if (outcome.type !== 'visible') fail();
  assertHumanVisibleEvidence(
    await readStableFile(humanVisiblePath, 1_024, true),
    diagnostic.lease.witnessNonce,
  );
  await assertHumanWitnessDirectory(diagnostic);
  await assertHumanWitnessLeaseFile(diagnostic);
  await assertExactRetainedHumanWitnessHost({
    bundle,
    hostLedger,
    hostPid,
    port,
  });
  return diagnostic;
}

function exactWdioRunner(cliPath) {
  const expectedCommand = [
    process.execPath,
    cliPath,
    'run',
    resolve(root, 'wdio.conf.ts'),
  ].join(' ');
  const matches = observeProcesses().filter((row) => {
    if (row.command !== expectedCommand || row.state?.startsWith('Z')) return false;
    try {
      return executableForPid(row.pid) === process.execPath;
    } catch {
      return false;
    }
  });
  if (matches.length !== 1 || matches[0].pid === process.pid) fail();
  return Object.freeze({
    executablePath: process.execPath,
    pid: matches[0].pid,
    start: matches[0].start,
  });
}

async function createFinalConsumerDirectory(repositoryRoot, architectureGateRun) {
  const path = resolve(
    repositoryRoot,
    '.forge/evidence/architecture-gate/runs',
    architectureGateRun.runId,
    'a28-final-consumer',
  );
  await mkdir(path, { mode: 0o700 });
  const item = await lstat(path);
  const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
  if (!item.isDirectory()
    || item.isSymbolicLink()
    || item.uid !== uid
    || (item.mode & 0o777) !== 0o700
    || await realpath(path) !== path) fail();
  return path;
}

function mapAccessibilityTree(tree) {
  return Object.freeze({
    trusted: tree.trusted,
    exactPid: tree.applicationPidMatched,
    bounded: tree.bounded,
    nodesVisited: tree.nodesVisited,
    listRoles: tree.listRoles,
    observedTranscriptRows: tree.namedTranscriptRows,
    roleErrors: tree.listItemRoles === tree.namedTranscriptRows ? 0 : 1,
    nameErrors: tree.listItemRoles === tree.namedTranscriptRows ? 0 : 1,
    orderErrors: tree.orderedTranscriptRows ? 0 : 1,
    focusErrors: tree.focusedTranscriptRows === 1 ? 0 : 1,
    focusedRows: tree.focusedTranscriptRows,
    focusedRowOrdinal: tree.focusedRowOrdinal,
  });
}

function mapAutomation(dom) {
  return Object.freeze(Object.fromEntries(
    AUTOMATION_KEYS.map((key) => [key, dom[key]]),
  ));
}

async function executeWdioObservation(
  bundle,
  port,
  nonce,
  identity,
  signal,
  finalConsumer,
) {
  if (exactHostPids(bundle.hostPath).length !== 0) fail();
  const runRoot = await createA28RuntimeIsolate('piui-a28-wdio-');
  const domEvidencePath = resolve(runRoot, 'dom-evidence.json');
  const axReadyPath = resolve(runRoot, 'ax-ready.json');
  const axReleasePath = resolve(runRoot, 'ax-release.json');
  const humanReadyPath = resolve(runRoot, 'human-ready.json');
  const humanVisiblePath = resolve(runRoot, 'human-visible.json');
  const localCutoff = new AbortController();
  const combinedSignal = signal
    ? AbortSignal.any([signal, localCutoff.signal])
    : localCutoff.signal;
  let hostLedger;
  let hostPid;
  let activeInventory;
  let dom;
  let tree;
  let voiceOver;
  let helper;
  let wdioPromise;
  let wdioResult;
  let releasePublished = false;
  let runRootRemoved = false;
  let listenerRemoved = false;
  let ownedProcessesAfterCleanup;
  let failure;
  let blocked;
  let finalContextLease;
  let installedWitness;
  try {
    helper = await compileAccessibilityHelper(runRoot, signal);
    const cliPath = await assertExactWdioInstall();
    const sandbox = a28WdioSandbox({
      bundle,
      controlRoot: helper.controlRoot.path,
      evidenceRoot: requestedHumanEvidenceRoot(),
      port,
      repositoryRoot: root,
      runRoot,
      runnerPath: process.execPath,
    });
    authoriseAuthenticatedNodeSandboxProfile({
      command: process.execPath,
      policy: Object.freeze({
        expectedProfileSha256: createHash('sha256').update(sandbox).digest('hex'),
        hostPath: bundle.hostPath,
        kind: 'a28-loopback',
        nodePath: bundle.nodePath,
        port,
        runnerPath: process.execPath,
      }),
      profile: sandbox,
    });
    wdioPromise = runOwnedCommand({
      command: process.execPath,
      args: [
        cliPath,
        'run',
        resolve(root, 'wdio.conf.ts'),
      ],
      cwd: root,
      env: {
        ...runtimeEnvironment(runRoot, undefined),
        NO_COLOR: '1',
        OPENSSL_CONF: '/System/Library/OpenSSL/openssl.cnf',
        PIUI_ARCHITECTURE_TEST_MODE: ACTIVATION_MODE,
        PIUI_ARCHITECTURE_TEST_NONCE: nonce,
        PIUI_ARCHITECTURE_TEST_PORT: String(port),
        PIUI_A28_APP_BINARY: bundle.hostPath,
        PIUI_A28_RUN_ROOT: runRoot,
        PIUI_A28_DOM_EVIDENCE: domEvidencePath,
        PIUI_A28_AX_READY: axReadyPath,
        PIUI_A28_AX_RELEASE: axReleasePath,
        PIUI_A28_HUMAN_READY: humanReadyPath,
        PIUI_A28_HUMAN_VISIBLE: humanVisiblePath,
      },
      timeoutMs: 35 * 60_000,
      maxOutputBytes: MAX_WDIO_OUTPUT_BYTES,
      sandboxProfile: sandbox,
      signal: combinedSignal,
      label: 'A.28 WDIO packaged accessibility run',
    });
    const hostOutcome = await Promise.race([
      waitForExactHost(bundle.hostPath, combinedSignal)
        .then((pid) => ({ type: 'host', pid })),
      wdioPromise.then(
        (result) => ({ type: 'exit', result }),
        (error) => ({ type: 'error', error }),
      ),
    ]);
    if (hostOutcome.type !== 'host') fail();
    hostPid = hostOutcome.pid;
    hostLedger = new A28RuntimeProcessLedger({
      hostPath: bundle.hostPath,
      nodePath: bundle.nodePath,
      networkChecker: createLifecycleNetworkChecker({
        hostPid,
        driverPort: port,
      }),
    });
    await hostLedger.initialise(hostPid);
    activeInventory = await waitForExactActiveListener(
      hostLedger,
      port,
      combinedSignal,
    );

    const checkpointOutcome = await Promise.race([
      waitForFile(axReadyPath, combinedSignal).then(() => ({ type: 'checkpoint' })),
      wdioPromise.then(
        (result) => ({ type: 'exit', result }),
        (error) => ({ type: 'error', error }),
      ),
    ]);
    if (checkpointOutcome.type !== 'checkpoint') fail();
    const liveAtCheckpoint = await hostLedger.sample();
    if (liveAtCheckpoint.filter((entry) =>
      entry.executable === bundle.hostPath && entry.pid === hostPid).length !== 1
      || !isDeepStrictEqual(
        listenerInventory(liveAtCheckpoint, port),
        { exact: 1, other: 0 },
      )) fail();

    const checkpointBytes = await readStableFile(axReadyPath, 1_024, true);
    assertCoordinationEvidence(checkpointBytes, nonce, 'ax-ready');
    dom = parseA28DomEvidence(
      await readStableFile(domEvidencePath, MAX_EVIDENCE_BYTES, true),
    );
    try {
      tree = await inspectAccessibilityTree(
        helper,
        hostPid,
        runRoot,
        combinedSignal,
      );
    } catch (error) {
      if (error instanceof A28AccessibilityBlockedError) blocked = error;
      else throw error;
    }
    if (!blocked) {
      try {
        await holdWdioForFormalWitness({
          bundle,
          hostLedger,
          hostPid,
          humanReadyPath,
          humanVisiblePath,
          identity,
          port,
          signal: combinedSignal,
          wdioPromise,
        });
        const wdioRunner = exactWdioRunner(cliPath);
        const runnerState = await lstat(wdioRunner.executablePath);
        if (!runnerState.isFile()
          || runnerState.isSymbolicLink()
          || runnerState.nlink !== 1
          || ![0o500, 0o555].includes(runnerState.mode & 0o777)
          || runnerState.size < 1) fail();
        const contextDirectory = await createFinalConsumerDirectory(
          finalConsumer.repositoryRoot,
          finalConsumer.architectureGateRun,
        );
        finalContextLease = await createA28FinalConsumerContext({
          architectureGateRun: finalConsumer.architectureGateRun,
          automationBundle: {
            appPath: bundle.appPath,
            bundleIdentifier: A28_AUTOMATION_BUNDLE_ID,
            fingerprint: bundle.fingerprint,
            hostIdentity: bundle.hostIdentity,
            hostPath: bundle.hostPath,
            hostSigningIdentity: bundle.hostSigningIdentity,
          },
          consumerAnchors: finalConsumer.consumerAnchors,
          contextDirectory,
          hostPid,
          measuredDelta: finalConsumer.measuredDelta,
          productionBundle: {
            appPath: finalConsumer.productionBundle.appPath,
            fingerprint: finalConsumer.productionBundle.fingerprint,
          },
          repositoryRoot: finalConsumer.repositoryRoot,
          runner: {
            executablePath: wdioRunner.executablePath,
            executableSha256: A28_OFFICIAL_NODE_SIGNING_IDENTITY.executableSha256,
            executableSize: runnerState.size,
            pid: wdioRunner.pid,
            signingIdentity: finalConsumer.runnerSigningIdentity,
          },
          sourceDigest: identity.sourceDigest,
        });
        installedWitness = await createA28InstalledWitnessCeremony({
          contextDirectory,
          repositoryRoot: finalConsumer.repositoryRoot,
          runnerSigningIdentity: finalConsumer.runnerSigningIdentity,
          signal: combinedSignal,
          timeoutMs: HUMAN_WITNESS_TIMEOUT_MS,
        });
        try {
          voiceOver = await executeA28FinalConsumerCeremony({
            ceremony: installedWitness.ceremony,
            contextLease: finalContextLease,
            now: () => Date.now(),
          });
        } finally {
          // The final-consumer executor consumes or releases the lease on every
          // entered ceremony path. The retained evidence files are never removed.
          finalContextLease = undefined;
        }
        await installedWitness.dispose();
        installedWitness = undefined;
      } catch (error) {
        if (error instanceof A28AccessibilityBlockedError) blocked = error;
        else throw error;
      }
    }
    await publishAxRelease(axReleasePath, nonce);
    releasePublished = true;
    wdioResult = await wdioPromise;
    if (wdioResult.status !== 0
      || wdioResult.signal !== null
      || wdioResult.forcedCleanup) fail();
    const liveAfter = await hostLedger.sample();
    ownedProcessesAfterCleanup = liveAfter.length;
    if (ownedProcessesAfterCleanup !== 0
      || exactHostPids(bundle.hostPath).length !== 0) fail();
    listenerRemoved = await canBind(port);
    if (!listenerRemoved
      || !isDeepStrictEqual(
        listenerInventory(liveAfter, port),
        { exact: 0, other: 0 },
      )) fail();
  } catch (error) {
    failure = error;
  } finally {
    if (finalContextLease) {
      try {
        await releaseA28FinalConsumerContext(finalContextLease);
        finalContextLease = undefined;
      } catch (error) {
        failure = failure
          ? new AggregateError([failure, error], 'A.28 observation and context release failed')
          : error;
      }
    }
    if (installedWitness) {
      try {
        await installedWitness.dispose();
        installedWitness = undefined;
      } catch (error) {
        failure = failure
          ? new AggregateError([failure, error], 'A.28 observation and witness cleanup failed')
          : error;
      }
    }
    if (!releasePublished) {
      try {
        const readyItem = await lstat(axReadyPath);
        if (readyItem.isFile()) {
          await publishAxRelease(axReleasePath, nonce);
          releasePublished = true;
        }
      } catch (error) {
        if (error?.code !== 'ENOENT') {
          failure = failure
            ? new AggregateError([failure, error], 'A.28 observation and release cleanup failed')
            : error;
        }
      }
    }
    if (failure) localCutoff.abort(failure);
    if (wdioPromise) {
      try {
        wdioResult ??= await wdioPromise;
      } catch (error) {
        failure = failure
          ? new AggregateError([failure, error], 'A.28 observation and command cleanup failed')
          : error;
      }
    }
    const commandOwnershipConfirmed = wdioPromise === undefined || wdioResult !== undefined;
    let hostOwnershipConfirmed = hostLedger === undefined;
    try {
      if (hostLedger) {
        const live = await hostLedger.sample();
        if (live.length === 0) {
          hostOwnershipConfirmed = true;
        } else {
          const cleanup = await confirmA28LedgerAbsence(hostLedger);
          hostOwnershipConfirmed = true;
          if (cleanup.cleanupFailure) {
            failure = failure
              ? new AggregateError(
                [failure, cleanup.cleanupFailure],
                'A.28 observation and host identity verification failed',
              )
              : cleanup.cleanupFailure;
          }
          const survivorError = new Error(
            'A.28 WDIO host required final identity-safe cleanup',
          );
          failure = failure
            ? new AggregateError(
              [failure, survivorError],
              'A.28 observation and host cleanup failed',
            )
            : survivorError;
        }
      }
    } catch (error) {
      hostOwnershipConfirmed = false;
      failure = failure
        ? new AggregateError([failure, error], 'A.28 observation and ownership cleanup failed')
        : error;
    }
    let exactHostIdentityAbsent;
    try {
      exactHostIdentityAbsent = exactHostPids(bundle.hostPath).length === 0;
    } catch (error) {
      hostOwnershipConfirmed = false;
      failure = failure
        ? new AggregateError([failure, error], 'A.28 observation and identity cleanup failed')
        : error;
    }
    if (exactHostIdentityAbsent === false) {
      hostOwnershipConfirmed = false;
      const identityError = new Error('A.28 packaged host identity survived cleanup');
      failure = failure
        ? new AggregateError([failure, identityError], 'A.28 observation and identity cleanup failed')
        : identityError;
    }
    const ownershipConfirmed = commandOwnershipConfirmed && hostOwnershipConfirmed;
    if (ownershipConfirmed) {
      let releasedHelper;
      try {
        if (helper) {
          await releasePrivateExecutableLeaseForRemoval(helper);
          releasedHelper = helper;
        }
        await rm(runRoot, { recursive: true, force: false });
        runRootRemoved = true;
      } catch (error) {
        if (releasedHelper) {
          try {
            await chmod(releasedHelper.controlRoot.path, 0o500);
          } catch (restoreError) {
            error = new AggregateError(
              [error, restoreError],
              'A.28 isolate cleanup and control reseal failed',
            );
          }
        }
        failure = failure
          ? new AggregateError([failure, error], 'A.28 observation and isolate cleanup failed')
          : error;
      }
    }
  }
  if (failure) throw failure;
  if (!runRootRemoved
    || !activeInventory
    || !dom
    || !listenerRemoved
    || ownedProcessesAfterCleanup !== 0
    || !wdioResult
    || !releasePublished) fail();
  if (blocked) throw blocked;
  if (!tree || !voiceOver) fail();
  return Object.freeze({
    activeInventory,
    accessibilityTree: mapAccessibilityTree(tree),
    dom,
    listenerRemoved,
    ownedProcessesAfterCleanup,
    runRootRemoved,
    voiceOver,
    webdriverSessionDeleted: true,
  });
}

function validateExecutionInput(input) {
  exactKeys(input, [
    'architectureGateRun',
    'automationBundle',
    'consumerAnchors',
    'measuredDelta',
    'productionBundle',
    'repositoryRoot',
    'runnerSigningIdentity',
    'signal',
    'sourceDigest',
  ]);
  exactSha(input.sourceDigest);
  exactKeys(input.architectureGateRun, ['contextSha256', 'runId']);
  exactKeys(input.consumerAnchors, FINAL_CONSUMER_ANCHOR_KEYS);
  exactKeys(input.measuredDelta, ['record', 'sha256']);
  exactSha(input.architectureGateRun.contextSha256);
  exactSha(input.measuredDelta.sha256);
  for (const value of Object.values(input.consumerAnchors)) exactSha(value);
  if (!/^\d{8}T\d{9}Z-[0-9a-f]{32}$/u.test(input.architectureGateRun.runId)
    || typeof input.repositoryRoot !== 'string'
    || resolve(input.repositoryRoot) !== input.repositoryRoot
    || !isDeepStrictEqual(
      input.runnerSigningIdentity,
      A28_OFFICIAL_NODE_SIGNING_IDENTITY,
    )
    || sha256Bytes(Buffer.from(
      canonicalArchitectureJson(input.measuredDelta.record),
      'utf8',
    )) !== input.measuredDelta.sha256) fail();
  if (!isRecord(input.productionBundle)
    || !isRecord(input.automationBundle)
    || typeof input.productionBundle.fingerprint !== 'string'
    || typeof input.automationBundle.fingerprint !== 'string'
    || !SHA256.test(input.productionBundle.fingerprint)
    || !SHA256.test(input.automationBundle.fingerprint)
    || input.productionBundle.fingerprint === input.automationBundle.fingerprint
    || typeof input.productionBundle.hostPath !== 'string'
    || typeof input.productionBundle.nodePath !== 'string'
    || typeof input.automationBundle.hostPath !== 'string'
    || typeof input.automationBundle.nodePath !== 'string'
    || !isRecord(input.automationBundle.hostSigningIdentity)) fail();
}

export async function executeAuthoritativeAccessibilityProbe(input) {
  validateExecutionInput(input);
  const {
    architectureGateRun,
    automationBundle,
    consumerAnchors,
    measuredDelta,
    productionBundle,
    repositoryRoot,
    runnerSigningIdentity,
    signal,
    sourceDigest,
  } = input;
  const controlledDeltaSha256 = measuredDelta.sha256;
  await assertExactWdioInstall();
  await revalidateBundle(productionBundle);
  await revalidateBundle(automationBundle);

  const hostilePort = await randomFreeHighPort();
  const hostileLegacyPort = await randomFreeHighPort(new Set([hostilePort]));
  const productionListeners = await runListenerNegative(productionBundle, {
    legacyPort: hostileLegacyPort,
    nonce: randomBytes(32).toString('hex'),
    port: hostilePort,
  }, signal);
  if (!(await canBind(hostilePort)) || !(await canBind(hostileLegacyPort))) fail();

  const dormantListeners = await runListenerNegative(
    automationBundle,
    undefined,
    signal,
  );
  const activePort = await randomFreeHighPort();
  const activeNonce = randomBytes(32).toString('hex');
  validateA28ActivationEnvironment({
    PIUI_ARCHITECTURE_TEST_MODE: ACTIVATION_MODE,
    PIUI_ARCHITECTURE_TEST_NONCE: activeNonce,
    PIUI_ARCHITECTURE_TEST_PORT: String(activePort),
  });

  const identity = Object.freeze({
    sourceDigest,
    productionFingerprint: productionBundle.fingerprint,
    automationFingerprint: automationBundle.fingerprint,
    controlledDeltaSha256,
    sameFrozenSource: true,
  });
  const observed = await executeWdioObservation(
    automationBundle,
    activePort,
    activeNonce,
    identity,
    signal,
    Object.freeze({
      architectureGateRun,
      consumerAnchors,
      measuredDelta,
      productionBundle,
      repositoryRoot,
      runnerSigningIdentity,
    }),
  );
  await revalidateBundle(productionBundle);
  await revalidateBundle(automationBundle);

  return assertA28AccessibilityEvidence({
    schemaVersion: 1,
    status: 'pass',
    identity,
    driver: {
      productionHostileActivationListeners: productionListeners,
      dormantTwinListeners: dormantListeners,
      activatedTwinIpv4LoopbackListeners: observed.activeInventory.exact,
      activatedTwinOtherListeners: observed.activeInventory.other,
      cleanupListeners: 0,
      ipv4LoopbackOnly: true,
      randomHighPort: activePort >= PORT_MIN && activePort <= PORT_MAX,
      webdriverSessions: observed.dom.webdriverSessions,
      stableSelectionCount: observed.dom.stableSelectionCount,
    },
    automation: mapAutomation(observed.dom),
    accessibilityTree: observed.accessibilityTree,
    voiceOver: observed.voiceOver,
    limitations: {
      automationConformanceEquivalence: 'not-claimed',
      voiceOverAutomationEquivalence: 'not-claimed',
      wcagConformance: 'not-claimed',
    },
    cleanup: {
      bundlesRevalidated: true,
      webdriverSessionDeleted: observed.webdriverSessionDeleted,
      listenerRemoved: observed.listenerRemoved,
      runnerIsolateRemoved: observed.runRootRemoved,
      ownedProcessesAfterCleanup: observed.ownedProcessesAfterCleanup,
    },
  });
}

export async function runAuthoritativeA28Command() {
  throw new A28AccessibilityBlockedError(
    'standalone A.28 has no formal gate context; run `pnpm gate:architecture:record`',
  );
}

export function classifyA28AuthoritativeCommandResult(result) {
  if (!isRecord(result)
    || !Buffer.isBuffer(result.stdout)
    || !Buffer.isBuffer(result.stderr)) fail();
  if (result.status === 2
    && result.signal === null
    && result.stdout.length === 0
    && result.stderr.toString('utf8') === BLOCKED_PACKAGE_STDERR
    && result.forcedCleanup === false) {
    throw new A28AccessibilityBlockedError(
      'the packaged proof reported an unmet human or macOS Accessibility prerequisite',
    );
  }
  if (result.status !== 0
      || result.signal !== null
      || result.stderr.length !== 0
      || result.forcedCleanup) fail();
  return parseA28AccessibilityEvidence(result.stdout);
}

if (process.argv[1]
  && import.meta.url === new URL(`file://${resolve(process.argv[1])}`).href) {
  runAuthoritativeA28Command().catch((error) => {
    if (error instanceof A28AccessibilityBlockedError) {
      console.error(error.message);
      process.exitCode = 2;
      return;
    }
    console.error('A.28 packaged accessibility probe rejected');
    process.exitCode = 1;
  });
}
