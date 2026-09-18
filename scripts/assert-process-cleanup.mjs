import { spawnSync } from 'node:child_process';
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  lstatSync,
  openSync,
  realpathSync,
} from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { isDeepStrictEqual } from 'node:util';

const MAX_EVIDENCE_BYTES = 65_536;
const LOCK_DESCRIPTOR = 3;
const EX_TEMPFAIL = 75;
const REJECTED = 'A.27 packaged lifecycle probe rejected';

export const A27_EXPECTED_EVIDENCE = Object.freeze({
  schemaVersion: 1,
  status: 'pass',
  productionBundleValidated: true,
  architectureTestTwinValidated: true,
  sourceFingerprintMatched: true,
  lastWindowCloseEvents: 1,
  reopenEvents: 1,
  sidecarsAfterClose: 0,
  duplicateStartRequests: 2,
  duplicateStartUniquePids: 1,
  duplicateStartUniqueGenerations: 1,
  maximumConcurrentHosts: 1,
  maximumConcurrentSidecars: 1,
  forcedSidecarDeaths: 1,
  automaticRecoveries: 1,
  automaticRecoveryGenerationDelta: 1,
  userRestartRequests: 1,
  userRestartGenerationDelta: 1,
  waitingApprovalsBeforeDeath: 1,
  generationLostApprovals: 1,
  pendingApprovalsAfterRecovery: 0,
  staleApprovalReplayRejections: 1,
  postDeathDelegateExecutions: 0,
  sidecarGenerationsObserved: 4,
  sidecarGenerationsWithoutLockDescriptor: 4,
  inheritedDescriptorLeaks: 0,
  ownershipLockContended: true,
  ownershipLockReleased: true,
  networkDescriptorsObserved: 0,
  exitRequestedObserved: true,
  exitObserved: true,
  ownedProcessesAfterQuit: 0,
  gracefulQuit: true,
  runnerIsolateRemoved: true,
  generatedOutputsRemoved: true,
});

export const A27_NATIVE_EVIDENCE_KEYS = Object.freeze([
  'schemaVersion',
  'status',
  'lastWindowCloseEvents',
  'reopenEvents',
  'sidecarsAfterClose',
  'duplicateStartRequests',
  'duplicateStartUniquePids',
  'duplicateStartUniqueGenerations',
  'forcedSidecarDeaths',
  'automaticRecoveries',
  'automaticRecoveryGenerationDelta',
  'userRestartRequests',
  'userRestartGenerationDelta',
  'waitingApprovalsBeforeDeath',
  'generationLostApprovals',
  'pendingApprovalsAfterRecovery',
  'staleApprovalReplayRejections',
  'postDeathDelegateExecutions',
  'sidecarGenerationsObserved',
  'exitRequestedObserved',
  'exitObserved',
  'gracefulQuit',
]);

const A27_EXTERNAL_EVIDENCE_KEYS = Object.freeze(
  Object.keys(A27_EXPECTED_EVIDENCE)
    .filter((key) => !A27_NATIVE_EVIDENCE_KEYS.includes(key)),
);

function fail() {
  throw new Error(REJECTED);
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || !isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort())) fail();
}

function parseOneLine(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 3 || bytes.length > MAX_EVIDENCE_BYTES) fail();
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail();
  }
  if (!text.endsWith('\n') || text.includes('\r') || text.slice(0, -1).includes('\n')) fail();
  try {
    return JSON.parse(text.slice(0, -1));
  } catch {
    fail();
  }
}

function assertExpectedValues(value, keys) {
  exactKeys(value, keys);
  for (const key of keys) {
    const expected = A27_EXPECTED_EVIDENCE[key];
    if (typeof value[key] !== typeof expected || value[key] !== expected) fail();
    if (typeof value[key] === 'number'
      && (!Number.isSafeInteger(value[key]) || value[key] < 0)) fail();
  }
}

export function parseLifecycleEvidence(bytes) {
  const value = parseOneLine(bytes);
  assertExpectedValues(value, Object.keys(A27_EXPECTED_EVIDENCE));
  return Object.freeze({ ...A27_EXPECTED_EVIDENCE });
}

export function parseNativeLifecycleEvidence(bytes) {
  const value = parseOneLine(bytes);
  assertExpectedValues(value, A27_NATIVE_EVIDENCE_KEYS);
  return Object.freeze(
    Object.fromEntries(A27_NATIVE_EVIDENCE_KEYS.map((key) => [key, value[key]])),
  );
}

export function mergeLifecycleEvidence(nativeEvidence, externalEvidence) {
  assertExpectedValues(nativeEvidence, A27_NATIVE_EVIDENCE_KEYS);
  assertExpectedValues(externalEvidence, A27_EXTERNAL_EVIDENCE_KEYS);
  const merged = { ...nativeEvidence, ...externalEvidence };
  assertExpectedValues(merged, Object.keys(A27_EXPECTED_EVIDENCE));
  return Object.freeze(merged);
}

function assertOwnerPrivateDirectory(path) {
  const canonical = realpathSync(path);
  const item = lstatSync(canonical);
  if (canonical !== path || !item.isDirectory() || item.isSymbolicLink()
    || (item.mode & 0o777) !== 0o700
    || (typeof process.getuid === 'function' && item.uid !== process.getuid())) fail();
}

function assertOwnerPrivateLockFile(item) {
  if (!item.isFile() || item.isSymbolicLink?.() || item.nlink !== 1
    || (item.mode & 0o777) !== 0o600
    || (typeof process.getuid === 'function' && item.uid !== process.getuid())) fail();
}

/**
 * Open, but deliberately do not lock, one private inode for descriptor 3.
 * The spawned architecture-test host acquires the BSD flock and immediately
 * marks descriptor 3 close-on-exec before it can start the Node sidecar.
 */
export function openLifecycleOwnershipDescriptor(lockPath) {
  const requested = resolve(lockPath);
  if (requested !== lockPath) fail();
  assertOwnerPrivateDirectory(dirname(requested));
  const fd = openSync(
    requested,
    constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    fchmodSync(fd, 0o600);
    const opened = fstatSync(fd);
    assertOwnerPrivateLockFile(opened);
    return {
      fd,
      path: requested,
      dev: opened.dev,
      ino: opened.ino,
      descriptor: LOCK_DESCRIPTOR,
      closed: false,
    };
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

export function closeLifecycleOwnershipDescriptor(descriptor) {
  if (!descriptor || descriptor.closed === true || descriptor.descriptor !== LOCK_DESCRIPTOR) fail();
  const item = fstatSync(descriptor.fd);
  if (item.dev !== descriptor.dev || item.ino !== descriptor.ino) fail();
  closeSync(descriptor.fd);
  descriptor.closed = true;
  // The caller owns the mutable descriptor record. Do not unlink the stable
  // lock pathname; the containing generated isolate owns eventual cleanup.
}

function runLockContender(lockPath) {
  const result = spawnSync(
    '/usr/bin/lockf',
    ['-s', '-t', '0', '-k', lockPath, '/usr/bin/true'],
    {
      encoding: 'utf8',
      env: { PATH: '/usr/bin:/bin' },
      timeout: 5_000,
    },
  );
  if (result.error || result.signal || result.stdout !== '' || result.stderr !== '') fail();
  return result.status;
}

export function assertOwnershipLockContended(lockPath) {
  if (runLockContender(lockPath) !== EX_TEMPFAIL) fail();
  return true;
}

export function assertOwnershipLockReleased(lockPath) {
  if (runLockContender(lockPath) !== 0) fail();
  return true;
}

function validPid(pid) {
  return Number.isSafeInteger(pid) && pid > 1;
}

function descriptorListing(pid, descriptor) {
  if (!validPid(pid) || !Number.isSafeInteger(descriptor) || descriptor < 0) fail();
  const result = spawnSync(
    '/usr/sbin/lsof',
    ['-a', '-p', String(pid), '-d', String(descriptor), '-Fn'],
    { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' }, timeout: 5_000 },
  );
  if (result.error || result.signal || ![0, 1].includes(result.status)) fail();
  return result.stdout;
}

export function assertHostOwnsLockDescriptor(pid, descriptor, lockPath) {
  const listing = descriptorListing(pid, descriptor.descriptor);
  const names = listing.split('\n').filter((line) => line.startsWith('n')).map((line) => line.slice(1));
  if (names.length !== 1 || names[0] !== lockPath) fail();
  return true;
}

export function assertSidecarDoesNotInheritLockDescriptor(pid) {
  if (descriptorListing(pid, LOCK_DESCRIPTOR).trim() !== '') fail();
  return true;
}

export function parseLifecycleNetworkListing(text) {
  if (typeof text !== 'string' || text.includes('\r')) fail();
  const records = [];
  let current;
  for (const line of text.split('\n')) {
    if (!line) continue;
    if (line.startsWith('p')) continue;
    if (line.startsWith('f')) {
      if (current) records.push(current);
      current = { descriptor: line.slice(1) };
      continue;
    }
    if (!current) fail();
    if (line.startsWith('P')) current.protocol = line.slice(1);
    else if (line.startsWith('n')) current.name = line.slice(1);
    else if (line.startsWith('TST=')) current.state = line.slice(4);
    else fail();
  }
  if (current) records.push(current);
  if (records.some((record) => !record.descriptor || !record.protocol || !record.name)) fail();
  return Object.freeze(records.map((record) => Object.freeze(record)));
}

export function assertLifecycleNetworkBoundaryFromListing({
  pid,
  hostPid,
  driverPort,
  listing,
}) {
  if (!validPid(pid) || !validPid(hostPid)
    || !Number.isSafeInteger(driverPort) || driverPort < 49_152 || driverPort > 65_535) fail();
  const records = parseLifecycleNetworkListing(listing);
  if (pid !== hostPid) {
    if (records.length !== 0) fail();
    return 0;
  }
  const listener = `127.0.0.1:${driverPort}`;
  const connection = new RegExp(`^127\\.0\\.0\\.1:${driverPort}->127\\.0\\.0\\.1:([1-9][0-9]{0,4})$`);
  const isAuthorisedConnection = (record) => {
    const match = connection.exec(record.name);
    return match !== null && Number(match[1]) <= 65_535 && record.state !== 'LISTEN';
  };
  const listeners = records.filter((record) => record.name === listener && record.state === 'LISTEN');
  if (listeners.length !== 1
    || records.some((record) => (
      record.protocol !== 'TCP'
      || (
        !(record.name === listener && record.state === 'LISTEN')
        && !isAuthorisedConnection(record)
      )
    ))) fail();
  // The one explicitly activated architecture driver is not a product
  // network descriptor. Every other host or sidecar socket remains rejected.
  return 0;
}

export function createLifecycleNetworkChecker({ hostPid, driverPort }) {
  if (!validPid(hostPid)
    || !Number.isSafeInteger(driverPort) || driverPort < 49_152 || driverPort > 65_535) fail();
  return (pid) => {
    if (!validPid(pid)) fail();
    const result = spawnSync(
      '/usr/sbin/lsof',
      ['-nP', '-a', '-p', String(pid), '-i', '-Ts', '-FpfPnT'],
      { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' }, timeout: 5_000 },
    );
    if (result.error || result.signal || ![0, 1].includes(result.status)) fail();
    return assertLifecycleNetworkBoundaryFromListing({
      pid,
      hostPid,
      driverPort,
      listing: result.stdout,
    });
  };
}

function validIdentity(entry) {
  return entry
    && typeof entry === 'object'
    && validPid(entry.pid)
    && validPid(entry.pgid)
    && typeof entry.start === 'string'
    && entry.start.length === 24
    && typeof entry.command === 'string'
    && entry.command.length > 0
    && typeof entry.executable === 'string'
    && entry.executable.startsWith('/');
}

/**
 * Accept only the exact host identity plus zero or one exact Node identity
 * already bound by ProcessLedger. Paths and PIDs are used for live
 * authorisation only and are never returned as evidence.
 */
export function assertLifecycleTopology({
  live,
  hostPath,
  nodePath,
  hostPid,
  expectedSidecars,
}) {
  if (!Array.isArray(live) || ![0, 1].includes(expectedSidecars)
    || !validPid(hostPid) || typeof hostPath !== 'string' || typeof nodePath !== 'string') fail();
  if (live.some((entry) => !validIdentity(entry))) fail();
  const hosts = live.filter((entry) => entry.executable === hostPath);
  const sidecars = live.filter((entry) => entry.executable === nodePath);
  if (hosts.length !== 1 || hosts[0].pid !== hostPid
    || sidecars.length !== expectedSidecars
    || live.length !== 1 + expectedSidecars
    || new Set(live.map((entry) => `${entry.pid}:${entry.pgid}:${entry.start}:${entry.command}`)).size
      !== live.length) fail();
  return Object.freeze({ hosts: 1, sidecars: expectedSidecars });
}

export class LifecycleObservation {
  constructor({ hostPath, nodePath, hostPid }) {
    if (typeof hostPath !== 'string' || typeof nodePath !== 'string' || !validPid(hostPid)) fail();
    this.hostPath = hostPath;
    this.nodePath = nodePath;
    this.hostPid = hostPid;
    this.maximumHosts = 0;
    this.maximumSidecars = 0;
    this.generations = new Map();
    this.sidecarGenerationsWithoutLockDescriptor = 0;
    this.networkDescriptorsObserved = 0;
  }

  observe(live, expectedSidecars) {
    const observed = assertLifecycleTopology({
      live,
      hostPath: this.hostPath,
      nodePath: this.nodePath,
      hostPid: this.hostPid,
      expectedSidecars,
    });
    this.maximumHosts = Math.max(this.maximumHosts, observed.hosts);
    this.maximumSidecars = Math.max(this.maximumSidecars, observed.sidecars);
    return observed;
  }

  observeGeneration(status, live) {
    this.observe(live, 1);
    if (!status || typeof status !== 'object'
      || !Number.isSafeInteger(status.generation) || status.generation < 1
      || !validPid(status.pid)) fail();
    const sidecar = live.find((entry) => entry.executable === this.nodePath);
    if (!sidecar || sidecar.pid !== status.pid) fail();
    const existing = this.generations.get(status.generation);
    const identity = `${sidecar.pid}:${sidecar.pgid}:${sidecar.start}:${sidecar.command}`;
    if (existing !== undefined && existing !== identity) fail();
    if (existing === undefined) {
      assertSidecarDoesNotInheritLockDescriptor(sidecar.pid);
      this.generations.set(status.generation, identity);
      this.sidecarGenerationsWithoutLockDescriptor += 1;
    }
  }

  evidence() {
    if (this.maximumHosts !== 1 || this.maximumSidecars !== 1
      || this.generations.size !== 4
      || this.sidecarGenerationsWithoutLockDescriptor !== 4
      || this.networkDescriptorsObserved !== 0) fail();
    return Object.freeze({
      maximumConcurrentHosts: 1,
      maximumConcurrentSidecars: 1,
      sidecarGenerationsWithoutLockDescriptor: 4,
      inheritedDescriptorLeaks: 0,
      networkDescriptorsObserved: 0,
    });
  }
}

export async function waitForOwnedProcessesToExit(
  ledger,
  { timeoutMs = 8_000, pause = sleep } = {},
) {
  if (!ledger || typeof ledger.sample !== 'function'
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1) fail();
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const live = await ledger.sample();
    if (live.length === 0) return 0;
    await pause(50);
  }
  fail();
}

export async function readNativeLifecycleWitness(path) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1 || before.size > MAX_EVIDENCE_BYTES
      || (before.mode & 0o777) !== 0o600
      || (typeof process.getuid === 'function' && before.uid !== process.getuid())) fail();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const pathname = await lstat(path);
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size
      || pathname.dev !== before.dev || pathname.ino !== before.ino || bytes.length !== before.size) fail();
    return parseNativeLifecycleEvidence(bytes);
  } finally {
    await handle?.close();
  }
}
