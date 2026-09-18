import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { inventoryBundle } from '../tests/packaged/bundle-inspection.mjs';
import { executableForPid, observeProcesses } from './a21-gate-support.mjs';
import {
  a28ChallengeRequestSha256,
  assertA28ChallengeRequest,
  assertA28PublishedReceipt,
  canonicalA28Line,
  parseCanonicalA28Line,
  sha256A28,
} from './a28-witness/contract.mjs';
import { canonicalArchitectureJson, sha256Bytes } from './architecture-gate-schema.mjs';

const SHA256 = /^[0-9a-f]{64}$/u;
const RUN_ID = /^\d{8}T\d{9}Z-[0-9a-f]{32}$/u;
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const MAX_CONTEXT_BYTES = 1024 * 1024;
const MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024;
const MAX_RECEIPT_BYTES = 65_536;
const FINAL_COMPARISON_DOMAIN = 'au.com.piui.a28.final-consumer-comparison.v1';
const COMPARED_VOICE_OVER_KEYS = Object.freeze([
  'architectureGateRunContextSha256',
  'attestationSha256',
  'blockingDefects',
  'challengeRequestSha256',
  'comparisonReceiptSha256',
  'evidenceValidated',
  'expectedContextSha256',
  'gateContextCompared',
  'humanWitnessed',
  'modesChecked',
  'publishedReceiptSha256',
]);
const leases = new WeakMap();

function reject(message = 'A.28 final-consumer context rejected') {
  throw new Error(message);
}

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, keys) {
  if (!record(value)
    || !isDeepStrictEqual(Object.keys(value).sort(), [...keys].sort())) reject();
}

function sha(value) {
  if (typeof value !== 'string' || !SHA256.test(value)) reject();
  return value;
}

function jsonTree(value, seen = new WeakSet(), depth = 0) {
  if (depth > 64) reject();
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) reject();
    return;
  }
  if (typeof value !== 'object' || Buffer.isBuffer(value) || seen.has(value)) reject();
  seen.add(value);
  if (Array.isArray(value)) {
    if (value.length > 200_000) reject();
    for (const child of value) jsonTree(child, seen, depth + 1);
  } else {
    if (Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).length > 200_000) reject();
    for (const child of Object.values(value)) jsonTree(child, seen, depth + 1);
  }
  seen.delete(value);
}

function clone(value) {
  jsonTree(value);
  return JSON.parse(canonicalArchitectureJson(value));
}

function identity(item) {
  return Object.freeze({
    ctimeNs: item.ctimeNs,
    dev: item.dev,
    gid: item.gid,
    ino: item.ino,
    mode: item.mode,
    mtimeNs: item.mtimeNs,
    nlink: item.nlink,
    size: item.size,
    uid: item.uid,
  });
}

function same(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

function sameDirectory(left, right) {
  return ['dev', 'gid', 'ino', 'mode', 'uid']
    .every((key) => left[key] === right[key]);
}

async function readAt(handle, size, maximumBytes = MAX_CONTEXT_BYTES) {
  if (size < 1n || size > BigInt(maximumBytes)) reject();
  const bytes = Buffer.alloc(Number(size));
  let offset = 0;
  while (offset < bytes.length) {
    const result = await handle.read(bytes, offset, bytes.length - offset, offset);
    if (result.bytesRead < 1) reject();
    offset += result.bytesRead;
  }
  return bytes;
}

async function hashAt(handle, size, maximumBytes) {
  if (size < 1n || size > BigInt(maximumBytes)) reject();
  const digest = createHash('sha256');
  const chunk = Buffer.allocUnsafe(1024 * 1024);
  let offset = 0n;
  while (offset < size) {
    const length = Number(size - offset > BigInt(chunk.length)
      ? BigInt(chunk.length)
      : size - offset);
    const result = await handle.read(chunk, 0, length, Number(offset));
    if (result.bytesRead < 1) reject();
    digest.update(chunk.subarray(0, result.bytesRead));
    offset += BigInt(result.bytesRead);
  }
  return digest.digest('hex');
}

async function heldFile(path, {
  allowedModes,
  expectedSha256,
  expectedSize,
  maximumBytes = MAX_CONTEXT_BYTES,
  retainBytes = true,
  uid,
}) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    const pathname = await lstat(path, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
      || before.uid !== BigInt(uid)
      || !allowedModes.includes(Number(before.mode & 0o777n))
      || (expectedSize !== undefined && before.size !== BigInt(expectedSize))
      || pathname.isSymbolicLink() || !same(identity(before), identity(pathname))) reject();
    const bytes = retainBytes ? await readAt(handle, before.size, maximumBytes) : undefined;
    const fileSha256 = retainBytes
      ? sha256A28(bytes)
      : await hashAt(handle, before.size, maximumBytes);
    if (expectedSha256 !== undefined && fileSha256 !== expectedSha256) reject();
    if (!same(identity(before), identity(await handle.stat({ bigint: true })))) reject();
    return { bytes, handle, identity: identity(before), maximumBytes, path, sha256: fileSha256 };
  } catch (error) {
    await handle?.close();
    throw error;
  }
}

async function heldDirectory(path, { exactMode, uid }) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW
      | (constants.O_DIRECTORY ?? 0));
    const before = await handle.stat({ bigint: true });
    const pathname = await lstat(path, { bigint: true });
    if (!before.isDirectory() || before.isSymbolicLink() || before.uid !== BigInt(uid)
      || (exactMode === undefined
        ? (before.mode & 0o022n) !== 0n
        : (before.mode & 0o777n) !== BigInt(exactMode))
      || pathname.isSymbolicLink() || !same(identity(before), identity(pathname))
      || await realpath(path) !== path) reject();
    return { directory: true, handle, identity: identity(before), path };
  } catch (error) {
    await handle?.close();
    throw error;
  }
}

async function heldAncestors(path, stop, uid) {
  if (resolve(stop) !== stop || await realpath(stop) !== stop) reject();
  const result = [];
  let current = dirname(path);
  try {
    while (true) {
      result.push(await heldDirectory(current, { uid }));
      if (current === stop) return result;
      if (!(stop === '/' ? current.startsWith('/') : current.startsWith(`${stop}/`))
        || dirname(current) === current) reject();
      current = dirname(current);
    }
  } catch (error) {
    await Promise.allSettled(result.map((entry) => entry.handle.close()));
    throw error;
  }
}

async function assertHeld(entry) {
  const descriptor = identity(await entry.handle.stat({ bigint: true }));
  const pathname = await lstat(entry.path, { bigint: true });
  const unchanged = entry.directory ? sameDirectory : same;
  if (!unchanged(entry.identity, descriptor) || pathname.isSymbolicLink()
    || !unchanged(entry.identity, identity(pathname))) reject();
  if (entry.bytes) {
    const bytes = await readAt(entry.handle, descriptor.size);
    if (!bytes.equals(entry.bytes) || sha256A28(bytes) !== entry.sha256) reject();
  } else if (!entry.directory
    && await hashAt(entry.handle, descriptor.size, entry.maximumBytes) !== entry.sha256) {
    reject();
  }
}

async function exclusiveHeldFile(path, bytes, uid) {
  let handle;
  try {
    handle = await open(path, constants.O_CREAT | constants.O_EXCL
      | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    const before = await handle.stat({ bigint: true });
    const pathname = await lstat(path, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(uid)
      || (before.mode & 0o777n) !== 0o600n || before.size !== BigInt(bytes.length)
      || pathname.isSymbolicLink() || !same(identity(before), identity(pathname))) reject();
    return { bytes, handle, identity: identity(before), path, sha256: sha256A28(bytes) };
  } catch (error) {
    await handle?.close();
    throw error;
  }
}

function startedValue(bytes, gate, sourceDigest) {
  let value;
  try {
    value = JSON.parse(bytes.subarray(0, -1).toString('utf8'));
  } catch {
    reject();
  }
  exactKeys(value, ['runId', 'schemaVersion', 'sourceDigest', 'startedAt', 'status', 'target']);
  if (bytes.at(-1) !== 0x0a || bytes.subarray(0, -1).includes(0x0a)
    || `${canonicalArchitectureJson(value)}\n` !== bytes.toString('utf8')
    || value.runId !== gate.runId || value.sourceDigest !== sourceDigest
    || value.schemaVersion !== 1 || value.status !== 'started'
    || value.target !== 'aarch64-apple-darwin' || !ISO_INSTANT.test(value.startedAt)
    || !Number.isFinite(Date.parse(value.startedAt))) reject();
  return value;
}

function inventoryDigest(value, fingerprint) {
  if (!record(value) || !Array.isArray(value.entries) || value.fingerprint !== fingerprint) reject();
  const entries = value.entries.map(({ dev: _dev, ino: _ino, ...entry }) => entry);
  const canonical = clone({ entries, rootProvenance: value.rootProvenance ?? null });
  return Object.freeze({
    entries: entries.length,
    sha256: sha256Bytes(Buffer.from(canonicalArchitectureJson(canonical), 'utf8')),
  });
}

function bundleHost(bundle) {
  exactKeys(bundle.hostIdentity, ['bytes', 'dev', 'ino', 'sha256']);
  if (![bundle.hostIdentity.bytes, bundle.hostIdentity.dev, bundle.hostIdentity.ino]
    .every((value) => Number.isSafeInteger(value) && value > 0)) reject();
  sha(bundle.hostIdentity.sha256);
  return Object.freeze({
    dev: bundle.hostIdentity.dev,
    ino: bundle.hostIdentity.ino,
    path: bundle.hostPath,
    sha256: bundle.hostIdentity.sha256,
    size: bundle.hostIdentity.bytes,
  });
}

function publicExecutable(entry) {
  return Object.freeze({
    dev: Number(entry.identity.dev),
    ino: Number(entry.identity.ino),
    path: entry.path,
    sha256: entry.sha256,
    size: Number(entry.identity.size),
  });
}

async function nativeProcessInspector(pid) {
  const matches = observeProcesses().filter((entry) => entry.pid === pid);
  if (matches.length !== 1) reject('A.28 retained process identity is unavailable');
  return Object.freeze({
    executable: executableForPid(pid),
    pid,
    start: matches[0].start,
  });
}

function assertProcessObservation(value, { executable, pid }) {
  exactKeys(value, ['executable', 'pid', 'start']);
  if (value.pid !== pid
    || value.executable !== executable
    || typeof value.start !== 'string'
    || value.start.length !== 24) reject();
  return Object.freeze({ ...value });
}

export async function createA28FinalConsumerContext(input, dependencies = {}) {
  exactKeys(input, ['architectureGateRun', 'automationBundle', 'consumerAnchors',
    'contextDirectory', 'hostPid', 'measuredDelta', 'productionBundle',
    'repositoryRoot', 'runner', 'sourceDigest']);
  if (Object.keys(dependencies).some((key) => ![
    'inventoryBundle',
    'processInspector',
  ].includes(key))) reject();
  exactKeys(input.architectureGateRun, ['contextSha256', 'runId']);
  exactKeys(input.consumerAnchors, [
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
  exactKeys(input.productionBundle, ['appPath', 'fingerprint']);
  exactKeys(input.automationBundle, ['appPath', 'bundleIdentifier', 'fingerprint',
    'hostIdentity', 'hostPath', 'hostSigningIdentity']);
  exactKeys(input.runner, [
    'executablePath',
    'executableSha256',
    'executableSize',
    'pid',
    'signingIdentity',
  ]);
  exactKeys(input.measuredDelta, ['record', 'sha256']);
  for (const value of [input.architectureGateRun.contextSha256,
    input.automationBundle.fingerprint,
    ...Object.values(input.consumerAnchors), input.measuredDelta.sha256,
    input.productionBundle.fingerprint, input.sourceDigest]) sha(value);
  if (!RUN_ID.test(input.architectureGateRun.runId)
    || !Number.isSafeInteger(input.hostPid) || input.hostPid < 2
    || !Number.isSafeInteger(input.runner.pid) || input.runner.pid < 2
    || !Number.isSafeInteger(input.runner.executableSize)
    || input.runner.executableSize < 1
    || input.runner.executableSize > MAX_EXECUTABLE_BYTES
    || input.runner.pid === input.hostPid
    || input.automationBundle.fingerprint === input.productionBundle.fingerprint) reject();
  for (const path of [input.repositoryRoot, input.contextDirectory,
    input.productionBundle.appPath, input.automationBundle.appPath,
    input.automationBundle.hostPath, input.runner.executablePath]) {
    if (typeof path !== 'string' || resolve(path) !== path || /[\0\r\n]/u.test(path)) reject();
  }
  jsonTree(input.measuredDelta.record);
  jsonTree(input.automationBundle.hostSigningIdentity);
  jsonTree(input.runner.signingIdentity);
  sha(input.runner.executableSha256);
  if (sha256Bytes(Buffer.from(canonicalArchitectureJson(input.measuredDelta.record), 'utf8'))
    !== input.measuredDelta.sha256) reject();

  const inspectInventory = dependencies.inventoryBundle ?? inventoryBundle;
  const inspectProcess = dependencies.processInspector ?? nativeProcessInspector;
  if (typeof inspectInventory !== 'function' || typeof inspectProcess !== 'function') reject();
  const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
  const held = [];
  try {
    held.push(await heldDirectory(input.contextDirectory, { exactMode: 0o700, uid }));
    const startedPath = resolve(input.repositoryRoot,
      '.forge/evidence/architecture-gate/runs', input.architectureGateRun.runId,
      'started.json');
    held.push(...await heldAncestors(startedPath, input.repositoryRoot, uid));
    const started = await heldFile(startedPath, { allowedModes: [0o600], uid });
    held.push(started);
    if (started.sha256 !== input.architectureGateRun.contextSha256) reject();
    const startedContext = startedValue(started.bytes, input.architectureGateRun,
      input.sourceDigest);
    const [productionInventory, automationInventory] = await Promise.all([
      inspectInventory(input.productionBundle.appPath),
      inspectInventory(input.automationBundle.appPath),
    ]);
    const production = inventoryDigest(productionInventory, input.productionBundle.fingerprint);
    const automation = inventoryDigest(automationInventory, input.automationBundle.fingerprint);
    held.push(await heldDirectory(input.productionBundle.appPath, {
      exactMode: 0o555,
      uid,
    }));
    held.push(await heldDirectory(input.automationBundle.appPath, {
      exactMode: 0o555,
      uid,
    }));
    const expectedHost = bundleHost(input.automationBundle);
    const host = await heldFile(input.automationBundle.hostPath, {
      allowedModes: [0o555],
      expectedSha256: expectedHost.sha256,
      expectedSize: expectedHost.size,
      maximumBytes: MAX_EXECUTABLE_BYTES,
      retainBytes: false,
      uid,
    });
    held.push(host);
    if (!isDeepStrictEqual(publicExecutable(host), expectedHost)) reject();
    const runner = await heldFile(input.runner.executablePath, {
      allowedModes: [0o500, 0o555],
      expectedSha256: input.runner.executableSha256,
      expectedSize: input.runner.executableSize,
      maximumBytes: MAX_EXECUTABLE_BYTES,
      retainBytes: false,
      uid,
    });
    held.push(runner);
    const [hostProcess, runnerProcess] = await Promise.all([
      inspectProcess(input.hostPid),
      inspectProcess(input.runner.pid),
    ]);
    const processObservations = Object.freeze({
      host: assertProcessObservation(hostProcess, {
        executable: input.automationBundle.hostPath,
        pid: input.hostPid,
      }),
      runner: assertProcessObservation(runnerProcess, {
        executable: input.runner.executablePath,
        pid: input.runner.pid,
      }),
    });
    const signing = clone(input.automationBundle.hostSigningIdentity);
    const runnerSigning = clone(input.runner.signingIdentity);
    const context = clone({
      architectureGateRun: { contextSha256: input.architectureGateRun.contextSha256,
        runId: input.architectureGateRun.runId, startedAt: startedContext.startedAt },
      automationBundle: { bundleIdentifier: input.automationBundle.bundleIdentifier,
        bundlePath: input.automationBundle.appPath, fingerprint: input.automationBundle.fingerprint,
        hostExecutable: expectedHost, hostSigningIdentity: signing,
        hostSigningIdentitySha256: sha256Bytes(Buffer.from(canonicalArchitectureJson(signing))),
        inventoryEntries: automation.entries, inventorySha256: automation.sha256 },
      consumerAnchors: input.consumerAnchors,
      live: { hostPid: input.hostPid, runnerExecutable: publicExecutable(runner),
        hostProcessStart: processObservations.host.start,
        runnerPid: input.runner.pid, runnerProcessStart: processObservations.runner.start,
        runnerSigningIdentity: runnerSigning,
        runnerSigningIdentitySha256: sha256Bytes(Buffer.from(
          canonicalArchitectureJson(runnerSigning),
        )) },
      measuredDelta: input.measuredDelta,
      productionBundle: { fingerprint: input.productionBundle.fingerprint,
        inventoryEntries: production.entries, inventorySha256: production.sha256 },
      schemaVersion: 1,
      sourceDigest: input.sourceDigest,
    });
    const bytes = Buffer.from(`${canonicalArchitectureJson(context)}\n`, 'utf8');
    if (bytes.length > MAX_CONTEXT_BYTES) reject();
    const contextPath = resolve(input.contextDirectory, 'expected-context.json');
    const contextFile = await exclusiveHeldFile(contextPath, bytes, uid);
    held.push(contextFile);
    const lease = Object.freeze({ path: contextPath, sha256: contextFile.sha256 });
    leases.set(lease, {
      automationBundle: input.automationBundle,
      automationInventory: automation,
      context,
      contextFile,
      held,
      inspectInventory,
      inspectProcess,
      processObservations,
      productionBundle: input.productionBundle,
      productionInventory: production,
      used: false,
    });
    return lease;
  } catch (error) {
    await Promise.allSettled(held.map((entry) => entry.handle.close()));
    throw error;
  }
}

export async function assertA28FinalConsumerContextLease(lease) {
  const state = leases.get(lease);
  if (!state || state.used) reject();
  for (const entry of state.held) await assertHeld(entry);
  if (state.contextFile.bytes.toString('utf8')
    !== `${canonicalArchitectureJson(state.context)}\n`) reject();
  return true;
}

export function a28FinalConsumerContextForComparison(lease) {
  const state = leases.get(lease);
  if (!state || state.used) reject();
  return state.context;
}

async function revalidateInventories(state) {
  const [production, automation] = await Promise.all([
    state.inspectInventory(state.productionBundle.appPath),
    state.inspectInventory(state.automationBundle.appPath),
  ]);
  if (!isDeepStrictEqual(
    inventoryDigest(production, state.productionBundle.fingerprint),
    state.productionInventory,
  ) || !isDeepStrictEqual(
    inventoryDigest(automation, state.automationBundle.fingerprint),
    state.automationInventory,
  )) reject();
}

async function assertLivePeers(state) {
  const [host, runner] = await Promise.all([
    state.inspectProcess(state.context.live.hostPid),
    state.inspectProcess(state.context.live.runnerPid),
  ]);
  if (!isDeepStrictEqual(host, state.processObservations.host)
    || !isDeepStrictEqual(runner, state.processObservations.runner)) reject();
}

export async function releaseA28FinalConsumerContext(lease) {
  const state = leases.get(lease);
  if (!state) reject();
  state.used = true;
  await Promise.allSettled(state.held.map((entry) => entry.handle.close()));
  leases.delete(lease);
}

function gateOwnedRequest(context) {
  return Object.freeze({
    applicationPid: context.live.hostPid,
    architectureGateRunContextSha256: context.architectureGateRun.contextSha256,
    architectureGateRunId: context.architectureGateRun.runId,
    automationTwinFingerprint: context.automationBundle.fingerprint,
    gateId: 'A.28',
    hostBundleFingerprint: context.automationBundle.fingerprint,
    hostBundleIdentifier: context.automationBundle.bundleIdentifier,
    hostBundlePath: context.automationBundle.bundlePath,
    hostExecutable: context.automationBundle.hostExecutable,
    measuredTwinDeltaSha256: context.measuredDelta.sha256,
    productionFingerprint: context.productionBundle.fingerprint,
    runnerAuthority: 'continuity-only',
    runnerExecutable: context.live.runnerExecutable,
    runnerPid: context.live.runnerPid,
    schemaVersion: 1,
    sourceDigest: context.sourceDigest,
  });
}

function assertSigningOverlap(request, signing, prefix) {
  const mappings = [
    ['bundleIdentifier', `${prefix}BundleIdentifier`],
    ['cdHash', `${prefix}CdHash`],
    ['designatedRequirement', `${prefix}DesignatedRequirement`],
  ];
  for (const [signingKey, requestKey] of mappings) {
    if (Object.hasOwn(signing, signingKey)
      && request[requestKey] !== signing[signingKey]) reject();
  }
  if (Object.hasOwn(signing, 'executableSha256')
    && request[`${prefix}Executable`]?.sha256 !== signing.executableSha256) reject();
}

function assertRequestAgainstContext(request, context) {
  if (!record(request)) reject();
  for (const [key, expected] of Object.entries(gateOwnedRequest(context))) {
    if (!Object.hasOwn(request, key) || !isDeepStrictEqual(request[key], expected)) reject();
  }
  assertSigningOverlap(request, context.automationBundle.hostSigningIdentity, 'host');
  assertSigningOverlap(request, context.live.runnerSigningIdentity, 'runner');
}

function assertReceiptAgainstContext(receipt, request, context, requestSha256) {
  const expected = {
    applicationPid: context.live.hostPid,
    architectureGateRunContextSha256: context.architectureGateRun.contextSha256,
    architectureGateRunId: context.architectureGateRun.runId,
    automationTwinFingerprint: context.automationBundle.fingerprint,
    challengeRequestSha256: requestSha256,
    hostBundleFingerprint: context.automationBundle.fingerprint,
    hostBundleIdentifier: context.automationBundle.bundleIdentifier,
    hostExecutableSha256: context.automationBundle.hostExecutable.sha256,
    measuredTwinDeltaSha256: context.measuredDelta.sha256,
    productionFingerprint: context.productionBundle.fingerprint,
    runnerAuthority: 'continuity-only',
    runnerBundleIdentifier: context.live.runnerSigningIdentity.bundleIdentifier,
    runnerExecutableSha256: context.live.runnerExecutable.sha256,
    runnerPid: context.live.runnerPid,
    sourceDigest: context.sourceDigest,
  };
  for (const [key, value] of Object.entries(expected)) {
    if (!Object.hasOwn(receipt, key) || !isDeepStrictEqual(receipt[key], value)) reject();
  }
  for (const key of [
    'hostAuditTokenSha256',
    'hostCdHash',
    'hostStartTime',
    'runnerAuditTokenSha256',
    'runnerCdHash',
    'runnerStartTime',
    'voiceOverAuditTokenSha256',
    'voiceOverBundleIdentifier',
    'voiceOverCdHash',
    'voiceOverPid',
    'voiceOverStartTime',
    'voiceOverVersion',
  ]) {
    if (!Object.hasOwn(request, key)
      || !Object.hasOwn(receipt, key)
      || receipt[key] !== request[key]) reject();
  }
}

export function assertA28ComparedVoiceOverEvidence(value) {
  exactKeys(value, COMPARED_VOICE_OVER_KEYS);
  for (const key of [
    'architectureGateRunContextSha256',
    'attestationSha256',
    'challengeRequestSha256',
    'comparisonReceiptSha256',
    'expectedContextSha256',
    'publishedReceiptSha256',
  ]) sha(value[key]);
  if (value.evidenceValidated !== true
    || value.gateContextCompared !== true
    || value.humanWitnessed !== true
    || value.modesChecked !== 4
    || value.blockingDefects !== 0) reject();
  return Object.freeze({ ...value });
}

export function a28FinalConsumerGateOwnedRequest(lease) {
  const state = leases.get(lease);
  if (!state || state.used) reject();
  return gateOwnedRequest(state.context);
}

export async function compareA28FinalConsumerReceipt(input, dependencies = {}) {
  exactKeys(input, [
    'attestationBytes',
    'challenge',
    'challengeRequest',
    'contextLease',
    'enrolment',
    'now',
    'policyPin',
    'publishedReceiptPath',
  ]);
  const dependencyKeys = Object.keys(dependencies);
  if (dependencyKeys.some((key) => ![
    'assertChallengeRequest',
    'assertPublishedReceipt',
    'afterReceiptOpen',
    'challengeRequestSha256',
    'receiptRoot',
    'receiptUid',
  ].includes(key))) reject();
  const state = leases.get(input.contextLease);
  if (!state || state.used) reject();
  state.used = true;
  const validateRequest = dependencies.assertChallengeRequest ?? assertA28ChallengeRequest;
  const validateReceipt = dependencies.assertPublishedReceipt ?? assertA28PublishedReceipt;
  const requestDigest = dependencies.challengeRequestSha256 ?? a28ChallengeRequestSha256;
  const receiptRoot = dependencies.receiptRoot ?? '/';
  const receiptUid = dependencies.receiptUid ?? 0;
  const afterReceiptOpen = dependencies.afterReceiptOpen;
  let receiptFile;
  let receiptAncestors = [];
  let comparisonFile;
  try {
    if (!Buffer.isBuffer(input.attestationBytes)
      || input.attestationBytes.length < 3
      || input.attestationBytes.length > MAX_RECEIPT_BYTES
      || !Number.isFinite(input.now)
      || typeof validateRequest !== 'function'
      || typeof validateReceipt !== 'function'
      || typeof requestDigest !== 'function'
      || (afterReceiptOpen !== undefined && typeof afterReceiptOpen !== 'function')
      || !Number.isSafeInteger(receiptUid)
      || receiptUid < 0) reject();
    for (const entry of state.held) await assertHeld(entry);
    await revalidateInventories(state);
    await assertLivePeers(state);

    // The expected digest is deliberately unavailable until every gate-owned
    // request field equals the independently retained package context.
    assertRequestAgainstContext(input.challengeRequest, state.context);
    const originalRequest = clone(input.challengeRequest);
    const acceptedRequest = validateRequest(originalRequest, input.policyPin, input.now);
    const challengeRequestSha256 = requestDigest(acceptedRequest);
    sha(challengeRequestSha256);
    if (input.challenge?.challengeRequestSha256 !== challengeRequestSha256) reject();

    if (typeof input.publishedReceiptPath !== 'string'
      || resolve(input.publishedReceiptPath) !== input.publishedReceiptPath
      || dirname(input.publishedReceiptPath) !== input.policyPin?.resultDirectoryPath
      || input.publishedReceiptPath
        !== resolve(input.policyPin.resultDirectoryPath, `${input.challenge?.witnessNonce}.json`)) reject();
    receiptAncestors = await heldAncestors(input.publishedReceiptPath, receiptRoot, receiptUid);
    receiptFile = await heldFile(input.publishedReceiptPath, {
      allowedModes: [0o444],
      maximumBytes: MAX_RECEIPT_BYTES,
      retainBytes: true,
      uid: receiptUid,
    });
    await afterReceiptOpen?.(Object.freeze({ path: input.publishedReceiptPath }));
    const receiptValue = parseCanonicalA28Line(receiptFile.bytes);
    const receipt = validateReceipt(receiptValue, {
      attestationBytes: input.attestationBytes,
      challenge: input.challenge,
      enrolment: input.enrolment,
      now: input.now,
      policyPin: input.policyPin,
    });
    if (!isDeepStrictEqual(clone(input.challengeRequest), originalRequest)) reject();
    assertReceiptAgainstContext(
      receipt,
      originalRequest,
      state.context,
      challengeRequestSha256,
    );
    for (const entry of [...state.held, ...receiptAncestors, receiptFile]) {
      await assertHeld(entry);
    }
    await revalidateInventories(state);
    await assertLivePeers(state);

    const comparedAt = new Date(input.now).toISOString();
    if (!ISO_INSTANT.test(comparedAt)) reject();
    const anchorsSha256 = sha256Bytes(Buffer.from(
      canonicalArchitectureJson(state.context.consumerAnchors),
      'utf8',
    ));
    const comparison = clone({
      architectureGateRunContextSha256: state.context.architectureGateRun.contextSha256,
      architectureGateRunId: state.context.architectureGateRun.runId,
      attestationSha256: sha256A28(input.attestationBytes),
      automationInventorySha256: state.context.automationBundle.inventorySha256,
      automationTwinFingerprint: state.context.automationBundle.fingerprint,
      challengeRequestSha256,
      comparedAt,
      comparisonDomain: FINAL_COMPARISON_DOMAIN,
      consumerAnchorsSha256: anchorsSha256,
      expectedContextSha256: input.contextLease.sha256,
      gateContextCompared: true,
      hostExecutableSha256: state.context.automationBundle.hostExecutable.sha256,
      hostSigningIdentitySha256: state.context.automationBundle.hostSigningIdentitySha256,
      measuredTwinDeltaSha256: state.context.measuredDelta.sha256,
      productionFingerprint: state.context.productionBundle.fingerprint,
      productionInventorySha256: state.context.productionBundle.inventorySha256,
      publishedReceiptSha256: receiptFile.sha256,
      runnerExecutableSha256: state.context.live.runnerExecutable.sha256,
      runnerSigningIdentitySha256: state.context.live.runnerSigningIdentitySha256,
      schemaVersion: 1,
      sourceDigest: state.context.sourceDigest,
      startedAt: state.context.architectureGateRun.startedAt,
      startedContextSha256: state.context.architectureGateRun.contextSha256,
    });
    comparisonFile = await exclusiveHeldFile(
      resolve(dirname(state.contextFile.path), 'comparison-receipt.json'),
      canonicalA28Line(comparison),
      typeof process.getuid === 'function' ? process.getuid() : 0,
    );
    for (const entry of [...state.held, ...receiptAncestors, receiptFile, comparisonFile]) {
      await assertHeld(entry);
    }
    await revalidateInventories(state);
    await assertLivePeers(state);
    return assertA28ComparedVoiceOverEvidence({
      architectureGateRunContextSha256: state.context.architectureGateRun.contextSha256,
      attestationSha256: comparison.attestationSha256,
      blockingDefects: 0,
      challengeRequestSha256,
      comparisonReceiptSha256: comparisonFile.sha256,
      evidenceValidated: true,
      expectedContextSha256: input.contextLease.sha256,
      gateContextCompared: true,
      humanWitnessed: true,
      modesChecked: 4,
      publishedReceiptSha256: receiptFile.sha256,
    });
  } finally {
    await Promise.allSettled([
      comparisonFile?.handle?.close(),
      receiptFile?.handle?.close(),
      ...receiptAncestors.map((entry) => entry.handle.close()),
      ...state.held.map((entry) => entry.handle.close()),
    ].filter(Boolean));
    leases.delete(input.contextLease);
  }
}

export async function executeA28FinalConsumerCeremony(input, dependencies = {}) {
  exactKeys(input, ['ceremony', 'contextLease', 'now']);
  exactKeys(input.ceremony, ['authorise', 'consume', 'prepare', 'reveal']);
  for (const method of Object.values(input.ceremony)) {
    if (typeof method !== 'function') reject();
  }
  const onPhase = dependencies.onPhase;
  if (onPhase !== undefined && typeof onPhase !== 'function') reject();
  const comparisonDependencies = Object.fromEntries(
    Object.entries(dependencies).filter(([key]) => key !== 'onPhase'),
  );
  const state = leases.get(input.contextLease);
  const clock = typeof input.now === 'function'
    ? input.now
    : () => input.now;
  const initialNow = clock();
  if (!state || state.used || !Number.isFinite(initialNow)) reject();
  let comparisonAttempted = false;
  try {
    const gateRequest = gateOwnedRequest(state.context);
    const prepared = await input.ceremony.prepare(Object.freeze({
      expectedContextPath: input.contextLease.path,
      expectedContextSha256: input.contextLease.sha256,
      gateOwnedRequest: gateRequest,
    }));
    await onPhase?.('prepare');
    exactKeys(prepared, ['challenge', 'challengeRequest', 'policyPin']);
    assertRequestAgainstContext(prepared.challengeRequest, state.context);
    const validateRequest = comparisonDependencies.assertChallengeRequest
      ?? assertA28ChallengeRequest;
    const requestDigest = comparisonDependencies.challengeRequestSha256
      ?? a28ChallengeRequestSha256;
    const acceptedRequest = validateRequest(
      clone(prepared.challengeRequest),
      prepared.policyPin,
      initialNow,
    );
    const expectedRequestSha256 = requestDigest(acceptedRequest);
    sha(expectedRequestSha256);
    if (prepared.challenge?.challengeRequestSha256 !== expectedRequestSha256) reject();

    const reveals = [];
    for (let ordinal = 1; ordinal <= 4; ordinal += 1) {
      reveals.push(await input.ceremony.reveal(Object.freeze({
        challenge: prepared.challenge,
        ordinal,
      })));
      await onPhase?.(`reveal-${ordinal}`);
    }
    const authorisation = await input.ceremony.authorise(Object.freeze({
      challenge: prepared.challenge,
      reveals: Object.freeze([...reveals]),
    }));
    await onPhase?.('authorise');
    const consumed = await input.ceremony.consume(Object.freeze({
      authorisation,
      challenge: prepared.challenge,
      reveals: Object.freeze([...reveals]),
    }));
    await onPhase?.('consume');
    exactKeys(consumed, ['attestationBytes', 'enrolment', 'publishedReceiptPath']);
    comparisonAttempted = true;
    const comparisonNow = clock();
    if (!Number.isFinite(comparisonNow)) reject();
    const result = await compareA28FinalConsumerReceipt({
      attestationBytes: consumed.attestationBytes,
      challenge: prepared.challenge,
      challengeRequest: prepared.challengeRequest,
      contextLease: input.contextLease,
      enrolment: consumed.enrolment,
      now: comparisonNow,
      policyPin: prepared.policyPin,
      publishedReceiptPath: consumed.publishedReceiptPath,
    }, comparisonDependencies);
    await onPhase?.('compare');
    return result;
  } finally {
    if (!comparisonAttempted && leases.has(input.contextLease)) {
      await releaseA28FinalConsumerContext(input.contextLease);
    }
  }
}
