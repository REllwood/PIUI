import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import {
  lstat,
  open,
  readdir,
  realpath,
} from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { isDeepStrictEqual } from 'node:util';
import {
  executableForPid,
  observeProcesses,
} from './a21-gate-support.mjs';
import {
  A28_MAX_ATTESTATION_BYTES,
  A28_MAX_CHALLENGE_BYTES,
  A28_MAX_ENROLMENT_BYTES,
  A28_MAX_POLICY_BYTES,
  A28_POLICY_PIN_PATH,
  a28ChallengeRequestSha256,
  a28CheckpointCommitmentSha256,
  assertA28Challenge,
  assertA28ChallengeRequest,
  assertA28Enrolment,
  assertA28PolicyPin,
  canonicalA28Line,
  parseCanonicalA28Line,
  sha256A28,
} from './a28-witness/contract.mjs';
import {
  inspectPinnedA28WitnessApp,
  readHeldCanonicalA28File,
} from './a28-witness/verify.mjs';

const SHA256 = /^[0-9a-f]{64}$/u;
const SESSION_FILE = /^[0-9a-f]{64}\.challenge\.json$/u;
const VOICE_OVER_EXECUTABLE =
  '/System/Library/CoreServices/VoiceOver.app/Contents/MacOS/VoiceOver';
const MAX_INSTALLED_EXECUTABLE_BYTES = 16 * 1024 * 1024;
const MAX_HELPER_OUTPUT_BYTES = 256 * 1024;
const MAX_PROGRESS_BYTES = 256 * 1024;
const MAX_PROGRESS_LINES = 128;
const MAX_PROGRESS_LINE_BYTES = 4_128;
const PROGRESS_PREFIX = Buffer.from('[working] A.28 ', 'utf8');
const DEFAULT_TIMEOUT_MS = 30 * 60_000;

export const A28_OFFICIAL_NODE_SIGNING_IDENTITY = Object.freeze({
  bundleIdentifier: 'node',
  cdHash: '59cdea89a982b05f23e756c08115bebc555ff092',
  designatedRequirement:
    'identifier node and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "HX7739G8FX"',
  executableSha256: '2e3f1286a7eb3736346ed1803e458a0ff909e2b2d5bc746144dcb76970e9b99d',
  teamIdentifier: 'HX7739G8FX',
});

function reject(message = 'A.28 installed witness ceremony rejected') {
  throw new Error(message);
}

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, keys) {
  if (!record(value)
    || !isDeepStrictEqual(Object.keys(value).sort(), [...keys].sort())) reject();
}

function absolutePath(value) {
  if (typeof value !== 'string'
    || resolve(value) !== value
    || /[\0\r\n]/u.test(value)) reject();
  return value;
}

function shellQuote(value) {
  if (typeof value !== 'string' || /[\0\r\n]/u.test(value)) reject();
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function progress(message) {
  if (typeof message !== 'string'
    || message.length < 1
    || message.length > 4_096
    || /[\r\n]/u.test(message)) reject();
  process.stderr.write(`[working] A.28 ${message}\n`);
}

export function assertA28ProgressTranscript(bytes, { allowEmpty = false } = {}) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length > MAX_PROGRESS_BYTES
    || (bytes.length === 0 && !allowEmpty)
    || (bytes.length > 0 && bytes.at(-1) !== 0x0a)
    || bytes.includes(0x00)
    || bytes.includes(0x0d)) reject();
  if (bytes.length === 0) return true;
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    reject();
  }
  const lines = text.slice(0, -1).split('\n');
  if (lines.length < 1
    || lines.length > MAX_PROGRESS_LINES
    || lines.some((line) => line.length < 18
      || line.length > MAX_PROGRESS_LINE_BYTES
      || !line.startsWith('[working] A.28 '))) reject();
  return true;
}

export function createA28ProgressTranscriptForwarder(write) {
  if (typeof write !== 'function') reject();
  const accepted = [];
  let acceptedBytes = 0;
  let finished = false;
  let pending = Buffer.alloc(0);

  const assertPossiblePrefix = () => {
    const prefixLength = Math.min(pending.length, PROGRESS_PREFIX.length);
    if (!pending.subarray(0, prefixLength).equals(
      PROGRESS_PREFIX.subarray(0, prefixLength),
    ) || pending.length > MAX_PROGRESS_LINE_BYTES) reject();
  };

  return Object.freeze({
    push(chunk) {
      if (finished || !Buffer.isBuffer(chunk) || chunk.length < 1
        || acceptedBytes + pending.length + chunk.length > MAX_PROGRESS_BYTES
        || chunk.includes(0x00)
        || chunk.includes(0x0d)) reject();
      pending = Buffer.concat([pending, chunk]);
      let newline = pending.indexOf(0x0a);
      while (newline !== -1) {
        const line = Buffer.from(pending.subarray(0, newline + 1));
        const proposed = Buffer.concat([...accepted, line]);
        assertA28ProgressTranscript(proposed);
        const retained = Buffer.from(line);
        write(Buffer.from(retained));
        accepted.push(retained);
        acceptedBytes += retained.length;
        pending = Buffer.from(pending.subarray(newline + 1));
        newline = pending.indexOf(0x0a);
      }
      assertPossiblePrefix();
    },
    finish({ allowEmpty = false } = {}) {
      if (finished || pending.length !== 0) reject();
      const transcript = Buffer.concat(accepted, acceptedBytes);
      assertA28ProgressTranscript(transcript, { allowEmpty });
      finished = true;
      return Buffer.from(transcript);
    },
  });
}

function runExact(path, arguments_, maximumBytes = MAX_HELPER_OUTPUT_BYTES) {
  const result = spawnSync(path, arguments_, {
    encoding: null,
    env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
    maxBuffer: maximumBytes,
    timeout: 30_000,
  });
  if (result.error
    || result.signal
    || result.status !== 0
    || !Buffer.isBuffer(result.stdout)
    || !Buffer.isBuffer(result.stderr)
    || result.stdout.length > maximumBytes
    || result.stderr.length !== 0) reject();
  return result.stdout;
}

async function assertRootPinnedExecutable(path, expectedSha256) {
  absolutePath(path);
  let current = path;
  let leaf = true;
  while (true) {
    const item = await lstat(current);
    if (item.isSymbolicLink()
      || item.uid !== 0
      || (item.mode & 0o022) !== 0
      || (leaf && (!item.isFile()
        || item.nlink !== 1
        || (item.mode & 0o777) !== 0o555))
      || (!leaf && !item.isDirectory())) reject();
    if (current === '/') break;
    current = resolve(current, '..');
    leaf = false;
  }
  if (await realpath(path) !== path) reject();
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    if (!before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1
      || before.uid !== 0
      || (before.mode & 0o777) !== 0o555
      || before.size < 8_192
      || before.size > MAX_INSTALLED_EXECUTABLE_BYTES) reject();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const pathname = await lstat(path);
    for (const key of [
      'ctimeMs', 'dev', 'gid', 'ino', 'mode', 'mtimeMs', 'nlink', 'size', 'uid',
    ]) {
      if (after[key] !== before[key] || pathname[key] !== before[key]) reject();
    }
    if (createHash('sha256').update(bytes).digest('hex') !== expectedSha256) reject();
  } finally {
    await handle?.close();
  }
}

function inspectProcess(policy, pid, bundleIdentifier, teamIdentifier, requirement) {
  const bytes = runExact(policy.processInspectorPath, [
    '--pid',
    String(pid),
    '--bundle-id',
    bundleIdentifier,
    '--team-id',
    teamIdentifier,
    '--reported-requirement',
    requirement,
  ]);
  return parseCanonicalA28Line(bytes);
}

function systemVersion(path, arguments_) {
  const value = runExact(path, arguments_, 16 * 1024).toString('utf8').trim();
  if (!value || /[\0\r\n]/u.test(value)) reject();
  return value;
}

function findExactProcess(executable) {
  const rows = observeProcesses().filter((row) => {
    if (row.state?.startsWith('Z')) return false;
    try {
      return executableForPid(row.pid) === executable;
    } catch {
      return false;
    }
  });
  if (rows.length !== 1) reject(`A.28 requires exactly one live ${executable}`);
  return rows[0];
}

async function writeExclusiveCanonical(path, value) {
  let handle;
  const bytes = canonicalA28Line(value);
  try {
    handle = await open(
      path,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
      0o600,
    );
    await handle.writeFile(bytes);
    await handle.sync();
    const before = await handle.stat();
    const pathname = await lstat(path);
    const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
    if (!before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1
      || before.uid !== uid
      || (before.mode & 0o777) !== 0o600
      || before.size !== bytes.length
      || before.dev !== pathname.dev
      || before.ino !== pathname.ino) reject();
    return Object.freeze({
      bytes,
      handle,
      identity: Object.freeze({
        ctimeMs: before.ctimeMs,
        dev: before.dev,
        gid: before.gid,
        ino: before.ino,
        mode: before.mode,
        mtimeMs: before.mtimeMs,
        nlink: before.nlink,
        size: before.size,
        uid: before.uid,
      }),
      path,
      sha256: sha256A28(bytes),
    });
  } catch (error) {
    await handle?.close();
    throw error;
  }
}

async function assertHeldRequest(file) {
  if (!file?.handle) reject();
  const descriptor = await file.handle.stat();
  const pathname = await lstat(file.path);
  for (const key of [
    'ctimeMs', 'dev', 'gid', 'ino', 'mode', 'mtimeMs', 'nlink', 'size', 'uid',
  ]) {
    if (descriptor[key] !== file.identity[key]
      || pathname[key] !== file.identity[key]) reject();
  }
  const bytes = Buffer.alloc(file.bytes.length);
  let offset = 0;
  while (offset < bytes.length) {
    const read = await file.handle.read(bytes, offset, bytes.length - offset, offset);
    if (read.bytesRead < 1) reject();
    offset += read.bytesRead;
  }
  if (!bytes.equals(file.bytes) || sha256A28(bytes) !== file.sha256) reject();
}

function requestFromLive({ enrolment, gateOwnedRequest, host, macosVersion,
  policy, policySha256, runner, voiceOver, voiceOverVersion }) {
  if (!isDeepStrictEqual(host.executable, gateOwnedRequest.hostExecutable)
    || !isDeepStrictEqual(runner.executable, gateOwnedRequest.runnerExecutable)
    || host.pid !== gateOwnedRequest.applicationPid
    || runner.pid !== gateOwnedRequest.runnerPid
    || host.bundleIdentifier !== gateOwnedRequest.hostBundleIdentifier
    || runner.bundleIdentifier !== policy.runnerBundleIdentifier
    || runner.cdHash !== A28_OFFICIAL_NODE_SIGNING_IDENTITY.cdHash
    || runner.executable.sha256
      !== A28_OFFICIAL_NODE_SIGNING_IDENTITY.executableSha256) reject();
  return assertA28ChallengeRequest({
    ...gateOwnedRequest,
    hostAuditTokenSha256: host.auditTokenSha256,
    hostCdHash: host.cdHash,
    hostDesignatedRequirement: host.designatedRequirement,
    hostStartTime: host.startTime,
    macosVersion,
    policyPinSha256: policySha256,
    reviewerIdentity: policy.reviewerIdentity,
    reviewerKeyId: enrolment.reviewerKeyId,
    runnerAuditTokenSha256: runner.auditTokenSha256,
    runnerBundleIdentifier: runner.bundleIdentifier,
    runnerCdHash: runner.cdHash,
    runnerDesignatedRequirement: runner.designatedRequirement,
    runnerStartTime: runner.startTime,
    voiceOverAuditTokenSha256: voiceOver.auditTokenSha256,
    voiceOverBundleIdentifier: voiceOver.bundleIdentifier,
    voiceOverCdHash: voiceOver.cdHash,
    voiceOverDesignatedRequirement: voiceOver.designatedRequirement,
    voiceOverExecutable: voiceOver.executable,
    voiceOverPid: voiceOver.pid,
    voiceOverStartTime: voiceOver.startTime,
    voiceOverVersion,
  }, policy, Date.now());
}

async function readNewChallenge({ before, policy, request, signal, timeoutAt,
  verifyContinuity }) {
  while (Date.now() < timeoutAt) {
    if (signal?.aborted) reject('A.28 installed witness ceremony was cancelled');
    await verifyContinuity(false);
    const entries = await readdir(policy.checkpointCommitmentDirectoryPath, {
      withFileTypes: true,
    });
    const candidates = entries
      .filter((entry) => entry.isFile()
        && SESSION_FILE.test(entry.name)
        && !before.has(entry.name))
      .sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
    for (const candidate of candidates) {
      const path = resolve(policy.checkpointCommitmentDirectoryPath, candidate.name);
      const file = await readHeldCanonicalA28File(path, {
        maximumBytes: A28_MAX_CHALLENGE_BYTES,
        mode: 0o444,
        uid: 0,
      });
      const challenge = assertA28Challenge(file.value, Date.now(), policy);
      if (challenge.challengeRequestSha256 !== a28ChallengeRequestSha256(request)) continue;
      for (const [key, value] of Object.entries(request)) {
        if (!isDeepStrictEqual(challenge[key], value)) reject();
      }
      return Object.freeze({ challenge, file, path });
    }
    await sleep(500, undefined, signal ? { signal } : undefined);
  }
  reject('A.28 root challenge preparation timed out');
}

function assertDelivery(value, challenge, ordinal) {
  exactKeys(value, [
    'appearance',
    'challengeRequestSha256',
    'checkpointId',
    'checkpointSessionId',
    'mode',
    'ordinal',
    'schemaVersion',
    'token',
    'tokenSha256',
  ]);
  const checkpoint = challenge.stateCheckpoints[ordinal - 1];
  if (!checkpoint
    || value.schemaVersion !== 1
    || value.ordinal !== ordinal
    || value.appearance !== checkpoint.appearance
    || value.mode !== checkpoint.mode
    || value.checkpointId !== checkpoint.checkpointId
    || value.checkpointSessionId !== challenge.checkpointSessionId
    || value.challengeRequestSha256 !== challenge.challengeRequestSha256
    || value.tokenSha256 !== checkpoint.tokenSha256
    || typeof value.token !== 'string'
    || !SHA256.test(value.token)
    || a28CheckpointCommitmentSha256({
      appearance: value.appearance,
      architectureGateRunId: challenge.architectureGateRunId,
      challengeRequestSha256: challenge.challengeRequestSha256,
      checkpointId: value.checkpointId,
      checkpointSessionId: challenge.checkpointSessionId,
      mode: value.mode,
      ordinal,
      token: value.token,
      witnessNonce: challenge.witnessNonce,
    }) !== checkpoint.tokenSha256) reject();
  return Object.freeze({ ...value });
}

async function waitForHeldFile({ path, mode, uid, maximumBytes, signal,
  pendingIdentity, timeoutAt, verifyContinuity }) {
  let unstableSince;
  while (Date.now() < timeoutAt) {
    if (signal?.aborted) reject('A.28 installed witness ceremony was cancelled');
    await verifyContinuity(true);
    try {
      return await readHeldCanonicalA28File(path, { maximumBytes, mode, uid });
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        const pending = await lstat(path);
        const safeLeaf = pending.isFile()
          && !pending.isSymbolicLink()
          && pending.nlink === 1
          && pending.uid === uid
          && (pending.mode & 0o777) === mode
          && pending.size >= 0
          && pending.size <= maximumBytes;
        const safePendingIdentity = pendingIdentity
          && pending.isFile()
          && !pending.isSymbolicLink()
          && pending.nlink === 1
          && pending.dev === pendingIdentity.dev
          && pending.gid === pendingIdentity.gid
          && pending.ino === pendingIdentity.ino
          && pending.uid === pendingIdentity.uid
          && [0o200, 0o400].includes(pending.mode & 0o777)
          && pending.size >= 0
          && pending.size <= maximumBytes;
        if (!safePendingIdentity && !safeLeaf) throw error;
        const waitingAttestationSlot = safePendingIdentity
          && (pending.mode & 0o777) === 0o200;
        if (!waitingAttestationSlot) {
          unstableSince ??= Date.now();
          if (Date.now() - unstableSince > 2_000) throw error;
        }
      }
    }
    await sleep(500, undefined, signal ? { signal } : undefined);
  }
  reject('A.28 installed witness ceremony timed out');
}

async function waitForSpawn(child) {
  if (Number.isSafeInteger(child.pid) && child.pid >= 2) return child.pid;
  return new Promise((resolveSpawn, rejectSpawn) => {
    child.once('spawn', () => resolveSpawn(child.pid));
    child.once('error', rejectSpawn);
  });
}

async function stopExactChild(child, expected) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  if (!expected) {
    const exited = new Promise((resolveExit) => child.once('close', resolveExit));
    child.kill('SIGTERM');
    await Promise.race([exited, sleep(3_000)]);
    return;
  }
  const rows = observeProcesses();
  const row = rows.find((candidate) => candidate.pid === expected.pid
    && candidate.start === expected.start);
  if (!row || executableForPid(row.pid) !== expected.executable) return;
  child.kill('SIGTERM');
  const exited = new Promise((resolveExit) => child.once('close', resolveExit));
  const graceful = await Promise.race([
    exited.then(() => true),
    sleep(3_000).then(() => false),
  ]);
  if (!graceful) {
    const current = observeProcesses().find((candidate) => candidate.pid === expected.pid
      && candidate.start === expected.start);
    if (current && executableForPid(current.pid) === expected.executable) {
      child.kill('SIGKILL');
      await exited;
    }
  }
}

export async function createA28InstalledWitnessCeremony(input) {
  exactKeys(input, [
    'contextDirectory',
    'repositoryRoot',
    'runnerSigningIdentity',
    'signal',
    'timeoutMs',
  ]);
  absolutePath(input.contextDirectory);
  absolutePath(input.repositoryRoot);
  if (!isDeepStrictEqual(
    input.runnerSigningIdentity,
    A28_OFFICIAL_NODE_SIGNING_IDENTITY,
  )) reject();
  const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs)
    || timeoutMs < 60_000
    || timeoutMs > DEFAULT_TIMEOUT_MS) reject();
  const timeoutAt = Date.now() + timeoutMs;
  const state = {
    attestationBytes: undefined,
    authorisation: undefined,
    challenge: undefined,
    challengePath: undefined,
    child: undefined,
    disposed: false,
    enrolment: undefined,
    live: undefined,
    policy: undefined,
    processRows: undefined,
    request: undefined,
    requestFile: undefined,
    lastNativeContinuityCheck: 0,
    phase: 'initial',
    reveals: [],
    witnessProcess: undefined,
  };

  const enterPhase = (expected, next) => {
    if (state.disposed || state.phase !== expected) reject();
    state.phase = next;
  };

  const verifyContinuity = async (includeWitness, forceNative = false) => {
    if (!state.policy || !state.live || !state.processRows) reject();
    if (state.requestFile) await assertHeldRequest(state.requestFile);
    const observed = observeProcesses();
    const expectedRows = [
      state.processRows.host,
      state.processRows.runner,
      state.processRows.voiceOver,
      ...(includeWitness && state.witnessProcess ? [state.witnessProcess] : []),
    ];
    for (const expected of expectedRows) {
      const row = observed.find((candidate) => candidate.pid === expected.pid
        && candidate.start === expected.start);
      if (!row || executableForPid(row.pid) !== expected.executable) reject();
    }
    if (!forceNative
      && Date.now() - state.lastNativeContinuityCheck < 60_000) return;
    await assertRootPinnedExecutable(
      state.policy.rootLauncherPath,
      state.policy.rootLauncherSha256,
    );
    const current = {
      host: inspectProcess(
        state.policy,
        state.live.host.pid,
        state.live.host.bundleIdentifier,
        state.policy.hostTeamIdentifier,
        state.policy.hostDesignatedRequirement,
      ),
      runner: inspectProcess(
        state.policy,
        state.live.runner.pid,
        state.live.runner.bundleIdentifier,
        state.policy.runnerTeamIdentifier,
        state.policy.runnerDesignatedRequirement,
      ),
      voiceOver: inspectProcess(
        state.policy,
        state.live.voiceOver.pid,
        'com.apple.VoiceOver',
        'APPLE-SYSTEM',
        state.policy.voiceOverDesignatedRequirement,
      ),
    };
    if (!isDeepStrictEqual(current.host, state.live.host)
      || !isDeepStrictEqual(current.runner, state.live.runner)
      || !isDeepStrictEqual(current.voiceOver, state.live.voiceOver)) reject();
    if (includeWitness) {
      if (!state.witnessProcess || state.child?.exitCode !== null) reject();
      const witness = inspectProcess(
        state.policy,
        state.witnessProcess.pid,
        state.policy.bundleIdentifier,
        state.policy.teamIdentifier,
        state.policy.designatedRequirement,
      );
      if (!isDeepStrictEqual(witness, state.witnessProcess.inspection)) reject();
    }
    state.lastNativeContinuityCheck = Date.now();
  };

  const ceremony = Object.freeze({
    async prepare(preparedInput) {
      enterPhase('initial', 'preparing');
      exactKeys(preparedInput, [
        'expectedContextPath',
        'expectedContextSha256',
        'gateOwnedRequest',
      ]);
      if (preparedInput.expectedContextPath
          !== resolve(input.contextDirectory, 'expected-context.json')
        || !SHA256.test(preparedInput.expectedContextSha256)) reject();
      const policyFile = await readHeldCanonicalA28File(A28_POLICY_PIN_PATH, {
        maximumBytes: A28_MAX_POLICY_BYTES,
        mode: 0o444,
        uid: 0,
      });
      const policy = assertA28PolicyPin(policyFile.value);
      if (policy.runnerBundleIdentifier
          !== A28_OFFICIAL_NODE_SIGNING_IDENTITY.bundleIdentifier
        || policy.runnerTeamIdentifier
          !== A28_OFFICIAL_NODE_SIGNING_IDENTITY.teamIdentifier
        || policy.runnerDesignatedRequirement
          !== A28_OFFICIAL_NODE_SIGNING_IDENTITY.designatedRequirement) reject();
      if (typeof process.getuid !== 'function'
        || process.getuid() !== policy.witnessUid) reject();
      await assertRootPinnedExecutable(policy.rootLauncherPath, policy.rootLauncherSha256);
      await inspectPinnedA28WitnessApp(policy);
      const enrolmentFile = await readHeldCanonicalA28File(
        policy.enrolmentManifestPath,
        {
          maximumBytes: A28_MAX_ENROLMENT_BYTES,
          mode: 0o444,
          uid: 0,
        },
      );
      const enrolment = assertA28Enrolment(enrolmentFile.value, policy, Date.now());
      const voiceOverRow = findExactProcess(VOICE_OVER_EXECUTABLE);
      const processRows = Object.freeze({
        host: observeProcesses().find((row) =>
          row.pid === preparedInput.gateOwnedRequest.applicationPid),
        runner: observeProcesses().find((row) =>
          row.pid === preparedInput.gateOwnedRequest.runnerPid),
        voiceOver: voiceOverRow,
      });
      for (const [name, row] of Object.entries(processRows)) {
        const expectedExecutable = name === 'host'
          ? preparedInput.gateOwnedRequest.hostExecutable.path
          : name === 'runner'
            ? preparedInput.gateOwnedRequest.runnerExecutable.path
            : VOICE_OVER_EXECUTABLE;
        if (!row || executableForPid(row.pid) !== expectedExecutable) reject();
      }
      const live = Object.freeze({
        host: inspectProcess(
          policy,
          preparedInput.gateOwnedRequest.applicationPid,
          preparedInput.gateOwnedRequest.hostBundleIdentifier,
          policy.hostTeamIdentifier,
          policy.hostDesignatedRequirement,
        ),
        runner: inspectProcess(
          policy,
          preparedInput.gateOwnedRequest.runnerPid,
          policy.runnerBundleIdentifier,
          policy.runnerTeamIdentifier,
          policy.runnerDesignatedRequirement,
        ),
        voiceOver: inspectProcess(
          policy,
          voiceOverRow.pid,
          'com.apple.VoiceOver',
          'APPLE-SYSTEM',
          policy.voiceOverDesignatedRequirement,
        ),
      });
      const request = requestFromLive({
        enrolment,
        gateOwnedRequest: preparedInput.gateOwnedRequest,
        host: live.host,
        macosVersion: systemVersion('/usr/bin/sw_vers', ['-productVersion']),
        policy,
        policySha256: policyFile.identity.sha256,
        runner: live.runner,
        voiceOver: live.voiceOver,
        voiceOverVersion: systemVersion('/usr/bin/plutil', [
          '-extract',
          'CFBundleShortVersionString',
          'raw',
          '-o',
          '-',
          '--',
          '/System/Library/CoreServices/VoiceOver.app/Contents/Info.plist',
        ]),
      });
      const requestPath = resolve(input.contextDirectory, 'challenge-request.json');
      const requestFile = await writeExclusiveCanonical(requestPath, request);
      state.requestFile = requestFile;
      const relativeRequest = relative(input.repositoryRoot, requestPath);
      if (!relativeRequest
        || relativeRequest === '..'
        || relativeRequest.startsWith('../')
        || resolve(input.repositoryRoot, relativeRequest) !== requestPath) reject();
      const before = new Set(await readdir(policy.checkpointCommitmentDirectoryPath));
      state.enrolment = enrolment;
      state.live = live;
      state.policy = policy;
      state.processRows = processRows;
      state.request = request;
      progress('from the repository root, run the already privileged managed prepare command: '
        + `${shellQuote(policy.rootLauncherPath)} --mode checkpoint --action prepare < ${shellQuote(relativeRequest)}`);
      progress('waiting for the root-owned challenge commitment while the packaged host and WDIO runner remain live.');
      const received = await readNewChallenge({
        before,
        policy,
        request,
        signal: input.signal,
        timeoutAt,
        verifyContinuity,
      });
      state.challenge = received.challenge;
      state.challengePath = received.path;
      if (observeProcesses().some((row) => {
        try {
          return executableForPid(row.pid) === policy.witnessExecutable.path;
        } catch {
          return false;
        }
      })) reject('A.28 installed witness application is already running');
      const child = spawn(policy.witnessExecutable.path, [
        '--mode',
        'witness',
        '--challenge',
        received.path,
        '--output',
        received.challenge.attestationSlot.path,
      ], {
        cwd: policy.witnessHomeDirectory,
        env: {
          HOME: policy.witnessHomeDirectory,
          LANG: 'en_AU.UTF-8',
          LC_ALL: 'en_AU.UTF-8',
          PATH: '/usr/bin:/bin',
          ...(typeof process.env.TMPDIR === 'string'
            ? { TMPDIR: process.env.TMPDIR }
            : {}),
        },
        stdio: 'ignore',
      });
      state.child = child;
      const witnessPid = await waitForSpawn(child);
      const row = observeProcesses().find((candidate) => candidate.pid === witnessPid);
      if (!row || executableForPid(witnessPid) !== policy.witnessExecutable.path) reject();
      state.witnessProcess = Object.freeze({
        executable: policy.witnessExecutable.path,
        inspection: undefined,
        pid: witnessPid,
        start: row.start,
      });
      state.witnessProcess = Object.freeze({
        ...state.witnessProcess,
        inspection: inspectProcess(
          policy,
          witnessPid,
          policy.bundleIdentifier,
          policy.teamIdentifier,
          policy.designatedRequirement,
        ),
      });
      await verifyContinuity(true, true);
      state.phase = 'prepared';
      return Object.freeze({
        challenge: received.challenge,
        challengeRequest: request,
        policyPin: policy,
      });
    },

    async reveal(revealInput) {
      exactKeys(revealInput, ['challenge', 'ordinal']);
      const expectedOrdinal = state.reveals.length + 1;
      if (!isDeepStrictEqual(revealInput.challenge, state.challenge)
        || !Number.isSafeInteger(revealInput.ordinal)
        || revealInput.ordinal < 1
        || revealInput.ordinal > 4
        || revealInput.ordinal !== expectedOrdinal
        || !state.witnessProcess) reject();
      const ordinal = revealInput.ordinal;
      enterPhase(
        ordinal === 1 ? 'prepared' : `revealed-${ordinal - 1}`,
        `revealing-${ordinal}`,
      );
      const deliveryPath = resolve(
        state.policy.checkpointDeliveryDirectoryPath,
        `${state.challenge.checkpointSessionId}-${ordinal}.token.json`,
      );
      await verifyContinuity(true, true);
      progress(`run root checkpoint reveal ${ordinal} of 4: `
        + `${shellQuote(state.policy.rootLauncherPath)} --mode checkpoint --action reveal `
        + `--input ${shellQuote(state.challengePath)} `
        + `--output ${shellQuote(state.policy.checkpointDeliveryDirectoryPath)} `
        + `--witness-pid ${state.witnessProcess.pid}`);
      progress(`waiting for root checkpoint reveal ${ordinal} of 4.`);
      const deliveryFile = await waitForHeldFile({
        maximumBytes: A28_MAX_CHALLENGE_BYTES,
        mode: 0o400,
        path: deliveryPath,
        signal: input.signal,
        timeoutAt,
        uid: state.policy.witnessUid,
        verifyContinuity,
      });
      const delivery = assertDelivery(deliveryFile.value, state.challenge, ordinal);
      state.reveals.push(delivery);
      state.phase = `revealed-${ordinal}`;
      progress(`checkpoint ${ordinal} is available in ${deliveryPath}; paste its token into the installed witness before continuing.`);
      return delivery;
    },

    async authorise(authoriseInput) {
      exactKeys(authoriseInput, ['challenge', 'reveals']);
      if (!isDeepStrictEqual(authoriseInput.challenge, state.challenge)
        || !Array.isArray(authoriseInput.reveals)
        || authoriseInput.reveals.length !== 4
        || !isDeepStrictEqual(authoriseInput.reveals, state.reveals)) reject();
      enterPhase('revealed-4', 'authorising');
      for (let index = 0; index < authoriseInput.reveals.length; index += 1) {
        assertDelivery(authoriseInput.reveals[index], state.challenge, index + 1);
      }
      await verifyContinuity(true, true);
      progress('waiting for the reviewer to complete all four VoiceOver observations and biometric signing.');
      const attestation = await waitForHeldFile({
        maximumBytes: A28_MAX_ATTESTATION_BYTES,
        mode: 0o400,
        pendingIdentity: state.challenge.attestationSlot,
        path: state.challenge.attestationSlot.path,
        signal: input.signal,
        timeoutAt,
        uid: state.policy.witnessUid,
        verifyContinuity,
      });
      if (attestation.identity.dev !== state.challenge.attestationSlot.dev
        || attestation.identity.gid !== state.challenge.attestationSlot.gid
        || attestation.identity.ino !== state.challenge.attestationSlot.ino
        || attestation.identity.path !== state.challenge.attestationSlot.path
        || attestation.identity.uid !== state.challenge.attestationSlot.uid) reject();
      state.attestationBytes = attestation.bytes;
      progress('run the already privileged managed verification command: '
        + `${shellQuote(state.policy.rootLauncherPath)} --mode verify `
        + `--attestation ${shellQuote(state.challenge.attestationSlot.path)} `
        + `--challenge ${shellQuote(state.challengePath)} `
        + `--expected-challenge-sha256 ${sha256A28(canonicalA28Line(state.challenge))}`);
      state.authorisation = Object.freeze({
        attestationSha256: attestation.identity.sha256,
        challengeSha256: sha256A28(canonicalA28Line(state.challenge)),
      });
      state.phase = 'authorised';
      return state.authorisation;
    },

    async consume(consumeInput) {
      exactKeys(consumeInput, ['authorisation', 'challenge', 'reveals']);
      if (!isDeepStrictEqual(consumeInput.challenge, state.challenge)
        || !isDeepStrictEqual(consumeInput.authorisation, state.authorisation)
        || !isDeepStrictEqual(consumeInput.reveals, state.reveals)
        || !state.attestationBytes) reject();
      enterPhase('authorised', 'consuming');
      await verifyContinuity(true, true);
      const publishedReceiptPath = resolve(
        state.policy.resultDirectoryPath,
        `${state.challenge.witnessNonce}.json`,
      );
      progress('waiting for root verification, checkpoint consumption and the public 0444 receipt.');
      await waitForHeldFile({
        maximumBytes: A28_MAX_ATTESTATION_BYTES,
        mode: 0o444,
        path: publishedReceiptPath,
        signal: input.signal,
        timeoutAt,
        uid: 0,
        verifyContinuity,
      });
      await verifyContinuity(true);
      state.phase = 'consumed';
      return Object.freeze({
        attestationBytes: state.attestationBytes,
        enrolment: state.enrolment,
        publishedReceiptPath,
      });
    },
  });

  return Object.freeze({
    ceremony,
    async dispose() {
      if (state.disposed) reject();
      state.disposed = true;
      state.phase = 'disposed';
      try {
        await stopExactChild(state.child, state.witnessProcess);
      } finally {
        await state.requestFile?.handle.close();
      }
    },
  });
}
