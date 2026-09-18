#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import {
  lstat,
  open,
  readdir,
  realpath,
} from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import {
  A28_MAX_CHALLENGE_BYTES,
  A28_MAX_ENROLMENT_BYTES,
  A28_MAX_POLICY_BYTES,
  A28_POLICY_PIN_PATH,
  A28_GATE_CONTEXT_AUTHORITY,
  A28_HUMAN_ASSERTION_SCOPE,
  a28CheckpointCommitmentSha256,
  a28ChallengeRequestSha256,
  assertA28Challenge,
  assertA28ChallengeRequest,
  assertA28Enrolment,
  assertA28EnrolmentAuthorityConfig,
  assertA28EnrolmentAuthorityReceipt,
  assertA28PolicyPin,
  assertA28RootLaunchConfig,
  canonicalA28Line,
  parseA28CheckpointAuthorityArguments,
  parseCanonicalA28Line,
  sha256A28,
} from '../verifier/contract.mjs';

const AUTHORITY_CONFIG_PATH =
  '/Library/Application Support/PIUI/A28Witness/enrolment-authority.json';
const MAX_AUTHORITY_RECORD_BYTES = 65_536;
const MAX_AUTHORITY_DIRECTORY_ENTRIES = 4_096;

function reject(message = 'A.28 root checkpoint authority rejected') {
  throw new Error(message);
}

function exactKeys(value, expected) {
  if (value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || !isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort())) reject();
}

function sameFile(before, after) {
  return before.dev === after.dev
    && before.ino === after.ino
    && before.size === after.size
    && before.mode === after.mode
    && before.mtimeMs === after.mtimeMs
    && before.ctimeMs === after.ctimeMs;
}

async function assertPathChain(path, { directory = false, mode, uid = 0 }) {
  if (typeof path !== 'string'
    || !path.startsWith('/')
    || resolve(path) !== path
    || /[\0\r\n]/u.test(path)
    || await realpath(path) !== path) reject();
  let current = path;
  let leaf = true;
  while (true) {
    const item = await lstat(current);
    if (item.isSymbolicLink()
      || item.uid !== (leaf ? uid : 0)
      || (item.mode & 0o022) !== 0
      || (leaf && (item.mode & 0o777) !== mode)
      || (leaf && directory && !item.isDirectory())
      || (leaf && !directory && (!item.isFile() || item.nlink !== 1))
      || (!leaf && !item.isDirectory())) reject();
    if (current === '/') break;
    current = dirname(current);
    leaf = false;
  }
}

async function readHeldCanonical(path, { maximumBytes, mode, uid = 0 }) {
  await assertPathChain(path, { mode, uid });
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    if (before.size < 3 || before.size > maximumBytes) reject();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const pathname = await lstat(path);
    if (!sameFile(before, after)
      || !sameFile(before, pathname)
      || bytes.length !== before.size) reject();
    return Object.freeze({
      bytes,
      identity: Object.freeze({
        dev: before.dev,
        gid: before.gid,
        ino: before.ino,
        mode: before.mode & 0o777,
        path,
        sha256: sha256A28(bytes),
        size: before.size,
        uid: before.uid,
      }),
      value: parseCanonicalA28Line(bytes),
    });
  } finally {
    await handle?.close();
  }
}

async function writeExclusiveCanonical(path, value, { gid = 0, mode, uid = 0 }) {
  const bytes = canonicalA28Line(value);
  let handle;
  try {
    handle = await open(
      path,
      constants.O_CREAT
        | constants.O_EXCL
        | constants.O_WRONLY
        | constants.O_NOFOLLOW,
      0o600,
    );
    await handle.chown(uid, gid);
    await handle.chmod(mode);
    await handle.writeFile(bytes);
    await handle.sync();
    const item = await handle.stat();
    if (item.uid !== uid
      || item.gid !== gid
      || (item.mode & 0o777) !== mode
      || item.size !== bytes.length) reject();
  } finally {
    await handle?.close();
  }
  return bytes;
}

async function syncDirectory(path) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function createAttestationSlot(policy, checkpointSessionId) {
  const path = resolve(
    policy.checkpointDeliveryDirectoryPath,
    checkpointSessionId + '.attestation.json',
  );
  if (dirname(path) !== policy.checkpointDeliveryDirectoryPath) reject();
  let handle;
  try {
    handle = await open(
      path,
      constants.O_CREAT
        | constants.O_EXCL
        | constants.O_WRONLY
        | constants.O_NOFOLLOW,
      0o600,
    );
    const initial = await handle.stat();
    if (!initial.isFile()
      || initial.isSymbolicLink()
      || initial.nlink !== 1
      || initial.uid !== 0
      || initial.gid !== 0
      || (initial.mode & 0o777) !== 0o600
      || initial.size !== 0) reject();
    await handle.chown(policy.witnessUid, policy.witnessGid);
    await handle.chmod(0o200);
    await handle.sync();
    const sealed = await handle.stat();
    const pathname = await lstat(path);
    if (!sameFile(sealed, pathname)
      || !sealed.isFile()
      || sealed.isSymbolicLink()
      || sealed.nlink !== 1
      || sealed.uid !== policy.witnessUid
      || sealed.gid !== policy.witnessGid
      || (sealed.mode & 0o777) !== 0o200
      || sealed.size !== 0) reject();
    return Object.freeze({
      dev: sealed.dev,
      gid: sealed.gid,
      ino: sealed.ino,
      path,
      uid: sealed.uid,
    });
  } finally {
    await handle?.close();
    await syncDirectory(policy.checkpointDeliveryDirectoryPath);
  }
}

async function consumeChallengeRequest(policy, requestFile) {
  const entries = await readdir(policy.checkpointAuthorityDirectoryPath, {
    withFileTypes: true,
  });
  if (entries.length >= MAX_AUTHORITY_DIRECTORY_ENTRIES
    || entries.some((entry) => entry.isSymbolicLink())) {
    reject('A.28 checkpoint authority quota is exhausted');
  }
  const challengeRequestSha256 = a28ChallengeRequestSha256(requestFile.value);
  if (requestFile.identity.sha256 !== sha256A28(requestFile.bytes)) reject();
  const markerPath = resolve(
    policy.checkpointAuthorityDirectoryPath,
    'request-sha256-' + challengeRequestSha256 + '.consumed.json',
  );
  if (dirname(markerPath) !== policy.checkpointAuthorityDirectoryPath) reject();
  try {
    await writeExclusiveCanonical(markerPath, {
      challengeRequestSha256,
      consumedAt: new Date().toISOString(),
      event: 'a28-root-challenge-request-consumed',
      requestIdentity: requestFile.identity,
      schemaVersion: 1,
    }, { mode: 0o400 });
    await syncDirectory(policy.checkpointAuthorityDirectoryPath);
  } catch (error) {
    if (error?.code === 'EEXIST') {
      reject('A.28 challenge request was already consumed');
    }
    throw error;
  }
  return challengeRequestSha256;
}

async function assertPinnedInspector(policy) {
  await assertPathChain(policy.processInspectorPath, { mode: 0o555 });
  let handle;
  try {
    handle = await open(
      policy.processInspectorPath,
      constants.O_RDONLY | constants.O_NOFOLLOW,
    );
    const before = await handle.stat();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (before.size < 8_192
      || before.size > 32 * 1024 * 1024
      || !sameFile(before, after)
      || sha256A28(bytes) !== policy.processInspectorSha256) reject();
  } finally {
    await handle?.close();
  }
}

function inspectProcess(policy, pid, bundleIdentifier, teamIdentifier, requirement) {
  const result = spawnSync(policy.processInspectorPath, [
    '--pid',
    String(pid),
    '--bundle-id',
    bundleIdentifier,
    '--team-id',
    teamIdentifier,
    '--reported-requirement',
    requirement,
  ], {
    encoding: null,
    env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
    maxBuffer: 256 * 1024,
    timeout: 30_000,
  });
  if (result.error
    || result.signal
    || result.status !== 0
    || !Buffer.isBuffer(result.stdout)
    || !Buffer.isBuffer(result.stderr)
    || result.stderr.length !== 0) reject();
  return parseCanonicalA28Line(result.stdout);
}

function inspectChallengePeers(policy, challenge, witnessPid) {
  const peers = {
    host: inspectProcess(
      policy,
      challenge.applicationPid,
      challenge.hostBundleIdentifier,
      policy.hostTeamIdentifier,
      policy.hostDesignatedRequirement,
    ),
    runner: inspectProcess(
      policy,
      challenge.runnerPid,
      challenge.runnerBundleIdentifier,
      policy.runnerTeamIdentifier,
      policy.runnerDesignatedRequirement,
    ),
    voiceOver: inspectProcess(
      policy,
      challenge.voiceOverPid,
      'com.apple.VoiceOver',
      'APPLE-SYSTEM',
      policy.voiceOverDesignatedRequirement,
    ),
  };
  if (witnessPid !== undefined) {
    peers.witness = inspectProcess(
      policy,
      witnessPid,
      policy.bundleIdentifier,
      policy.teamIdentifier,
      policy.designatedRequirement,
    );
  }
  return peers;
}

function expectedChallengePeers(challenge) {
  return {
    host: {
      auditTokenSha256: challenge.hostAuditTokenSha256,
      bundleIdentifier: challenge.hostBundleIdentifier,
      cdHash: challenge.hostCdHash,
      designatedRequirement: challenge.hostDesignatedRequirement,
      executable: challenge.hostExecutable,
      pid: challenge.applicationPid,
      startTime: challenge.hostStartTime,
    },
    runner: {
      auditTokenSha256: challenge.runnerAuditTokenSha256,
      bundleIdentifier: challenge.runnerBundleIdentifier,
      cdHash: challenge.runnerCdHash,
      designatedRequirement: challenge.runnerDesignatedRequirement,
      executable: challenge.runnerExecutable,
      pid: challenge.runnerPid,
      startTime: challenge.runnerStartTime,
    },
    voiceOver: {
      auditTokenSha256: challenge.voiceOverAuditTokenSha256,
      bundleIdentifier: challenge.voiceOverBundleIdentifier,
      cdHash: challenge.voiceOverCdHash,
      designatedRequirement: challenge.voiceOverDesignatedRequirement,
      executable: challenge.voiceOverExecutable,
      pid: challenge.voiceOverPid,
      startTime: challenge.voiceOverStartTime,
    },
  };
}

function assertSystemVersions(challenge) {
  const macos = spawnSync('/usr/bin/sw_vers', ['-productVersion'], {
    encoding: 'utf8',
    env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
    timeout: 10_000,
  });
  const voiceOver = spawnSync('/usr/bin/plutil', [
    '-extract',
    'CFBundleShortVersionString',
    'raw',
    '-o',
    '-',
    '--',
    '/System/Library/CoreServices/VoiceOver.app/Contents/Info.plist',
  ], {
    encoding: 'utf8',
    env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
    timeout: 10_000,
  });
  if (macos.error || macos.signal || macos.status !== 0
    || voiceOver.error || voiceOver.signal || voiceOver.status !== 0
    || macos.stdout.trim() !== challenge.macosVersion
    || voiceOver.stdout.trim() !== challenge.voiceOverVersion) reject();
}

async function readAuthorityMaterials(now = Date.now()) {
  const [policyFile, configFile] = await Promise.all([
    readHeldCanonical(A28_POLICY_PIN_PATH, {
      maximumBytes: A28_MAX_POLICY_BYTES,
      mode: 0o444,
    }),
    readHeldCanonical(AUTHORITY_CONFIG_PATH, {
      maximumBytes: A28_MAX_POLICY_BYTES,
      mode: 0o444,
    }),
  ]);
  const policy = assertA28PolicyPin(policyFile.value);
  const config = assertA28EnrolmentAuthorityConfig(configFile.value);
  if (sha256A28(configFile.bytes) !== policy.enrolmentAuthorityConfigSha256) reject();
  const [enrolmentFile, receiptFile] = await Promise.all([
    readHeldCanonical(policy.enrolmentManifestPath, {
      maximumBytes: A28_MAX_ENROLMENT_BYTES,
      mode: 0o444,
    }),
    readHeldCanonical(policy.enrolmentAuthorityReceiptPath, {
      maximumBytes: A28_MAX_ENROLMENT_BYTES,
      mode: 0o400,
    }),
  ]);
  const enrolment = assertA28Enrolment(enrolmentFile.value, policy, now);
  assertA28EnrolmentAuthorityReceipt(receiptFile.value, {
    authorityConfig: config,
    enrolment,
    now,
    policyPin: policy,
  });
  if (sha256A28(receiptFile.bytes) !== policy.enrolmentAuthorityReceiptSha256) reject();
  const launchConfigFile = await readHeldCanonical(
    policy.rootCheckpointLaunchConfigPath,
    {
      maximumBytes: A28_MAX_POLICY_BYTES,
      mode: 0o444,
    },
  );
  if (sha256A28(launchConfigFile.bytes)
      !== policy.rootCheckpointLaunchConfigSha256) reject();
  assertA28RootLaunchConfig(launchConfigFile.value, policy, 'checkpoint');
  await assertPinnedInspector(policy);
  return Object.freeze({ config, enrolment, policy, policyFile });
}

function assertLaunchedAuthority(policy, parsedArguments) {
  if (typeof process.getuid !== 'function'
    || typeof process.geteuid !== 'function'
    || process.getuid() !== 0
    || process.geteuid() !== 0
    || fileURLToPath(import.meta.url) !== policy.rootCheckpointAuthorityPath
    || resolve(process.argv[1]) !== policy.rootCheckpointAuthorityPath
    || process.execPath !== policy.rootVerifierNodePath
    || process.execArgv.length !== 0
    || process.cwd() !== '/private/var/empty'
    || process.env.PATH !== '/usr/bin:/bin'
    || process.env.HOME !== '/var/root'
    || process.env.LANG !== 'C'
    || process.env.LC_ALL !== 'C'
    || Object.keys(process.env).some((name) =>
      name.startsWith('NODE_')
        || name.startsWith('DYLD_')
        || name.startsWith('LD_')
        || ['BASH_ENV', 'ENV', 'OPENSSL_CONF', 'SSLKEYLOGFILE'].includes(name))
    || (parsedArguments.action === 'prepare'
      && parsedArguments.witnessPid !== undefined)
    || (parsedArguments.action === 'reveal'
      && (!Number.isSafeInteger(parsedArguments.witnessPid)
        || parsedArguments.witnessPid < 2))) reject();
}

async function prepareChallenge(materials, requestPath, outputDirectory) {
  const { enrolment, policy, policyFile } = materials;
  if (outputDirectory !== policy.checkpointCommitmentDirectoryPath) reject();
  await assertPathChain(outputDirectory, { directory: true, mode: 0o755 });
  await assertPathChain(policy.checkpointAuthorityDirectoryPath, {
    directory: true,
    mode: 0o700,
  });
  if (dirname(requestPath) !== policy.checkpointAuthorityDirectoryPath
    || !/\/request-[0-9a-f]{64}\.json$/u.test(requestPath)) reject();
  const requestFile = await readHeldCanonical(requestPath, {
    maximumBytes: A28_MAX_CHALLENGE_BYTES,
    mode: 0o400,
  });
  const request = assertA28ChallengeRequest(requestFile.value, policy);
  const challengeRequestSha256 = await consumeChallengeRequest(
    policy,
    requestFile,
  );
  if (request.reviewerKeyId !== enrolment.reviewerKeyId) reject();
  const peers = inspectChallengePeers(policy, request);
  if (!isDeepStrictEqual(peers, expectedChallengePeers(request))) reject();
  assertSystemVersions(request);
  const checkpointSessionId = randomBytes(32).toString('hex');
  const witnessNonce = randomBytes(32).toString('hex');
  const tokens = [0, 1, 2, 3].map(() => randomBytes(32).toString('hex'));
  if (new Set(tokens).size !== 4) reject();
  const labels = [
    ['dark', 'accessible'],
    ['dark', 'virtualised'],
    ['light', 'accessible'],
    ['light', 'virtualised'],
  ];
  const stateCheckpoints = labels.map(([appearance, mode], index) => {
    const checkpointId = randomBytes(32).toString('hex');
    return {
      appearance,
      checkpointId,
      mode,
      ordinal: index + 1,
      tokenSha256: a28CheckpointCommitmentSha256({
        appearance,
        architectureGateRunId: request.architectureGateRunId,
        challengeRequestSha256,
        checkpointId,
        checkpointSessionId,
        mode,
        ordinal: index + 1,
        token: tokens[index],
        witnessNonce,
      }),
    };
  });
  const attestationSlot = await createAttestationSlot(
    policy,
    checkpointSessionId,
  );
  const issued = Date.now();
  const challenge = assertA28Challenge({
    ...request,
    attestationSlot,
    challengeExpiresAt: new Date(issued + 20 * 60_000).toISOString(),
    challengeIssuedAt: new Date(issued).toISOString(),
    challengeRequestSha256,
    checkpointSessionId,
    gateContextAuthority: A28_GATE_CONTEXT_AUTHORITY,
    stateCheckpoints,
    witnessNonce,
  }, issued, policy);
  const challengeBytes = canonicalA28Line(challenge);
  const challengeSha256 = sha256A28(challengeBytes);
  const session = {
    attestationSlot,
    challengeSha256,
    challengeRequestSha256,
    checkpointSessionId,
    createdAt: new Date(issued).toISOString(),
    event: 'a28-root-checkpoint-session-created',
    initialIdentities: peers,
    policyPinSha256: sha256A28(policyFile.bytes),
    schemaVersion: 1,
    requestIdentity: requestFile.identity,
    stateCheckpoints,
    tokens: stateCheckpoints.map((checkpoint, index) => ({
      ...checkpoint,
      token: tokens[index],
    })),
    witnessNonce,
  };
  const sessionPath = resolve(
    policy.checkpointAuthorityDirectoryPath,
    checkpointSessionId + '.session.json',
  );
  const challengePath = resolve(
    outputDirectory,
    checkpointSessionId + '.challenge.json',
  );
  if (dirname(sessionPath) !== policy.checkpointAuthorityDirectoryPath
    || dirname(challengePath) !== outputDirectory) reject();
  await writeExclusiveCanonical(sessionPath, session, { mode: 0o400 });
  await writeExclusiveCanonical(challengePath, challenge, { mode: 0o444 });
  return Object.freeze({
    attestationSlot,
    challengePath,
    challengeSha256,
    challengeRequestSha256,
    checkpointSessionId,
    gateContextAuthority: A28_GATE_CONTEXT_AUTHORITY,
    humanWitnessed: false,
    runnerAuthority: 'continuity-only',
    schemaVersion: 1,
  });
}

async function pathExists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

async function revealNextCheckpoint(
  materials,
  challengePath,
  outputDirectory,
  witnessPid,
) {
  const { policy, policyFile } = materials;
  if (outputDirectory !== policy.checkpointDeliveryDirectoryPath) reject();
  await assertPathChain(outputDirectory, { directory: true, mode: 0o755 });
  const challengeFile = await readHeldCanonical(challengePath, {
    maximumBytes: A28_MAX_CHALLENGE_BYTES,
    mode: 0o444,
  });
  const challenge = assertA28Challenge(challengeFile.value, Date.now(), policy);
  const sessionPath = resolve(
    policy.checkpointAuthorityDirectoryPath,
    challenge.checkpointSessionId + '.session.json',
  );
  const sessionFile = await readHeldCanonical(sessionPath, {
    maximumBytes: MAX_AUTHORITY_RECORD_BYTES,
    mode: 0o400,
  });
  const session = sessionFile.value;
  exactKeys(session, [
    'attestationSlot',
    'challengeSha256',
    'challengeRequestSha256',
    'checkpointSessionId',
    'createdAt',
    'event',
    'initialIdentities',
    'policyPinSha256',
    'requestIdentity',
    'schemaVersion',
    'stateCheckpoints',
    'tokens',
    'witnessNonce',
  ]);
  if (session.schemaVersion !== 1
    || session.event !== 'a28-root-checkpoint-session-created'
    || session.challengeSha256 !== sha256A28(challengeFile.bytes)
    || session.challengeRequestSha256 !== challenge.challengeRequestSha256
    || !isDeepStrictEqual(session.attestationSlot, challenge.attestationSlot)
    || session.checkpointSessionId !== challenge.checkpointSessionId
    || session.policyPinSha256 !== sha256A28(policyFile.bytes)
    || session.witnessNonce !== challenge.witnessNonce
    || !isDeepStrictEqual(session.stateCheckpoints, challenge.stateCheckpoints)
    || !Array.isArray(session.tokens)
    || session.tokens.length !== 4) reject();
  let ordinal;
  for (let candidate = 1; candidate <= 4; candidate += 1) {
    const receiptPath = resolve(
      policy.checkpointAuthorityDirectoryPath,
      challenge.checkpointSessionId + '-' + candidate + '.reveal.json',
    );
    if (!await pathExists(receiptPath)) {
      ordinal = candidate;
      break;
    }
  }
  if (ordinal === undefined) reject('A.28 checkpoint session is already fully revealed');
  const checkpoint = challenge.stateCheckpoints[ordinal - 1];
  const tokenRecord = session.tokens[ordinal - 1];
  if (!isDeepStrictEqual(tokenRecord, {
    ...checkpoint,
    token: tokenRecord.token,
  })
    || a28CheckpointCommitmentSha256({
      appearance: checkpoint.appearance,
      architectureGateRunId: challenge.architectureGateRunId,
      challengeRequestSha256: challenge.challengeRequestSha256,
      checkpointId: checkpoint.checkpointId,
      checkpointSessionId: challenge.checkpointSessionId,
      mode: checkpoint.mode,
      ordinal,
      token: tokenRecord.token,
      witnessNonce: challenge.witnessNonce,
    }) !== checkpoint.tokenSha256) reject();
  process.stderr.write(
    '[working] Validating the retained host, runner, VoiceOver and witness identities.\n',
  );
  const peers = inspectChallengePeers(policy, challenge, witnessPid);
  if (!isDeepStrictEqual(
    Object.fromEntries(Object.entries(peers).filter(([key]) => key !== 'witness')),
    expectedChallengePeers(challenge),
  )
    || peers.witness.bundleIdentifier !== policy.bundleIdentifier
    || peers.witness.cdHash !== policy.cdHash
    || peers.witness.designatedRequirement !== policy.designatedRequirement
    || !isDeepStrictEqual(peers.witness.executable, policy.witnessExecutable)) reject();
  const revealedAt = new Date().toISOString();
  const delivery = {
    appearance: checkpoint.appearance,
    challengeRequestSha256: challenge.challengeRequestSha256,
    checkpointId: checkpoint.checkpointId,
    checkpointSessionId: challenge.checkpointSessionId,
    mode: checkpoint.mode,
    ordinal,
    schemaVersion: 1,
    token: tokenRecord.token,
    tokenSha256: checkpoint.tokenSha256,
  };
  const deliveryPath = resolve(
    outputDirectory,
    challenge.checkpointSessionId + '-' + ordinal + '.token.json',
  );
  const receiptPath = resolve(
    policy.checkpointAuthorityDirectoryPath,
    challenge.checkpointSessionId + '-' + ordinal + '.reveal.json',
  );
  if (dirname(deliveryPath) !== outputDirectory
    || dirname(receiptPath) !== policy.checkpointAuthorityDirectoryPath) reject();
  const receipt = {
    challengeSha256: sha256A28(challengeFile.bytes),
    challengeRequestSha256: challenge.challengeRequestSha256,
    checkpointId: checkpoint.checkpointId,
    checkpointSessionId: challenge.checkpointSessionId,
    event: 'a28-root-checkpoint-revealed',
    liveIdentities: peers,
    ordinal,
    revealedAt,
    schemaVersion: 1,
    token: tokenRecord.token,
    tokenSha256: checkpoint.tokenSha256,
  };
  await writeExclusiveCanonical(deliveryPath, delivery, {
    gid: policy.witnessGid,
    mode: 0o400,
    uid: policy.witnessUid,
  });
  await writeExclusiveCanonical(receiptPath, receipt, { mode: 0o400 });
  return Object.freeze({
    checkpointId: checkpoint.checkpointId,
    checkpointSessionId: challenge.checkpointSessionId,
    deliveryPath,
    humanWitnessed: false,
    ordinal,
    schemaVersion: 1,
  });
}

async function authoriseCheckpointSession(
  materials,
  challengePath,
  requestPath,
) {
  const { policy, policyFile } = materials;
  if (dirname(requestPath) !== policy.checkpointAuthorityDirectoryPath
    || !requestPath.endsWith('.authorise-request.json')) reject();
  const [challengeFile, requestFile] = await Promise.all([
    readHeldCanonical(challengePath, {
      maximumBytes: A28_MAX_CHALLENGE_BYTES,
      mode: 0o444,
    }),
    readHeldCanonical(requestPath, {
      maximumBytes: MAX_AUTHORITY_RECORD_BYTES,
      mode: 0o400,
    }),
  ]);
  const challenge = assertA28Challenge(challengeFile.value, Date.now(), policy);
  const request = requestFile.value;
  exactKeys(request, [
    'challengeSha256',
    'challengeRequestSha256',
    'checkpointChecksSha256',
    'checkpointSessionId',
    'checks',
    'completedAt',
    'schemaVersion',
    'witnessPid',
  ]);
  if (request.schemaVersion !== 1
    || request.challengeSha256 !== sha256A28(challengeFile.bytes)
    || request.challengeRequestSha256 !== challenge.challengeRequestSha256
    || request.checkpointSessionId !== challenge.checkpointSessionId
    || request.checkpointChecksSha256
      !== sha256A28(canonicalA28Line(request.checks))
    || !Number.isSafeInteger(request.witnessPid)
    || request.witnessPid < 2
    || !Array.isArray(request.checks)
    || request.checks.length !== 4
    || !Number.isFinite(Date.parse(request.completedAt))) reject();
  const sessionPath = resolve(
    policy.checkpointAuthorityDirectoryPath,
    challenge.checkpointSessionId + '.session.json',
  );
  const sessionFile = await readHeldCanonical(sessionPath, {
    maximumBytes: MAX_AUTHORITY_RECORD_BYTES,
    mode: 0o400,
  });
  const session = sessionFile.value;
  exactKeys(session, [
    'attestationSlot',
    'challengeSha256',
    'challengeRequestSha256',
    'checkpointSessionId',
    'createdAt',
    'event',
    'initialIdentities',
    'policyPinSha256',
    'requestIdentity',
    'schemaVersion',
    'stateCheckpoints',
    'tokens',
    'witnessNonce',
  ]);
  if (session.challengeSha256 !== request.challengeSha256
    || session.challengeRequestSha256 !== challenge.challengeRequestSha256
    || !isDeepStrictEqual(session.attestationSlot, challenge.attestationSlot)
    || session.checkpointSessionId !== request.checkpointSessionId
    || session.policyPinSha256 !== sha256A28(policyFile.bytes)
    || !isDeepStrictEqual(session.stateCheckpoints, challenge.stateCheckpoints)
    || !Array.isArray(session.tokens)
    || session.tokens.length !== 4) reject();
  let previousReveal = Date.parse(challenge.challengeIssuedAt);
  for (let index = 0; index < 4; index += 1) {
    const ordinal = index + 1;
    const checkpoint = challenge.stateCheckpoints[index];
    const tokenRecord = session.tokens[index];
    const decision = request.checks[index];
    const revealPath = resolve(
      policy.checkpointAuthorityDirectoryPath,
      challenge.checkpointSessionId + '-' + ordinal + '.reveal.json',
    );
    const revealFile = await readHeldCanonical(revealPath, {
      maximumBytes: MAX_AUTHORITY_RECORD_BYTES,
      mode: 0o400,
    });
    const reveal = revealFile.value;
    exactKeys(reveal, [
      'challengeSha256',
      'challengeRequestSha256',
      'checkpointId',
      'checkpointSessionId',
      'event',
      'liveIdentities',
      'ordinal',
      'revealedAt',
      'schemaVersion',
      'token',
      'tokenSha256',
    ]);
    const revealAt = Date.parse(reveal.revealedAt);
    const observedAt = Date.parse(decision?.observedAt);
    if (reveal.schemaVersion !== 1
      || reveal.event !== 'a28-root-checkpoint-revealed'
      || reveal.challengeSha256 !== request.challengeSha256
      || reveal.challengeRequestSha256 !== challenge.challengeRequestSha256
      || reveal.checkpointSessionId !== request.checkpointSessionId
      || reveal.checkpointId !== checkpoint.checkpointId
      || reveal.ordinal !== ordinal
      || reveal.token !== tokenRecord.token
      || reveal.tokenSha256 !== checkpoint.tokenSha256
      || !Number.isFinite(revealAt)
      || !Number.isFinite(observedAt)
      || revealAt < previousReveal
      || revealAt > observedAt
      || decision.appearance !== checkpoint.appearance
      || decision.mode !== checkpoint.mode
      || decision.checkpointId !== checkpoint.checkpointId
      || decision.checkpointOrdinal !== ordinal
      || decision.checkpointToken !== reveal.token
      || decision.checkpointTokenSha256 !== checkpoint.tokenSha256
      || decision.humanAssertion !== true
      || decision.assertionScope !== A28_HUMAN_ASSERTION_SCOPE
      || a28CheckpointCommitmentSha256({
        appearance: checkpoint.appearance,
        architectureGateRunId: challenge.architectureGateRunId,
        challengeRequestSha256: challenge.challengeRequestSha256,
        checkpointId: checkpoint.checkpointId,
        checkpointSessionId: challenge.checkpointSessionId,
        mode: checkpoint.mode,
        ordinal,
        token: reveal.token,
        witnessNonce: challenge.witnessNonce,
      }) !== checkpoint.tokenSha256) reject();
    previousReveal = revealAt;
  }
  if (previousReveal > Date.parse(request.completedAt)) reject();
  const live = inspectChallengePeers(policy, challenge, request.witnessPid);
  if (!isDeepStrictEqual(
    Object.fromEntries(Object.entries(live).filter(([key]) => key !== 'witness')),
    expectedChallengePeers(challenge),
  )
    || live.witness.bundleIdentifier !== policy.bundleIdentifier
    || live.witness.cdHash !== policy.cdHash
    || live.witness.designatedRequirement !== policy.designatedRequirement
    || !isDeepStrictEqual(live.witness.executable, policy.witnessExecutable)) reject();
  const authorisation = {
    authorised: true,
    authorisedAt: new Date().toISOString(),
    challengeSha256: request.challengeSha256,
    challengeRequestSha256: challenge.challengeRequestSha256,
    checkpointChecksSha256: request.checkpointChecksSha256,
    checkpointSessionId: request.checkpointSessionId,
  };
  const consumptionPath = resolve(
    policy.checkpointAuthorityDirectoryPath,
    challenge.checkpointSessionId + '.consumed.json',
  );
  if (dirname(consumptionPath) !== policy.checkpointAuthorityDirectoryPath) reject();
  await writeExclusiveCanonical(consumptionPath, authorisation, { mode: 0o400 });
  return Object.freeze(authorisation);
}

export async function runA28CheckpointAuthority(arguments_) {
  const materials = await readAuthorityMaterials();
  assertLaunchedAuthority(materials.policy, arguments_);
  if (arguments_.action === 'prepare') {
    return prepareChallenge(materials, arguments_.input, arguments_.output);
  }
  if (arguments_.action === 'authorise') {
    return authoriseCheckpointSession(
      materials,
      arguments_.input,
      arguments_.output,
    );
  }
  return revealNextCheckpoint(
    materials,
    arguments_.input,
    arguments_.output,
    arguments_.witnessPid,
  );
}

if (import.meta.url === new URL(process.argv[1], 'file:').href) {
  runA28CheckpointAuthority(
    parseA28CheckpointAuthorityArguments(process.argv.slice(2)),
  )
    .then((result) => process.stdout.write(canonicalA28Line(result)))
    .catch((error) => {
      process.stderr.write('A.28 root checkpoint authority failed: '
        + error.message + '\n');
      process.exitCode = 1;
    });
}
