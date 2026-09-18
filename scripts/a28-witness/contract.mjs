import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from 'node:crypto';
import { resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';

export const A28_WITNESS_DOMAIN = 'au.com.piui.a28.voiceover-witness.v1';
export const A28_ENROLMENT_DOMAIN = 'au.com.piui.a28.secure-enclave-enrolment.v1';
export const A28_WITNESS_BUNDLE_ID = 'au.com.piui.a28-witness';
export const A28_WITNESS_POLICY_ID = 'piui-a28-witness-policy-v1';
export const A28_WITNESS_SCHEMA_VERSION = 1;
export const A28_GATE_CONTEXT_AUTHORITY =
  'external-final-consumer-required';
export const A28_HUMAN_ASSERTION_SCOPE =
  'reviewer-reported-voiceover-behaviour-only;excludes-run-source-artifact-fingerprint-authentication';
export const A28_POLICY_PIN_PATH =
  '/Library/Application Support/PIUI/A28Witness/policy-pin.json';
export const A28_MAX_ATTESTATION_BYTES = 65_536;
export const A28_MAX_CHALLENGE_BYTES = 65_536;
export const A28_MAX_ENROLMENT_BYTES = 65_536;
export const A28_MAX_POLICY_BYTES = 65_536;
export const A28_MAX_PUBLISHED_RECEIPT_BYTES = 65_536;
export const A28_WITNESS_SIGNING_PREFIX = Buffer.from(
  'PIUI-A28-VOICEOVER-WITNESS\0v1\0',
  'utf8',
);
export const A28_ENROLMENT_SIGNING_PREFIX = Buffer.from(
  'PIUI-A28-SECURE-ENCLAVE-ENROLMENT\0v1\0',
  'utf8',
);
export const A28_CHALLENGE_REQUEST_PREFIX = Buffer.from(
  'PIUI-A28-CHALLENGE-REQUEST\0v1\0',
  'utf8',
);

const SHA256 = /^[0-9a-f]{64}$/u;
const CDHASH = /^[0-9a-f]{40}$/u;
const UUID = /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const MACOS_VERSION = /^\d{1,3}\.\d{1,3}(?:\.\d{1,3})?$/u;
const VOICEOVER_VERSION = /^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$/u;
const GATE_RUN_ID = /^\d{8}T\d{9}Z-[0-9a-f]{32}$/u;
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const PROCESS_START = /^\d{1,12}\.\d{6}$/u;
const MAX_CANONICAL_BYTES = Math.max(
  A28_MAX_ATTESTATION_BYTES,
  A28_MAX_CHALLENGE_BYTES,
  A28_MAX_ENROLMENT_BYTES,
  A28_MAX_POLICY_BYTES,
  A28_MAX_PUBLISHED_RECEIPT_BYTES,
);
const MAX_WITNESS_WINDOW_MS = 30 * 60_000;
const MAX_CLOCK_SKEW_MS = 5 * 60_000;
const MAX_ATTESTATION_AGE_MS = 15 * 60_000;
const P256_ORDER = BigInt(
  '0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
);
const EXPECTED_COMBINATIONS = Object.freeze([
  'dark:accessible',
  'dark:virtualised',
  'light:accessible',
  'light:virtualised',
]);
const DECISION_KEYS = Object.freeze([
  'announcements',
  'appearance',
  'blockingDefects',
  'checkpointId',
  'checkpointOrdinal',
  'checkpointToken',
  'checkpointTokenSha256',
  'focusRetention',
  'humanAssertion',
  'keyboardOrder',
  'mode',
  'observedAt',
  'assertionScope',
]);
const EXECUTABLE_KEYS = Object.freeze(['dev', 'ino', 'path', 'sha256', 'size']);
const ATTESTATION_SLOT_KEYS = Object.freeze([
  'dev',
  'gid',
  'ino',
  'path',
  'uid',
]);
const ATTESTATION_OUTPUT_IDENTITY_KEYS = Object.freeze([
  'dev',
  'gid',
  'ino',
  'mode',
  'path',
  'sha256',
  'size',
  'uid',
]);
const STATE_CHECKPOINT_KEYS = Object.freeze([
  'appearance',
  'checkpointId',
  'mode',
  'ordinal',
  'tokenSha256',
]);
const CHALLENGE_KEYS = Object.freeze([
  'applicationPid',
  'architectureGateRunContextSha256',
  'architectureGateRunId',
  'attestationSlot',
  'automationTwinFingerprint',
  'challengeExpiresAt',
  'challengeIssuedAt',
  'challengeRequestSha256',
  'checkpointSessionId',
  'gateId',
  'gateContextAuthority',
  'hostAuditTokenSha256',
  'hostBundleFingerprint',
  'hostBundleIdentifier',
  'hostBundlePath',
  'hostCdHash',
  'hostDesignatedRequirement',
  'hostExecutable',
  'hostStartTime',
  'macosVersion',
  'measuredTwinDeltaSha256',
  'policyPinSha256',
  'productionFingerprint',
  'reviewerIdentity',
  'reviewerKeyId',
  'runnerAuditTokenSha256',
  'runnerAuthority',
  'runnerBundleIdentifier',
  'runnerCdHash',
  'runnerDesignatedRequirement',
  'runnerExecutable',
  'runnerPid',
  'runnerStartTime',
  'schemaVersion',
  'sourceDigest',
  'stateCheckpoints',
  'voiceOverAuditTokenSha256',
  'voiceOverBundleIdentifier',
  'voiceOverCdHash',
  'voiceOverDesignatedRequirement',
  'voiceOverExecutable',
  'voiceOverPid',
  'voiceOverStartTime',
  'voiceOverVersion',
  'witnessNonce',
]);
const ROOT_ISSUED_CHALLENGE_KEYS = new Set([
  'attestationSlot',
  'challengeExpiresAt',
  'challengeIssuedAt',
  'challengeRequestSha256',
  'checkpointSessionId',
  'gateContextAuthority',
  'stateCheckpoints',
  'witnessNonce',
]);
const CHALLENGE_REQUEST_KEYS = Object.freeze(
  CHALLENGE_KEYS.filter((key) => !ROOT_ISSUED_CHALLENGE_KEYS.has(key)),
);
const PAYLOAD_KEYS = Object.freeze([
  ...CHALLENGE_KEYS,
  'challengeSha256',
  'checks',
  'completedAt',
  'domain',
  'observationStartedAt',
  'status',
  'witnessApplicationPid',
  'witnessAuditTokenSha256',
  'witnessBundleIdentifier',
  'witnessCdHash',
  'witnessDesignatedRequirement',
  'witnessExecutable',
  'witnessKeySha256',
  'witnessStartTime',
  'witnessUid',
]);
const ENVELOPE_KEYS = Object.freeze([
  'algorithm',
  'payload',
  'schemaVersion',
  'signatureDerBase64',
]);
const ROOT_LAUNCH_CONFIG_KEYS = Object.freeze([
  'contractPath',
  'contractSha256',
  'entrypointPath',
  'entrypointSha256',
  'launcherCdHash',
  'launcherDesignatedRequirement',
  'launcherPath',
  'launcherSha256',
  'mode',
  'nodePath',
  'nodeSha256',
  'schemaVersion',
  'teamIdentifier',
]);
const AUTHORITY_CONFIG_KEYS = Object.freeze([
  'applicationIdentifier',
  'auditDirectoryPath',
  'bundleIdentifier',
  'cdHash',
  'checkpointAuthorityDirectoryPath',
  'checkpointCommitmentDirectoryPath',
  'checkpointDeliveryDirectoryPath',
  'designatedRequirement',
  'effectiveEntitlements',
  'effectiveEntitlementsSha256',
  'enrolmentAuthorityReceiptPath',
  'enrolmentManifestPath',
  'hostDesignatedRequirement',
  'hostTeamIdentifier',
  'installedApplicationPath',
  'keychainAccessGroup',
  'minimumMacOSVersion',
  'policyId',
  'processInspectorPath',
  'processInspectorSha256',
  'profileName',
  'profileSha256',
  'profileUuid',
  'reviewerIdentity',
  'resultDirectoryPath',
  'rootCheckpointAuthorityPath',
  'rootCheckpointAuthoritySha256',
  'rootCheckpointLaunchConfigPath',
  'rootCheckpointLaunchConfigSha256',
  'rootEnrolmentLaunchConfigPath',
  'rootEnrolmentLaunchConfigSha256',
  'rootEnrolmentRegistrarPath',
  'rootEnrolmentRegistrarSha256',
  'rootLauncherCdHash',
  'rootLauncherDesignatedRequirement',
  'rootLauncherPath',
  'rootLauncherSha256',
  'rootLauncherUnsignedSha256',
  'rootVerifierContractPath',
  'rootVerifierContractSha256',
  'rootVerifierEntrypointPath',
  'rootVerifierEntrypointSha256',
  'rootVerifierLaunchConfigPath',
  'rootVerifierLaunchConfigSha256',
  'rootVerifierNodePath',
  'rootVerifierNodeSha256',
  'runnerBundleIdentifier',
  'runnerDesignatedRequirement',
  'runnerTeamIdentifier',
  'schemaVersion',
  'signingCertificateSha256',
  'signingIdentity',
  'sourceSha256',
  'teamIdentifier',
  'voiceOverDesignatedRequirement',
  'witnessExecutable',
  'witnessExecutableUnsignedSha256',
  'witnessGid',
  'witnessHomeDirectory',
  'witnessUid',
  'witnessUsername',
]);
const POLICY_KEYS = Object.freeze([
  ...AUTHORITY_CONFIG_KEYS,
  'enrolmentAuthorityConfigPath',
  'enrolmentAuthorityConfigSha256',
  'enrolmentAuthorityReceiptSha256',
  'enrolmentManifestSha256',
]);
const KEY_ATTRIBUTES_KEYS = Object.freeze([
  'accessControlFlags',
  'accessGroup',
  'applicationTag',
  'canSign',
  'dataProtectionKeychain',
  'isPermanent',
  'keyClass',
  'keySizeInBits',
  'keyType',
  'tokenId',
]);
const ENROLMENT_KEYS = Object.freeze([
  'algorithm',
  'enrolledAt',
  'enrolmentAuthorityConfigSha256',
  'enrolmentProof',
  'keyAttributes',
  'publicKeySha256',
  'publicKeySpkiDerBase64',
  'reviewerIdentity',
  'reviewerKeyId',
  'schemaVersion',
  'witnessUid',
]);
const ENROLMENT_PROOF_KEYS = Object.freeze([
  'algorithm',
  'enrolmentNonce',
  'enrolledAt',
  'enrolmentAuthorityConfigSha256',
  'keyAttributes',
  'publicKeySha256',
  'reviewerIdentity',
  'reviewerKeyId',
  'signatureDerBase64',
  'witnessUid',
]);
const OUTPUT_IDENTITY_KEYS = Object.freeze([
  'dev',
  'gid',
  'ino',
  'mode',
  'path',
  'sha256',
  'size',
  'uid',
]);
const ENROLMENT_AUTHORITY_RECEIPT_KEYS = Object.freeze([
  'applicationIdentityAfter',
  'applicationIdentityBefore',
  'authorisedAt',
  'enrolmentAuthorityConfigSha256',
  'enrolmentManifestSha256',
  'event',
  'keyAttributes',
  'outputIdentity',
  'publicKeySha256',
  'reviewerIdentity',
  'reviewerKeyId',
  'schemaVersion',
  'witnessGid',
  'witnessUid',
]);
const INSPECTION_KEYS = Object.freeze([
  'applicationIdentifier',
  'appleCertificateChain',
  'bundleIdentifier',
  'cdHash',
  'designatedRequirement',
  'effectiveEntitlements',
  'effectiveEntitlementsSha256',
  'hardenedRuntime',
  'installedApplicationPath',
  'keychainAccessGroups',
  'profileName',
  'profileSha256',
  'profileTeamIdentifiers',
  'profileUuid',
  'signingCertificateSha256',
  'signingIdentity',
  'teamIdentifier',
]);
const LIVE_PROCESS_KEYS = Object.freeze([
  'auditTokenSha256',
  'bundleIdentifier',
  'cdHash',
  'designatedRequirement',
  'executable',
  'pid',
  'startTime',
]);
const LIVE_SNAPSHOT_KEYS = Object.freeze(['host', 'runner', 'voiceOver', 'witness']);
const CHECKPOINT_AUTHORISATION_KEYS = Object.freeze([
  'authorised',
  'authorisedAt',
  'challengeSha256',
  'challengeRequestSha256',
  'checkpointChecksSha256',
  'checkpointSessionId',
]);
const PUBLISHED_RECEIPT_KEYS = Object.freeze([
  'applicationPid',
  'architectureGateRunContextSha256',
  'architectureGateRunId',
  'attestationOutputIdentity',
  'attestationSha256',
  'automationTwinFingerprint',
  'challengeExpiresAt',
  'challengeIssuedAt',
  'challengeRequestSha256',
  'challengeSha256',
  'checkpointAuthorisedAt',
  'checkpointChecksSha256',
  'checkpointSessionId',
  'completedAt',
  'consumed',
  'consumedAt',
  'event',
  'gateContextAuthority',
  'gateContextComparisonRequired',
  'hostAuditTokenSha256',
  'hostBundleFingerprint',
  'hostBundleIdentifier',
  'hostCdHash',
  'hostDesignatedRequirementSha256',
  'hostExecutableSha256',
  'hostStartTime',
  'humanWitnessed',
  'humanWitnessAssertionScope',
  'macosVersion',
  'measuredTwinDeltaSha256',
  'observationStartedAt',
  'enrolmentAuthorityConfigSha256',
  'enrolmentAuthorityReceiptSha256',
  'enrolmentManifestSha256',
  'policyPinSha256',
  'productionFingerprint',
  'reviewerIdentity',
  'reviewerKeyId',
  'runnerAuditTokenSha256',
  'runnerAuthority',
  'runnerBundleIdentifier',
  'runnerCdHash',
  'runnerDesignatedRequirementSha256',
  'runnerExecutableSha256',
  'runnerPid',
  'runnerStartTime',
  'schemaVersion',
  'sourceDigest',
  'status',
  'voiceOverAuditTokenSha256',
  'voiceOverBundleIdentifier',
  'voiceOverCdHash',
  'voiceOverDesignatedRequirementSha256',
  'voiceOverExecutableSha256',
  'voiceOverPid',
  'voiceOverStartTime',
  'voiceOverVersion',
  'witnessApplicationPid',
  'witnessAuditTokenSha256',
  'witnessBundleIdentifier',
  'witnessCdHash',
  'witnessDesignatedRequirementSha256',
  'witnessExecutableSha256',
  'witnessKeySha256',
  'witnessNonce',
  'witnessStartTime',
  'witnessUid',
]);

function reject(message = 'A.28 authenticated witness rejected') {
  throw new Error(message);
}

function isRecord(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, expected) {
  if (!isRecord(value)
    || !isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort())) reject();
}

function canonicalise(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) reject();
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalise);
  if (!isRecord(value)) reject();
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonicalise(value[key])]),
  );
}

export function canonicalA28Json(value) {
  return JSON.stringify(canonicalise(value));
}

export function sha256A28(bytes) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) reject();
  return createHash('sha256').update(bytes).digest('hex');
}

export function canonicalA28Line(value) {
  return Buffer.from(canonicalA28Json(value) + '\n', 'utf8');
}

export function parseCanonicalA28Line(bytes) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 3
    || bytes.length > MAX_CANONICAL_BYTES
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
    || bytes.includes(0x00)) reject();
  let value;
  try {
    value = JSON.parse(bytes.subarray(0, -1).toString('utf8'));
  } catch {
    reject();
  }
  if (!isRecord(value)
    || !canonicalA28Line(value).equals(bytes)) reject();
  return value;
}

function assertSha256(value) {
  if (typeof value !== 'string' || !SHA256.test(value)) reject();
}

function parseInstant(value) {
  if (typeof value !== 'string' || !ISO_INSTANT.test(value)) reject();
  const instant = Date.parse(value);
  if (!Number.isFinite(instant) || new Date(instant).toISOString() !== value) reject();
  return instant;
}

function assertReviewerIdentity(value) {
  if (typeof value !== 'string'
    || value.length < 3
    || value.length > 120
    || value !== value.trim()
    || !/^\p{L}[\p{L}\p{M}'’ʼ -]*\p{L}$/u.test(value)
    || !value.includes(' ')
    || /[\0\r\n/\\]/u.test(value)) reject();
}

function assertExecutableIdentity(value) {
  exactKeys(value, EXECUTABLE_KEYS);
  if (!Number.isSafeInteger(value.dev)
    || value.dev < 1
    || !Number.isSafeInteger(value.ino)
    || value.ino < 1
    || !Number.isSafeInteger(value.size)
    || value.size < 8_192
    || value.size > 1024 * 1024 * 1024) reject();
  assertSha256(value.sha256);
  if (typeof value.path !== 'string'
    || !value.path.startsWith('/')
    || resolve(value.path) !== value.path
    || value.path.split('/').includes('..')
    || /[\0\r\n]/u.test(value.path)) reject();
  return value;
}

function assertAbsoluteSystemPath(value, prefix) {
  if (typeof value !== 'string'
    || !value.startsWith(prefix)
    || resolve(value) !== value
    || value.includes('\0')
    || value.includes('\r')
    || value.includes('\n')
    || value.split('/').includes('..')) reject();
}

function assertCanonicalBase64(value, minimumBytes, maximumBytes) {
  if (typeof value !== 'string'
    || value.length < 4
    || value.length > Math.ceil(maximumBytes / 3) * 4
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) reject();
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length < minimumBytes
    || bytes.length > maximumBytes
    || bytes.toString('base64') !== value) reject();
  return bytes;
}

function assertDesignatedRequirement(value, {
  bundleIdentifier,
  systemApple = false,
  teamIdentifier,
}) {
  const identifierClause = 'identifier "' + bundleIdentifier + '"';
  const bareIdentifierClause = 'identifier ' + bundleIdentifier;
  const containsAndClause = (clause) => value === clause
    || value.startsWith(clause + ' and ')
    || value.endsWith(' and ' + clause)
    || value.includes(' and ' + clause + ' and ');
  const hasIdentifier = typeof value === 'string'
    && (containsAndClause(identifierClause)
      || containsAndClause(bareIdentifierClause));
  const teamClause = teamIdentifier === undefined
    ? undefined
    : 'certificate leaf[subject.OU] = ' + teamIdentifier;
  const quotedTeamClause = teamIdentifier === undefined
    ? undefined
    : 'certificate leaf[subject.OU] = "' + teamIdentifier + '"';
  const hasTeam = teamIdentifier === undefined
    || (typeof value === 'string'
      && (containsAndClause(teamClause)
        || containsAndClause(quotedTeamClause)));
  if (typeof value !== 'string'
    || value.length < 20
    || value.length > 4_096
    || value !== value.trim()
    || !hasIdentifier
    || !value.includes(systemApple ? 'anchor apple' : 'anchor apple generic')
    || (systemApple && value.includes('anchor apple generic'))
    || (!systemApple && !hasTeam)
    || /(^|[^A-Za-z0-9_])(or|not|always|true)([^A-Za-z0-9_]|$)|!/iu.test(value)
    || /[\0\r\n]/u.test(value)) reject();
}

function assertKeyAttributes(value, expectedAccessGroup) {
  exactKeys(value, KEY_ATTRIBUTES_KEYS);
  if (!isDeepStrictEqual(value.accessControlFlags, [
    'biometryCurrentSet',
    'privateKeyUsage',
  ])
    || value.accessGroup !== expectedAccessGroup
    || value.applicationTag !== A28_WITNESS_BUNDLE_ID + '.secure-enclave.v1'
    || value.canSign !== true
    || value.dataProtectionKeychain !== true
    || value.isPermanent !== true
    || value.keyClass !== 'private'
    || value.keySizeInBits !== 256
    || value.keyType !== 'ECSECPrimeRandom'
    || value.tokenId !== 'com.apple.setoken') reject();
  return Object.freeze({
    ...value,
    accessControlFlags: Object.freeze([...value.accessControlFlags]),
  });
}

function assertStateCheckpoints(value) {
  if (!Array.isArray(value)
    || value.length !== EXPECTED_COMBINATIONS.length) reject();
  const checkpointIds = new Set();
  const commitments = new Set();
  for (let index = 0; index < value.length; index += 1) {
    const checkpoint = value[index];
    exactKeys(checkpoint, STATE_CHECKPOINT_KEYS);
    assertSha256(checkpoint.checkpointId);
    assertSha256(checkpoint.tokenSha256);
    if (checkpoint.ordinal !== index + 1
      || checkpoint.appearance + ':' + checkpoint.mode
        !== EXPECTED_COMBINATIONS[index]
      || checkpointIds.has(checkpoint.checkpointId)
      || commitments.has(checkpoint.tokenSha256)) reject();
    checkpointIds.add(checkpoint.checkpointId);
    commitments.add(checkpoint.tokenSha256);
  }
  return Object.freeze(value.map((checkpoint) => Object.freeze({ ...checkpoint })));
}

function assertAttestationSlot(value, policy) {
  exactKeys(value, ATTESTATION_SLOT_KEYS);
  for (const field of ['dev', 'gid', 'ino', 'uid']) {
    if (!Number.isSafeInteger(value[field]) || value[field] < 0) reject();
  }
  if (value.ino < 1
    || typeof value.path !== 'string'
    || resolve(value.path) !== value.path
    || !/\/[0-9a-f]{64}\.attestation\.json$/u.test(value.path)
    || /[\0\r\n]/u.test(value.path)) reject();
  if (policy !== undefined
    && (value.uid !== policy.witnessUid
      || value.gid !== policy.witnessGid
      || !value.path.startsWith(
        policy.checkpointDeliveryDirectoryPath + '/',
      ))) reject();
  return Object.freeze({ ...value });
}

function assertAttestationOutputIdentity(value, challenge, bytes) {
  exactKeys(value, ATTESTATION_OUTPUT_IDENTITY_KEYS);
  const slot = challenge.attestationSlot;
  if (!Buffer.isBuffer(bytes)
    || value.dev !== slot.dev
    || value.gid !== slot.gid
    || value.ino !== slot.ino
    || value.mode !== 0o400
    || value.path !== slot.path
    || value.sha256 !== sha256A28(bytes)
    || value.size !== bytes.length
    || value.uid !== slot.uid) reject();
  assertSha256(value.sha256);
  return Object.freeze({ ...value });
}

export function a28ChallengeRequestSha256(value) {
  exactKeys(value, CHALLENGE_REQUEST_KEYS);
  return sha256A28(Buffer.concat([
    A28_CHALLENGE_REQUEST_PREFIX,
    canonicalA28Line(value),
  ]));
}

export function parseA28CheckpointAuthorityArguments(argv) {
  if (!Array.isArray(argv) || argv.length % 2 !== 0) reject();
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!['--action', '--input', '--output', '--witness-pid'].includes(flag)
      || typeof value !== 'string'
      || value.length === 0
      || Object.hasOwn(values, flag)) reject();
    values[flag] = value;
  }
  if (!['authorise', 'prepare', 'reveal'].includes(values['--action'])
    || typeof values['--input'] !== 'string'
    || resolve(values['--input']) !== values['--input']
    || typeof values['--output'] !== 'string'
    || resolve(values['--output']) !== values['--output']) reject();
  const reveal = values['--action'] === 'reveal';
  exactKeys(values, reveal
    ? ['--action', '--input', '--output', '--witness-pid']
    : ['--action', '--input', '--output']);
  const witnessPid = reveal ? Number(values['--witness-pid']) : undefined;
  if (reveal
    && (!Number.isSafeInteger(witnessPid) || witnessPid < 2)) reject();
  return Object.freeze({
    action: values['--action'],
    input: values['--input'],
    output: values['--output'],
    witnessPid,
  });
}

export function a28CheckpointCommitmentSha256({
  appearance,
  architectureGateRunId,
  challengeRequestSha256,
  checkpointId,
  checkpointSessionId,
  mode,
  ordinal,
  token,
  witnessNonce,
}) {
  for (const digest of [
    challengeRequestSha256,
    checkpointId,
    checkpointSessionId,
    token,
    witnessNonce,
  ]) {
    assertSha256(digest);
  }
  if (typeof architectureGateRunId !== 'string'
    || !GATE_RUN_ID.test(architectureGateRunId)
    || !Number.isSafeInteger(ordinal)
    || ordinal < 1
    || ordinal > EXPECTED_COMBINATIONS.length
    || appearance + ':' + mode !== EXPECTED_COMBINATIONS[ordinal - 1]) reject();
  return sha256A28(canonicalA28Line({
    appearance,
    architectureGateRunId,
    challengeRequestSha256,
    checkpointId,
    checkpointSessionId,
    mode,
    ordinal,
    token,
    witnessNonce,
  }));
}

export function assertA28Challenge(value, now = Date.now(), policyPin) {
  if (!Number.isFinite(now)) reject();
  exactKeys(value, CHALLENGE_KEYS);
  for (const digest of [
    value.architectureGateRunContextSha256,
    value.challengeRequestSha256,
    value.automationTwinFingerprint,
    value.checkpointSessionId,
    value.hostAuditTokenSha256,
    value.hostBundleFingerprint,
    value.measuredTwinDeltaSha256,
    value.policyPinSha256,
    value.productionFingerprint,
    value.reviewerKeyId,
    value.runnerAuditTokenSha256,
    value.sourceDigest,
    value.voiceOverAuditTokenSha256,
    value.witnessNonce,
  ]) assertSha256(digest);
  for (const cdHash of [
    value.hostCdHash,
    value.runnerCdHash,
    value.voiceOverCdHash,
  ]) {
    if (typeof cdHash !== 'string' || !CDHASH.test(cdHash)) reject();
  }
  const issuedAt = parseInstant(value.challengeIssuedAt);
  const expiresAt = parseInstant(value.challengeExpiresAt);
  const requestProjection = Object.fromEntries(
    CHALLENGE_REQUEST_KEYS.map((key) => [key, value[key]]),
  );
  if (value.schemaVersion !== A28_WITNESS_SCHEMA_VERSION
    || value.gateId !== 'A.28'
    || value.gateContextAuthority !== A28_GATE_CONTEXT_AUTHORITY
    || value.challengeRequestSha256
      !== a28ChallengeRequestSha256(requestProjection)
    || typeof value.architectureGateRunId !== 'string'
    || !GATE_RUN_ID.test(value.architectureGateRunId)
    || !Number.isSafeInteger(value.applicationPid)
    || value.applicationPid < 2
    || !Number.isSafeInteger(value.runnerPid)
    || value.runnerPid < 2
    || value.runnerPid === value.applicationPid
    || !Number.isSafeInteger(value.voiceOverPid)
    || value.voiceOverPid < 2
    || [value.applicationPid, value.runnerPid].includes(value.voiceOverPid)
    || typeof value.runnerStartTime !== 'string'
    || !PROCESS_START.test(value.runnerStartTime)
    || typeof value.hostStartTime !== 'string'
    || !PROCESS_START.test(value.hostStartTime)
    || typeof value.voiceOverStartTime !== 'string'
    || !PROCESS_START.test(value.voiceOverStartTime)
    || value.hostBundleIdentifier !== 'au.com.piui.desktop.architecture-test'
    || value.hostBundleFingerprint !== value.automationTwinFingerprint
    || typeof value.hostBundlePath !== 'string'
    || !value.hostBundlePath.startsWith('/')
    || resolve(value.hostBundlePath) !== value.hostBundlePath
    || !value.hostBundlePath.endsWith('.app')
    || value.hostBundlePath.split('/').includes('..')
    || /[\0\r\n]/u.test(value.hostBundlePath)
    || typeof value.runnerBundleIdentifier !== 'string'
    || value.runnerBundleIdentifier.length < 3
    || value.runnerBundleIdentifier.length > 255
    || value.runnerAuthority !== 'continuity-only'
    || typeof value.macosVersion !== 'string'
    || !MACOS_VERSION.test(value.macosVersion)
    || typeof value.voiceOverVersion !== 'string'
    || !VOICEOVER_VERSION.test(value.voiceOverVersion)
    || value.voiceOverBundleIdentifier !== 'com.apple.VoiceOver'
    || value.voiceOverExecutable.path
      !== '/System/Library/CoreServices/VoiceOver.app/Contents/MacOS/VoiceOver'
    || value.productionFingerprint === value.automationTwinFingerprint
    || !value.hostExecutable.path.startsWith(
      value.hostBundlePath + '/Contents/MacOS/',
    )
    || expiresAt <= issuedAt
    || expiresAt - issuedAt > MAX_WITNESS_WINDOW_MS
    || issuedAt > now + MAX_CLOCK_SKEW_MS
    || expiresAt < now - MAX_CLOCK_SKEW_MS) reject();
  assertReviewerIdentity(value.reviewerIdentity);
  assertDesignatedRequirement(value.hostDesignatedRequirement, {
    bundleIdentifier: value.hostBundleIdentifier,
  });
  assertDesignatedRequirement(value.runnerDesignatedRequirement, {
    bundleIdentifier: value.runnerBundleIdentifier,
  });
  assertDesignatedRequirement(value.voiceOverDesignatedRequirement, {
    bundleIdentifier: 'com.apple.VoiceOver',
    systemApple: true,
  });
  assertExecutableIdentity(value.hostExecutable);
  assertExecutableIdentity(value.runnerExecutable);
  assertExecutableIdentity(value.voiceOverExecutable);
  const attestationSlot = assertAttestationSlot(
    value.attestationSlot,
    policyPin === undefined ? undefined : assertA28PolicyPin(policyPin),
  );
  const stateCheckpoints = assertStateCheckpoints(value.stateCheckpoints);
  if (policyPin !== undefined) {
    const policy = assertA28PolicyPin(policyPin);
    if (value.policyPinSha256 !== sha256A28(canonicalA28Line(policy))
      || value.reviewerIdentity !== policy.reviewerIdentity
      || value.runnerBundleIdentifier !== policy.runnerBundleIdentifier
      || value.hostDesignatedRequirement !== policy.hostDesignatedRequirement
      || value.runnerDesignatedRequirement !== policy.runnerDesignatedRequirement
      || value.voiceOverDesignatedRequirement
        !== policy.voiceOverDesignatedRequirement) reject();
  }
  return Object.freeze({ ...value, attestationSlot, stateCheckpoints });
}

export function assertA28ChallengeRequest(value, policyPin, now = Date.now()) {
  const policy = assertA28PolicyPin(policyPin);
  exactKeys(value, CHALLENGE_REQUEST_KEYS);
  const requestSha256 = a28ChallengeRequestSha256(value);
  const checkpointSessionId = 'a'.repeat(64);
  const witnessNonce = 'b'.repeat(64);
  const stateCheckpoints = EXPECTED_COMBINATIONS.map((combination, index) => {
    const [appearance, mode] = combination.split(':');
    const checkpointId = String(index + 1).repeat(64);
    const token = String(index + 5).repeat(64);
    return {
      appearance,
      checkpointId,
      mode,
      ordinal: index + 1,
      tokenSha256: a28CheckpointCommitmentSha256({
        appearance,
        architectureGateRunId: value.architectureGateRunId,
        challengeRequestSha256: requestSha256,
        checkpointId,
        checkpointSessionId,
        mode,
        ordinal: index + 1,
        token,
        witnessNonce,
      }),
    };
  });
  const challenge = assertA28Challenge({
    ...value,
    attestationSlot: {
      dev: 1,
      gid: policy.witnessGid,
      ino: 1,
      path: policy.checkpointDeliveryDirectoryPath
        + '/' + checkpointSessionId + '.attestation.json',
      uid: policy.witnessUid,
    },
    challengeExpiresAt: new Date(now + 15 * 60_000).toISOString(),
    challengeIssuedAt: new Date(now).toISOString(),
    challengeRequestSha256: requestSha256,
    checkpointSessionId,
    gateContextAuthority: A28_GATE_CONTEXT_AUTHORITY,
    stateCheckpoints,
    witnessNonce,
  }, now, policy);
  return Object.freeze(Object.fromEntries(
    CHALLENGE_REQUEST_KEYS.map((key) => [key, challenge[key]]),
  ));
}

function assertAuthorityConfiguration(value, expectedKeys) {
  exactKeys(value, expectedKeys);
  for (const digest of [
    value.effectiveEntitlementsSha256,
    value.profileSha256,
    value.processInspectorSha256,
    value.rootCheckpointAuthoritySha256,
    value.rootCheckpointLaunchConfigSha256,
    value.rootEnrolmentLaunchConfigSha256,
    value.rootEnrolmentRegistrarSha256,
    value.rootLauncherSha256,
    value.rootLauncherUnsignedSha256,
    value.rootVerifierContractSha256,
    value.rootVerifierEntrypointSha256,
    value.rootVerifierLaunchConfigSha256,
    value.rootVerifierNodeSha256,
    value.signingCertificateSha256,
    value.sourceSha256,
    value.witnessExecutableUnsignedSha256,
  ]) assertSha256(digest);
  if (value.schemaVersion !== A28_WITNESS_SCHEMA_VERSION
    || value.policyId !== A28_WITNESS_POLICY_ID
    || value.bundleIdentifier !== A28_WITNESS_BUNDLE_ID
    || typeof value.teamIdentifier !== 'string'
    || !TEAM_ID.test(value.teamIdentifier)
    || value.applicationIdentifier !== value.teamIdentifier + '.' + value.bundleIdentifier
    || value.keychainAccessGroup
      !== value.teamIdentifier + '.' + value.bundleIdentifier + '.secure-enclave'
    || typeof value.cdHash !== 'string'
    || !CDHASH.test(value.cdHash)
    || typeof value.profileUuid !== 'string'
    || !UUID.test(value.profileUuid)
    || typeof value.profileName !== 'string'
    || value.profileName.length < 3
    || value.profileName.length > 128
    || typeof value.signingIdentity !== 'string'
    || value.signingIdentity.length < 3
    || value.signingIdentity.length > 256
    || !value.signingIdentity.startsWith('Developer ID Application: ')
    || typeof value.designatedRequirement !== 'string'
    || value.designatedRequirement.length < 40
    || value.designatedRequirement.length > 4_096
    || !value.designatedRequirement.includes('identifier "' + value.bundleIdentifier + '"')
    || !value.designatedRequirement.includes('anchor apple generic')
    || typeof value.minimumMacOSVersion !== 'string'
    || !MACOS_VERSION.test(value.minimumMacOSVersion)
    || !Number.isSafeInteger(value.witnessUid)
    || value.witnessUid < 501
    || !Number.isSafeInteger(value.witnessGid)
    || value.witnessGid < 20
    || typeof value.witnessUsername !== 'string'
    || !/^[a-z_][a-z0-9_-]{0,31}$/u.test(value.witnessUsername)
    || typeof value.rootLauncherCdHash !== 'string'
    || !CDHASH.test(value.rootLauncherCdHash)
    || typeof value.runnerBundleIdentifier !== 'string'
    || value.runnerBundleIdentifier.length < 3
    || value.runnerBundleIdentifier.length > 255
    || typeof value.hostTeamIdentifier !== 'string'
    || !TEAM_ID.test(value.hostTeamIdentifier)
    || typeof value.runnerTeamIdentifier !== 'string'
    || !TEAM_ID.test(value.runnerTeamIdentifier)
    || !isRecord(value.effectiveEntitlements)) reject();
  assertDesignatedRequirement(value.designatedRequirement, {
    bundleIdentifier: value.bundleIdentifier,
    teamIdentifier: value.teamIdentifier,
  });
  assertDesignatedRequirement(value.rootLauncherDesignatedRequirement, {
    bundleIdentifier: 'au.com.piui.a28-root-launcher',
    teamIdentifier: value.teamIdentifier,
  });
  assertDesignatedRequirement(value.hostDesignatedRequirement, {
    bundleIdentifier: 'au.com.piui.desktop.architecture-test',
    teamIdentifier: value.hostTeamIdentifier,
  });
  assertDesignatedRequirement(value.runnerDesignatedRequirement, {
    bundleIdentifier: value.runnerBundleIdentifier,
    teamIdentifier: value.runnerTeamIdentifier,
  });
  assertDesignatedRequirement(value.voiceOverDesignatedRequirement, {
    bundleIdentifier: 'com.apple.VoiceOver',
    systemApple: true,
  });
  assertReviewerIdentity(value.reviewerIdentity);
  assertExecutableIdentity(value.witnessExecutable);
  assertAbsoluteSystemPath(
    value.installedApplicationPath,
    '/Library/Application Support/PIUI/A28Witness/app/',
  );
  assertAbsoluteSystemPath(
    value.enrolmentManifestPath,
    '/Library/Application Support/PIUI/',
  );
  assertAbsoluteSystemPath(value.auditDirectoryPath, '/Library/Application Support/PIUI/');
  assertAbsoluteSystemPath(value.resultDirectoryPath, '/Library/Application Support/PIUI/');
  assertAbsoluteSystemPath(
    value.enrolmentAuthorityReceiptPath,
    '/Library/Application Support/PIUI/A28Witness/',
  );
  assertAbsoluteSystemPath(
    value.processInspectorPath,
    '/Library/Application Support/PIUI/',
  );
  for (const path of [
    value.checkpointAuthorityDirectoryPath,
    value.checkpointCommitmentDirectoryPath,
    value.checkpointDeliveryDirectoryPath,
    value.rootCheckpointAuthorityPath,
    value.rootCheckpointLaunchConfigPath,
    value.rootEnrolmentLaunchConfigPath,
    value.rootEnrolmentRegistrarPath,
    value.rootLauncherPath,
    value.rootVerifierContractPath,
    value.rootVerifierEntrypointPath,
    value.rootVerifierLaunchConfigPath,
    value.rootVerifierNodePath,
  ]) {
    assertAbsoluteSystemPath(path, '/Library/Application Support/PIUI/');
  }
  assertAbsoluteSystemPath(value.witnessHomeDirectory, '/');
  if (!value.installedApplicationPath.endsWith('.app')
    || value.installedApplicationPath.endsWith('/app/.app')
    || !value.enrolmentManifestPath.endsWith('/enrolment.json')
    || !value.enrolmentAuthorityReceiptPath.endsWith(
      '/enrolment-authority-receipt.json',
    )
    || !value.auditDirectoryPath.endsWith('/consumed')
    || !value.resultDirectoryPath.endsWith('/results')
    || !value.checkpointAuthorityDirectoryPath.endsWith('/checkpoint-private')
    || !value.checkpointCommitmentDirectoryPath.endsWith('/checkpoint-commitments')
    || !value.checkpointDeliveryDirectoryPath.endsWith('/checkpoint-deliveries')
    || !value.processInspectorPath.endsWith('/bin/a28-process-identity')
    || !value.rootCheckpointAuthorityPath.endsWith(
      '/authority/checkpoint-authority.mjs',
    )
    || !value.rootCheckpointLaunchConfigPath.endsWith(
      '/launcher/checkpoint-launch.json',
    )
    || !value.rootEnrolmentLaunchConfigPath.endsWith(
      '/launcher/enrolment-launch.json',
    )
    || !value.rootEnrolmentRegistrarPath.endsWith(
      '/authority/register-enrolment.mjs',
    )
    || !value.rootLauncherPath.endsWith('/bin/a28-root-launcher')
    || !value.rootVerifierContractPath.endsWith('/verifier/contract.mjs')
    || !value.rootVerifierEntrypointPath.endsWith('/verifier/verify.mjs')
    || !value.rootVerifierLaunchConfigPath.endsWith(
      '/launcher/verifier-launch.json',
    )
    || !value.rootVerifierNodePath.endsWith('/bin/node')
    || value.witnessHomeDirectory === '/'
    || value.witnessExecutable.path
      !== value.installedApplicationPath + '/Contents/MacOS/A28Witness') reject();
  const expectedEntitlements = {
    'com.apple.application-identifier': value.applicationIdentifier,
    'com.apple.developer.team-identifier': value.teamIdentifier,
    'keychain-access-groups': [value.keychainAccessGroup],
  };
  if (!isDeepStrictEqual(value.effectiveEntitlements, expectedEntitlements)
    || sha256A28(Buffer.from(canonicalA28Json(value.effectiveEntitlements), 'utf8'))
      !== value.effectiveEntitlementsSha256) reject();
  return Object.freeze({
    ...value,
    effectiveEntitlements: Object.freeze({
      ...value.effectiveEntitlements,
      'keychain-access-groups': Object.freeze([
        ...value.effectiveEntitlements['keychain-access-groups'],
      ]),
    }),
  });
}

export function assertA28EnrolmentAuthorityConfig(value) {
  return assertAuthorityConfiguration(value, AUTHORITY_CONFIG_KEYS);
}

export function assertA28PolicyPin(value) {
  const policy = assertAuthorityConfiguration(value, POLICY_KEYS);
  for (const digest of [
    policy.enrolmentAuthorityConfigSha256,
    policy.enrolmentAuthorityReceiptSha256,
    policy.enrolmentManifestSha256,
  ]) assertSha256(digest);
  assertAbsoluteSystemPath(
    policy.enrolmentAuthorityConfigPath,
    '/Library/Application Support/PIUI/A28Witness/',
  );
  if (!policy.enrolmentAuthorityConfigPath.endsWith(
    '/enrolment-authority.json',
  )) reject();
  return policy;
}

export function assertA28RootLaunchConfig(value, policyPin, mode) {
  const finalPolicy = isRecord(policyPin)
    && Object.hasOwn(policyPin, 'enrolmentManifestSha256');
  const policy = finalPolicy
    ? assertA28PolicyPin(policyPin)
    : assertA28EnrolmentAuthorityConfig(policyPin);
  exactKeys(value, ROOT_LAUNCH_CONFIG_KEYS);
  const entrypoints = {
    checkpoint: [
      policy.rootCheckpointAuthorityPath,
      policy.rootCheckpointAuthoritySha256,
    ],
    enrol: [
      policy.rootEnrolmentRegistrarPath,
      policy.rootEnrolmentRegistrarSha256,
    ],
    verify: [
      policy.rootVerifierEntrypointPath,
      policy.rootVerifierEntrypointSha256,
    ],
  };
  const expected = entrypoints[mode];
  if (expected === undefined
    || value.schemaVersion !== A28_WITNESS_SCHEMA_VERSION
    || value.mode !== mode
    || value.contractPath !== policy.rootVerifierContractPath
    || value.contractSha256 !== policy.rootVerifierContractSha256
    || value.entrypointPath !== expected[0]
    || value.entrypointSha256 !== expected[1]
    || value.launcherCdHash !== policy.rootLauncherCdHash
    || value.launcherDesignatedRequirement
      !== policy.rootLauncherDesignatedRequirement
    || value.launcherPath !== policy.rootLauncherPath
    || value.launcherSha256 !== policy.rootLauncherSha256
    || value.nodePath !== policy.rootVerifierNodePath
    || value.nodeSha256 !== policy.rootVerifierNodeSha256
    || value.teamIdentifier !== policy.teamIdentifier) reject();
  return Object.freeze({ ...value });
}

function assertP256PublicKey(spkiBase64, expectedSha256) {
  const spki = assertCanonicalBase64(spkiBase64, 80, 160);
  assertSha256(expectedSha256);
  if (sha256A28(spki) !== expectedSha256) reject();
  let key;
  try {
    key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  } catch {
    reject();
  }
  if (key.asymmetricKeyType !== 'ec'
    || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1'
    || !key.export({ format: 'der', type: 'spki' }).equals(spki)) reject();
  return key;
}

function readDerInteger(bytes, offset) {
  if (bytes[offset] !== 0x02) reject();
  const length = bytes[offset + 1];
  if (!Number.isSafeInteger(length)
    || length < 1
    || length > 33
    || offset + 2 + length > bytes.length) reject();
  const integer = bytes.subarray(offset + 2, offset + 2 + length);
  if ((integer[0] & 0x80) !== 0
    || (integer.length > 1 && integer[0] === 0 && (integer[1] & 0x80) === 0)) reject();
  const numeric = BigInt('0x' + integer.toString('hex'));
  if (numeric < 1n || numeric >= P256_ORDER) reject();
  return { next: offset + 2 + length, numeric };
}

export function assertCanonicalP256Signature(value) {
  const bytes = assertCanonicalBase64(value, 68, 72);
  if (bytes[0] !== 0x30
    || bytes[1] !== bytes.length - 2
    || (bytes[1] & 0x80) !== 0) reject();
  const first = readDerInteger(bytes, 2);
  const second = readDerInteger(bytes, first.next);
  if (second.next !== bytes.length) reject();
  return bytes;
}

export function assertA28Enrolment(value, policyPin, now = Date.now()) {
  const finalPolicy = isRecord(policyPin)
    && Object.hasOwn(policyPin, 'enrolmentManifestSha256');
  const policy = finalPolicy
    ? assertA28PolicyPin(policyPin)
    : assertA28EnrolmentAuthorityConfig(policyPin);
  if (!Number.isFinite(now)) reject();
  exactKeys(value, ENROLMENT_KEYS);
  exactKeys(value.enrolmentProof, ENROLMENT_PROOF_KEYS);
  const authorityConfigSha256 = finalPolicy
    ? policy.enrolmentAuthorityConfigSha256
    : sha256A28(canonicalA28Line(policy));
  const enrolledAt = parseInstant(value.enrolledAt);
  const proofAt = parseInstant(value.enrolmentProof.enrolledAt);
  const keyAttributes = assertKeyAttributes(
    value.keyAttributes,
    policy.keychainAccessGroup,
  );
  const proofKeyAttributes = assertKeyAttributes(
    value.enrolmentProof.keyAttributes,
    policy.keychainAccessGroup,
  );
  if (value.schemaVersion !== A28_WITNESS_SCHEMA_VERSION
    || value.algorithm !== 'ES256'
    || value.witnessUid !== policy.witnessUid
    || value.reviewerIdentity !== policy.reviewerIdentity
    || value.reviewerKeyId !== value.publicKeySha256
    || value.enrolmentAuthorityConfigSha256 !== authorityConfigSha256
    || value.enrolmentProof.enrolmentAuthorityConfigSha256
      !== authorityConfigSha256
    || value.enrolmentProof.publicKeySha256 !== value.publicKeySha256
    || !isDeepStrictEqual(proofKeyAttributes, keyAttributes)
    || value.enrolmentProof.algorithm !== value.algorithm
    || value.enrolmentProof.reviewerIdentity !== value.reviewerIdentity
    || value.enrolmentProof.reviewerKeyId !== value.reviewerKeyId
    || value.enrolmentProof.witnessUid !== value.witnessUid
    || value.enrolmentProof.enrolledAt !== value.enrolledAt
    || enrolledAt !== proofAt
    || enrolledAt > now + MAX_CLOCK_SKEW_MS) reject();
  assertSha256(value.enrolmentProof.enrolmentNonce);
  assertSha256(value.reviewerKeyId);
  assertReviewerIdentity(value.reviewerIdentity);
  const key = assertP256PublicKey(value.publicKeySpkiDerBase64, value.publicKeySha256);
  const proofPayload = {
    algorithm: value.algorithm,
    domain: A28_ENROLMENT_DOMAIN,
    enrolledAt: value.enrolledAt,
    enrolmentAuthorityConfigSha256: value.enrolmentAuthorityConfigSha256,
    enrolmentNonce: value.enrolmentProof.enrolmentNonce,
    keyAttributes: value.keyAttributes,
    publicKeySha256: value.publicKeySha256,
    reviewerIdentity: value.reviewerIdentity,
    reviewerKeyId: value.reviewerKeyId,
    schemaVersion: A28_WITNESS_SCHEMA_VERSION,
    witnessUid: value.witnessUid,
  };
  const signature = assertCanonicalP256Signature(
    value.enrolmentProof.signatureDerBase64,
  );
  const signed = Buffer.concat([
    A28_ENROLMENT_SIGNING_PREFIX,
    Buffer.from(canonicalA28Json(proofPayload), 'utf8'),
  ]);
  if (!verifySignature('sha256', signed, key, signature)) reject();
  if (finalPolicy
    && sha256A28(canonicalA28Line(value))
      !== policy.enrolmentManifestSha256) reject();
  return Object.freeze({
    ...value,
    keyAttributes,
    enrolmentProof: Object.freeze({
      ...value.enrolmentProof,
      keyAttributes: proofKeyAttributes,
    }),
  });
}

export function assertA28EnrolmentAuthorityReceipt(value, {
  authorityConfig,
  enrolment,
  now = Date.now(),
  policyPin,
}) {
  if (!Number.isFinite(now)) reject();
  const config = assertA28EnrolmentAuthorityConfig(authorityConfig);
  const policy = assertA28PolicyPin(policyPin);
  for (const key of AUTHORITY_CONFIG_KEYS) {
    if (!isDeepStrictEqual(config[key], policy[key])) reject();
  }
  const configSha256 = sha256A28(canonicalA28Line(config));
  if (configSha256 !== policy.enrolmentAuthorityConfigSha256) reject();
  const enrolmentValue = assertA28Enrolment(enrolment, policy, now);
  exactKeys(value, ENROLMENT_AUTHORITY_RECEIPT_KEYS);
  const authorisedAt = parseInstant(value.authorisedAt);
  const enrolledAt = parseInstant(enrolmentValue.enrolledAt);
  const manifestBytes = canonicalA28Line(enrolmentValue);
  const manifestSha256 = sha256A28(manifestBytes);
  const keyAttributes = assertKeyAttributes(
    value.keyAttributes,
    policy.keychainAccessGroup,
  );
  exactKeys(value.outputIdentity, OUTPUT_IDENTITY_KEYS);
  for (const identity of [
    value.applicationIdentityBefore,
    value.applicationIdentityAfter,
  ]) {
    exactKeys(identity, LIVE_PROCESS_KEYS);
    assertSha256(identity.auditTokenSha256);
    if (!Number.isSafeInteger(identity.pid)
      || identity.pid < 2
      || identity.bundleIdentifier !== policy.bundleIdentifier
      || identity.cdHash !== policy.cdHash
      || identity.designatedRequirement !== policy.designatedRequirement
      || !PROCESS_START.test(identity.startTime)
      || !isDeepStrictEqual(identity.executable, policy.witnessExecutable)) reject();
    assertExecutableIdentity(identity.executable);
  }
  if (value.schemaVersion !== A28_WITNESS_SCHEMA_VERSION
    || value.event !== 'a28-secure-enclave-enrolment-authorised'
    || value.enrolmentAuthorityConfigSha256 !== configSha256
    || value.enrolmentManifestSha256 !== manifestSha256
    || value.enrolmentManifestSha256 !== policy.enrolmentManifestSha256
    || value.publicKeySha256 !== enrolmentValue.publicKeySha256
    || value.reviewerIdentity !== policy.reviewerIdentity
    || value.reviewerKeyId !== enrolmentValue.reviewerKeyId
    || value.witnessUid !== policy.witnessUid
    || value.witnessGid !== policy.witnessGid
    || !isDeepStrictEqual(keyAttributes, enrolmentValue.keyAttributes)
    || !isDeepStrictEqual(
      value.applicationIdentityBefore,
      value.applicationIdentityAfter,
    )
    || authorisedAt < enrolledAt
    || authorisedAt > now + MAX_CLOCK_SKEW_MS
    || value.outputIdentity.path !== policy.enrolmentManifestPath
    || value.outputIdentity.uid !== 0
    || value.outputIdentity.gid !== 0
    || value.outputIdentity.mode !== 0o400
    || value.outputIdentity.size !== manifestBytes.length
    || value.outputIdentity.sha256 !== manifestSha256
    || !Number.isSafeInteger(value.outputIdentity.dev)
    || value.outputIdentity.dev < 1
    || !Number.isSafeInteger(value.outputIdentity.ino)
    || value.outputIdentity.ino < 1
    || sha256A28(canonicalA28Line(value))
      !== policy.enrolmentAuthorityReceiptSha256) reject();
  return Object.freeze({
    ...value,
    applicationIdentityAfter: Object.freeze({
      ...value.applicationIdentityAfter,
      executable: Object.freeze({ ...value.applicationIdentityAfter.executable }),
    }),
    applicationIdentityBefore: Object.freeze({
      ...value.applicationIdentityBefore,
      executable: Object.freeze({ ...value.applicationIdentityBefore.executable }),
    }),
    keyAttributes,
    outputIdentity: Object.freeze({ ...value.outputIdentity }),
  });
}

export function assertA28WitnessAppInspection(value, policyPin) {
  const policy = assertA28PolicyPin(policyPin);
  exactKeys(value, INSPECTION_KEYS);
  if (value.installedApplicationPath !== policy.installedApplicationPath
    || value.bundleIdentifier !== policy.bundleIdentifier
    || value.teamIdentifier !== policy.teamIdentifier
    || value.applicationIdentifier !== policy.applicationIdentifier
    || value.cdHash !== policy.cdHash
    || value.designatedRequirement !== policy.designatedRequirement
    || value.signingCertificateSha256 !== policy.signingCertificateSha256
    || value.signingIdentity !== policy.signingIdentity
    || value.profileSha256 !== policy.profileSha256
    || value.profileUuid !== policy.profileUuid
    || value.profileName !== policy.profileName
    || value.effectiveEntitlementsSha256 !== policy.effectiveEntitlementsSha256
    || value.hardenedRuntime !== true
    || !isDeepStrictEqual(value.effectiveEntitlements, policy.effectiveEntitlements)
    || !isDeepStrictEqual(value.profileTeamIdentifiers, [policy.teamIdentifier])
    || !isDeepStrictEqual(value.keychainAccessGroups, [policy.keychainAccessGroup])
    || !Array.isArray(value.appleCertificateChain)
    || value.appleCertificateChain.length < 3
    || value.appleCertificateChain[0] !== policy.signingIdentity
    || !value.appleCertificateChain.some((name) =>
      typeof name === 'string'
        && name.includes('Developer ID Certification Authority'))
    || !value.appleCertificateChain.some((name) => name === 'Apple Root CA')) reject();
  return Object.freeze({ ...value });
}

function assertDecision(value, checkpoint, challenge) {
  exactKeys(value, DECISION_KEYS);
  if (!['dark', 'light'].includes(value.appearance)
    || !['accessible', 'virtualised'].includes(value.mode)
    || !['pass', 'fail'].includes(value.announcements)
    || !['pass', 'fail'].includes(value.focusRetention)
    || !['pass', 'fail'].includes(value.keyboardOrder)
    || value.humanAssertion !== true
    || value.assertionScope !== A28_HUMAN_ASSERTION_SCOPE
    || value.checkpointId !== checkpoint.checkpointId
    || value.checkpointOrdinal !== checkpoint.ordinal
    || value.checkpointTokenSha256 !== checkpoint.tokenSha256
    || value.appearance !== checkpoint.appearance
    || value.mode !== checkpoint.mode
    || a28CheckpointCommitmentSha256({
      appearance: value.appearance,
      architectureGateRunId: challenge.architectureGateRunId,
      challengeRequestSha256: challenge.challengeRequestSha256,
      checkpointId: value.checkpointId,
      checkpointSessionId: challenge.checkpointSessionId,
      mode: value.mode,
      ordinal: value.checkpointOrdinal,
      token: value.checkpointToken,
      witnessNonce: challenge.witnessNonce,
    }) !== checkpoint.tokenSha256
    || typeof value.observedAt !== 'string'
    || !Array.isArray(value.blockingDefects)
    || value.blockingDefects.length > 10
    || value.blockingDefects.some((defect) =>
      typeof defect !== 'string'
      || defect.length < 1
      || defect.length > 240
      || defect !== defect.trim()
      || /[\0\r\n]/u.test(defect))
    || new Set(value.blockingDefects).size !== value.blockingDefects.length) reject();
  parseInstant(value.observedAt);
  const passed = value.announcements === 'pass'
    && value.focusRetention === 'pass'
    && value.keyboardOrder === 'pass';
  if (passed !== (value.blockingDefects.length === 0)) reject();
  return passed;
}

export function assertA28LiveIdentitySnapshot(
  value,
  challenge,
  witnessIdentity,
  now = Date.now(),
) {
  const expected = assertA28Challenge(challenge, now);
  exactKeys(value, LIVE_SNAPSHOT_KEYS);
  for (const processValue of [
    value.host,
    value.runner,
    value.voiceOver,
    value.witness,
  ]) {
    exactKeys(processValue, LIVE_PROCESS_KEYS);
    if (!Number.isSafeInteger(processValue.pid)
      || processValue.pid < 2
      || typeof processValue.startTime !== 'string'
      || !PROCESS_START.test(processValue.startTime)) reject();
    assertSha256(processValue.auditTokenSha256);
    if (typeof processValue.cdHash !== 'string'
      || !CDHASH.test(processValue.cdHash)) reject();
    assertDesignatedRequirement(processValue.designatedRequirement, {
      bundleIdentifier: processValue.bundleIdentifier,
      systemApple: processValue.bundleIdentifier === 'com.apple.VoiceOver',
    });
    assertExecutableIdentity(processValue.executable);
    if (typeof processValue.bundleIdentifier !== 'string'
      || processValue.bundleIdentifier.length < 3
      || processValue.bundleIdentifier.length > 255) reject();
  }
  if (value.host.pid !== expected.applicationPid
    || value.host.startTime !== expected.hostStartTime
    || value.host.auditTokenSha256 !== expected.hostAuditTokenSha256
    || value.host.bundleIdentifier !== expected.hostBundleIdentifier
    || value.host.cdHash !== expected.hostCdHash
    || value.host.designatedRequirement !== expected.hostDesignatedRequirement
    || !isDeepStrictEqual(value.host.executable, expected.hostExecutable)
    || value.runner.pid !== expected.runnerPid
    || value.runner.startTime !== expected.runnerStartTime
    || value.runner.auditTokenSha256 !== expected.runnerAuditTokenSha256
    || value.runner.bundleIdentifier !== expected.runnerBundleIdentifier
    || value.runner.cdHash !== expected.runnerCdHash
    || value.runner.designatedRequirement !== expected.runnerDesignatedRequirement
    || !isDeepStrictEqual(value.runner.executable, expected.runnerExecutable)
    || value.voiceOver.pid !== expected.voiceOverPid
    || value.voiceOver.startTime !== expected.voiceOverStartTime
    || value.voiceOver.auditTokenSha256 !== expected.voiceOverAuditTokenSha256
    || value.voiceOver.bundleIdentifier !== expected.voiceOverBundleIdentifier
    || value.voiceOver.cdHash !== expected.voiceOverCdHash
    || value.voiceOver.designatedRequirement
      !== expected.voiceOverDesignatedRequirement
    || !isDeepStrictEqual(
      value.voiceOver.executable,
      expected.voiceOverExecutable,
    )
    || value.witness.pid !== witnessIdentity?.witnessApplicationPid
    || value.witness.startTime !== witnessIdentity?.witnessStartTime
    || value.witness.auditTokenSha256 !== witnessIdentity?.witnessAuditTokenSha256
    || value.witness.bundleIdentifier !== witnessIdentity?.witnessBundleIdentifier
    || value.witness.cdHash !== witnessIdentity?.witnessCdHash
    || value.witness.designatedRequirement
      !== witnessIdentity?.witnessDesignatedRequirement
    || !isDeepStrictEqual(
      value.witness.executable,
      witnessIdentity?.witnessExecutable,
    )) reject();
  return Object.freeze({
    host: Object.freeze({
      ...value.host,
      executable: Object.freeze({ ...value.host.executable }),
    }),
    runner: Object.freeze({
      ...value.runner,
      executable: Object.freeze({ ...value.runner.executable }),
    }),
    voiceOver: Object.freeze({
      ...value.voiceOver,
      executable: Object.freeze({ ...value.voiceOver.executable }),
    }),
    witness: Object.freeze({
      ...value.witness,
      executable: Object.freeze({ ...value.witness.executable }),
    }),
  });
}

export function assertA28PublishedReceipt(value, {
  attestationBytes,
  challenge,
  enrolment,
  now = Date.now(),
  policyPin,
}) {
  if (!Buffer.isBuffer(attestationBytes) || !Number.isFinite(now)) reject();
  exactKeys(value, PUBLISHED_RECEIPT_KEYS);
  const policy = assertA28PolicyPin(policyPin);
  const challengeValue = assertA28Challenge(challenge, now, policy);
  const attestationOutputIdentity = assertAttestationOutputIdentity(
    value.attestationOutputIdentity,
    challengeValue,
    attestationBytes,
  );
  const enrolmentValue = assertA28Enrolment(enrolment, policy, now);
  const envelope = parseCanonicalA28Line(attestationBytes);
  exactKeys(envelope, ENVELOPE_KEYS);
  if (envelope.schemaVersion !== A28_WITNESS_SCHEMA_VERSION
    || envelope.algorithm !== 'ES256') reject();
  const payload = assertAttestationPayload(envelope.payload, {
    challenge: challengeValue,
    enrolment: enrolmentValue,
    now,
    policyPin: policy,
    requirePassing: true,
  });
  const signature = assertCanonicalP256Signature(envelope.signatureDerBase64);
  const key = assertP256PublicKey(
    enrolmentValue.publicKeySpkiDerBase64,
    enrolmentValue.publicKeySha256,
  );
  const signed = Buffer.concat([
    A28_WITNESS_SIGNING_PREFIX,
    Buffer.from(canonicalA28Json(payload), 'utf8'),
  ]);
  if (!verifySignature('sha256', signed, key, signature)) reject();
  const completedAt = parseInstant(value.completedAt);
  const consumedAt = parseInstant(value.consumedAt);
  const checkpointAuthorisedAt = parseInstant(value.checkpointAuthorisedAt);
  const issuedAt = parseInstant(value.challengeIssuedAt);
  const observationStartedAt = parseInstant(value.observationStartedAt);
  const expiresAt = parseInstant(value.challengeExpiresAt);
  for (const digest of [
    value.architectureGateRunContextSha256,
    value.attestationSha256,
    value.automationTwinFingerprint,
    value.challengeSha256,
    value.challengeRequestSha256,
    value.checkpointChecksSha256,
    value.checkpointSessionId,
    value.enrolmentAuthorityConfigSha256,
    value.enrolmentAuthorityReceiptSha256,
    value.enrolmentManifestSha256,
    value.hostAuditTokenSha256,
    value.hostBundleFingerprint,
    value.hostDesignatedRequirementSha256,
    value.hostExecutableSha256,
    value.measuredTwinDeltaSha256,
    value.policyPinSha256,
    value.productionFingerprint,
    value.reviewerKeyId,
    value.runnerAuditTokenSha256,
    value.runnerDesignatedRequirementSha256,
    value.runnerExecutableSha256,
    value.sourceDigest,
    value.voiceOverAuditTokenSha256,
    value.voiceOverDesignatedRequirementSha256,
    value.voiceOverExecutableSha256,
    value.witnessAuditTokenSha256,
    value.witnessDesignatedRequirementSha256,
    value.witnessExecutableSha256,
    value.witnessKeySha256,
    value.witnessNonce,
  ]) assertSha256(digest);
  for (const digest of [
    value.hostCdHash,
    value.runnerCdHash,
    value.voiceOverCdHash,
    value.witnessCdHash,
  ]) {
    if (typeof digest !== 'string' || !CDHASH.test(digest)) reject();
  }
  if (value.schemaVersion !== A28_WITNESS_SCHEMA_VERSION
    || value.event !== 'a28-authenticated-witness-consumed'
    || value.consumed !== true
    || value.humanWitnessed !== true
    || value.humanWitnessAssertionScope
      !== A28_HUMAN_ASSERTION_SCOPE
    || value.gateContextAuthority !== A28_GATE_CONTEXT_AUTHORITY
    || value.gateContextComparisonRequired !== true
    || value.status !== 'pass'
    || value.attestationSha256 !== sha256A28(attestationBytes)
    || value.applicationPid !== challengeValue.applicationPid
    || value.architectureGateRunContextSha256
      !== challengeValue.architectureGateRunContextSha256
    || value.architectureGateRunId !== challengeValue.architectureGateRunId
    || value.automationTwinFingerprint
      !== challengeValue.automationTwinFingerprint
    || value.challengeExpiresAt !== challengeValue.challengeExpiresAt
    || value.challengeIssuedAt !== challengeValue.challengeIssuedAt
    || value.challengeSha256 !== payload.challengeSha256
    || value.challengeRequestSha256
      !== challengeValue.challengeRequestSha256
    || value.checkpointChecksSha256
      !== sha256A28(canonicalA28Line(payload.checks))
    || value.checkpointSessionId !== challengeValue.checkpointSessionId
    || value.enrolmentAuthorityConfigSha256
      !== policy.enrolmentAuthorityConfigSha256
    || value.enrolmentAuthorityReceiptSha256
      !== policy.enrolmentAuthorityReceiptSha256
    || value.enrolmentManifestSha256 !== policy.enrolmentManifestSha256
    || value.completedAt !== payload.completedAt
    || value.hostAuditTokenSha256 !== challengeValue.hostAuditTokenSha256
    || value.hostBundleFingerprint !== challengeValue.hostBundleFingerprint
    || value.hostBundleIdentifier !== challengeValue.hostBundleIdentifier
    || value.hostCdHash !== challengeValue.hostCdHash
    || value.hostDesignatedRequirementSha256 !== sha256A28(
      Buffer.from(challengeValue.hostDesignatedRequirement, 'utf8'),
    )
    || value.hostExecutableSha256 !== challengeValue.hostExecutable.sha256
    || value.hostStartTime !== challengeValue.hostStartTime
    || value.macosVersion !== challengeValue.macosVersion
    || value.measuredTwinDeltaSha256
      !== challengeValue.measuredTwinDeltaSha256
    || value.observationStartedAt !== payload.observationStartedAt
    || value.policyPinSha256 !== challengeValue.policyPinSha256
    || value.policyPinSha256 !== sha256A28(canonicalA28Line(policy))
    || value.productionFingerprint !== challengeValue.productionFingerprint
    || value.reviewerIdentity !== challengeValue.reviewerIdentity
    || value.reviewerIdentity !== enrolmentValue.reviewerIdentity
    || value.reviewerKeyId !== challengeValue.reviewerKeyId
    || value.reviewerKeyId !== enrolmentValue.reviewerKeyId
    || value.runnerAuditTokenSha256 !== challengeValue.runnerAuditTokenSha256
    || value.runnerAuthority !== 'continuity-only'
    || value.runnerBundleIdentifier !== challengeValue.runnerBundleIdentifier
    || value.runnerCdHash !== challengeValue.runnerCdHash
    || value.runnerDesignatedRequirementSha256 !== sha256A28(
      Buffer.from(challengeValue.runnerDesignatedRequirement, 'utf8'),
    )
    || value.runnerExecutableSha256 !== challengeValue.runnerExecutable.sha256
    || value.runnerPid !== challengeValue.runnerPid
    || value.runnerStartTime !== challengeValue.runnerStartTime
    || value.sourceDigest !== challengeValue.sourceDigest
    || value.voiceOverAuditTokenSha256
      !== challengeValue.voiceOverAuditTokenSha256
    || value.voiceOverBundleIdentifier
      !== challengeValue.voiceOverBundleIdentifier
    || value.voiceOverCdHash !== challengeValue.voiceOverCdHash
    || value.voiceOverDesignatedRequirementSha256 !== sha256A28(
      Buffer.from(challengeValue.voiceOverDesignatedRequirement, 'utf8'),
    )
    || value.voiceOverExecutableSha256
      !== challengeValue.voiceOverExecutable.sha256
    || value.voiceOverPid !== challengeValue.voiceOverPid
    || value.voiceOverStartTime !== challengeValue.voiceOverStartTime
    || value.voiceOverVersion !== challengeValue.voiceOverVersion
    || value.witnessBundleIdentifier !== policy.bundleIdentifier
    || value.witnessApplicationPid !== payload.witnessApplicationPid
    || value.witnessAuditTokenSha256 !== payload.witnessAuditTokenSha256
    || value.witnessCdHash !== policy.cdHash
    || value.witnessDesignatedRequirementSha256 !== sha256A28(
      Buffer.from(policy.designatedRequirement, 'utf8'),
    )
    || value.witnessExecutableSha256 !== policy.witnessExecutable.sha256
    || value.witnessKeySha256 !== enrolmentValue.publicKeySha256
    || value.witnessNonce !== challengeValue.witnessNonce
    || value.witnessStartTime !== payload.witnessStartTime
    || value.witnessUid !== enrolmentValue.witnessUid
    || !Number.isSafeInteger(value.witnessApplicationPid)
    || value.witnessApplicationPid < 2
    || typeof value.witnessStartTime !== 'string'
    || !PROCESS_START.test(value.witnessStartTime)
    || completedAt < issuedAt
    || observationStartedAt < issuedAt
    || observationStartedAt > completedAt
    || completedAt > expiresAt
    || checkpointAuthorisedAt < completedAt
    || checkpointAuthorisedAt > consumedAt
    || consumedAt < completedAt
    || consumedAt > now + MAX_CLOCK_SKEW_MS
    || now - consumedAt > MAX_ATTESTATION_AGE_MS) reject();
  return Object.freeze({
    ...value,
    attestationOutputIdentity,
  });
}

function assertAttestationPayload(payload, {
  challenge,
  enrolment,
  now,
  policyPin,
  requirePassing,
}) {
  exactKeys(payload, PAYLOAD_KEYS);
  const policy = assertA28PolicyPin(policyPin);
  const challengeValue = assertA28Challenge(challenge, now, policy);
  const enrolmentValue = assertA28Enrolment(enrolment, policy, now);
  const completedAt = parseInstant(payload.completedAt);
  const observationStartedAt = parseInstant(payload.observationStartedAt);
  const issuedAt = parseInstant(challengeValue.challengeIssuedAt);
  const expiresAt = parseInstant(challengeValue.challengeExpiresAt);
  const challengeSha256 = sha256A28(canonicalA28Line(challengeValue));
  const policyPinSha256 = sha256A28(canonicalA28Line(policy));
  for (const digest of [
    payload.architectureGateRunContextSha256,
    payload.automationTwinFingerprint,
    payload.challengeSha256,
    payload.challengeRequestSha256,
    payload.hostAuditTokenSha256,
    payload.hostBundleFingerprint,
    payload.measuredTwinDeltaSha256,
    payload.policyPinSha256,
    payload.productionFingerprint,
    payload.reviewerKeyId,
    payload.runnerAuditTokenSha256,
    payload.sourceDigest,
    payload.voiceOverAuditTokenSha256,
    payload.witnessAuditTokenSha256,
    payload.witnessKeySha256,
    payload.witnessNonce,
  ]) assertSha256(digest);
  for (const cdHash of [
    payload.hostCdHash,
    payload.runnerCdHash,
    payload.voiceOverCdHash,
    payload.witnessCdHash,
  ]) {
    if (typeof cdHash !== 'string' || !CDHASH.test(cdHash)) reject();
  }
  const challengeProjection = Object.fromEntries(
    CHALLENGE_KEYS.map((key) => [key, payload[key]]),
  );
  if (!isDeepStrictEqual(challengeProjection, challengeValue)
    || payload.schemaVersion !== A28_WITNESS_SCHEMA_VERSION
    || payload.domain !== A28_WITNESS_DOMAIN
    || payload.gateId !== 'A.28'
    || payload.applicationPid !== challengeValue.applicationPid
    || payload.architectureGateRunContextSha256
      !== challengeValue.architectureGateRunContextSha256
    || payload.architectureGateRunId !== challengeValue.architectureGateRunId
    || payload.automationTwinFingerprint !== challengeValue.automationTwinFingerprint
    || payload.challengeExpiresAt !== challengeValue.challengeExpiresAt
    || payload.challengeIssuedAt !== challengeValue.challengeIssuedAt
    || payload.challengeSha256 !== challengeSha256
    || payload.hostAuditTokenSha256 !== challengeValue.hostAuditTokenSha256
    || payload.hostBundleFingerprint !== challengeValue.hostBundleFingerprint
    || payload.hostBundleIdentifier !== challengeValue.hostBundleIdentifier
    || payload.hostBundlePath !== challengeValue.hostBundlePath
    || payload.hostCdHash !== challengeValue.hostCdHash
    || !isDeepStrictEqual(payload.hostExecutable, challengeValue.hostExecutable)
    || payload.hostStartTime !== challengeValue.hostStartTime
    || payload.macosVersion !== challengeValue.macosVersion
    || payload.measuredTwinDeltaSha256 !== challengeValue.measuredTwinDeltaSha256
    || payload.policyPinSha256 !== policyPinSha256
    || payload.policyPinSha256 !== challengeValue.policyPinSha256
    || payload.productionFingerprint !== challengeValue.productionFingerprint
    || payload.reviewerIdentity !== challengeValue.reviewerIdentity
    || payload.reviewerIdentity !== enrolmentValue.reviewerIdentity
    || payload.reviewerKeyId !== challengeValue.reviewerKeyId
    || payload.reviewerKeyId !== enrolmentValue.reviewerKeyId
    || payload.runnerAuditTokenSha256 !== challengeValue.runnerAuditTokenSha256
    || payload.runnerBundleIdentifier !== challengeValue.runnerBundleIdentifier
    || payload.runnerCdHash !== challengeValue.runnerCdHash
    || !isDeepStrictEqual(payload.runnerExecutable, challengeValue.runnerExecutable)
    || payload.runnerPid !== challengeValue.runnerPid
    || payload.runnerStartTime !== challengeValue.runnerStartTime
    || payload.sourceDigest !== challengeValue.sourceDigest
    || payload.voiceOverVersion !== challengeValue.voiceOverVersion
    || payload.witnessNonce !== challengeValue.witnessNonce
    || payload.witnessKeySha256 !== enrolmentValue.publicKeySha256
    || payload.witnessUid !== enrolmentValue.witnessUid
    || !Number.isSafeInteger(payload.witnessApplicationPid)
    || payload.witnessApplicationPid < 2
    || payload.witnessApplicationPid === payload.applicationPid
    || payload.witnessApplicationPid === payload.runnerPid
    || payload.witnessApplicationPid === payload.voiceOverPid
    || payload.witnessBundleIdentifier !== policy.bundleIdentifier
    || payload.witnessCdHash !== policy.cdHash
    || payload.witnessDesignatedRequirement !== policy.designatedRequirement
    || !isDeepStrictEqual(payload.witnessExecutable, policy.witnessExecutable)
    || typeof payload.witnessStartTime !== 'string'
    || !PROCESS_START.test(payload.witnessStartTime)
    || observationStartedAt < issuedAt
    || observationStartedAt > completedAt
    || completedAt < issuedAt
    || completedAt > expiresAt
    || completedAt > now + MAX_CLOCK_SKEW_MS
    || now - completedAt > MAX_ATTESTATION_AGE_MS
    || !Array.isArray(payload.checks)
    || payload.checks.length !== EXPECTED_COMBINATIONS.length) reject();
  assertExecutableIdentity(payload.witnessExecutable);
  const combinations = [];
  const revealedTokens = new Set();
  let lastObservedAt = observationStartedAt;
  let passed = true;
  for (let index = 0; index < payload.checks.length; index += 1) {
    const decision = payload.checks[index];
    passed = assertDecision(
      decision,
      challengeValue.stateCheckpoints[index],
      challengeValue,
    ) && passed;
    const observedAt = parseInstant(decision.observedAt);
    if (observedAt < observationStartedAt
      || observedAt < lastObservedAt
      || observedAt > completedAt
      || revealedTokens.has(decision.checkpointToken)) reject();
    revealedTokens.add(decision.checkpointToken);
    lastObservedAt = observedAt;
    combinations.push(decision.appearance + ':' + decision.mode);
  }
  if (!isDeepStrictEqual(combinations, EXPECTED_COMBINATIONS)
    || payload.status !== (passed ? 'pass' : 'fail')
    || (requirePassing && !passed)) reject();
  return Object.freeze({
    ...payload,
    checks: Object.freeze(payload.checks.map((decision) => Object.freeze({
      ...decision,
      blockingDefects: Object.freeze([...decision.blockingDefects]),
    }))),
  });
}

export async function verifyA28WitnessAttestation({
  attestationBytes,
  attestationOutputIdentity,
  authoriseCheckpoints,
  authorityConfig,
  challenge,
  consumeOnce,
  enrolment,
  enrolmentAuthorityReceipt,
  inspection,
  now = Date.now(),
  observeLiveIdentities,
  policyPin,
  requirePassing = true,
}) {
  if (typeof authoriseCheckpoints !== 'function'
    || typeof consumeOnce !== 'function'
    || typeof observeLiveIdentities !== 'function'
    || !Number.isFinite(now)) reject();
  const policy = assertA28PolicyPin(policyPin);
  const enrolmentValue = assertA28Enrolment(enrolment, policy, now);
  assertA28EnrolmentAuthorityReceipt(enrolmentAuthorityReceipt, {
    authorityConfig,
    enrolment: enrolmentValue,
    now,
    policyPin: policy,
  });
  assertA28WitnessAppInspection(inspection, policy);
  const challengeValue = assertA28Challenge(challenge, now, policy);
  const outputIdentity = assertAttestationOutputIdentity(
    attestationOutputIdentity,
    challengeValue,
    attestationBytes,
  );
  const envelope = parseCanonicalA28Line(attestationBytes);
  exactKeys(envelope, ENVELOPE_KEYS);
  if (envelope.schemaVersion !== A28_WITNESS_SCHEMA_VERSION
    || envelope.algorithm !== 'ES256') reject();
  const payload = assertAttestationPayload(envelope.payload, {
    challenge: challengeValue,
    enrolment: enrolmentValue,
    now,
    policyPin: policy,
    requirePassing,
  });
  const before = assertA28LiveIdentitySnapshot(
    await observeLiveIdentities('before-signature-verification', payload),
    challengeValue,
    payload,
    now,
  );
  const signature = assertCanonicalP256Signature(envelope.signatureDerBase64);
  const key = assertP256PublicKey(
    enrolmentValue.publicKeySpkiDerBase64,
    enrolmentValue.publicKeySha256,
  );
  const signed = Buffer.concat([
    A28_WITNESS_SIGNING_PREFIX,
    Buffer.from(canonicalA28Json(payload), 'utf8'),
  ]);
  if (!verifySignature('sha256', signed, key, signature)) reject();
  const after = assertA28LiveIdentitySnapshot(
    await observeLiveIdentities('after-signature-verification', payload),
    challengeValue,
    payload,
    now,
  );
  if (!isDeepStrictEqual(before, after)) reject();
  const challengeSha256 = sha256A28(canonicalA28Line(challengeValue));
  const checkpointChecksSha256 = sha256A28(canonicalA28Line(payload.checks));
  const checkpointAuthorisation = await authoriseCheckpoints(Object.freeze({
    challengeSha256,
    challengeRequestSha256: challengeValue.challengeRequestSha256,
    checkpointChecksSha256,
    checkpointSessionId: challengeValue.checkpointSessionId,
    checks: payload.checks,
    completedAt: payload.completedAt,
    witnessApplicationPid: payload.witnessApplicationPid,
  }));
  exactKeys(checkpointAuthorisation, CHECKPOINT_AUTHORISATION_KEYS);
  const checkpointAuthorisedAt = parseInstant(
    checkpointAuthorisation.authorisedAt,
  );
  if (checkpointAuthorisation.authorised !== true
    || checkpointAuthorisation.challengeSha256 !== challengeSha256
    || checkpointAuthorisation.challengeRequestSha256
      !== challengeValue.challengeRequestSha256
    || checkpointAuthorisation.checkpointChecksSha256
      !== checkpointChecksSha256
    || checkpointAuthorisation.checkpointSessionId
      !== challengeValue.checkpointSessionId
    || checkpointAuthorisedAt < parseInstant(payload.completedAt)
    || checkpointAuthorisedAt > now + MAX_CLOCK_SKEW_MS) reject();
  const attestationSha256 = sha256A28(attestationBytes);
  const auditRecord = Object.freeze({
    applicationPid: payload.applicationPid,
    architectureGateRunContextSha256: payload.architectureGateRunContextSha256,
    architectureGateRunId: payload.architectureGateRunId,
    attestationOutputIdentity: outputIdentity,
    attestationSha256,
    automationTwinFingerprint: payload.automationTwinFingerprint,
    challengeExpiresAt: payload.challengeExpiresAt,
    challengeIssuedAt: payload.challengeIssuedAt,
    challengeRequestSha256: payload.challengeRequestSha256,
    challengeSha256,
    checkpointAuthorisedAt: checkpointAuthorisation.authorisedAt,
    checkpointChecksSha256,
    checkpointSessionId: payload.checkpointSessionId,
    completedAt: payload.completedAt,
    consumed: true,
    consumedAt: new Date(now).toISOString(),
    event: 'a28-authenticated-witness-consumed',
    gateContextAuthority: A28_GATE_CONTEXT_AUTHORITY,
    gateContextComparisonRequired: true,
    enrolmentAuthorityConfigSha256: policy.enrolmentAuthorityConfigSha256,
    enrolmentAuthorityReceiptSha256: policy.enrolmentAuthorityReceiptSha256,
    enrolmentManifestSha256: policy.enrolmentManifestSha256,
    hostAuditTokenSha256: payload.hostAuditTokenSha256,
    hostBundleFingerprint: payload.hostBundleFingerprint,
    hostBundleIdentifier: payload.hostBundleIdentifier,
    hostCdHash: payload.hostCdHash,
    hostDesignatedRequirementSha256: sha256A28(
      Buffer.from(payload.hostDesignatedRequirement, 'utf8'),
    ),
    hostExecutableSha256: payload.hostExecutable.sha256,
    hostStartTime: payload.hostStartTime,
    humanWitnessed: true,
    humanWitnessAssertionScope: A28_HUMAN_ASSERTION_SCOPE,
    macosVersion: payload.macosVersion,
    measuredTwinDeltaSha256: payload.measuredTwinDeltaSha256,
    observationStartedAt: payload.observationStartedAt,
    policyPinSha256: payload.policyPinSha256,
    productionFingerprint: payload.productionFingerprint,
    schemaVersion: A28_WITNESS_SCHEMA_VERSION,
    sourceDigest: payload.sourceDigest,
    status: payload.status,
    reviewerIdentity: payload.reviewerIdentity,
    reviewerKeyId: payload.reviewerKeyId,
    runnerAuditTokenSha256: payload.runnerAuditTokenSha256,
    runnerAuthority: 'continuity-only',
    runnerBundleIdentifier: payload.runnerBundleIdentifier,
    runnerCdHash: payload.runnerCdHash,
    runnerDesignatedRequirementSha256: sha256A28(
      Buffer.from(payload.runnerDesignatedRequirement, 'utf8'),
    ),
    runnerExecutableSha256: payload.runnerExecutable.sha256,
    runnerPid: payload.runnerPid,
    runnerStartTime: payload.runnerStartTime,
    voiceOverAuditTokenSha256: payload.voiceOverAuditTokenSha256,
    voiceOverBundleIdentifier: payload.voiceOverBundleIdentifier,
    voiceOverCdHash: payload.voiceOverCdHash,
    voiceOverDesignatedRequirementSha256: sha256A28(
      Buffer.from(payload.voiceOverDesignatedRequirement, 'utf8'),
    ),
    voiceOverExecutableSha256: payload.voiceOverExecutable.sha256,
    voiceOverPid: payload.voiceOverPid,
    voiceOverStartTime: payload.voiceOverStartTime,
    voiceOverVersion: payload.voiceOverVersion,
    witnessApplicationPid: payload.witnessApplicationPid,
    witnessAuditTokenSha256: payload.witnessAuditTokenSha256,
    witnessBundleIdentifier: payload.witnessBundleIdentifier,
    witnessCdHash: payload.witnessCdHash,
    witnessDesignatedRequirementSha256: sha256A28(
      Buffer.from(payload.witnessDesignatedRequirement, 'utf8'),
    ),
    witnessExecutableSha256: payload.witnessExecutable.sha256,
    witnessKeySha256: payload.witnessKeySha256,
    witnessNonce: payload.witnessNonce,
    witnessUid: payload.witnessUid,
    witnessStartTime: payload.witnessStartTime,
  });
  const receipt = await consumeOnce(auditRecord);
  if (!isDeepStrictEqual(receipt, auditRecord)) reject();
  return Object.freeze({
    attestationSha256,
    audit: Object.freeze({ ...receipt }),
    checks: payload.checks,
    humanWitnessed: true,
    gateContextAuthority: A28_GATE_CONTEXT_AUTHORITY,
    gateContextComparisonRequired: true,
    schemaVersion: A28_WITNESS_SCHEMA_VERSION,
    status: payload.status,
    witnessKeySha256: payload.witnessKeySha256,
    witnessNonce: payload.witnessNonce,
  });
}
