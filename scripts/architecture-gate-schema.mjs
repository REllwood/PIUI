import { createHash } from 'node:crypto';
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { dirname, resolve } from 'node:path';

export const ARCHITECTURE_GATE_SCHEMA_VERSION = 1;
export const ARCHITECTURE_GATE_TARGET = 'aarch64-apple-darwin';
export const MAX_ARCHITECTURE_RESULTS_BYTES = 1_048_576;
const SHA256 = /^[0-9a-f]{64}$/;
const SHA1 = /^[0-9A-F]{40}$/;
const CDHASH = /^[0-9a-f]{40}$/;
const TEAM_ID = /^[A-Z0-9]{10}$/;
const APPLE_DEVELOPMENT_COMMON_NAME = /^Apple Development: [^\p{Cc}"\\]{1,200} \([A-Z0-9]{10}\)$/u;
export const AUTOMATION_SIGNING_BUNDLE_IDENTIFIER = 'au.com.piui.desktop.architecture-test';
export const AUTOMATION_SIGNING_POLICY_ENVIRONMENT = 'PIUI_AUTOMATION_SIGNING_POLICY';
export const AUTOMATION_SIGNING_POLICY_DEFAULT_RELATIVE_PATH =
  'Library/Application Support/PIUI/automation-signing-policy.json';
export const AUTOMATION_SIGNING_NOT_CONFIGURED = 'PIUI_AUTOMATION_SIGNING_NOT_CONFIGURED';
const AUTOMATION_SIGNING_REQUIREMENTS_BYTES = 136;
const MAX_AUTOMATION_SIGNING_POLICY_BYTES = 16_384;
const AUTOMATION_SIGNING_POLICY_KEYS = Object.freeze([
  'bundleIdentifier',
  'certificateCommonName',
  'certificateSha1',
  'certificateSha256',
  'designatedRequirement',
  'requirementsBytes',
  'schemaVersion',
  'teamIdentifier',
]);
let configuredAutomationSigningPolicy;
export const ARCHITECTURE_VARIANT_DEFINITION_SHA256 = Object.freeze({
  'approval-twin': 'e43d120f6b463a0cfb9abcc976f1623fed7c413345e993fd2c43af021fa78989',
  'automation-twin': '2b8951ea71e231e3dcef4f47e0871d39c6608e614fe4bf3a716fc8c5dbafffdd',
  'credential-twin': '46fe35ee085461fe862709f0bb59261bdb6b0df264e342874845b97222e3f9b7',
});
export const ARCHITECTURE_PROOF_CONTRACTS = Object.freeze({
  'A.21': Object.freeze({
    artifactKind: 'production',
    artifactResultKey: 'production',
    batchId: 'production',
    commandId: 'spike:package:inspect',
  }),
  'A.22': Object.freeze({
    artifactKind: 'production',
    artifactResultKey: 'production',
    batchId: 'production',
    commandId: 'spike:packaged:sdk',
  }),
  'A.23': Object.freeze({
    artifactKind: 'credential-twin',
    artifactResultKey: 'credentialTwin',
    batchId: 'credential',
    commandId: 'spike:packaged:credentials',
  }),
  'A.24': Object.freeze({
    artifactKind: 'production',
    artifactResultKey: 'production',
    batchId: 'production',
    commandId: 'spike:packaged:trust',
  }),
  'A.25': Object.freeze({
    artifactKind: 'approval-twin',
    artifactResultKey: 'approvalTwin',
    batchId: 'approval',
    commandId: 'spike:packaged:approvals',
  }),
  'A.26': Object.freeze({
    artifactKind: 'automation-twin',
    artifactResultKey: 'automationTwin',
    batchId: 'automation',
    commandId: 'spike:packaged:markdown',
  }),
  'A.27': Object.freeze({
    artifactKind: 'automation-twin',
    artifactResultKey: 'automationTwin',
    batchId: 'automation',
    commandId: 'spike:packaged:lifecycle',
  }),
  'A.28': Object.freeze({
    artifactKind: 'automation-twin',
    artifactResultKey: 'automationTwin',
    batchId: 'automation',
    commandId: 'spike:packaged:accessibility',
  }),
});
export const ARCHITECTURE_PROOF_IDS = Object.freeze(
  Object.keys(ARCHITECTURE_PROOF_CONTRACTS),
);

function reject(message = 'Architecture gate evidence rejected') {
  throw new Error(message);
}

function isRecord(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, expected) {
  if (!isRecord(value)) reject();
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])) reject();
}

function exactSha256(value) {
  if (typeof value !== 'string' || !SHA256.test(value)) reject();
}

function exactPositiveInteger(value) {
  if (!Number.isSafeInteger(value) || value < 1) reject();
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
    Object.keys(value)
      .sort()
      .map((key) => [key, canonicalise(value[key])]),
  );
}

export function canonicalArchitectureJson(value) {
  return JSON.stringify(canonicalise(value));
}

/**
 * The Apple Development identity that signs the automation twin belongs to
 * one developer, so it is never committed. It lives in a local, owner-only
 * JSON file outside the repository and is resolved lazily: copies of this
 * schema inside narrower sandboxes never touch the file unless they validate
 * automation-signed evidence.
 */
export function automationSigningPolicyPath(
  environment = process.env,
  home = homedir(),
) {
  const configured = environment?.[AUTOMATION_SIGNING_POLICY_ENVIRONMENT];
  if (configured === undefined || configured === '') {
    if (typeof home !== 'string' || !home.startsWith('/') || /[\0\r\n]/u.test(home)) {
      reject('Automation signing policy home directory is invalid');
    }
    return resolve(home, AUTOMATION_SIGNING_POLICY_DEFAULT_RELATIVE_PATH);
  }
  if (typeof configured !== 'string'
    || !configured.startsWith('/')
    || resolve(configured) !== configured
    || /[\0\r\n]/u.test(configured)) {
    reject(`${AUTOMATION_SIGNING_POLICY_ENVIRONMENT} must be an absolute, normalised path`);
  }
  return configured;
}

export function parseAutomationSigningPolicy(value) {
  const invalid = 'Automation signing policy is invalid';
  if (!isRecord(value)) reject(invalid);
  const keys = Object.keys(value).sort();
  if (keys.length !== AUTOMATION_SIGNING_POLICY_KEYS.length
    || keys.some((key, index) => key !== AUTOMATION_SIGNING_POLICY_KEYS[index])) reject(invalid);
  if (value.schemaVersion !== 1
    || value.bundleIdentifier !== AUTOMATION_SIGNING_BUNDLE_IDENTIFIER
    || typeof value.certificateCommonName !== 'string'
    || !APPLE_DEVELOPMENT_COMMON_NAME.test(value.certificateCommonName)
    || typeof value.certificateSha1 !== 'string'
    || !SHA1.test(value.certificateSha1)
    || typeof value.certificateSha256 !== 'string'
    || !SHA256.test(value.certificateSha256)
    || typeof value.teamIdentifier !== 'string'
    || !TEAM_ID.test(value.teamIdentifier)
    || value.designatedRequirement
      !== `anchor apple generic and identifier "${AUTOMATION_SIGNING_BUNDLE_IDENTIFIER}" and certificate leaf[subject.OU] = "${value.teamIdentifier}"`
    || value.requirementsBytes !== AUTOMATION_SIGNING_REQUIREMENTS_BYTES) reject(invalid);
  return Object.freeze({
    bundleIdentifier: value.bundleIdentifier,
    certificateCommonName: value.certificateCommonName,
    certificateSha1: value.certificateSha1,
    certificateSha256: value.certificateSha256,
    designatedRequirement: value.designatedRequirement,
    requirementsBytes: value.requirementsBytes,
    schemaVersion: value.schemaVersion,
    teamIdentifier: value.teamIdentifier,
  });
}

/**
 * Read one policy file without following links. The file and its parent must
 * belong to the current account and be unwritable by group or world, so no
 * other local account can redirect which certificate the gate trusts.
 */
export function readAutomationSigningPolicy(path) {
  if (typeof path !== 'string'
    || !path.startsWith('/')
    || resolve(path) !== path
    || /[\0\r\n]/u.test(path)) {
    reject('Automation signing policy path is invalid');
  }
  let pathState;
  try {
    pathState = lstatSync(path, { bigint: true });
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    const missing = new Error(
      `Automation signing identity not configured: ${path} is absent; create it or set ${AUTOMATION_SIGNING_POLICY_ENVIRONMENT}`,
    );
    missing.code = AUTOMATION_SIGNING_NOT_CONFIGURED;
    throw missing;
  }
  const unsafe = 'Automation signing policy file is unsafe';
  const uid = typeof process.getuid === 'function' ? BigInt(process.getuid()) : undefined;
  const parentState = lstatSync(dirname(path), { bigint: true });
  if (pathState.isSymbolicLink()
    || !pathState.isFile()
    || !parentState.isDirectory()
    || (parentState.mode & 0o022n) !== 0n
    || (uid !== undefined && parentState.uid !== uid && parentState.uid !== 0n)
    || realpathSync(path) !== path) reject(unsafe);
  let descriptor;
  let bytes;
  try {
    descriptor = openSync(
      path,
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
    );
    const state = fstatSync(descriptor, { bigint: true });
    if (!state.isFile()
      || state.dev !== pathState.dev
      || state.ino !== pathState.ino
      || state.nlink !== 1n
      || (uid !== undefined && state.uid !== uid)
      || (state.mode & 0o022n) !== 0n
      || state.size < 2n
      || state.size > BigInt(MAX_AUTOMATION_SIGNING_POLICY_BYTES)) reject(unsafe);
    bytes = readFileSync(descriptor);
    if (bytes.length !== Number(state.size)) reject(unsafe);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  const text = bytes.toString('utf8');
  let parsed;
  try {
    if (Buffer.byteLength(text, 'utf8') !== bytes.length) throw new Error('not UTF-8');
    parsed = JSON.parse(text);
  } catch {
    reject('Automation signing policy is invalid');
  }
  return parseAutomationSigningPolicy(parsed);
}

/**
 * The process-wide pin. Anything that signs, inspects or accepts
 * automation-signed evidence calls this, so an unconfigured machine fails
 * closed before touching the Keychain or trusting recorded evidence.
 */
export function automationSigningPolicy() {
  configuredAutomationSigningPolicy ??= readAutomationSigningPolicy(
    automationSigningPolicyPath(),
  );
  return configuredAutomationSigningPolicy;
}

export function sha256Bytes(bytes) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) reject();
  return createHash('sha256').update(bytes).digest('hex');
}

function assertMeasuredDeltaSlots(value, expectedSlots) {
  if (!Array.isArray(value) || value.length !== expectedSlots.length) reject();
  value.forEach((entry, index) => {
    exactKeys(entry, ['sha256', 'size', 'slot']);
    exactSha256(entry.sha256);
    exactPositiveInteger(entry.size);
    if (entry.size < 8 || entry.slot !== expectedSlots[index]) reject();
  });
}

export function assertMeasuredTwinDeltaRecord(value, kind, {
  baseFingerprint,
  twinFingerprint,
  variantDefinitionSha256 = ARCHITECTURE_VARIANT_DEFINITION_SHA256[kind],
} = {}) {
  const plistIdentity = {
    'approval-twin': {
      identifier: 'au.com.piui.desktop.a25-test',
      productName: 'PIUI A25 Architecture Test',
    },
    'automation-twin': {
      identifier: 'au.com.piui.desktop.architecture-test',
      productName: 'PIUI Architecture Test',
    },
    'credential-twin': {
      identifier: 'au.com.piui.desktop.a23-test',
      productName: 'PIUI A23 Architecture Test',
    },
  }[kind];
  if (!plistIdentity) reject();
  exactKeys(value, [
    'added',
    'baseFingerprint',
    'changes',
    'equalEntriesSha256',
    'kind',
    'removed',
    'repeatTwinFingerprint',
    'schemaVersion',
    'twinFingerprint',
    'variantDefinitionSha256',
  ]);
  if (value.schemaVersion !== 1
    || value.kind !== kind
    || !Array.isArray(value.added)
    || value.added.length !== 0
    || !Array.isArray(value.removed)
    || value.removed.length !== 0
    || !Array.isArray(value.changes)
    || value.changes.length !== 2) reject();
  for (const digest of [
    value.baseFingerprint,
    value.equalEntriesSha256,
    value.repeatTwinFingerprint,
    value.twinFingerprint,
    value.variantDefinitionSha256,
  ]) exactSha256(digest);
  if ((baseFingerprint !== undefined && value.baseFingerprint !== baseFingerprint)
    || (twinFingerprint !== undefined && value.twinFingerprint !== twinFingerprint)
    || value.variantDefinitionSha256 !== variantDefinitionSha256
    || (kind !== 'automation-twin'
      && value.repeatTwinFingerprint !== value.twinFingerprint)
    || value.baseFingerprint === value.twinFingerprint) reject();

  const [plist, host] = value.changes;
  exactKeys(plist, [
    'baseSha256',
    'path',
    'semanticPatch',
    'twinSha256',
    'type',
  ]);
  if (plist.path !== 'Contents/Info.plist'
    || plist.type !== 'plist'
    || !Array.isArray(plist.semanticPatch)
    || plist.semanticPatch.length < 2
    || plist.semanticPatch.length > 3) reject();
  exactSha256(plist.baseSha256);
  exactSha256(plist.twinSha256);
  if (plist.baseSha256 === plist.twinSha256) reject();
  const semanticKeys = [];
  for (const change of plist.semanticPatch) {
    exactKeys(change, ['base', 'key', 'twin']);
    if (typeof change.base !== 'string'
      || typeof change.key !== 'string'
      || typeof change.twin !== 'string'
      || ![
        'CFBundleDisplayName',
        'CFBundleIdentifier',
        'CFBundleName',
      ].includes(change.key)) reject();
    semanticKeys.push(change.key);
    if (change.key === 'CFBundleIdentifier') {
      if (change.base !== 'au.com.piui.desktop'
        || change.twin !== plistIdentity.identifier) reject();
    } else if (change.base !== 'PIUI'
      || change.twin !== plistIdentity.productName) reject();
  }
  if (new Set(semanticKeys).size !== semanticKeys.length
    || semanticKeys.join('\0') !== [...semanticKeys].sort().join('\0')
    || !semanticKeys.includes('CFBundleIdentifier')
    || !semanticKeys.some(
      (key) => key === 'CFBundleDisplayName' || key === 'CFBundleName',
    )) reject();

  exactKeys(host, [
    'baseCodeDirectoryFlags',
    'baseCodeDirectorySha256',
    'basePreSignNormalisedSha256',
    'baseSha256',
    'baseSignature',
    'baseSignatureForm',
    'baseUuid',
    'loadCommandContractSha256',
    'path',
    'postSignBundleIdentifier',
    'postSignCdHash',
    'postSignCertificateSha1',
    'postSignCertificateSha256',
    'postSignCmsBytes',
    'postSignCmsSha256',
    'postSignCodeDirectoryFlags',
    'postSignCodeDirectorySha256',
    'postSignDesignatedRequirement',
    'postSignDeterministicIdentitySha256',
    'postSignEntitlements',
    'postSignExecutableBytes',
    'postSignForm',
    'postSignNonCmsSignatureSha256',
    'postSignRequirementsSha256',
    'postSignSignatureContainerBytes',
    'postSignSlots',
    'postSignTeamIdentifier',
    'repeatPreSignCodeDirectorySha256',
    'repeatPostSignCmsSha256',
    'repeatPostSignCmsBytes',
    'repeatPostSignCodeDirectorySha256',
    'repeatPostSignDeterministicIdentitySha256',
    'repeatPostSignExecutableBytes',
    'repeatPostSignNonCmsSignatureSha256',
    'repeatPostSignSignatureContainerBytes',
    'repeatPostSignSlots',
    'repeatTwinSha256',
    'repeatTwinUuid',
    'twinPreSignCodeDirectoryFlags',
    'twinPreSignCodeDirectorySha256',
    'twinPreSignForm',
    'twinPreSignNormalisedSha256',
    'twinSha256',
    'twinSignature',
    'twinUuid',
    'type',
  ]);
  if (host.path !== 'Contents/MacOS/piui'
    || host.type !== 'macho'
    || host.baseSignature !== 'adhoc'
    || !['code-directory', 'superblob'].includes(host.baseSignatureForm)
    || !['code-directory', 'superblob'].includes(host.twinPreSignForm)
    || host.baseCodeDirectoryFlags !== 0x20002
    || host.twinPreSignCodeDirectoryFlags !== 0x20002) reject();
  for (const digest of [
    host.baseCodeDirectorySha256,
    host.basePreSignNormalisedSha256,
    host.baseSha256,
    host.loadCommandContractSha256,
    host.postSignCodeDirectorySha256,
    host.repeatPreSignCodeDirectorySha256,
    host.twinPreSignCodeDirectorySha256,
    host.twinPreSignNormalisedSha256,
    host.twinSha256,
  ]) exactSha256(digest);
  for (const uuid of [host.baseUuid, host.repeatTwinUuid, host.twinUuid]) {
    if (typeof uuid !== 'string' || !/^[0-9a-f]{32}$/u.test(uuid)) reject();
  }
  if (host.baseSha256 === host.twinSha256
    || host.baseUuid === host.twinUuid
    || host.repeatTwinUuid !== host.twinUuid
    || host.repeatPreSignCodeDirectorySha256
      !== host.twinPreSignCodeDirectorySha256) reject();
  if (kind === 'automation-twin') {
    const identity = automationSigningPolicy();
    if (host.twinSignature !== 'cms'
      || host.postSignBundleIdentifier !== identity.bundleIdentifier
      || host.postSignCertificateSha1 !== identity.certificateSha1
      || host.postSignCertificateSha256 !== identity.certificateSha256
      || host.postSignDesignatedRequirement !== identity.designatedRequirement
      || host.postSignEntitlements !== 'none'
      || host.postSignTeamIdentifier !== identity.teamIdentifier
      || !CDHASH.test(host.postSignCdHash)
      || !SHA1.test(host.postSignCertificateSha1)
      || host.postSignCodeDirectoryFlags !== 0
      || host.postSignForm !== 'superblob'
      || !Number.isSafeInteger(host.postSignCmsBytes)
      || host.postSignCmsBytes <= 8
      || !Number.isSafeInteger(host.postSignExecutableBytes)
      || host.postSignExecutableBytes < 1
      || !Number.isSafeInteger(host.postSignSignatureContainerBytes)
      || !Number.isSafeInteger(host.repeatPostSignCmsBytes)
      || host.repeatPostSignCmsBytes <= 8
      || !Number.isSafeInteger(host.repeatPostSignExecutableBytes)
      || host.repeatPostSignExecutableBytes < 1
      || !Number.isSafeInteger(host.repeatPostSignSignatureContainerBytes)
      || host.postSignCdHash !== host.postSignCodeDirectorySha256.slice(0, 40)) reject();
    for (const digest of [
      host.postSignCmsSha256,
      host.postSignDeterministicIdentitySha256,
      host.postSignNonCmsSignatureSha256,
      host.postSignRequirementsSha256,
      host.repeatPostSignCmsSha256,
      host.repeatPostSignCodeDirectorySha256,
      host.repeatPostSignDeterministicIdentitySha256,
      host.repeatPostSignNonCmsSignatureSha256,
      host.repeatTwinSha256,
    ]) exactSha256(digest);
    assertMeasuredDeltaSlots(host.postSignSlots, [0, 2, 0x10000]);
    assertMeasuredDeltaSlots(host.repeatPostSignSlots, [0, 2, 0x10000]);
    if (host.postSignSlots[0].sha256 !== host.postSignCodeDirectorySha256
      || host.postSignSlots[1].sha256 !== host.postSignRequirementsSha256
      || host.postSignSlots[2].sha256 !== host.postSignCmsSha256
      || host.repeatPostSignSlots[0].sha256
        !== host.repeatPostSignCodeDirectorySha256
      || host.repeatPostSignSlots[1].sha256 !== host.postSignRequirementsSha256
      || host.repeatPostSignSlots[2].sha256 !== host.repeatPostSignCmsSha256
      || host.postSignSlots[0].size !== host.repeatPostSignSlots[0].size
      || host.postSignSlots[1].size !== identity.requirementsBytes
      || host.repeatPostSignSlots[1].size !== identity.requirementsBytes
      || host.postSignSlots[2].size !== host.postSignCmsBytes
      || host.repeatPostSignSlots[2].size !== host.repeatPostSignCmsBytes
      || host.postSignSignatureContainerBytes
        < 36 + host.postSignSlots.reduce((total, slot) => total + slot.size, 0)
      || host.repeatPostSignSignatureContainerBytes
        < 36 + host.repeatPostSignSlots.reduce((total, slot) => total + slot.size, 0)
      || host.repeatPostSignCodeDirectorySha256
        !== host.postSignCodeDirectorySha256
      || host.repeatPostSignNonCmsSignatureSha256
        !== host.postSignNonCmsSignatureSha256) reject();
    const deterministicSigningIdentity = Object.freeze({
      bundleIdentifier: host.postSignBundleIdentifier,
      cdHash: host.postSignCdHash,
      certificateSha1: host.postSignCertificateSha1,
      certificateSha256: host.postSignCertificateSha256,
      codeDirectoryFlags: host.postSignCodeDirectoryFlags,
      codeDirectorySha256: host.postSignCodeDirectorySha256,
      designatedRequirement: host.postSignDesignatedRequirement,
      entitlements: host.postSignEntitlements,
      nonCmsSignatureSha256: host.postSignNonCmsSignatureSha256,
      nonCmsSignatureSlots: host.postSignSlots.slice(0, 2),
      requirementsSha256: host.postSignRequirementsSha256,
      schemaVersion: 1,
      signature: 'apple-development',
      teamIdentifier: host.postSignTeamIdentifier,
    });
    const deterministicSigningIdentitySha256 = sha256Bytes(Buffer.from(
      canonicalArchitectureJson(deterministicSigningIdentity),
      'utf8',
    ));
    if (host.postSignDeterministicIdentitySha256
        !== deterministicSigningIdentitySha256
      || host.repeatPostSignDeterministicIdentitySha256
        !== deterministicSigningIdentitySha256) reject();
  } else {
    if (host.twinSignature !== 'adhoc'
      || host.postSignBundleIdentifier !== null
      || host.postSignCdHash !== null
      || host.postSignCertificateSha1 !== null
      || host.postSignCertificateSha256 !== null
      || host.postSignCmsBytes !== null
      || host.postSignCmsSha256 !== null
      || host.postSignDesignatedRequirement !== null
      || host.postSignDeterministicIdentitySha256 !== null
      || host.postSignEntitlements !== null
      || host.postSignExecutableBytes !== null
      || host.postSignNonCmsSignatureSha256 !== null
      || host.postSignRequirementsSha256 !== null
      || host.postSignSignatureContainerBytes !== null
      || host.postSignTeamIdentifier !== null
      || host.repeatPostSignCmsSha256 !== null
      || host.repeatPostSignCmsBytes !== null
      || host.repeatPostSignCodeDirectorySha256 !== null
      || host.repeatPostSignDeterministicIdentitySha256 !== null
      || host.repeatPostSignExecutableBytes !== null
      || host.repeatPostSignNonCmsSignatureSha256 !== null
      || host.repeatPostSignSignatureContainerBytes !== null
      || host.repeatPostSignSlots !== null
      || host.repeatTwinSha256 !== null
      || host.postSignCodeDirectoryFlags !== 0x20002
      || !['code-directory', 'superblob'].includes(host.postSignForm)
      || host.postSignCodeDirectorySha256
        !== host.twinPreSignCodeDirectorySha256) reject();
    assertMeasuredDeltaSlots(host.postSignSlots, [0]);
    if (host.postSignSlots[0].sha256 !== host.postSignCodeDirectorySha256) reject();
  }
  return value;
}

function assertSource(source) {
  exactKeys(source, [
    'cargoLockSha256',
    'digest',
    'forgeSha256',
    'inventorySha256',
    'packageLockSha256',
    'planSha256',
    'specSha256',
  ]);
  for (const value of Object.values(source)) exactSha256(value);
}

function assertArtifact(artifact, expected) {
  exactKeys(artifact, [
    'baseProductionFingerprint',
    'bundleEntries',
    'bundleFiles',
    'controlledDelta',
    'controlledDeltaSha256',
    'distribution',
    'fingerprint',
    'kind',
    'machoFiles',
    'nodeSha256',
    'sidecarSha256',
    'signature',
    'webdriverIncluded',
  ]);
  if (artifact.kind !== expected.kind
    || artifact.distribution !== expected.distribution
    || artifact.signature !== expected.signature
    || artifact.webdriverIncluded !== expected.webdriverIncluded) reject();
  exactSha256(artifact.fingerprint);
  exactSha256(artifact.nodeSha256);
  exactSha256(artifact.sidecarSha256);
  exactPositiveInteger(artifact.bundleEntries);
  exactPositiveInteger(artifact.bundleFiles);
  exactPositiveInteger(artifact.machoFiles);
  if (expected.kind === 'production') {
    if (artifact.baseProductionFingerprint !== null
      || artifact.controlledDelta !== null
      || artifact.controlledDeltaSha256 !== null) reject();
  } else {
    exactSha256(artifact.baseProductionFingerprint);
    exactSha256(artifact.controlledDeltaSha256);
    assertMeasuredTwinDeltaRecord(artifact.controlledDelta, expected.kind, {
      baseFingerprint: artifact.baseProductionFingerprint,
      twinFingerprint: artifact.fingerprint,
    });
    if (artifact.controlledDeltaSha256 !== sha256Bytes(Buffer.from(
      canonicalArchitectureJson(artifact.controlledDelta),
      'utf8',
    ))) reject();
  }
}

export function assertArchitectureArtifact(artifact, kind) {
  const contracts = {
    'approval-twin': {
      kind: 'approval-twin',
      distribution: 'non-distributable',
      signature: 'unsigned-or-adhoc',
      webdriverIncluded: false,
    },
    'automation-twin': {
      kind: 'automation-twin',
      distribution: 'non-distributable',
      signature: 'apple-development',
      webdriverIncluded: true,
    },
    'credential-twin': {
      kind: 'credential-twin',
      distribution: 'non-distributable',
      signature: 'unsigned-or-adhoc',
      webdriverIncluded: false,
    },
    production: {
      kind: 'production',
      distribution: 'local-candidate',
      signature: 'unsigned-or-adhoc',
      webdriverIncluded: false,
    },
  };
  const contract = contracts[kind];
  if (!contract) reject();
  assertArtifact(artifact, contract);
  return artifact;
}

function assertArtifacts(artifacts) {
  exactKeys(artifacts, [
    'approvalTwin',
    'automationTwin',
    'credentialTwin',
    'production',
  ]);
  assertArchitectureArtifact(artifacts.production, 'production');
  assertArchitectureArtifact(artifacts.credentialTwin, 'credential-twin');
  assertArchitectureArtifact(artifacts.approvalTwin, 'approval-twin');
  assertArchitectureArtifact(artifacts.automationTwin, 'automation-twin');
  const productionFingerprint = artifacts.production.fingerprint;
  for (const twin of [
    artifacts.credentialTwin,
    artifacts.approvalTwin,
    artifacts.automationTwin,
  ]) {
    if (twin.baseProductionFingerprint !== productionFingerprint
      || twin.fingerprint === productionFingerprint
      || twin.nodeSha256 !== artifacts.production.nodeSha256
      || twin.sidecarSha256 !== artifacts.production.sidecarSha256) reject();
  }
}

function artifactForProof(artifacts, artifactKind) {
  if (artifactKind === 'production') return artifacts.production;
  if (artifactKind === 'credential-twin') return artifacts.credentialTwin;
  if (artifactKind === 'approval-twin') return artifacts.approvalTwin;
  if (artifactKind === 'automation-twin') return artifacts.automationTwin;
  reject();
}

function assertProof(proof, id, source, artifacts) {
  exactKeys(proof, [
    'artifactFingerprint',
    'artifactKind',
    'commandId',
    'evidenceSha256',
    'sourceDigest',
    'status',
  ]);
  const contract = ARCHITECTURE_PROOF_CONTRACTS[id];
  if (!contract
    || proof.status !== 'pass'
    || proof.commandId !== contract.commandId
    || proof.artifactKind !== contract.artifactKind
    || proof.sourceDigest !== source.digest) reject();
  exactSha256(proof.evidenceSha256);
  const artifact = artifactForProof(artifacts, contract.artifactKind);
  if (proof.artifactFingerprint !== artifact.fingerprint) reject();
}

function assertProofs(proofs, source, artifacts) {
  exactKeys(proofs, ARCHITECTURE_PROOF_IDS);
  for (const id of ARCHITECTURE_PROOF_IDS) assertProof(proofs[id], id, source, artifacts);
  if (proofs['A.26'].artifactFingerprint !== proofs['A.28'].artifactFingerprint) reject();
}

function assertExternalReleaseGates(gates) {
  exactKeys(gates, [
    'developerId',
    'distributionAuthorised',
    'notarisation',
    'updaterHosting',
    'updaterSigning',
  ]);
  if (gates.developerId !== 'not-provided'
    || gates.notarisation !== 'not-provided'
    || gates.updaterHosting !== 'not-provided'
    || gates.updaterSigning !== 'not-provided'
    || gates.distributionAuthorised !== false) reject();
}

function assertLimitations(limitations) {
  exactKeys(limitations, [
    'automationConformanceEquivalence',
    'publicDistribution',
    'trustedExtensionContainment',
  ]);
  if (limitations.automationConformanceEquivalence !== 'not-claimed'
    || limitations.publicDistribution !== 'not-authorised'
    || limitations.trustedExtensionContainment !== 'not-claimed') reject();
}

export function assertArchitectureGateResults(value) {
  exactKeys(value, [
    'artifacts',
    'externalReleaseGates',
    'limitations',
    'proofs',
    'schemaVersion',
    'source',
    'target',
  ]);
  if (value.schemaVersion !== ARCHITECTURE_GATE_SCHEMA_VERSION
    || value.target !== ARCHITECTURE_GATE_TARGET) reject();
  assertSource(value.source);
  assertArtifacts(value.artifacts);
  assertProofs(value.proofs, value.source, value.artifacts);
  assertExternalReleaseGates(value.externalReleaseGates);
  assertLimitations(value.limitations);
  return value;
}

function parseCanonicalOneLine(bytes, maximumBytes) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 3
    || bytes.length > maximumBytes
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
    || bytes.includes(0x00)) reject();
  const text = bytes.subarray(0, -1).toString('utf8');
  if (Buffer.byteLength(text, 'utf8') !== bytes.length - 1) reject();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    reject();
  }
  if (`${canonicalArchitectureJson(parsed)}\n` !== bytes.toString('utf8')) reject();
  return parsed;
}

export function parseArchitectureGateResults(bytes) {
  return assertArchitectureGateResults(
    parseCanonicalOneLine(bytes, MAX_ARCHITECTURE_RESULTS_BYTES),
  );
}

export function createArchitecturePassMarker(results) {
  assertArchitectureGateResults(results);
  const resultsBytes = Buffer.from(`${canonicalArchitectureJson(results)}\n`, 'utf8');
  return Object.freeze({
    decision: 'pass',
    distributionAuthorised: false,
    productionFingerprint: results.artifacts.production.fingerprint,
    resultsSha256: sha256Bytes(resultsBytes),
    schemaVersion: ARCHITECTURE_GATE_SCHEMA_VERSION,
    sourceDigest: results.source.digest,
  });
}

export function assertArchitecturePassMarker(marker, results) {
  exactKeys(marker, [
    'decision',
    'distributionAuthorised',
    'productionFingerprint',
    'resultsSha256',
    'schemaVersion',
    'sourceDigest',
  ]);
  if (marker.schemaVersion !== ARCHITECTURE_GATE_SCHEMA_VERSION
    || marker.decision !== 'pass'
    || marker.distributionAuthorised !== false) reject();
  const expected = createArchitecturePassMarker(results);
  if (canonicalArchitectureJson(marker) !== canonicalArchitectureJson(expected)) reject();
  return marker;
}

export function parseArchitecturePassMarker(bytes, results) {
  return assertArchitecturePassMarker(
    parseCanonicalOneLine(bytes, 4_096),
    results,
  );
}
