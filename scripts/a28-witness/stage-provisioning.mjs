#!/usr/bin/env node
import { constants } from 'node:fs';
import {
  lstat,
  open,
  readdir,
  realpath,
} from 'node:fs/promises';
import {
  dirname,
  isAbsolute,
  relative,
  resolve,
  sep,
} from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import {
  A28_WITNESS_BUNDLE_ID,
  A28_WITNESS_POLICY_ID,
  A28_WITNESS_SCHEMA_VERSION,
  assertA28EnrolmentAuthorityConfig,
  assertA28RootLaunchConfig,
  canonicalA28Json,
  canonicalA28Line,
  parseCanonicalA28Line,
  sha256A28,
} from './contract.mjs';

const REPOSITORY_ROOT = resolve(import.meta.dirname, '../..');
const SUPPORT_ROOT = '/Library/Application Support/PIUI/A28Witness';
const APPLICATION_NAME = 'PIUI A28 VoiceOver Witness.app';
const MAX_INPUT_BYTES = 1024 * 1024;
const MAX_FILE_BYTES = 256 * 1024 * 1024;
const MAX_TREE_BYTES = 512 * 1024 * 1024;
const MAX_TREE_ENTRIES = 4096;
const MAX_TREE_NAME_BYTES = 255;
const MAX_TREE_PATH_BYTES = 4096;
const MAX_DARWIN_PATH_BYTES = 1023;
const PROVISIONING_DISCLOSURE = 'private-operator-material-never-publish';
const SHA256 = /^[0-9a-f]{64}$/u;
const MACH_O_MAGICS = new Set([
  'bebafeca',
  'bfbafeca',
  'cafebabe',
  'cafebabf',
  'cefaedfe',
  'cffaedfe',
  'feedface',
  'feedfacf',
]);

const SOURCE_NAMES = Object.freeze([
  'A28ProcessIdentity.m',
  'A28RootLauncher.m',
  'A28Witness.entitlements.in',
  'A28WitnessApp.m',
  'Info.plist',
]);

const REPOSITORY_TOOL_DEFINITIONS = Object.freeze({
  checkpointAuthority: 'scripts/a28-witness/checkpoint-authority.mjs',
  enrolmentRegistrar: 'scripts/a28-witness/register-enrolment.mjs',
  verifierContract: 'scripts/a28-witness/contract.mjs',
  verifierEntrypoint: 'scripts/a28-witness/verify.mjs',
});

const ACCEPTED_FILE_KEYS = Object.freeze([
  'processInspector',
  'rootLauncher',
  'rootLauncherUnsigned',
  'rootVerifierNode',
  'witnessApplication',
  'witnessExecutableUnsigned',
]);

const EXTERNAL_PIN_KEYS = Object.freeze([
  'cdHash',
  'designatedRequirement',
  'hostDesignatedRequirement',
  'hostTeamIdentifier',
  'minimumMacOSVersion',
  'profileName',
  'profileSha256',
  'profileUuid',
  'repositoryToolSha256',
  'reviewerIdentity',
  'rootLauncherCdHash',
  'rootLauncherDesignatedRequirement',
  'runnerBundleIdentifier',
  'runnerDesignatedRequirement',
  'runnerTeamIdentifier',
  'signingCertificateSha256',
  'signingIdentity',
  'sourceSha256',
  'teamIdentifier',
  'voiceOverDesignatedRequirement',
  'witnessGid',
  'witnessHomeDirectory',
  'witnessTargetDev',
  'witnessTargetIno',
  'witnessUid',
  'witnessUsername',
]);

function reject(message = 'A.28 provisioning stage rejected') {
  throw new Error(message);
}

function exactKeys(value, expected, label) {
  if (value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || !isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort())) {
    reject(`A.28 provisioning ${label} schema rejected`);
  }
}

function assertNonRoot() {
  if (typeof process.getuid !== 'function'
    || typeof process.geteuid !== 'function') reject();
  const uid = process.getuid();
  if (!Number.isSafeInteger(uid)
    || uid < 1
    || process.geteuid() !== uid) {
    reject('A.28 provisioning staging must run as one non-root user');
  }
  return uid;
}

function assertNoPlaceholders(value) {
  if (typeof value === 'string') {
    if (value.startsWith('REQUIRED_')) {
      reject('A.28 provisioning input still contains required placeholders');
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) assertNoPlaceholders(item);
    return;
  }
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) assertNoPlaceholders(item);
  }
}

function sameFile(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.size === right.size
    && left.uid === right.uid
    && left.gid === right.gid
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

function assertAbsoluteCanonicalInputPath(value) {
  if (typeof value !== 'string'
    || !isAbsolute(value)
    || resolve(value) !== value
    || /[\0\r\n]/u.test(value)) {
    reject('A.28 provisioning input path rejected');
  }
}

async function readStableFile(path, {
  maximumBytes = MAX_FILE_BYTES,
  expectedSha256,
  requireMachO = false,
} = {}) {
  assertAbsoluteCanonicalInputPath(path);
  if (await realpath(path) !== path) {
    reject('A.28 provisioning input must use its canonical path');
  }
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    if (!before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1
      || before.size < 1
      || before.size > maximumBytes
      || (before.mode & 0o7022) !== 0
      || ![0, process.getuid()].includes(before.uid)) {
      reject('A.28 provisioning input file metadata rejected');
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const pathname = await lstat(path);
    if (!sameFile(before, after)
      || !sameFile(before, pathname)
      || bytes.length !== before.size) {
      reject('A.28 provisioning input file changed during validation');
    }
    const sha256 = sha256A28(bytes);
    if (expectedSha256 !== undefined
      && (!SHA256.test(expectedSha256) || sha256 !== expectedSha256)) {
      reject('A.28 provisioning input file hash rejected');
    }
    if (requireMachO
      && (bytes.length < 4
        || !MACH_O_MAGICS.has(bytes.subarray(0, 4).toString('hex')))) {
      reject('A.28 provisioning accepted executable is not Mach-O');
    }
    return Object.freeze({
      bytes,
      identity: Object.freeze({
        mode: before.mode & 0o7777,
        path,
        sha256,
        size: before.size,
        uid: before.uid,
      }),
    });
  } finally {
    await handle?.close();
  }
}

async function readCanonicalInput(path) {
  const file = await readStableFile(path, { maximumBytes: MAX_INPUT_BYTES });
  return Object.freeze({
    bytes: file.bytes,
    value: parseCanonicalA28Line(file.bytes),
  });
}

function assertAcceptedFileDescriptor(value, label, tree = false) {
  exactKeys(value, tree ? ['path', 'treeSha256'] : ['path', 'sha256'], label);
  assertAbsoluteCanonicalInputPath(value.path);
  const digest = tree ? value.treeSha256 : value.sha256;
  if (typeof digest !== 'string' || !SHA256.test(digest)) {
    reject(`A.28 provisioning ${label} digest rejected`);
  }
}

function assertProvisioningInput(input) {
  exactKeys(input, ['acceptedFiles', 'externalPins', 'schemaVersion'], 'input');
  if (input.schemaVersion !== A28_WITNESS_SCHEMA_VERSION) reject();
  exactKeys(input.acceptedFiles, ACCEPTED_FILE_KEYS, 'accepted files');
  exactKeys(input.externalPins, EXTERNAL_PIN_KEYS, 'external pins');
  exactKeys(
    input.externalPins.repositoryToolSha256,
    Object.keys(REPOSITORY_TOOL_DEFINITIONS),
    'repository tool pins',
  );
  assertNoPlaceholders(input);
  for (const key of ACCEPTED_FILE_KEYS) {
    assertAcceptedFileDescriptor(
      input.acceptedFiles[key],
      `accepted file ${key}`,
      key === 'witnessApplication',
    );
  }
  for (const digest of [
    input.externalPins.profileSha256,
    input.externalPins.signingCertificateSha256,
    input.externalPins.sourceSha256,
    ...Object.values(input.externalPins.repositoryToolSha256),
  ]) {
    if (typeof digest !== 'string' || !SHA256.test(digest)) reject();
  }
  if (!Number.isSafeInteger(input.externalPins.witnessTargetDev)
    || input.externalPins.witnessTargetDev < 1
    || !Number.isSafeInteger(input.externalPins.witnessTargetIno)
    || input.externalPins.witnessTargetIno < 1) {
    reject('A.28 provisioning final installed witness identity pins rejected');
  }
  return input;
}

async function captureRepositoryInputs(repositoryRoot) {
  assertAbsoluteCanonicalInputPath(repositoryRoot);
  if (await realpath(repositoryRoot) !== repositoryRoot) {
    reject('A.28 provisioning repository root rejected');
  }
  const sourceRoot = resolve(repositoryRoot, 'scripts/a28-witness');
  const sources = [];
  for (const name of SOURCE_NAMES) {
    const sourcePath = resolve(sourceRoot, name);
    if (dirname(sourcePath) !== sourceRoot) reject();
    const file = await readStableFile(sourcePath, { maximumBytes: 4 * 1024 * 1024 });
    sources.push(Object.freeze({
      path: `scripts/a28-witness/${name}`,
      sha256: file.identity.sha256,
    }));
  }
  const sourceManifest = Object.freeze({
    schemaVersion: A28_WITNESS_SCHEMA_VERSION,
    sources: Object.freeze(sources),
  });
  const sourceSha256 = sha256A28(canonicalA28Line(sourceManifest));
  const tools = {};
  for (const [role, relativePath] of Object.entries(REPOSITORY_TOOL_DEFINITIONS)) {
    const file = await readStableFile(resolve(repositoryRoot, relativePath), {
      maximumBytes: 4 * 1024 * 1024,
    });
    tools[role] = Object.freeze({
      path: relativePath,
      sha256: file.identity.sha256,
      size: file.identity.size,
    });
  }
  return Object.freeze({
    sourceManifest,
    sourceSha256,
    tools: Object.freeze(tools),
  });
}

function safeTreeName(name) {
  return typeof name === 'string'
    && name.length >= 1
    && name.isWellFormed()
    && /^[A-Za-z0-9._+@() -]+$/u.test(name)
    && Buffer.byteLength(name, 'utf8') <= MAX_TREE_NAME_BYTES
    && name !== '.'
    && name !== '..'
    && !/[\/\0\r\n]/u.test(name);
}

function normalisedInstallationPathKey(path) {
  if (typeof path !== 'string'
    || path.length < 1
    || !path.isWellFormed()
    || !/^[\x20-\x7e]+$/u.test(path)
    || Buffer.byteLength(path, 'utf8') > MAX_DARWIN_PATH_BYTES) {
    reject('A.28 provisioning installation path rejected');
  }
  return path.toLowerCase();
}

async function captureApplicationTree(rootPath, expectedTreeSha256) {
  assertAbsoluteCanonicalInputPath(rootPath);
  if (await realpath(rootPath) !== rootPath) {
    reject('A.28 provisioning witness application path is not canonical');
  }
  const rootState = await lstat(rootPath);
  if (!rootState.isDirectory()
    || rootState.isSymbolicLink()
    || (rootState.mode & 0o7022) !== 0
    || ![0, process.getuid()].includes(rootState.uid)) {
    reject('A.28 provisioning witness application root metadata rejected');
  }
  const records = [];
  let totalBytes = 0;
  const visit = async (directoryPath, prefix) => {
    const entries = await readdir(directoryPath, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name, 'en'));
    for (const entry of entries) {
      if (!safeTreeName(entry.name)) reject();
      const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absolutePath = resolve(directoryPath, entry.name);
      if (relative(rootPath, absolutePath).split(sep).includes('..')) reject();
      const item = await lstat(absolutePath);
      if (item.isSymbolicLink()
        || (item.isFile() && item.nlink !== 1)
        || (item.mode & 0o7022) !== 0
        || ![0, process.getuid()].includes(item.uid)) {
        reject('A.28 provisioning witness application entry metadata rejected');
      }
      if (item.isDirectory()) {
        records.push(Object.freeze({
          mode: item.mode & 0o7777,
          path: relativePath,
          type: 'directory',
        }));
        await visit(absolutePath, relativePath);
      } else if (item.isFile()) {
        const file = await readStableFile(absolutePath, { maximumBytes: MAX_FILE_BYTES });
        totalBytes += file.identity.size;
        records.push(Object.freeze({
          mode: item.mode & 0o7777,
          path: relativePath,
          sha256: file.identity.sha256,
          size: file.identity.size,
          type: 'file',
        }));
      } else {
        reject('A.28 provisioning witness application special entry rejected');
      }
      if (records.length > MAX_TREE_ENTRIES || totalBytes > MAX_TREE_BYTES) {
        reject('A.28 provisioning witness application exceeds its bounds');
      }
    }
  };
  await visit(rootPath, '');
  records.sort((left, right) => {
    if (left.path < right.path) return -1;
    if (left.path > right.path) return 1;
    return 0;
  });
  const tree = Object.freeze({
    records: Object.freeze(records),
    rootMode: rootState.mode & 0o7777,
    schemaVersion: A28_WITNESS_SCHEMA_VERSION,
  });
  const treeSha256 = sha256A28(canonicalA28Line(tree));
  if (expectedTreeSha256 !== undefined && treeSha256 !== expectedTreeSha256) {
    reject('A.28 provisioning witness application tree hash rejected');
  }
  const executableRecord = records.find(({ path }) =>
    path === 'Contents/MacOS/A28Witness');
  const infoPlistRecord = records.find(({ path }) => path === 'Contents/Info.plist');
  const profileRecord = records.find(({ path }) =>
    path === 'Contents/embedded.provisionprofile');
  if (!executableRecord
    || executableRecord.type !== 'file'
    || !infoPlistRecord
    || infoPlistRecord.type !== 'file'
    || !profileRecord
    || profileRecord.type !== 'file') {
    reject('A.28 provisioning witness application is incomplete');
  }
  const executable = await readStableFile(
    resolve(rootPath, 'Contents/MacOS/A28Witness'),
    { expectedSha256: executableRecord.sha256, requireMachO: true },
  );
  return Object.freeze({
    executable: executable.identity,
    profile: Object.freeze({ ...profileRecord }),
    rootPath,
    tree,
    treeSha256,
  });
}

export async function measureA28AcceptedApplicationTree(rootPath) {
  assertNonRoot();
  const measured = await captureApplicationTree(rootPath);
  return Object.freeze({
    executableSha256: measured.executable.sha256,
    executableSize: measured.executable.size,
    profileSha256: measured.profile.sha256,
    treeSha256: measured.treeSha256,
  });
}

function rootLaunchConfig(values, mode) {
  const entrypoints = {
    checkpoint: [
      `${SUPPORT_ROOT}/authority/checkpoint-authority.mjs`,
      values.repository.tools.checkpointAuthority.sha256,
    ],
    enrol: [
      `${SUPPORT_ROOT}/authority/register-enrolment.mjs`,
      values.repository.tools.enrolmentRegistrar.sha256,
    ],
    verify: [
      `${SUPPORT_ROOT}/verifier/verify.mjs`,
      values.repository.tools.verifierEntrypoint.sha256,
    ],
  };
  const entrypoint = entrypoints[mode];
  if (entrypoint === undefined) reject();
  return Object.freeze({
    contractPath: `${SUPPORT_ROOT}/verifier/contract.mjs`,
    contractSha256: values.repository.tools.verifierContract.sha256,
    entrypointPath: entrypoint[0],
    entrypointSha256: entrypoint[1],
    launcherCdHash: values.externalPins.rootLauncherCdHash,
    launcherDesignatedRequirement:
      values.externalPins.rootLauncherDesignatedRequirement,
    launcherPath: `${SUPPORT_ROOT}/bin/a28-root-launcher`,
    launcherSha256: values.accepted.rootLauncher.identity.sha256,
    mode,
    nodePath: `${SUPPORT_ROOT}/bin/node`,
    nodeSha256: values.accepted.rootVerifierNode.identity.sha256,
    schemaVersion: A28_WITNESS_SCHEMA_VERSION,
    teamIdentifier: values.externalPins.teamIdentifier,
  });
}

function buildAuthorityConfig(values, launchConfigs) {
  const external = values.externalPins;
  const applicationIdentifier = `${external.teamIdentifier}.${A28_WITNESS_BUNDLE_ID}`;
  const keychainAccessGroup = `${applicationIdentifier}.secure-enclave`;
  const effectiveEntitlements = Object.freeze({
    'com.apple.application-identifier': applicationIdentifier,
    'com.apple.developer.team-identifier': external.teamIdentifier,
    'keychain-access-groups': Object.freeze([keychainAccessGroup]),
  });
  const executableTarget =
    `${SUPPORT_ROOT}/app/${APPLICATION_NAME}/Contents/MacOS/A28Witness`;
  return Object.freeze({
    applicationIdentifier,
    auditDirectoryPath: `${SUPPORT_ROOT}/consumed`,
    bundleIdentifier: A28_WITNESS_BUNDLE_ID,
    cdHash: external.cdHash,
    checkpointAuthorityDirectoryPath: `${SUPPORT_ROOT}/checkpoint-private`,
    checkpointCommitmentDirectoryPath: `${SUPPORT_ROOT}/checkpoint-commitments`,
    checkpointDeliveryDirectoryPath: `${SUPPORT_ROOT}/checkpoint-deliveries`,
    designatedRequirement: external.designatedRequirement,
    effectiveEntitlements,
    effectiveEntitlementsSha256: sha256A28(
      Buffer.from(canonicalA28Json(effectiveEntitlements), 'utf8'),
    ),
    enrolmentAuthorityReceiptPath: `${SUPPORT_ROOT}/enrolment-authority-receipt.json`,
    enrolmentManifestPath: `${SUPPORT_ROOT}/enrolment.json`,
    hostDesignatedRequirement: external.hostDesignatedRequirement,
    hostTeamIdentifier: external.hostTeamIdentifier,
    installedApplicationPath: `${SUPPORT_ROOT}/app/${APPLICATION_NAME}`,
    keychainAccessGroup,
    minimumMacOSVersion: external.minimumMacOSVersion,
    policyId: A28_WITNESS_POLICY_ID,
    processInspectorPath: `${SUPPORT_ROOT}/bin/a28-process-identity`,
    processInspectorSha256: values.accepted.processInspector.identity.sha256,
    profileName: external.profileName,
    profileSha256: external.profileSha256,
    profileUuid: external.profileUuid,
    reviewerIdentity: external.reviewerIdentity,
    resultDirectoryPath: `${SUPPORT_ROOT}/results`,
    rootCheckpointAuthorityPath: `${SUPPORT_ROOT}/authority/checkpoint-authority.mjs`,
    rootCheckpointAuthoritySha256:
      values.repository.tools.checkpointAuthority.sha256,
    rootCheckpointLaunchConfigPath: `${SUPPORT_ROOT}/launcher/checkpoint-launch.json`,
    rootCheckpointLaunchConfigSha256:
      sha256A28(canonicalA28Line(launchConfigs.checkpoint)),
    rootEnrolmentLaunchConfigPath: `${SUPPORT_ROOT}/launcher/enrolment-launch.json`,
    rootEnrolmentLaunchConfigSha256:
      sha256A28(canonicalA28Line(launchConfigs.enrol)),
    rootEnrolmentRegistrarPath: `${SUPPORT_ROOT}/authority/register-enrolment.mjs`,
    rootEnrolmentRegistrarSha256:
      values.repository.tools.enrolmentRegistrar.sha256,
    rootLauncherCdHash: external.rootLauncherCdHash,
    rootLauncherDesignatedRequirement: external.rootLauncherDesignatedRequirement,
    rootLauncherPath: `${SUPPORT_ROOT}/bin/a28-root-launcher`,
    rootLauncherSha256: values.accepted.rootLauncher.identity.sha256,
    rootLauncherUnsignedSha256:
      values.accepted.rootLauncherUnsigned.identity.sha256,
    rootVerifierContractPath: `${SUPPORT_ROOT}/verifier/contract.mjs`,
    rootVerifierContractSha256: values.repository.tools.verifierContract.sha256,
    rootVerifierEntrypointPath: `${SUPPORT_ROOT}/verifier/verify.mjs`,
    rootVerifierEntrypointSha256:
      values.repository.tools.verifierEntrypoint.sha256,
    rootVerifierLaunchConfigPath: `${SUPPORT_ROOT}/launcher/verifier-launch.json`,
    rootVerifierLaunchConfigSha256:
      sha256A28(canonicalA28Line(launchConfigs.verify)),
    rootVerifierNodePath: `${SUPPORT_ROOT}/bin/node`,
    rootVerifierNodeSha256: values.accepted.rootVerifierNode.identity.sha256,
    runnerBundleIdentifier: external.runnerBundleIdentifier,
    runnerDesignatedRequirement: external.runnerDesignatedRequirement,
    runnerTeamIdentifier: external.runnerTeamIdentifier,
    schemaVersion: A28_WITNESS_SCHEMA_VERSION,
    signingCertificateSha256: external.signingCertificateSha256,
    signingIdentity: external.signingIdentity,
    sourceSha256: values.repository.sourceSha256,
    teamIdentifier: external.teamIdentifier,
    voiceOverDesignatedRequirement: external.voiceOverDesignatedRequirement,
    witnessExecutable: Object.freeze({
      dev: external.witnessTargetDev,
      ino: external.witnessTargetIno,
      path: executableTarget,
      sha256: values.application.executable.sha256,
      size: values.application.executable.size,
    }),
    witnessExecutableUnsignedSha256:
      values.accepted.witnessExecutableUnsigned.identity.sha256,
    witnessGid: external.witnessGid,
    witnessHomeDirectory: external.witnessHomeDirectory,
    witnessUid: external.witnessUid,
    witnessUsername: external.witnessUsername,
  });
}

function installTarget(path, type, mode, availability, extra = {}) {
  return Object.freeze({
    availability,
    gid: 0,
    mode,
    path,
    type,
    uid: 0,
    ...extra,
  });
}

function buildRequiredAncestorPolicy() {
  const existingSystemAncestor = (path) => Object.freeze({
    allowedBsdFlags: Object.freeze([0, 0x00100000]),
    allowedModes: Object.freeze([0o755]),
    allowedXattrNames: Object.freeze([]),
    canonicalPathRequired: true,
    extendedAclPolicy: 'no-write-granting-entries',
    groupOrOtherWritable: false,
    path,
    state: 'pre-existing-required',
    symbolicLinkAllowed: false,
    type: 'directory',
    uid: 0,
  });
  return Object.freeze([
    existingSystemAncestor('/Library'),
    existingSystemAncestor('/Library/Application Support'),
    Object.freeze({
      allowedBsdFlags: Object.freeze([0]),
      allowedModes: Object.freeze([0o755]),
      allowedXattrNames: Object.freeze([]),
      canonicalPathRequired: true,
      createExclusive: Object.freeze({ gid: 0, mode: 0o755, uid: 0 }),
      extendedAclPolicy: 'no-write-granting-entries',
      groupOrOtherWritable: false,
      path: '/Library/Application Support/PIUI',
      state: 'pre-existing-valid-or-create-exclusive-during-app-preinstall',
      symbolicLinkAllowed: false,
      type: 'directory',
      uid: 0,
    }),
  ]);
}

function buildInstallationTargets(values, authority, generatedFiles) {
  const targets = [];
  for (const [path, mode, availability] of [
    [SUPPORT_ROOT, 0o755, 'preinstalled-validation'],
    [`${SUPPORT_ROOT}/app`, 0o755, 'preinstalled-validation'],
    [`${SUPPORT_ROOT}/authority`, 0o755, 'installation'],
    [`${SUPPORT_ROOT}/bin`, 0o755, 'installation'],
    [`${SUPPORT_ROOT}/launcher`, 0o755, 'installation'],
    [`${SUPPORT_ROOT}/verifier`, 0o755, 'installation'],
    [authority.auditDirectoryPath, 0o700, 'installation'],
    [authority.checkpointAuthorityDirectoryPath, 0o700, 'installation'],
    [authority.checkpointCommitmentDirectoryPath, 0o755, 'installation'],
    [authority.checkpointDeliveryDirectoryPath, 0o755, 'installation'],
    [authority.resultDirectoryPath, 0o755, 'installation'],
    [authority.installedApplicationPath, 0o755, 'preinstalled-validation'],
  ]) targets.push(installTarget(path, 'directory', mode, availability));

  for (const record of values.application.tree.records) {
    const targetPath = `${authority.installedApplicationPath}/${record.path}`;
    if (record.type === 'directory') {
      targets.push(installTarget(
        targetPath,
        'directory',
        0o755,
        'preinstalled-validation',
      ));
    } else {
      targets.push(installTarget(
        targetPath,
        'file',
        (record.mode & 0o111) === 0 ? 0o444 : 0o555,
        'preinstalled-validation',
        {
          ...(record.path === 'Contents/MacOS/A28Witness'
            ? {
              expectedDev: authority.witnessExecutable.dev,
              expectedIno: authority.witnessExecutable.ino,
            }
            : {}),
          sha256: record.sha256,
          size: record.size,
          source: Object.freeze({
            relativePath: record.path,
            role: 'witnessApplication',
          }),
        },
      ));
    }
  }

  for (const [path, mode, role, accepted] of [
    [authority.processInspectorPath, 0o555, 'processInspector',
      values.accepted.processInspector],
    [authority.rootLauncherPath, 0o555, 'rootLauncher',
      values.accepted.rootLauncher],
    [authority.rootVerifierNodePath, 0o500, 'rootVerifierNode',
      values.accepted.rootVerifierNode],
  ]) {
    targets.push(installTarget(path, 'file', mode, 'installation', {
      sha256: accepted.identity.sha256,
      size: accepted.identity.size,
      source: Object.freeze({ role }),
    }));
  }

  for (const [path, mode, repositoryTool] of [
    [authority.rootCheckpointAuthorityPath, 0o444,
      values.repository.tools.checkpointAuthority],
    [authority.rootEnrolmentRegistrarPath, 0o444,
      values.repository.tools.enrolmentRegistrar],
    [authority.rootVerifierContractPath, 0o444,
      values.repository.tools.verifierContract],
    [authority.rootVerifierEntrypointPath, 0o444,
      values.repository.tools.verifierEntrypoint],
  ]) {
    targets.push(installTarget(path, 'file', mode, 'installation', {
      sha256: repositoryTool.sha256,
      size: repositoryTool.size,
      source: Object.freeze({
        relativePath: repositoryTool.path,
        role: 'reviewedRepositoryTool',
      }),
    }));
  }

  for (const [path, stagedFile] of [
    [`${SUPPORT_ROOT}/enrolment-authority.json`, generatedFiles.authority],
    [authority.rootCheckpointLaunchConfigPath, generatedFiles.checkpoint],
    [authority.rootEnrolmentLaunchConfigPath, generatedFiles.enrol],
    [authority.rootVerifierLaunchConfigPath, generatedFiles.verify],
  ]) {
    targets.push(installTarget(path, 'file', 0o444, 'installation', {
      sha256: sha256A28(stagedFile),
      size: stagedFile.length,
      source: Object.freeze({
        relativePath: stagedFile.logicalPath,
        role: 'generatedProvisioningFile',
      }),
    }));
  }

  targets.push(installTarget(
    authority.enrolmentManifestPath,
    'file',
    0o444,
    'post-enrolment',
  ));
  targets.push(installTarget(
    authority.enrolmentAuthorityReceiptPath,
    'file',
    0o400,
    'post-enrolment',
  ));
  targets.push(installTarget(
    `${SUPPORT_ROOT}/policy-pin.json`,
    'file',
    0o444,
    'post-enrolment-policy-finalisation',
  ));
  targets.sort((left, right) => left.path.localeCompare(right.path, 'en'));
  const targetCollisionKeys = targets.map(({ path }) =>
    normalisedInstallationPathKey(path));
  if (new Set(targets.map(({ path }) => path)).size !== targets.length
    || new Set(targetCollisionKeys).size !== targets.length
    || targets.some((target) => target.uid !== 0
      || target.gid !== 0
      || ![
        'installation',
        'post-enrolment',
        'post-enrolment-policy-finalisation',
        'preinstalled-validation',
      ].includes(target.availability)
      || (target.type === 'directory'
        ? ![0o700, 0o755].includes(target.mode)
        : ![0o400, 0o444, 0o500, 0o555].includes(target.mode)))) {
    reject('A.28 provisioning installation target policy rejected');
  }
  return Object.freeze(targets);
}

async function inspectAcceptedFiles(input) {
  const accepted = {};
  for (const role of ACCEPTED_FILE_KEYS) {
    if (role === 'witnessApplication') continue;
    accepted[role] = await readStableFile(input.acceptedFiles[role].path, {
      expectedSha256: input.acceptedFiles[role].sha256,
      requireMachO: true,
    });
  }
  return Object.freeze(accepted);
}

function comparePinnedRepositoryInputs(input, repository) {
  if (input.externalPins.sourceSha256 !== repository.sourceSha256) {
    reject('A.28 provisioning reviewed source digest is stale');
  }
  for (const [role, tool] of Object.entries(repository.tools)) {
    if (input.externalPins.repositoryToolSha256[role] !== tool.sha256) {
      reject(`A.28 provisioning reviewed ${role} digest is stale`);
    }
  }
}

function makeLaunchConfigs(values) {
  return Object.freeze({
    checkpoint: rootLaunchConfig(values, 'checkpoint'),
    enrol: rootLaunchConfig(values, 'enrol'),
    verify: rootLaunchConfig(values, 'verify'),
  });
}

function withLogicalPath(bytes, logicalPath) {
  Object.defineProperty(bytes, 'logicalPath', {
    configurable: false,
    enumerable: false,
    value: logicalPath,
    writable: false,
  });
  return bytes;
}

export async function materialiseA28ProvisioningStage(input, {
  repositoryRoot = REPOSITORY_ROOT,
  progress = () => {},
} = {}) {
  assertNonRoot();
  assertProvisioningInput(input);
  progress('validating reviewed A.28 source and root tool hashes.');
  const repository = await captureRepositoryInputs(repositoryRoot);
  comparePinnedRepositoryInputs(input, repository);
  progress('validating accepted native files and the signed witness tree.');
  const [accepted, application] = await Promise.all([
    inspectAcceptedFiles(input),
    captureApplicationTree(
      input.acceptedFiles.witnessApplication.path,
      input.acceptedFiles.witnessApplication.treeSha256,
    ),
  ]);
  if (application.profile.sha256 !== input.externalPins.profileSha256) {
    reject('A.28 provisioning embedded profile hash rejected');
  }
  const values = Object.freeze({
    accepted,
    application,
    externalPins: input.externalPins,
    repository,
  });
  return buildMaterialisedProvisioning(values);
}

function buildMaterialisedProvisioning(values) {
  const {
    accepted,
    application,
    externalPins,
    repository,
  } = values;
  const preliminaryLaunchConfigs = makeLaunchConfigs(values);
  const authority = buildAuthorityConfig(values, preliminaryLaunchConfigs);
  const launchConfigs = makeLaunchConfigs(values);
  assertA28EnrolmentAuthorityConfig(authority);
  for (const mode of ['checkpoint', 'enrol', 'verify']) {
    assertA28RootLaunchConfig(launchConfigs[mode], authority, mode);
  }
  const authorityBytes = withLogicalPath(
    canonicalA28Line(authority),
    'authority/enrolment-authority.json',
  );
  const checkpointBytes = withLogicalPath(
    canonicalA28Line(launchConfigs.checkpoint),
    'launcher/checkpoint-launch.json',
  );
  const enrolBytes = withLogicalPath(
    canonicalA28Line(launchConfigs.enrol),
    'launcher/enrolment-launch.json',
  );
  const verifyBytes = withLogicalPath(
    canonicalA28Line(launchConfigs.verify),
    'launcher/verifier-launch.json',
  );
  const generatedFiles = Object.freeze({
    authority: authorityBytes,
    checkpoint: checkpointBytes,
    enrol: enrolBytes,
    verify: verifyBytes,
  });
  const targets = buildInstallationTargets(values, authority, generatedFiles);
  const acceptedFiles = Object.freeze(Object.fromEntries(
    ACCEPTED_FILE_KEYS.map((role) => {
      if (role === 'witnessApplication') {
        return [role, Object.freeze({
          executableSha256: application.executable.sha256,
          executableSize: application.executable.size,
          profileSha256: application.profile.sha256,
          role,
          tree: application.tree,
          treeSha256: application.treeSha256,
        })];
      }
      return [role, Object.freeze({
        role,
        sha256: accepted[role].identity.sha256,
        size: accepted[role].identity.size,
      })];
    }),
  ));
  const acceptedInstanceRecord = Object.freeze({
    acceptedFiles,
    acceptedInputPathsIncluded: false,
    disclosureClassification: PROVISIONING_DISCLOSURE,
    externalPins,
    repositorySourceManifest: repository.sourceManifest,
    schemaVersion: A28_WITNESS_SCHEMA_VERSION,
  });
  const acceptedInstanceRecordBytes = canonicalA28Line(acceptedInstanceRecord);
  const installationManifest = Object.freeze({
    acceptedApplicationTreeSha256: application.treeSha256,
    acceptedInputPathsIncluded: false,
    acceptedInstanceRecordSha256: sha256A28(acceptedInstanceRecordBytes),
    authorityConfigSha256: sha256A28(authorityBytes),
    authoritative: false,
    credentialsAccessed: false,
    disclosureClassification: PROVISIONING_DISCLOSURE,
    enrolmentPerformed: false,
    installationSequence: Object.freeze([
      Object.freeze({
        availability: 'preinstalled-validation',
        operation: 'validate-complete-preinstalled-witness-tree',
        ordinal: 1,
      }),
      Object.freeze({
        availability: 'installation',
        operation: 'create-absent-supporting-targets-exclusively',
        ordinal: 2,
      }),
      Object.freeze({
        availability: 'post-enrolment',
        operation: 'validate-root-enrolment-outputs',
        ordinal: 3,
      }),
      Object.freeze({
        availability: 'post-enrolment-policy-finalisation',
        operation: 'create-final-policy-exclusively',
        ordinal: 4,
      }),
    ]),
    installationRequired: true,
    metadataPolicy: Object.freeze({
      bsdFlags: 0,
      extendedAclEntries: 0,
      xattrs: Object.freeze([]),
    }),
    policyFinalisationRequired: true,
    requiredAncestors: buildRequiredAncestorPolicy(),
    repositorySourceManifest: repository.sourceManifest,
    schemaVersion: A28_WITNESS_SCHEMA_VERSION,
    targetRoot: SUPPORT_ROOT,
    targets,
  });
  const policyFinalisationInput = Object.freeze({
    enrolmentAuthorityConfigPath: `${SUPPORT_ROOT}/enrolment-authority.json`,
    enrolmentAuthorityConfigSha256: sha256A28(authorityBytes),
    enrolmentAuthorityReceiptSha256: 'REQUIRED_POST_ENROLMENT_SHA256',
    enrolmentManifestSha256: 'REQUIRED_POST_ENROLMENT_SHA256',
    policyOutputPath: `${SUPPORT_ROOT}/policy-pin.json`,
    schemaVersion: A28_WITNESS_SCHEMA_VERSION,
  });
  return Object.freeze({
    acceptedInstanceRecord,
    authority,
    files: Object.freeze({
      'accepted-instance-record.json': acceptedInstanceRecordBytes,
      'authority/enrolment-authority.json': authorityBytes,
      'installation-manifest.json': canonicalA28Line(installationManifest),
      'launcher/checkpoint-launch.json': checkpointBytes,
      'launcher/enrolment-launch.json': enrolBytes,
      'launcher/verifier-launch.json': verifyBytes,
      'policy-finalisation-input.template.json':
        canonicalA28Line(policyFinalisationInput),
    }),
    installationManifest,
    launchConfigs,
    policyFinalisationInput,
  });
}

function recipeText(authorityConfigSha256) {
  return `# A.28 witness provisioning-plan recipe

This canonical plan is private operator material and must never be published.
It includes the named reviewer account and home-directory policy. It is
non-authoritative, has not installed, signed, enrolled or accessed credentials,
and is not a passing A.28 witness. It contains no original accepted-input path
or binary payload.

1. Independently review the accepted-instance record and the exact source,
   tool, application-tree and Developer ID/profile pins.
2. Validate the saved canonical plan with the non-root validate command before
   privileged work. The plan never authorises an original measurement path.
3. A separately authorised security administrator must independently acquire
   each logical source role and compare its exact hash, size and
   application-tree digest. Validate every preinstalled-validation target from
   the completed exclusive witness-app pass. Create only installation targets
   exclusively and refuse every unrecorded collision.
4. Validate the exact type, canonical no-symlink identity, ownership, mode,
   ACL, BSD-flag and xattr policies for /Library, /Library/Application Support
   and /Library/Application Support/PIUI. The first two are pre-existing system
   ancestors and do not require gid 0. PIUI must already satisfy its recorded
   policy after the exclusive app pass. Every PIUI-owned installed target must
   be root:wheel, use the recorded mode, have zero BSD flags, zero extended ACL
   entries and zero extended attributes. Recheck complete membership, every
   installed hash and size, and final witness dev/ino before enrolment.
5. Run enrolment only through the installed hardened root launcher. Repository
   JavaScript must not run as root.
6. After enrolment, independently validate the root-owned enrolment manifest
   and authority receipt. Replace both REQUIRED_POST_ENROLMENT_SHA256 values in
   the policy-finalisation input with their exact canonical hashes, construct
   the final policy from the unchanged authority config, and validate it with
   assertA28PolicyPin, assertA28Enrolment and
   assertA28EnrolmentAuthorityReceipt before exclusive installation.
7. Never overwrite or remove an existing app, authority, policy, receipt,
   checkpoint, result or Secure Enclave key. Stop for explicit direction on
   any collision or duplicate-key result.

Authority config SHA-256: ${authorityConfigSha256}
`;
}

function provisioningPlanReceipt(materialised, recipe) {
  return Object.freeze({
    acceptedInputPathsIncluded: false,
    acceptedInstanceRecordSha256: sha256A28(
      canonicalA28Line(materialised.acceptedInstanceRecord),
    ),
    authorityConfigSha256: sha256A28(canonicalA28Line(materialised.authority)),
    authoritative: false,
    credentialsAccessed: false,
    disclosureClassification: PROVISIONING_DISCLOSURE,
    enrolmentPerformed: false,
    installationManifestSha256: sha256A28(
      canonicalA28Line(materialised.installationManifest),
    ),
    installationRequired: true,
    launchConfigsSha256: sha256A28(canonicalA28Line(materialised.launchConfigs)),
    policyFinalisationInputSha256: sha256A28(
      canonicalA28Line(materialised.policyFinalisationInput),
    ),
    policyFinalisationRequired: true,
    recipeSha256: sha256A28(Buffer.from(recipe, 'utf8')),
    schemaVersion: A28_WITNESS_SCHEMA_VERSION,
  });
}

function provisioningPlan(materialised) {
  const recipe = recipeText(sha256A28(canonicalA28Line(materialised.authority)));
  const plan = Object.freeze({
    acceptedInstanceRecord: materialised.acceptedInstanceRecord,
    authority: materialised.authority,
    disclosureClassification: PROVISIONING_DISCLOSURE,
    installationManifest: materialised.installationManifest,
    kind: 'a28-provisioning-plan',
    launchConfigs: materialised.launchConfigs,
    policyFinalisationInput: materialised.policyFinalisationInput,
    receipt: provisioningPlanReceipt(materialised, recipe),
    recipe,
    schemaVersion: A28_WITNESS_SCHEMA_VERSION,
  });
  if (canonicalA28Line(plan).length > MAX_INPUT_BYTES) {
    reject('A.28 provisioning canonical plan exceeds its byte bound');
  }
  return plan;
}

function assertRecordedApplicationTree(value, treeSha256) {
  exactKeys(value, ['records', 'rootMode', 'schemaVersion'], 'application tree');
  if (value.schemaVersion !== A28_WITNESS_SCHEMA_VERSION
    || !Number.isSafeInteger(value.rootMode)
    || value.rootMode < 0
    || value.rootMode > 0o7777
    || (value.rootMode & 0o7022) !== 0
    || !Array.isArray(value.records)
    || value.records.length < 3
    || value.records.length > MAX_TREE_ENTRIES
    || sha256A28(canonicalA28Line(value)) !== treeSha256) reject();
  let previousPath;
  let totalBytes = 0;
  const priorTypes = new Map();
  const normalisedTreePaths = new Set();
  for (const record of value.records) {
    const isFile = record?.type === 'file';
    exactKeys(
      record,
      isFile
        ? ['mode', 'path', 'sha256', 'size', 'type']
        : ['mode', 'path', 'type'],
      'application tree record',
    );
    if (typeof record.path !== 'string'
      || record.path.startsWith('/')
      || record.path.endsWith('/')
      || Buffer.byteLength(record.path, 'utf8') > MAX_TREE_PATH_BYTES
      || record.path.split('/').some((segment) => !safeTreeName(segment))
      || (previousPath !== undefined && record.path <= previousPath)
      || !Number.isSafeInteger(record.mode)
      || record.mode < 0
      || record.mode > 0o7777
      || (record.mode & 0o7022) !== 0
      || !['directory', 'file'].includes(record.type)) reject();
    const installedPath = `${SUPPORT_ROOT}/app/${APPLICATION_NAME}/${record.path}`;
    const normalisedPath = normalisedInstallationPathKey(installedPath);
    if (normalisedTreePaths.has(normalisedPath)) reject();
    normalisedTreePaths.add(normalisedPath);
    const segments = record.path.split('/');
    for (let index = 1; index < segments.length; index += 1) {
      const parent = segments.slice(0, index).join('/');
      if (priorTypes.get(parent) !== 'directory') reject();
    }
    previousPath = record.path;
    priorTypes.set(record.path, record.type);
    if (isFile) {
      if (!SHA256.test(record.sha256)
        || !Number.isSafeInteger(record.size)
        || record.size < 1
        || record.size > MAX_FILE_BYTES) reject();
      totalBytes += record.size;
      if (totalBytes > MAX_TREE_BYTES) reject();
    }
  }
  for (const required of [
    ['Contents', 'directory'],
    ['Contents/Info.plist', 'file'],
    ['Contents/MacOS', 'directory'],
    ['Contents/MacOS/A28Witness', 'file'],
    ['Contents/embedded.provisionprofile', 'file'],
  ]) {
    if (priorTypes.get(required[0]) !== required[1]) reject();
  }
  const executable = value.records.find(({ path }) =>
    path === 'Contents/MacOS/A28Witness');
  if ((executable.mode & 0o111) === 0) reject();
  return value;
}

function measurementsFromAcceptedRecord(record, repository) {
  exactKeys(
    record,
    [
      'acceptedFiles',
      'acceptedInputPathsIncluded',
      'disclosureClassification',
      'externalPins',
      'repositorySourceManifest',
      'schemaVersion',
    ],
    'accepted-instance record',
  );
  if (record.schemaVersion !== A28_WITNESS_SCHEMA_VERSION
    || record.acceptedInputPathsIncluded !== false
    || record.disclosureClassification !== PROVISIONING_DISCLOSURE
    || !isDeepStrictEqual(record.repositorySourceManifest, repository.sourceManifest)) reject();
  exactKeys(record.acceptedFiles, ACCEPTED_FILE_KEYS, 'accepted-instance files');
  const logicalDescriptors = {};
  const accepted = {};
  for (const role of ACCEPTED_FILE_KEYS) {
    const item = record.acceptedFiles[role];
    if (role === 'witnessApplication') continue;
    exactKeys(item, ['role', 'sha256', 'size'], `accepted-instance ${role}`);
    if (item.role !== role
      || !SHA256.test(item.sha256)
      || !Number.isSafeInteger(item.size)
      || item.size < 1
      || item.size > MAX_FILE_BYTES) reject();
    logicalDescriptors[role] = Object.freeze({
      path: `/logical/${role}`,
      sha256: item.sha256,
    });
    accepted[role] = Object.freeze({
      identity: Object.freeze({ sha256: item.sha256, size: item.size }),
    });
  }
  const applicationRecord = record.acceptedFiles.witnessApplication;
  exactKeys(
    applicationRecord,
    [
      'executableSha256',
      'executableSize',
      'profileSha256',
      'role',
      'tree',
      'treeSha256',
    ],
    'accepted-instance witness application',
  );
  if (applicationRecord.role !== 'witnessApplication'
    || !SHA256.test(applicationRecord.executableSha256)
    || !SHA256.test(applicationRecord.profileSha256)
    || !SHA256.test(applicationRecord.treeSha256)
    || !Number.isSafeInteger(applicationRecord.executableSize)
    || applicationRecord.executableSize < 1
    || applicationRecord.executableSize > MAX_FILE_BYTES) reject();
  const tree = assertRecordedApplicationTree(
    applicationRecord.tree,
    applicationRecord.treeSha256,
  );
  const executable = tree.records.find(({ path }) =>
    path === 'Contents/MacOS/A28Witness');
  const profile = tree.records.find(({ path }) =>
    path === 'Contents/embedded.provisionprofile');
  if (executable?.type !== 'file'
    || executable.sha256 !== applicationRecord.executableSha256
    || executable.size !== applicationRecord.executableSize
    || profile?.type !== 'file'
    || profile.sha256 !== applicationRecord.profileSha256) reject();
  logicalDescriptors.witnessApplication = Object.freeze({
    path: '/logical/witnessApplication',
    treeSha256: applicationRecord.treeSha256,
  });
  assertProvisioningInput({
    acceptedFiles: logicalDescriptors,
    externalPins: record.externalPins,
    schemaVersion: A28_WITNESS_SCHEMA_VERSION,
  });
  comparePinnedRepositoryInputs(
    { externalPins: record.externalPins },
    repository,
  );
  if (applicationRecord.profileSha256 !== record.externalPins.profileSha256) {
    reject('A.28 provisioning embedded profile hash rejected');
  }
  return Object.freeze({
    accepted: Object.freeze(accepted),
    application: Object.freeze({
      executable: Object.freeze({
        sha256: applicationRecord.executableSha256,
        size: applicationRecord.executableSize,
      }),
      profile: Object.freeze({ sha256: applicationRecord.profileSha256 }),
      tree,
      treeSha256: applicationRecord.treeSha256,
    }),
    externalPins: record.externalPins,
    repository,
  });
}

export async function stageA28Provisioning({
  input,
  progress = (message) => {
    process.stderr.write(`[working] A.28 provisioning ${message}\n`);
  },
  repositoryRoot = REPOSITORY_ROOT,
}) {
  assertNonRoot();
  progress('materialising the path-independent provisioning plan.');
  const materialised = await materialiseA28ProvisioningStage(input, {
    progress,
    repositoryRoot,
  });
  const plan = provisioningPlan(materialised);
  await validateA28ProvisioningStage({ plan, progress, repositoryRoot });
  return plan;
}

export async function validateA28ProvisioningStage({
  plan,
  progress = (message) => {
    process.stderr.write(`[working] A.28 provisioning ${message}\n`);
  },
  repositoryRoot = REPOSITORY_ROOT,
}) {
  assertNonRoot();
  exactKeys(
    plan,
    [
      'acceptedInstanceRecord',
      'authority',
      'disclosureClassification',
      'installationManifest',
      'kind',
      'launchConfigs',
      'policyFinalisationInput',
      'receipt',
      'recipe',
      'schemaVersion',
    ],
    'plan',
  );
  if (plan.kind !== 'a28-provisioning-plan'
    || plan.disclosureClassification !== PROVISIONING_DISCLOSURE
    || plan.schemaVersion !== A28_WITNESS_SCHEMA_VERSION
    || typeof plan.recipe !== 'string'
    || plan.recipe.length < 256
    || plan.recipe.length > 16_384) reject();
  progress('rehashing the reviewed repository and validating the canonical plan.');
  const repository = await captureRepositoryInputs(repositoryRoot);
  const values = measurementsFromAcceptedRecord(
    plan.acceptedInstanceRecord,
    repository,
  );
  const expectedPlan = provisioningPlan(buildMaterialisedProvisioning(values));
  if (!isDeepStrictEqual(plan, expectedPlan)) {
    reject('A.28 provisioning plan bytes or semantics rejected');
  }
  return Object.freeze({
    acceptedInputPathsIncluded: false,
    authoritative: false,
    disclosureClassification: PROVISIONING_DISCLOSURE,
    installationManifestSha256: plan.receipt.installationManifestSha256,
    planSha256: sha256A28(canonicalA28Line(plan)),
    schemaVersion: A28_WITNESS_SCHEMA_VERSION,
    validated: true,
  });
}

function provisioningTemplate(repository) {
  const requiredFile = (role) => Object.freeze({
    path: `REQUIRED_CANONICAL_ABSOLUTE_${role.toUpperCase()}_PATH`,
    sha256: `REQUIRED_${role.toUpperCase()}_SHA256`,
  });
  return Object.freeze({
    acceptedFiles: Object.freeze({
      processInspector: requiredFile('process_inspector'),
      rootLauncher: requiredFile('signed_root_launcher'),
      rootLauncherUnsigned: requiredFile('unsigned_root_launcher'),
      rootVerifierNode: requiredFile('private_node'),
      witnessApplication: Object.freeze({
        path: 'REQUIRED_CANONICAL_ABSOLUTE_SIGNED_WITNESS_APPLICATION_PATH',
        treeSha256: 'REQUIRED_SIGNED_WITNESS_APPLICATION_TREE_SHA256',
      }),
      witnessExecutableUnsigned: requiredFile('unsigned_witness_executable'),
    }),
    externalPins: Object.freeze({
      cdHash: 'REQUIRED_WITNESS_CDHASH',
      designatedRequirement: 'REQUIRED_WITNESS_DESIGNATED_REQUIREMENT',
      hostDesignatedRequirement: 'REQUIRED_AUTOMATION_HOST_DESIGNATED_REQUIREMENT',
      hostTeamIdentifier: 'REQUIRED_AUTOMATION_HOST_TEAM_IDENTIFIER',
      minimumMacOSVersion: 'REQUIRED_MINIMUM_MACOS_VERSION',
      profileName: 'REQUIRED_DEVELOPER_ID_PROFILE_NAME',
      profileSha256: 'REQUIRED_DEVELOPER_ID_PROFILE_SHA256',
      profileUuid: 'REQUIRED_DEVELOPER_ID_PROFILE_UUID',
      repositoryToolSha256: Object.freeze(Object.fromEntries(
        Object.entries(repository.tools).map(([role, item]) => [role, item.sha256]),
      )),
      reviewerIdentity: 'REQUIRED_NAMED_REVIEWER_IDENTITY',
      rootLauncherCdHash: 'REQUIRED_ROOT_LAUNCHER_CDHASH',
      rootLauncherDesignatedRequirement:
        'REQUIRED_ROOT_LAUNCHER_DESIGNATED_REQUIREMENT',
      runnerBundleIdentifier: 'REQUIRED_AUTHENTICATED_RUNNER_BUNDLE_IDENTIFIER',
      runnerDesignatedRequirement:
        'REQUIRED_AUTHENTICATED_RUNNER_DESIGNATED_REQUIREMENT',
      runnerTeamIdentifier: 'REQUIRED_AUTHENTICATED_RUNNER_TEAM_IDENTIFIER',
      signingCertificateSha256: 'REQUIRED_DEVELOPER_ID_CERTIFICATE_SHA256',
      signingIdentity: 'REQUIRED_DEVELOPER_ID_APPLICATION_IDENTITY',
      sourceSha256: repository.sourceSha256,
      teamIdentifier: 'REQUIRED_DEVELOPER_TEAM_IDENTIFIER',
      voiceOverDesignatedRequirement: 'REQUIRED_VOICEOVER_DESIGNATED_REQUIREMENT',
      witnessGid: 'REQUIRED_REVIEWER_GID',
      witnessHomeDirectory: 'REQUIRED_REVIEWER_HOME_DIRECTORY',
      witnessTargetDev: 'REQUIRED_FINAL_INSTALLED_WITNESS_DEVICE',
      witnessTargetIno: 'REQUIRED_FINAL_INSTALLED_WITNESS_INODE',
      witnessUid: 'REQUIRED_REVIEWER_UID',
      witnessUsername: 'REQUIRED_REVIEWER_USERNAME',
    }),
    schemaVersion: A28_WITNESS_SCHEMA_VERSION,
  });
}

export async function createA28ProvisioningInputTemplate({
  repositoryRoot = REPOSITORY_ROOT,
} = {}) {
  assertNonRoot();
  const repository = await captureRepositoryInputs(repositoryRoot);
  return provisioningTemplate(repository);
}

export async function stageA28ProvisioningTemplate({
  progress = (message) => {
    process.stderr.write(`[working] A.28 provisioning ${message}\n`);
  },
  repositoryRoot = REPOSITORY_ROOT,
} = {}) {
  assertNonRoot();
  progress('hashing the reviewed repository sources for the input template.');
  const repository = await captureRepositoryInputs(repositoryRoot);
  const template = provisioningTemplate(repository);
  const requirements = Object.freeze({
    acceptedInputPathsIncluded: false,
    authoritative: false,
    credentialsAccessed: false,
    disclosureClassification: PROVISIONING_DISCLOSURE,
    installationRoot: SUPPORT_ROOT,
    metadataPolicy: Object.freeze({
      bsdFlags: 0,
      extendedAclEntries: 0,
      xattrs: Object.freeze([]),
    }),
    requiredAncestors: buildRequiredAncestorPolicy(),
    requiredDirectoryModes: Object.freeze([0o700, 0o755]),
    requiredFileModes: Object.freeze([0o400, 0o444, 0o500, 0o555]),
    requiredOwner: Object.freeze({ gid: 0, uid: 0 }),
    schemaVersion: A28_WITNESS_SCHEMA_VERSION,
    sourceManifest: repository.sourceManifest,
    sourceSha256: repository.sourceSha256,
    workflow:
      'template-build-measure-exclusive-app-preinstall-plan-validate-support-install-enrol-finalise-policy',
  });
  return Object.freeze({
    acceptedInputPathsIncluded: false,
    authoritative: false,
    credentialsAccessed: false,
    disclosureClassification: PROVISIONING_DISCLOSURE,
    installationPerformed: false,
    kind: 'a28-provisioning-input-template',
    requirements,
    schemaVersion: A28_WITNESS_SCHEMA_VERSION,
    template,
  });
}

function parseArguments(argv) {
  const command = argv[0];
  const values = {};
  for (let index = 1; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (value === undefined
      || !['--application', '--input'].includes(key)
      || Object.hasOwn(values, key)) reject();
    values[key] = value;
  }
  if (command === 'template'
    && Object.keys(values).length === 0) {
    return Object.freeze({ command });
  }
  if (command === 'stage'
    && isDeepStrictEqual(Object.keys(values).sort(), ['--input'])) {
    assertAbsoluteCanonicalInputPath(values['--input']);
    return Object.freeze({
      command,
      inputPath: values['--input'],
    });
  }
  if (command === 'validate'
    && isDeepStrictEqual(Object.keys(values).sort(), ['--input'])) {
    assertAbsoluteCanonicalInputPath(values['--input']);
    return Object.freeze({ command, inputPath: values['--input'] });
  }
  if (command === 'measure-application'
    && isDeepStrictEqual(Object.keys(values).sort(), ['--application'])) {
    assertAbsoluteCanonicalInputPath(values['--application']);
    return Object.freeze({
      applicationPath: values['--application'],
      command,
    });
  }
  reject('A.28 provisioning arguments rejected');
}

async function main() {
  const arguments_ = parseArguments(process.argv.slice(2));
  let result;
  if (arguments_.command === 'template') {
    result = await stageA28ProvisioningTemplate();
  } else if (arguments_.command === 'stage') {
    const inputFile = await readCanonicalInput(arguments_.inputPath);
    result = await stageA28Provisioning({
      input: inputFile.value,
    });
  } else if (arguments_.command === 'validate') {
    const planFile = await readCanonicalInput(arguments_.inputPath);
    result = await validateA28ProvisioningStage({
      plan: planFile.value,
    });
  } else {
    process.stderr.write(
      '[working] A.28 provisioning measuring the accepted application tree.\n',
    );
    result = await measureA28AcceptedApplicationTree(
      arguments_.applicationPath,
    );
  }
  process.stdout.write(canonicalA28Line(result));
}

const invokedPath = process.argv[1] === undefined
  ? undefined
  : resolve(process.argv[1]);
if (invokedPath !== undefined && fileURLToPath(import.meta.url) === invokedPath) {
  main().catch((error) => {
    process.stderr.write(`A.28 provisioning stage failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
