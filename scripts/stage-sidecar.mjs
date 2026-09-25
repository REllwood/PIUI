import { createHash } from 'node:crypto';
import {
  constants,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  lstatSync,
  realpathSync,
  writeSync,
} from 'node:fs';
import {
  chmod,
  cp,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { acquireOwnedLock, releaseOwnedLock } from './a21-gate-support.mjs';
import {
  isForbiddenDocumentationDirectoryPath,
  isForbiddenDocumentationFile,
  isForbiddenDocumentationPath,
} from './sidecar-closure-policy.mjs';
import {
  prepareCandidateForRename,
  assertSidecarCandidateLease,
  captureSidecarCandidateLease,
  sealPublishedOutput,
} from './sidecar-publication-policy.mjs';
import {
  assertHeldEmptyDirectoryPlaceholder,
  assertHeldPathHasNoAcl,
  assertHeldTreeHasNoAcl,
  beginExclusiveRenameCompilerSession,
  endExclusiveRenameCompilerSession,
  exclusiveDirectoryRename,
  rewriteHeldRegularFile,
} from './exclusive-rename.mjs';
import {
  assertSidecarDeploymentMatchesReceipt,
  readHeldSidecarDeploymentReceipt,
} from './sidecar-deployment-witness.mjs';
import {
  captureSystemDescriptorAclInspector,
  removeDescriptorBoundTree,
} from './descriptor-acl.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cacheRoot = resolve(root, '.cache');
const output = resolve(root, 'src-tauri/resources/sidecar');
const lockPath = resolve(cacheRoot, 'sidecar-stage.lock');
const a25FixtureOutput = resolve(root, 'src-tauri/target/a25-sidecar-fixture');
const A25_FIXTURE_FILES = Object.freeze([
  'package.json',
  'spike/approval-entry.js',
  'spike/approval-matrix.js',
  'spike/approval-probes.js',
]);
const A25_FIXTURE_PACKAGE = `${JSON.stringify({
  name: '@piui/a25-approval-fixture',
  private: true,
  type: 'module',
  version: '0.0.0',
}, null, 2)}\n`;
const A25_COMPILED_PREFIXES = Object.freeze([
  'spike/approval-entry.',
  'spike/approval-matrix.',
  'spike/approval-probes.',
]);
const CONTROLLED_FINALISATION_PHASES = Object.freeze(new Set([
  'entry',
  'transaction-validation',
  'resource-preparation',
  'workspace-validation',
  'receipt-read',
  'finalisation-authority-acquisition',
  'receipt-validate-before-copy',
  'deployment-copy',
  'receipt-validate-after-copy',
  'importer-read',
  'a25-fixture',
  'sidecar-copy',
  'fixture-copy',
  'protocol-copy',
  'protocol-target-create',
  'protocol-dist-copy',
  'protocol-schema-copy',
  'protocol-package-write',
  'importer-package-write',
  'closure-prune',
  'closure-validation',
  'manifest-build',
  'candidate-seal',
  'publication-preparation',
  'prior-output-retire',
  'candidate-publish',
  'workspace-cleanup-phase-write',
  'workspace-cleanup-authority-validation',
  'workspace-cleanup-temporary-lease',
  'workspace-cleanup-workspace-lease',
  'workspace-cleanup-tree-unlock',
  'workspace-cleanup-post-unlock-lease-validation',
  'workspace-cleanup-inspector-capture',
  'workspace-cleanup-descriptor-bound-removal',
  'workspace-cleanup-path-absence',
  'workspace-cleanup-compiler-authority-release',
  'workspace-cleanup-descriptor-releases',
  'workspace-cleanup-final-progress-write',
  'complete',
]));
let lockOwnership;
let workspace;
let workspaceCleanupLease;
let workspaceCleanupAuthorised = false;
let temporaryCleanupLease;
let helperRootLease;
let helperWorkspaceParent;
let controlledProgressIdentity;
let controlledFailure;
let exclusiveRenameCompilerSession;
const controlledMode = process.argv[2];
const controlledWorkspaceArgument = process.argv[3];
const controlledLockFdArgument = process.argv[4];
const controlledLockFd = parseControlledDescriptor(controlledLockFdArgument);
const controlledReceiptFdArgument = process.argv[5];
const controlledReceiptFd = parseControlledDescriptor(controlledReceiptFdArgument);
const controlledReceiptSha256 = process.argv[6];
const controlledProgressFdArgument = process.argv[7];
const controlledProgressFd = parseControlledDescriptor(controlledProgressFdArgument);
const controlledFinalise = controlledMode === '--finalise-controlled';
if ((controlledMode === undefined) !== (controlledWorkspaceArgument === undefined)
  || (controlledMode !== undefined
    && !['--prepare-controlled', '--finalise-controlled'].includes(controlledMode))
  || (controlledMode === undefined && controlledLockFdArgument !== undefined)
  || (controlledMode !== undefined && controlledLockFd === undefined)
  || (controlledFinalise
    ? (controlledReceiptFd === undefined
      || controlledReceiptFd === controlledLockFd
      || controlledProgressFd === undefined
      || controlledProgressFd === controlledLockFd
      || controlledProgressFd === controlledReceiptFd
      || !/^[0-9a-f]{64}$/u.test(controlledReceiptSha256 ?? '')
      || process.argv.length !== 8)
    : (controlledReceiptFdArgument !== undefined
      || controlledReceiptSha256 !== undefined
      || controlledProgressFdArgument !== undefined
      || process.argv.length !== (controlledMode === undefined ? 2 : 5)))) {
  throw new Error('Sidecar staging arguments are invalid');
}
try {
  if (controlledFinalise) {
    assertControlledProgressDescriptor(controlledProgressFd);
    setControlledFinalisationPhase('entry');
    setControlledFinalisationPhase('transaction-validation');
  }
  if (controlledMode) {
    assertControlledLockDescriptor(controlledLockFd);
  } else {
    await mkdir(cacheRoot, { recursive: true });
    lockOwnership = await acquireOwnedLock(lockPath, { timeoutMs: 120_000, label: 'Sidecar staging lock' });
  }
  if (controlledFinalise) setControlledFinalisationPhase('resource-preparation');
  await unlockTauriResourceCopies();
  await quarantineLegacyDeployment(Boolean(controlledMode));
  if (controlledMode) {
    if (controlledFinalise) setControlledFinalisationPhase('workspace-validation');
    workspace = await controlledWorkspace(controlledWorkspaceArgument, controlledMode);
    if (controlledMode === '--prepare-controlled') {
      await prepareDeployment(workspace);
      console.log(`Prepared controlled sidecar deployment at ${workspace}`);
      workspace = undefined;
    } else {
      const deployment = resolve(workspace, 'deployment');
      setControlledFinalisationPhase('receipt-read');
      const receipt = readHeldSidecarDeploymentReceipt({
        descriptor: controlledReceiptFd,
        expectedRoot: deployment,
        receiptSha256: controlledReceiptSha256,
      });
      await finaliseDeployment(workspace, receipt);
    }
  } else {
    const temporary = await realpath(resolve(process.env.TMPDIR || tmpdir()));
    workspace = await mkdtemp(resolve(temporary, 'piui-sidecar-stage-'));
    await acquireFinalisationRootLeases(workspace);
    const result = runPnpm(['--filter', '@piui/sidecar', 'build']);
    if (result.status !== 0) throw new Error('Sidecar build failed');
    await prepareDeployment(workspace);
    const install = runPnpm(sidecarInstallArguments(resolve(workspace, 'deployment')));
    if (install.status !== 0) throw new Error('Isolated production dependency installation failed');
    await finaliseDeployment(workspace);
  }
} catch (error) {
  controlledFailure = error;
  throw error;
} finally {
  const cleanupFailures = [];
  const trackCleanupPhase = controlledFinalise && !controlledFailure;
  let cleanupPhaseLocked = false;
  const recordCleanupFailure = (error) => {
    cleanupFailures.push(error);
    cleanupPhaseLocked = true;
  };
  const setCleanupPhase = (phase) => {
    if (!trackCleanupPhase || cleanupPhaseLocked) return;
    try {
      setControlledFinalisationPhase(phase);
    } catch (error) {
      recordCleanupFailure(error);
    }
  };
  setCleanupPhase('workspace-cleanup-phase-write');
  if (workspace) {
    setCleanupPhase('workspace-cleanup-authority-validation');
    if (!workspaceCleanupAuthorised || !workspaceCleanupLease || !temporaryCleanupLease) {
      recordCleanupFailure(new Error('Sidecar staging workspace cleanup authority is unavailable'));
    } else {
      try {
        await cleanHeldWorkspaceMandatory(
          workspaceCleanupLease,
          temporaryCleanupLease,
          setCleanupPhase,
        );
      } catch (error) {
        recordCleanupFailure(error);
      }
    }
  }
  setCleanupPhase('workspace-cleanup-compiler-authority-release');
  if (exclusiveRenameCompilerSession) {
    const compilerSession = exclusiveRenameCompilerSession;
    exclusiveRenameCompilerSession = undefined;
    try { endExclusiveRenameCompilerSession(compilerSession); } catch (error) {
      recordCleanupFailure(error);
    }
  }
  setCleanupPhase('workspace-cleanup-descriptor-releases');
  for (const lease of [workspaceCleanupLease, temporaryCleanupLease, helperRootLease]) {
    if (!lease) continue;
    try { await lease.handle.close(); } catch (error) { recordCleanupFailure(error); }
  }
  if (lockOwnership) {
    try { await releaseOwnedLock(lockOwnership); } catch (error) { recordCleanupFailure(error); }
  }
  if (cleanupFailures.length) {
    throw new AggregateError(
      controlledFailure ? [controlledFailure, ...cleanupFailures] : cleanupFailures,
      'Sidecar staging cleanup failed',
    );
  }
  if (controlledFinalise && !controlledFailure) {
    setControlledFinalisationPhase('workspace-cleanup-final-progress-write');
    setControlledFinalisationPhase('complete');
  }
}

function parseControlledDescriptor(value) {
  if (!/^(?:[3-9]|[1-9][0-9]{1,2})$/u.test(value ?? '')) return undefined;
  const descriptor = Number(value);
  return descriptor <= 255 ? descriptor : undefined;
}

function sameDescriptorIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.uid === right.uid
    && left.gid === right.gid
    && left.nlink === right.nlink
    && left.isFile() === right.isFile();
}

function sameFileState(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
    && left.isFile() === right.isFile();
}

function sameHeldObject(left, right, kind) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.uid === right.uid
    && left.gid === right.gid
    && (kind === 'directory'
      ? left.isDirectory() && (right.kind === 'directory' || right.isDirectory?.())
      : left.isFile() && (right.kind === 'file' || right.isFile?.()) && left.nlink === 1n);
}

function sameHeldPathState(left, right, kind, mutableDirectory) {
  return mutableDirectory && kind === 'directory'
    ? sameHeldObject(left, right, kind) && left.mode === right.mode
    : sameFileState(left, right);
}

function currentUid() {
  if (typeof process.getuid !== 'function' || typeof process.geteuid !== 'function'
    || process.getuid() !== process.geteuid()) {
    throw new Error('Sidecar filesystem authority is unavailable');
  }
  return BigInt(process.getuid());
}

function assertSafeHeldState(state, kind, modes, label) {
  const mode = state.mode & 0o777n;
  if (state.uid !== currentUid() || state.isSymbolicLink()
    || (state.mode & 0o022n) !== 0n
    || (kind === 'directory'
      ? !state.isDirectory()
      : (!state.isFile() || state.nlink !== 1n))
    || (modes && !modes.includes(mode))) {
    throw new Error(`${label} is unsafe`);
  }
}

async function acquireHeldPathLease(path, kind, {
  helperParent,
  label,
  modes,
  mutableDirectory = false,
} = {}) {
  if (mutableDirectory && kind !== 'directory') {
    throw new Error(`${label} mutable lease kind is invalid`);
  }
  if (typeof path !== 'string' || resolve(path) !== path || await realpath(path) !== path) {
    throw new Error(`${label} path is not canonical`);
  }
  const pathname = await lstat(path, { bigint: true });
  assertSafeHeldState(pathname, kind, modes, label);
  const handle = await open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC
      | (kind === 'directory' ? constants.O_DIRECTORY : 0),
  );
  let accepted = false;
  try {
    const held = await handle.stat({ bigint: true });
    const rebound = await lstat(path, { bigint: true });
    assertSafeHeldState(held, kind, modes, label);
    if (!sameHeldPathState(pathname, held, kind, mutableDirectory)
      || !sameHeldPathState(held, rebound, kind, mutableDirectory)
      || await realpath(path) !== path) {
      throw new Error(`${label} identity changed during acquisition`);
    }
    assertHeldPathHasNoAcl({
      compilerSession: exclusiveRenameCompilerSession,
      fd: handle.fd,
      helperWorkspaceParent: helperParent,
      identity: held,
      kind: mutableDirectory ? 'mutable-directory' : kind,
      path,
    });
    const afterInspection = await handle.stat({ bigint: true });
    const pathAfterInspection = await lstat(path, { bigint: true });
    if (!sameHeldPathState(afterInspection, pathAfterInspection, kind, mutableDirectory)
      || !sameHeldObject(held, afterInspection, kind)
      || (!mutableDirectory && !sameFileState(held, afterInspection))
      || await realpath(path) !== path) {
      throw new Error(`${label} changed during ACL inspection`);
    }
    accepted = true;
    return Object.freeze({
      handle,
      identity: Object.freeze({
        dev: held.dev,
        gid: held.gid,
        ino: held.ino,
        kind,
        uid: held.uid,
      }),
      kind,
      label,
      modes,
      mutableDirectory,
      path,
    });
  } finally {
    if (!accepted) await handle.close();
  }
}

async function assertHeldPathLease(lease, {
  modes = lease.modes,
  path = lease.path,
} = {}) {
  if (!lease || typeof path !== 'string' || resolve(path) !== path
    || await realpath(path) !== path) {
    throw new Error(`${lease?.label ?? 'Sidecar filesystem lease'} path changed`);
  }
  const held = await lease.handle.stat({ bigint: true });
  const pathname = await lstat(path, { bigint: true });
  assertSafeHeldState(held, lease.kind, modes, lease.label);
  if (!sameHeldObject(held, lease.identity, lease.kind)
    || !sameHeldPathState(held, pathname, lease.kind, lease.mutableDirectory)) {
    throw new Error(`${lease.label} identity changed while held`);
  }
  assertHeldPathHasNoAcl({
    compilerSession: exclusiveRenameCompilerSession,
    fd: lease.handle.fd,
    helperWorkspaceParent,
    identity: held,
    kind: lease.mutableDirectory ? 'mutable-directory' : lease.kind,
    path,
  });
  const afterInspection = await lease.handle.stat({ bigint: true });
  const pathAfterInspection = await lstat(path, { bigint: true });
  if (!sameHeldPathState(
    afterInspection,
    pathAfterInspection,
    lease.kind,
    lease.mutableDirectory,
  )
    || !sameHeldObject(held, afterInspection, lease.kind)
    || (!lease.mutableDirectory && !sameFileState(held, afterInspection))
    || await realpath(path) !== path) {
    throw new Error(`${lease.label} changed during ACL inspection`);
  }
  return afterInspection;
}

async function readHeldFileBytes(lease, path, maximumBytes = 1024 * 1024) {
  const before = await assertHeldPathLease(lease, { path });
  if (before.size < 1n || before.size > BigInt(maximumBytes)) {
    throw new Error(`${lease.label} size is invalid`);
  }
  const bytes = Buffer.alloc(Number(before.size));
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesRead } = await lease.handle.read(bytes, offset, bytes.length - offset, offset);
    if (bytesRead < 1) throw new Error(`${lease.label} read was incomplete`);
    offset += bytesRead;
  }
  const after = await assertHeldPathLease(lease, { path });
  if (!sameFileState(before, after)) throw new Error(`${lease.label} changed while read`);
  return bytes;
}

async function readHeldUtf8File(lease, path, maximumBytes = 1024 * 1024) {
  return (await readHeldFileBytes(lease, path, maximumBytes)).toString('utf8');
}

async function rewritePreparedImporterPackage(parentLease, importerLease, path, bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1) {
    throw new Error('Prepared sidecar importer package bytes are invalid');
  }
  const parentState = await assertHeldPathLease(parentLease);
  const importerState = await assertHeldPathLease(importerLease, {
    modes: [0o400n, 0o600n, 0o644n],
    path,
  });
  rewriteHeldRegularFile({
    bytes,
    compilerSession: exclusiveRenameCompilerSession,
    fileFd: importerLease.handle.fd,
    fileIdentity: importerState,
    helperWorkspaceParent,
    name: 'package.json',
    parentFd: parentLease.handle.fd,
    parentIdentity: parentState,
    parentPath: parentLease.path,
  });
  const written = await assertHeldPathLease(importerLease, {
    modes: [0o600n],
    path,
  });
  if (written.size !== BigInt(bytes.length)) {
    throw new Error('Prepared sidecar importer package rewrite was incomplete');
  }
  const stored = await readHeldFileBytes(importerLease, path);
  if (!stored.equals(bytes)) {
    throw new Error('Prepared sidecar importer package bytes changed during rewrite');
  }
  await assertHeldPathLease(parentLease);
}

function assertControlledProgressState(state) {
  if (!state.isFile()
    || state.isSymbolicLink()
    || state.nlink !== 1
    || state.uid !== process.getuid()
    || (state.mode & 0o777) !== 0o600) {
    throw new Error('Controlled sidecar finalisation progress descriptor is invalid');
  }
}

function assertControlledProgressDescriptor(descriptor) {
  const held = fstatSync(descriptor);
  assertControlledProgressState(held);
  if (held.size !== 0) {
    throw new Error('Controlled sidecar finalisation progress descriptor is not fresh');
  }
  controlledProgressIdentity = held;
}

function setControlledFinalisationPhase(phase) {
  if (!controlledFinalise) return;
  if (!CONTROLLED_FINALISATION_PHASES.has(phase) || !controlledProgressIdentity) {
    throw new Error('Controlled sidecar finalisation progress phase is invalid');
  }
  const before = fstatSync(controlledProgressFd);
  assertControlledProgressState(before);
  if (!sameDescriptorIdentity(controlledProgressIdentity, before)) {
    throw new Error('Controlled sidecar finalisation progress descriptor changed');
  }
  const bytes = Buffer.from(`PIUI_SIDECAR_FINALISATION_PHASE=${phase}\n`, 'utf8');
  ftruncateSync(controlledProgressFd, 0);
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(
      controlledProgressFd,
      bytes,
      offset,
      bytes.length - offset,
      offset,
    );
    if (written < 1) throw new Error('Controlled sidecar finalisation progress write failed');
    offset += written;
  }
  fsyncSync(controlledProgressFd);
  const after = fstatSync(controlledProgressFd);
  assertControlledProgressState(after);
  if (!sameDescriptorIdentity(controlledProgressIdentity, after) || after.size !== bytes.length) {
    throw new Error('Controlled sidecar finalisation progress descriptor changed');
  }
}

function assertControlledLockDescriptor(descriptor) {
  const held = fstatSync(descriptor);
  const pathname = lstatSync(lockPath);
  if (!held.isFile()
    || held.isSymbolicLink()
    || held.nlink !== 1
    || held.uid !== process.getuid()
    || (held.mode & 0o077) !== 0
    || pathname.isSymbolicLink()
    || held.dev !== pathname.dev
    || held.ino !== pathname.ino
    || realpathSync(lockPath) !== lockPath) {
    throw new Error('Controlled sidecar transaction lock is invalid');
  }
}

async function controlledWorkspace(path, mode) {
  if (typeof path !== 'string' || !path.startsWith('/') || resolve(path) !== path) {
    throw new Error('Controlled sidecar workspace is invalid');
  }
  const temporary = await realpath(resolve(process.env.TMPDIR || tmpdir()));
  const canonical = await realpath(path);
  const state = await lstat(canonical);
  if (canonical !== path
    || dirname(canonical) !== temporary
    || !canonical.startsWith(`${temporary}/piui-sidecar-stage-control-`)
    || state.isSymbolicLink()
    || !state.isDirectory()
    || state.uid !== process.getuid()
    || (state.mode & 0o777) !== 0o700) {
    throw new Error('Controlled sidecar workspace is unsafe');
  }
  const entries = (await readdir(canonical)).sort();
  if (mode === '--prepare-controlled' && entries.length !== 0) {
    throw new Error('Controlled sidecar workspace is not fresh');
  }
  if (mode === '--finalise-controlled'
    && JSON.stringify(entries) !== JSON.stringify(['deployment'])) {
    throw new Error('Controlled sidecar workspace is incomplete');
  }
  return canonical;
}

function sidecarInstallArguments(deployment) {
  return [
    '--dir',
    deployment,
    '--config.node-linker=hoisted',
    ...(process.env.PIUI_PNPM_STORE ? [`--store-dir=${process.env.PIUI_PNPM_STORE}`] : []),
    'install',
    '--prod',
    '--ignore-workspace',
    '--frozen-lockfile',
    '--ignore-scripts',
    ...(process.env.PIUI_PNPM_OFFLINE === '1' ? ['--offline'] : []),
  ];
}

async function prepareDeployment(stagingWorkspace) {
  const deployment = resolve(stagingWorkspace, 'deployment');
  await mkdir(deployment, { mode: 0o700 });
  const productionImporter = resolve(root, 'sidecar/production');
  await cp(resolve(productionImporter, 'package.json'), resolve(deployment, 'package.json'));
  await cp(resolve(productionImporter, 'pnpm-lock.yaml'), resolve(deployment, 'pnpm-lock.yaml'));
}

async function prepareHelperWorkspaceParent() {
  const target = resolve(root, 'src-tauri/target');
  await mkdir(target, { recursive: true });
  if (await realpath(target) !== target) {
    throw new Error('Sidecar helper target path is not canonical');
  }
  const targetState = await lstat(target, { bigint: true });
  assertSafeHeldState(targetState, 'directory', undefined, 'Sidecar helper target');
  const requested = resolve(target, 'piui-sidecar-helper');
  try {
    await mkdir(requested, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  if (await realpath(requested) !== requested) {
    throw new Error('Sidecar helper workspace path is not canonical');
  }
  const state = await lstat(requested, { bigint: true });
  assertSafeHeldState(state, 'directory', [0o700n], 'Sidecar helper workspace');
  if (exclusiveRenameCompilerSession) {
    throw new Error('Sidecar helper compiler session is already active');
  }
  exclusiveRenameCompilerSession = beginExclusiveRenameCompilerSession();
  helperWorkspaceParent = requested;
  helperRootLease = await acquireHeldPathLease(requested, 'directory', {
    helperParent: requested,
    label: 'Sidecar helper workspace',
    modes: [0o700n],
    mutableDirectory: true,
  });
}

async function acquireFinalisationRootLeases(stagingWorkspace) {
  if (workspaceCleanupLease || temporaryCleanupLease || helperRootLease) {
    if (!workspaceCleanupLease || !temporaryCleanupLease || !helperRootLease
      || workspaceCleanupLease.path !== stagingWorkspace) {
      throw new Error('Sidecar finalisation root leases are inconsistent');
    }
    await assertHeldPathLease(helperRootLease);
    await assertHeldPathLease(temporaryCleanupLease);
    await assertHeldPathLease(workspaceCleanupLease);
    return;
  }
  await prepareHelperWorkspaceParent();
  const temporary = await realpath(resolve(process.env.TMPDIR || tmpdir()));
  const canonicalWorkspace = await realpath(stagingWorkspace);
  if (canonicalWorkspace !== stagingWorkspace || dirname(canonicalWorkspace) !== temporary) {
    throw new Error('Sidecar finalisation workspace is outside its canonical temporary directory');
  }
  temporaryCleanupLease = await acquireHeldPathLease(temporary, 'directory', {
    helperParent: helperWorkspaceParent,
    label: 'Sidecar temporary directory',
    modes: [0o700n],
    mutableDirectory: true,
  });
  workspaceCleanupLease = await acquireHeldPathLease(stagingWorkspace, 'directory', {
    helperParent: helperWorkspaceParent,
    label: 'Sidecar finalisation workspace',
    modes: [0o700n],
  });
  workspaceCleanupAuthorised = true;
  await assertHeldPathLease(helperRootLease);
  await assertHeldPathLease(temporaryCleanupLease);
  await assertHeldPathLease(workspaceCleanupLease);
}

async function assertPathMissing(path, label) {
  try {
    await lstat(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  throw new Error(`${label} already exists`);
}

function receiptMatchesDirectory(receipt, destination, state) {
  return receipt?.operationCompleted === true
    && receipt.destination === destination
    && receipt.destinationIdentity?.dev === state.dev
    && receipt.destinationIdentity?.ino === state.ino
    && receipt.destinationIdentity?.uid === state.uid
    && receipt.destinationIdentity?.gid === state.gid
    && receipt.destinationIdentity?.mode === state.mode;
}

async function moveHeldDirectory(
  lease,
  source,
  destination,
  sourceParentLease,
  destinationParentLease,
  { sourcePolicy = 'private-directory' } = {},
) {
  const sourceState = await assertHeldPathLease(lease, {
    modes: [0o700n],
    path: source,
  });
  const sourceParentState = await assertHeldPathLease(sourceParentLease);
  const destinationParentState = await assertHeldPathLease(destinationParentLease);
  if (sourceState.dev !== sourceParentState.dev || sourceState.dev !== destinationParentState.dev) {
    throw new Error(`${lease.label} cannot be moved across filesystems`);
  }
  await assertPathMissing(destination, `${lease.label} destination`);
  let receipt;
  let finalisationError;
  try {
    receipt = exclusiveDirectoryRename(source, destination, {
      compilerSession: exclusiveRenameCompilerSession,
      expectedDestinationParentIdentity: destinationParentState,
      expectedSourceIdentity: sourceState,
      expectedSourceParentIdentity: sourceParentState,
      helperWorkspaceParent,
      sourcePolicy,
    });
  } catch (error) {
    if (!error?.operationCompleted || !error.receipt) throw error;
    receipt = error.receipt;
    finalisationError = error;
  }
  if (!receiptMatchesDirectory(receipt, destination, sourceState)) {
    throw new Error(`${lease.label} exclusive rename receipt is invalid`);
  }
  await assertPathMissing(source, `${lease.label} source`);
  await assertHeldPathLease(lease, { modes: [0o700n], path: destination });
  await assertHeldPathLease(sourceParentLease);
  await assertHeldPathLease(destinationParentLease);
  return Object.freeze({ finalisationError, receipt });
}

async function locateHeldDirectoryLease(lease, candidates) {
  const matches = [];
  for (const path of candidates) {
    let pathname;
    try {
      pathname = await lstat(path, { bigint: true });
    } catch (error) {
      if (error?.code === 'ENOENT') continue;
      throw error;
    }
    if (pathname.dev !== lease.identity.dev || pathname.ino !== lease.identity.ino
      || pathname.uid !== lease.identity.uid || pathname.gid !== lease.identity.gid
      || !pathname.isDirectory() || pathname.isSymbolicLink()) {
      continue;
    }
    await assertHeldPathLease(lease, {
      modes: [0o700n, 0o555n],
      path,
    });
    matches.push(path);
  }
  if (matches.length !== 1) {
    throw new Error(`${lease.label} could not be located exactly once`);
  }
  return matches[0];
}

async function assertHeldTreeLeaseHasNoAcl(lease, path, modes = lease.modes) {
  const state = await assertHeldPathLease(lease, { modes, path });
  assertHeldTreeHasNoAcl({
    compilerSession: exclusiveRenameCompilerSession,
    fd: lease.handle.fd,
    helperWorkspaceParent,
    identity: state,
    path,
  });
}

async function assertHeldResetPlaceholder(lease, path) {
  const state = await assertHeldPathLease(lease, { modes: [0o700n], path });
  assertHeldEmptyDirectoryPlaceholder({
    compilerSession: exclusiveRenameCompilerSession,
    fd: lease.handle.fd,
    helperWorkspaceParent,
    identity: state,
    path,
  });
  return assertHeldPathLease(lease, { modes: [0o700n], path });
}

async function sealHeldPublication(lease, path, candidateLease) {
  await assertHeldPathLease(lease, { modes: [0o700n], path });
  await sealPublishedOutput(path, {
    candidateLease,
    heldRootFd: lease.handle.fd,
    helperWorkspaceParent,
  });
  await assertHeldPathLease(lease, { modes: [0o555n], path });
  await assertHeldTreeLeaseHasNoAcl(lease, path, [0o555n]);
}

async function finaliseDeployment(stagingWorkspace, controlledReceipt) {
  const deployment = resolve(stagingWorkspace, 'deployment');
  const prepared = resolve(stagingWorkspace, 'prepared');
  const importerPath = resolve(prepared, 'package.json');
  let importerLease;
  let outputParentLease;
  let preparedLease;
  let priorCandidateLease;
  let priorOutputLease;
  let transactionFailure;
  const descriptorFailures = [];
  setControlledFinalisationPhase('finalisation-authority-acquisition');
  await acquireFinalisationRootLeases(stagingWorkspace);
  try {
  if (controlledReceipt) {
    setControlledFinalisationPhase('receipt-validate-before-copy');
    await assertSidecarDeploymentMatchesReceipt(deployment, controlledReceipt.bytes);
  }
  setControlledFinalisationPhase('deployment-copy');
  await cp(deployment, prepared, { recursive: true, dereference: true });
  await chmod(prepared, 0o700);
  preparedLease = await acquireHeldPathLease(prepared, 'directory', {
    helperParent: helperWorkspaceParent,
    label: 'Prepared sidecar candidate',
    modes: [0o700n],
  });
  await assertHeldPathLease(workspaceCleanupLease);
  if (controlledReceipt) {
    setControlledFinalisationPhase('receipt-validate-after-copy');
    await assertSidecarDeploymentMatchesReceipt(deployment, controlledReceipt.bytes);
  }
  setControlledFinalisationPhase('importer-read');
  importerLease = await acquireHeldPathLease(importerPath, 'file', {
    helperParent: helperWorkspaceParent,
    label: 'Prepared sidecar importer package',
    modes: [0o400n, 0o600n, 0o644n],
  });
  const importerPackage = JSON.parse(await readHeldUtf8File(importerLease, importerPath));
  setControlledFinalisationPhase('a25-fixture');
  await publishA25Fixture();
  const compiledSidecar = resolve(root, 'sidecar/dist');
  setControlledFinalisationPhase('sidecar-copy');
  await cp(compiledSidecar, resolve(prepared, 'dist'), {
    recursive: true,
    filter: (source) => {
      const candidate = relative(compiledSidecar, source).split('\\').join('/');
      return !A25_COMPILED_PREFIXES.some((prefix) => candidate.startsWith(prefix));
    },
  });
  setControlledFinalisationPhase('fixture-copy');
  const packagedFixtureDirectory = resolve(prepared, 'fixture');
  await mkdir(packagedFixtureDirectory, { recursive: true });
  await cp(
    resolve(root, 'tests/fixtures/pi-sessions/active-branch-v3.jsonl'),
    resolve(packagedFixtureDirectory, 'active-branch-v3.jsonl'),
  );
  setControlledFinalisationPhase('protocol-copy');
  const protocolTarget = resolve(prepared, 'node_modules/@piui/protocol');
  setControlledFinalisationPhase('protocol-target-create');
  await mkdir(protocolTarget, { recursive: true });
  setControlledFinalisationPhase('protocol-dist-copy');
  await cp(resolve(root, 'packages/protocol/dist'), resolve(protocolTarget, 'dist'), { recursive: true });
  setControlledFinalisationPhase('protocol-schema-copy');
  await cp(resolve(root, 'packages/protocol/schema'), resolve(protocolTarget, 'schema'), { recursive: true });
  setControlledFinalisationPhase('protocol-package-write');
  await writeFile(
    resolve(protocolTarget, 'package.json'),
    `${JSON.stringify({
      name: '@piui/protocol',
      version: '0.1.0',
      type: 'module',
      main: './dist/index.js',
      exports: {
        '.': './dist/index.js',
        './codec': './dist/codec.js',
      },
    }, null, 2)}\n`,
  );
  importerPackage.dependencies['@piui/protocol'] = '0.1.0';
  setControlledFinalisationPhase('importer-package-write');
  await rewritePreparedImporterPackage(
    preparedLease,
    importerLease,
    importerPath,
    Buffer.from(`${JSON.stringify(importerPackage, null, 2)}\n`, 'utf8'),
  );
  setControlledFinalisationPhase('closure-prune');
  await prune(prepared);
  setControlledFinalisationPhase('closure-validation');
  await validateProductionClosure(prepared);
  setControlledFinalisationPhase('manifest-build');
  const all = await files(prepared, prepared);
  all.sort((left, right) => Buffer.from(relative(prepared, left)).compare(Buffer.from(relative(prepared, right))));
  const manifest = [];
  for (const path of all) {
    const data = await readFile(path);
    manifest.push({
      path: relative(prepared, path),
      bytes: data.length,
      sha256: createHash('sha256').update(data).digest('hex'),
    });
    await chmod(path, 0o644);
  }
  const manifestPath = resolve(prepared, 'manifest.json');
  await writeFile(
    manifestPath,
    `${JSON.stringify({ node: '22.23.1', piSdk: '0.82.0', closure: 'isolated-v1', files: manifest }, null, 2)}\n`,
    { mode: 0o644 },
  );
  setControlledFinalisationPhase('candidate-seal');
  await prepareCandidateForRename(prepared, { heldRootFd: preparedLease.handle.fd });
  await assertHeldPathLease(preparedLease, { modes: [0o700n] });
  await assertHeldPathLease(importerLease, { modes: [0o644n], path: importerPath });
  const candidateLease = await captureSidecarCandidateLease(prepared, {
    heldRootFd: preparedLease.handle.fd,
    helperWorkspaceParent,
  });

  setControlledFinalisationPhase('publication-preparation');
  const outputParent = dirname(output);
  await mkdir(outputParent, { recursive: true });
  outputParentLease = await acquireHeldPathLease(outputParent, 'directory', {
    helperParent: helperWorkspaceParent,
    label: 'Sidecar publication parent',
  });
  await assertHeldPathLease(temporaryCleanupLease);
  await assertHeldPathLease(workspaceCleanupLease);
  await assertSidecarCandidateLease(prepared, candidateLease, {
    heldRootFd: preparedLease.handle.fd,
    helperWorkspaceParent,
  });
  const retired = resolve(stagingWorkspace, 'retired');
  const failedPublish = resolve(stagingWorkspace, 'failed-publish');
  let candidatePublished = false;
  let priorOutputKind;
  let priorRetired = false;
  try {
    if (await pathExists(output)) {
      setControlledFinalisationPhase('prior-output-retire');
      priorOutputLease = await acquireHeldPathLease(output, 'directory', {
        helperParent: helperWorkspaceParent,
        label: 'Prior staged sidecar output',
        modes: [0o555n, 0o700n],
      });
      const priorState = await assertHeldPathLease(priorOutputLease, {
        modes: [0o555n, 0o700n],
        path: output,
      });
      if ((priorState.mode & 0o777n) === 0o555n) {
        await assertHeldTreeLeaseHasNoAcl(priorOutputLease, output, [0o555n]);
        priorCandidateLease = await captureSidecarCandidateLease(output, {
          heldRootFd: priorOutputLease.handle.fd,
          helperWorkspaceParent,
        });
        priorOutputKind = 'published';
        await priorOutputLease.handle.chmod(0o700);
        await assertHeldPathLease(priorOutputLease, { modes: [0o700n], path: output });
      } else {
        // A terminated publisher can leave an otherwise complete, manifest-bound
        // output at the private 0700 transition mode. Re-capture the complete
        // tree before accepting it as the previous publication. An empty 0700
        // directory remains the only accepted reset placeholder; populated or
        // malformed trees fail closed.
        try {
          priorCandidateLease = await captureSidecarCandidateLease(output, {
            heldRootFd: priorOutputLease.handle.fd,
            helperWorkspaceParent,
          });
          priorOutputKind = 'published';
        } catch (publicationError) {
          try {
            await assertHeldResetPlaceholder(priorOutputLease, output);
            await assertHeldResetPlaceholder(priorOutputLease, output);
            priorOutputKind = 'reset-placeholder';
          } catch (placeholderError) {
            throw new AggregateError(
              [publicationError, placeholderError],
              'Prior staged sidecar output is neither a valid interrupted publication nor an empty reset placeholder',
            );
          }
        }
      }
      const retirement = await moveHeldDirectory(
        priorOutputLease,
        output,
        retired,
        outputParentLease,
        workspaceCleanupLease,
        {
          sourcePolicy: priorOutputKind === 'reset-placeholder'
            ? 'empty-placeholder'
            : 'private-directory',
        },
      );
      priorRetired = true;
      if (retirement.finalisationError) throw retirement.finalisationError;
    }
    setControlledFinalisationPhase('candidate-publish');
    const publication = await moveHeldDirectory(
      preparedLease,
      prepared,
      output,
      workspaceCleanupLease,
      outputParentLease,
    );
    candidatePublished = true;
    if (publication.finalisationError) throw publication.finalisationError;
    await assertSidecarCandidateLease(output, candidateLease, {
      allowRootModeChange: true,
      heldRootFd: preparedLease.handle.fd,
      helperWorkspaceParent,
    });
    await assertHeldPathLease(importerLease, {
      modes: [0o644n],
      path: resolve(output, 'package.json'),
    });
    await sealHeldPublication(preparedLease, output, candidateLease);
    await assertSidecarCandidateLease(output, candidateLease, {
      allowRootModeChange: true,
      heldRootFd: preparedLease.handle.fd,
      helperWorkspaceParent,
    });
  } catch (error) {
    const rollbackFailures = [];
    try {
      candidatePublished = await locateHeldDirectoryLease(
        preparedLease,
        [prepared, output, failedPublish],
      ) === output;
    } catch (rollbackError) {
      workspaceCleanupAuthorised = false;
      rollbackFailures.push(rollbackError);
    }
    if (priorOutputLease && priorOutputKind) {
      try {
        const priorLocation = await locateHeldDirectoryLease(
          priorOutputLease,
          [output, retired],
        );
        priorRetired = priorLocation === retired;
        if (priorLocation === output) {
          const priorState = await assertHeldPathLease(priorOutputLease, {
            modes: [0o700n, 0o555n],
            path: output,
          });
          if ((priorState.mode & 0o777n) === 0o700n) {
            if (priorOutputKind === 'published') {
              await sealHeldPublication(priorOutputLease, output, priorCandidateLease);
            } else {
              await assertHeldResetPlaceholder(priorOutputLease, output);
            }
          } else if (priorOutputKind === 'reset-placeholder') {
            throw new Error('Reset sidecar placeholder mode changed during rollback');
          }
        }
      } catch (rollbackError) {
        workspaceCleanupAuthorised = false;
        rollbackFailures.push(rollbackError);
      }
    }
    if (candidatePublished) {
      try {
        await assertHeldPathLease(preparedLease, {
          modes: [0o700n, 0o555n],
          path: output,
        });
        await preparedLease.handle.chmod(0o700);
        await assertHeldPathLease(preparedLease, { modes: [0o700n], path: output });
        const relocation = await moveHeldDirectory(
          preparedLease,
          output,
          failedPublish,
          outputParentLease,
          workspaceCleanupLease,
        );
        candidatePublished = false;
        if (relocation.finalisationError) rollbackFailures.push(relocation.finalisationError);
      } catch (rollbackError) {
        workspaceCleanupAuthorised = false;
        rollbackFailures.push(rollbackError);
      }
    }
    if (priorRetired && !candidatePublished) {
      try {
        const restoration = await moveHeldDirectory(
          priorOutputLease,
          retired,
          output,
          workspaceCleanupLease,
          outputParentLease,
          {
            sourcePolicy: priorOutputKind === 'reset-placeholder'
              ? 'empty-placeholder'
              : 'private-directory',
          },
        );
        priorRetired = false;
        if (priorOutputKind === 'published') {
          await sealHeldPublication(priorOutputLease, output, priorCandidateLease);
        } else {
          await assertHeldResetPlaceholder(priorOutputLease, output);
        }
        if (restoration.finalisationError) rollbackFailures.push(restoration.finalisationError);
      } catch (rollbackError) {
        rollbackFailures.push(rollbackError);
      }
    }
    if (priorRetired) workspaceCleanupAuthorised = false;
    if (rollbackFailures.length) {
      throw new AggregateError(
        [error, ...rollbackFailures],
        'Sidecar publication and leased rollback failed',
      );
    }
    throw error;
  }
  console.log(
    `Staged ${manifest.length} production resources; manifest=${relative(root, resolve(output, 'manifest.json'))}`,
  );
  } catch (error) {
    transactionFailure = error;
  } finally {
    for (const lease of [priorOutputLease, importerLease, preparedLease, outputParentLease]
      .filter((entry, index, entries) => entry && entries.indexOf(entry) === index)
      .reverse()) {
      try { await lease.handle.close(); } catch (error) { descriptorFailures.push(error); }
    }
  }
  if (transactionFailure && descriptorFailures.length) {
    throw new AggregateError(
      [transactionFailure, ...descriptorFailures],
      'Sidecar finalisation and descriptor cleanup failed',
    );
  }
  if (transactionFailure) throw transactionFailure;
  if (descriptorFailures.length) {
    throw new AggregateError(descriptorFailures, 'Sidecar finalisation descriptor cleanup failed');
  }
}

function runPnpm(args) {
  const entry = process.env.PIUI_PNPM_ENTRY;
  const node = process.env.PIUI_PNPM_NODE;
  if (entry && node) return spawnSync(node, [entry, ...args], { cwd: root, stdio: 'inherit', env: process.env });
  return spawnSync('pnpm', args, { cwd: root, stdio: 'inherit', env: process.env });
}

async function publishA25Fixture() {
  const compiled = resolve(root, 'sidecar/dist');
  await mkdir(resolve(a25FixtureOutput, 'spike'), { recursive: true, mode: 0o700 });
  await chmod(a25FixtureOutput, 0o700);
  await chmod(resolve(a25FixtureOutput, 'spike'), 0o700);
  for (const relativePath of A25_FIXTURE_FILES) {
    const source = resolve(compiled, relativePath);
    const destination = resolve(a25FixtureOutput, relativePath);
    if (await pathExists(destination)) await chmod(destination, 0o600);
    if (relativePath === 'package.json') {
      await writeFile(destination, A25_FIXTURE_PACKAGE, { mode: 0o600 });
    } else {
      await cp(source, destination, { force: true });
    }
    await chmod(destination, 0o400);
  }
  const inventory = (await files(a25FixtureOutput, a25FixtureOutput))
    .map((path) => relative(a25FixtureOutput, path).split('\\').join('/'))
    .sort();
  if (JSON.stringify(inventory) !== JSON.stringify([...A25_FIXTURE_FILES].sort())) {
    throw new Error('A.25 external fixture inventory rejected');
  }
}

async function unlockTauriResourceCopies() {
  const target = resolve(root, 'src-tauri/target');
  for (const path of [
    resolve(target, 'debug/resources/sidecar'),
    resolve(target, 'release/resources/sidecar'),
    resolve(target, 'aarch64-apple-darwin/debug/resources/sidecar'),
    resolve(target, 'aarch64-apple-darwin/release/resources/sidecar'),
  ]) {
    if (await pathExists(path)) await makeTreeOwnerWritable(path);
  }
}

async function quarantineLegacyDeployment(controlled = false) {
  const legacy = resolve(cacheRoot, 'sidecar-deploy');
  if (!(await pathExists(legacy))) return;
  if (controlled) {
    throw new Error('Controlled sidecar staging found a legacy deployment');
  }
  // One fixed quarantine path: a copy left by an interrupted cleanup is
  // removed first rather than accumulating uniquely named siblings.
  const abandoned = resolve(cacheRoot, 'sidecar-deploy-abandoned');
  if (await pathExists(abandoned)) await cleanTreeMandatory(abandoned);
  await rename(legacy, abandoned);
  await cleanTreeMandatory(abandoned);
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

async function cleanTreeMandatory(path) {
  async function unlockDirectories(current) {
    const item = await lstat(current);
    if (item.isSymbolicLink() || !item.isDirectory()) return;
    await chmod(current, 0o700);
    for (const name of await readdir(current)) await unlockDirectories(resolve(current, name));
  }
  await unlockDirectories(path);
  await rm(path, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  if (await pathExists(path)) throw new Error(`Staging workspace remained after cleanup: ${relative(root, path)}`);
}

async function cleanHeldWorkspaceMandatory(workspaceLease, parentLease, setCleanupPhase) {
  setCleanupPhase('workspace-cleanup-temporary-lease');
  const parentState = await assertHeldPathLease(parentLease);
  setCleanupPhase('workspace-cleanup-workspace-lease');
  const workspaceState = await assertHeldPathLease(workspaceLease, {
    modes: [0o700n],
    path: workspaceLease.path,
  });
  if (dirname(workspaceLease.path) !== parentLease.path
    || workspaceState.dev !== parentState.dev) {
    throw new Error('Staging workspace cleanup descriptors are inconsistent');
  }
  setCleanupPhase('workspace-cleanup-tree-unlock');
  await makeTreeOwnerWritable(workspaceLease.path, false, 0o700);
  setCleanupPhase('workspace-cleanup-post-unlock-lease-validation');
  const unlockedWorkspace = await assertHeldPathLease(workspaceLease, {
    modes: [0o700n],
    path: workspaceLease.path,
  });
  const reboundParent = await assertHeldPathLease(parentLease);
  if (unlockedWorkspace.dev !== workspaceState.dev
    || unlockedWorkspace.ino !== workspaceState.ino
    || reboundParent.dev !== parentState.dev
    || reboundParent.ino !== parentState.ino) {
    throw new Error('Staging workspace cleanup lease changed while unlocking');
  }
  setCleanupPhase('workspace-cleanup-inspector-capture');
  const inspector = captureSystemDescriptorAclInspector();
  setCleanupPhase('workspace-cleanup-descriptor-bound-removal');
  removeDescriptorBoundTree({
    dev: Number(workspaceState.dev),
    fd: workspaceLease.handle.fd,
    ino: Number(workspaceState.ino),
    parentDev: Number(parentState.dev),
    parentFd: parentLease.handle.fd,
    parentIno: Number(parentState.ino),
  }, inspector);
  setCleanupPhase('workspace-cleanup-path-absence');
  if (await pathExists(workspaceLease.path)) {
    throw new Error(`Staging workspace remained after cleanup: ${relative(root, workspaceLease.path)}`);
  }
}

async function files(path, boundary) {
  const entries = [];
  for (const name of (await readdir(path)).sort()) {
    const absolute = resolve(path, name);
    // Finder may recreate metadata between the prune and manifest walks. Remove
    // it at the point of enumeration so repeated staging stays byte-for-byte
    // deterministic and the bundle never records Finder state.
    if (name === '.DS_Store') {
      await rm(absolute, { recursive: true, force: true });
      continue;
    }
    const stat = await lstat(absolute);
    if (stat.isSymbolicLink()) {
      throw new Error(`Staged resource contains symlink: ${relative(boundary, absolute)}`);
    }
    if (stat.isDirectory()) entries.push(...(await files(absolute, boundary)));
    else entries.push(absolute);
  }
  return entries;
}

async function validateProductionClosure(path) {
  const required = [
    'dist/index.js',
    'dist/runtime.js',
    'dist/pi/trust-gate.js',
    'dist/pi/trust-loader.js',
    'dist/pi/trust-loader-worker.js',
    'dist/pi/trust-loader-executor.js',
    'dist/pi/trust-loader-project-thread.js',
    'dist/pi/ai-public-sdk.js',
    'dist/pi/deterministic-turn.js',
    'dist/pi/packaged-sdk-probe.js',
    'dist/pi/packaged-sdk-probe-entry.js',
    'dist/pi/session-spike.js',
    'fixture/active-branch-v3.jsonl',
    'node_modules/@piui/protocol/dist/codec.js',
    'node_modules/@piui/protocol/schema/envelope.schema.json',
    'node_modules/@earendil-works/pi-coding-agent/dist/index.js',
    'node_modules/@earendil-works/pi-coding-agent/dist/utils/changelog.js',
    'node_modules/@earendil-works/pi-ai/package.json',
    'node_modules/@earendil-works/pi-ai/dist/index.js',
    'node_modules/yaml/dist/doc/directives.js',
    'node_modules/yaml/dist/doc/Document.js',
    'node_modules/@earendil-works/pi-coding-agent/dist/modes/interactive/theme/theme-schema.json',
    'node_modules/@earendil-works/pi-coding-agent/dist/modes/interactive/theme/light.json',
    'node_modules/@earendil-works/pi-coding-agent/dist/modes/interactive/theme/dark.json',
  ];
  for (const requiredPath of required) {
    if (!(await pathExists(resolve(path, requiredPath)))) {
      throw new Error(`Required sidecar runtime asset missing: ${requiredPath}`);
    }
  }
  const staged = await files(path, path);
  const relativeFiles = staged.map((entry) => relative(path, entry).split('\\').join('/'));
  const leakedFixture = relativeFiles.filter((entry) => (
    A25_COMPILED_PREFIXES.some((prefix) => entry.startsWith(`dist/${prefix}`))
  ));
  if (leakedFixture.length) {
    throw new Error(`A.25 fixture entered production closure: ${leakedFixture.join(', ')}`);
  }
  const activationMarkers = [
    'PIUI_A25_',
    'createA25Approval',
    'approval-matrix.complete',
    'spike/approval-matrix',
    'spike/approval-probes',
  ];
  for (const relativePath of relativeFiles.filter((entry) => (
    entry.startsWith('dist/') && entry.endsWith('.js')
  ))) {
    const source = await readFile(resolve(path, relativePath), 'utf8');
    if (activationMarkers.some((marker) => source.includes(marker))) {
      throw new Error(`A.25 activation entered production closure: ${relativePath}`);
    }
  }
  const forbiddenPackages = [
    '@tauri-apps',
    '@testing-library',
    '@types',
    '@vitejs',
    'react',
    'react-aria',
    'react-aria-components',
    'react-dom',
    'tailwindcss',
    'typescript',
    'vite',
    'vitest',
  ];
  for (const packageName of forbiddenPackages) {
    if (await pathExists(resolve(path, 'node_modules', packageName))) {
      throw new Error(`Non-sidecar package entered production closure: ${packageName}`);
    }
  }
  const forbiddenPath = /(^|\/)(?:\.github|\.history)(\/|$)|(^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock)$|\.(?:d\.)?(?:m|c)?ts$|\.map$/;
  const rejected = staged
    .map((entry) => relative(path, entry))
    .filter((entry) => isForbiddenDocumentationPath(entry) || forbiddenPath.test(entry));
  if (rejected.length) {
    throw new Error(`Rejected production resources remain: ${rejected.slice(0, 10).join(', ')}`);
  }
}

async function prune(path, boundary = path) {
  for (const name of await readdir(path)) {
    const child = resolve(path, name);
    const stat = await lstat(child);
    if (stat.isDirectory()) {
      const relativePath = relative(boundary, child);
      const normalisedRelative = relativePath.split('\\').join('/');
      const foreignNativePackage =
        /(^|\/)node_modules\/@mariozechner\/clipboard-(?!darwin-arm64(?:\/|$))/.test(normalisedRelative) ||
        /(^|\/)node_modules\/@earendil-works\/pi-tui\/native\/win32(?:\/|$)/.test(normalisedRelative) ||
        /(^|\/)node_modules\/@earendil-works\/pi-tui\/native\/darwin\/prebuilds\/darwin-x64(?:\/|$)/.test(normalisedRelative);
      if (
        /^(?:@types|\.cache|\.git|\.github|\.history|\.bin|\.pnpm|\.pnpm-store)$/.test(name) ||
        foreignNativePackage ||
        isForbiddenDocumentationDirectoryPath(relativePath)
      ) {
        await rm(child, { recursive: true, force: true });
      } else {
        await prune(child, boundary);
      }
    } else if (
      name === '.DS_Store' ||
      name === '.modules.yaml' ||
      /^(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock)$/.test(name) ||
      /^(\.editorconfig|\.eslintignore|\.eslintrc.*|\.gitignore|\.jscs.*|\.npmignore|\.nvmrc|\.prettier.*|\.travis.*|\.yarnrc.*)$/.test(name) ||
      isForbiddenDocumentationFile(name) ||
      /\.(d\.)?(m|c)?ts$|\.map$/.test(name)
    ) {
      await rm(child, { force: true });
    }
  }
}

async function makeTreeOwnerWritable(path, rootOnly = false, rootDirectoryMode) {
  const item = await lstat(path);
  if (item.isSymbolicLink()) {
    if (rootOnly) throw new Error('Prior staged closure root is unsafe');
    return;
  }
  if (!item.isDirectory() && !item.isFile()) throw new Error('Staged closure contains a special entry');
  if (item.isFile() && item.nlink !== 1) throw new Error('Staged closure contains a hard-linked file');
  const flags = constants.O_RDONLY | constants.O_NOFOLLOW | (item.isDirectory() ? constants.O_DIRECTORY : 0);
  const handle = await open(path, flags);
  try {
    const exact = await handle.stat();
    if (exact.dev !== item.dev || exact.ino !== item.ino || exact.isDirectory() !== item.isDirectory()) {
      throw new Error('Staged closure identity changed while unlocking');
    }
    await handle.chmod(item.isDirectory()
      ? (rootDirectoryMode ?? 0o755)
      : ((item.mode & 0o111) ? 0o755 : 0o644));
  } finally {
    await handle.close();
  }
  if (item.isDirectory() && !rootOnly) {
    for (const name of await readdir(path)) await makeTreeOwnerWritable(resolve(path, name));
  }
}
