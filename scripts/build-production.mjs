import { randomBytes } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { spawnSync } from 'node:child_process';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  realpath,
  rm,
} from 'node:fs/promises';
import { arch, platform, tmpdir } from 'node:os';
import {
  basename,
  dirname,
  isAbsolute,
  relative,
  resolve,
  sep,
} from 'node:path';
import { fileURLToPath } from 'node:url';
import { inventoryBundle } from '../tests/packaged/bundle-inspection.mjs';
import {
  canonicalArchitectureJson,
  sha256Bytes,
} from './architecture-gate-schema.mjs';
import {
  equalArchitectureSourceLease,
  snapshotArchitectureSource,
} from './architecture-source-snapshot.mjs';
import { validateLatestArchitectureGate } from './check-architecture-gate.mjs';
import {
  assertGuardedProductionResult,
  parseGuardedProductionResult,
} from './guarded-production-contract.mjs';
import { exclusiveDirectoryRename } from './exclusive-rename.mjs';
import {
  acquireOwnedLock,
  configureAuthenticatedNodeSpawn,
  createAuthenticatedNodeGuardedProductionSandboxProfile,
  installParentCutoffs,
  releaseOwnedLock,
  runOwnedCommand,
} from './a21-gate-support.mjs';
import { createAuthenticatedNodeSpawnConfiguration } from './authenticated-node-spawn.mjs';
import {
  architectureBootstrapChildOptions,
  assertArchitectureBootstrap,
  releaseArchitectureBootstrap,
} from './architecture-bootstrap-contract.mjs';
import { APPLE_TOOLCHAIN_PATHS } from './apple-toolchain-trust.mjs';

process.umask(0o077);

const TARGET = 'aarch64-apple-darwin';
const RUN_ID = /^\d{8}T\d{9}Z-[0-9a-f]{32}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function reject(message = 'Guarded production build rejected') {
  throw new Error(message);
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject(`${label} is invalid`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])) reject(`${label} fields are not exact`);
}

function assertGateSummary(value) {
  exactKeys(value, [
    'decision',
    'distributionAuthorised',
    'productionFingerprint',
    'runId',
    'sourceDigest',
    'target',
  ], 'Architecture gate summary');
  if (value.decision !== 'pass'
    || value.distributionAuthorised !== false
    || typeof value.productionFingerprint !== 'string'
    || !SHA256.test(value.productionFingerprint)
    || typeof value.runId !== 'string'
    || !RUN_ID.test(value.runId)
    || typeof value.sourceDigest !== 'string'
    || !SHA256.test(value.sourceDigest)
    || value.target !== TARGET) reject('Architecture gate does not authorise a local production candidate');
  return Object.freeze({ ...value });
}

function sameGate(left, right) {
  return canonicalArchitectureJson(left) === canonicalArchitectureJson(right);
}

function sameSource(left, right) {
  return left.inventoryBytes.equals(right.inventoryBytes)
    && canonicalArchitectureJson(left.source) === canonicalArchitectureJson(right.source)
    && equalArchitectureSourceLease(left, right);
}

function sameReproducibleSource(left, right) {
  return left.inventoryBytes.equals(right.inventoryBytes)
    && canonicalArchitectureJson(left.source) === canonicalArchitectureJson(right.source);
}

function parseSourceLease(snapshot) {
  let lease;
  try {
    lease = JSON.parse(snapshot.leaseBytes.toString('utf8'));
  } catch {
    reject('Architecture source lease is invalid');
  }
  if (lease?.schemaVersion !== 1
    || !Array.isArray(lease.entries)
    || `${canonicalArchitectureJson(lease)}\n` !== snapshot.leaseBytes.toString('utf8')) {
    reject('Architecture source lease is invalid');
  }
  return lease.entries;
}

function isControlledForgeInfrastructureTransition(before, after) {
  if (!sameReproducibleSource(before, after)
    || before.lease?.entries !== after.lease?.entries) return false;
  const beforeEntries = parseSourceLease(before);
  const afterEntries = parseSourceLease(after);
  if (beforeEntries.length !== afterEntries.length) return false;
  const stableForgeFields = ['dev', 'gid', 'ino', 'kind', 'mode', 'path', 'uid'];
  for (let index = 0; index < beforeEntries.length; index += 1) {
    const left = beforeEntries[index];
    const right = afterEntries[index];
    if (left.path !== right.path) return false;
    if (left.path !== '.forge/') {
      if (canonicalArchitectureJson(left) !== canonicalArchitectureJson(right)) return false;
      continue;
    }
    if (stableForgeFields.some((field) => left[field] !== right[field])) return false;
    const beforeLinks = BigInt(left.nlink);
    const afterLinks = BigInt(right.nlink);
    if (afterLinks < beforeLinks || afterLinks > beforeLinks + 1n
      || BigInt(right.mtimeNs) < BigInt(left.mtimeNs)
      || BigInt(right.ctimeNs) < BigInt(left.ctimeNs)) return false;
  }
  return true;
}

function assertSourceBoundToGate(snapshot, gate) {
  if (!snapshot
    || !Buffer.isBuffer(snapshot.inventoryBytes)
    || !Buffer.isBuffer(snapshot.leaseBytes)
    || typeof snapshot.lease?.sha256 !== 'string'
    || !SHA256.test(snapshot.lease.sha256)
    || snapshot.source?.digest !== gate.sourceDigest) {
    reject('Architecture source is not bound to the accepted gate');
  }
}

function assertNoAcl(path, label) {
  const result = spawnSync('/bin/ls', [
    platform() === 'darwin' ? '-lde' : '-ld',
    '--',
    path,
  ], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const lines = typeof result.stdout === 'string' ? result.stdout.split('\n') : [];
  if (result.status !== 0
    || result.signal !== null
    || result.stderr !== ''
    || lines.some((line) => /^[bcdlps-][rwxStTs-]{9}\+/u.test(line))
    || lines.some((line) => /^\s+\d+:/u.test(line))) reject(`${label} has an unsafe ACL`);
}

async function assertDirectory(path, label, { exactPrivate = false } = {}) {
  if (!isAbsolute(path) || resolve(path) !== path) reject(`${label} is not canonical`);
  const state = await lstat(path, { bigint: true });
  const expectedUid = typeof process.getuid === 'function' ? BigInt(process.getuid()) : null;
  if (expectedUid === null
    || !state.isDirectory()
    || state.isSymbolicLink()
    || state.uid !== expectedUid
    || (state.mode & 0o022n) !== 0n
    || (exactPrivate && (state.mode & 0o777n) !== 0o700n)
    || await realpath(path) !== path) reject(`${label} is unsafe`);
  assertNoAcl(path, label);
  return Object.freeze({
    ctimeNs: state.ctimeNs,
    dev: state.dev,
    gid: state.gid,
    ino: state.ino,
    mode: state.mode,
    mtimeNs: state.mtimeNs,
    nlink: state.nlink,
    path,
    size: state.size,
    uid: state.uid,
  });
}

function sameDirectoryAnchor(left, right) {
  return left.path === right.path && sameDirectoryIdentity(left, right);
}

function sameDirectoryIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid;
}

function sameDirectoryLease(left, right) {
  return sameDirectoryAnchor(left, right)
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

async function assertDirectoryMatches(expected, label, {
  exactLease = false,
  exactPrivate = false,
} = {}) {
  const current = await assertDirectory(expected.path, label, { exactPrivate });
  if (!(exactLease ? sameDirectoryLease(current, expected) : sameDirectoryAnchor(current, expected))) {
    reject(`${label} identity changed`);
  }
  return current;
}

async function ensurePrivateChild(parent, name, label) {
  const parentBefore = await assertDirectory(parent.path, `${label} parent`, {
    exactPrivate: parent.exactPrivate,
  });
  if (!sameDirectoryAnchor(parentBefore, parent)) {
    reject(`${label} parent identity changed`);
  }
  const path = resolve(parent.path, name);
  if (dirname(path) !== parent.path) reject();
  try {
    await mkdir(path, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  const child = await assertDirectory(path, label, { exactPrivate: true });
  const parentAfter = await assertDirectory(parent.path, `${label} parent`, {
    exactPrivate: parent.exactPrivate,
  });
  if (!sameDirectoryAnchor(parentAfter, parent)) {
    reject(`${label} parent identity changed`);
  }
  return Object.freeze({ ...child, exactPrivate: true });
}

async function createFreshPrivateChild(parent, name, label) {
  const parentBefore = await assertDirectoryMatches(parent, `${label} parent`, {
    exactPrivate: parent.exactPrivate,
  });
  const path = resolve(parent.path, name);
  if (dirname(path) !== parent.path || basename(path) !== name) reject();
  await mkdir(path, { mode: 0o700 });
  const child = await assertDirectory(path, label, { exactPrivate: true });
  const parentAfter = await assertDirectory(parent.path, `${label} parent`, {
    exactPrivate: parent.exactPrivate,
  });
  if (!sameDirectoryAnchor(parentAfter, parentBefore)) reject(`${label} parent identity changed`);
  if (child.dev !== parentAfter.dev) reject(`${label} is not on its parent filesystem`);
  return Object.freeze({ ...child, exactPrivate: true });
}

async function assertExactEntries(path, expected) {
  const entries = await readdir(path, { withFileTypes: true });
  entries.sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
  const wanted = [...expected].sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  if (entries.length !== wanted.length
    || entries.some((entry, index) => entry.name !== wanted[index])) {
    reject('Guarded production directory inventory is not exact');
  }
  return entries;
}

async function collectTreeLease(rootPath) {
  const expectedUid = typeof process.getuid === 'function' ? BigInt(process.getuid()) : null;
  if (expectedUid === null) reject();
  const entries = [];
  async function visit(path, pathLabel) {
    const state = await lstat(path, { bigint: true });
    if (state.isSymbolicLink()
      || (!state.isDirectory() && !state.isFile())
      || state.uid !== expectedUid
      || (state.mode & 0o022n) !== 0n
      || (state.isFile() && state.nlink !== 1n)) {
      reject(`Production staging lease contains an unsafe entry: ${pathLabel}`);
    }
    entries.push(Object.freeze({
      ctimeNs: state.ctimeNs.toString(10),
      dev: state.dev.toString(10),
      gid: state.gid.toString(10),
      ino: state.ino.toString(10),
      kind: state.isDirectory() ? 'directory' : 'file',
      mode: state.mode.toString(10),
      mtimeNs: state.mtimeNs.toString(10),
      nlink: state.nlink.toString(10),
      path: pathLabel,
      size: state.size.toString(10),
      uid: state.uid.toString(10),
    }));
    if (!state.isDirectory()) return;
    const children = await readdir(path, { withFileTypes: true });
    children.sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
    for (const child of children) {
      const childPath = resolve(path, child.name);
      const childRelative = relative(rootPath, childPath);
      if (!childRelative
        || childRelative === '..'
        || childRelative.startsWith(`..${sep}`)
        || resolve(rootPath, childRelative) !== childPath) reject();
      await visit(childPath, childRelative.split(sep).join('/'));
    }
  }
  await visit(rootPath, '.');
  return Buffer.from(canonicalArchitectureJson(entries), 'utf8');
}

async function snapshotTreeLease(rootPath) {
  const root = await realpath(rootPath);
  if (root !== rootPath) reject('Production staging bundle is not canonical');
  const first = await collectTreeLease(root);
  const second = await collectTreeLease(root);
  if (!first.equals(second)) reject('Production staging bundle changed while its lease was captured');
  return Object.freeze({ bytes: first, root });
}

async function assertTreeLease(expected) {
  const current = await snapshotTreeLease(expected.root);
  if (!current.bytes.equals(expected.bytes)) reject('Production staging bundle lease changed');
}

function pathForTreeEntry(root, pathLabel) {
  if (pathLabel === '.') return root;
  if (typeof pathLabel !== 'string'
    || pathLabel.startsWith('/')
    || pathLabel.split('/').some((part) => !part || part === '.' || part === '..')) reject();
  const path = resolve(root, ...pathLabel.split('/'));
  if (relative(root, path).split(sep).join('/') !== pathLabel) reject();
  return path;
}

function parseTreeLease(lease) {
  let entries;
  try {
    entries = JSON.parse(lease.bytes.toString('utf8'));
  } catch {
    reject('Production tree lease is invalid');
  }
  if (!Array.isArray(entries)
    || !Buffer.from(canonicalArchitectureJson(entries), 'utf8').equals(lease.bytes)) {
    reject('Production tree lease is invalid');
  }
  return entries;
}

function treeEntryMatchesState(entry, state) {
  return state.dev.toString(10) === entry.dev
    && state.ino.toString(10) === entry.ino
    && state.mode.toString(10) === entry.mode
    && state.uid.toString(10) === entry.uid
    && state.gid.toString(10) === entry.gid
    && state.nlink.toString(10) === entry.nlink
    && state.size.toString(10) === entry.size
    && state.mtimeNs.toString(10) === entry.mtimeNs
    && state.ctimeNs.toString(10) === entry.ctimeNs;
}

async function syncOwnedTree(lease) {
  const entries = parseTreeLease(lease);
  const ordered = [
    ...entries.filter((entry) => entry.kind === 'file'),
    ...entries
      .filter((entry) => entry.kind === 'directory')
      .sort((left, right) => right.path.split('/').length - left.path.split('/').length),
  ];
  for (const entry of ordered) {
    const path = pathForTreeEntry(lease.root, entry.path);
    const flags = fsConstants.O_RDONLY
      | (fsConstants.O_NOFOLLOW ?? 0)
      | (entry.kind === 'directory' ? (fsConstants.O_DIRECTORY ?? 0) : 0);
    const handle = await open(path, flags);
    try {
      const before = await handle.stat({ bigint: true });
      if ((entry.kind === 'directory' ? !before.isDirectory() : !before.isFile())
        || !treeEntryMatchesState(entry, before)) reject('Copied production tree changed before sync');
      await handle.sync();
      const after = await handle.stat({ bigint: true });
      const pathAfter = await lstat(path, { bigint: true });
      if (!treeEntryMatchesState(entry, after)
        || pathAfter.isSymbolicLink()
        || !treeEntryMatchesState(entry, pathAfter)) {
        reject('Copied production tree changed during sync');
      }
    } finally {
      await handle.close();
    }
  }
  await assertTreeLease(lease);
}

async function makeTreeRemovable(lease) {
  const entries = parseTreeLease(lease);
  const directories = entries
    .filter((entry) => entry?.kind === 'directory')
    .sort((left, right) => right.path.split('/').length - left.path.split('/').length);
  for (const entry of directories) {
    const path = pathForTreeEntry(lease.root, entry.path);
    const state = await lstat(path, { bigint: true });
    if (!state.isDirectory()
      || state.isSymbolicLink()
      || !treeEntryMatchesState(entry, state)) {
      reject('Production staging cleanup lease changed');
    }
    await chmod(path, 0o700);
    const changed = await lstat(path, { bigint: true });
    if (!changed.isDirectory()
      || changed.isSymbolicLink()
      || changed.dev !== state.dev
      || changed.ino !== state.ino
      || changed.uid !== state.uid
      || changed.gid !== state.gid
      || (changed.mode & 0o777n) !== 0o700n) {
      reject('Production staging directory changed while preparing cleanup');
    }
  }
}

async function assertPathMissing(path, label) {
  try {
    await lstat(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  reject(`${label} already exists`);
}

function combineFailures(message, ...failures) {
  const errors = failures.filter((failure) => failure !== undefined);
  if (errors.length === 1) return errors[0];
  return new AggregateError(errors, message);
}

export async function createPrivateTemporary(prefix, {
  makeTemporary = mkdtemp,
  removeTemporary = (path) => rm(path, { force: false, recursive: true }),
  setMode = chmod,
} = {}) {
  if (typeof prefix !== 'string' || !/^[a-z0-9-]+$/u.test(prefix)) {
    reject('Guarded production staging prefix is invalid');
  }
  const temporaryRoot = await realpath(tmpdir());
  const requestedPrefix = resolve(temporaryRoot, prefix);
  let path;
  try {
    path = await makeTemporary(requestedPrefix);
    if (typeof path !== 'string'
      || dirname(path) !== temporaryRoot
      || !basename(path).startsWith(prefix)) reject('Guarded production staging path is invalid');
    await setMode(path, 0o700);
    return await assertDirectory(path, 'Guarded production staging root', { exactPrivate: true });
  } catch (error) {
    if (path === undefined) throw error;
    let cleanupError;
    try {
      await removeTemporary(path);
      await assertPathMissing(path, 'Failed guarded production staging root');
    } catch (failure) {
      cleanupError = failure;
    }
    throw combineFailures(
      'Guarded production staging creation and cleanup failed',
      error,
      cleanupError,
    );
  }
}

async function copySealedBundle({ destination, source }) {
  await assertPathMissing(destination, 'Incoming production bundle');
  const copied = spawnSync('/bin/cp', ['-pR', '--', source, destination], {
    encoding: 'utf8',
    env: {
      LANG: 'en_AU.UTF-8',
      LC_ALL: 'en_AU.UTF-8',
      PATH: '/usr/bin:/bin',
    },
    maxBuffer: 256 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (copied.status !== 0
    || copied.signal !== null
    || copied.stdout !== ''
    || copied.stderr !== '') reject('Sealed production bundle copy failed');
}

async function syncDirectory(path) {
  const handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function removePrivateTemporary(staging, expectedLease) {
  await assertDirectoryMatches(staging, 'Guarded production staging root', {
    exactLease: false,
    exactPrivate: true,
  });
  if (expectedLease) {
    await assertDirectoryMatches(expectedLease, 'Guarded production staging root', {
      exactLease: true,
      exactPrivate: true,
    });
  }
  const cleanupLease = await snapshotTreeLease(staging.path);
  await makeTreeRemovable(cleanupLease);
  await rm(staging.path, { force: false, recursive: true });
  await assertPathMissing(staging.path, 'Guarded production staging root');
}

async function retainFailedPublication({
  alternatePath,
  builds,
  candidateValidator,
  directorySynchroniser,
  incoming,
  incomingPath,
  publicationRenamer,
  publicationStem,
}) {
  if (!incoming) return undefined;
  const candidatePaths = [...new Set(
    [incomingPath, alternatePath].filter((path) => typeof path === 'string'),
  )];
  const matches = [];
  for (const candidatePath of candidatePaths) {
    let state;
    try {
      state = await lstat(candidatePath, { bigint: true });
    } catch (error) {
      if (error?.code === 'ENOENT') continue;
      throw error;
    }
    if (state.isDirectory()
      && !state.isSymbolicLink()
      && sameDirectoryIdentity(state, incoming)) {
      matches.push(candidatePath);
    }
  }
  if (matches.length !== 1) {
    reject('Failed production publication lease could not be located exactly once');
  }
  const sourcePath = matches[0];
  const source = await assertDirectory(sourcePath, 'Failed production publication', {
    exactPrivate: true,
  });
  if (!sameDirectoryIdentity(source, incoming)) {
    reject('Failed production publication identity changed');
  }
  let validationError;
  try {
    if (typeof candidateValidator === 'function') {
      await candidateValidator(sourcePath, source);
    }
  } catch (error) {
    validationError = error;
  }
  let relocationError;
  let failedPath;
  try {
    const sourceBeforeRename = await assertDirectory(
      sourcePath,
      'Failed production publication',
      { exactPrivate: true },
    );
    if (!sameDirectoryIdentity(sourceBeforeRename, incoming)) {
      reject('Failed production publication identity changed');
    }
    await assertDirectoryMatches(builds, 'Production build directory', {
      exactPrivate: true,
    });
    failedPath = resolve(
      builds.path,
      `.failed-${publicationStem}-${randomBytes(8).toString('hex')}`,
    );
    await assertPathMissing(failedPath, 'Failed production evidence');
    await publicationRenamer(sourcePath, failedPath, {
      expectedParentIdentity: builds,
      expectedSourceIdentity: incoming,
    });
    await assertPathMissing(sourcePath, 'Relocated failed production publication');
    const failed = await assertDirectory(
      failedPath,
      'Failed production evidence',
      { exactPrivate: true },
    );
    if (!sameDirectoryIdentity(failed, incoming)) {
      reject('Failed production evidence identity changed');
    }
    await directorySynchroniser(builds.path);
  } catch (error) {
    relocationError = error;
  }
  if (validationError || relocationError) {
    throw combineFailures(
      'Failed production evidence validation or relocation failed',
      validationError,
      relocationError,
    );
  }
  return failedPath;
}

async function validateCompletePublication({
  bundleInventory,
  expectedFingerprint,
  expectedIncoming,
  prepared,
  publicationPath,
}) {
  const publication = await assertDirectory(
    publicationPath,
    'Completed production publication',
    { exactPrivate: true },
  );
  if (!sameDirectoryIdentity(publication, expectedIncoming)) {
    reject('Completed production publication identity changed');
  }
  await assertExactEntries(publicationPath, ['PIUI.app', 'build.json']);
  const bundlePath = resolve(publicationPath, 'PIUI.app');
  const bundleLease = await snapshotTreeLease(bundlePath);
  if (!bundleLease.bytes.equals(prepared.copiedBundleLease.bytes)) {
    reject('Completed production bundle lease changed after atomic rename');
  }
  const inventory = await bundleInventory(bundlePath);
  if (inventory.fingerprint !== expectedFingerprint) {
    reject('Completed production bundle fingerprint changed after atomic rename');
  }
  await assertBuildRecordSha256(
    resolve(publicationPath, 'build.json'),
    prepared.recordSha256,
  );
  await assertExactEntries(publicationPath, ['PIUI.app', 'build.json']);
  const publicationAfter = await assertDirectory(
    publicationPath,
    'Completed production publication',
    { exactPrivate: true },
  );
  if (!sameDirectoryIdentity(publicationAfter, expectedIncoming)) {
    reject('Completed production publication identity changed');
  }
}

const guardedProductionAppleToolchainExecutables = Object.freeze([
  APPLE_TOOLCHAIN_PATHS.ar,
  APPLE_TOOLCHAIN_PATHS.clang,
  APPLE_TOOLCHAIN_PATHS.clangxx,
  APPLE_TOOLCHAIN_PATHS.dsymutil,
  APPLE_TOOLCHAIN_PATHS.installNameTool,
  APPLE_TOOLCHAIN_PATHS.ld,
  APPLE_TOOLCHAIN_PATHS.libtool,
  APPLE_TOOLCHAIN_PATHS.lipo,
  APPLE_TOOLCHAIN_PATHS.llvmNm,
  APPLE_TOOLCHAIN_PATHS.llvmOtool,
  APPLE_TOOLCHAIN_PATHS.nm,
  APPLE_TOOLCHAIN_PATHS.otool,
  APPLE_TOOLCHAIN_PATHS.otoolClassic,
  APPLE_TOOLCHAIN_PATHS.ranlib,
  APPLE_TOOLCHAIN_PATHS.strip,
]);

const guardedProductionSystemExecutables = Object.freeze([
  '/bin/bash',
  '/bin/chmod',
  '/bin/cp',
  '/bin/ls',
  '/bin/ps',
  '/bin/sh',
  '/usr/bin/codesign',
  '/usr/bin/env',
  '/usr/bin/lockf',
  '/usr/bin/plutil',
  '/usr/bin/ruby',
  '/usr/bin/sandbox-exec',
  '/usr/bin/bsdtar',
  '/usr/bin/uname',
  '/usr/bin/xattr',
  '/usr/sbin/lsof',
]);

function canonicalAbsolute(path, label) {
  if (typeof path !== 'string'
    || !isAbsolute(path)
    || resolve(path) !== path
    || /[\0\r\n]/u.test(path)) reject(`${label} is not canonical`);
  return path;
}

export function guardedProductionGlobalLockPath(repositoryRoot, globalTemporaryRoot) {
  canonicalAbsolute(repositoryRoot, 'Guarded production repository root');
  canonicalAbsolute(globalTemporaryRoot, 'Guarded production global temporary root');
  return resolve(
    globalTemporaryRoot,
    'piui-architecture-gate-locks',
    `${sha256Bytes(Buffer.from(repositoryRoot, 'utf8'))}.lock`,
  );
}

export function guardedProductionOuterSandboxConfiguration({
  bootstrapRoot,
  command,
  isolateRoot,
  lockPath,
  outputRoot,
  repositoryRoot,
}) {
  for (const [path, label] of [
    [bootstrapRoot, 'Architecture bootstrap root'],
    [command, 'Authenticated Node command'],
    [isolateRoot, 'Guarded production package isolate'],
    [lockPath, 'Guarded production global lock'],
    [outputRoot, 'Guarded production output root'],
    [repositoryRoot, 'Guarded production repository root'],
  ]) canonicalAbsolute(path, label);
  const unique = (values) => Object.freeze([...new Set(values)].sort((left, right) => (
    Buffer.from(left).compare(Buffer.from(right))
  )));
  const appleToolchainAuthorityDirectories = [
    '/',
    '/Library',
    '/Library/Developer',
  ];
  const systemRuntimeRoots = [
    '/Library/Apple/System/Library',
    '/System/Library',
    '/private/var/db/timezone',
    '/usr/lib',
    '/usr/share/zoneinfo',
  ];
  const systemRuntimeFiles = [
    '/dev/null',
    '/dev/random',
    '/dev/urandom',
    '/dev/zero',
    '/private/etc/localtime',
    '/private/etc/ssl/openssl.cnf',
    '/private/var/select/sh',
  ];
  return Object.freeze({
    executableFiles: unique([
      command,
      ...guardedProductionAppleToolchainExecutables,
      ...guardedProductionSystemExecutables,
    ]),
    executableRoots: unique([
      resolve(isolateRoot, 'authenticated-toolchain'),
      resolve(isolateRoot, 'source/node_modules'),
      resolve(isolateRoot, 'source/src-tauri/binaries'),
      resolve(isolateRoot, 'source/src-tauri/target'),
      resolve(isolateRoot, 'tauri-build-tools'),
      resolve(isolateRoot, 'tmp'),
    ]),
    readableFiles: unique([
      command,
      lockPath,
      ...appleToolchainAuthorityDirectories,
      ...guardedProductionAppleToolchainExecutables,
      ...guardedProductionSystemExecutables,
      ...systemRuntimeFiles,
    ]),
    readableRoots: unique([
      bootstrapRoot,
      isolateRoot,
      outputRoot,
      repositoryRoot,
      APPLE_TOOLCHAIN_PATHS.root,
      ...systemRuntimeRoots,
    ]),
    writableFiles: Object.freeze([]),
    writableRoots: unique([isolateRoot, outputRoot]),
  });
}

const guardedProductionSandboxCanarySource = String.raw`
(async () => {
const { readFileSync, writeFileSync } = require('node:fs');
const { spawnSync } = require('node:child_process');
const { connect } = require('node:net');
const deniedCode = (error) => error?.code === 'EPERM' || error?.code === 'EACCES';
const deniedFile = (operation) => {
  try { operation(); return false; } catch (error) { return deniedCode(error); }
};
const deniedCommand = (path, args) => deniedCode(spawnSync(path, args, {
  encoding: 'utf8',
  env: { HOME: process.env.HOME, PATH: '/usr/bin:/bin', TMPDIR: process.env.TMPDIR },
  stdio: ['ignore', 'pipe', 'pipe'],
}).error);
const allowedCommand = (path, args) => {
  const result = spawnSync(path, args, {
    encoding: 'utf8',
    env: { HOME: process.env.HOME, PATH: process.env.PATH, TMPDIR: process.env.TMPDIR },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return !result.error && !result.signal && result.status === 0;
};
const loopbackDenied = await new Promise((complete) => {
  const socket = connect({ host: '127.0.0.1', port: 9 });
  let finished = false;
  const finish = (value) => {
    if (finished) return;
    finished = true;
    socket.destroy();
    complete(value);
  };
  socket.once('connect', () => finish(false));
  socket.once('error', (error) => finish(deniedCode(error)));
  socket.setTimeout(1_500, () => finish(false));
});
process.stdout.write(JSON.stringify({
  authenticatedParentReexecDenied: deniedCommand(process.execPath, ['--version']),
  clangShimExecutionDenied: deniedCommand('/usr/bin/clang', ['--version']),
  cltClangByBasenameAllowed: allowedCommand('clang', ['--version']),
  curlExecutionDenied: deniedCommand('/usr/bin/curl', ['--version']),
  loopbackDenied,
  securityIdentityDenied: deniedCommand('/usr/bin/security', ['find-identity', '-v', '-p', 'codesigning']),
  siblingHomeReadDenied: deniedFile(() => readFileSync(process.env.PIUI_CANARY_SIBLING_HOME_READ)),
  siblingHomeWriteDenied: deniedFile(() => writeFileSync(process.env.PIUI_CANARY_SIBLING_HOME_WRITE, 'denied\n', { flag: 'wx' })),
  siblingTemporaryReadDenied: deniedFile(() => readFileSync(process.env.PIUI_CANARY_SIBLING_TMP_READ)),
  siblingTemporaryWriteDenied: deniedFile(() => writeFileSync(process.env.PIUI_CANARY_SIBLING_TMP_WRITE, 'denied\n', { flag: 'wx' })),
  xcrunExecutionDenied: deniedCommand('/usr/bin/xcrun', ['--version']),
}) + '\n');
})().catch(() => { process.exitCode = 1; });
`;

async function writeExclusivePrivateFile(path, bytes) {
  const handle = await open(
    path,
    fsConstants.O_WRONLY
      | fsConstants.O_CREAT
      | fsConstants.O_EXCL
      | (fsConstants.O_NOFOLLOW ?? 0),
    0o600,
  );
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function prepareGuardedPackageIsolate(repositoryRoot) {
  const root = await createPrivateTemporary('piui-guarded-package-');
  let descriptor;
  try {
    const home = await createFreshPrivateChild(root, 'home', 'Guarded production package home');
    const temporary = await createFreshPrivateChild(root, 'tmp', 'Guarded production package temporary root');
    descriptor = await open(
      root.path,
      fsConstants.O_RDONLY
        | (fsConstants.O_NOFOLLOW ?? 0)
        | (fsConstants.O_DIRECTORY ?? 0),
    );
    const held = await descriptor.stat({ bigint: true });
    const pathname = await assertDirectory(
      root.path,
      'Guarded production package isolate',
      { exactPrivate: true },
    );
    if (!sameDirectoryIdentity(held, pathname)) {
      reject('Guarded production package isolate descriptor identity changed');
    }
    return Object.freeze({
      descriptor,
      dev: held.dev,
      home: home.path,
      identity: pathname,
      ino: held.ino,
      path: root.path,
      repositoryRoot,
      temporary: temporary.path,
    });
  } catch (error) {
    if (descriptor) await descriptor.close();
    try {
      await removePrivateTemporary(root);
    } catch (cleanupError) {
      throw combineFailures(
        'Guarded package isolate preparation and cleanup failed',
        error,
        cleanupError,
      );
    }
    throw error;
  }
}

async function prepareGuardedSandboxCanary() {
  const root = await createPrivateTemporary('piui-guarded-sandbox-canary-');
  try {
    const home = await createFreshPrivateChild(root, 'home', 'Guarded sandbox sibling home');
    const temporary = await createFreshPrivateChild(root, 'tmp', 'Guarded sandbox sibling temporary root');
    const homeRead = resolve(home.path, 'private.txt');
    const temporaryRead = resolve(temporary.path, 'private.txt');
    await writeExclusivePrivateFile(homeRead, Buffer.from('sibling-home-canary\n', 'utf8'));
    await writeExclusivePrivateFile(temporaryRead, Buffer.from('sibling-temporary-canary\n', 'utf8'));
    return Object.freeze({
      homeRead,
      homeWrite: resolve(home.path, 'write-denied.txt'),
      root,
      temporaryRead,
      temporaryWrite: resolve(temporary.path, 'write-denied.txt'),
    });
  } catch (error) {
    try {
      await removePrivateTemporary(root);
    } catch (cleanupError) {
      throw combineFailures(
        'Guarded sandbox canary preparation and cleanup failed',
        error,
        cleanupError,
      );
    }
    throw error;
  }
}

function assertGuardedSandboxCanary(bytes) {
  let result;
  try {
    result = JSON.parse(bytes.toString('utf8'));
  } catch {
    reject('Guarded production sandbox canary result is invalid');
  }
  const keys = [
    'authenticatedParentReexecDenied',
    'clangShimExecutionDenied',
    'cltClangByBasenameAllowed',
    'curlExecutionDenied',
    'loopbackDenied',
    'securityIdentityDenied',
    'siblingHomeReadDenied',
    'siblingHomeWriteDenied',
    'siblingTemporaryReadDenied',
    'siblingTemporaryWriteDenied',
    'xcrunExecutionDenied',
  ];
  exactKeys(result, keys, 'Guarded production sandbox canary result');
  if (`${JSON.stringify(result)}\n` !== bytes.toString('utf8')
    || keys.some((key) => result[key] !== true)) {
    const missed = keys.filter((key) => result[key] !== true);
    reject(`Guarded production outer sandbox canaries did not all deny: ${missed.join(',')}`);
  }
  return Object.freeze({ ...result });
}

export async function runGuardedProductionOuterSandboxCanary({
  canary,
  command,
  home,
  inheritedFds,
  profile,
  repositoryRoot,
  signal,
  temporary,
}) {
  const result = await runOwnedCommand({
    command,
    args: ['-e', guardedProductionSandboxCanarySource],
    cwd: repositoryRoot,
    env: {
      HOME: home,
      LANG: 'en_AU.UTF-8',
      LC_ALL: 'en_AU.UTF-8',
      PATH: `${APPLE_TOOLCHAIN_PATHS.bin}:/usr/bin:/bin:/usr/sbin:/sbin`,
      PIUI_CANARY_SIBLING_HOME_READ: canary.homeRead,
      PIUI_CANARY_SIBLING_HOME_WRITE: canary.homeWrite,
      PIUI_CANARY_SIBLING_TMP_READ: canary.temporaryRead,
      PIUI_CANARY_SIBLING_TMP_WRITE: canary.temporaryWrite,
      TMPDIR: `${temporary}/`,
    },
    inheritedFds,
    label: 'Guarded production outer sandbox denial canaries',
    maxOutputBytes: 16 * 1_024,
    sandboxProfile: profile,
    signal,
    timeoutMs: 30_000,
  });
  if (result.status !== 0
    || result.signal !== null
    || result.stderr.length !== 0
    || result.forcedCleanup) reject('Guarded production outer sandbox canaries failed');
  return assertGuardedSandboxCanary(result.stdout);
}

async function assertGuardedPackageIsolateConsumed(isolate) {
  const held = await isolate.descriptor.stat({ bigint: true });
  if (!held.isDirectory()
    || held.isSymbolicLink()
    || held.dev !== isolate.dev
    || held.ino !== isolate.ino
    || held.uid !== BigInt(process.getuid())
    || (held.mode & 0o777n) !== 0o700n
    || held.nlink !== 0n) {
    reject('Guarded production package isolate was not consumed exactly');
  }
  await assertPathMissing(isolate.path, 'Guarded production package isolate');
}

async function releaseGuardedPackageIsolate(isolate) {
  let pathState;
  try {
    pathState = await lstat(isolate.path, { bigint: true });
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  const held = await isolate.descriptor.stat({ bigint: true });
  let cleanupError;
  if (pathState !== undefined && (!pathState.isDirectory()
    || pathState.isSymbolicLink()
    || pathState.dev !== isolate.dev
    || pathState.ino !== isolate.ino
    || held.dev !== isolate.dev
    || held.ino !== isolate.ino)) {
    cleanupError = new Error('Guarded production package isolate pathname identity changed');
  }
  await isolate.descriptor.close();
  if (cleanupError) throw cleanupError;
  if (pathState !== undefined) {
    await removePrivateTemporary(isolate.identity);
  }
}

async function defaultPackageExecutor({ gate, outputRoot, repositoryRoot, signal }) {
  const architectureBootstrap = assertArchitectureBootstrap({ repositoryRoot });
  const bootstrap = architectureBootstrapChildOptions(repositoryRoot);
  const globalTemporaryRoot = await realpath(tmpdir());
  const globalLockPath = guardedProductionGlobalLockPath(
    repositoryRoot,
    globalTemporaryRoot,
  );
  let canary;
  let isolate;
  let globalLock;
  let primaryError;
  let parsed;
  try {
    isolate = await prepareGuardedPackageIsolate(repositoryRoot);
    globalLock = await acquireOwnedLock(globalLockPath, {
      label: 'Guarded production global package lease',
      timeoutMs: 0,
    });
    canary = await prepareGuardedSandboxCanary();
    const profile = createAuthenticatedNodeGuardedProductionSandboxProfile({
      command: process.execPath,
      ...guardedProductionOuterSandboxConfiguration({
        bootstrapRoot: architectureBootstrap.receipt.privateRoot,
        command: process.execPath,
        isolateRoot: isolate.path,
        lockPath: globalLockPath,
        outputRoot,
        repositoryRoot,
      }),
    });
    const inheritedFds = Object.freeze([
      ...bootstrap.inheritedFds,
      isolate.descriptor.fd,
      globalLock.fd,
    ]);
    await runGuardedProductionOuterSandboxCanary({
      canary,
      command: process.execPath,
      home: isolate.home,
      inheritedFds: [],
      profile,
      repositoryRoot,
      signal,
      temporary: isolate.temporary,
    });
    await removePrivateTemporary(canary.root);
    canary = undefined;
    const command = await runOwnedCommand({
      command: process.execPath,
      args: [
        resolve(repositoryRoot, 'scripts/package-spike.mjs'),
        '--guarded-production-build',
      ],
      cwd: repositoryRoot,
      env: {
        HOME: isolate.home,
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
        PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
        ...bootstrap.environment,
        PIUI_ARCHITECTURE_SOURCE_DIGEST: gate.sourceDigest,
        PIUI_GUARDED_PRODUCTION_GLOBAL_LOCK_DEV: String(globalLock.dev),
        PIUI_GUARDED_PRODUCTION_GLOBAL_LOCK_FD: String(globalLock.fd),
        PIUI_GUARDED_PRODUCTION_GLOBAL_LOCK_INO: String(globalLock.ino),
        PIUI_GUARDED_PRODUCTION_GLOBAL_LOCK_PATH: globalLockPath,
        PIUI_GUARDED_PRODUCTION_OUTPUT_ROOT: outputRoot,
        PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE: isolate.path,
        PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE_DEV: isolate.dev.toString(10),
        PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE_FD: String(isolate.descriptor.fd),
        PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE_INO: isolate.ino.toString(10),
        TMPDIR: `${isolate.temporary}/`,
      },
      label: 'Authenticated frozen production package build',
      inheritedFds,
      maxOutputBytes: 256 * 1024,
      sandboxProfile: profile,
      signal,
      timeoutMs: 90 * 60_000,
    });
    if (command.status !== 0
      || command.signal !== null
      || command.stderr.length !== 0
      || command.forcedCleanup) reject('Authenticated frozen production package build failed');
    parsed = parseGuardedProductionResult(command.stdout, {
      expectedFingerprint: gate.productionFingerprint,
      expectedRunId: gate.runId,
      expectedSourceDigest: gate.sourceDigest,
      requireCleanup: true,
    });
    await assertGuardedPackageIsolateConsumed(isolate);
  } catch (error) {
    primaryError = error;
  }
  const cleanupFailures = [];
  if (canary) {
    try {
      await removePrivateTemporary(canary.root);
    } catch (error) {
      cleanupFailures.push(error);
    }
  }
  if (isolate) {
    try {
      await releaseGuardedPackageIsolate(isolate);
    } catch (error) {
      cleanupFailures.push(error);
    }
  }
  if (globalLock) {
    try {
      await releaseOwnedLock(globalLock);
    } catch (error) {
      cleanupFailures.push(error);
    }
  }
  if (primaryError || cleanupFailures.length > 0) {
    throw combineFailures(
      'Guarded production package execution or cleanup failed',
      primaryError,
      ...cleanupFailures,
    );
  }
  return parsed;
}

async function writeBuildRecord(path, record) {
  const bytes = Buffer.from(`${canonicalArchitectureJson(record)}\n`, 'utf8');
  const flags = fsConstants.O_RDWR
    | fsConstants.O_CREAT
    | fsConstants.O_EXCL
    | (fsConstants.O_NOFOLLOW ?? 0);
  const handle = await open(path, flags, 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
    const state = await handle.stat({ bigint: true });
    const expectedUid = typeof process.getuid === 'function' ? BigInt(process.getuid()) : null;
    if (expectedUid === null
      || !state.isFile()
      || state.isSymbolicLink()
      || state.nlink !== 1n
      || state.uid !== expectedUid
      || (state.mode & 0o777n) !== 0o600n
      || state.size !== BigInt(bytes.length)) reject('Production build record is unsafe');
    const stored = Buffer.alloc(bytes.length);
    let offset = 0;
    while (offset < stored.length) {
      const { bytesRead } = await handle.read(
        stored,
        offset,
        stored.length - offset,
        offset,
      );
      if (bytesRead < 1) reject('Production build record could not be reread');
      offset += bytesRead;
    }
    const pathState = await lstat(path, { bigint: true });
    if (pathState.isSymbolicLink()
      || pathState.dev !== state.dev
      || pathState.ino !== state.ino
      || pathState.mode !== state.mode
      || pathState.uid !== state.uid
      || pathState.gid !== state.gid
      || pathState.nlink !== state.nlink
      || pathState.size !== state.size
      || pathState.mtimeNs !== state.mtimeNs
      || pathState.ctimeNs !== state.ctimeNs
      || !stored.equals(bytes)) reject('Production build record changed during publication');
    assertNoAcl(path, 'Production build record');
  } finally {
    await handle.close();
  }
  return sha256Bytes(bytes);
}

async function assertBuildRecordSha256(path, expectedSha256) {
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  const handle = await open(path, flags);
  try {
    const before = await handle.stat({ bigint: true });
    const expectedUid = typeof process.getuid === 'function' ? BigInt(process.getuid()) : null;
    if (expectedUid === null
      || !before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1n
      || before.uid !== expectedUid
      || (before.mode & 0o777n) !== 0o600n
      || before.size < 3n
      || before.size > 64n * 1024n) reject('Production build record is unsafe');
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (BigInt(bytes.length) !== before.size
      || after.dev !== before.dev
      || after.ino !== before.ino
      || after.mode !== before.mode
      || after.uid !== before.uid
      || after.gid !== before.gid
      || after.nlink !== before.nlink
      || after.size !== before.size
      || after.mtimeNs !== before.mtimeNs
      || after.ctimeNs !== before.ctimeNs
      || pathAfter.isSymbolicLink()
      || pathAfter.dev !== after.dev
      || pathAfter.ino !== after.ino
      || pathAfter.mode !== after.mode
      || pathAfter.uid !== after.uid
      || pathAfter.gid !== after.gid
      || pathAfter.nlink !== after.nlink
      || pathAfter.size !== after.size
      || pathAfter.mtimeNs !== after.mtimeNs
      || pathAfter.ctimeNs !== after.ctimeNs
      || sha256Bytes(bytes) !== expectedSha256) {
      reject('Production build record changed after its atomic rename');
    }
    assertNoAcl(path, 'Production build record');
  } finally {
    await handle.close();
  }
}

async function validateGateAndSource({ gateValidator, repositoryRoot, snapshotter }, expected) {
  const gate = assertGateSummary(await gateValidator(repositoryRoot));
  const source = await snapshotter(repositoryRoot);
  assertSourceBoundToGate(source, gate);
  if (expected
    && (!sameGate(gate, expected.gate) || !sameSource(source, expected.source))) {
    reject('Architecture gate or source changed during the guarded production build');
  }
  return Object.freeze({ gate, source });
}

async function validateAfterInfrastructureCreation(dependencies, expected) {
  const current = await validateGateAndSource(dependencies);
  if (!sameGate(current.gate, expected.gate)
    || (!sameSource(current.source, expected.source)
      && !isControlledForgeInfrastructureTransition(expected.source, current.source))) {
    reject('Architecture gate or source changed while preparing production output');
  }
  return current;
}

export async function buildGuardedProduction(repositoryRootPath, {
  bundleCopier = copySealedBundle,
  bundleInventory = inventoryBundle,
  directorySynchroniser = syncDirectory,
  gateValidator = validateLatestArchitectureGate,
  nonceFactory = () => randomBytes(16).toString('hex'),
  now = () => new Date(),
  packageExecutor = defaultPackageExecutor,
  publicationRenamer = exclusiveDirectoryRename,
  signal,
  snapshotter = snapshotArchitectureSource,
  stagingCleaner = removePrivateTemporary,
  temporaryFactory = createPrivateTemporary,
} = {}) {
  if (typeof repositoryRootPath !== 'string'
    || !isAbsolute(repositoryRootPath)
    || resolve(repositoryRootPath) !== repositoryRootPath) reject('Repository root is not canonical');
  const repositoryRoot = repositoryRootPath;
  const repository = await assertDirectory(repositoryRoot, 'Repository root');
  const forge = await assertDirectory(resolve(repositoryRoot, '.forge'), '.forge directory');
  const beforeInfrastructure = await validateGateAndSource({
    gateValidator,
    repositoryRoot,
    snapshotter,
  });
  const artifacts = await ensurePrivateChild(
    { ...forge, exactPrivate: false },
    'artifacts',
    'Architecture artefact directory',
  );
  const builds = await ensurePrivateChild(
    artifacts,
    'production-builds',
    'Production build directory',
  );
  const initial = await validateAfterInfrastructureCreation({
    gateValidator,
    repositoryRoot,
    snapshotter,
  }, beforeInfrastructure);
  let incoming;
  let incomingLease;
  let incomingOwned = false;
  let incomingPath;
  let prepared;
  let primaryError;
  let staging;
  let stagingBundleLease;
  let stagingLease;
  let publicationStem;
  try {
    staging = await temporaryFactory('piui-production-output-');
    await assertDirectoryMatches(staging, 'Guarded production staging root', {
      exactLease: true,
      exactPrivate: true,
    });
    const result = assertGuardedProductionResult(await packageExecutor({
      gate: initial.gate,
      outputRoot: staging.path,
      repositoryRoot,
      signal,
    }), {
      expectedFingerprint: initial.gate.productionFingerprint,
      expectedRunId: initial.gate.runId,
      expectedSourceDigest: initial.gate.sourceDigest,
      requireCleanup: true,
    });
    stagingLease = await assertDirectoryMatches(
      staging,
      'Guarded production staging root',
      { exactPrivate: true },
    );
    const stagingEntries = await assertExactEntries(staging.path, ['PIUI.app']);
    await assertDirectoryMatches(stagingLease, 'Guarded production staging root', {
      exactLease: true,
      exactPrivate: true,
    });
    if (!stagingEntries[0]?.isDirectory()) reject('Guarded production staging bundle is invalid');
    const stagedBundle = resolve(staging.path, 'PIUI.app');
    const stagedInventory = await bundleInventory(stagedBundle);
    stagingBundleLease = await snapshotTreeLease(stagedBundle);
    await assertDirectoryMatches(stagingLease, 'Guarded production staging root', {
      exactLease: true,
      exactPrivate: true,
    });
    if (stagedInventory.fingerprint !== initial.gate.productionFingerprint
      || result.artifact.fingerprint !== stagedInventory.fingerprint) {
      reject('Built production bundle does not match the recorded architecture artefact');
    }
    await validateGateAndSource(
      { gateValidator, repositoryRoot, snapshotter },
      initial,
    );

    const repositoryAfterBuild = await assertDirectory(repository.path, 'Repository root');
    const forgeAfterBuild = await assertDirectory(forge.path, '.forge directory');
    if (!sameDirectoryAnchor(repositoryAfterBuild, repository)
      || !sameDirectoryAnchor(forgeAfterBuild, forge)) {
      reject('Repository control directory identity changed');
    }
    const nonce = nonceFactory();
    if (typeof nonce !== 'string' || !/^[0-9a-f]{32}$/u.test(nonce)) reject('Production build nonce is invalid');
    publicationStem = `${initial.gate.runId}-${nonce}`;
    const finalPath = resolve(builds.path, publicationStem);
    await assertPathMissing(finalPath, 'Final production publication');
    incomingPath = resolve(builds.path, `.incoming-${publicationStem}`);
    incoming = await createFreshPrivateChild(
      builds,
      basename(incomingPath),
      'Incoming production publication',
    );
    incomingOwned = true;
    await assertExactEntries(incoming.path, []);
    const incomingBundle = resolve(incoming.path, 'PIUI.app');
    await assertDirectoryMatches(stagingLease, 'Guarded production staging root', {
      exactLease: true,
      exactPrivate: true,
    });
    await assertTreeLease(stagingBundleLease);
    await bundleCopier({
      destination: incomingBundle,
      source: stagedBundle,
    });
    await assertDirectoryMatches(stagingLease, 'Guarded production staging root', {
      exactLease: true,
      exactPrivate: true,
    });
    await assertTreeLease(stagingBundleLease);
    const copiedInventory = await bundleInventory(incomingBundle);
    if (copiedInventory.fingerprint !== initial.gate.productionFingerprint) {
      reject('Copied production bundle fingerprint changed');
    }
    const copiedBundleLease = await snapshotTreeLease(incomingBundle);
    await syncOwnedTree(copiedBundleLease);
    const sourceAfterCopy = await bundleInventory(stagedBundle);
    if (sourceAfterCopy.fingerprint !== stagedInventory.fingerprint) {
      reject('Staged production bundle changed during its copy');
    }
    await assertDirectoryMatches(stagingLease, 'Guarded production staging root', {
      exactLease: true,
      exactPrivate: true,
    });
    await assertTreeLease(stagingBundleLease);
    await assertExactEntries(incoming.path, ['PIUI.app']);
    await validateGateAndSource(
      { gateValidator, repositoryRoot, snapshotter },
      initial,
    );
    const finalInventory = await bundleInventory(incomingBundle);
    if (finalInventory.fingerprint !== initial.gate.productionFingerprint) {
      reject('Production bundle changed before its append-only record was written');
    }
    await assertTreeLease(copiedBundleLease);

    const builtAt = now();
    if (!(builtAt instanceof Date) || Number.isNaN(builtAt.valueOf())) reject('Production build time is invalid');
    const record = Object.freeze({
      artifact: result.artifact,
      builtAt: builtAt.toISOString(),
      bundleDirectory: 'PIUI.app',
      distributionAuthorised: false,
      gateRunId: initial.gate.runId,
      schemaVersion: 1,
      sourceDigest: initial.gate.sourceDigest,
      status: 'pass',
      target: TARGET,
    });
    const incomingRecord = resolve(incoming.path, 'build.json');
    const recordSha256 = await writeBuildRecord(incomingRecord, record);
    await assertExactEntries(incoming.path, ['PIUI.app', 'build.json']);
    await directorySynchroniser(incoming.path);
    incomingLease = await assertDirectoryMatches(
      incoming,
      'Incoming production publication',
      { exactPrivate: true },
    );
    prepared = Object.freeze({
      finalPath,
      incomingBundle,
      copiedBundleLease,
      recordSha256,
      result: Object.freeze({
        buildRecord: relative(repositoryRoot, resolve(finalPath, 'build.json')).split('/').join('/'),
        bundlePath: relative(repositoryRoot, resolve(finalPath, 'PIUI.app')).split('/').join('/'),
        distributionAuthorised: false,
        gateRunId: initial.gate.runId,
        productionFingerprint: initial.gate.productionFingerprint,
        recordSha256,
        schemaVersion: 1,
        sourceDigest: initial.gate.sourceDigest,
        status: 'pass',
      }),
    });
  } catch (error) {
    primaryError = error;
  }

  let cleanupError;
  if (staging) {
    try {
      await stagingCleaner(staging, stagingLease);
      await assertPathMissing(staging.path, 'Guarded production staging root');
    } catch (error) {
      cleanupError = error;
    }
  }
  if (primaryError || cleanupError) {
    let retentionError;
    try {
      await retainFailedPublication({
        builds,
        directorySynchroniser,
        incoming,
        incomingPath: incomingOwned ? incomingPath : undefined,
        publicationRenamer,
        publicationStem,
      });
    } catch (error) {
      retentionError = error;
    }
    throw combineFailures(
      'Guarded production build, cleanup or evidence retention failed',
      primaryError,
      cleanupError,
      retentionError,
    );
  }
  if (!prepared || !incoming || !incomingLease || !staging) reject();

  try {
    await assertDirectoryMatches(incomingLease, 'Incoming production publication', {
      exactLease: true,
      exactPrivate: true,
    });
    await assertExactEntries(incoming.path, ['PIUI.app', 'build.json']);
    const finalInventory = await bundleInventory(prepared.incomingBundle);
    if (finalInventory.fingerprint !== initial.gate.productionFingerprint) {
      reject('Production bundle changed before atomic publication');
    }
    await assertTreeLease(prepared.copiedBundleLease);
    await validateGateAndSource(
      { gateValidator, repositoryRoot, snapshotter },
      initial,
    );
    await assertDirectoryMatches(incomingLease, 'Incoming production publication', {
      exactLease: true,
      exactPrivate: true,
    });
    await assertPathMissing(prepared.finalPath, 'Final production publication');
    await assertDirectoryMatches(builds, 'Production build directory', {
      exactPrivate: true,
    });
    await publicationRenamer(incoming.path, prepared.finalPath, {
      expectedParentIdentity: builds,
      expectedSourceIdentity: incoming,
    });
    await assertPathMissing(incoming.path, 'Committed incoming production publication');
    await validateCompletePublication({
      bundleInventory,
      expectedFingerprint: initial.gate.productionFingerprint,
      expectedIncoming: incoming,
      prepared,
      publicationPath: prepared.finalPath,
    });
    await directorySynchroniser(builds.path);
    incomingOwned = false;
    incomingPath = undefined;
    return prepared.result;
  } catch (error) {
    let retentionError;
    try {
      await retainFailedPublication({
        alternatePath: prepared.finalPath,
        builds,
        candidateValidator: async (publicationPath) => validateCompletePublication({
          bundleInventory,
          expectedFingerprint: initial.gate.productionFingerprint,
          expectedIncoming: incoming,
          prepared,
          publicationPath,
        }),
        directorySynchroniser,
        incoming,
        incomingPath: incomingOwned ? incomingPath : undefined,
        publicationRenamer,
        publicationStem,
      });
    } catch (failure) {
      retentionError = failure;
    }
    throw combineFailures(
      'Guarded production publication or evidence retention failed',
      error,
      retentionError,
    );
  }
}

function safeMessage(error) {
  const message = error instanceof Error ? error.message : 'Guarded production build rejected';
  return message.replace(/[\r\n]+/gu, ' ').slice(0, 320);
}

const invokedPath = process.argv[1] ? await realpath(process.argv[1]) : undefined;
if (invokedPath === await realpath(fileURLToPath(import.meta.url))) {
  const cutoffs = installParentCutoffs();
  let bootstrapAccepted = false;
  try {
    const bootstrap = assertArchitectureBootstrap({ repositoryRoot: root });
    bootstrapAccepted = true;
    if (process.argv.length !== 2) reject('Unsupported production build arguments');
    if (platform() !== 'darwin' || arch() !== 'arm64') {
      reject('Guarded production build requires Apple Silicon macOS');
    }
    const source = await snapshotArchitectureSource(root);
    configureAuthenticatedNodeSpawn(await createAuthenticatedNodeSpawnConfiguration({
      nodePath: bootstrap.receipt.nodePath,
      snapshot: source,
      sourceRoot: root,
    }));
    const result = await buildGuardedProduction(root, { signal: cutoffs.signal });
    process.stdout.write(`${canonicalArchitectureJson(result)}\n`);
  } catch (error) {
    process.stderr.write(`${safeMessage(error)}\n`);
    process.exitCode = 1;
  } finally {
    cutoffs.dispose();
    if (bootstrapAccepted) releaseArchitectureBootstrap();
  }
}
