import { spawn } from 'node:child_process';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readSync,
  realpathSync,
} from 'node:fs';
import { chmod, lstat, mkdir, open, readFile, readdir, realpath, rm } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import { isDeepStrictEqual } from 'node:util';
import { NODE_PATH, SIDECAR_ROOT, revalidateBundle, sha256 } from '../tests/packaged/bundle-inspection.mjs';
import {
  ProcessLedger,
  installParentCutoffs,
  isProcessObservationFailure,
  runOwnedCommand,
  terminateRecordedProcessGroupsWithoutObservation,
  waitForChildSpawn,
} from './a21-gate-support.mjs';
import {
  assertDescriptorHasNoAcl,
  captureSystemDescriptorAclInspector,
  removeDescriptorBoundTree,
  revalidateSystemDescriptorAclInspector,
} from './descriptor-acl.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE_FIXTURE = resolve(root, 'tests/fixtures/hostile-project');
const HARNESS_RELATIVE = 'src-tauri/target/aarch64-apple-darwin/release/project-trust-harness';
const MAX_OUTPUT_BYTES = 65_536;
const MAX_FIXTURE_ENTRIES = 64;
const MAX_FIXTURE_BYTES = 1024 * 1024;
const MAX_FIXTURE_DEPTH = 8;
const HARNESS_DEADLINE_MS = 6 * 60_000;
const MARKERS = new Set(['import-marker.log', 'skill-marker.log', 'package-marker.log']);
const HARNESS_KEYS = [
  'schemaVersion',
  'packagedRuntimeValidated',
  'metadataInspections',
  'untrustedLoadRejections',
  'projectTrustAuthorisations',
  'sentinelWorkspaceAuthorisations',
  'authoriseExecutions',
  'sidecarGenerationRestarted',
  'sidecarGenerationRestarts',
  'trustedLoadExecutions',
  'markerBytes',
  'markerLines',
  'concurrentReplayRequests',
  'cachedReplayResults',
  'skillCanaryExecutions',
  'packageCanaryExecutions',
  'settingsCanaryLoads',
  'ancestorCanaryLoads',
  'projectTrustApprovalPolicyMutations',
  'approvalRecordsBeforeTrust',
  'approvalRecordsAfterTrust',
  'rememberedApprovalScopes',
  'groupApprovalScopes',
  'blanketApprovalScopes',
  'approvalSentinelUnchangedThroughTrustedLoad',
  'revocations',
  'postRevokeLoadRejections',
  'staleGenerationRejections',
  'staleRevisionRejections',
  'staleLeaseRejections',
  'sourceMarkerExecutions',
  'fixtureInventoryUnchanged',
];
const EXPECTED = Object.freeze({
  schemaVersion: 1,
  packagedRuntimeValidated: true,
  metadataInspections: 1,
  untrustedLoadRejections: 1,
  projectTrustAuthorisations: 1,
  sentinelWorkspaceAuthorisations: 1,
  authoriseExecutions: 0,
  sidecarGenerationRestarted: true,
  sidecarGenerationRestarts: 2,
  trustedLoadExecutions: 1,
  markerBytes: 9,
  markerLines: 1,
  concurrentReplayRequests: 16,
  cachedReplayResults: 16,
  skillCanaryExecutions: 0,
  packageCanaryExecutions: 0,
  settingsCanaryLoads: 0,
  ancestorCanaryLoads: 0,
  projectTrustApprovalPolicyMutations: 0,
  approvalRecordsBeforeTrust: 0,
  approvalRecordsAfterTrust: 0,
  rememberedApprovalScopes: 0,
  groupApprovalScopes: 0,
  blanketApprovalScopes: 0,
  approvalSentinelUnchangedThroughTrustedLoad: true,
  revocations: 1,
  postRevokeLoadRejections: 1,
  staleGenerationRejections: 1,
  staleRevisionRejections: 1,
  staleLeaseRejections: 1,
  sourceMarkerExecutions: 0,
  fixtureInventoryUnchanged: true,
});

function fail() {
  throw new Error('A.24 packaged trust probe rejected');
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || !isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort())) fail();
}

function parseOneLine(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 3 || bytes.length > MAX_OUTPUT_BYTES) fail();
  const text = bytes.toString('utf8');
  if (Buffer.from(text, 'utf8').length !== bytes.length || !/^[^\r\n]+\n$/.test(text)) fail();
  try { return JSON.parse(text.slice(0, -1)); } catch { fail(); }
}

/** Strictly normalise the path-free evidence emitted by the Rust harness. */
export function parseProjectTrustHarnessEvidence(bytes) {
  const value = parseOneLine(bytes);
  exactKeys(value, HARNESS_KEYS);
  for (const key of HARNESS_KEYS) {
    const expected = EXPECTED[key];
    if (value[key] !== expected || typeof value[key] !== typeof expected) fail();
  }
  return Object.freeze({ ...EXPECTED });
}

/** Strictly parse the formal package command after all JS/package cleanup. */
export function parsePackagedTrustEvidence(bytes) {
  const value = parseOneLine(bytes);
  exactKeys(value, [...HARNESS_KEYS, 'runnerIsolateRemoved', 'generatedOutputsRemoved']);
  if (value.runnerIsolateRemoved !== true || value.generatedOutputsRemoved !== true) fail();
  const harness = {};
  for (const key of HARNESS_KEYS) harness[key] = value[key];
  parseProjectTrustHarnessEvidence(Buffer.from(`${JSON.stringify(harness)}\n`));
  return Object.freeze({ ...EXPECTED, runnerIsolateRemoved: true, generatedOutputsRemoved: true });
}

async function readIdentityBoundFile(path, expected, aclInspector) {
  if (!aclInspector) fail();
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1 || (before.mode & 0o022) !== 0
      || (typeof process.getuid === 'function' && before.uid !== process.getuid())
      || (expected && (before.dev !== expected.dev || before.ino !== expected.ino
        || before.size !== expected.size))) fail();
    assertDescriptorHasNoAcl(handle.fd, aclInspector);
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (!after.isFile() || after.dev !== before.dev || after.ino !== before.ino
      || after.size !== before.size || bytes.length !== before.size) fail();
    assertDescriptorHasNoAcl(handle.fd, aclInspector);
    const pathAfter = await lstat(path);
    if (pathAfter.isSymbolicLink() || pathAfter.dev !== after.dev || pathAfter.ino !== after.ino) fail();
    const identity = Object.freeze({
      dev: before.dev,
      ino: before.ino,
      size: before.size,
      mode: before.mode & 0o777,
      sha256: sha256(bytes),
    });
    if (expected && ((expected.sha256 !== undefined && identity.sha256 !== expected.sha256)
      || (expected.mode !== undefined && identity.mode !== expected.mode))) fail();
    return Object.freeze({ bytes, identity });
  } finally {
    await handle?.close();
  }
}

/** Bind the release harness produced by the same target build as the app. */
export async function captureProjectTrustHarness(sourceRoot = root) {
  const path = resolve(sourceRoot, HARNESS_RELATIVE);
  const aclInspector = captureSystemDescriptorAclInspector();
  const read = await readIdentityBoundFile(path, undefined, aclInspector);
  if ((read.identity.mode & 0o111) === 0 || read.identity.size < 4096) fail();
  return Object.freeze({ path, ...read.identity, aclInspector });
}

function safeRelative(rootPath, path) {
  const value = relative(rootPath, path);
  if (value === '..' || value.startsWith(`..${sep}`) || resolve(rootPath, value || '.') !== path) fail();
  return value.split(sep).join('/');
}

export async function captureFixture(rootPath, { retainBytes = false, aclInspector } = {}) {
  if (!aclInspector) fail();
  const requested = resolve(rootPath);
  const requestedItem = await lstat(requested);
  if (!requestedItem.isDirectory() || requestedItem.isSymbolicLink()) fail();
  const canonical = await realpath(requested);
  const canonicalItem = await lstat(canonical);
  if (canonical !== requested || canonicalItem.dev !== requestedItem.dev || canonicalItem.ino !== requestedItem.ino) fail();
  const entries = [];
  let bytesTotal = 0;

  async function visit(path, depth) {
    if (depth > MAX_FIXTURE_DEPTH || entries.length >= MAX_FIXTURE_ENTRIES) fail();
    const before = await lstat(path);
    const rel = safeRelative(canonical, path);
    if (before.isSymbolicLink() || (!before.isDirectory() && !before.isFile())
      || (typeof process.getuid === 'function' && before.uid !== process.getuid())
      || (before.mode & 0o022) !== 0) fail();
    if (MARKERS.has(rel)) fail();
    if (before.isDirectory()) {
      const fd = openSync(
        path,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
      );
      try {
        const opened = fstatSync(fd);
        if (!opened.isDirectory() || opened.dev !== before.dev || opened.ino !== before.ino) fail();
        assertDescriptorHasNoAcl(fd, aclInspector);
        const children = (await readdir(path))
          .sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
        entries.push(Object.freeze({ path: rel, kind: 'directory', mode: before.mode & 0o777,
          dev: before.dev, ino: before.ino, size: 0, sha256: null }));
        for (const name of children) await visit(resolve(path, name), depth + 1);
        assertDescriptorHasNoAcl(fd, aclInspector);
        const after = await lstat(path);
        const openedAfter = fstatSync(fd);
        if (!after.isDirectory() || after.isSymbolicLink()
          || after.dev !== before.dev || after.ino !== before.ino
          || openedAfter.dev !== opened.dev || openedAfter.ino !== opened.ino) fail();
      } finally {
        closeSync(fd);
      }
      return;
    }
    const read = await readIdentityBoundFile(path, {
      dev: before.dev, ino: before.ino, size: before.size, mode: before.mode & 0o777,
    }, aclInspector);
    bytesTotal += read.bytes.length;
    if (bytesTotal > MAX_FIXTURE_BYTES) fail();
    entries.push(Object.freeze({ path: rel, kind: 'file', ...read.identity,
      bytes: retainBytes ? read.bytes : undefined }));
  }

  await visit(canonical, 0);
  entries.sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
  return Object.freeze({ root: canonical, entries: Object.freeze(entries), bytesTotal });
}

function fixtureComparison(inventory) {
  return inventory.entries.map(({ bytes: _bytes, ...entry }) => entry);
}

function sameFixture(left, right) {
  return left.root === right.root && left.bytesTotal === right.bytesTotal
    && isDeepStrictEqual(fixtureComparison(left), fixtureComparison(right));
}

async function writeFixtureCopy(source, destination, aclInspector) {
  await mkdir(destination, { mode: 0o700 });
  for (const entry of source.entries) {
    if (!entry.path) continue;
    const path = resolve(destination, entry.path);
    if (!safeRelative(destination, path)) fail();
    if (entry.kind === 'directory') {
      await mkdir(path, { mode: 0o700 });
      await chmod(path, 0o700);
      const fd = openSync(
        path,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
      );
      try {
        assertDescriptorHasNoAcl(fd, aclInspector);
      } finally {
        closeSync(fd);
      }
    } else {
      let handle;
      try {
        handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
        await handle.writeFile(entry.bytes);
        await handle.sync();
        await handle.chmod(0o600);
        const item = await handle.stat();
        if (!item.isFile() || item.nlink !== 1 || item.size !== entry.bytes.length || (item.mode & 0o777) !== 0o600) fail();
        assertDescriptorHasNoAcl(handle.fd, aclInspector);
      } finally {
        await handle?.close();
      }
    }
  }
  await chmod(destination, 0o700);
  const rootFd = openSync(
    destination,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
  );
  try {
    assertDescriptorHasNoAcl(rootFd, aclInspector);
  } finally {
    closeSync(rootFd);
  }
}

function expectedPrivateCopy(source, destination, actual) {
  if (actual.root !== destination || actual.bytesTotal !== source.bytesTotal
    || actual.entries.length !== source.entries.length) return false;
  const sourceByPath = new Map(source.entries.map((entry) => [entry.path, entry]));
  return actual.entries.every((entry) => {
    const original = sourceByPath.get(entry.path);
    return original && entry.kind === original.kind && entry.sha256 === original.sha256
      && entry.size === original.size && entry.mode === (entry.kind === 'directory' ? 0o700 : 0o600);
  });
}

function privateIsolate(aclInspector) {
  const parentPath = realpathSync(resolve(tmpdir()));
  const parentItem = lstatSync(parentPath);
  if (!parentItem.isDirectory() || parentItem.isSymbolicLink()
    || (parentItem.mode & 0o077) !== 0
    || (typeof process.getuid === 'function' && parentItem.uid !== process.getuid())) fail();
  let parentFd;
  let reserveFd;
  let cleanupPath;
  let rootFd;
  let witness;
  try {
    parentFd = openSync(
      parentPath,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
    );
    const parentOpened = fstatSync(parentFd);
    if (!parentOpened.isDirectory() || parentOpened.dev !== parentItem.dev
      || parentOpened.ino !== parentItem.ino || parentOpened.mode !== parentItem.mode
      || parentOpened.uid !== parentItem.uid || parentOpened.gid !== parentItem.gid
      || (parentOpened.mode & 0o077) !== 0) fail();
    assertDescriptorHasNoAcl(parentFd, aclInspector);
    reserveFd = openSync('/dev/null', constants.O_RDONLY | constants.O_CLOEXEC);
    cleanupPath = mkdtempSync(resolve(parentPath, 'piui-a24-packaged-'));
    closeSync(reserveFd);
    reserveFd = undefined;
    rootFd = openSync(
      cleanupPath,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
    );
    const opened = fstatSync(rootFd);
    witness = Object.freeze({
      cleanupPath,
      dev: opened.dev,
      ino: opened.ino,
      fd: rootFd,
      parentDev: parentOpened.dev,
      parentIno: parentOpened.ino,
      parentFd,
    });
    const item = lstatSync(cleanupPath);
    if (!item.isDirectory() || item.isSymbolicLink()
      || item.dev !== opened.dev || item.ino !== opened.ino
      || item.mode !== opened.mode || item.uid !== opened.uid || item.gid !== opened.gid
      || (item.mode & 0o077) !== 0
      || (typeof process.getuid === 'function' && item.uid !== process.getuid())) fail();
    assertDescriptorHasNoAcl(rootFd, aclInspector);
    const path = resolve(cleanupPath, 'work');
    mkdirSync(path, { mode: 0o700 });
    const isolateFd = openSync(
      path,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
    );
    try {
      const isolateItem = fstatSync(isolateFd);
      if (!isolateItem.isDirectory() || (isolateItem.mode & 0o777) !== 0o700
        || (typeof process.getuid === 'function' && isolateItem.uid !== process.getuid())) fail();
      assertDescriptorHasNoAcl(isolateFd, aclInspector);
    } finally {
      closeSync(isolateFd);
    }
    return Object.freeze({ ...witness, path });
  } catch (error) {
    const failures = [error];
    if (Number.isSafeInteger(reserveFd)) {
      try { closeSync(reserveFd); } catch (failure) { failures.push(failure); }
    }
    if (witness) {
      try {
        removeDescriptorBoundTree(witness, aclInspector);
      } catch (failure) {
        failures.push(failure);
      } finally {
        try { closeSync(witness.fd); } catch (failure) { failures.push(failure); }
        try { closeSync(witness.parentFd); } catch (failure) { failures.push(failure); }
      }
    } else {
      if (cleanupPath && Number.isSafeInteger(parentFd)) {
        let fallbackFd = rootFd;
        try {
          fallbackFd ??= openSync(
            cleanupPath,
            constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
          );
          const opened = fstatSync(fallbackFd);
          const item = lstatSync(cleanupPath);
          const parentOpened = fstatSync(parentFd);
          if (!opened.isDirectory() || item.isSymbolicLink() || !item.isDirectory()
            || opened.dev !== item.dev || opened.ino !== item.ino) fail();
          removeDescriptorBoundTree({
            fd: fallbackFd,
            parentFd,
            dev: opened.dev,
            ino: opened.ino,
            parentDev: parentOpened.dev,
            parentIno: parentOpened.ino,
          }, aclInspector);
        } catch (failure) {
          failures.push(failure);
        } finally {
          if (Number.isSafeInteger(fallbackFd)) {
            try { closeSync(fallbackFd); } catch (failure) { failures.push(failure); }
          }
        }
      } else if (Number.isSafeInteger(rootFd)) {
        try { closeSync(rootFd); } catch (failure) { failures.push(failure); }
      }
      if (Number.isSafeInteger(parentFd)) {
        try { closeSync(parentFd); } catch (failure) { failures.push(failure); }
      }
    }
    if (failures.length === 1) throw error;
    throw new AggregateError(failures, 'A.24 isolate validation and cleanup failed');
  }
}

function removePrivateIsolate(witness, aclInspector) {
  let failure;
  try {
    const rootItem = fstatSync(witness.fd);
    if (!rootItem.isDirectory() || rootItem.dev !== witness.dev || rootItem.ino !== witness.ino) fail();
    assertDescriptorHasNoAcl(witness.fd, aclInspector);
    removeDescriptorBoundTree(witness, aclInspector);
    try {
      lstatSync(witness.cleanupPath);
      fail();
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
  } catch (error) {
    failure = error;
  } finally {
    try { closeSync(witness.fd); } catch (error) { failure ??= error; }
    try { closeSync(witness.parentFd); } catch (error) { failure ??= error; }
  }
  if (failure) throw failure;
}

function seatbeltPath(path) {
  return path.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
}

export { waitForChildSpawn };

/** Deny-default profile for the native harness and its exact packaged Node. */
export function projectTrustSandbox({ appPath, harnessPath, isolatePath, nodePath }) {
  const ancestors = ['/', '/var', '/etc', '/System/Volumes/Data', '/System/Cryptexes/OS'];
  for (const candidate of [appPath, harnessPath, isolatePath, nodePath]) {
    for (let path = dirname(candidate); path !== dirname(path); path = dirname(path)) ancestors.push(path);
  }
  const ancestorRules = [...new Set(ancestors)]
    .map((path) => `  (allow file-read-metadata (literal "${seatbeltPath(path)}"))`).join('\n');
  return `(version 1)
  (deny default)
  (deny network*)
  (allow process-fork)
  (allow process-exec* (literal "${seatbeltPath(harnessPath)}"))
  (allow process-exec* (literal "${seatbeltPath(nodePath)}"))
  (deny mach-lookup (global-name "com.apple.securityd"))
  (deny mach-lookup (global-name "com.apple.SecurityServer"))
  (allow signal (target same-sandbox))
  (allow sysctl-read)
  (allow file-read-data (literal "/"))
${ancestorRules}
  (allow file-read* (subpath "${seatbeltPath(appPath)}"))
  (deny file-write* (subpath "${seatbeltPath(appPath)}"))
  (allow file-read* (subpath "${seatbeltPath(isolatePath)}"))
  (allow file-write* (subpath "${seatbeltPath(isolatePath)}"))
  (allow file-read* (subpath "/System/Library"))
  (allow file-read* (subpath "/usr/lib"))
  (allow file-read* (subpath "/usr/share/zoneinfo"))
  (allow file-read* (subpath "/private/var/db/timezone"))
  (allow file-read* (literal "/private/etc/localtime"))
  (allow file-read* (literal "/dev/null"))
  (allow file-read* (literal "/dev/random"))
  (allow file-read* (literal "/dev/urandom"))
  (allow file-write* (literal "/dev/null"))`;
}

async function copyHarness(anchor, isolatePath, aclInspector) {
  const source = await readIdentityBoundFile(anchor.path, anchor, aclInspector);
  const destination = resolve(isolatePath, 'project-trust-harness');
  let handle;
  try {
    handle = await open(destination, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o500);
    await handle.writeFile(source.bytes);
    await handle.sync();
    await handle.chmod(0o500);
    const item = await handle.stat();
    if (!item.isFile() || item.nlink !== 1 || item.size !== source.bytes.length || (item.mode & 0o777) !== 0o500) fail();
    assertDescriptorHasNoAcl(handle.fd, aclInspector);
  } finally {
    await handle?.close();
  }
  const copied = await readIdentityBoundFile(destination, undefined, aclInspector);
  if (copied.identity.sha256 !== anchor.sha256 || copied.identity.size !== anchor.size
    || copied.identity.mode !== 0o500) fail();
  return Object.freeze({ path: destination, ...copied.identity });
}

function captureOutputWitness(fd, aclInspector) {
  const item = fstatSync(fd);
  if (!item.isFile() || item.nlink !== 1 || item.size !== 0
    || (item.mode & 0o777) !== 0o600
    || (typeof process.getuid === 'function' && item.uid !== process.getuid())) fail();
  assertDescriptorHasNoAcl(fd, aclInspector);
  return Object.freeze({
    dev: item.dev,
    ino: item.ino,
    mode: item.mode,
    uid: item.uid,
    gid: item.gid,
  });
}

function readBoundOutput(fd, path, witness, aclInspector) {
  const before = fstatSync(fd);
  if (!before.isFile() || before.nlink !== 1
    || before.dev !== witness.dev || before.ino !== witness.ino
    || before.mode !== witness.mode || before.uid !== witness.uid || before.gid !== witness.gid
    || before.size > MAX_OUTPUT_BYTES) fail();
  assertDescriptorHasNoAcl(fd, aclInspector);
  const bytes = Buffer.alloc(before.size);
  let offset = 0;
  while (offset < bytes.length) {
    const length = readSync(fd, bytes, offset, bytes.length - offset, offset);
    if (length <= 0) fail();
    offset += length;
  }
  const after = fstatSync(fd);
  const pathAfter = lstatSync(path);
  if (!after.isFile() || after.nlink !== 1
    || after.dev !== before.dev || after.ino !== before.ino
    || after.mode !== before.mode || after.uid !== before.uid || after.gid !== before.gid
    || after.size !== before.size
    || pathAfter.isSymbolicLink() || !pathAfter.isFile() || pathAfter.nlink !== 1
    || pathAfter.dev !== after.dev || pathAfter.ino !== after.ino
    || pathAfter.mode !== after.mode || pathAfter.uid !== after.uid || pathAfter.gid !== after.gid
    || pathAfter.size !== after.size) fail();
  assertDescriptorHasNoAcl(fd, aclInspector);
  return bytes;
}

async function runHarness({
  bundle, fixturePath, harness, isolatePath, aclInspector,
}) {
  const stdoutPath = resolve(isolatePath, 'harness.stdout');
  const stderrPath = resolve(isolatePath, 'harness.stderr');
  let stdoutFd;
  let stderrFd;
  try {
    stdoutFd = openSync(
      stdoutPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
      0o600,
    );
    stderrFd = openSync(
      stderrPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
      0o600,
    );
    const stdoutWitness = captureOutputWitness(stdoutFd, aclInspector);
    const stderrWitness = captureOutputWitness(stderrFd, aclInspector);
    const resources = resolve(bundle.appPath, SIDECAR_ROOT);
    const profile = projectTrustSandbox({ appPath: bundle.appPath, harnessPath: harness.path,
      isolatePath, nodePath: bundle.nodePath });
    const child = spawn('/usr/bin/sandbox-exec', ['-p', profile, harness.path], {
      cwd: isolatePath,
      env: {
        HOME: isolatePath,
        CFFIXED_USER_HOME: isolatePath,
        TMPDIR: `${isolatePath}/`,
        XDG_CACHE_HOME: isolatePath,
        XDG_CONFIG_HOME: isolatePath,
        XDG_DATA_HOME: isolatePath,
        PATH: '/usr/bin:/bin',
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
        PI_OFFLINE: '1',
        PIUI_A24_NODE: bundle.nodePath,
        PIUI_A24_RESOURCES: resources,
        PIUI_A24_FIXTURE: fixturePath,
      },
      detached: true,
      stdio: ['ignore', stdoutFd, stderrFd],
    });
    await waitForChildSpawn(child);
    const ledger = new ProcessLedger({ bundleRoot: bundle.appPath, isolateRoot: isolatePath,
      hostPath: harness.path, nodePath: bundle.nodePath });
    let failure;
    let initialised = false;
    try {
      for (let attempt = 0; attempt < 100 && !initialised; attempt += 1) {
        try { await ledger.initialise(child.pid); initialised = true; } catch { await sleep(10); }
      }
      if (!initialised) fail();
      const deadline = Date.now() + HARNESS_DEADLINE_MS;
      while (child.exitCode === null && child.signalCode === null && Date.now() < deadline) {
        await ledger.sample();
        if (fstatSync(stdoutFd).size > MAX_OUTPUT_BYTES
          || fstatSync(stderrFd).size > MAX_OUTPUT_BYTES) fail();
        await sleep(20);
      }
      if (child.exitCode === null && child.signalCode === null) fail();
      await ledger.sample();
      if (child.exitCode !== 0 || child.signalCode !== null || fstatSync(stderrFd).size !== 0) fail();
    } catch (error) {
      failure = error;
    } finally {
      try {
        const cleanup = await ledger.terminate();
        if (cleanup.forced) fail();
      } catch (error) {
        if (!initialised || isProcessObservationFailure(error)) {
          try {
            await terminateRecordedProcessGroupsWithoutObservation([
              child.pid,
              ...ledger.groups,
            ]);
          } catch (emergencyError) {
            error = new AggregateError(
              [error, emergencyError],
              'A.24 observed and emergency process cleanup failed',
            );
          }
        }
        failure ??= error;
      }
    }
    if (failure) throw failure;
    const stdout = readBoundOutput(stdoutFd, stdoutPath, stdoutWitness, aclInspector);
    const stderr = readBoundOutput(stderrFd, stderrPath, stderrWitness, aclInspector);
    if (stderr.length !== 0) fail();
    return stdout;
  } finally {
    if (Number.isSafeInteger(stderrFd)) closeSync(stderrFd);
    if (Number.isSafeInteger(stdoutFd)) closeSync(stdoutFd);
  }
}

/**
 * Execute A.24 against A.21's still-leased, independently inspected bundle.
 * The release harness anchor must come from that same target build.
 */
export async function executeAuthoritativeProjectTrustProbe(bundle, harnessAnchor,
  { sourceRoot = root } = {}) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') fail();
  if (!bundle || !harnessAnchor || resolve(sourceRoot, 'tests/fixtures/hostile-project') !== SOURCE_FIXTURE) fail();
  let isolate;
  let evidence;
  let failure;
  try {
    await revalidateBundle(bundle);
    const aclInspector = harnessAnchor.aclInspector;
    revalidateSystemDescriptorAclInspector(aclInspector);
    isolate = privateIsolate(aclInspector);
    const sourceBefore = await captureFixture(SOURCE_FIXTURE, {
      retainBytes: true,
      aclInspector,
    });
    const fixturePath = resolve(isolate.path, 'selected-project');
    await writeFixtureCopy(sourceBefore, fixturePath, aclInspector);
    const copiedBefore = await captureFixture(fixturePath, { aclInspector });
    if (!expectedPrivateCopy(sourceBefore, fixturePath, copiedBefore)) fail();
    const harness = await copyHarness(harnessAnchor, isolate.path, aclInspector);
    const bytes = await runHarness({
      bundle,
      fixturePath,
      harness,
      isolatePath: isolate.path,
      aclInspector,
    });
    evidence = parseProjectTrustHarnessEvidence(bytes);
    const copiedAfter = await captureFixture(fixturePath, { aclInspector });
    const sourceAfter = await captureFixture(SOURCE_FIXTURE, { aclInspector });
    if (!sameFixture(copiedBefore, copiedAfter) || !sameFixture(sourceBefore, sourceAfter)) fail();
    const harnessAfter = await readIdentityBoundFile(harness.path, harness, aclInspector);
    if (harnessAfter.identity.sha256 !== harness.sha256) fail();
    revalidateSystemDescriptorAclInspector(aclInspector);
    await revalidateBundle(bundle);
  } catch (error) {
    failure = error;
  } finally {
    if (isolate) {
      try { removePrivateIsolate(isolate, harnessAnchor.aclInspector); } catch (error) { failure ??= error; }
    }
  }
  if (failure || !evidence) throw failure ?? new Error('A.24 packaged trust probe rejected');
  return Object.freeze({ ...evidence, runnerIsolateRemoved: true });
}

/** Formal CLI: only a fresh authoritative package command can produce evidence. */
export async function runAuthoritativeA24Command() {
  const cutoffs = installParentCutoffs();
  try {
    const result = await runOwnedCommand({
      command: process.execPath,
      args: [resolve(root, 'scripts/package-spike.mjs'), '--authoritative-a24'],
      cwd: root,
      env: process.env,
      timeoutMs: 45 * 60_000,
      maxOutputBytes: MAX_OUTPUT_BYTES,
      signal: cutoffs.signal,
      label: 'Authoritative A.21/A.24 package gate',
    });
    if (result.status !== 0 || result.signal !== null || result.stderr.length !== 0) fail();
    return parsePackagedTrustEvidence(result.stdout);
  } finally {
    cutoffs.dispose();
  }
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  try {
    const evidence = await runAuthoritativeA24Command();
    process.stdout.write(`${JSON.stringify(evidence)}\n`);
  } catch {
    process.stderr.write('A.24 packaged trust probe unavailable: the authoritative A.21/A.24 gate failed.\n');
    process.exitCode = 1;
  }
}
