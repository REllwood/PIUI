import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
} from 'node:fs';
import { chmod, lstat, mkdir, open, readdir, rename, rm } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import { isDeepStrictEqual } from 'node:util';
import {
  HOST_PATH,
  NODE_PATH,
  SIDECAR_MANIFEST,
  SIDECAR_ROOT,
  inventoryBundle,
  parseStrictManifest,
  revalidateBundle,
  sha256,
} from '../tests/packaged/bundle-inspection.mjs';
import { ProcessLedger, installParentCutoffs, runOwnedCommand } from './a21-gate-support.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURE_SHA256 = 'ea8814148eccb23250f92af2bf9f42a89e38f3f137d3fb380f42f830ac47a742';
const PARTIAL_SHA256 = '668e1c03090afbe4491469529c26b0f21aac187f63f0187bef8f17906abc783c';
const SHA256 = /^[0-9a-f]{64}$/;
const MAX_OUTPUT_BYTES = 65_536;
const TOP_LEVEL_KEYS = [
  'fixtureSha256',
  'forkEntriesAfterTurn',
  'forkEntriesBeforeTurn',
  'forkedAtSelection',
  'publicSdkImported',
  'repositoryFixtureUnchanged',
  'resumed',
  'schemaVersion',
  'selectedBranchEntries',
  'sourceAfterTurnSha256',
  'sourceBeforeTurnSha256',
  'sourceEntries',
  'sourceUnchanged',
  'turn',
  'zeroTools',
];
const TURN_KEYS = [
  'abortedTerminals',
  'approvalHostCalls',
  'cancellationLatencyMilliseconds',
  'completeTerminals',
  'credentialAccess',
  'forbiddenFinalChunkAbsent',
  'messageStarts',
  'partialBytes',
  'partialSha256',
  'postAbortRequestUpdates',
  'postTerminalEvents',
  'providerAbortObserved',
  'providerCalls',
  'textDeltas',
];
const CREDENTIAL_KEYS = ['deletes', 'lists', 'modifies', 'providerIds', 'reads', 'unexpectedProviderIds'];

function fail() {
  throw new Error('A.22 packaged probe rejected');
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || !isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort())) fail();
}

export function assertSafeEvidence(value) {
  exactKeys(value, TOP_LEVEL_KEYS);
  exactKeys(value.turn, TURN_KEYS);
  exactKeys(value.turn.credentialAccess, CREDENTIAL_KEYS);
  if (value.schemaVersion !== 1 || value.publicSdkImported !== true || value.resumed !== true
    || value.forkedAtSelection !== true || value.sourceUnchanged !== true
    || value.repositoryFixtureUnchanged !== true || value.zeroTools !== true
    || value.fixtureSha256 !== FIXTURE_SHA256
    || typeof value.sourceBeforeTurnSha256 !== 'string' || !SHA256.test(value.sourceBeforeTurnSha256)
    || value.sourceAfterTurnSha256 !== value.sourceBeforeTurnSha256
    || value.selectedBranchEntries !== 4 || value.sourceEntries !== 9
    || value.forkEntriesBeforeTurn !== 4 || value.forkEntriesAfterTurn !== 7
    || value.turn.providerCalls !== 1 || value.turn.providerAbortObserved !== true
    || value.turn.messageStarts !== 1 || value.turn.textDeltas !== 1
    || value.turn.abortedTerminals !== 1 || value.turn.completeTerminals !== 0
    || value.turn.postAbortRequestUpdates !== 0 || value.turn.postTerminalEvents !== 0
    || value.turn.forbiddenFinalChunkAbsent !== true || value.turn.partialBytes !== 4
    || value.turn.partialSha256 !== PARTIAL_SHA256
    || !Number.isSafeInteger(value.turn.cancellationLatencyMilliseconds)
    || value.turn.cancellationLatencyMilliseconds < 0 || value.turn.cancellationLatencyMilliseconds > 1_000
    || value.turn.credentialAccess.reads !== 1_400 || value.turn.credentialAccess.lists !== 8
    || value.turn.credentialAccess.modifies !== 0 || value.turn.credentialAccess.deletes !== 0
    || value.turn.credentialAccess.providerIds !== 39
    || value.turn.credentialAccess.unexpectedProviderIds !== 0
    || value.turn.approvalHostCalls !== 0) fail();

  return Object.freeze({
    schemaVersion: 1,
    publicSdkImported: true,
    resumed: true,
    forkedAtSelection: true,
    sourceUnchanged: true,
    repositoryFixtureUnchanged: true,
    zeroTools: true,
    fixtureSha256: FIXTURE_SHA256,
    sourceBeforeTurnSha256: value.sourceBeforeTurnSha256,
    sourceAfterTurnSha256: value.sourceAfterTurnSha256,
    selectedBranchEntries: 4,
    sourceEntries: 9,
    forkEntriesBeforeTurn: 4,
    forkEntriesAfterTurn: 7,
    turn: Object.freeze({
      providerCalls: 1,
      providerAbortObserved: true,
      messageStarts: 1,
      textDeltas: 1,
      abortedTerminals: 1,
      completeTerminals: 0,
      postAbortRequestUpdates: 0,
      postTerminalEvents: 0,
      forbiddenFinalChunkAbsent: true,
      partialBytes: 4,
      partialSha256: PARTIAL_SHA256,
      cancellationLatencyMilliseconds: value.turn.cancellationLatencyMilliseconds,
      credentialAccess: Object.freeze({
        reads: 1_400,
        lists: 8,
        modifies: 0,
        deletes: 0,
        providerIds: 39,
        unexpectedProviderIds: 0,
      }),
      approvalHostCalls: 0,
    }),
  });
}

export function parsePackagedEvidence(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > MAX_OUTPUT_BYTES) fail();
  const text = bytes.toString('utf8');
  if (Buffer.from(text, 'utf8').length !== bytes.length || !/^[^\r\n]+\n$/.test(text)) fail();
  let value;
  try { value = JSON.parse(text.slice(0, -1)); } catch { fail(); }
  return assertSafeEvidence(value);
}

function seatbeltPath(path) {
  return path.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
}

/** Deny-default A.22 profile. The only writable namespace is the isolate. */
export function packagedProbeSandbox(runtimeRoot, isolateRoot, nodePath = resolve(runtimeRoot, 'node')) {
  const ancestors = ['/'];
  for (let path = dirname(isolateRoot); path !== dirname(path); path = dirname(path)) ancestors.push(path);
  const ancestorRules = [...new Set(ancestors)].map((path) => `  (allow file-read* (literal "${seatbeltPath(path)}"))`).join('\n');
  return `(version 1)
  (deny default)
  (deny network*)
  (deny process-fork)
  (allow process-exec* (literal "${seatbeltPath(nodePath)}"))
  (deny mach-lookup (global-name "com.apple.securityd"))
  (deny mach-lookup (global-name "com.apple.SecurityServer"))
  (allow signal (target self))
  (allow sysctl-read)
${ancestorRules}
  (allow file-read* (subpath "${seatbeltPath(isolateRoot)}"))
  (allow file-write* (subpath "${seatbeltPath(isolateRoot)}"))
  (deny file-write* (subpath "${seatbeltPath(runtimeRoot)}"))
  (allow file-read* (subpath "/System/Library"))
  (allow file-read* (subpath "/usr/lib"))
  (allow file-read* (subpath "/usr/share/zoneinfo"))
  (allow file-read* (subpath "/private/var/db/timezone"))
  (allow file-read* (literal "/private/etc/localtime"))
  (allow file-read-metadata (literal "/tmp"))
  (allow file-read-metadata (literal "/private/tmp"))
  (allow file-read* (literal "/dev/null"))
  (allow file-read* (literal "/dev/random"))
  (allow file-read* (literal "/dev/urandom"))
  (allow file-write* (literal "/dev/null"))`;
}

function privateIsolate() {
  const isolate = realpathSync(mkdtempSync(join(tmpdir(), 'piui-a22-packaged-')));
  const item = lstatSync(isolate);
  if (!item.isDirectory() || item.isSymbolicLink() || (item.mode & 0o077) !== 0) fail();
  return { path: isolate, dev: item.dev, ino: item.ino };
}

function removePrivateIsolate(witness) {
  const item = lstatSync(witness.path);
  if (!item.isDirectory() || item.isSymbolicLink() || item.dev !== witness.dev || item.ino !== witness.ino) fail();
  const unlockDirectories = (path) => {
    const observed = lstatSync(path);
    if (observed.isSymbolicLink() || !observed.isDirectory()) return;
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const opened = fstatSync(fd);
      if (!opened.isDirectory() || opened.dev !== observed.dev || opened.ino !== observed.ino) fail();
      fchmodSync(fd, 0o700);
    } finally {
      closeSync(fd);
    }
    for (const name of readdirSync(path)) unlockDirectories(resolve(path, name));
  };
  unlockDirectories(witness.path);
  rmSync(witness.path, { recursive: true, force: true });
}

function sameIdentity(item, expected) {
  const expectedSize = expected.size ?? expected.bytes;
  return item.dev === expected.dev && item.ino === expected.ino && item.size === expectedSize;
}

async function readIdentityBound(path, expected, expectedIdentity = expected) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1
      || (expectedIdentity && !sameIdentity(before, expectedIdentity))) fail();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (!sameIdentity(after, before) || bytes.length !== expected.bytes || sha256(bytes) !== expected.sha256) fail();
    return Object.freeze({
      bytes,
      witness: Object.freeze({
        dev: before.dev,
        ino: before.ino,
        size: before.size,
        bytes: bytes.length,
        sha256: expected.sha256,
      }),
    });
  } finally {
    await handle?.close();
  }
}

async function writeIdentityBound(path, bytes, mode) {
  let handle;
  try {
    handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, mode);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.chmod(mode);
    const item = await handle.stat();
    if (!item.isFile() || item.nlink !== 1 || item.size !== bytes.length || (item.mode & 0o777) !== mode) fail();
    return Object.freeze({ dev: item.dev, ino: item.ino, size: item.size, bytes: bytes.length, sha256: sha256(bytes), mode });
  } finally {
    await handle?.close();
  }
}

function assertRevalidatedInventory(bundle, inventory) {
  if (inventory.root !== bundle.appPath || inventory.fingerprint !== bundle.fingerprint) fail();
  for (const [path, expected] of [[HOST_PATH, bundle.hostIdentity], [NODE_PATH, bundle.nodeIdentity]]) {
    const entry = inventory.entries.find((candidate) => candidate.path === path && candidate.kind === 'file');
    if (!entry || entry.dev !== expected.dev || entry.ino !== expected.ino
      || entry.bytes !== expected.bytes || entry.sha256 !== expected.sha256) fail();
  }
}

function runtimeRelative(entryPath) {
  if (entryPath === NODE_PATH) return 'node';
  if (!entryPath.startsWith(`${SIDECAR_ROOT}/`)) fail();
  return `sidecar/${entryPath.slice(SIDECAR_ROOT.length + 1)}`;
}

async function expectedRuntimeClosure(bundle, inventory) {
  assertRevalidatedInventory(bundle, inventory);
  const manifestEntry = inventory.entries.find((entry) => entry.path === SIDECAR_MANIFEST && entry.kind === 'file');
  if (!manifestEntry) fail();
  const manifestRead = await readIdentityBound(resolve(bundle.appPath, SIDECAR_MANIFEST), manifestEntry);
  const manifest = parseStrictManifest(manifestRead.bytes);
  if (manifest.files.length !== bundle.sidecarFiles) fail();

  const expectedSourceFiles = [NODE_PATH, SIDECAR_MANIFEST,
    ...manifest.files.map((entry) => `${SIDECAR_ROOT}/${entry.path}`)]
    .sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  const selectedFiles = inventory.entries.filter((entry) => entry.kind === 'file'
    && (entry.path === NODE_PATH || entry.path.startsWith(`${SIDECAR_ROOT}/`)))
    .sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
  if (!isDeepStrictEqual(selectedFiles.map((entry) => entry.path), expectedSourceFiles)) fail();
  for (const manifestFile of manifest.files) {
    const entry = selectedFiles.find((candidate) => candidate.path === `${SIDECAR_ROOT}/${manifestFile.path}`);
    if (!entry || entry.bytes !== manifestFile.bytes || entry.sha256 !== manifestFile.sha256) fail();
  }

  const expectedFiles = new Map(selectedFiles.map((entry) => [runtimeRelative(entry.path), entry]));
  const expectedDirectories = inventory.entries.filter((entry) => entry.kind === 'directory'
    && entry.path.startsWith(`${SIDECAR_ROOT}/`))
    .map((entry) => runtimeRelative(entry.path))
    .sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  return Object.freeze({ expectedFiles, expectedDirectories: Object.freeze(expectedDirectories) });
}

/** Use macOS clonefile/copyfile recursion instead of thousands of JS write/fsync operations. */
export async function cloneRuntimeClosureNative({ bundleRoot, runtimeRoot }) {
  await mkdir(runtimeRoot, { mode: 0o700 });
  const result = await runOwnedCommand({
    command: '/bin/cp',
    args: [
      '-cRP',
      resolve(bundleRoot, NODE_PATH),
      resolve(bundleRoot, SIDECAR_ROOT),
      runtimeRoot,
    ],
    cwd: runtimeRoot,
    env: { PATH: '/usr/bin:/bin', LANG: 'en_AU.UTF-8', LC_ALL: 'en_AU.UTF-8' },
    timeoutMs: 120_000,
    maxOutputBytes: 4_096,
    label: 'A.22 native runtime clone',
  });
  if (result.status !== 0 || result.signal !== null || result.stdout.length !== 0 || result.stderr.length !== 0) fail();
  const modes = await runOwnedCommand({
    command: '/bin/chmod',
    args: [
      '-R',
      '-P',
      'u-w,go-rwx',
      resolve(runtimeRoot, 'piui-node'),
      resolve(runtimeRoot, 'sidecar'),
    ],
    cwd: runtimeRoot,
    env: { PATH: '/usr/bin:/bin' },
    timeoutMs: 120_000,
    maxOutputBytes: 4_096,
    label: 'A.22 runtime mode confinement',
  });
  if (modes.status !== 0 || modes.signal !== null || modes.stdout.length !== 0 || modes.stderr.length !== 0) fail();
  await rename(resolve(runtimeRoot, 'piui-node'), resolve(runtimeRoot, 'node'));
}

async function makeDirectoryPrivate(path, expected) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    if (!before.isDirectory() || before.dev !== expected.dev || before.ino !== expected.ino) fail();
    await handle.chmod(0o700);
    const after = await handle.stat();
    if (!after.isDirectory() || after.dev !== before.dev || after.ino !== before.ino
      || (after.mode & 0o777) !== 0o700) fail();
  } finally {
    await handle?.close();
  }
}

async function runtimeInventory(rootPath, boundary = rootPath) {
  const files = new Map();
  const directories = [];
  for (const name of (await readdir(rootPath)).sort((a, b) => Buffer.from(a).compare(Buffer.from(b)))) {
    const path = resolve(rootPath, name);
    const relativePath = relative(boundary, path).split('\\').join('/');
    const item = await lstat(path);
    if (item.isSymbolicLink() || (!item.isDirectory() && !item.isFile())) fail();
    if (item.isDirectory()) {
      directories.push(`${relativePath}/`);
      await makeDirectoryPrivate(path, item);
      const nested = await runtimeInventory(path, boundary);
      directories.push(...nested.directories);
      for (const [nestedPath, nestedItem] of nested.files) files.set(nestedPath, nestedItem);
    } else {
      if (item.nlink !== 1 || (item.mode & 0o777) !== (relativePath === 'node' ? 0o500 : 0o400)) fail();
      files.set(relativePath, item);
    }
  }
  return { files, directories };
}

async function concurrentMap(values, worker, concurrency = 32) {
  const results = new Array(values.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(concurrency, values.length) }, async () => {
    while (cursor < values.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await worker(values[index], index);
    }
  });
  await Promise.all(workers);
  return results;
}

/** Verify exact paths and SHA-256 content; later calls also bind destination inodes. */
export async function verifyExecutionCopy(copy) {
  const rootItem = await lstat(copy.runtimeRoot);
  if (!rootItem.isDirectory() || rootItem.isSymbolicLink()
    || rootItem.dev !== copy.rootIdentity.dev || rootItem.ino !== copy.rootIdentity.ino) fail();
  const actual = await runtimeInventory(copy.runtimeRoot);
  const actualFiles = [...actual.files.keys()].sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  const expectedFiles = [...copy.expectedFiles.keys()].sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  actual.directories.sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  if (!isDeepStrictEqual(actualFiles, expectedFiles)
    || !isDeepStrictEqual(actual.directories, copy.expectedDirectories)) fail();

  const witnessed = await concurrentMap(expectedFiles, async (relativePath) => {
    const expected = copy.expectedFiles.get(relativePath);
    const expectedIdentity = copy.witnesses?.get(relativePath) ?? actual.files.get(relativePath);
    const destination = resolve(copy.runtimeRoot, relativePath);
    if (relative(copy.runtimeRoot, destination).startsWith('..')) fail();
    const read = await readIdentityBound(destination, expected, expectedIdentity);
    return [relativePath, read.witness];
  });
  return new Map(witnessed);
}

async function copyIdentityBoundRuntime(bundle, isolate) {
  const inventory = await inventoryBundle(bundle.appPath);
  const expected = await expectedRuntimeClosure(bundle, inventory);
  const runtimeRoot = resolve(isolate, 'runtime');
  await cloneRuntimeClosureNative({ bundleRoot: bundle.appPath, runtimeRoot });
  const rootItem = await lstat(runtimeRoot);
  const copy = {
    runtimeRoot,
    nodePath: resolve(runtimeRoot, 'node'),
    entryPath: resolve(runtimeRoot, 'sidecar/dist/pi/packaged-sdk-probe-entry.js'),
    expectedFiles: expected.expectedFiles,
    expectedDirectories: expected.expectedDirectories,
    rootIdentity: Object.freeze({ dev: rootItem.dev, ino: rootItem.ino }),
  };
  copy.witnesses = await verifyExecutionCopy(copy);
  const fixtureRelative = 'sidecar/fixture/active-branch-v3.jsonl';
  const fixtureExpected = copy.expectedFiles.get(fixtureRelative);
  const fixtureWitness = copy.witnesses.get(fixtureRelative);
  if (!fixtureExpected || !fixtureWitness) fail();
  const fixtureRead = await readIdentityBound(
    resolve(runtimeRoot, fixtureRelative),
    fixtureExpected,
    fixtureWitness,
  );
  if (fixtureRead.witness.sha256 !== FIXTURE_SHA256) fail();
  await mkdir(resolve(isolate, 'fixture'), { mode: 0o700 });
  await writeIdentityBound(resolve(isolate, 'fixture/active-branch-v3.jsonl'), fixtureRead.bytes, 0o600);
  return Object.freeze(copy);
}

async function runSandboxedNode({ copy, isolate, script, outputName, env, timeoutMs }) {
  const stdoutPath = resolve(isolate, `${outputName}.stdout`);
  const stderrPath = resolve(isolate, `${outputName}.stderr`);
  const stdoutFd = openSync(stdoutPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
  const stderrFd = openSync(stderrPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
  const child = spawn('/usr/bin/sandbox-exec', ['-p', packagedProbeSandbox(copy.runtimeRoot, isolate, copy.nodePath), copy.nodePath, script], {
    cwd: isolate,
    env,
    detached: true,
    stdio: ['ignore', stdoutFd, stderrFd],
  });
  closeSync(stdoutFd);
  closeSync(stderrFd);
  const ledger = new ProcessLedger({
    bundleRoot: copy.runtimeRoot,
    isolateRoot: isolate,
    hostPath: copy.nodePath,
    nodePath: copy.nodePath,
  });
  let failure;
  try {
    let initialised = false;
    for (let attempt = 0; attempt < 100 && !initialised; attempt += 1) {
      try { await ledger.initialise(child.pid); initialised = true; } catch { await sleep(10); }
    }
    if (!initialised) fail();
    const deadline = Date.now() + timeoutMs;
    while (child.exitCode === null && child.signalCode === null && Date.now() < deadline) {
      await ledger.sample();
      if (statSync(stdoutPath).size > MAX_OUTPUT_BYTES || statSync(stderrPath).size > MAX_OUTPUT_BYTES) fail();
      await sleep(20);
    }
    if (child.exitCode === null && child.signalCode === null) fail();
    await ledger.sample();
    if (child.exitCode !== 0 || child.signalCode !== null || statSync(stderrPath).size !== 0) fail();
  } catch (error) {
    failure = error;
  } finally {
    try {
      const cleanup = await ledger.terminate();
      if (cleanup.forced) fail();
    } catch (error) {
      failure ??= error;
    }
  }
  if (failure) throw failure;
  return readFileSync(stdoutPath);
}

async function runDenialProbes(copy, isolate, sourceRoot) {
  const token = randomUUID();
  const repositoryWrite = resolve(sourceRoot, `.cache/a22-repository-write-${token}`);
  const homeWrite = resolve(homedir(), `.piui-a22-home-write-${token}`);
  const nonAllowlistedRead = resolve(sourceRoot, 'package.json');
  const probePath = resolve(isolate, 'sandbox-denial-probe.mjs');
  const source = `import { spawnSync } from 'node:child_process';\nimport { readFileSync, writeFileSync } from 'node:fs';\nconst denied = (operation) => { try { operation(); return false; } catch (error) { return error?.code === 'EPERM' || error?.code === 'EACCES'; } };\nconst child = spawnSync('/usr/bin/true');\nconst result = { repositoryWriteDenied: denied(() => writeFileSync(process.env.REPOSITORY_WRITE, 'denied', { flag: 'wx' })), homeWriteDenied: denied(() => writeFileSync(process.env.HOME_WRITE, 'denied', { flag: 'wx' })), nonAllowlistedReadDenied: denied(() => readFileSync(process.env.NON_ALLOWLISTED_READ)), processCreationDenied: child.error?.code === 'EPERM' || child.error?.code === 'EACCES' };\nprocess.stdout.write(JSON.stringify(result) + '\\n');\nawait new Promise((resolve) => setTimeout(resolve, 150));\n`;
  await writeIdentityBound(probePath, Buffer.from(source), 0o400);
  let bytes;
  try {
    bytes = await runSandboxedNode({
      copy,
      isolate,
      script: probePath,
      outputName: 'sandbox-denials',
      timeoutMs: 5_000,
      env: {
        HOME: isolate,
        TMPDIR: `${isolate}/`,
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
        REPOSITORY_WRITE: repositoryWrite,
        HOME_WRITE: homeWrite,
        NON_ALLOWLISTED_READ: nonAllowlistedRead,
      },
    });
    let result;
    try { result = JSON.parse(bytes.toString('utf8')); } catch { fail(); }
    exactKeys(result, ['homeWriteDenied', 'nonAllowlistedReadDenied', 'processCreationDenied', 'repositoryWriteDenied']);
    if (!Object.values(result).every((value) => value === true)) fail();
  } finally {
    let escaped = false;
    for (const path of [repositoryWrite, homeWrite]) {
      try { await lstat(path); escaped = true; await rm(path, { force: true }); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
    }
    if (escaped) fail();
  }
}

/**
 * Authoritative A.22 execution. Callers must pass A.21's still-leased,
 * independently inspected in-memory bundle before publication or lock release.
 */
export async function executeAuthoritativePackagedProbe(bundle, { sourceRoot = root } = {}) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') fail();
  let isolate;
  let evidence;
  let failure;
  try {
    isolate = privateIsolate();
    for (const name of ['tmp', 'cache', 'config', 'data']) await mkdir(resolve(isolate.path, name), { mode: 0o700 });
    const copy = await copyIdentityBoundRuntime(bundle, isolate.path);
    await runDenialProbes(copy, isolate.path, sourceRoot);
    await verifyExecutionCopy(copy);
    const bytes = await runSandboxedNode({
      copy,
      isolate: isolate.path,
      script: copy.entryPath,
      outputName: 'sdk-proof',
      timeoutMs: 15_000,
      env: {
        HOME: isolate.path,
        CFFIXED_USER_HOME: isolate.path,
        TMPDIR: `${resolve(isolate.path, 'tmp')}/`,
        XDG_CACHE_HOME: resolve(isolate.path, 'cache'),
        XDG_CONFIG_HOME: resolve(isolate.path, 'config'),
        XDG_DATA_HOME: resolve(isolate.path, 'data'),
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
        PATH: '/usr/bin:/bin',
        PI_OFFLINE: '1',
      },
    });
    evidence = parsePackagedEvidence(bytes);
    await verifyExecutionCopy(copy);
    // The source bundle is revalidated after the independently verified clone
    // and both sandboxed executions, closing the before/after provenance pair.
    await revalidateBundle(bundle);
  } catch (error) {
    failure = error;
  } finally {
    if (isolate) {
      try { removePrivateIsolate(isolate); } catch (error) { failure ??= error; }
    }
  }
  if (failure) throw failure;
  if (!evidence) fail();
  return evidence;
}

/** Formal CLI: execute a fixed A.21 build-and-inspect mode, then normalise only A.22 evidence. */
export async function runAuthoritativeA22Command() {
  const cutoffs = installParentCutoffs();
  try {
    const result = await runOwnedCommand({
      command: process.execPath,
      args: [resolve(root, 'scripts/package-spike.mjs'), '--authoritative-a22'],
      cwd: root,
      env: process.env,
      timeoutMs: 45 * 60_000,
      maxOutputBytes: MAX_OUTPUT_BYTES,
      signal: cutoffs.signal,
      label: 'Authoritative A.21/A.22 package gate',
    });
    if (result.status !== 0 || result.signal !== null || result.stderr.length !== 0) fail();
    return parsePackagedEvidence(result.stdout);
  } finally {
    cutoffs.dispose();
  }
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  try {
    const evidence = await runAuthoritativeA22Command();
    process.stdout.write(`${JSON.stringify(evidence)}\n`);
  } catch {
    process.stderr.write('A.22 packaged probe unavailable: the authoritative A.21/A.22 gate failed.\n');
    process.exitCode = 1;
  }
}
