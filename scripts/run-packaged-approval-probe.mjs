import { constants, realpathSync } from 'node:fs';
import {
  chmod,
  lstat,
  mkdtemp,
  mkdir,
  open,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { NODE_PATH, SIDECAR_ROOT, revalidateBundle, sha256 } from '../tests/packaged/bundle-inspection.mjs';
import { installParentCutoffs, runOwnedCommand } from './a21-gate-support.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const HARNESS_RELATIVE = 'src-tauri/target/aarch64-apple-darwin/release/approval-matrix-harness';
const FIXTURE_ROOT_RELATIVE = 'src-tauri/target/a25-sidecar-fixture';
const FIXTURE_MODULE_FILES = Object.freeze([
  'spike/approval-entry.js',
  'spike/approval-matrix.js',
  'spike/approval-probes.js',
]);
const FIXTURE_FILES = Object.freeze([
  'package.json',
  ...FIXTURE_MODULE_FILES,
]);
const FIXTURE_PACKAGE = `${JSON.stringify({
  name: '@piui/a25-approval-fixture',
  private: true,
  type: 'module',
  version: '0.0.0',
}, null, 2)}\n`;
const FIXTURE_COMPILED_PREFIXES = Object.freeze([
  'dist/spike/approval-entry.',
  'dist/spike/approval-matrix.',
  'dist/spike/approval-probes.',
]);
const MAX_OUTPUT_BYTES = 65_536;

export const APPROVAL_MATRIX_EXPECTED_EVIDENCE = Object.freeze({
  schemaVersion: 1,
  packagedRuntimeValidated: true,
  piPublicRootSessions: 5,
  piPromptTurns: 12,
  approvalRequests: 36,
  fiveArgumentDelegateCalls: 6,
  fiveArgumentViolations: 0,
  individualApproveOnceExecutions: 1,
  eligibleGroupMembers: 3,
  eligibleGroupExecutions: 3,
  denyCaseExecutions: 0,
  timeoutExecutions: 0,
  disconnectExecutions: 0,
  quitExecutions: 0,
  sidecarDeathExecutions: 0,
  destructiveApproveOnceExecutions: 1,
  destructiveRepeatExecutions: 0,
  externalApproveOnceExecutions: 1,
  externalRepeatExecutions: 0,
  ineligibleGroupActionsExposed: 0,
  rememberedAutoApprovals: 0,
  staleIndividualDecisionRejections: 1,
  staleGroupDecisionRejections: 1,
  freshBridgeStateInitialRecords: 0,
  freshBridgeStateInitialChangeSequence: 0,
  freshBridgeStateGenerationRestartedAtOne: true,
  staleNativeIndividualFrameRejections: 1,
  staleNativeGroupFrameRejections: 1,
  staleBrokerWaitersRemaining: 0,
  staleBrokerGenerationsAborted: 2,
  replacementCohortUnchangedAfterReplay: true,
  replacementCohortExecutions: 0,
  productionSidecarExcludesApprovalFixture: true,
  approvedRecords: 6,
  deniedRecords: 18,
  expiredRecords: 3,
  cancelledRecords: 9,
  timedOutRecords: 3,
  generationLostRecords: 9,
  sidecarGenerations: 5,
  unapprovedDelegateExecutions: 0,
  witnessInventoryExact: true,
});

const HARNESS_KEYS = Object.freeze(Object.keys(APPROVAL_MATRIX_EXPECTED_EVIDENCE));

function fail() {
  throw new Error('A.25 packaged approval probe rejected');
}

function parseOneLine(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 3 || bytes.length > MAX_OUTPUT_BYTES) fail();
  const text = bytes.toString('utf8');
  if (Buffer.from(text, 'utf8').length !== bytes.length || !/^[^\r\n]+\n$/.test(text)) fail();
  try {
    return JSON.parse(text.slice(0, -1));
  } catch {
    fail();
  }
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || !isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort())) fail();
}

export function parseApprovalMatrixHarnessEvidence(bytes) {
  const value = parseOneLine(bytes);
  exactKeys(value, HARNESS_KEYS);
  for (const key of HARNESS_KEYS) {
    const expected = APPROVAL_MATRIX_EXPECTED_EVIDENCE[key];
    if (value[key] !== expected || typeof value[key] !== typeof expected) fail();
  }
  return Object.freeze({ ...APPROVAL_MATRIX_EXPECTED_EVIDENCE });
}

export function parsePackagedApprovalMatrixEvidence(bytes) {
  const value = parseOneLine(bytes);
  exactKeys(value, [...HARNESS_KEYS, 'runnerIsolateRemoved', 'generatedOutputsRemoved']);
  if (value.runnerIsolateRemoved !== true || value.generatedOutputsRemoved !== true) fail();
  const harness = {};
  for (const key of HARNESS_KEYS) harness[key] = value[key];
  parseApprovalMatrixHarnessEvidence(Buffer.from(`${JSON.stringify(harness)}\n`));
  return Object.freeze({
    ...APPROVAL_MATRIX_EXPECTED_EVIDENCE,
    runnerIsolateRemoved: true,
    generatedOutputsRemoved: true,
  });
}

async function readIdentityBoundFile(path, expected) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1 || (before.mode & 0o022) !== 0
      || (typeof process.getuid === 'function' && before.uid !== process.getuid())
      || (expected && (before.dev !== expected.dev || before.ino !== expected.ino
        || before.size !== expected.size || (before.mode & 0o777) !== expected.mode))) fail();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size
      || bytes.length !== before.size) fail();
    const identity = Object.freeze({
      dev: before.dev,
      ino: before.ino,
      size: before.size,
      mode: before.mode & 0o777,
      sha256: sha256(bytes),
    });
    if (expected && identity.sha256 !== expected.sha256) fail();
    return Object.freeze({ bytes, identity });
  } finally {
    await handle?.close();
  }
}

export async function captureApprovalMatrixHarness(sourceRoot = root) {
  const path = resolve(sourceRoot, HARNESS_RELATIVE);
  const read = await readIdentityBoundFile(path);
  if ((read.identity.mode & 0o111) === 0 || read.identity.size < 4_096) fail();
  const fixtureRoot = resolve(sourceRoot, FIXTURE_ROOT_RELATIVE);
  const fixtureRootItem = await lstat(fixtureRoot);
  const fixtureSpikeItem = await lstat(resolve(fixtureRoot, 'spike'));
  if (realpathSync(fixtureRoot) !== fixtureRoot
    || !fixtureRootItem.isDirectory() || fixtureRootItem.isSymbolicLink()
    || (fixtureRootItem.mode & 0o777) !== 0o700
    || !fixtureSpikeItem.isDirectory() || fixtureSpikeItem.isSymbolicLink()
    || (fixtureSpikeItem.mode & 0o777) !== 0o700
    || (typeof process.getuid === 'function'
      && (fixtureRootItem.uid !== process.getuid()
        || fixtureSpikeItem.uid !== process.getuid()))) fail();
  const rootEntries = (await readdir(fixtureRoot)).sort();
  const spikeEntries = (await readdir(resolve(fixtureRoot, 'spike'))).sort();
  if (!isDeepStrictEqual(rootEntries, ['package.json', 'spike'])
    || !isDeepStrictEqual(
      spikeEntries,
      FIXTURE_MODULE_FILES.map((entry) => entry.slice('spike/'.length)).sort(),
    )) fail();
  const fixtureFiles = [];
  for (const relativePath of FIXTURE_FILES) {
    const fixturePath = resolve(fixtureRoot, relativePath);
    const fixtureRead = await readIdentityBoundFile(fixturePath);
    if (fixtureRead.identity.mode !== 0o400 || fixtureRead.identity.size < 32) fail();
    if (relativePath === 'package.json'
      && fixtureRead.bytes.toString('utf8') !== FIXTURE_PACKAGE) fail();
    fixtureFiles.push(Object.freeze({
      relativePath,
      path: fixturePath,
      ...fixtureRead.identity,
    }));
  }
  return Object.freeze({
    path,
    ...read.identity,
    fixture: Object.freeze({
      root: fixtureRoot,
      files: Object.freeze(fixtureFiles),
    }),
  });
}

function seatbeltPath(path) {
  return path.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
}

export function approvalMatrixSandbox({ appPath, harnessPath, isolatePath, nodePath }) {
  const ancestors = [];
  for (const candidate of [appPath, harnessPath, isolatePath, nodePath]) {
    for (let path = dirname(candidate); path !== dirname(path); path = dirname(path)) ancestors.push(path);
  }
  const metadata = [...new Set(ancestors)]
    .map((path) => `  (allow file-read-metadata (literal "${seatbeltPath(path)}"))`).join('\n');
  return `(version 1)
  (deny default)
  (import "dyld-support.sb")
  (deny network*)
  (allow process-fork)
  (allow process-exec* (literal "${seatbeltPath(harnessPath)}"))
  (allow process-exec* (literal "${seatbeltPath(nodePath)}"))
  (allow signal (target same-sandbox))
  (allow sysctl-read)
${metadata}
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

async function createRunnerIsolate() {
  const path = await mkdtemp(resolve(tmpdir(), 'piui-a25-runner-'));
  await chmod(path, 0o700);
  const canonical = realpathSync(path);
  for (const name of ['witness', 'workspace', 'agent']) {
    await mkdir(resolve(canonical, name), { mode: 0o700 });
  }
  const planPath = resolve(canonical, 'plan.json');
  await writeFile(planPath, `${JSON.stringify({
    schemaVersion: 1,
    matrixVersion: 'a25-v1',
    generations: 5,
    turns: 12,
    requests: 36,
  })}\n`, { flag: 'wx', mode: 0o600 });
  await chmod(planPath, 0o400);
  return canonical;
}

async function copyHarness(anchor, isolatePath) {
  const source = await readIdentityBoundFile(anchor.path, anchor);
  const destination = resolve(isolatePath, 'approval-matrix-harness');
  await writeFile(destination, source.bytes, { flag: 'wx', mode: 0o500 });
  await chmod(destination, 0o500);
  const copied = await readIdentityBoundFile(destination);
  if (copied.identity.sha256 !== anchor.sha256 || copied.identity.mode !== 0o500) fail();
  return Object.freeze({ path: destination, ...copied.identity });
}

async function copyApprovalFixture(anchor, isolatePath) {
  exactKeys(anchor.fixture, ['root', 'files']);
  if (!Array.isArray(anchor.fixture.files)
    || anchor.fixture.files.length !== FIXTURE_FILES.length) fail();
  const relativePaths = anchor.fixture.files.map((entry) => entry.relativePath);
  if (!isDeepStrictEqual([...relativePaths].sort(), [...FIXTURE_FILES].sort())) fail();
  const destinationRoot = resolve(isolatePath, 'a25-sidecar-fixture');
  await mkdir(resolve(destinationRoot, 'spike'), { recursive: true, mode: 0o700 });
  await chmod(destinationRoot, 0o700);
  await chmod(resolve(destinationRoot, 'spike'), 0o700);
  const copiedFiles = [];
  for (const sourceAnchor of anchor.fixture.files) {
    exactKeys(sourceAnchor, [
      'relativePath', 'path', 'dev', 'ino', 'size', 'mode', 'sha256',
    ]);
    const source = await readIdentityBoundFile(sourceAnchor.path, sourceAnchor);
    if (resolve(anchor.fixture.root, sourceAnchor.relativePath) !== sourceAnchor.path) fail();
    const destination = resolve(destinationRoot, sourceAnchor.relativePath);
    await writeFile(destination, source.bytes, { flag: 'wx', mode: 0o400 });
    await chmod(destination, 0o400);
    const copied = await readIdentityBoundFile(destination);
    if (copied.identity.sha256 !== sourceAnchor.sha256
      || copied.identity.mode !== 0o400) fail();
    copiedFiles.push(Object.freeze({
      relativePath: sourceAnchor.relativePath,
      path: destination,
      ...copied.identity,
    }));
  }
  return Object.freeze({
    entrypoint: resolve(destinationRoot, 'spike/approval-entry.js'),
    files: Object.freeze(copiedFiles),
  });
}

async function assertApprovalFixtureAbsentFromBundle(bundle) {
  const resources = resolve(bundle.appPath, SIDECAR_ROOT);
  const forbiddenNames = new Set(FIXTURE_MODULE_FILES.map((entry) => (
    entry.slice('spike/'.length)
  )));
  const pending = [bundle.appPath];
  while (pending.length) {
    const directory = pending.pop();
    if (!directory) fail();
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) fail();
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) pending.push(path);
      else if (forbiddenNames.has(entry.name)) fail();
    }
  }
  try {
    await lstat(resolve(bundle.appPath, 'Contents/MacOS/approval-matrix-harness'));
    fail();
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  for (const relativePath of FIXTURE_MODULE_FILES) {
    try {
      await lstat(resolve(resources, 'dist', relativePath));
      fail();
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
  }
  const manifest = JSON.parse(await readFile(resolve(resources, 'manifest.json'), 'utf8'));
  if (!Array.isArray(manifest.files)
    || manifest.files.some((entry) => (
      entry && typeof entry.path === 'string'
      && FIXTURE_COMPILED_PREFIXES.some((prefix) => entry.path.startsWith(prefix))
    ))) fail();
  for (const relativePath of ['dist/index.js', 'dist/runtime.js']) {
    const source = await readFile(resolve(resources, relativePath), 'utf8');
    if ([
      'PIUI_A25_',
      'createA25Approval',
      'approval-matrix.complete',
      'spike/approval-matrix',
      'spike/approval-probes',
    ]
      .some((marker) => source.includes(marker))) fail();
  }
}

export async function executeAuthoritativeApprovalProbe(bundle, harnessAnchor, { signal } = {}) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64' || !bundle || !harnessAnchor) fail();
  exactKeys(harnessAnchor, [
    'path', 'dev', 'ino', 'size', 'mode', 'sha256', 'fixture',
  ]);
  let isolate;
  let evidence;
  let failure;
  try {
    await revalidateBundle(bundle);
    await assertApprovalFixtureAbsentFromBundle(bundle);
    isolate = await createRunnerIsolate();
    const harness = await copyHarness(harnessAnchor, isolate);
    const fixture = await copyApprovalFixture(harnessAnchor, isolate);
    const nodePath = bundle.nodePath ?? resolve(bundle.appPath, NODE_PATH);
    const resources = resolve(bundle.appPath, SIDECAR_ROOT);
    const profile = approvalMatrixSandbox({
      appPath: bundle.appPath,
      harnessPath: harness.path,
      isolatePath: isolate,
      nodePath,
    });
    const result = await runOwnedCommand({
      command: '/usr/bin/sandbox-exec',
      args: ['-p', profile, harness.path],
      cwd: isolate,
      env: {
        HOME: isolate,
        CFFIXED_USER_HOME: isolate,
        TMPDIR: `${isolate}/`,
        XDG_CACHE_HOME: isolate,
        XDG_CONFIG_HOME: isolate,
        XDG_DATA_HOME: isolate,
        PATH: '/usr/bin:/bin',
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
        PI_OFFLINE: '1',
        PIUI_A25_NODE: nodePath,
        PIUI_A25_RESOURCES: resources,
        PIUI_A25_CONTROL_ROOT: isolate,
        PIUI_A25_FIXTURE_ENTRY: fixture.entrypoint,
      },
      timeoutMs: 20 * 60_000,
      maxOutputBytes: MAX_OUTPUT_BYTES,
      signal,
      label: 'A.25 approval matrix harness',
    });
    if (result.status !== 0 || result.signal !== null || result.stderr.length !== 0) fail();
    evidence = parseApprovalMatrixHarnessEvidence(result.stdout);
    const after = await readIdentityBoundFile(harness.path, harness);
    if (after.identity.sha256 !== harness.sha256) fail();
    for (const copied of fixture.files) {
      const afterFixture = await readIdentityBoundFile(copied.path, copied);
      if (afterFixture.identity.sha256 !== copied.sha256) fail();
    }
    await revalidateBundle(bundle);
    await assertApprovalFixtureAbsentFromBundle(bundle);
  } catch (error) {
    failure = error;
  } finally {
    if (isolate) {
      try {
        await rm(isolate, { recursive: true, force: false });
      } catch (error) {
        failure ??= error;
      }
    }
  }
  if (failure || !evidence) throw failure ?? new Error('A.25 packaged approval probe rejected');
  return Object.freeze({ ...evidence, runnerIsolateRemoved: true });
}

export async function runAuthoritativeA25Command() {
  const cutoffs = installParentCutoffs();
  try {
    const result = await runOwnedCommand({
      command: process.execPath,
      args: [resolve(root, 'scripts/package-spike.mjs'), '--authoritative-a25'],
      cwd: root,
      env: process.env,
      timeoutMs: 45 * 60_000,
      maxOutputBytes: MAX_OUTPUT_BYTES,
      signal: cutoffs.signal,
      label: 'Authoritative A.21/A.25 package gate',
    });
    if (result.status !== 0 || result.signal !== null || result.stderr.length !== 0) fail();
    return parsePackagedApprovalMatrixEvidence(result.stdout);
  } finally {
    cutoffs.dispose();
  }
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  try {
    const evidence = await runAuthoritativeA25Command();
    process.stdout.write(`${JSON.stringify(evidence)}\n`);
  } catch {
    process.stderr.write('A.25 packaged approval probe unavailable: the authoritative A.21/A.25 gate failed.\n');
    process.exitCode = 1;
  }
}
