import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import {
  assertPrivateExecutableLease,
  capturePrivateExecutable,
  releasePrivateExecutableLeaseForRemoval,
} from './private-executable-lease.mjs';
import {
  APPLE_TOOLCHAIN_PATHS,
  appleToolchainBuildEnvironment,
  captureAppleToolchainAuthority,
  releaseAppleToolchainAuthority,
  revalidateAppleToolchainAuthority,
} from './apple-toolchain-trust.mjs';

export const CANARY_SCAN_TEST_HOOK = Symbol('CANARY_SCAN_TEST_HOOK');
export const CANARY_SCAN_RUNTIME_TEST_HOOK = Symbol('CANARY_SCAN_RUNTIME_TEST_HOOK');

export const CANARY_SCAN_LIMITS = Object.freeze({
  maxRoots: 16,
  maxAuthorisedFiles: 16,
  maxEntries: 512,
  maxDepth: 32,
  maxFileBytes: 256 * 1024,
  maxAggregateFileDataBytes: 2 * 1024 * 1024,
  maxMetadataBytes: 16 * 1024,
  maxResolutionComponents: 2_048,
  maxExpectedOccurrencesPerFile: 4_096,
  minCanaryBytes: 24,
  maxCanaryBytes: 1_024,
  maxConfigBytes: 64 * 1024,
});

const FRAME_MAGIC = Buffer.from('PIUISCAN', 'ascii');
const FRAME_VERSION = 1;
const FRAME_HEADER_BYTES = 28;
const FRAME_HOOK_FLAG = 1;
const MAX_FRAME_BYTES = FRAME_HEADER_BYTES
  + CANARY_SCAN_LIMITS.maxConfigBytes
  + CANARY_SCAN_LIMITS.maxCanaryBytes;
const MAX_HELPER_OUTPUT_BYTES = 4_096;
const COMPILER_TIMEOUT_MS = 15_000;
const HELPER_TIMEOUT_MS = 15_000;
const CHILD_CLOSE_TIMEOUT_MS = 1_000;
const INJECTED_TIMEOUT_MS = 100;
const HELPER_WORKSPACE_PREFIX = `piui-a23-scanner-helper-${process.pid}-`;
const SCANNER_SOURCE_SHA256 = 'a9a62e87983180b8bf97684ce79b81f7bf1c8fa742d54c26e65d98d206970b25';
const SCANNER_SOURCE_MAX_BYTES = 128 * 1024;
const SAFE_REJECTION = Object.freeze({
  schemaVersion: 1,
  status: 'rejected',
  errorCode: 'canary-scan-rejected',
});
const SUCCESS_KEYS = Object.freeze([
  'authorisedFiles',
  'authorisedOccurrences',
  'entriesScanned',
  'fileDataBytesScanned',
  'filesScanned',
  'metadataBytesScanned',
  'rootsScanned',
  'schemaVersion',
  'status',
  'unauthorisedOccurrences',
]);
const HOOK_PHASES = Object.freeze(new Map([
  [1, 'roots-held'],
  [2, 'traversal-complete'],
  [3, 'file-opened'],
]));

let compiledHelper;
let helperWorkspace;
let exitCleanupRegistered = false;

export class CanaryScanError extends Error {
  constructor() {
    super('Secret canary scan rejected');
    this.name = 'CanaryScanError';
    this.code = 'canary-scan-rejected';
    this.stack = `${this.name}: ${this.message}`;
  }
}

function reject() {
  throw new CanaryScanError();
}

function clearBuffer(value) {
  if (Buffer.isBuffer(value)) value.fill(0);
}

function sameIdentity(before, after) {
  return before.dev === after.dev
    && before.ino === after.ino
    && before.mode === after.mode
    && before.nlink === after.nlink
    && before.uid === after.uid
    && before.size === after.size
    && before.mtimeNs === after.mtimeNs
    && before.ctimeNs === after.ctimeNs;
}

function assertOwnedHelperWorkspace(workspace) {
  if (!workspace || typeof workspace !== 'object' || Array.isArray(workspace)
    || typeof workspace.path !== 'string'
    || !workspace.path.startsWith(realpathSync(tmpdir()) + sep)
    || !/^piui-a23-scanner-helper-[0-9]+-[A-Za-z0-9]+$/u.test(workspace.path.split(sep).at(-1))) {
    reject();
  }
  const item = lstatSync(workspace.path, { bigint: true });
  if (!item.isDirectory() || item.isSymbolicLink()
    || item.dev !== workspace.dev || item.ino !== workspace.ino
    || item.uid !== BigInt(process.getuid()) || (item.mode & 0o077n) !== 0n
    || realpathSync(workspace.path) !== workspace.path) reject();
}

function unlockControlForCleanup(workspacePath) {
  const control = join(workspacePath, 'control');
  try {
    const item = lstatSync(control, { bigint: true });
    if (item.isDirectory() && !item.isSymbolicLink()
      && item.uid === BigInt(process.getuid()) && realpathSync(control) === control) {
      chmodSync(control, 0o700);
    }
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

function cleanupHelperOnExit() {
  const workspace = helperWorkspace;
  compiledHelper = undefined;
  helperWorkspace = undefined;
  if (!workspace) return;
  try {
    assertOwnedHelperWorkspace(workspace);
    unlockControlForCleanup(workspace.path);
    rmSync(workspace.path, { recursive: true, force: true });
  } catch {
    // The exit hook is best-effort and must never widen a deletion target.
  }
}

async function cleanupHelper() {
  const helper = compiledHelper;
  const workspace = helperWorkspace;
  compiledHelper = undefined;
  helperWorkspace = undefined;
  if (!workspace) return;
  const cleanupErrors = [];
  if (helper) {
    try {
      await releasePrivateExecutableLeaseForRemoval(helper);
    } catch (error) {
      cleanupErrors.push(error);
    }
  }
  try {
    assertOwnedHelperWorkspace(workspace);
    unlockControlForCleanup(workspace.path);
    rmSync(workspace.path, { recursive: true, force: true });
  } catch (error) {
    cleanupErrors.push(error);
  }
  if (cleanupErrors.length > 1) {
    throw new AggregateError(cleanupErrors, 'Secret scanner helper workspace cleanup rejected');
  }
  if (cleanupErrors[0]) throw cleanupErrors[0];
}

function cleanupStaleHelperLeases() {
  const temporaryRoot = realpathSync(tmpdir());
  const pattern = /^piui-a23-scanner-helper-(\d+)-[A-Za-z0-9]+$/;
  for (const entry of readdirSync(temporaryRoot, { withFileTypes: true })) {
    const match = pattern.exec(entry.name);
    if (!match || !entry.isDirectory() || entry.isSymbolicLink()) continue;
    const ownerPid = Number(match[1]);
    if (!Number.isSafeInteger(ownerPid) || ownerPid < 1 || ownerPid === process.pid) continue;
    try {
      process.kill(ownerPid, 0);
      continue;
    } catch (error) {
      if (error?.code !== 'ESRCH') continue;
    }
    const candidate = join(temporaryRoot, entry.name);
    const identity = lstatSync(candidate, { bigint: true });
    if (!identity.isDirectory() || identity.isSymbolicLink()
      || identity.uid !== BigInt(process.getuid()) || (identity.mode & 0o077n) !== 0n
      || realpathSync(candidate) !== candidate) {
      continue;
    }
    unlockControlForCleanup(candidate);
    rmSync(candidate, { recursive: true, force: true });
  }
}

function openPinnedScannerSource() {
  const path = fileURLToPath(new URL('./scan-secret-canary-helper.c', import.meta.url));
  let descriptor;
  let bytes;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = fstatSync(descriptor, { bigint: true });
    const pathname = lstatSync(path, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
      || before.uid !== BigInt(process.getuid()) || (before.mode & 0o022n) !== 0n
      || before.size < 1n || before.size > BigInt(SCANNER_SOURCE_MAX_BYTES)
      || !sameIdentity(before, pathname) || realpathSync(path) !== path) reject();
    bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count < 1) reject();
      offset += count;
    }
    const after = fstatSync(descriptor, { bigint: true });
    if (!sameIdentity(before, after)
      || createHash('sha256').update(bytes).digest('hex') !== SCANNER_SOURCE_SHA256) reject();
    return { bytes, descriptor, identity: after, path };
  } catch (error) {
    clearBuffer(bytes);
    if (descriptor !== undefined) closeSync(descriptor);
    throw error;
  }
}

function assertPinnedScannerSource(source) {
  const descriptor = fstatSync(source.descriptor, { bigint: true });
  const pathname = lstatSync(source.path, { bigint: true });
  if (!sameIdentity(source.identity, descriptor)
    || !sameIdentity(source.identity, pathname)
    || realpathSync(source.path) !== source.path
    || createHash('sha256').update(source.bytes).digest('hex') !== SCANNER_SOURCE_SHA256) reject();
}

async function assertHelper(helper) {
  try {
    await assertPrivateExecutableLease(helper);
  } catch {
    reject();
  }
}

async function ensureHelper(mode = 'normal') {
  cleanupStaleHelperLeases();
  const compilerInjection = mode === 'compiler-failure' || mode === 'compiler-timeout';
  if (!compilerInjection && compiledHelper) {
    await assertHelper(compiledHelper);
    return compiledHelper;
  }
  if (compilerInjection) {
    try { await cleanupHelper(); } catch { reject(); }
  }
  const workspacePath = mkdtempSync(join(realpathSync(tmpdir()), HELPER_WORKSPACE_PREFIX));
  chmodSync(workspacePath, 0o700);
  const workspaceItem = lstatSync(workspacePath, { bigint: true });
  helperWorkspace = Object.freeze({
    dev: workspaceItem.dev,
    ino: workspaceItem.ino,
    path: realpathSync(workspacePath),
  });
  if (!exitCleanupRegistered) {
    process.once('exit', cleanupHelperOnExit);
    exitCleanupRegistered = true;
  }

  let compilation;
  let compilerAuthority;
  let preparedHelper;
  let primaryError;
  let source;
  let prepared = false;
  try {
    source = openPinnedScannerSource();
    const output = join(workspacePath, 'compiled-scanner-helper');
    const command = mode === 'compiler-failure'
      ? '/usr/bin/false'
      : mode === 'compiler-timeout'
        ? '/bin/sleep'
        : APPLE_TOOLCHAIN_PATHS.clang;
    const args = mode === 'compiler-timeout'
      ? ['10']
      : mode === 'compiler-failure'
        ? []
        : [
            '-std=c11',
            '-Wall',
            '-Wextra',
            '-Werror',
            '-O2',
            '-isysroot',
            APPLE_TOOLCHAIN_PATHS.sdk,
            '-x',
            'c',
            '-',
            '-o',
            output,
          ];
    if (!compilerInjection) {
      compilerAuthority = captureAppleToolchainAuthority();
    }
    compilation = spawnSync(command, args, {
      cwd: workspacePath,
      encoding: null,
      env: {
        ...appleToolchainBuildEnvironment(),
        PATH: `${APPLE_TOOLCHAIN_PATHS.bin}:/usr/bin:/bin`,
        TMPDIR: workspacePath,
      },
      input: source.bytes,
      killSignal: 'SIGKILL',
      maxBuffer: 256 * 1024,
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: mode === 'compiler-timeout' ? INJECTED_TIMEOUT_MS : COMPILER_TIMEOUT_MS,
    });
    if (!compilerInjection) {
      revalidateAppleToolchainAuthority(compilerAuthority);
    }
    if (compilation.status !== 0 || compilation.signal !== null || compilation.error
      || !Buffer.isBuffer(compilation.stdout) || compilation.stdout.length !== 0
      || !Buffer.isBuffer(compilation.stderr) || compilation.stderr.length !== 0) reject();
    assertPinnedScannerSource(source);
    chmodSync(output, 0o500);
    compiledHelper = await capturePrivateExecutable({
      controlRoot: join(workspacePath, 'control'),
      executableName: 'scan-secret-canary-helper',
      sourcePath: output,
    });
    await assertHelper(compiledHelper);
    prepared = true;
    preparedHelper = compiledHelper;
  } catch (error) {
    primaryError = error;
  }

  const cleanupErrors = [];
  if (compilerAuthority) {
    try {
      releaseAppleToolchainAuthority(compilerAuthority);
    } catch (error) {
      cleanupErrors.push(error);
    }
  }
  for (const buffer of [compilation?.stdout, compilation?.stderr, source?.bytes]) {
    try { clearBuffer(buffer); } catch (error) { cleanupErrors.push(error); }
  }
  if (source?.descriptor !== undefined) {
    try { closeSync(source.descriptor); } catch (error) { cleanupErrors.push(error); }
  }
  if (!prepared || primaryError || cleanupErrors.length > 0) {
    try { await cleanupHelper(); } catch (error) { cleanupErrors.push(error); }
  }
  const cleanupError = cleanupErrors.length > 1
    ? new AggregateError(cleanupErrors, 'Secret scanner helper preparation cleanup rejected')
    : cleanupErrors[0];
  if (primaryError && cleanupError) {
    throw new AggregateError(
      [primaryError, cleanupError],
      'Secret scanner helper preparation and cleanup rejected',
    );
  }
  if (primaryError) throw primaryError;
  if (cleanupError) throw cleanupError;
  return preparedHelper;
}

function runtimeMode(value) {
  if (value === undefined) return 'normal';
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== 1 || !Object.hasOwn(value, 'mode')
    || ![
      'compiler-failure',
      'compiler-timeout',
      'helper-timeout',
      'helper-replacement',
      'hook-timeout',
    ].includes(value.mode)) {
    reject();
  }
  return value.mode;
}

function pathBytes(value) {
  let bytes;
  if (Buffer.isBuffer(value)) bytes = Buffer.from(value);
  else if (typeof value === 'string') bytes = Buffer.from(value, 'utf8');
  else reject();
  if (bytes.length === 0 || bytes.length > 4_095 || bytes[0] !== 0x2f || bytes.includes(0)) {
    clearBuffer(bytes);
    reject();
  }
  return bytes;
}

function appendPath(parts, value, configLength) {
  const bytes = pathBytes(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  parts.push(length, bytes);
  return configLength + length.length + bytes.length;
}

/**
 * Creates the bounded binary stdin contract used by the fixed scanner runner.
 * The canary is copied as raw bytes and is never converted to a JavaScript string.
 */
export function encodeCanaryScanFrame(options, includeHooks = false) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) reject();
  const { workspace, roots, authorised, canary } = options;
  if (!Buffer.isBuffer(canary)
    || canary.length < CANARY_SCAN_LIMITS.minCanaryBytes
    || canary.length > CANARY_SCAN_LIMITS.maxCanaryBytes
    || !Array.isArray(roots) || roots.length === 0 || roots.length > CANARY_SCAN_LIMITS.maxRoots
    || !Array.isArray(authorised) || authorised.length === 0
    || authorised.length > CANARY_SCAN_LIMITS.maxAuthorisedFiles) {
    reject();
  }

  const parts = [];
  let configLength = 0;
  try {
    configLength = appendPath(parts, workspace, configLength);
    for (const root of roots) configLength = appendPath(parts, root, configLength);
    for (const entry of authorised) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)
        || Object.keys(entry).length !== 2
        || !Number.isSafeInteger(entry.count) || entry.count < 1
        || entry.count > CANARY_SCAN_LIMITS.maxExpectedOccurrencesPerFile) {
        reject();
      }
      configLength = appendPath(parts, entry.path, configLength);
      const count = Buffer.alloc(4);
      count.writeUInt32BE(entry.count);
      parts.push(count);
      configLength += count.length;
    }
    if (configLength === 0 || configLength > CANARY_SCAN_LIMITS.maxConfigBytes) reject();

    const header = Buffer.alloc(FRAME_HEADER_BYTES);
    FRAME_MAGIC.copy(header, 0);
    header.writeUInt32BE(FRAME_VERSION, 8);
    header.writeUInt32BE(includeHooks ? FRAME_HOOK_FLAG : 0, 12);
    header.writeUInt32BE(configLength, 16);
    header.writeUInt32BE(canary.length, 20);
    header.writeUInt16BE(roots.length, 24);
    header.writeUInt16BE(authorised.length, 26);
    const frame = Buffer.concat([header, ...parts, canary], FRAME_HEADER_BYTES + configLength + canary.length);
    clearBuffer(header);
    return frame;
  } finally {
    for (const part of parts) clearBuffer(part);
  }
}

function decodeSandboxPath(bytes) {
  const path = bytes.toString('utf8');
  const roundTrip = Buffer.from(path, 'utf8');
  try {
    if (!roundTrip.equals(bytes)
      || !path.startsWith('/') || resolve(path) !== path || /[\0\r\n]/u.test(path)) reject();
    return path;
  } finally {
    clearBuffer(roundTrip);
  }
}

function scannerAuthorityFromFrame(frame) {
  const configLength = frame.readUInt32BE(16);
  const canaryLength = frame.readUInt32BE(20);
  const rootCount = frame.readUInt16BE(24);
  const authorisedCount = frame.readUInt16BE(26);
  const configEnd = FRAME_HEADER_BYTES + configLength;
  if (configLength < 1 || configLength > CANARY_SCAN_LIMITS.maxConfigBytes
    || canaryLength < CANARY_SCAN_LIMITS.minCanaryBytes
    || canaryLength > CANARY_SCAN_LIMITS.maxCanaryBytes
    || rootCount < 1 || rootCount > CANARY_SCAN_LIMITS.maxRoots
    || authorisedCount < 1 || authorisedCount > CANARY_SCAN_LIMITS.maxAuthorisedFiles
    || configEnd + canaryLength !== frame.length) reject();
  const canary = frame.subarray(configEnd);

  let offset = FRAME_HEADER_BYTES;
  const readPath = () => {
    if (offset + 4 > configEnd) reject();
    const length = frame.readUInt32BE(offset);
    offset += 4;
    if (length < 1 || length > 4_095 || offset + length > configEnd) reject();
    const bytes = frame.subarray(offset, offset + length);
    if (bytes.indexOf(canary) !== -1) reject();
    const path = decodeSandboxPath(bytes);
    offset += length;
    return path;
  };
  const workspace = readPath();
  const roots = Array.from({ length: rootCount }, readPath);
  for (let index = 0; index < authorisedCount; index += 1) {
    readPath();
    if (offset + 4 > configEnd) reject();
    const count = frame.readUInt32BE(offset);
    offset += 4;
    if (count < 1 || count > CANARY_SCAN_LIMITS.maxExpectedOccurrencesPerFile) reject();
  }
  if (offset !== configEnd) reject();
  for (const root of roots) {
    const rel = relative(workspace, root);
    if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || resolve(workspace, rel) !== root) reject();
  }
  return Object.freeze({ workspace, roots: Object.freeze(roots) });
}

function seatbeltPath(path) {
  return path.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
}

function sandboxPathAncestors(paths) {
  const ancestors = new Set(['/']);
  for (const path of paths) {
    const spellings = path.startsWith('/private/var/')
      ? [path, path.slice('/private'.length)]
      : [path];
    for (const spelling of spellings) {
      for (let current = dirname(spelling);; current = dirname(current)) {
        ancestors.add(current);
        if (current === dirname(current)) break;
      }
    }
  }
  return [...ancestors].sort();
}

export function canaryScannerSandbox(helperPath, workspace, roots) {
  if (typeof helperPath !== 'string' || !helperPath.startsWith('/')
    || resolve(helperPath) !== helperPath || /[\0\r\n]/u.test(helperPath)
    || typeof workspace !== 'string' || !workspace.startsWith('/')
    || resolve(workspace) !== workspace || /[\0\r\n]/u.test(workspace)
    || !Array.isArray(roots) || roots.length < 1 || roots.length > CANARY_SCAN_LIMITS.maxRoots) {
    reject();
  }
  for (const root of roots) {
    const rel = typeof root === 'string' ? relative(workspace, root) : '';
    if (!rel || rel === '..' || rel.startsWith(`..${sep}`)
      || resolve(root) !== root || resolve(workspace, rel) !== root || /[\0\r\n]/u.test(root)) reject();
  }
  const helper = seatbeltPath(helperPath);
  const metadata = sandboxPathAncestors([workspace, ...roots, helperPath])
    .map((path) => `      (literal "${seatbeltPath(path)}")`)
    .join('\n');
  const scanRoots = roots
    .flatMap((root) => [
      `      (literal "${seatbeltPath(root)}")`,
      `      (subpath "${seatbeltPath(root)}")`,
    ])
    .join('\n');
  return `(version 1)
  (deny default)
  (import "dyld-support.sb")
  (deny network*)
  (deny appleevent-send)
  (deny mach-lookup)
  (with-filter (process-path "/usr/bin/sandbox-exec")
    (allow process-exec (literal "${helper}")))
  (with-filter (process-path "${helper}")
    (allow file-read* file-test-existence
${metadata})
    (allow file-read* file-test-existence
      (literal "${seatbeltPath(workspace)}")
${scanRoots}))
  (allow file-read* file-test-existence file-map-executable
    (literal "${helper}")
    (subpath "/Library/Apple/System/Library")
    (subpath "/System/Library")
    (subpath "/usr/lib"))`;
}

function strictReport(bytes, status) {
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString('utf8'));
  } catch {
    reject();
  }
  if (status === 1) {
    if (JSON.stringify(parsed) !== JSON.stringify(SAFE_REJECTION)) reject();
    reject();
  }
  if (status !== 0 || !parsed || typeof parsed !== 'object' || Array.isArray(parsed)
    || JSON.stringify(Object.keys(parsed).sort()) !== JSON.stringify([...SUCCESS_KEYS].sort())
    || parsed.schemaVersion !== 1 || parsed.status !== 'pass'
    || parsed.unauthorisedOccurrences !== 0) {
    reject();
  }
  for (const key of SUCCESS_KEYS) {
    if (['schemaVersion', 'status'].includes(key)) continue;
    if (!Number.isSafeInteger(parsed[key]) || parsed[key] < 0) reject();
  }
  if (parsed.rootsScanned < 1 || parsed.rootsScanned > CANARY_SCAN_LIMITS.maxRoots
    || parsed.entriesScanned > CANARY_SCAN_LIMITS.maxEntries
    || parsed.filesScanned > parsed.entriesScanned
    || parsed.fileDataBytesScanned > CANARY_SCAN_LIMITS.maxAggregateFileDataBytes
    || parsed.metadataBytesScanned > CANARY_SCAN_LIMITS.maxMetadataBytes
    || parsed.authorisedFiles < 1
    || parsed.authorisedFiles > CANARY_SCAN_LIMITS.maxAuthorisedFiles
    || parsed.authorisedOccurrences > CANARY_SCAN_LIMITS.maxAuthorisedFiles
      * CANARY_SCAN_LIMITS.maxExpectedOccurrencesPerFile) {
    reject();
  }
  return Object.freeze(parsed);
}

function deadlineAfter(milliseconds) {
  let timer;
  const promise = new Promise((resolveDeadline) => {
    timer = setTimeout(() => resolveDeadline({ timedOut: true }), milliseconds);
  });
  timer.unref?.();
  return { promise, clear: () => clearTimeout(timer) };
}

async function awaitBoundedClose(closePromise) {
  const deadline = deadlineAfter(CHILD_CLOSE_TIMEOUT_MS);
  try {
    await Promise.race([closePromise, deadline.promise]);
  } finally {
    deadline.clear();
  }
}

async function invokeHook(child, testHook, hardDeadline) {
  const signal = child.stdio[3];
  const acknowledgement = child.stdio[4];
  if (!signal || !acknowledgement) reject();
  const seen = new Set();
  for await (const chunk of signal) {
    const phaseCodes = [...chunk];
    clearBuffer(chunk);
    for (const phaseCode of phaseCodes) {
      const phase = HOOK_PHASES.get(phaseCode);
      if (!phase || seen.has(phaseCode)) reject();
      seen.add(phaseCode);
      const hookResult = await Promise.race([
        Promise.resolve().then(() => testHook(phase)).then(() => ({ hookSettled: true })),
        hardDeadline,
      ]);
      if (!hookResult?.hookSettled) reject();
      const acknowledgementByte = Buffer.from([phaseCode]);
      try {
        if (!acknowledgement.write(acknowledgementByte)) reject();
      } finally {
        clearBuffer(acknowledgementByte);
      }
    }
    phaseCodes.fill(0);
  }
}

function replacePrivateHelperForTest(helper) {
  let bytes;
  try {
    bytes = readFileSync(helper.path);
    chmodSync(helper.controlRoot.path, 0o700);
    renameSync(helper.path, join(helper.controlRoot.path, 'original-helper'));
    writeFileSync(helper.path, bytes, { flag: 'wx', mode: 0o500 });
    chmodSync(helper.path, 0o500);
    chmodSync(helper.controlRoot.path, 0o500);
  } finally {
    clearBuffer(bytes);
  }
}

/** Runs a pre-encoded frame and clears that caller-owned input buffer on every path. */
export async function runCanaryScannerFrame(frame, testHook, runtimeTestControl) {
  if (!Buffer.isBuffer(frame) || frame.length < FRAME_HEADER_BYTES
    || frame.length > MAX_FRAME_BYTES || !frame.subarray(0, 8).equals(FRAME_MAGIC)) {
    clearBuffer(frame);
    reject();
  }
  const frameUsesHooks = frame.readUInt32BE(12) === FRAME_HOOK_FLAG;
  if (frameUsesHooks !== (typeof testHook === 'function')) {
    clearBuffer(frame);
    reject();
  }

  let stdout = Buffer.alloc(0);
  let stderr = Buffer.alloc(0);
  let child;
  let closePromise;
  let hardDeadline;
  let hardTimedOut = false;
  let mode = 'normal';
  let helper;
  try {
    mode = runtimeMode(runtimeTestControl);
    const authority = scannerAuthorityFromFrame(frame);
    helper = await ensureHelper(mode);
    await assertHelper(helper);
    if (mode === 'helper-replacement') replacePrivateHelperForTest(helper);
    await assertHelper(helper);
    const profile = canaryScannerSandbox(helper.path, authority.workspace, authority.roots);
    await assertHelper(helper);
    child = spawn('/usr/bin/sandbox-exec', ['-p', profile, helper.path], {
      env: {},
      stdio: ['pipe', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe'],
    });
    let spawnError;
    closePromise = new Promise((resolveClose) => {
      child.once('error', (error) => {
        spawnError = error;
      });
      child.once('close', (status, signal) => resolveClose({ status, signal }));
    });
    child.stdin.on('error', () => undefined);
    if (mode !== 'helper-timeout') child.stdin.end(frame);

    let outputRejected = false;
    child.stdout.on('data', (chunk) => {
      if (stdout.length + chunk.length > MAX_HELPER_OUTPUT_BYTES) {
        outputRejected = true;
        child.kill('SIGKILL');
        clearBuffer(chunk);
        return;
      }
      const previous = stdout;
      stdout = Buffer.concat([stdout, chunk]);
      clearBuffer(previous);
      clearBuffer(chunk);
    });
    child.stderr.on('data', (chunk) => {
      if (stderr.length + chunk.length > MAX_HELPER_OUTPUT_BYTES) {
        outputRejected = true;
        child.kill('SIGKILL');
        clearBuffer(chunk);
        return;
      }
      const previous = stderr;
      stderr = Buffer.concat([stderr, chunk]);
      clearBuffer(previous);
      clearBuffer(chunk);
    });

    hardDeadline = deadlineAfter(
      ['helper-timeout', 'hook-timeout'].includes(mode)
        ? INJECTED_TIMEOUT_MS
        : HELPER_TIMEOUT_MS,
    );
    let hookError;
    const hookTask = frameUsesHooks
      ? invokeHook(child, testHook, hardDeadline.promise).catch((error) => {
        hookError = error;
        child.kill('SIGKILL');
      })
      : Promise.resolve();
    const terminal = await Promise.race([
      Promise.all([closePromise, hookTask]).then(([completion]) => ({ completion })),
      hardDeadline.promise,
    ]);
    if (terminal?.timedOut) {
      hardTimedOut = true;
      child.kill('SIGKILL');
      await awaitBoundedClose(closePromise);
      reject();
    }
    const { completion } = terminal;
    if (hookError || spawnError || completion.signal || outputRejected || stderr.length !== 0) reject();
    await assertHelper(helper);
    return strictReport(stdout, completion.status);
  } finally {
    hardDeadline?.clear();
    if (child && child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    if (closePromise) await awaitBoundedClose(closePromise);
    child?.stdin?.destroy();
    child?.stdout?.removeAllListeners('data');
    child?.stderr?.removeAllListeners('data');
    child?.stdout?.destroy();
    child?.stderr?.destroy();
    child?.stdio?.[5]?.destroy();
    clearBuffer(frame);
    clearBuffer(stdout);
    clearBuffer(stderr);
    if (hardTimedOut || mode !== 'normal') {
      try { await cleanupHelper(); } catch { reject(); }
    }
  }
}

/**
 * Scans only exact roots beneath a caller-created, canonical owner-private workspace.
 * The mutable canary supplied by the caller is erased before this promise settles.
 */
export async function scanSecretCanary(options) {
  const canary = options?.canary;
  const testHook = options?.[CANARY_SCAN_TEST_HOOK];
  const runtimeTestControl = options?.[CANARY_SCAN_RUNTIME_TEST_HOOK];
  if (testHook !== undefined && typeof testHook !== 'function') {
    clearBuffer(canary);
    reject();
  }
  let frame;
  try {
    frame = encodeCanaryScanFrame(options, testHook !== undefined);
    return await runCanaryScannerFrame(frame, testHook, runtimeTestControl);
  } finally {
    clearBuffer(frame);
    clearBuffer(canary);
  }
}

async function readBoundedStandardInput() {
  const chunks = [];
  let total = 0;
  try {
    for await (const chunk of process.stdin) {
      if (!Buffer.isBuffer(chunk) || total + chunk.length > MAX_FRAME_BYTES) {
        clearBuffer(chunk);
        reject();
      }
      chunks.push(chunk);
      total += chunk.length;
    }
    if (total < FRAME_HEADER_BYTES) reject();
    const input = Buffer.alloc(total);
    let offset = 0;
    for (const chunk of chunks) {
      chunk.copy(input, offset);
      offset += chunk.length;
      clearBuffer(chunk);
    }
    chunks.length = 0;
    return input;
  } finally {
    for (const chunk of chunks) clearBuffer(chunk);
  }
}

export async function runCanaryScannerCli() {
  let input;
  try {
    if (process.argv.length !== 2) reject();
    input = await readBoundedStandardInput();
    const report = await runCanaryScannerFrame(input);
    process.stdout.write(`${JSON.stringify(report)}\n`);
    return 0;
  } catch {
    process.stdout.write(`${JSON.stringify(SAFE_REJECTION)}\n`);
    return 1;
  } finally {
    clearBuffer(input);
  }
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  process.exitCode = await runCanaryScannerCli();
}
