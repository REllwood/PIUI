import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readSync,
  realpathSync,
  writeSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  assertDescriptorHasNoAcl,
  captureSystemDescriptorAclInspector,
} from './descriptor-acl.mjs';
import {
  APPLE_TOOLCHAIN_PATHS,
  appleToolchainBuildEnvironment,
  captureAppleToolchainAuthority,
  releaseAppleToolchainAuthority,
  revalidateAppleToolchainAuthority,
} from './apple-toolchain-trust.mjs';

const HELPER_SOURCE = fileURLToPath(new URL('./exclusive-rename.c', import.meta.url));
const EXPECTED_HELPER_SOURCE_SHA256 = 'ca66f50bec496bebb4c63c1a7fcaa328160e7179afc49b56a1a4bd96ab9da9ef';
const EXPECTED_HELPER_DYLIB_SHA256 = '86326d0672312dcc8ff440fa5576a4826aca32a3bebffe4c56a11bc2a769c94c';
const MAX_SOURCE_BYTES = 64 * 1024;
const MAX_HELPER_BYTES = 4 * 1024 * 1024;
const MAX_CHILD_OUTPUT_BYTES = 64 * 1024;
// These are hang cut-offs, not latency expectations. Formal packaging can put
// authenticated Clang and the system Ruby loader under sustained filesystem
// pressure; their output, identity and exit status are still checked exactly.
const COMPILER_TIMEOUT_MS = 120_000;
const HELPER_TIMEOUT_MS = 30_000;
const RENAME_COMPLETED_REJECTED_STATUS = 76;
const SYSTEM_ACL_INSPECTOR = process.platform === 'darwin'
  ? captureSystemDescriptorAclInspector()
  : undefined;
const COMPILER_SESSIONS = new WeakMap();
const RUBY_DYLIB_BROKER = [
  'series = RUBY_VERSION[/\\A\\d+\\.\\d+/]',
  'base = "/System/Library/Frameworks/Ruby.framework/Versions/#{series}/usr/lib/ruby/#{series}.0"',
  'extensions = Dir[File.join(base, "*", "fiddle.bundle")]',
  'exit 125 unless extensions.length == 1',
  'require extensions[0]',
  'def Fiddle.last_error; Thread.current[:__FIDDLE_LAST_ERROR__]; end',
  'def Fiddle.last_error=(error); Thread.current[:__FIDDLE_LAST_ERROR__] = error; end',
  'exit 125 if ARGV.empty? || ARGV.any? { |value| value.include?("\\0") }',
  'values = ARGV.map { |value| (value + "\\0").b }',
  'pointers = values.map { |value| Fiddle::Pointer[value] }',
  'format = Fiddle::SIZEOF_VOIDP == 8 ? "Q" : "L"',
  'vector = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP * (pointers.length + 1))',
  'pointers.each_with_index { |pointer, index| vector[index * Fiddle::SIZEOF_VOIDP, Fiddle::SIZEOF_VOIDP] = [pointer.to_i].pack(format) }',
  'vector[pointers.length * Fiddle::SIZEOF_VOIDP, Fiddle::SIZEOF_VOIDP] = [0].pack(format)',
  'handle = Fiddle::Handle.new("/dev/fd/9")',
  'entry = Fiddle::Function.new(handle["main"], [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT)',
  'status = entry.call(pointers.length, vector)',
  'exit 125 unless status.is_a?(Integer) && status.between?(0, 255)',
  'exit status',
].join(';');

export function beginExclusiveRenameCompilerSession() {
  const authority = captureAppleToolchainAuthority();
  const token = Object.freeze({});
  COMPILER_SESSIONS.set(token, Object.freeze({ authority }));
  return token;
}

export function endExclusiveRenameCompilerSession(token) {
  const session = COMPILER_SESSIONS.get(token);
  if (!session) reject();
  COMPILER_SESSIONS.delete(token);
  const { authority } = session;
  releaseAppleToolchainAuthority(authority);
}

export class ExclusiveRenameError extends Error {
  constructor({ operationCompleted = false, receipt } = {}) {
    super(operationCompleted
      ? 'Exclusive directory rename completed but finalisation rejected'
      : 'Exclusive directory rename rejected');
    this.name = 'ExclusiveRenameError';
    this.code = operationCompleted
      ? 'exclusive-rename-completed-finalisation-rejected'
      : 'exclusive-rename-rejected';
    this.operationCompleted = operationCompleted;
    if (receipt) this.receipt = receipt;
    this.stack = `${this.name}: ${this.message}`;
  }
}

function reject() {
  throw new ExclusiveRenameError();
}

function sameLease(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function sameRegularFileObject(left, right) {
  return left.isFile() && right.isFile()
    && !left.isSymbolicLink() && !right.isSymbolicLink()
    && left.dev === right.dev
    && left.ino === right.ino
    && left.uid === right.uid
    && left.gid === right.gid
    && left.nlink === 1n
    && right.nlink === 1n;
}

function sameDirectoryIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid;
}

function currentUid() {
  if (typeof process.getuid !== 'function' || typeof process.geteuid !== 'function') reject();
  const uid = process.getuid();
  if (!Number.isSafeInteger(uid) || uid < 0 || process.geteuid() !== uid) reject();
  return BigInt(uid);
}

function safeOwnedDirectory(path, expectedUid, { exactPrivate = true } = {}) {
  const state = lstatSync(path, { bigint: true });
  if (!state.isDirectory() || state.isSymbolicLink() || state.uid !== expectedUid
    || (exactPrivate
      ? (state.mode & 0o777n) !== 0o700n
      : (state.mode & 0o022n) !== 0n)
    || realpathSync(path) !== path) reject();
  return state;
}

function assertHeldOwnedDirectory(directory, expectedUid, { exactPrivate = true } = {}) {
  const descriptor = fstatSync(directory.fd, { bigint: true });
  const pathname = lstatSync(directory.path, { bigint: true });
  if (!descriptor.isDirectory() || descriptor.isSymbolicLink()
    || !sameDirectoryIdentity(descriptor, directory.identity)
    || !sameDirectoryIdentity(descriptor, pathname)
    || descriptor.uid !== expectedUid
    || (exactPrivate
      ? (descriptor.mode & 0o777n) !== 0o700n
      : (descriptor.mode & 0o022n) !== 0n)
    || realpathSync(directory.path) !== directory.path) reject();
  if (SYSTEM_ACL_INSPECTOR) assertDescriptorHasNoAcl(directory.fd, SYSTEM_ACL_INSPECTOR);
  return descriptor;
}

function assertMissing(path) {
  try {
    lstatSync(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  reject();
}

function readExactFile(path, expectedUid) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
    || before.uid !== expectedUid || (before.mode & 0o022n) !== 0n
    || before.size < 1n || before.size > BigInt(MAX_SOURCE_BYTES)) reject();
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC);
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!sameLease(before, opened)) reject();
    const bytes = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count < 1) reject();
      offset += count;
    }
    const after = fstatSync(fd, { bigint: true });
    const pathAfter = lstatSync(path, { bigint: true });
    if (!sameLease(opened, after) || !sameLease(opened, pathAfter)) reject();
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function descriptorSha256(fd, state) {
  if (!state.isFile() || state.size < 1n || state.size > BigInt(MAX_HELPER_BYTES)) reject();
  const digest = createHash('sha256');
  const buffer = Buffer.allocUnsafe(64 * 1024);
  let offset = 0;
  const size = Number(state.size);
  while (offset < size) {
    const count = readSync(fd, buffer, 0, Math.min(buffer.length, size - offset), offset);
    if (count < 1) reject();
    digest.update(buffer.subarray(0, count));
    offset += count;
  }
  buffer.fill(0);
  return digest.digest('hex');
}

function writePrivateFile(path, bytes) {
  const fd = openSync(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL
      | constants.O_NOFOLLOW | constants.O_CLOEXEC,
    0o600,
  );
  try {
    let offset = 0;
    while (offset < bytes.length) {
      const count = writeSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count < 1) reject();
      offset += count;
    }
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function loadBoundHelperSource() {
  const bytes = readExactFile(HELPER_SOURCE, currentUid());
  if (createHash('sha256').update(bytes).digest('hex') !== EXPECTED_HELPER_SOURCE_SHA256) {
    bytes.fill(0);
    reject();
  }
  return bytes;
}

const BOUND_HELPER_SOURCE = loadBoundHelperSource();

function strictChildResult(result) {
  return !result.error
    && result.signal === null
    && Buffer.isBuffer(result.stdout)
    && result.stdout.length === 0
    && Buffer.isBuffer(result.stderr)
    && result.stderr.length === 0;
}

function strictChildSucceeded(result) {
  return strictChildResult(result) && result.status === 0;
}

function compileHelper(
  workspace,
  expectedUid,
  ownedEntries,
  compilerSession,
  testSynchronization,
) {
  assertHeldOwnedDirectory(workspace, expectedUid);
  const sourceBytes = Buffer.from(BOUND_HELPER_SOURCE);
  const sourceSha256 = createHash('sha256').update(sourceBytes).digest('hex');
  const privateSource = join(workspace.path, `exclusive-rename-${sourceSha256}.c`);
  const output = join(workspace.path, `exclusive-rename-${sourceSha256}.dylib`);
  let compilation;
  let compilerAuthority;
  let compilerAuthorityOwned = false;
  let compiled;
  let helperFd;
  let outputFd;
  let primaryError;
  let sourceFd;
  let completed = false;
  try {
    writePrivateFile(privateSource, sourceBytes);
    const copiedSource = readExactFile(privateSource, expectedUid);
    try {
      if (createHash('sha256').update(copiedSource).digest('hex') !== sourceSha256) reject();
    } finally {
      copiedSource.fill(0);
    }
    const privateSourceIdentity = lstatSync(privateSource, { bigint: true });
    if (!privateSourceIdentity.isFile()
      || privateSourceIdentity.isSymbolicLink()
      || privateSourceIdentity.nlink !== 1n
      || privateSourceIdentity.uid !== expectedUid
      || (privateSourceIdentity.mode & 0o777n) !== 0o600n
      || realpathSync(privateSource) !== privateSource) reject();
    sourceFd = openSync(
      privateSource,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
    );
    const heldPrivateSource = fstatSync(sourceFd, { bigint: true });
    if (!sameLease(privateSourceIdentity, heldPrivateSource)
      || descriptorSha256(sourceFd, heldPrivateSource) !== sourceSha256) reject();
    ownedEntries.push(Object.freeze({
      identity: privateSourceIdentity,
      name: basename(privateSource),
    }));
    outputFd = openSync(
      output,
      constants.O_RDWR | constants.O_CREAT | constants.O_EXCL
        | constants.O_NOFOLLOW | constants.O_CLOEXEC,
      0o600,
    );
    const outputIdentity = fstatSync(outputFd, { bigint: true });
    const outputPathIdentity = lstatSync(output, { bigint: true });
    if (!sameLease(outputIdentity, outputPathIdentity)
      || !outputIdentity.isFile()
      || outputIdentity.isSymbolicLink()
      || outputIdentity.nlink !== 1n
      || outputIdentity.uid !== expectedUid
      || (outputIdentity.mode & 0o777n) !== 0o600n
      || outputIdentity.size !== 0n
      || realpathSync(output) !== output) reject();
    const session = compilerSession === undefined
      ? undefined
      : COMPILER_SESSIONS.get(compilerSession);
    if (compilerSession !== undefined && !session) reject();
    if (session) {
      compilerAuthority = session.authority;
      revalidateAppleToolchainAuthority(compilerAuthority);
    } else {
      compilerAuthority = captureAppleToolchainAuthority();
      compilerAuthorityOwned = true;
    }
    compilation = spawnSync(APPLE_TOOLCHAIN_PATHS.clang, [
      '-std=c11',
      '-Wall',
      '-Wextra',
      '-Werror',
      '-O2',
      '-dynamiclib',
      '-isysroot',
      APPLE_TOOLCHAIN_PATHS.sdk,
      '-x',
      'c',
      '-',
      '-o',
      '/dev/fd/3',
    ], {
      cwd: workspace.path,
      encoding: null,
      env: {
        ...appleToolchainBuildEnvironment(),
        PATH: `${APPLE_TOOLCHAIN_PATHS.bin}:/usr/bin:/bin`,
        TMPDIR: workspace.path,
      },
      input: sourceBytes,
      killSignal: 'SIGKILL',
      maxBuffer: MAX_CHILD_OUTPUT_BYTES,
      stdio: ['pipe', 'pipe', 'pipe', outputFd],
      timeout: COMPILER_TIMEOUT_MS,
    });
    waitForTestSynchronization(testSynchronization);
    revalidateAppleToolchainAuthority(compilerAuthority);
    const privateSourceAfter = lstatSync(privateSource, { bigint: true });
    const heldPrivateSourceAfter = fstatSync(sourceFd, { bigint: true });
    fsyncSync(outputFd);
    const heldOutputAfter = fstatSync(outputFd, { bigint: true });
    const outputPathAfter = lstatSync(output, { bigint: true });
    const helperSha256 = descriptorSha256(outputFd, heldOutputAfter);
    if (!sameLease(privateSourceIdentity, privateSourceAfter)
      || !sameLease(privateSourceIdentity, heldPrivateSourceAfter)
      || descriptorSha256(sourceFd, heldPrivateSourceAfter) !== sourceSha256
      || !sameRegularFileObject(outputIdentity, heldOutputAfter)
      || !sameLease(heldOutputAfter, outputPathAfter)
      || heldOutputAfter.size < 1n
      || heldOutputAfter.size > BigInt(MAX_HELPER_BYTES)
      || (heldOutputAfter.mode & 0o022n) !== 0n
      || helperSha256 !== EXPECTED_HELPER_DYLIB_SHA256
      || realpathSync(output) !== output
      || !strictChildSucceeded(compilation)) reject();
    assertHeldOwnedDirectory(workspace, expectedUid);
    fchmodSync(outputFd, 0o700);
    fsyncSync(outputFd);
    const helper = fstatSync(outputFd, { bigint: true });
    const helperPath = lstatSync(output, { bigint: true });
    if (!helper.isFile() || helper.isSymbolicLink() || helper.nlink !== 1n
      || helper.uid !== expectedUid || (helper.mode & 0o777n) !== 0o700n
      || helper.size < 1n
      || !sameLease(helper, helperPath)
      || descriptorSha256(outputFd, helper) !== EXPECTED_HELPER_DYLIB_SHA256
      || realpathSync(output) !== output) reject();
    helperFd = outputFd;
    outputFd = undefined;
    ownedEntries.push(Object.freeze({
      identity: helper,
      name: basename(output),
    }));
    compiled = Object.freeze({
      fd: helperFd,
      identity: helper,
      path: output,
      sha256: helperSha256,
      sourceFd,
      sourceIdentity: privateSourceIdentity,
      sourceName: basename(privateSource),
      sourceSha256,
      workspace,
    });
    completed = true;
  } catch (error) {
    primaryError = error;
  }

  const cleanupErrors = [];
  if (compilerAuthorityOwned && compilerAuthority) {
    try {
      releaseAppleToolchainAuthority(compilerAuthority);
    } catch (error) {
      cleanupErrors.push(error);
    }
  }
  for (const buffer of [sourceBytes, compilation?.stdout, compilation?.stderr]) {
    if (!Buffer.isBuffer(buffer)) continue;
    try { buffer.fill(0); } catch (error) { cleanupErrors.push(error); }
  }
  if (!completed || primaryError || cleanupErrors.length > 0) {
    for (const descriptor of [outputFd, helperFd, sourceFd]) {
      if (descriptor === undefined) continue;
      try { closeSync(descriptor); } catch (error) { cleanupErrors.push(error); }
    }
  }
  const cleanupError = cleanupErrors.length > 1
    ? new AggregateError(cleanupErrors, 'Exclusive rename compiler cleanup rejected')
    : cleanupErrors[0];
  if (primaryError && cleanupError) {
    throw new AggregateError(
      [primaryError, cleanupError],
      'Exclusive rename helper compilation and cleanup rejected',
    );
  }
  if (primaryError) throw primaryError;
  if (cleanupError) throw cleanupError;
  return compiled;
}

function createHelperWorkspace(parent, expectedUid) {
  assertHeldOwnedDirectory(parent, expectedUid);
  const path = mkdtempSync(join(parent.path, `piui-exclusive-rename-${process.pid}-`));
  let fd;
  try {
    const created = lstatSync(path, { bigint: true });
    if (!created.isDirectory() || created.isSymbolicLink() || created.uid !== expectedUid
      || realpathSync(path) !== path) reject();
    chmodSync(path, 0o700);
    const identity = safeOwnedDirectory(path, expectedUid);
    fd = openSync(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC | constants.O_DIRECTORY,
    );
    const workspace = Object.freeze({ fd, identity, parent, path });
    assertHeldOwnedDirectory(workspace, expectedUid);
    assertHeldOwnedDirectory(parent, expectedUid);
    return workspace;
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    throw error;
  }
}

function helperArguments(
  sourceParent,
  sourceName,
  destinationParent,
  destinationName,
  sourcePolicy,
  sourceParentState,
  destinationParentState,
  sourceState,
  testSynchronization,
) {
  const identity = (state) => [
    state.dev,
    state.ino,
    state.uid,
    state.gid,
    state.mode,
  ].map((value) => value.toString(10));
  const argumentsList = [
    sourceParent,
    sourceName,
    destinationParent,
    destinationName,
    sourcePolicy,
    ...identity(sourceParentState),
    ...identity(destinationParentState),
    ...identity(sourceState),
  ];
  if (testSynchronization) {
    argumentsList.push(
      testSynchronization.phase,
      testSynchronization.readyPath,
      testSynchronization.continuePath,
    );
  }
  return argumentsList;
}

function waitForTestSynchronization(synchronisation) {
  if (!synchronisation) return;
  const { continuePath, readyPath } = synchronisation;
  if (typeof readyPath !== 'string' || typeof continuePath !== 'string'
    || !isAbsolute(readyPath) || !isAbsolute(continuePath)
    || resolve(readyPath) !== readyPath || resolve(continuePath) !== continuePath
    || readyPath === continuePath || dirname(readyPath) !== dirname(continuePath)) reject();
  const parent = dirname(readyPath);
  safeOwnedDirectory(parent, currentUid());
  assertMissing(readyPath);
  assertMissing(continuePath);
  writePrivateFile(readyPath, Buffer.from('ready\n'));
  for (let attempt = 0; attempt < 30_000; attempt += 1) {
    try {
      const state = lstatSync(continuePath, { bigint: true });
      if (!state.isFile() || state.isSymbolicLink() || state.nlink !== 1n
        || state.uid !== currentUid() || (state.mode & 0o022n) !== 0n) reject();
      return;
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1);
  }
  reject();
}

function validateNativeTestSynchronization(synchronisation) {
  if (!synchronisation) return undefined;
  if (!['before-final-check', 'after-final-check', 'after-rename']
    .includes(synchronisation.phase)) reject();
  const { continuePath, readyPath } = synchronisation;
  if (typeof readyPath !== 'string' || typeof continuePath !== 'string'
    || !isAbsolute(readyPath) || !isAbsolute(continuePath)
    || resolve(readyPath) !== readyPath || resolve(continuePath) !== continuePath
    || readyPath === continuePath || dirname(readyPath) !== dirname(continuePath)) reject();
  safeOwnedDirectory(dirname(readyPath), currentUid());
  assertMissing(readyPath);
  assertMissing(continuePath);
  return Object.freeze({ continuePath, phase: synchronisation.phase, readyPath });
}

function helperExecutionSynchronizationPhase(synchronisation) {
  if (!synchronisation) return undefined;
  const phase = synchronisation.phase ?? 'before-final-check';
  if (!['before-final-check', 'after-final-check'].includes(phase)) reject();
  return phase;
}

function systemRubyStateMatches(state, inspector) {
  return state.isFile()
    && !state.isSymbolicLink()
    && state.nlink === 1n
    && Number(state.dev) === inspector.dev
    && Number(state.ino) === inspector.ino
    && Number(state.mode) === inspector.mode
    && state.uid === 0n
    && Number(state.gid) === inspector.gid
    && Number(state.size) === inspector.size
    && (state.mode & 0o022n) === 0n;
}

function openValidatedSystemRuby() {
  const inspector = SYSTEM_ACL_INSPECTOR;
  if (!inspector || inspector.path !== '/usr/bin/ruby'
    || realpathSync(inspector.path) !== inspector.path) reject();
  const pathState = lstatSync(inspector.path, { bigint: true });
  const fd = openSync(
    inspector.path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
  );
  let accepted = false;
  try {
    const held = fstatSync(fd, { bigint: true });
    if (!systemRubyStateMatches(held, inspector)
      || !sameLease(held, pathState)
      || descriptorSha256(fd, held) !== inspector.sha256) reject();
    accepted = true;
    return Object.freeze({ fd, identity: held, inspector });
  } finally {
    if (!accepted) closeSync(fd);
  }
}

function revalidateSystemRuby(lease) {
  const held = fstatSync(lease.fd, { bigint: true });
  const pathState = lstatSync(lease.inspector.path, { bigint: true });
  if (!sameLease(held, lease.identity)
    || !sameLease(held, pathState)
    || !systemRubyStateMatches(held, lease.inspector)
    || realpathSync(lease.inspector.path) !== lease.inspector.path
    || descriptorSha256(lease.fd, held) !== lease.inspector.sha256) reject();
}

function invokeHelper(helper, args, {
  acceptCompletedRejection = false,
  inheritedFds = [],
  input,
  testSynchronization,
} = {}) {
  const uid = currentUid();
  const synchronisationPhase = helperExecutionSynchronizationPhase(testSynchronization);
  assertHeldOwnedDirectory(helper.workspace, uid);
  assertHeldOwnedDirectory(helper.workspace.parent, uid);
  const before = lstatSync(helper.path, { bigint: true });
  const heldBefore = fstatSync(helper.fd, { bigint: true });
  if (!sameLease(before, helper.identity) || !sameLease(heldBefore, helper.identity)
    || descriptorSha256(helper.fd, heldBefore) !== helper.sha256
    || !Array.isArray(inheritedFds)
    || inheritedFds.length > 6
    || inheritedFds.some((fd) => !Number.isSafeInteger(fd) || fd < 3 || fd > 255)
    || new Set(inheritedFds).size !== inheritedFds.length
    || (input !== undefined && !Buffer.isBuffer(input))) reject();
  if (synchronisationPhase === 'before-final-check') {
    waitForTestSynchronization(testSynchronization);
  }
  const immediatelyBefore = lstatSync(helper.path, { bigint: true });
  const heldImmediatelyBefore = fstatSync(helper.fd, { bigint: true });
  if (!sameLease(before, immediatelyBefore)
    || !sameLease(heldBefore, heldImmediatelyBefore)
    || descriptorSha256(helper.fd, heldImmediatelyBefore) !== helper.sha256) reject();
  if (synchronisationPhase === 'after-final-check') {
    waitForTestSynchronization(testSynchronization);
  }
  const stdio = Array.from(
    { length: 10 },
    (_, fd) => (fd === 0 ? (input === undefined ? 'ignore' : 'pipe') : fd < 3 ? 'pipe' : 'ignore'),
  );
  inheritedFds.forEach((fd, index) => { stdio[index + 3] = fd; });
  stdio[7] = helper.workspace.fd;
  stdio[8] = helper.workspace.parent.fd;
  stdio[9] = helper.fd;
  let outcome;
  let primaryError;
  let result;
  let rubyLease;
  try {
    rubyLease = openValidatedSystemRuby();
    result = spawnSync(rubyLease.inspector.path, [
      '--disable=gems,rubyopt,did_you_mean',
      '-C/',
      '-e',
      RUBY_DYLIB_BROKER,
      '--',
      helper.path,
      ...args,
    ], {
      cwd: '/',
      encoding: null,
      env: { PATH: '/usr/bin:/bin' },
      input,
      killSignal: 'SIGKILL',
      maxBuffer: MAX_CHILD_OUTPUT_BYTES,
      stdio,
      timeout: testSynchronization ? COMPILER_TIMEOUT_MS : HELPER_TIMEOUT_MS,
    });
    const after = lstatSync(helper.path, { bigint: true });
    const heldAfter = fstatSync(helper.fd, { bigint: true });
    revalidateSystemRuby(rubyLease);
    assertHeldOwnedDirectory(helper.workspace, uid);
    assertHeldOwnedDirectory(helper.workspace.parent, uid);
    if (!sameLease(before, after) || !sameLease(heldBefore, heldAfter)
      || descriptorSha256(helper.fd, heldAfter) !== helper.sha256
      || !strictChildResult(result)
      || (result.status !== 0
        && !(acceptCompletedRejection
          && result.status === RENAME_COMPLETED_REJECTED_STATUS))) reject();
    outcome = Object.freeze({
      completedRejection: result.status === RENAME_COMPLETED_REJECTED_STATUS,
    });
  } catch (error) {
    primaryError = error;
  }
  const cleanupErrors = [];
  for (const buffer of [result?.stdout, result?.stderr]) {
    if (!Buffer.isBuffer(buffer)) continue;
    try { buffer.fill(0); } catch (error) { cleanupErrors.push(error); }
  }
  if (rubyLease) {
    try { closeSync(rubyLease.fd); } catch (error) { cleanupErrors.push(error); }
  }
  const cleanupError = cleanupErrors.length > 1
    ? new AggregateError(cleanupErrors, 'Exclusive rename broker cleanup rejected')
    : cleanupErrors[0];
  if (primaryError && cleanupError) {
    throw new AggregateError(
      [primaryError, cleanupError],
      'Exclusive rename broker invocation and cleanup rejected',
    );
  }
  if (primaryError) throw primaryError;
  if (cleanupError) throw cleanupError;
  return outcome;
}

function sameUnlinkedFileIdentity(current, expected) {
  return current.isFile() && !current.isSymbolicLink()
    && current.dev === expected.dev
    && current.ino === expected.ino
    && current.mode === expected.mode
    && current.uid === expected.uid
    && current.gid === expected.gid
    && current.size === expected.size
    && current.nlink === 0n;
}

function validateCleanupTestSynchronization(synchronisation) {
  if (!synchronisation) return undefined;
  const { continuePath, readyPath } = synchronisation;
  if (typeof readyPath !== 'string' || typeof continuePath !== 'string'
    || !isAbsolute(readyPath) || !isAbsolute(continuePath)
    || resolve(readyPath) !== readyPath || resolve(continuePath) !== continuePath
    || readyPath === continuePath || dirname(readyPath) !== dirname(continuePath)) reject();
  safeOwnedDirectory(dirname(readyPath), currentUid());
  assertMissing(readyPath);
  assertMissing(continuePath);
  return Object.freeze({ continuePath, readyPath });
}

function cleanupHeldHelperWorkspace(helper, ownedEntries, testSynchronization) {
  const cleanupSynchronization = validateCleanupTestSynchronization(testSynchronization);
  const helperName = basename(helper.path);
  const sourceEntry = ownedEntries.find((entry) => entry.name === helper.sourceName);
  const helperEntry = ownedEntries.find((entry) => entry.name === helperName);
  if (ownedEntries.length !== 2 || !sourceEntry || !helperEntry
    || !sameLease(sourceEntry.identity, helper.sourceIdentity)
    || !sameLease(helperEntry.identity, helper.identity)) reject();
  const uid = currentUid();
  assertHeldOwnedDirectory(helper.workspace, uid);
  assertHeldOwnedDirectory(helper.workspace.parent, uid);
  const sourceBefore = fstatSync(helper.sourceFd, { bigint: true });
  const helperBefore = fstatSync(helper.fd, { bigint: true });
  const helperPathBefore = lstatSync(helper.path, { bigint: true });
  if (!sameLease(sourceBefore, helper.sourceIdentity)
    || !sameLease(helperBefore, helper.identity)
    || !sameLease(helperPathBefore, helper.identity)
    || descriptorSha256(helper.sourceFd, sourceBefore) !== helper.sourceSha256
    || descriptorSha256(helper.fd, helperBefore) !== helper.sha256) reject();
  const argumentsList = [
    '--cleanup-held-helper-workspace',
    helper.workspace.path,
    helper.sourceName,
    helperName,
    ...stateArguments(helper.sourceIdentity),
    ...stateArguments(helper.identity),
  ];
  if (cleanupSynchronization) {
    argumentsList.push(cleanupSynchronization.readyPath, cleanupSynchronization.continuePath);
  }
  const stdio = Array.from(
    { length: 10 },
    (_, descriptor) => (descriptor === 1 || descriptor === 2 ? 'pipe' : 'ignore'),
  );
  stdio[6] = helper.sourceFd;
  stdio[7] = helper.workspace.fd;
  stdio[8] = helper.workspace.parent.fd;
  stdio[9] = helper.fd;
  let primaryError;
  let result;
  let rubyLease;
  try {
    rubyLease = openValidatedSystemRuby();
    result = spawnSync(rubyLease.inspector.path, [
      '--disable=gems,rubyopt,did_you_mean',
      '-C/',
      '-e',
      RUBY_DYLIB_BROKER,
      '--',
      helper.path,
      ...argumentsList,
    ], {
      cwd: '/',
      encoding: null,
      env: { PATH: '/usr/bin:/bin' },
      killSignal: 'SIGKILL',
      maxBuffer: MAX_CHILD_OUTPUT_BYTES,
      stdio,
      timeout: cleanupSynchronization ? COMPILER_TIMEOUT_MS : HELPER_TIMEOUT_MS,
    });
    revalidateSystemRuby(rubyLease);
    if (!strictChildSucceeded(result)) reject();
    const sourceAfter = fstatSync(helper.sourceFd, { bigint: true });
    const helperAfter = fstatSync(helper.fd, { bigint: true });
    const workspaceAfter = fstatSync(helper.workspace.fd, { bigint: true });
    if (!sameUnlinkedFileIdentity(sourceAfter, helper.sourceIdentity)
      || !sameUnlinkedFileIdentity(helperAfter, helper.identity)
      || !sameDirectoryIdentity(workspaceAfter, helper.workspace.identity)
      || descriptorSha256(helper.sourceFd, sourceAfter) !== helper.sourceSha256
      || descriptorSha256(helper.fd, helperAfter) !== helper.sha256) reject();
    assertHeldOwnedDirectory(helper.workspace.parent, uid);
    assertMissing(helper.workspace.path);
  } catch (error) {
    primaryError = error;
  }
  const cleanupErrors = [];
  for (const buffer of [result?.stdout, result?.stderr]) {
    if (!Buffer.isBuffer(buffer)) continue;
    try { buffer.fill(0); } catch (error) { cleanupErrors.push(error); }
  }
  if (rubyLease) {
    try { closeSync(rubyLease.fd); } catch (error) { cleanupErrors.push(error); }
  }
  const cleanupError = cleanupErrors.length > 1
    ? new AggregateError(cleanupErrors, 'Exclusive rename workspace broker cleanup rejected')
    : cleanupErrors[0];
  if (primaryError && cleanupError) {
    throw new AggregateError(
      [primaryError, cleanupError],
      'Exclusive rename workspace cleanup and broker cleanup rejected',
    );
  }
  if (primaryError) throw primaryError;
  if (cleanupError) throw cleanupError;
}

function identityArguments(state) {
  return [state.dev, state.ino, state.uid, state.gid, state.mode]
    .map((value) => value.toString(10));
}

function stateArguments(state) {
  return [
    ...identityArguments(state),
    state.nlink,
    state.size,
    state.mtimeNs,
    state.ctimeNs,
  ].map((value) => value.toString(10));
}

function inspectHeldArguments(path, kind, state) {
  return ['--inspect-held', path, kind, ...stateArguments(state)];
}

function helperWorkspaceParent(path, expectedUid) {
  const requested = path === undefined ? realpathSync(tmpdir()) : path;
  if (typeof requested !== 'string' || !isAbsolute(requested)
    || resolve(requested) !== requested || realpathSync(requested) !== requested) reject();
  const pathname = safeOwnedDirectory(requested, expectedUid);
  const fd = openSync(
    requested,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC | constants.O_DIRECTORY,
  );
  try {
    const parent = Object.freeze({ fd, identity: pathname, path: requested });
    assertHeldOwnedDirectory(parent, expectedUid);
    return parent;
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function assertHelperWorkspaceParent(helper, parent) {
  const current = assertHeldOwnedDirectory(parent, currentUid());
  invokeHelper(
    helper,
    inspectHeldArguments(parent.path, 'mutable-directory', current),
    { inheritedFds: [parent.fd] },
  );
}

function withNonPublicationHelper(workspaceParent, compilerSession, operation) {
  const uid = currentUid();
  const parent = helperWorkspaceParent(workspaceParent, uid);
  let workspace;
  const ownedEntries = [];
  let helper;
  let primaryError;
  let value;
  try {
    workspace = createHelperWorkspace(parent, uid);
    helper = compileHelper(workspace, uid, ownedEntries, compilerSession);
    assertHelperWorkspaceParent(helper, parent);
    value = operation(helper);
  } catch (error) {
    primaryError = error;
  }
  const cleanupErrors = [];
  if (helper) {
    try {
      cleanupHeldHelperWorkspace(helper, ownedEntries);
    } catch (error) {
      cleanupErrors.push(error);
    }
  } else if (workspace) {
    cleanupErrors.push(new Error('Private filesystem helper cleanup authority is unavailable'));
  }
  for (const descriptor of [helper?.sourceFd, helper?.fd]) {
    if (descriptor === undefined) continue;
    try { closeSync(descriptor); } catch (error) { cleanupErrors.push(error); }
  }
  for (const descriptor of [workspace?.fd, parent.fd]) {
    if (descriptor === undefined) continue;
    try { closeSync(descriptor); } catch (error) { cleanupErrors.push(error); }
  }
  const cleanupError = cleanupErrors.length > 1
    ? new AggregateError(cleanupErrors, 'Private filesystem helper descriptor cleanup rejected')
    : cleanupErrors[0];
  if (primaryError && cleanupError) {
    throw new AggregateError([primaryError, cleanupError], 'Private filesystem helper and cleanup rejected');
  }
  if (primaryError) throw primaryError;
  if (cleanupError) throw cleanupError;
  return value;
}

export function assertHeldPathHasNoAcl({
  compilerSession,
  fd,
  helperWorkspaceParent: workspaceParent,
  identity,
  kind,
  path,
}) {
  if (!Number.isSafeInteger(fd) || fd < 3 || fd > 255
    || !identity || !['directory', 'file', 'mutable-directory'].includes(kind)
    || typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path) reject();
  withNonPublicationHelper(workspaceParent, compilerSession, (helper) => {
    const current = fstatSync(fd, { bigint: true });
    const mutableHelperParent = workspaceParent === undefined
      ? realpathSync(tmpdir())
      : workspaceParent;
    if (kind === 'mutable-directory'
      || (kind === 'directory' && path === mutableHelperParent)
      ? !sameDirectoryIdentity(current, identity)
      : !sameLease(current, identity)) reject();
    invokeHelper(helper, inspectHeldArguments(path, kind, current), { inheritedFds: [fd] });
  });
}

function inspectHeldEmptyDirectoryPlaceholder({
  compilerSession,
  fd,
  helperWorkspaceParent: workspaceParent,
  identity,
  path,
}) {
  if (!Number.isSafeInteger(fd) || fd < 3 || fd > 255 || !identity
    || typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path) reject();
  withNonPublicationHelper(workspaceParent, compilerSession, (helper) => {
    const current = fstatSync(fd, { bigint: true });
    if (!sameLease(current, identity) || !current.isDirectory()
      || current.isSymbolicLink() || current.uid !== currentUid()
      || (current.mode & 0o777n) !== 0o700n) reject();
    invokeHelper(helper, [
      '--inspect-held-empty-placeholder',
      path,
      ...stateArguments(current),
    ], { inheritedFds: [fd] });
    const after = fstatSync(fd, { bigint: true });
    const pathname = lstatSync(path, { bigint: true });
    if (!sameLease(current, after)
      || !sameLease(after, pathname)
      || (after.mode & 0o777n) !== 0o700n
      || realpathSync(path) !== path) reject();
  });
}

/** Prove the exact empty 0700 inode, allowing only stable macOS provenance metadata. */
export function assertHeldEmptyDirectoryPlaceholder(options) {
  inspectHeldEmptyDirectoryPlaceholder(options);
}

export function assertHeldTreeHasNoAcl({
  compilerSession,
  fd,
  helperWorkspaceParent: workspaceParent,
  identity,
  path,
  testOnlyAdvanceSharedOffset = false,
}) {
  if (!Number.isSafeInteger(fd) || fd < 3 || fd > 255 || !identity
    || typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path) reject();
  withNonPublicationHelper(workspaceParent, compilerSession, (helper) => {
    const current = fstatSync(fd, { bigint: true });
    if (!sameLease(current, identity)) reject();
    invokeHelper(helper, [
      testOnlyAdvanceSharedOffset
        ? '--inspect-held-tree-after-offset'
        : '--inspect-held-tree',
      path,
      ...stateArguments(current),
    ], { inheritedFds: [fd] });
  });
}

export function rewriteHeldRegularFile({
  bytes,
  compilerSession,
  fileFd,
  fileIdentity,
  helperWorkspaceParent: workspaceParent,
  name,
  parentFd,
  parentIdentity,
  parentPath,
}) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 1024 * 1024
    || !Number.isSafeInteger(parentFd) || parentFd < 3 || parentFd > 255
    || !Number.isSafeInteger(fileFd) || fileFd < 3 || fileFd > 255
    || fileFd === parentFd || !parentIdentity || !fileIdentity
    || typeof parentPath !== 'string' || !isAbsolute(parentPath)
    || resolve(parentPath) !== parentPath || typeof name !== 'string'
    || name.length < 1 || name.includes('/') || name === '.' || name === '..') reject();
  withNonPublicationHelper(workspaceParent, compilerSession, (helper) => {
    const currentParent = fstatSync(parentFd, { bigint: true });
    const currentFile = fstatSync(fileFd, { bigint: true });
    if (!sameLease(currentParent, parentIdentity) || !sameLease(currentFile, fileIdentity)) reject();
    invokeHelper(helper, [
      '--rewrite-held-file',
      parentPath,
      name,
      ...stateArguments(currentParent),
      ...stateArguments(currentFile),
    ], {
      inheritedFds: [parentFd, fileFd],
      input: bytes,
    });
  });
}

function openHeldRenameDescriptors({
  destinationParent,
  destinationParentIdentity,
  source,
  sourceIdentity,
  sourceParent,
  sourceParentIdentity,
}) {
  const descriptors = [];
  try {
    const sourceParentFd = openSync(
      sourceParent,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
    );
    descriptors.push(sourceParentFd);
    const destinationParentFd = openSync(
      destinationParent,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
    );
    descriptors.push(destinationParentFd);
    const sourceFd = openSync(
      source,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
    );
    descriptors.push(sourceFd);
    const heldSourceParent = fstatSync(sourceParentFd, { bigint: true });
    const heldDestinationParent = fstatSync(destinationParentFd, { bigint: true });
    const heldSource = fstatSync(sourceFd, { bigint: true });
    if (!sameDirectoryIdentity(heldSourceParent, sourceParentIdentity)
      || !sameDirectoryIdentity(heldDestinationParent, destinationParentIdentity)
      || !sameLease(heldSource, sourceIdentity)) reject();
    return Object.freeze({
      destinationParentFd,
      descriptors: Object.freeze(descriptors),
      sourceFd,
      sourceParentFd,
    });
  } catch (error) {
    for (const descriptor of descriptors.reverse()) {
      try { closeSync(descriptor); } catch { /* preserve the primary rejection */ }
    }
    throw error;
  }
}

/** Atomically renames one private directory to a missing path without replacement. */
export function exclusiveDirectoryRename(source, destination, {
  compilerSession,
  expectedDestinationParentIdentity,
  expectedParentIdentity,
  expectedSourceIdentity,
  expectedSourceParentIdentity,
  helperWorkspaceParent: workspaceParent,
  sourcePolicy = 'private-directory',
  testOnlySynchronization,
} = {}) {
  if (process.platform !== 'darwin') reject();
  if (typeof source !== 'string' || typeof destination !== 'string'
    || source.includes('\0') || destination.includes('\0')
    || !isAbsolute(source) || !isAbsolute(destination)
    || resolve(source) !== source || resolve(destination) !== destination
    || source === destination
    || !['private-directory', 'empty-placeholder'].includes(sourcePolicy)) reject();

  const sourceParent = dirname(source);
  const destinationParent = dirname(destination);
  const sourceName = basename(source);
  const destinationName = basename(destination);
  if ((sourceParent === destinationParent && sourceName === destinationName)
    || sourceName === '.' || sourceName === '..'
    || destinationName === '.' || destinationName === '..'
    || Buffer.byteLength(sourceName) > 255 || Buffer.byteLength(destinationName) > 255) reject();

  const uid = currentUid();
  const sourceParentBefore = safeOwnedDirectory(sourceParent, uid, { exactPrivate: false });
  const destinationParentBefore = safeOwnedDirectory(destinationParent, uid, { exactPrivate: false });
  const sourceBefore = safeOwnedDirectory(source, uid);
  const expectedSourceParent = expectedSourceParentIdentity ?? expectedParentIdentity;
  const expectedDestinationParent = expectedDestinationParentIdentity
    ?? (sourceParent === destinationParent ? expectedParentIdentity : undefined);
  if (sourceBefore.dev !== sourceParentBefore.dev
    || sourceBefore.dev !== destinationParentBefore.dev
    || (expectedSourceParent
      && !sameDirectoryIdentity(sourceParentBefore, expectedSourceParent))
    || (expectedDestinationParent
      && !sameDirectoryIdentity(destinationParentBefore, expectedDestinationParent))
    || (expectedSourceIdentity
      && !sameDirectoryIdentity(sourceBefore, expectedSourceIdentity))
      || realpathSync(source) !== source) reject();
  assertMissing(destination);

  const nativeTestSynchronization = validateNativeTestSynchronization(
    testOnlySynchronization?.native,
  );
  const helperExecTestSynchronization = testOnlySynchronization?.helperExec;
  const helperParent = helperWorkspaceParent(workspaceParent, uid);
  let held;
  try {
    held = openHeldRenameDescriptors({
      destinationParent,
      destinationParentIdentity: destinationParentBefore,
      source,
      sourceIdentity: sourceBefore,
      sourceParent,
      sourceParentIdentity: sourceParentBefore,
    });
  } catch (error) {
    closeSync(helperParent.fd);
    throw error;
  }
  let workspace;
  const ownedEntries = [];
  let helper;
  let primaryError;
  let operationCompleted = false;
  let receipt;
  try {
    workspace = createHelperWorkspace(helperParent, uid);
    helper = compileHelper(
      workspace,
      uid,
      ownedEntries,
      compilerSession,
      testOnlySynchronization?.compiler,
    );
    assertHelperWorkspaceParent(helper, helperParent);
    const sourceParentCurrent = safeOwnedDirectory(sourceParent, uid, { exactPrivate: false });
    const destinationParentCurrent = safeOwnedDirectory(destinationParent, uid, { exactPrivate: false });
    const sourceCurrent = safeOwnedDirectory(source, uid);
    if (!sameDirectoryIdentity(sourceParentBefore, sourceParentCurrent)
      || !sameDirectoryIdentity(destinationParentBefore, destinationParentCurrent)
      || !sameDirectoryIdentity(sourceBefore, sourceCurrent)) reject();
    assertMissing(destination);

    const nativeOutcome = invokeHelper(helper, helperArguments(
      sourceParent,
      sourceName,
      destinationParent,
      destinationName,
      sourcePolicy,
      sourceParentBefore,
      destinationParentBefore,
      sourceBefore,
      nativeTestSynchronization,
    ), {
      acceptCompletedRejection: true,
      inheritedFds: [held.sourceParentFd, held.destinationParentFd, held.sourceFd],
      testSynchronization: helperExecTestSynchronization,
    });
    operationCompleted = true;
    receipt = Object.freeze({
      destination,
      nativePostconditionAccepted: nativeOutcome.completedRejection === false,
      operationCompleted: true,
    });

    assertMissing(source);
    const sourceParentAfter = safeOwnedDirectory(sourceParent, uid, { exactPrivate: false });
    const destinationParentAfter = safeOwnedDirectory(destinationParent, uid, { exactPrivate: false });
    const destinationAfter = safeOwnedDirectory(destination, uid);
    const heldSourceAfter = fstatSync(held.sourceFd, { bigint: true });
    if (!sameDirectoryIdentity(sourceParentBefore, sourceParentAfter)
      || !sameDirectoryIdentity(destinationParentBefore, destinationParentAfter)
      || !sameDirectoryIdentity(sourceBefore, destinationAfter)
      || !sameDirectoryIdentity(sourceBefore, heldSourceAfter)
      || realpathSync(destination) !== destination) reject();
    receipt = Object.freeze({
      destination,
      destinationIdentity: Object.freeze({
        dev: destinationAfter.dev,
        gid: destinationAfter.gid,
        ino: destinationAfter.ino,
        mode: destinationAfter.mode,
        uid: destinationAfter.uid,
      }),
      destinationVerified: true,
      nativePostconditionAccepted: nativeOutcome.completedRejection === false,
      operationCompleted: true,
    });
    if (nativeOutcome.completedRejection) {
      throw new ExclusiveRenameError({ operationCompleted: true, receipt });
    }
  } catch (error) {
    primaryError = error;
  }

  const cleanupErrors = [];
  if (helper) {
    try {
      cleanupHeldHelperWorkspace(
        helper,
        ownedEntries,
        testOnlySynchronization?.cleanup,
      );
    } catch (error) {
      cleanupErrors.push(error);
    }
  } else if (workspace) {
    cleanupErrors.push(new Error('Exclusive rename helper cleanup authority is unavailable'));
  }
  for (const descriptor of [helper?.sourceFd, helper?.fd]) {
    if (descriptor === undefined) continue;
    try { closeSync(descriptor); } catch (error) { cleanupErrors.push(error); }
  }
  for (const descriptor of [workspace?.fd, helperParent.fd]) {
    if (descriptor === undefined) continue;
    try { closeSync(descriptor); } catch (error) { cleanupErrors.push(error); }
  }
  for (const descriptor of [...held.descriptors].reverse()) {
    try { closeSync(descriptor); } catch (error) { cleanupErrors.push(error); }
  }
  const cleanupError = cleanupErrors.length > 1
    ? new AggregateError(cleanupErrors, 'Exclusive directory rename descriptor cleanup rejected')
    : cleanupErrors[0];
  if (operationCompleted && (primaryError || cleanupError)) {
    throw new ExclusiveRenameError({ operationCompleted: true, receipt });
  }
  if (primaryError && cleanupError) {
    throw new AggregateError([primaryError, cleanupError], 'Exclusive directory rename and helper cleanup rejected');
  }
  if (primaryError) throw primaryError;
  if (cleanupError) throw cleanupError;
  return receipt;
}
