import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
  rmSync,
} from 'node:fs';
import { realpathSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { canonicalArchitectureJson } from './architecture-gate-schema.mjs';

const SHA256 = /^[0-9a-f]{64}$/u;
const TOKEN = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/u;
const nodeSha256 = '2e3f1286a7eb3736346ed1803e458a0ff909e2b2d5bc746144dcb76970e9b99d';
const nodeBytes = 112_928_848;
const envSha256 = '6e506aec3c0cff703ac1e66cedc6f1945354ad41339a38db4425c7c88227128f';
const rubySha256 = '9d6ff3e289c7d908e3c785e0bedd6692d1d6a3377965c88c04d847104b7c892c';
const pinsSha256 = '891a488ec9fad57e5500944c3ac7c08a89a90fe99154f772055dd22f30b75bb4';
const targetNames = Object.freeze({
  build: 'build-production.mjs',
  package: 'package-spike.mjs',
  record: 'record-architecture-gate.mjs',
});
const receiptKeys = Object.freeze([
  'bootstrapSourceDev',
  'bootstrapSourceIno',
  'bootstrapSourceSha256',
  'envSha256',
  'loaderPath',
  'loaderSha256',
  'mode',
  'nodeDev',
  'nodeIno',
  'nodePath',
  'nodeSha256',
  'nodeSize',
  'pinsSha256',
  'privateRoot',
  'privateRootDev',
  'privateRootIno',
  'repositoryRoot',
  'rootPid',
  'rubyDev',
  'rubyIno',
  'rubySha256',
  'schemaVersion',
  'stdlibSha256',
  'sourceManifestEntries',
  'sourceManifestPath',
  'sourceManifestSha256',
  'targetPath',
  'token',
]);

let cached;
let released = false;

function fail(message = 'Architecture bootstrap contract rejected') {
  throw new Error(message);
}

function inheritedDescriptor(value) {
  if (typeof value !== 'string' || !/^[0-9]+$/u.test(value)) fail();
  const descriptor = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(descriptor)
    || descriptor < 3
    || descriptor > 255
    || String(descriptor) !== value) fail();
  return descriptor;
}

function assertReadOnlyDescriptor(fd) {
  let writable;
  try {
    writable = openSync(`/dev/fd/${fd}`, constants.O_WRONLY);
  } catch (error) {
    if (error?.code === 'EACCES' || error?.code === 'EBADF') return;
    fail('Architecture bootstrap receipt descriptor access mode is unavailable');
  }
  closeSync(writable);
  fail('Architecture bootstrap receipt descriptor is writable');
}

function sameState(left, right) {
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

function exactKeys(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail();
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])) fail();
}

function heldBytes(fd, state, label) {
  if (state.size > 1_048_576n) fail(`${label} exceeds its byte bound`);
  const bytes = Buffer.alloc(Number(state.size));
  let offset = 0;
  while (offset < bytes.length) {
    const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
    if (count < 1) fail(`${label} ended during its held read`);
    offset += count;
  }
  return bytes;
}

function sha256Descriptor(fd, expectedState, label) {
  const held = fstatSync(fd, { bigint: true });
  if (!sameState(held, expectedState) || !held.isFile() || held.isSymbolicLink()) {
    fail(`${label} held identity changed`);
  }
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(1_048_576);
  let offset = 0;
  while (offset < Number(held.size)) {
    const length = Math.min(buffer.length, Number(held.size) - offset);
    const count = readSync(fd, buffer, 0, length, offset);
    if (count < 1) fail(`${label} ended during hashing`);
    hash.update(buffer.subarray(0, count));
    offset += count;
  }
  if (!sameState(held, fstatSync(fd, { bigint: true }))) {
    fail(`${label} changed during hashing`);
  }
  return hash.digest('hex');
}

function assertCachedBootstrapLease(bootstrap) {
  const node = fstatSync(bootstrap.nodeFd, { bigint: true });
  const nodePath = lstatSync(bootstrap.receipt.nodePath, { bigint: true });
  const root = fstatSync(bootstrap.rootFd, { bigint: true });
  const rootPath = lstatSync(bootstrap.receipt.privateRoot, { bigint: true });
  if (!sameState(node, bootstrap.nodeState)
    || !sameState(node, nodePath)
    || nodePath.isSymbolicLink()
    || !sameState(root, bootstrap.rootState)
    || !sameState(root, rootPath)
    || rootPath.isSymbolicLink()
    || realpathSync(process.execPath) !== bootstrap.receipt.nodePath
    || realpathSync(bootstrap.receipt.privateRoot) !== bootstrap.receipt.privateRoot) {
    fail('Architecture bootstrap retained execution lease changed');
  }
}

function sha256Path(path, expectedState, label) {
  const before = lstatSync(path, { bigint: true });
  if (!sameState(before, expectedState) || before.isSymbolicLink() || !before.isFile()) {
    fail(`${label} path identity changed`);
  }
  const hash = createHash('sha256');
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const held = fstatSync(descriptor, { bigint: true });
    if (!sameState(held, before)) fail(`${label} held identity changed`);
    const buffer = Buffer.allocUnsafe(1_048_576);
    let offset = 0;
    while (offset < Number(held.size)) {
      const length = Math.min(buffer.length, Number(held.size) - offset);
      const count = readSync(descriptor, buffer, 0, length, offset);
      if (count < 1) fail(`${label} ended during hashing`);
      hash.update(buffer.subarray(0, count));
      offset += count;
    }
    const after = fstatSync(descriptor, { bigint: true });
    const pathAfter = lstatSync(path, { bigint: true });
    if (!sameState(held, after) || !sameState(after, pathAfter)) {
      fail(`${label} changed during hashing`);
    }
  } finally {
    closeSync(descriptor);
  }
  return hash.digest('hex');
}

function parseReceipt(bytes) {
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail();
  }
  exactKeys(value, receiptKeys);
  if (`${canonicalArchitectureJson(value)}\n` !== bytes.toString('utf8')) fail();
  return value;
}

function assertSystemExecutable(path, { bytes, digest, mode, receiptDev, receiptIno }, label) {
  const state = lstatSync(path, { bigint: true });
  if (!state.isFile()
    || state.isSymbolicLink()
    || state.uid !== 0n
    || state.gid !== 0n
    || (state.mode & 0o777n) !== BigInt(mode)
    || state.size !== BigInt(bytes)
    || (receiptDev !== undefined && state.dev !== BigInt(receiptDev))
    || (receiptIno !== undefined && state.ino !== BigInt(receiptIno))
    || sha256Path(path, state, label) !== digest) fail(`${label} identity changed`);
}

function assertSourceManifest(bytes, expectedEntries) {
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail('Architecture bootstrap source manifest is invalid');
  }
  exactKeys(manifest, ['files', 'schemaVersion']);
  if (manifest.schemaVersion !== 1
    || !Array.isArray(manifest.files)
    || manifest.files.length !== expectedEntries
    || `${canonicalArchitectureJson(manifest)}\n` !== bytes.toString('utf8')) fail();
  let prior;
  const paths = new Set();
  for (const record of manifest.files) {
    exactKeys(record, ['mode', 'path', 'sha256', 'size']);
    if (typeof record.path !== 'string'
      || !/^(?:scripts|tests\/packaged)\/(?:[^/]+\/)*[^/]+\.(?:js|json|mjs|rb)$/u.test(record.path)
      || record.path.includes('/../')
      || record.path.includes('/./')
      || /[\\\0\r\n]/u.test(record.path)
      || paths.has(record.path)
      || (prior !== undefined && Buffer.from(prior).compare(Buffer.from(record.path)) >= 0)
      || !Number.isSafeInteger(record.mode)
      || (record.mode & 0o022) !== 0
      || !Number.isSafeInteger(record.size)
      || record.size < 0
      || record.size > 16 * 1_048_576
      || !SHA256.test(record.sha256)) fail();
    paths.add(record.path);
    prior = record.path;
  }
  return manifest;
}

export function assertArchitectureBootstrap({ repositoryRoot } = {}) {
  if (released) fail('Architecture bootstrap capability was already released');
  if (cached) {
    if (repositoryRoot !== undefined && cached.receipt.repositoryRoot !== repositoryRoot) fail();
    assertCachedBootstrapLease(cached);
    return cached;
  }
  const fdText = process.env.PIUI_ARCHITECTURE_BOOTSTRAP_FD;
  const token = process.env.PIUI_ARCHITECTURE_BOOTSTRAP_TOKEN;
  if (!TOKEN.test(token ?? '')) fail();
  const fd = inheritedDescriptor(fdText);
  assertReadOnlyDescriptor(fd);
  const state = fstatSync(fd, { bigint: true });
  if (!state.isFile()
    || state.isSymbolicLink()
    || state.nlink !== 1n
    || state.uid !== BigInt(process.getuid())
    || (state.mode & 0o777n) !== 0o400n
    || state.size < 128n
    || state.size > 64n * 1_024n) fail();
  const receiptBytes = heldBytes(fd, state, 'Architecture bootstrap receipt');
  const receipt = parseReceipt(receiptBytes);
  if (receipt.schemaVersion !== 1
    || !['build', 'package', 'record'].includes(receipt.mode)
    || receipt.token !== token
    || receipt.envSha256 !== envSha256
    || receipt.rubySha256 !== rubySha256
    || receipt.nodeSha256 !== nodeSha256
    || receipt.nodeSize !== nodeBytes
    || receipt.pinsSha256 !== pinsSha256
    || !SHA256.test(receipt.bootstrapSourceSha256)
    || !SHA256.test(receipt.loaderSha256)
    || !SHA256.test(receipt.sourceManifestSha256)
    || !SHA256.test(receipt.stdlibSha256)
    || !DECIMAL.test(receipt.nodeDev)
    || !DECIMAL.test(receipt.nodeIno)
    || !DECIMAL.test(receipt.bootstrapSourceDev)
    || !DECIMAL.test(receipt.bootstrapSourceIno)
    || !DECIMAL.test(receipt.privateRootDev)
    || !DECIMAL.test(receipt.privateRootIno)
    || !DECIMAL.test(receipt.rubyDev)
    || !DECIMAL.test(receipt.rubyIno)
    || !Number.isSafeInteger(receipt.rootPid)
    || receipt.rootPid < 1
    || !Number.isSafeInteger(receipt.sourceManifestEntries)
    || receipt.sourceManifestEntries < 50
    || receipt.sourceManifestEntries > 256) fail();
  if (repositoryRoot !== undefined && receipt.repositoryRoot !== repositoryRoot) fail();
  const repository = lstatSync(receipt.repositoryRoot, { bigint: true });
  if (!repository.isDirectory()
    || repository.isSymbolicLink()
    || repository.uid !== BigInt(process.getuid())
    || (repository.mode & 0o022n) !== 0n
    || realpathSync(receipt.repositoryRoot) !== receipt.repositoryRoot
    || receipt.targetPath !== resolve(
      receipt.repositoryRoot,
      'scripts',
      targetNames[receipt.mode],
    )) fail();
  assertSystemExecutable('/usr/bin/env', {
    bytes: 102_368,
    digest: envSha256,
    mode: 0o755,
  }, 'System env');
  assertSystemExecutable('/usr/bin/ruby', {
    bytes: 135_200,
    digest: rubySha256,
    mode: 0o555,
    receiptDev: receipt.rubyDev,
    receiptIno: receipt.rubyIno,
  }, 'System Ruby');
  const receiptPath = resolve(receipt.privateRoot, 'receipt.json');
  const receiptPathState = lstatSync(receiptPath, { bigint: true });
  if (receiptPathState.isSymbolicLink() || !sameState(state, receiptPathState)) fail();
  const root = lstatSync(receipt.privateRoot, { bigint: true });
  if (!root.isDirectory()
    || root.isSymbolicLink()
    || root.uid !== BigInt(process.getuid())
    || (root.mode & 0o777n) !== 0o700n
    || root.dev !== BigInt(receipt.privateRootDev)
    || root.ino !== BigInt(receipt.privateRootIno)
    || realpathSync(receipt.privateRoot) !== receipt.privateRoot) fail();
  let nodeFd;
  let rootFd;
  let candidate;
  try {
    nodeFd = openSync(receipt.nodePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    rootFd = openSync(receipt.privateRoot, constants.O_RDONLY | constants.O_NOFOLLOW
      | (constants.O_DIRECTORY ?? 0));
    const node = fstatSync(nodeFd, { bigint: true });
    const nodePath = lstatSync(receipt.nodePath, { bigint: true });
    const heldRoot = fstatSync(rootFd, { bigint: true });
    const rootPath = lstatSync(receipt.privateRoot, { bigint: true });
    if (!node.isFile()
      || node.isSymbolicLink()
      || node.nlink !== 1n
      || node.uid !== BigInt(process.getuid())
      || (node.mode & 0o777n) !== 0o500n
      || node.size !== BigInt(nodeBytes)
      || node.dev !== BigInt(receipt.nodeDev)
      || node.ino !== BigInt(receipt.nodeIno)
      || nodePath.isSymbolicLink()
      || !sameState(node, nodePath)
      || !heldRoot.isDirectory()
      || heldRoot.isSymbolicLink()
      || !sameState(heldRoot, rootPath)
      || rootPath.isSymbolicLink()
      || realpathSync(process.execPath) !== receipt.nodePath
      || sha256Descriptor(nodeFd, node, 'Architecture bootstrap Node') !== nodeSha256) fail();
    candidate = Object.freeze({
      fd,
      inheritedFds: Object.freeze([fd]),
      nodeFd,
      nodeState: node,
      receipt: Object.freeze(receipt),
      receiptSha256: createHash('sha256').update(receiptBytes).digest('hex'),
      rootFd,
      rootState: heldRoot,
    });
  } catch (error) {
    if (nodeFd !== undefined) closeSync(nodeFd);
    if (rootFd !== undefined) closeSync(rootFd);
    throw error;
  }
  try {
    const source = lstatSync(
      resolve(receipt.repositoryRoot, 'scripts/architecture-bootstrap.rb'),
      { bigint: true },
    );
    if (!source.isFile()
      || source.isSymbolicLink()
      || source.dev !== BigInt(receipt.bootstrapSourceDev)
      || source.ino !== BigInt(receipt.bootstrapSourceIno)
      || sha256Path(
        resolve(receipt.repositoryRoot, 'scripts/architecture-bootstrap.rb'),
        source,
        'Architecture bootstrap source',
      ) !== receipt.bootstrapSourceSha256) fail();
    for (const [path, digest, label, maximum] of [
      [receipt.loaderPath, receipt.loaderSha256, 'Architecture bootstrap loader', 256 * 1_024],
      [receipt.sourceManifestPath, receipt.sourceManifestSha256, 'Architecture bootstrap source manifest', 256 * 1_024],
    ]) {
      if (dirname(path) !== receipt.privateRoot) fail();
      const item = lstatSync(path, { bigint: true });
      if (!item.isFile()
        || item.isSymbolicLink()
        || item.nlink !== 1n
        || item.uid !== BigInt(process.getuid())
        || (item.mode & 0o777n) !== 0o400n
        || item.size < 64n
        || item.size > BigInt(maximum)
        || sha256Path(path, item, label) !== digest) fail();
    }
    const manifestState = lstatSync(receipt.sourceManifestPath, { bigint: true });
    const manifestFd = openSync(
      receipt.sourceManifestPath,
      constants.O_RDONLY | constants.O_NOFOLLOW,
    );
    try {
      const held = fstatSync(manifestFd, { bigint: true });
      if (!sameState(manifestState, held)) fail();
      assertSourceManifest(
        heldBytes(manifestFd, held, 'Architecture bootstrap source manifest'),
        receipt.sourceManifestEntries,
      );
      if (!sameState(held, fstatSync(manifestFd, { bigint: true }))) fail();
    } finally {
      closeSync(manifestFd);
    }
    assertCachedBootstrapLease(candidate);
    cached = candidate;
    return cached;
  } catch (error) {
    closeSync(candidate.nodeFd);
    closeSync(candidate.rootFd);
    throw error;
  }
}

export function architectureBootstrapChildOptions(repositoryRoot) {
  const bootstrap = assertArchitectureBootstrap({ repositoryRoot });
  return Object.freeze({
    environment: Object.freeze({
      PIUI_ARCHITECTURE_BOOTSTRAP_FD: String(bootstrap.fd),
      PIUI_ARCHITECTURE_BOOTSTRAP_TOKEN: bootstrap.receipt.token,
    }),
    inheritedFds: bootstrap.inheritedFds,
  });
}

function makeTreeRemovable(path) {
  const item = lstatSync(path, { bigint: true });
  if (item.isSymbolicLink()) fail('Architecture bootstrap cleanup found a symbolic link');
  if (item.isDirectory()) {
    for (const name of readdirSync(path).sort()) makeTreeRemovable(resolve(path, name));
    chmodSync(path, 0o700);
    return;
  }
  if (!item.isFile() || item.nlink !== 1n || item.uid !== BigInt(process.getuid())) {
    fail('Architecture bootstrap cleanup found an unsafe entry');
  }
}

export function releaseArchitectureBootstrap() {
  const bootstrap = assertArchitectureBootstrap();
  if (process.pid !== bootstrap.receipt.rootPid) return false;
  const root = lstatSync(bootstrap.receipt.privateRoot, { bigint: true });
  if (root.dev !== BigInt(bootstrap.receipt.privateRootDev)
    || root.ino !== BigInt(bootstrap.receipt.privateRootIno)
    || dirname(bootstrap.receipt.privateRoot) !== realpathSync(dirname(bootstrap.receipt.privateRoot))
    || !resolve(bootstrap.receipt.privateRoot).startsWith(`${dirname(bootstrap.receipt.privateRoot)}/piui-architecture-bootstrap-`)) {
    fail('Architecture bootstrap cleanup lease changed');
  }
  closeSync(bootstrap.fd);
  closeSync(bootstrap.nodeFd);
  closeSync(bootstrap.rootFd);
  makeTreeRemovable(bootstrap.receipt.privateRoot);
  rmSync(bootstrap.receipt.privateRoot, { force: false, recursive: true });
  released = true;
  cached = undefined;
  delete process.env.PIUI_ARCHITECTURE_BOOTSTRAP_FD;
  delete process.env.PIUI_ARCHITECTURE_BOOTSTRAP_TOKEN;
  return true;
}
