import { constants as fsConstants } from 'node:fs';
import { spawnSync } from 'node:child_process';
import {
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rename,
} from 'node:fs/promises';
import {
  basename,
  dirname,
  isAbsolute,
  relative,
  resolve,
} from 'node:path';
import { platform } from 'node:os';
import {
  canonicalArchitectureJson,
  sha256Bytes,
} from './architecture-gate-schema.mjs';

const AUTH_DIRECTORY = 'tauri-build-authorisations';
const MAX_AUTH_BYTES = 16_384;
const MAX_TOOL_BYTES = 128 * 1_048_576;
const MAX_TOOLCHAIN_ENTRY_BYTES = 256 * 1_048_576;
const MAX_TOOL_FILES = 2_048;
const MAX_TOOLCHAIN_INVENTORY_BYTES = 64 * 1_048_576;
const MAX_TOOLCHAIN_INVENTORY_ENTRIES = 200_000;
const SHA256 = /^[0-9a-f]{64}$/u;
const PACKAGE_MODES = Object.freeze(new Set([
  'a21',
  'a22',
  'a23',
  'a24',
  'a25',
  'a26',
  'a27',
  'a28',
  'gate-approval',
  'gate-automation',
  'gate-credential',
  'gate-production',
  'guarded-production',
]));

function reject(message = 'Tauri build authorisation rejected') {
  throw new Error(message);
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject();
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])) reject();
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

function expectedUid() {
  if (typeof process.getuid !== 'function') reject();
  return BigInt(process.getuid());
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
    || lines.some((line) => /^\s+\d+:/u.test(line))) {
    reject(`${label} has an unsafe ACL`);
  }
}

async function assertPrivateDirectory(path, label) {
  if (!isAbsolute(path) || resolve(path) !== path) reject();
  const state = await lstat(path, { bigint: true });
  if (!state.isDirectory()
    || state.isSymbolicLink()
    || state.uid !== expectedUid()
    || (state.mode & 0o777n) !== 0o700n
    || await realpath(path) !== path) reject(`${label} is not a private canonical directory`);
  assertNoAcl(path, label);
  return state;
}

function identityFromState(state) {
  return Object.freeze({
    ctimeNs: state.ctimeNs.toString(10),
    dev: state.dev.toString(10),
    gid: state.gid.toString(10),
    ino: state.ino.toString(10),
    mode: state.mode.toString(10),
    mtimeNs: state.mtimeNs.toString(10),
    nlink: state.nlink.toString(10),
    size: state.size.toString(10),
    uid: state.uid.toString(10),
  });
}

function assertIdentity(value) {
  exactKeys(value, [
    'ctimeNs',
    'dev',
    'gid',
    'ino',
    'mode',
    'mtimeNs',
    'nlink',
    'size',
    'uid',
  ]);
  if (Object.values(value).some((part) => typeof part !== 'string' || !/^\d+$/u.test(part))) {
    reject();
  }
}

async function captureDirectoryIdentity(path, label) {
  const state = await assertPrivateDirectory(path, label);
  return identityFromState(state);
}

async function assertDirectoryIdentity(path, expected, label) {
  assertIdentity(expected);
  const actual = await captureDirectoryIdentity(path, label);
  if (canonicalArchitectureJson(actual) !== canonicalArchitectureJson(expected)) {
    reject(`${label} identity changed`);
  }
}

async function ensureAuthorisationDirectory(buildIsolate) {
  const path = resolve(buildIsolate, AUTH_DIRECTORY);
  try {
    await mkdir(path, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  await assertPrivateDirectory(path, 'Tauri build authorisation directory');
  return path;
}

async function readAuthorisation(path) {
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  const handle = await open(path, flags);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()
      || before.nlink !== 1n
      || before.uid !== expectedUid()
      || (before.mode & 0o777n) !== 0o600n
      || before.size < 3n
      || before.size > BigInt(MAX_AUTH_BYTES)) reject();
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (BigInt(bytes.length) !== before.size
      || !sameState(before, after)
      || pathAfter.isSymbolicLink()
      || !sameState(after, pathAfter)) reject();
    assertNoAcl(path, 'Tauri build authorisation');
    return bytes;
  } finally {
    await handle.close();
  }
}

function parseAuthorisation(bytes) {
  if (!Buffer.isBuffer(bytes)
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
    || bytes.includes(0x00)) reject();
  let value;
  try {
    value = JSON.parse(bytes.subarray(0, -1).toString('utf8'));
  } catch {
    reject();
  }
  if (`${canonicalArchitectureJson(value)}\n` !== bytes.toString('utf8')) reject();
  exactKeys(value, [
    'buildIsolate',
    'buildIsolateIdentity',
    'mode',
    'nonce',
    'pnpmEntry',
    'pnpmNode',
    'schemaVersion',
    'sourceDigest',
    'sourceRoot',
    'sourceRootIdentity',
  ]);
  return value;
}

async function readTrustedTool(path, label, {
  allowEmpty = false,
  requireUnique = true,
} = {}) {
  if (typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path) reject();
  const canonical = await realpath(path);
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  const handle = await open(path, flags);
  try {
    const before = await handle.stat({ bigint: true });
    if (canonical !== path
      || !before.isFile()
      || before.isSymbolicLink()
      || (requireUnique && before.nlink !== 1n)
      || before.uid !== expectedUid()
      || (before.mode & 0o022n) !== 0n
      || (!allowEmpty && before.size < 1n)
      || before.size > BigInt(MAX_TOOL_BYTES)) reject(`${label} is not trusted`);
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (BigInt(bytes.length) !== before.size
      || !sameState(before, after)
      || pathAfter.isSymbolicLink()
      || !sameState(after, pathAfter)) reject(`${label} changed during inspection`);
    assertNoAcl(path, label);
    return Object.freeze({
      bytes,
      record: Object.freeze({
        ...identityFromState(after),
        path,
        sha256: sha256Bytes(bytes),
      }),
    });
  } finally {
    await handle.close();
  }
}

async function captureTrustedTool(path, label) {
  return (await readTrustedTool(path, label)).record;
}

async function assertTrustedSourceDirectory(path, label) {
  if (!isAbsolute(path) || resolve(path) !== path) reject();
  const state = await lstat(path, { bigint: true });
  if (!state.isDirectory()
    || state.isSymbolicLink()
    || state.uid !== expectedUid()
    || (state.mode & 0o022n) !== 0n
    || await realpath(path) !== path) reject(`${label} is not trusted`);
  assertNoAcl(path, label);
  return state;
}

async function writePrivateTool(path, inspected, executable) {
  const flags = fsConstants.O_WRONLY
    | fsConstants.O_CREAT
    | fsConstants.O_EXCL
    | (fsConstants.O_NOFOLLOW ?? 0);
  const handle = await open(path, flags, executable ? 0o500 : 0o400);
  try {
    await handle.writeFile(inspected.bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
  const copied = await readTrustedTool(path, 'Private build tool copy', {
    allowEmpty: true,
  });
  if (copied.record.sha256 !== inspected.record.sha256
    || copied.record.size !== inspected.record.size) reject('Private build tool copy changed');
}

function parseToolchainClosureWitness(value) {
  exactKeys(value, [
    'entries',
    'inventoryBytes',
    'inventorySha256',
    'root',
  ]);
  if (!Number.isSafeInteger(value.entries)
    || value.entries < 1
    || value.entries > MAX_TOOLCHAIN_INVENTORY_ENTRIES
    || !Buffer.isBuffer(value.inventoryBytes)
    || value.inventoryBytes.length < 3
    || value.inventoryBytes.length > MAX_TOOLCHAIN_INVENTORY_BYTES
    || value.inventoryBytes.at(-1) !== 0x0a
    || value.inventoryBytes.subarray(0, -1).includes(0x0a)
    || value.inventoryBytes.includes(0x0d)
    || value.inventoryBytes.includes(0x00)
    || typeof value.inventorySha256 !== 'string'
    || !SHA256.test(value.inventorySha256)
    || sha256Bytes(value.inventoryBytes) !== value.inventorySha256
    || typeof value.root !== 'string'
    || !isAbsolute(value.root)
    || resolve(value.root) !== value.root) {
    reject('Authenticated toolchain closure witness is invalid');
  }
  let inventory;
  try {
    inventory = JSON.parse(value.inventoryBytes.subarray(0, -1).toString('utf8'));
  } catch {
    reject('Authenticated toolchain closure witness is invalid');
  }
  if (!Array.isArray(inventory)
    || inventory.length !== value.entries
    || `${canonicalArchitectureJson(inventory)}\n` !== value.inventoryBytes.toString('utf8')) {
    reject('Authenticated toolchain closure witness is invalid');
  }
  const byPath = new Map();
  for (const entry of inventory) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      reject('Authenticated toolchain closure witness is invalid');
    }
    const path = entry.path;
    if (typeof path !== 'string'
      || (path !== '.' && path.split('/').some((part) => part === '' || part === '.' || part === '..'))
      || byPath.has(path)) {
      reject('Authenticated toolchain closure witness is invalid');
    }
    const resolvedPath = path === '.'
      ? value.root
      : resolve(value.root, ...path.split('/'));
    if (resolvedPath !== value.root && !resolvedPath.startsWith(`${value.root}/`)) {
      reject('Authenticated toolchain closure witness is invalid');
    }
    if (entry.kind === 'directory') {
      exactKeys(entry, ['kind', 'path']);
    } else if (entry.kind === 'symlink') {
      exactKeys(entry, ['kind', 'link', 'path', 'target']);
      if (typeof entry.link !== 'string' || typeof entry.target !== 'string') {
        reject('Authenticated toolchain closure witness is invalid');
      }
    } else {
      exactKeys(entry, ['executable', 'path', 'sha256', 'size']);
      if (typeof entry.executable !== 'boolean'
        || !Number.isSafeInteger(entry.size)
        || entry.size < 0
        || entry.size > MAX_TOOLCHAIN_ENTRY_BYTES
        || typeof entry.sha256 !== 'string'
        || !SHA256.test(entry.sha256)) {
        reject('Authenticated toolchain closure witness is invalid');
      }
    }
    byPath.set(path, entry);
  }
  if (byPath.get('.')?.kind !== 'directory') {
    reject('Authenticated toolchain closure witness is invalid');
  }
  return Object.freeze({
    byPath,
    entries: Object.freeze(inventory),
    root: value.root,
  });
}

function witnessRelativePath(root, path, label) {
  const pathLabel = relative(root, path).split('/').join('/');
  if (pathLabel === ''
    || pathLabel === '.'
    || pathLabel.startsWith('../')
    || isAbsolute(pathLabel)) {
    reject(`${label} escaped the authenticated toolchain closure witness`);
  }
  return pathLabel;
}

function assertWitnessFile(entry, inspected, label) {
  if (!entry || entry.kind !== undefined
    || entry.sha256 !== inspected.record.sha256
    || entry.size.toString(10) !== inspected.record.size
    || entry.executable !== ((BigInt(inspected.record.mode) & 0o111n) !== 0n)) {
    reject(`${label} does not match the authenticated toolchain closure witness`);
  }
}

export async function preparePrivateTauriBuildTools({
  authenticatedToolchainWitness,
  buildIsolate,
  pnpmEntry,
  pnpmNode,
}) {
  await assertPrivateDirectory(buildIsolate, 'Owned build isolate');
  const witness = parseToolchainClosureWitness(authenticatedToolchainWitness);
  if (await realpath(witness.root) !== witness.root) {
    reject('Authenticated toolchain closure witness root is not canonical');
  }
  await assertTrustedSourceDirectory(
    witness.root,
    'Authenticated toolchain closure witness root',
  );
  const toolRoot = resolve(buildIsolate, 'tauri-build-tools');
  await mkdir(toolRoot, { mode: 0o700 });
  await assertPrivateDirectory(toolRoot, 'Private build tool root');

  const inspectedNode = await readTrustedTool(pnpmNode, 'Pinned pnpm node');
  const nodePathLabel = witnessRelativePath(
    witness.root,
    pnpmNode,
    'Pinned pnpm node',
  );
  assertWitnessFile(
    witness.byPath.get(nodePathLabel),
    inspectedNode,
    'Pinned pnpm node',
  );
  const privateNode = resolve(toolRoot, 'node');
  await writePrivateTool(privateNode, inspectedNode, true);

  const pnpmRoot = resolve(dirname(pnpmEntry), '..');
  const pnpmRootPathLabel = witnessRelativePath(
    witness.root,
    pnpmRoot,
    'Pinned pnpm package',
  );
  if (nodePathLabel === pnpmRootPathLabel
    || nodePathLabel.startsWith(`${pnpmRootPathLabel}/`)) {
    reject('Pinned pnpm node is unexpectedly inside the pnpm package');
  }
  const pnpmRootState = await assertTrustedSourceDirectory(pnpmRoot, 'Pinned pnpm package');
  const entryRelative = relative(pnpmRoot, pnpmEntry).split('/').join('/');
  if (entryRelative !== 'bin/pnpm.cjs') reject('Pinned pnpm entry layout is unexpected');
  const expectedPnpmEntries = witness.entries.filter((entry) => (
    entry.path === pnpmRootPathLabel
    || entry.path.startsWith(`${pnpmRootPathLabel}/`)
  ));
  if (expectedPnpmEntries.length < 2
    || expectedPnpmEntries[0]?.path !== pnpmRootPathLabel
    || expectedPnpmEntries[0]?.kind !== 'directory'
    || expectedPnpmEntries.some((entry) => entry.kind === 'symlink')) {
    reject('Pinned pnpm package inventory is invalid');
  }
  const expectedPnpmByPath = new Map(expectedPnpmEntries.map((entry) => {
    const pathLabel = entry.path === pnpmRootPathLabel
      ? '.'
      : entry.path.slice(pnpmRootPathLabel.length + 1);
    return [pathLabel, entry];
  }));
  const expectedPnpmEntry = expectedPnpmByPath.get(entryRelative);
  if (!expectedPnpmEntry || expectedPnpmEntry.kind !== undefined) {
    reject('Pinned pnpm entry is absent from the authenticated toolchain closure witness');
  }
  const privatePnpmRoot = resolve(toolRoot, 'pnpm');
  await mkdir(privatePnpmRoot, { mode: 0o700 });
  let files = 0;
  let totalBytes = 0;
  const copiedPaths = new Set(['.']);
  async function copyDirectory(source, destination, sourceState, pathLabel) {
    const entries = await readdir(source, { withFileTypes: true });
    entries.sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
    for (const entry of entries) {
      const sourcePath = resolve(source, entry.name);
      const destinationPath = resolve(destination, entry.name);
      const childPathLabel = pathLabel === '.'
        ? entry.name
        : `${pathLabel}/${entry.name}`;
      const expected = expectedPnpmByPath.get(childPathLabel);
      if (!expected || copiedPaths.has(childPathLabel)) {
        reject('Pinned pnpm package inventory does not match its authenticated witness');
      }
      copiedPaths.add(childPathLabel);
      if (entry.isDirectory()) {
        if (expected.kind !== 'directory') {
          reject('Pinned pnpm package inventory does not match its authenticated witness');
        }
        const directoryState = await assertTrustedSourceDirectory(
          sourcePath,
          `Pinned pnpm directory ${pathLabel}/${entry.name}`,
        );
        await mkdir(destinationPath, { mode: 0o700 });
        await copyDirectory(
          sourcePath,
          destinationPath,
          directoryState,
          childPathLabel,
        );
        const directoryAfter = await lstat(sourcePath, { bigint: true });
        if (!sameState(directoryState, directoryAfter)) reject('Pinned pnpm directory changed');
        continue;
      }
      if (!entry.isFile()) reject('Pinned pnpm package contains an unsupported entry');
      const inspected = await readTrustedTool(
        sourcePath,
        `Pinned pnpm file ${pathLabel}/${entry.name}`,
        {
          allowEmpty: true,
          requireUnique: false,
        },
      );
      assertWitnessFile(expected, inspected, 'Pinned pnpm file');
      files += 1;
      totalBytes += inspected.bytes.length;
      if (files > MAX_TOOL_FILES || totalBytes > MAX_TOOL_BYTES) {
        reject('Pinned pnpm package exceeds its copy bound');
      }
      const executable = (BigInt(inspected.record.mode) & 0o111n) !== 0n;
      await writePrivateTool(destinationPath, inspected, executable);
    }
    const sourceAfter = await lstat(source, { bigint: true });
    if (!sameState(sourceState, sourceAfter)) reject('Pinned pnpm package changed during copying');
  }
  await copyDirectory(pnpmRoot, privatePnpmRoot, pnpmRootState, '.');
  if (copiedPaths.size !== expectedPnpmByPath.size
    || [...expectedPnpmByPath.keys()].some((path) => !copiedPaths.has(path))) {
    reject('Pinned pnpm package inventory does not match its authenticated witness');
  }

  const verifiedPrivatePaths = new Set(['.']);
  async function verifyPrivateDirectory(path, pathLabel) {
    const entries = await readdir(path, { withFileTypes: true });
    entries.sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
    for (const entry of entries) {
      const childPathLabel = pathLabel === '.'
        ? entry.name
        : `${pathLabel}/${entry.name}`;
      const expected = expectedPnpmByPath.get(childPathLabel);
      if (!expected || verifiedPrivatePaths.has(childPathLabel)) {
        reject('Private pnpm package inventory changed');
      }
      verifiedPrivatePaths.add(childPathLabel);
      const childPath = resolve(path, entry.name);
      if (entry.isDirectory()) {
        if (expected.kind !== 'directory') reject('Private pnpm package inventory changed');
        const before = await assertTrustedSourceDirectory(childPath, 'Private pnpm directory');
        await verifyPrivateDirectory(childPath, childPathLabel);
        const after = await lstat(childPath, { bigint: true });
        if (!sameState(before, after)) reject('Private pnpm package inventory changed');
        continue;
      }
      if (!entry.isFile()) reject('Private pnpm package inventory changed');
      const inspected = await readTrustedTool(childPath, 'Private pnpm file', {
        allowEmpty: true,
      });
      assertWitnessFile(expected, inspected, 'Private pnpm file');
    }
  }
  await verifyPrivateDirectory(privatePnpmRoot, '.');
  if (verifiedPrivatePaths.size !== expectedPnpmByPath.size
    || [...expectedPnpmByPath.keys()].some((path) => !verifiedPrivatePaths.has(path))) {
    reject('Private pnpm package inventory changed');
  }
  const privatePnpmEntry = resolve(privatePnpmRoot, ...entryRelative.split('/'));
  await captureTrustedTool(privatePnpmEntry, 'Private pnpm entry');
  const privateNodeInspection = await readTrustedTool(privateNode, 'Private pnpm node');
  assertWitnessFile(
    witness.byPath.get(nodePathLabel),
    privateNodeInspection,
    'Private pnpm node',
  );
  return Object.freeze({
    pnpmEntry: privatePnpmEntry,
    pnpmNode: privateNode,
  });
}

function assertToolRecord(value) {
  exactKeys(value, [
    'ctimeNs',
    'dev',
    'gid',
    'ino',
    'mode',
    'mtimeNs',
    'nlink',
    'path',
    'sha256',
    'size',
    'uid',
  ]);
  assertIdentity(Object.fromEntries(Object.entries(value).filter(([key]) => (
    !['path', 'sha256'].includes(key)
  ))));
  if (typeof value.path !== 'string'
    || !isAbsolute(value.path)
    || resolve(value.path) !== value.path
    || typeof value.sha256 !== 'string'
    || !SHA256.test(value.sha256)) reject();
}

async function assertTrustedToolRecord(record, label) {
  assertToolRecord(record);
  const actual = await captureTrustedTool(record.path, label);
  if (canonicalArchitectureJson(actual) !== canonicalArchitectureJson(record)) {
    reject(`${label} identity or bytes changed`);
  }
}

function assertRecordValues(record, { buildIsolate, sourceRoot }) {
  if (record.schemaVersion !== 1
    || record.buildIsolate !== buildIsolate
    || record.sourceRoot !== sourceRoot
    || !PACKAGE_MODES.has(record.mode)
    || typeof record.nonce !== 'string'
    || !SHA256.test(record.nonce)
    || typeof record.sourceDigest !== 'string'
    || !SHA256.test(record.sourceDigest)) reject();
  assertIdentity(record.buildIsolateIdentity);
  assertIdentity(record.sourceRootIdentity);
  assertToolRecord(record.pnpmEntry);
  assertToolRecord(record.pnpmNode);
}

export async function createTauriBuildAuthorisation({
  buildIsolate,
  mode,
  nonce,
  pnpmEntry,
  pnpmNode,
  sourceDigest,
  sourceRoot,
}) {
  if (dirname(sourceRoot) !== buildIsolate) reject();
  const authorisationDirectory = await ensureAuthorisationDirectory(buildIsolate);
  const buildIsolateIdentity = await captureDirectoryIdentity(buildIsolate, 'Owned build isolate');
  const sourceRootIdentity = await captureDirectoryIdentity(sourceRoot, 'Frozen source root');
  const pnpmEntryRecord = await captureTrustedTool(pnpmEntry, 'Pinned pnpm entry');
  const pnpmNodeRecord = await captureTrustedTool(pnpmNode, 'Pinned pnpm node');
  const record = {
    buildIsolate,
    buildIsolateIdentity,
    mode,
    nonce,
    pnpmEntry: pnpmEntryRecord,
    pnpmNode: pnpmNodeRecord,
    schemaVersion: 1,
    sourceDigest,
    sourceRoot,
    sourceRootIdentity,
  };
  assertRecordValues(record, { buildIsolate, sourceRoot });
  const bytes = Buffer.from(`${canonicalArchitectureJson(record)}\n`, 'utf8');
  const path = resolve(authorisationDirectory, `${nonce}.json`);
  const flags = fsConstants.O_WRONLY
    | fsConstants.O_CREAT
    | fsConstants.O_EXCL
    | (fsConstants.O_NOFOLLOW ?? 0);
  const handle = await open(path, flags, 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
  const verified = await readAuthorisation(path);
  if (!verified.equals(bytes)) reject();
  return Object.freeze({
    environment: Object.freeze({
      PIUI_TAURI_BUILD_AUTHORISATION_PATH: path,
      PIUI_TAURI_BUILD_AUTHORISATION_SHA256: sha256Bytes(bytes),
    }),
    record: Object.freeze(record),
  });
}

export async function validateTauriBuildAuthorisation(sourceRootPath, environment = process.env) {
  if (typeof sourceRootPath !== 'string'
    || !isAbsolute(sourceRootPath)
    || resolve(sourceRootPath) !== sourceRootPath) reject();
  const sourceRoot = sourceRootPath;
  const buildIsolate = dirname(sourceRoot);
  if (resolve(buildIsolate, 'source') !== sourceRoot) reject();
  const authorisationDirectory = await ensureAuthorisationDirectory(buildIsolate);
  const path = environment.PIUI_TAURI_BUILD_AUTHORISATION_PATH;
  const expectedSha256 = environment.PIUI_TAURI_BUILD_AUTHORISATION_SHA256;
  if (typeof path !== 'string'
    || dirname(path) !== authorisationDirectory
    || !/^[0-9a-f]{64}\.json$/u.test(basename(path))
    || typeof expectedSha256 !== 'string'
    || !SHA256.test(expectedSha256)) reject();
  const claimedPath = `${path}.claimed`;
  try {
    await lstat(claimedPath);
    reject('Tauri build authorisation was already claimed');
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  try {
    await rename(path, claimedPath);
  } catch {
    reject('Tauri build authorisation could not be claimed');
  }
  const bytes = await readAuthorisation(claimedPath);
  if (sha256Bytes(bytes) !== expectedSha256) reject();
  const record = parseAuthorisation(bytes);
  assertRecordValues(record, { buildIsolate, sourceRoot });
  if (basename(path) !== `${record.nonce}.json`) reject();
  await assertDirectoryIdentity(
    buildIsolate,
    record.buildIsolateIdentity,
    'Owned build isolate',
  );
  await assertDirectoryIdentity(
    sourceRoot,
    record.sourceRootIdentity,
    'Frozen source root',
  );
  await assertTrustedToolRecord(record.pnpmEntry, 'Pinned pnpm entry');
  await assertTrustedToolRecord(record.pnpmNode, 'Pinned pnpm node');
  return Object.freeze({
    ...record,
    authorisationPath: path,
    authorisationSha256: expectedSha256,
    claimedPath,
  });
}

export async function revalidateTauriBuildAuthorisation(authorisation) {
  if (!authorisation
    || typeof authorisation.authorisationPath !== 'string'
    || typeof authorisation.claimedPath !== 'string'
    || authorisation.claimedPath !== `${authorisation.authorisationPath}.claimed`
    || typeof authorisation.authorisationSha256 !== 'string'
    || !SHA256.test(authorisation.authorisationSha256)) reject();
  try {
    await lstat(authorisation.authorisationPath);
    reject('Claimed Tauri build authorisation was replayed');
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  const bytes = await readAuthorisation(authorisation.claimedPath);
  if (sha256Bytes(bytes) !== authorisation.authorisationSha256) reject();
  await assertDirectoryIdentity(
    authorisation.buildIsolate,
    authorisation.buildIsolateIdentity,
    'Owned build isolate',
  );
  await assertDirectoryIdentity(
    authorisation.sourceRoot,
    authorisation.sourceRootIdentity,
    'Frozen source root',
  );
  await assertTrustedToolRecord(authorisation.pnpmEntry, 'Pinned pnpm entry');
  await assertTrustedToolRecord(authorisation.pnpmNode, 'Pinned pnpm node');
}
