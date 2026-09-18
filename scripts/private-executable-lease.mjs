import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import {
  chmod,
  lstat,
  mkdir,
  open,
  realpath,
} from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';

const MAX_EXECUTABLE_BYTES = 128 * 1_048_576;
const SHA256 = /^[0-9a-f]{64}$/u;
const EXECUTABLE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const LEASE_KEYS = Object.freeze([
  'controlRoot',
  'dev',
  'ino',
  'mode',
  'path',
  'sha256',
  'size',
]);
const CONTROL_KEYS = Object.freeze(['dev', 'ino', 'mode', 'path']);

function reject() {
  throw new Error('Private executable lease rejected');
}

function exactKeys(value, expected) {
  if (!value
    || typeof value !== 'object'
    || Array.isArray(value)
    || !isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort())) reject();
}

function assertAbsolutePath(path) {
  if (typeof path !== 'string'
    || !path.startsWith('/')
    || resolve(path) !== path
    || /[\0\r\n]/u.test(path)) reject();
}

function assertOwnedRegularExecutable(item) {
  if (!item.isFile()
    || item.isSymbolicLink()
    || item.nlink !== 1
    || item.size < 1
    || item.size > MAX_EXECUTABLE_BYTES
    || (item.mode & 0o111) === 0
    || (item.mode & 0o022) !== 0
    || (typeof process.getuid === 'function' && item.uid !== process.getuid())) reject();
}

function sameFile(before, after) {
  return before.dev === after.dev
    && before.ino === after.ino
    && before.size === after.size
    && before.mode === after.mode
    && before.mtimeMs === after.mtimeMs;
}

async function readHeldExecutable(path) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    assertOwnedRegularExecutable(before);
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const pathname = await lstat(path);
    assertOwnedRegularExecutable(after);
    assertOwnedRegularExecutable(pathname);
    if (!sameFile(before, after)
      || !sameFile(before, pathname)
      || bytes.length !== before.size) reject();
    return Object.freeze({
      bytes,
      sha256: createHash('sha256').update(bytes).digest('hex'),
    });
  } finally {
    await handle?.close();
  }
}

async function assertControlParent(controlRoot) {
  const parent = dirname(controlRoot);
  const canonical = await realpath(parent);
  const item = await lstat(parent);
  if (canonical !== parent
    || !item.isDirectory()
    || item.isSymbolicLink()
    || (item.mode & 0o022) !== 0
    || (typeof process.getuid === 'function' && item.uid !== process.getuid())) reject();
}

async function assertControlRoot(control) {
  exactKeys(control, CONTROL_KEYS);
  assertAbsolutePath(control.path);
  if (!Number.isSafeInteger(control.dev)
    || !Number.isSafeInteger(control.ino)
    || control.mode !== 0o500
    || await realpath(control.path) !== control.path) reject();
  const item = await lstat(control.path);
  if (!item.isDirectory()
    || item.isSymbolicLink()
    || item.dev !== control.dev
    || item.ino !== control.ino
    || (item.mode & 0o777) !== control.mode
    || (typeof process.getuid === 'function' && item.uid !== process.getuid())) reject();
}

export async function assertPrivateExecutableLease(lease) {
  exactKeys(lease, LEASE_KEYS);
  exactKeys(lease.controlRoot, CONTROL_KEYS);
  assertAbsolutePath(lease.path);
  if (dirname(lease.path) !== lease.controlRoot.path
    || basename(lease.path).length === 0
    || !Number.isSafeInteger(lease.dev)
    || !Number.isSafeInteger(lease.ino)
    || !Number.isSafeInteger(lease.size)
    || lease.size < 1
    || lease.size > MAX_EXECUTABLE_BYTES
    || lease.mode !== 0o500
    || typeof lease.sha256 !== 'string'
    || !SHA256.test(lease.sha256)) reject();
  await assertControlRoot(lease.controlRoot);
  if (await realpath(lease.path) !== lease.path) reject();

  let handle;
  try {
    handle = await open(lease.path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    assertOwnedRegularExecutable(before);
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const pathname = await lstat(lease.path);
    assertOwnedRegularExecutable(after);
    assertOwnedRegularExecutable(pathname);
    if (!sameFile(before, after)
      || !sameFile(before, pathname)
      || before.dev !== lease.dev
      || before.ino !== lease.ino
      || before.size !== lease.size
      || (before.mode & 0o777) !== lease.mode
      || bytes.length !== lease.size
      || createHash('sha256').update(bytes).digest('hex') !== lease.sha256) reject();
  } finally {
    await handle?.close();
  }
  return true;
}

export async function releasePrivateExecutableLeaseForRemoval(lease) {
  await assertPrivateExecutableLease(lease);
  await chmod(lease.controlRoot.path, 0o700);
}

export async function capturePrivateExecutable({
  controlRoot,
  executableName,
  sourcePath,
}) {
  assertAbsolutePath(controlRoot);
  assertAbsolutePath(sourcePath);
  if (typeof executableName !== 'string' || !EXECUTABLE_NAME.test(executableName)) reject();
  await assertControlParent(controlRoot);
  const held = await readHeldExecutable(sourcePath);
  let controlCreated = false;
  try {
    await mkdir(controlRoot, { mode: 0o700 });
    controlCreated = true;
  } catch (error) {
    if (error?.code === 'EEXIST') reject();
    throw error;
  }
  try {
    const output = resolve(controlRoot, executableName);
    if (dirname(output) !== controlRoot) reject();
    let handle;
    try {
      handle = await open(
        output,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
        0o400,
      );
      await handle.writeFile(held.bytes);
      await handle.sync();
    } finally {
      await handle?.close();
    }
    await chmod(output, 0o500);
    await chmod(controlRoot, 0o500);

    const rootItem = await lstat(controlRoot);
    const item = await lstat(output);
    const lease = Object.freeze({
      controlRoot: Object.freeze({
        dev: rootItem.dev,
        ino: rootItem.ino,
        mode: rootItem.mode & 0o777,
        path: controlRoot,
      }),
      dev: item.dev,
      ino: item.ino,
      mode: item.mode & 0o777,
      path: output,
      sha256: held.sha256,
      size: item.size,
    });
    await assertPrivateExecutableLease(lease);
    return lease;
  } catch (error) {
    if (!controlCreated) throw error;
    try {
      await chmod(controlRoot, 0o700);
    } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        'Private executable capture and recovery failed',
      );
    }
    throw error;
  }
}
