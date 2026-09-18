import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { resolve } from 'node:path';

const NODE_SHA256 = '2e3f1286a7eb3736346ed1803e458a0ff909e2b2d5bc746144dcb76970e9b99d';
const NODE_BYTES = 112_928_848;
const LAUNCHER_RELATIVE_PATH = 'scripts/authenticated-node-launcher.rb';

function reject(message = 'Authenticated Node spawn configuration rejected') {
  throw new Error(message);
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

async function heldSource(path, record) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    const pathname = await lstat(path, { bigint: true });
    if (!before.isFile()
      || before.isSymbolicLink()
      || before.uid !== BigInt(process.getuid())
      || before.nlink !== 1n
      || (before.mode & 0o022n) !== 0n
      || before.size !== BigInt(record.size)
      || pathname.isSymbolicLink()
      || !sameState(before, pathname)
      || await realpath(path) !== path
      || ((before.mode & 0o111n) !== 0n) !== record.executable) reject();
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (bytes.length !== record.size
      || createHash('sha256').update(bytes).digest('hex') !== record.sha256
      || !sameState(before, after)
      || pathAfter.isSymbolicLink()
      || !sameState(after, pathAfter)) reject();
    return bytes;
  } finally {
    await handle?.close();
  }
}

async function authenticatedNodeIdentity(path) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    const pathname = await lstat(path, { bigint: true });
    if (!before.isFile()
      || before.isSymbolicLink()
      || before.uid !== BigInt(process.getuid())
      || before.nlink !== 1n
      || (before.mode & 0o777n) !== 0o500n
      || before.size !== BigInt(NODE_BYTES)
      || pathname.isSymbolicLink()
      || !sameState(before, pathname)
      || await realpath(path) !== path) reject();
    const digest = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1_048_576);
    let offset = 0;
    while (offset < NODE_BYTES) {
      const result = await handle.read(
        buffer,
        0,
        Math.min(buffer.length, NODE_BYTES - offset),
        offset,
      );
      if (result.bytesRead < 1) reject();
      digest.update(buffer.subarray(0, result.bytesRead));
      offset += result.bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (digest.digest('hex') !== NODE_SHA256
      || !sameState(before, after)
      || pathAfter.isSymbolicLink()
      || !sameState(after, pathAfter)) reject();
    return Object.freeze({
      dev: after.dev.toString(),
      ino: after.ino.toString(),
      path,
      sha256: NODE_SHA256,
      size: Number(after.size),
    });
  } finally {
    await handle?.close();
  }
}

export async function createAuthenticatedNodeSpawnConfiguration({
  nodePath,
  snapshot,
  sourceRoot,
}) {
  if (!snapshot
    || !Array.isArray(snapshot.inventory)
    || typeof sourceRoot !== 'string'
    || resolve(sourceRoot) !== sourceRoot
    || typeof nodePath !== 'string'
    || resolve(nodePath) !== nodePath) reject();
  const records = snapshot.inventory.filter((entry) => (
    entry?.path === LAUNCHER_RELATIVE_PATH
  ));
  if (records.length !== 1) reject();
  const record = records[0];
  if (!Number.isSafeInteger(record.size)
    || record.size < 8_192
    || record.size > 128 * 1_024
    || record.executable !== false
    || typeof record.sha256 !== 'string'
    || !/^[0-9a-f]{64}$/u.test(record.sha256)) reject();
  const launcherPath = resolve(sourceRoot, ...LAUNCHER_RELATIVE_PATH.split('/'));
  const launcherBytes = await heldSource(launcherPath, record);
  const launcherSource = new TextDecoder('utf-8', { fatal: true }).decode(launcherBytes);
  if (launcherSource.includes('\0')
    || !launcherSource.startsWith('#!/usr/bin/ruby --disable-gems\n')) reject();
  return Object.freeze({
    launcherSha256: record.sha256,
    launcherSource,
    node: await authenticatedNodeIdentity(nodePath),
    rubyPath: '/usr/bin/ruby',
    schemaVersion: 1,
  });
}

export const authenticatedNodePins = Object.freeze({
  bytes: NODE_BYTES,
  cdHash: '59cdea89a982b05f23e756c08115bebc555ff092',
  designatedRequirement: 'identifier node and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = HX7739G8FX',
  identifier: 'node',
  sha256: NODE_SHA256,
  teamIdentifier: 'HX7739G8FX',
});
