import { createHash } from 'node:crypto';
import { constants, fstatSync, readSync } from 'node:fs';
import {
  lstat,
  open,
  readlink,
  readdir,
  realpath,
} from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import { canonicalArchitectureJson } from './architecture-gate-schema.mjs';

const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_ENTRIES = 100_000;
const MAX_RECEIPT_BYTES = 64 * 1_048_576;
const MAX_TOTAL_FILE_BYTES = 2 * 1_024 * 1_024 * 1_024;

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function compareReceiptPaths(left, right) {
  if (left === right) {
    return 0;
  }
  if (left === '.') {
    return -1;
  }
  if (right === '.') {
    return 1;
  }
  return Buffer.from(left).compare(Buffer.from(right));
}

function exactKeys(value, keys) {
  return value
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
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

function stateRecord(state) {
  return {
    ctimeNs: state.ctimeNs.toString(10),
    dev: state.dev.toString(10),
    gid: state.gid.toString(10),
    ino: state.ino.toString(10),
    mode: state.mode.toString(10),
    mtimeNs: state.mtimeNs.toString(10),
    nlink: state.nlink.toString(10),
    size: state.size.toString(10),
    uid: state.uid.toString(10),
  };
}

async function heldFileSha256(path, expected) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat({ bigint: true });
    const pathname = await lstat(path, { bigint: true });
    if (!sameState(expected, opened)
      || !sameState(opened, pathname)
      || !opened.isFile()
      || opened.nlink !== 1n) {
      throw new Error('Controlled sidecar deployment file identity changed');
    }
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1_048_576);
    let offset = 0n;
    while (offset < opened.size) {
      const length = Number(
        opened.size - offset < BigInt(buffer.length)
          ? opened.size - offset
          : BigInt(buffer.length),
      );
      const { bytesRead } = await handle.read(buffer, 0, length, Number(offset));
      if (bytesRead !== length) {
        throw new Error('Controlled sidecar deployment file ended early');
      }
      hash.update(buffer.subarray(0, bytesRead));
      offset += BigInt(bytesRead);
    }
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (!sameState(opened, after) || !sameState(after, pathAfter)) {
      throw new Error('Controlled sidecar deployment file changed while read');
    }
    return hash.digest('hex');
  } finally {
    await handle.close();
  }
}

export async function captureSidecarDeploymentReceipt(deploymentRoot) {
  if (typeof deploymentRoot !== 'string'
    || resolve(deploymentRoot) !== deploymentRoot
    || await realpath(deploymentRoot) !== deploymentRoot) {
    throw new Error('Controlled sidecar deployment root is not canonical');
  }
  const expectedUid = typeof process.getuid === 'function'
    ? BigInt(process.getuid())
    : undefined;
  if (expectedUid === undefined) {
    throw new Error('Controlled sidecar deployment owner is unavailable');
  }
  const entries = [];
  let totalFileBytes = 0;

  async function visit(path, pathLabel) {
    const before = await lstat(path, { bigint: true });
    if (before.uid !== expectedUid
      || (!before.isSymbolicLink() && (before.mode & 0o022n) !== 0n)
      || entries.length >= MAX_ENTRIES) {
      throw new Error('Controlled sidecar deployment contains an unsafe entry');
    }
    const state = stateRecord(before);
    if (before.isDirectory()) {
      entries.push({ kind: 'directory', path: pathLabel, ...state });
      const names = await readdir(path);
      names.sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
      for (const name of names) {
        const child = resolve(path, name);
        const childLabel = pathLabel === '.' ? name : `${pathLabel}/${name}`;
        await visit(child, childLabel);
      }
      const after = await lstat(path, { bigint: true });
      if (!sameState(before, after)) {
        throw new Error('Controlled sidecar deployment directory changed during capture');
      }
      return;
    }
    if (before.isSymbolicLink()) {
      const link = await readlink(path);
      const target = await realpath(path);
      if (target !== deploymentRoot && !target.startsWith(`${deploymentRoot}/`)) {
        throw new Error('Controlled sidecar deployment link escaped its root');
      }
      const after = await lstat(path, { bigint: true });
      if (!sameState(before, after)) {
        throw new Error('Controlled sidecar deployment link changed during capture');
      }
      entries.push({
        kind: 'symlink',
        link,
        path: pathLabel,
        target: relative(deploymentRoot, target),
        ...state,
      });
      return;
    }
    if (!before.isFile() || before.nlink !== 1n || before.size < 0n) {
      throw new Error('Controlled sidecar deployment contains an unsupported entry');
    }
    totalFileBytes += Number(before.size);
    if (!Number.isSafeInteger(totalFileBytes)
      || totalFileBytes > MAX_TOTAL_FILE_BYTES) {
      throw new Error('Controlled sidecar deployment exceeds its byte bound');
    }
    entries.push({
      kind: 'file',
      path: pathLabel,
      sha256: await heldFileSha256(path, before),
      ...state,
    });
  }

  await visit(deploymentRoot, '.');
  entries.sort((left, right) => (
    compareReceiptPaths(left.path, right.path)
  ));
  const value = {
    deploymentRoot,
    entries,
    schemaVersion: 1,
  };
  const bytes = Buffer.from(`${canonicalArchitectureJson(value)}\n`, 'utf8');
  if (bytes.length > MAX_RECEIPT_BYTES) {
    throw new Error('Controlled sidecar deployment receipt exceeds its bound');
  }
  return Object.freeze({
    bytes,
    sha256: sha256(bytes),
    value: Object.freeze(value),
  });
}

function validateStateField(value, { allowZero = true } = {}) {
  return typeof value === 'string'
    && (allowZero ? /^(?:0|[1-9][0-9]*)$/u : /^[1-9][0-9]*$/u).test(value);
}

function parseReceiptBytes(bytes, expectedRoot) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 128
    || bytes.length > MAX_RECEIPT_BYTES
    || bytes.at(-1) !== 0x0a
    || bytes.includes(0)
    || bytes.includes(0x0d)) {
    throw new Error('Controlled sidecar deployment receipt is malformed');
  }
  let value;
  try {
    value = JSON.parse(bytes.subarray(0, -1).toString('utf8'));
  } catch {
    throw new Error('Controlled sidecar deployment receipt is malformed');
  }
  if (!exactKeys(value, ['deploymentRoot', 'entries', 'schemaVersion'])
    || value.schemaVersion !== 1
    || value.deploymentRoot !== expectedRoot
    || !Array.isArray(value.entries)
    || value.entries.length < 2
    || value.entries.length > MAX_ENTRIES
    || `${canonicalArchitectureJson(value)}\n` !== bytes.toString('utf8')) {
    throw new Error('Controlled sidecar deployment receipt is invalid');
  }
  let priorPath;
  for (const entry of value.entries) {
    const commonKeys = [
      'ctimeNs', 'dev', 'gid', 'ino', 'kind', 'mode', 'mtimeNs',
      'nlink', 'path', 'size', 'uid',
    ];
    const extraKeys = entry?.kind === 'file'
      ? ['sha256']
      : entry?.kind === 'symlink'
        ? ['link', 'target']
        : [];
    if (!exactKeys(entry, [...commonKeys, ...extraKeys])
      || !['directory', 'file', 'symlink'].includes(entry.kind)
      || typeof entry.path !== 'string'
      || (entry.path !== '.'
        && (!/^[^/\0]+(?:\/[^/\0]+)*$/u.test(entry.path)
          || entry.path.split('/').includes('..')))
      || (priorPath !== undefined
        && compareReceiptPaths(priorPath, entry.path) >= 0)
      || !validateStateField(entry.ctimeNs)
      || !validateStateField(entry.dev)
      || !validateStateField(entry.gid)
      || !validateStateField(entry.ino, { allowZero: false })
      || !validateStateField(entry.mode)
      || !validateStateField(entry.mtimeNs)
      || !validateStateField(entry.nlink)
      || !validateStateField(entry.size)
      || !validateStateField(entry.uid)
      || (entry.kind === 'file' && !SHA256.test(entry.sha256))
      || (entry.kind === 'symlink'
        && (typeof entry.link !== 'string'
          || typeof entry.target !== 'string'
          || entry.link.includes('\0')
          || entry.target.includes('\0')))) {
      throw new Error('Controlled sidecar deployment receipt entry is invalid');
    }
    priorPath = entry.path;
  }
  if (value.entries[0].kind !== 'directory'
    || value.entries[0].path !== '.') {
    throw new Error('Controlled sidecar deployment receipt root is invalid');
  }
  return Object.freeze(value);
}

export function readHeldSidecarDeploymentReceipt({
  descriptor,
  expectedRoot,
  receiptSha256,
}) {
  if (!Number.isSafeInteger(descriptor)
    || descriptor < 3
    || descriptor > 255
    || typeof expectedRoot !== 'string'
    || resolve(expectedRoot) !== expectedRoot
    || !SHA256.test(receiptSha256 ?? '')) {
    throw new Error('Controlled sidecar deployment receipt authority is invalid');
  }
  const before = fstatSync(descriptor, { bigint: true });
  if (!before.isFile()
    || before.isSymbolicLink()
    || before.uid !== BigInt(process.getuid())
    || before.nlink !== 1n
    || (before.mode & 0o777n) !== 0o400n
    || before.size < 128n
    || before.size > BigInt(MAX_RECEIPT_BYTES)) {
    throw new Error('Controlled sidecar deployment receipt descriptor is invalid');
  }
  const bytes = Buffer.alloc(Number(before.size));
  let offset = 0;
  while (offset < bytes.length) {
    const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
    if (count < 1) {
      throw new Error('Controlled sidecar deployment receipt ended early');
    }
    offset += count;
  }
  const after = fstatSync(descriptor, { bigint: true });
  if (!sameState(before, after) || sha256(bytes) !== receiptSha256) {
    throw new Error('Controlled sidecar deployment receipt changed while held');
  }
  return Object.freeze({
    bytes,
    sha256: receiptSha256,
    value: parseReceiptBytes(bytes, expectedRoot),
  });
}

export async function assertSidecarDeploymentMatchesReceipt(deploymentRoot, receiptBytes) {
  const current = await captureSidecarDeploymentReceipt(deploymentRoot);
  if (!current.bytes.equals(receiptBytes)) {
    throw new Error('Controlled sidecar deployment changed after installation');
  }
  return current;
}
