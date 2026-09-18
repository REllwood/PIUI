import { createHash } from 'node:crypto';
import { constants, fchmodSync, fstatSync, lstatSync } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  assertHeldTreeHasNoAcl,
  exclusiveDirectoryRename,
} from './exclusive-rename.mjs';

const MAX_TREE_ENTRIES = 100_000;
const MAX_TREE_BYTES = 2 * 1024 * 1024 * 1024;

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
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

async function prepareDirectory(path, isRoot, heldHandle) {
  const expectedUid = typeof process.getuid === 'function' ? BigInt(process.getuid()) : undefined;
  if (expectedUid === undefined) throw new Error('Prepared sidecar candidate owner is unavailable');
  let handle = heldHandle;
  try {
    if (!handle) {
      handle = await open(
        path,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY,
      );
    }
    const before = await lstat(path, { bigint: true });
    const opened = await handle.stat({ bigint: true });
    if (!before.isDirectory() || before.isSymbolicLink() || before.uid !== expectedUid
      || !sameState(before, opened) || (before.mode & 0o022n) !== 0n) {
      throw new Error('Prepared sidecar candidate contains an unsafe directory');
    }
    for (const entry of await readdir(path, { withFileTypes: true })) {
      const child = resolve(path, entry.name);
      if (entry.name === '.DS_Store') {
        throw new Error('Prepared sidecar candidate contains Finder metadata');
      } else if (entry.isDirectory()) {
        const childHandle = await open(
          child,
          constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY,
        );
        await prepareDirectory(child, false, childHandle);
      } else if (!entry.isFile() || entry.isSymbolicLink()) {
        throw new Error('Prepared sidecar candidate contains an unsafe entry');
      } else {
        const childBefore = await lstat(child, { bigint: true });
        const childHandle = await open(child, constants.O_RDONLY | constants.O_NOFOLLOW);
        try {
          const childOpened = await childHandle.stat({ bigint: true });
          if (!childBefore.isFile() || childBefore.isSymbolicLink()
            || childBefore.nlink !== 1n || childBefore.uid !== expectedUid
            || (childBefore.mode & 0o022n) !== 0n
            || !sameState(childBefore, childOpened)) {
            throw new Error('Prepared sidecar candidate contains an unsafe file');
          }
        } finally {
          await childHandle.close();
        }
      }
    }
    await handle.chmod(isRoot ? 0o700 : 0o555);
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (!sameState(after, pathAfter)
      || after.dev !== opened.dev || after.ino !== opened.ino
      || after.uid !== opened.uid || after.gid !== opened.gid
      || (after.mode & 0o777n) !== (isRoot ? 0o700n : 0o555n)) {
      throw new Error('Prepared sidecar candidate directory changed while sealing');
    }
  } finally {
    await handle?.close();
  }
}

/** Seal descendants while keeping the candidate root writable for macOS rename. */
export async function prepareCandidateForRename(path, { heldRootFd } = {}) {
  if (!Number.isSafeInteger(heldRootFd) || heldRootFd < 3 || heldRootFd > 255) {
    throw new Error('Prepared sidecar candidate descriptor is unavailable');
  }
  const rootBefore = fstatSync(heldRootFd, { bigint: true });
  const pathBefore = lstatSync(path, { bigint: true });
  if (!sameState(rootBefore, pathBefore)) {
    throw new Error('Prepared sidecar candidate descriptor changed before sealing');
  }
  const duplicate = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
  try {
    const opened = await duplicate.stat({ bigint: true });
    if (!sameState(rootBefore, opened)) {
      throw new Error('Prepared sidecar candidate descriptor changed before sealing');
    }
    await prepareDirectory(path, true, duplicate);
  } finally {
    if (duplicate.fd >= 0) await duplicate.close();
  }
  const rootAfter = fstatSync(heldRootFd, { bigint: true });
  const pathAfter = lstatSync(path, { bigint: true });
  if (!sameState(rootAfter, pathAfter)
    || rootAfter.dev !== rootBefore.dev || rootAfter.ino !== rootBefore.ino) {
    throw new Error('Prepared sidecar candidate descriptor changed while sealing');
  }
}

function exactManifest(manifestBytes, files) {
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch {
    throw new Error('Prepared sidecar manifest is invalid');
  }
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)
    || Object.keys(manifest).sort().join(',') !== 'closure,files,node,piSdk'
    || manifest.closure !== 'isolated-v1'
    || typeof manifest.node !== 'string'
    || typeof manifest.piSdk !== 'string'
    || !Array.isArray(manifest.files)) {
    throw new Error('Prepared sidecar manifest is invalid');
  }
  const expected = files
    .filter((entry) => entry.kind === 'file' && entry.path !== 'manifest.json')
    .map((entry) => ({ bytes: entry.size, path: entry.path, sha256: entry.sha256 }));
  expected.sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
  if (manifest.files.length !== expected.length || manifest.files.some((entry, index) => (
    !entry || typeof entry !== 'object' || Array.isArray(entry)
    || Object.keys(entry).sort().join(',') !== 'bytes,path,sha256'
    || entry.bytes !== expected[index]?.bytes
    || entry.path !== expected[index]?.path
    || entry.sha256 !== expected[index]?.sha256
  ))) {
    throw new Error('Prepared sidecar tree does not match its manifest');
  }
  return sha256(manifestBytes);
}

async function captureTreeLease(path) {
  if (typeof path !== 'string' || resolve(path) !== path || await realpath(path) !== path) {
    throw new Error('Prepared sidecar candidate path is not canonical');
  }
  const expectedUid = typeof process.getuid === 'function' ? BigInt(process.getuid()) : undefined;
  if (expectedUid === undefined) throw new Error('Prepared sidecar candidate owner is unavailable');
  const entries = [];
  let totalBytes = 0;
  async function visit(current, relativePath) {
    const before = await lstat(current, { bigint: true });
    if (before.uid !== expectedUid || (before.mode & 0o022n) !== 0n
      || before.isSymbolicLink() || entries.length >= MAX_TREE_ENTRIES) {
      throw new Error('Prepared sidecar candidate contains an unsafe entry');
    }
    if (before.isDirectory()) {
      const names = await readdir(current);
      names.sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
      for (const name of names) {
        const child = resolve(current, name);
        const childPath = relativePath === '.' ? name : `${relativePath}/${name}`;
        await visit(child, childPath);
      }
      const after = await lstat(current, { bigint: true });
      if (!sameState(before, after)) {
        throw new Error('Prepared sidecar candidate directory changed during capture');
      }
      entries.push(Object.freeze({
        ctimeNs: before.ctimeNs,
        dev: before.dev,
        gid: before.gid,
        ino: before.ino,
        kind: 'directory',
        mode: before.mode,
        mtimeNs: before.mtimeNs,
        nlink: before.nlink,
        path: relativePath,
        size: before.size,
        uid: before.uid,
      }));
      return;
    }
    if (!before.isFile() || before.nlink !== 1n || before.size < 0n
      || before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('Prepared sidecar candidate contains an unsupported entry');
    }
    totalBytes += Number(before.size);
    if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_TREE_BYTES) {
      throw new Error('Prepared sidecar candidate exceeds its byte bound');
    }
    const handle = await open(current, constants.O_RDONLY | constants.O_NOFOLLOW);
    let bytes;
    try {
      const opened = await handle.stat({ bigint: true });
      if (!sameState(before, opened)) {
        throw new Error('Prepared sidecar candidate file changed before capture');
      }
      bytes = await handle.readFile();
      const after = await handle.stat({ bigint: true });
      const pathAfter = await lstat(current, { bigint: true });
      if (!sameState(opened, after) || !sameState(after, pathAfter)
        || BigInt(bytes.length) !== opened.size) {
        throw new Error('Prepared sidecar candidate file changed during capture');
      }
    } finally {
      await handle.close();
    }
    entries.push(Object.freeze({
      ctimeNs: before.ctimeNs,
      dev: before.dev,
      gid: before.gid,
      ino: before.ino,
      kind: 'file',
      mode: before.mode,
      mtimeNs: before.mtimeNs,
      nlink: before.nlink,
      path: relativePath,
      sha256: sha256(bytes),
      size: Number(before.size),
      uid: before.uid,
    }));
  }
  await visit(path, '.');
  entries.sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
  const root = entries.find((entry) => entry.path === '.');
  const manifest = entries.find((entry) => entry.path === 'manifest.json');
  if (!root || root.kind !== 'directory' || !manifest || manifest.kind !== 'file') {
    throw new Error('Prepared sidecar candidate manifest is missing');
  }
  const manifestBytes = await (async () => {
    const manifestPath = resolve(path, 'manifest.json');
    const before = await lstat(manifestPath, { bigint: true });
    const handle = await open(manifestPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const opened = await handle.stat({ bigint: true });
      const bytes = await handle.readFile();
      const after = await handle.stat({ bigint: true });
      const pathAfter = await lstat(manifestPath, { bigint: true });
      if (!sameState(before, opened) || !sameState(opened, after)
        || !sameState(after, pathAfter) || await realpath(manifestPath) !== manifestPath
        || opened.dev !== manifest.dev || opened.ino !== manifest.ino
        || opened.mode !== manifest.mode || opened.uid !== manifest.uid
        || opened.gid !== manifest.gid || opened.nlink !== manifest.nlink
        || opened.size !== BigInt(manifest.size)
        || opened.mtimeNs !== manifest.mtimeNs || opened.ctimeNs !== manifest.ctimeNs
        || BigInt(bytes.length) !== opened.size) {
        throw new Error('Prepared sidecar candidate manifest changed after capture');
      }
      return bytes;
    } finally {
      await handle.close();
    }
  })();
  const manifestSha256 = exactManifest(manifestBytes, entries);
  if (manifestSha256 !== manifest.sha256) {
    throw new Error('Prepared sidecar candidate manifest changed after capture');
  }
  return Object.freeze({
    entries: Object.freeze(entries),
    manifestSha256,
    rootIdentity: Object.freeze({
      dev: root.dev,
      gid: root.gid,
      ino: root.ino,
      uid: root.uid,
    }),
  });
}

function assertCandidateLeaseMatches(actual, expected, { allowRootModeChange = false } = {}) {
  if (!expected || actual.manifestSha256 !== expected.manifestSha256
    || actual.rootIdentity.dev !== expected.rootIdentity?.dev
    || actual.rootIdentity.ino !== expected.rootIdentity?.ino
    || actual.rootIdentity.uid !== expected.rootIdentity?.uid
    || actual.rootIdentity.gid !== expected.rootIdentity?.gid
    || actual.entries.length !== expected.entries?.length) {
    throw new Error('Published sidecar candidate does not match its held lease');
  }
  for (let index = 0; index < actual.entries.length; index += 1) {
    const current = actual.entries[index];
    const prior = expected.entries[index];
    const rootTransition = allowRootModeChange && current.path === '.';
    if (!prior || current.path !== prior.path || current.kind !== prior.kind
      || current.dev !== prior.dev || current.ino !== prior.ino
      || current.uid !== prior.uid || current.gid !== prior.gid
      || current.nlink !== prior.nlink || current.size !== prior.size
      || current.sha256 !== prior.sha256
      || (!rootTransition && (current.mode !== prior.mode
        || current.mtimeNs !== prior.mtimeNs || current.ctimeNs !== prior.ctimeNs))) {
      throw new Error('Published sidecar candidate does not match its held lease');
    }
  }
}

/** Capture the exact tree and reject every extended ACL with one native tree walk. */
export async function captureSidecarCandidateLease(path, {
  heldRootFd,
  helperWorkspaceParent,
} = {}) {
  const captured = await captureTreeLease(path);
  const root = captured.entries.find((entry) => entry.path === '.');
  let handle;
  try {
    if (heldRootFd === undefined) {
      handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
    }
    const fd = heldRootFd ?? handle?.fd;
    if (!Number.isSafeInteger(fd) || !root) {
      throw new Error('Prepared sidecar candidate descriptor is unavailable');
    }
    assertHeldTreeHasNoAcl({
      fd,
      helperWorkspaceParent,
      identity: root,
      path,
    });
    const afterAclWitness = await captureTreeLease(path);
    assertCandidateLeaseMatches(afterAclWitness, captured);
  } finally {
    await handle?.close();
  }
  return captured;
}

export async function assertSidecarCandidateLease(path, expected, {
  allowRootModeChange = false,
  heldRootFd,
  helperWorkspaceParent,
} = {}) {
  const current = await captureSidecarCandidateLease(path, {
    heldRootFd,
    helperWorkspaceParent,
  });
  assertCandidateLeaseMatches(current, expected, { allowRootModeChange });
  return current;
}

/** Change only the exact held root mode, with the captured tree sealed on both sides. */
export async function sealPublishedOutput(path, {
  candidateLease,
  heldRootFd,
  helperWorkspaceParent,
} = {}) {
  if (!candidateLease || !Number.isSafeInteger(heldRootFd)
    || heldRootFd < 3 || heldRootFd > 255) {
    throw new Error('Published sidecar sealing authority is unavailable');
  }
  await assertSidecarCandidateLease(path, candidateLease, {
    allowRootModeChange: true,
    heldRootFd,
    helperWorkspaceParent,
  });
  const heldBefore = fstatSync(heldRootFd, { bigint: true });
  const pathBefore = lstatSync(path, { bigint: true });
  if (!heldBefore.isDirectory() || heldBefore.isSymbolicLink()
    || !sameState(heldBefore, pathBefore)
    || heldBefore.dev !== candidateLease.rootIdentity?.dev
    || heldBefore.ino !== candidateLease.rootIdentity?.ino
    || heldBefore.uid !== candidateLease.rootIdentity?.uid
    || heldBefore.gid !== candidateLease.rootIdentity?.gid) {
    throw new Error('Published sidecar root does not match its held lease');
  }
  fchmodSync(heldRootFd, 0o555);
  const heldAfter = fstatSync(heldRootFd, { bigint: true });
  const pathAfter = lstatSync(path, { bigint: true });
  if (!sameState(heldAfter, pathAfter)
    || heldAfter.dev !== heldBefore.dev || heldAfter.ino !== heldBefore.ino
    || heldAfter.uid !== heldBefore.uid || heldAfter.gid !== heldBefore.gid
    || (heldAfter.mode & 0o777n) !== 0o555n) {
    throw new Error('Published sidecar root changed while sealing');
  }
  return assertSidecarCandidateLease(path, candidateLease, {
    allowRootModeChange: true,
    heldRootFd,
    helperWorkspaceParent,
  });
}

/** Lease-bound rename seam used by the disposable macOS regression. */
export async function renamePreparedCandidate(prepared, output, {
  candidateLease,
  heldRootFd,
  helperWorkspaceParent,
  ...renameOptions
} = {}) {
  if (!candidateLease || !Number.isSafeInteger(heldRootFd)) {
    throw new Error('Prepared sidecar publication lease is unavailable');
  }
  await assertSidecarCandidateLease(prepared, candidateLease, {
    heldRootFd,
    helperWorkspaceParent,
  });
  const root = candidateLease.entries?.find((entry) => entry.path === '.');
  if (!root || root.kind !== 'directory') {
    throw new Error('Prepared sidecar publication lease is invalid');
  }
  const receipt = exclusiveDirectoryRename(prepared, output, {
    ...renameOptions,
    expectedSourceIdentity: renameOptions.expectedSourceIdentity ?? root,
    helperWorkspaceParent,
  });
  await assertSidecarCandidateLease(output, candidateLease, {
    allowRootModeChange: true,
    heldRootFd,
    helperWorkspaceParent,
  });
  await sealPublishedOutput(output, {
    candidateLease,
    heldRootFd,
    helperWorkspaceParent,
  });
  return receipt;
}
