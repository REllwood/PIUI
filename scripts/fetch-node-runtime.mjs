import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  openSync,
  readSync,
  writeSync,
} from 'node:fs';
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  realpath,
  rm,
} from 'node:fs/promises';
import { arch, platform } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { architectureToolchainPins } from './architecture-toolchain-trust.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const version = '22.23.1';
const target = 'aarch64-apple-darwin';
if (platform() !== 'darwin' || arch() !== 'arm64') throw new Error('The architecture gate requires arm64 macOS');
const checksums = JSON.parse(await readFile(resolve(root, 'scripts/node-checksums.json'), 'utf8'));
const pin = checksums[version]['darwin-arm64'];
const trustedNodePin = architectureToolchainPins.node;
if (trustedNodePin.version !== version
  || trustedNodePin.filename !== pin.archive
  || trustedNodePin.digest !== pin.sha256
  || trustedNodePin.algorithm !== 'sha256'
  || trustedNodePin.minBytes !== trustedNodePin.maxBytes) {
  throw new Error('Bundled Node archive pins are inconsistent');
}
const cache = resolve(root, '.cache/node-runtime');
const archive = resolve(cache, pin.archive);
const output = resolve(root, `src-tauri/binaries/piui-node-${target}`);
const MiB = 1_048_576;
const MAX_NODE_EXECUTABLE_BYTES = 128 * MiB;
const DOWNLOAD_TIMEOUT_MS = 300_000;
const outputArguments = process.argv.slice(2);
const heldOutputFd = outputArguments.length === 0
  ? undefined
  : outputArguments.length === 2
    && outputArguments[0] === '--held-output-fd'
    && /^(?:[3-9]|[1-9][0-9]{1,2})$/u.test(outputArguments[1])
    ? Number(outputArguments[1])
    : null;
if (heldOutputFd === null || (heldOutputFd !== undefined && heldOutputFd > 255)) {
  throw new Error('Bundled Node output authority is invalid');
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

function assertPrivateRegularFile(state, label) {
  if (!state.isFile()
    || state.isSymbolicLink()
    || state.nlink !== 1n
    || (typeof process.getuid === 'function' && state.uid !== BigInt(process.getuid()))
    || (state.mode & 0o022n) !== 0n) {
    throw new Error(`${label} is unsafe`);
  }
}

function assertBoundedSize(state, label, minBytes, maxBytes) {
  if (!Number.isSafeInteger(minBytes)
    || !Number.isSafeInteger(maxBytes)
    || minBytes < 0
    || maxBytes < minBytes
    || state.size < BigInt(minBytes)
    || state.size > BigInt(maxBytes)) {
    throw new Error(`${label} size is outside its bound`);
  }
}

async function readHeldFile(path, label, {
  maxBytes = MAX_NODE_EXECUTABLE_BYTES,
  minBytes = 1,
} = {}) {
  const before = await lstat(path, { bigint: true });
  assertPrivateRegularFile(before, label);
  assertBoundedSize(before, label, minBytes, maxBytes);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const held = await handle.stat({ bigint: true });
    if (!sameState(before, held)) throw new Error(`${label} identity changed`);
    const size = Number(held.size);
    const bytes = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      const { bytesRead } = await handle.read(
        bytes,
        offset,
        size - offset,
        offset,
      );
      if (bytesRead < 1) throw new Error(`${label} ended while held`);
      offset += bytesRead;
    }
    const heldAfter = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (!sameState(held, heldAfter) || !sameState(held, pathAfter)) {
      throw new Error(`${label} changed while held`);
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

async function assertCanonicalCacheDirectory(path) {
  const state = await lstat(path, { bigint: true });
  if (!state.isDirectory()
    || state.isSymbolicLink()
    || (typeof process.getuid === 'function' && state.uid !== BigInt(process.getuid()))
    || (state.mode & 0o022n) !== 0n
    || await realpath(path) !== path) {
    throw new Error('Bundled Node cache directory is unsafe');
  }
}

function writeAll(descriptor, bytes, label) {
  let offset = 0;
  while (offset < bytes.length) {
    const count = writeSync(
      descriptor,
      bytes,
      offset,
      bytes.length - offset,
      offset,
    );
    if (count < 1) throw new Error(`${label} accepted a zero-byte write`);
    offset += count;
  }
}

function descriptorSha256(descriptor, size, label = 'Bundled Node output') {
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(1_048_576);
  let position = 0;
  while (position < size) {
    const length = Math.min(buffer.length, size - position);
    const count = readSync(descriptor, buffer, 0, length, position);
    if (count !== length) throw new Error(`${label} ended while held`);
    hash.update(buffer.subarray(0, count));
    position += count;
  }
  return hash.digest('hex');
}

async function downloadPinnedArchive(requirement) {
  const response = await fetch(requirement.url, {
    redirect: 'error',
    signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`Official Node download failed with ${response.status}`);
  const contentLength = response.headers?.get('content-length');
  if (contentLength !== null && contentLength !== undefined) {
    if (!/^(?:0|[1-9][0-9]{0,15})$/u.test(contentLength)
      || Number(contentLength) < requirement.minBytes
      || Number(contentLength) > requirement.maxBytes) {
      throw new Error('Official Node download size is outside its bound');
    }
  }
  if (!response.body) throw new Error('Official Node download has no response body');

  const chunks = [];
  const hash = createHash(requirement.algorithm);
  let downloadedBytes = 0;
  const reader = response.body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)
        || value.byteLength < 1
        || value.byteLength > requirement.maxBytes - downloadedBytes) {
        await reader.cancel('Official Node download exceeded its bound');
        throw new Error('Official Node download exceeded its bound');
      }
      const chunk = Buffer.from(value);
      downloadedBytes += chunk.length;
      hash.update(chunk);
      chunks.push(chunk);
    }
  } finally {
    reader.releaseLock();
  }
  if (downloadedBytes < requirement.minBytes
    || downloadedBytes > requirement.maxBytes
    || hash.digest('hex') !== requirement.digest) {
    throw new Error('Official Node download failed byte authentication');
  }
  return Buffer.concat(chunks, downloadedBytes);
}

async function publishAuthenticatedArchive(path, bytes, requirement) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < requirement.minBytes
    || bytes.length > requirement.maxBytes
    || createHash(requirement.algorithm).update(bytes).digest('hex') !== requirement.digest) {
    throw new Error('Official Node archive publication lacks authenticated bytes');
  }
  const descriptor = openSync(
    path,
    constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    const accepted = fstatSync(descriptor, { bigint: true });
    assertPrivateRegularFile(accepted, 'Published Node archive');
    if (accepted.size !== 0n || (accepted.mode & 0o777n) !== 0o600n) {
      throw new Error('Published Node archive did not start as an empty private file');
    }
    writeAll(descriptor, bytes, 'Published Node archive');
    fsyncSync(descriptor);
    const published = fstatSync(descriptor, { bigint: true });
    const publishedPath = await lstat(path, { bigint: true });
    if (published.dev !== accepted.dev
      || published.ino !== accepted.ino
      || published.nlink !== 1n
      || published.size !== BigInt(bytes.length)
      || (published.mode & 0o777n) !== 0o600n
      || published.dev !== publishedPath.dev
      || published.ino !== publishedPath.ino
      || published.nlink !== publishedPath.nlink
      || published.size !== publishedPath.size
      || published.mode !== publishedPath.mode
      || descriptorSha256(descriptor, bytes.length, 'Published Node archive') !== requirement.digest) {
      throw new Error('Published Node archive changed while held');
    }
    const verified = fstatSync(descriptor, { bigint: true });
    const verifiedPath = await lstat(path, { bigint: true });
    if (!sameState(published, verified) || !sameState(verified, verifiedPath)) {
      throw new Error('Published Node archive state changed during authentication');
    }
  } finally {
    closeSync(descriptor);
  }
}

function classifyBsdtarFailure(result) {
  const errorCode = result.error?.code;
  if (['ENOSPC', 'EDQUOT', 'EFBIG'].includes(errorCode)) return 'disk-capacity';
  if (['EPERM', 'EACCES', 'EROFS'].includes(errorCode)) return 'sandbox-denial';
  const stderr = Buffer.isBuffer(result.stderr)
    ? result.stderr
    : Buffer.from(typeof result.stderr === 'string' ? result.stderr : '');
  const contains = (value) => stderr.includes(Buffer.from(value, 'utf8'));
  if (contains('No space left on device')
    || contains('Disk quota exceeded')
    || contains('File too large')) {
    return 'disk-capacity';
  }
  if (contains('Operation not permitted')
    || contains('Permission denied')
    || contains('Read-only file system')) {
    return 'sandbox-denial';
  }
  return 'subprocess-failure';
}

/**
 * Authenticates the output that is already in place without ever asking for
 * write access. The bundled runtime is hardened to mode 0500 once it has been
 * staged, so an `O_RDWR` open of it is refused; a read-only authentication is
 * both sufficient and the only one the hardened file permits. Returns true when
 * the file already carries the pinned bytes, in which case it is left hardened
 * and the rewrite below is skipped.
 */
async function verifyHeldOutput(path, expectedSha256) {
  let before;
  try {
    before = await lstat(path, { bigint: true });
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    return false;
  }
  assertPrivateRegularFile(before, 'Bundled Node output');
  assertBoundedSize(before, 'Bundled Node output', 1, MAX_NODE_EXECUTABLE_BYTES);
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const held = fstatSync(descriptor, { bigint: true });
    assertPrivateRegularFile(held, 'Bundled Node output');
    if (!sameState(before, held)) throw new Error('Bundled Node output identity changed');
    if (descriptorSha256(descriptor, Number(held.size)) !== expectedSha256) return false;
    const authenticated = fstatSync(descriptor, { bigint: true });
    const authenticatedPath = await lstat(path, { bigint: true });
    if (!sameState(held, authenticated) || !sameState(authenticated, authenticatedPath)) {
      throw new Error('Bundled Node output changed while held');
    }
    if ((held.mode & 0o777n) !== 0o500n) {
      // fchmod needs ownership, not write access, so the hardened mode can be
      // restored through the same authenticated descriptor.
      fchmodSync(descriptor, 0o500);
      fsyncSync(descriptor);
      const hardened = fstatSync(descriptor, { bigint: true });
      const hardenedPath = await lstat(path, { bigint: true });
      if (hardened.dev !== held.dev
        || hardened.ino !== held.ino
        || hardened.nlink !== 1n
        || hardened.size !== held.size
        || (hardened.mode & 0o777n) !== 0o500n
        || !sameState(hardened, hardenedPath)
        || descriptorSha256(descriptor, Number(hardened.size)) !== expectedSha256) {
        throw new Error('Bundled Node output changed during hardening');
      }
    }
    return true;
  } finally {
    closeSync(descriptor);
  }
}

async function overwriteHeldOutput(path, bytes, expectedSha256, inheritedDescriptor) {
  let before;
  try {
    before = await lstat(path, { bigint: true });
    assertPrivateRegularFile(before, 'Bundled Node output');
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  if (inheritedDescriptor !== undefined && before === undefined) {
    throw new Error('Bundled Node output authority lost its pathname');
  }
  await mkdir(dirname(path), { recursive: true });
  const flags = before
    ? constants.O_RDWR | constants.O_NOFOLLOW
    : constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;
  const descriptor = inheritedDescriptor ?? openSync(path, flags, 0o600);
  const ownsDescriptor = inheritedDescriptor === undefined;
  let demoted = false;
  try {
    const accepted = fstatSync(descriptor, { bigint: true });
    assertPrivateRegularFile(accepted, 'Bundled Node output');
    if (before && !sameState(before, accepted)) {
      throw new Error('Bundled Node output identity changed');
    }
    fchmodSync(descriptor, 0o600);
    demoted = true;
    ftruncateSync(descriptor, 0);
    let offset = 0;
    while (offset < bytes.length) {
      const count = writeSync(
        descriptor,
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      if (count < 1) throw new Error('Bundled Node output accepted a zero-byte write');
      offset += count;
    }
    fsyncSync(descriptor);
    const written = fstatSync(descriptor, { bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (written.dev !== accepted.dev
      || written.ino !== accepted.ino
      || written.nlink !== 1n
      || written.size !== BigInt(bytes.length)
      || (written.mode & 0o777n) !== 0o600n
      || written.dev !== pathAfter.dev
      || written.ino !== pathAfter.ino
      || written.nlink !== pathAfter.nlink
      || written.size !== pathAfter.size
      || written.mode !== pathAfter.mode
      || descriptorSha256(descriptor, bytes.length) !== expectedSha256) {
      throw new Error('Bundled Node output changed while held');
    }
    fchmodSync(descriptor, 0o755);
    fsyncSync(descriptor);
    const promoted = fstatSync(descriptor, { bigint: true });
    const promotedPath = await lstat(path, { bigint: true });
    if (promoted.dev !== accepted.dev
      || promoted.ino !== accepted.ino
      || promoted.nlink !== 1n
      || promoted.size !== BigInt(bytes.length)
      || (promoted.mode & 0o777n) !== 0o755n
      || promoted.dev !== promotedPath.dev
      || promoted.ino !== promotedPath.ino
      || promoted.nlink !== promotedPath.nlink
      || promoted.size !== promotedPath.size
      || promoted.mode !== promotedPath.mode) {
      throw new Error('Bundled Node output changed during promotion');
    }
    const promotedSha256 = descriptorSha256(descriptor, bytes.length);
    const verified = fstatSync(descriptor, { bigint: true });
    const verifiedPath = await lstat(path, { bigint: true });
    if (promotedSha256 !== expectedSha256
      || !sameState(promoted, verified)
      || !sameState(verified, verifiedPath)) {
      throw new Error('Bundled Node output failed post-promotion authentication');
    }
    demoted = false;
  } catch (error) {
    if (demoted) {
      try {
        fchmodSync(descriptor, 0o600);
        fsyncSync(descriptor);
      } catch (demotionError) {
        throw new AggregateError(
          [error, demotionError],
          'Bundled Node output failed and could not be demoted',
        );
      }
    }
    throw error;
  } finally {
    if (ownsDescriptor) closeSync(descriptor);
  }
}

await mkdir(cache, { recursive: true, mode: 0o700 });
await assertCanonicalCacheDirectory(cache);
let bytes;
try {
  bytes = await readHeldFile(archive, 'Pinned Node archive', {
    maxBytes: trustedNodePin.maxBytes,
    minBytes: trustedNodePin.minBytes,
  });
} catch (error) {
  if (error?.code !== 'ENOENT') throw error;
  if (process.env.PIUI_NODE_OFFLINE === '1') throw new Error('Pinned Node archive is absent in offline architecture-gate mode');
  bytes = await downloadPinnedArchive(trustedNodePin);
  await publishAuthenticatedArchive(archive, bytes, trustedNodePin);
  bytes = await readHeldFile(archive, 'Published Node archive', {
    maxBytes: trustedNodePin.maxBytes,
    minBytes: trustedNodePin.minBytes,
  });
}
const actual = createHash('sha256').update(bytes).digest('hex');
if (actual !== pin.sha256) throw new Error(`Node archive checksum mismatch: ${actual}`);
// The held-descriptor authority is supplied by the packaging pipeline, which
// owns the output for the whole build and always expects the rewrite. Only the
// plain invocation may settle for authenticating what is already in place.
const provisioned = heldOutputFd === undefined
  && await verifyHeldOutput(output, architectureToolchainPins.node.executableSha256);
if (!provisioned) {
  const extraction = await mkdtemp(resolve(cache, 'node-extract-'));
  try {
    const unpack = spawnSync(
      '/usr/bin/bsdtar',
      [
        '-xzf',
        '-',
        '-C',
        extraction,
        '--strip-components=2',
        `node-v${version}-darwin-arm64/bin/node`,
      ],
      {
        env: { ...process.env, LANG: 'C', LC_ALL: 'C' },
        input: bytes,
        maxBuffer: 1 * 1_048_576,
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    );
    if (unpack.error
      || unpack.status !== 0
      || unpack.signal !== null) {
      const failureClass = classifyBsdtarFailure(unpack);
      throw new Error(`Node archive extraction failed (${failureClass})`);
    }
    const extractedBytes = await readHeldFile(
      resolve(extraction, 'node'),
      'Extracted Node executable',
    );
    const extractedSha256 = createHash('sha256').update(extractedBytes).digest('hex');
    if (extractedSha256 !== architectureToolchainPins.node.executableSha256) {
      throw new Error('Extracted Node executable does not match its pin');
    }
    await overwriteHeldOutput(
      output,
      extractedBytes,
      extractedSha256,
      heldOutputFd,
    );
  } finally {
    await rm(extraction, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  }
}
const executableBytes = await readHeldFile(output, 'Bundled Node output');
const executableSha256 = createHash('sha256').update(executableBytes).digest('hex');
if (executableSha256 !== architectureToolchainPins.node.executableSha256) {
  throw new Error('Bundled Node executable does not match the pinned official runtime');
}
console.log(`Bundled official Node v${version} (${actual}; executable ${executableSha256})`);
