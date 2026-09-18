import { createHash, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import {
  chmod,
  link,
  lstat,
  mkdir,
  open,
  realpath,
  unlink,
} from 'node:fs/promises';
import { get as httpsGet } from 'node:https';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  architectureCacheEntryPath,
  architectureToolchainCacheRoot,
  architectureToolchainPins,
  provisionRequirements,
  verifyProvisionedArchive,
} from './architecture-toolchain-trust.mjs';

const repositoryRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const provisionerPath = fileURLToPath(import.meta.url);
const cacheRoot = architectureToolchainCacheRoot();
const concurrency = 8;
const DOWNLOAD_DEADLINE_MS = 300_000;
const MiB = 1_048_576;

function sameFileState(left, right) {
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

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

async function assertPrivateDirectory(path, label) {
  const state = await lstat(path);
  if (!state.isDirectory()
    || state.isSymbolicLink()
    || (typeof process.getuid === 'function' && state.uid !== process.getuid())
    || (state.mode & 0o777) !== 0o700
    || await realpath(path) !== path) {
    throw new Error(`${label} is not a canonical private directory`);
  }
}

async function ensurePrivateDirectory(path, label) {
  let created = false;
  try {
    await mkdir(path, { mode: 0o700, recursive: false });
    created = true;
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  if (created) await chmod(path, 0o700);
  await assertPrivateDirectory(path, label);
}

async function request(url, origin, redirectsRemaining, deadlineSignal) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:'
    || parsed.origin !== origin
    || parsed.username
    || parsed.password
    || parsed.hash) {
    throw new Error('Toolchain provisioning URL escaped its approved HTTPS origin');
  }
  if (deadlineSignal.aborted) {
    throw new Error('Toolchain download exceeded its overall deadline');
  }
  return new Promise((accept, reject) => {
    const requestHandle = httpsGet(parsed, {
      headers: { 'user-agent': 'PIUI architecture toolchain provisioner/1' },
      signal: deadlineSignal,
      timeout: 30_000,
    }, async (response) => {
      const abortResponse = () => response.destroy(
        new Error('Toolchain download exceeded its overall deadline'),
      );
      deadlineSignal.addEventListener('abort', abortResponse, { once: true });
      response.once('close', () => {
        deadlineSignal.removeEventListener('abort', abortResponse);
      });
      response.once('error', reject);
      try {
        const status = response.statusCode ?? 0;
        if ([301, 302, 303, 307, 308].includes(status)) {
          response.resume();
          if (redirectsRemaining < 1 || typeof response.headers.location !== 'string') {
            throw new Error('Toolchain download exceeded its redirect policy');
          }
          const redirected = new URL(response.headers.location, parsed);
          if (redirected.origin !== origin) {
            throw new Error('Toolchain download redirected outside its approved origin');
          }
          accept(await request(
            redirected.href,
            origin,
            redirectsRemaining - 1,
            deadlineSignal,
          ));
          return;
        }
        if (status !== 200) {
          response.resume();
          throw new Error(`Toolchain download returned HTTP ${status}`);
        }
        accept(response);
      } catch (error) {
        response.destroy();
        reject(error);
      }
    });
    requestHandle.once('timeout', () => requestHandle.destroy(
      new Error('Toolchain download timed out'),
    ));
    requestHandle.once('error', reject);
  });
}

async function writeAll(handle, chunk, position, label) {
  let offset = 0;
  while (offset < chunk.length) {
    const { bytesWritten } = await handle.write(
      chunk,
      offset,
      chunk.length - offset,
      position + offset,
    );
    if (!Number.isSafeInteger(bytesWritten) || bytesWritten < 1) {
      throw new Error(`${label} accepted a zero-byte write`);
    }
    offset += bytesWritten;
  }
}

async function authenticateHeldTemporary(handle, path, requirement, expectedBytes) {
  const before = await handle.stat({ bigint: true });
  const pathBefore = await lstat(path, { bigint: true });
  const expectedUid = typeof process.getuid === 'function'
    ? BigInt(process.getuid())
    : undefined;
  if (!before.isFile()
    || before.isSymbolicLink()
    || before.nlink !== 1n
    || (expectedUid !== undefined && before.uid !== expectedUid)
    || (before.mode & 0o777n) !== 0o400n
    || before.size !== BigInt(expectedBytes)
    || pathBefore.isSymbolicLink()
    || !sameFileState(before, pathBefore)) {
    throw new Error(`Provisioned ${requirement.kind} temporary file is not sealed and stable`);
  }

  const hash = createHash(requirement.algorithm);
  const buffer = Buffer.allocUnsafe(MiB);
  let position = 0;
  while (position < expectedBytes) {
    const length = Math.min(buffer.length, expectedBytes - position);
    const { bytesRead } = await handle.read(buffer, 0, length, position);
    if (!Number.isSafeInteger(bytesRead) || bytesRead < 1) {
      throw new Error(`Provisioned ${requirement.kind} temporary file ended while held`);
    }
    hash.update(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }

  const after = await handle.stat({ bigint: true });
  const pathAfter = await lstat(path, { bigint: true });
  if (hash.digest('hex') !== requirement.digest
    || !sameFileState(before, after)
    || pathAfter.isSymbolicLink()
    || !sameFileState(after, pathAfter)) {
    throw new Error(`Provisioned ${requirement.kind} temporary file failed held-byte authentication`);
  }
  return after;
}

async function downloadAndPublish(requirement) {
  const destination = architectureCacheEntryPath(requirement, cacheRoot);
  try {
    await verifyProvisionedArchive(requirement, cacheRoot);
    return 'verified';
  } catch (error) {
    if (!/archive is missing/u.test(error.message)) throw error;
  }
  const temporary = resolve(
    cacheRoot,
    `.incoming-${requirement.algorithm}-${randomBytes(24).toString('hex')}`,
  );
  let handle;
  let published = false;
  try {
    const deadlineSignal = AbortSignal.timeout(DOWNLOAD_DEADLINE_MS);
    let response;
    try {
      response = await request(
        requirement.url,
        new URL(requirement.url).origin,
        3,
        deadlineSignal,
      );
    } catch (error) {
      if (deadlineSignal.aborted) {
        throw new Error('Toolchain download exceeded its overall deadline', { cause: error });
      }
      throw error;
    }
    const declaredLength = Number(response.headers['content-length']);
    if (Number.isFinite(declaredLength)
      && (declaredLength < requirement.minBytes || declaredLength > requirement.maxBytes)) {
      response.destroy();
      throw new Error(`Provisioned ${requirement.kind} Content-Length is outside its bound`);
    }
    handle = await open(
      temporary,
      constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    await handle.chmod(0o600);
    const hash = createHash(requirement.algorithm);
    let bytes = 0;
    try {
      for await (const chunk of response) {
        if (chunk.length > requirement.maxBytes - bytes) {
          response.destroy();
          throw new Error(`Provisioned ${requirement.kind} download exceeded its byte cap`);
        }
        hash.update(chunk);
        await writeAll(handle, chunk, bytes, `Provisioned ${requirement.kind} temporary file`);
        bytes += chunk.length;
      }
    } catch (error) {
      if (deadlineSignal.aborted) {
        throw new Error('Toolchain download exceeded its overall deadline', { cause: error });
      }
      throw error;
    }
    if (bytes < requirement.minBytes
      || bytes > requirement.maxBytes
      || hash.digest('hex') !== requirement.digest) {
      throw new Error(`Provisioned ${requirement.kind} download failed expected-digest authentication`);
    }
    await handle.sync();
    await handle.chmod(0o400);
    await handle.sync();
    const authenticated = await authenticateHeldTemporary(
      handle,
      temporary,
      requirement,
      bytes,
    );
    try {
      await link(temporary, destination);
      published = true;
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }
    await unlink(temporary);
    if (published) {
      const heldAfterPublication = await handle.stat({ bigint: true });
      const destinationState = await lstat(destination, { bigint: true });
      if (!sameFileIdentity(authenticated, heldAfterPublication)
        || heldAfterPublication.nlink !== 1n
        || destinationState.isSymbolicLink()
        || !sameFileState(heldAfterPublication, destinationState)) {
        throw new Error(`Provisioned ${requirement.kind} publication identity is unstable`);
      }
    }
    await handle.close();
    handle = undefined;
    await verifyProvisionedArchive(requirement, cacheRoot);
    return published ? 'downloaded' : 'verified-race';
  } catch (error) {
    const cleanupErrors = [];
    try {
      await handle?.close();
    } catch (cleanupError) {
      cleanupErrors.push(cleanupError);
    }
    try {
      await unlink(temporary);
    } catch (cleanupError) {
      if (cleanupError?.code !== 'ENOENT') cleanupErrors.push(cleanupError);
    }
    if (cleanupErrors.length > 0) {
      throw new AggregateError(
        [error, ...cleanupErrors],
        'Toolchain download and temporary cleanup failed',
      );
    }
    throw error;
  }
}

async function ensureArchitectureCacheLayout() {
  await ensurePrivateDirectory(resolve(cacheRoot, '..'), 'PIUI cache namespace');
  await ensurePrivateDirectory(cacheRoot, 'Architecture toolchain cache');
  for (const algorithm of ['sha256', 'sha512']) {
    await ensurePrivateDirectory(resolve(cacheRoot, algorithm), `${algorithm} cache directory`);
  }
}

export async function provisionNodeArchitectureArchive() {
  architectureCacheEntryPath(architectureToolchainPins.node, cacheRoot);
  await ensureArchitectureCacheLayout();
  return downloadAndPublish(architectureToolchainPins.node);
}

async function run() {
  if (process.argv.length !== 2) throw new Error('Architecture toolchain provisioner accepts no arguments');
  await ensureArchitectureCacheLayout();
  const requirements = await provisionRequirements(repositoryRoot);
  let cursor = 0;
  let completed = 0;
  let downloaded = 0;
  process.stderr.write(`Provisioning ${requirements.length} authenticated archives into ${cacheRoot}\n`);
  const workers = Array.from({ length: concurrency }, async () => {
    while (true) {
      const index = cursor;
      cursor += 1;
      if (index >= requirements.length) return;
      const status = await downloadAndPublish(requirements[index]);
      completed += 1;
      if (status === 'downloaded') downloaded += 1;
      if (completed % 25 === 0 || completed === requirements.length) {
        process.stderr.write(`Provisioned ${completed}/${requirements.length} archives\n`);
      }
    }
  });
  await Promise.all(workers);
  process.stdout.write(`Architecture toolchain cache ready: ${requirements.length} verified, ${downloaded} downloaded\n`);
}

async function isDirectInvocation() {
  if (typeof process.argv[1] !== 'string') return false;
  try {
    return await realpath(process.argv[1]) === await realpath(provisionerPath);
  } catch (error) {
    if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') return false;
    throw error;
  }
}

const directlyInvoked = await isDirectInvocation();
if (directlyInvoked) await run();
