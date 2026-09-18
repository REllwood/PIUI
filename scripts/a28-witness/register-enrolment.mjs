#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import {
  lstat,
  open,
  realpath,
} from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import {
  A28_MAX_ENROLMENT_BYTES,
  A28_MAX_POLICY_BYTES,
  assertA28Enrolment,
  assertA28EnrolmentAuthorityConfig,
  assertA28RootLaunchConfig,
  canonicalA28Line,
  parseCanonicalA28Line,
  sha256A28,
} from '../verifier/contract.mjs';

const AUTHORITY_CONFIG_PATH =
  '/Library/Application Support/PIUI/A28Witness/enrolment-authority.json';
const MAX_PROTOCOL_BYTES = 4_096;

function reject(message = 'A.28 root enrolment authority rejected') {
  throw new Error(message);
}

function exactKeys(value, expected) {
  if (value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || !isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort())) reject();
}

function sameFile(before, after) {
  return before.dev === after.dev
    && before.ino === after.ino
    && before.size === after.size
    && before.mode === after.mode
    && before.mtimeMs === after.mtimeMs
    && before.ctimeMs === after.ctimeMs;
}

async function assertPathChain(path, mode, uid = 0) {
  if (typeof path !== 'string'
    || !path.startsWith('/')
    || resolve(path) !== path
    || /[\0\r\n]/u.test(path)) reject();
  if (await realpath(path) !== path) reject();
  let current = path;
  let leaf = true;
  while (true) {
    const item = await lstat(current);
    if (item.isSymbolicLink()
      || item.uid !== (leaf ? uid : 0)
      || (item.mode & 0o022) !== 0
      || (leaf && (!item.isFile() || item.nlink !== 1
        || (item.mode & 0o777) !== mode))
      || (!leaf && !item.isDirectory())) reject();
    if (current === '/') break;
    current = dirname(current);
    leaf = false;
  }
}

async function readHeldCanonical(path, mode, maximumBytes) {
  await assertPathChain(path, mode);
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    if (before.size < 3 || before.size > maximumBytes) reject();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (!sameFile(before, after) || bytes.length !== before.size) reject();
    return Object.freeze({ bytes, value: parseCanonicalA28Line(bytes) });
  } finally {
    await handle?.close();
  }
}

async function assertPinnedExecutable(path, expectedSha256) {
  await assertPathChain(path, 0o555);
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    if (before.size < 8_192 || before.size > 32 * 1024 * 1024) reject();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (!sameFile(before, after)
      || bytes.length !== before.size
      || sha256A28(bytes) !== expectedSha256) reject();
  } finally {
    await handle?.close();
  }
}

function inspectProcess(config, pid) {
  const result = spawnSync(config.processInspectorPath, [
    '--pid',
    String(pid),
    '--bundle-id',
    config.bundleIdentifier,
    '--team-id',
    config.teamIdentifier,
    '--reported-requirement',
    config.designatedRequirement,
  ], {
    encoding: null,
    env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
    maxBuffer: 256 * 1024,
    timeout: 30_000,
  });
  if (result.error
    || result.signal
    || result.status !== 0
    || !Buffer.isBuffer(result.stdout)
    || !Buffer.isBuffer(result.stderr)
    || result.stderr.length !== 0) reject();
  return parseCanonicalA28Line(result.stdout);
}

function waitForExit(child) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve({ code: child.exitCode, signal: child.signalCode });
  }
  return new Promise((accept, rejectPromise) => {
    child.once('error', rejectPromise);
    child.once('exit', (code, signal) => accept({ code, signal }));
  });
}

async function readProtocolLine(iterator, state, expected) {
  const timeout = new Promise((_, rejectPromise) => {
    const timer = setTimeout(() => {
      rejectPromise(new Error('A.28 enrolment application protocol timed out'));
    }, 5 * 60_000);
    timer.unref();
  });
  while (!state.buffer.includes(0x0a)) {
    const next = await Promise.race([iterator.next(), timeout]);
    if (next.done || !Buffer.isBuffer(next.value)) reject();
    state.buffer = Buffer.concat([state.buffer, next.value]);
    if (state.buffer.length > MAX_PROTOCOL_BYTES) reject();
  }
  const newline = state.buffer.indexOf(0x0a);
  const line = state.buffer.subarray(0, newline + 1);
  state.buffer = state.buffer.subarray(newline + 1);
  if (!line.equals(Buffer.from(expected + '\n', 'utf8'))) reject();
}

async function writeExclusiveCanonical(path, value, mode) {
  const bytes = canonicalA28Line(value);
  let handle;
  try {
    handle = await open(
      path,
      constants.O_CREAT
        | constants.O_EXCL
        | constants.O_WRONLY
        | constants.O_NOFOLLOW,
      mode,
    );
    await handle.chown(0, 0);
    await handle.chmod(mode);
    await handle.writeFile(bytes);
    await handle.sync();
    const written = await handle.stat();
    if (written.uid !== 0
      || written.gid !== 0
      || (written.mode & 0o777) !== mode
      || written.size !== bytes.length) reject();
  } finally {
    await handle?.close();
  }
  return bytes;
}

function assertLaunchedAuthority(config) {
  const expectedEntrypoint = config.rootEnrolmentRegistrarPath;
  if (typeof process.getuid !== 'function'
    || typeof process.geteuid !== 'function'
    || process.getuid() !== 0
    || process.geteuid() !== 0
    || process.argv.length !== 2
    || fileURLToPath(import.meta.url) !== expectedEntrypoint
    || resolve(process.argv[1]) !== expectedEntrypoint
    || process.execPath !== config.rootVerifierNodePath
    || process.execArgv.length !== 0
    || process.cwd() !== '/private/var/empty'
    || process.env.PATH !== '/usr/bin:/bin'
    || process.env.HOME !== '/var/root'
    || process.env.LANG !== 'C'
    || process.env.LC_ALL !== 'C'
    || Object.keys(process.env).some((name) =>
      name.startsWith('NODE_')
        || name.startsWith('DYLD_')
        || name.startsWith('LD_')
        || ['BASH_ENV', 'ENV', 'OPENSSL_CONF', 'SSLKEYLOGFILE'].includes(name))) reject();
}

export async function registerA28Enrolment() {
  const configFile = await readHeldCanonical(
    AUTHORITY_CONFIG_PATH,
    0o444,
    A28_MAX_POLICY_BYTES,
  );
  const config = assertA28EnrolmentAuthorityConfig(configFile.value);
  const launchConfigFile = await readHeldCanonical(
    config.rootEnrolmentLaunchConfigPath,
    0o444,
    A28_MAX_POLICY_BYTES,
  );
  if (sha256A28(launchConfigFile.bytes)
      !== config.rootEnrolmentLaunchConfigSha256) reject();
  assertA28RootLaunchConfig(launchConfigFile.value, config, 'enrol');
  assertLaunchedAuthority(config);
  await assertPinnedExecutable(
    config.processInspectorPath,
    config.processInspectorSha256,
  );
  const enrolmentNonce = randomBytes(32).toString('hex');
  let candidateHandle;
  let child;
  let stderr = Buffer.alloc(0);
  try {
    candidateHandle = await open(
      config.enrolmentManifestPath,
      constants.O_CREAT
        | constants.O_EXCL
        | constants.O_RDWR
        | constants.O_NOFOLLOW,
      0o400,
    );
    await candidateHandle.chown(0, 0);
    await candidateHandle.chmod(0o400);
    const initial = await candidateHandle.stat();
    if (!initial.isFile()
      || initial.nlink !== 1
      || initial.uid !== 0
      || initial.gid !== 0
      || (initial.mode & 0o777) !== 0o400
      || initial.size !== 0) reject();
    process.stderr.write(
      '[working] Waiting for the witness app and Secure Enclave biometric confirmation.\n',
    );
    child = spawn(config.witnessExecutable.path, [
      '--mode',
      'enrol',
      '--enrolment-authority-config-sha256',
      sha256A28(configFile.bytes),
      '--enrolment-nonce',
      enrolmentNonce,
      '--output-fd',
      '3',
      '--reviewer-identity',
      config.reviewerIdentity,
      '--witness-uid',
      String(config.witnessUid),
    ], {
      cwd: config.witnessHomeDirectory,
      env: {
        HOME: config.witnessHomeDirectory,
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
        PATH: '/usr/bin:/bin',
        USER: config.witnessUsername,
      },
      gid: config.witnessGid,
      stdio: ['pipe', 'pipe', 'pipe', candidateHandle.fd],
      uid: config.witnessUid,
    });
    child.stderr.on('data', (bytes) => {
      if (!Buffer.isBuffer(bytes)) return;
      stderr = Buffer.concat([stderr, bytes]);
      if (stderr.length > MAX_PROTOCOL_BYTES) child.kill('SIGTERM');
    });
    const iterator = child.stdout[Symbol.asyncIterator]();
    const protocol = { buffer: Buffer.alloc(0) };
    await readProtocolLine(iterator, protocol, 'READY');
    const before = inspectProcess(config, child.pid);
    if (before.bundleIdentifier !== config.bundleIdentifier
      || before.cdHash !== config.cdHash
      || before.designatedRequirement !== config.designatedRequirement
      || !isDeepStrictEqual(before.executable, config.witnessExecutable)) reject();
    child.stdin.write('G\n');
    await readProtocolLine(iterator, protocol, 'SIGNED');
    await candidateHandle.sync();
    const final = await candidateHandle.stat();
    const pathname = await lstat(config.enrolmentManifestPath);
    if (!final.isFile()
      || final.nlink !== 1
      || final.uid !== 0
      || final.gid !== 0
      || (final.mode & 0o777) !== 0o400
      || final.size < 3
      || final.size > A28_MAX_ENROLMENT_BYTES
      || initial.dev !== final.dev
      || initial.ino !== final.ino
      || !sameFile(final, pathname)) reject();
    const bytes = Buffer.alloc(final.size);
    const read = await candidateHandle.read(bytes, 0, bytes.length, 0);
    if (read.bytesRead !== bytes.length) reject();
    const enrolment = assertA28Enrolment(
      parseCanonicalA28Line(bytes),
      config,
    );
    if (enrolment.enrolmentProof.enrolmentNonce !== enrolmentNonce) reject();
    const after = inspectProcess(config, child.pid);
    if (!isDeepStrictEqual(before, after)) reject();
    const authorisedAt = new Date().toISOString();
    const receipt = {
      applicationIdentityAfter: after,
      applicationIdentityBefore: before,
      authorisedAt,
      enrolmentAuthorityConfigSha256: sha256A28(configFile.bytes),
      enrolmentManifestSha256: sha256A28(bytes),
      event: 'a28-secure-enclave-enrolment-authorised',
      keyAttributes: enrolment.keyAttributes,
      outputIdentity: {
        dev: final.dev,
        gid: final.gid,
        ino: final.ino,
        mode: final.mode & 0o777,
        path: config.enrolmentManifestPath,
        sha256: sha256A28(bytes),
        size: final.size,
        uid: final.uid,
      },
      publicKeySha256: enrolment.publicKeySha256,
      reviewerIdentity: enrolment.reviewerIdentity,
      reviewerKeyId: enrolment.reviewerKeyId,
      schemaVersion: 1,
      witnessGid: config.witnessGid,
      witnessUid: config.witnessUid,
    };
    child.stdin.end('A\n');
    const exited = await waitForExit(child);
    if (exited.code !== 0
      || exited.signal !== null
      || protocol.buffer.length !== 0
      || stderr.length !== 0) reject();
    await writeExclusiveCanonical(
      config.enrolmentAuthorityReceiptPath,
      receipt,
      0o400,
    );
    await candidateHandle.chmod(0o444);
    await candidateHandle.sync();
    const result = Object.freeze({
      authoritative: true,
      enrolmentAuthorityConfigSha256: sha256A28(configFile.bytes),
      enrolmentAuthorityReceiptSha256: sha256A28(canonicalA28Line(receipt)),
      enrolmentManifestSha256: sha256A28(bytes),
      humanWitnessed: false,
      schemaVersion: 1,
    });
    process.stdout.write(canonicalA28Line(result));
    return result;
  } catch (error) {
    if (child && child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
    }
    throw error;
  } finally {
    await candidateHandle?.close();
  }
}

if (import.meta.url === new URL(process.argv[1], 'file:').href) {
  registerA28Enrolment().catch((error) => {
    process.stderr.write('A.28 root enrolment authority failed: '
      + error.message + '\n');
    process.exitCode = 1;
  });
}
