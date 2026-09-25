import { createHash, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import {
  lstat,
  open,
  readdir,
  realpath,
} from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  AUTOMATION_SIGNING_POLICY_ENVIRONMENT,
  automationSigningPolicy,
  automationSigningPolicyPath,
  canonicalArchitectureJson,
  sha256Bytes,
} from './architecture-gate-schema.mjs';
import {
  applyAutomationHostSignatureInBroker,
  assertAutomationHostSigningEvidence,
  authenticateAutomationSigningAuthorityInBroker,
  automationSigningKeychainPath,
  inspectAppleDevelopmentHost,
} from './automation-host-signing.mjs';

const BROKER_SCRIPT = fileURLToPath(import.meta.url);
const NONCE = /^[0-9a-f]{64}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/u;
const MAX_PROTOCOL_BYTES = 64 * 1024;
const MAX_HOST_BYTES = 512 * 1_048_576;
const DEFAULT_REQUEST_TIMEOUT_MS = 90_000;
const sessionStates = new WeakMap();

function reject(message = 'Automation signing broker rejected') {
  throw new Error(message);
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype) reject();
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])) reject();
}

function exactAbsolutePath(path) {
  if (typeof path !== 'string'
    || !path.startsWith('/')
    || resolve(path) !== path
    || /[\0\r\n]/u.test(path)) reject();
  return path;
}

function hostIdentity(state, unsignedSha256) {
  if (!state.isFile()
    || state.isSymbolicLink()
    || state.nlink !== 1n
    || state.uid !== BigInt(process.getuid())
    || ![0o500n, 0o700n].includes(state.mode & 0o7777n)
    || state.size < 32n
    || state.size > BigInt(MAX_HOST_BYTES)
    || state.size > BigInt(Number.MAX_SAFE_INTEGER)
    || (unsignedSha256 !== undefined && !SHA256.test(unsignedSha256))) reject();
  return Object.freeze({
    dev: state.dev.toString(),
    ino: state.ino.toString(),
    mode: Number(state.mode & 0o7777n),
    size: Number(state.size),
    ...(unsignedSha256 === undefined ? {} : { unsignedSha256 }),
  });
}

function sameHostIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.size === right.size;
}

function directoryIdentity(state) {
  if (!state.isDirectory()
    || state.isSymbolicLink()
    || state.uid !== BigInt(process.getuid())
    || (state.mode & 0o7777n) !== 0o700n) reject();
  return Object.freeze({
    dev: state.dev,
    gid: state.gid,
    ino: state.ino,
    mode: state.mode,
    uid: state.uid,
  });
}

function sameDirectoryIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid;
}

async function openPrivateDirectory(path) {
  exactAbsolutePath(path);
  let handle;
  try {
    handle = await open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_DIRECTORY ?? 0),
    );
    const descriptor = directoryIdentity(await handle.stat({ bigint: true }));
    const pathname = directoryIdentity(await lstat(path, { bigint: true }));
    if (!sameDirectoryIdentity(descriptor, pathname) || await realpath(path) !== path) reject();
    return Object.freeze({ handle, identity: descriptor, path });
  } catch (error) {
    await handle?.close();
    throw error;
  }
}

async function assertPrivateDirectory(directory) {
  const descriptor = directoryIdentity(await directory.handle.stat({ bigint: true }));
  const pathname = directoryIdentity(await lstat(directory.path, { bigint: true }));
  if (!sameDirectoryIdentity(directory.identity, descriptor)
    || !sameDirectoryIdentity(descriptor, pathname)
    || await realpath(directory.path) !== directory.path) reject();
}

async function readAt(handle, size, maximum = MAX_HOST_BYTES) {
  if (typeof size !== 'bigint'
    || size < 1n
    || size > BigInt(maximum)
    || size > BigInt(Number.MAX_SAFE_INTEGER)) reject();
  const bytes = Buffer.alloc(Number(size));
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesRead } = await handle.read(
      bytes,
      offset,
      Math.min(64 * 1024, bytes.length - offset),
      offset,
    );
    if (bytesRead < 1) reject();
    offset += bytesRead;
  }
  return bytes;
}

async function hashHeld(handle, size) {
  const bytes = await readAt(handle, size);
  try {
    return sha256Bytes(bytes);
  } finally {
    bytes.fill(0);
  }
}

async function openHeldUnsignedHost(path) {
  exactAbsolutePath(path);
  let handle;
  try {
    handle = await open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_CLOEXEC ?? 0),
    );
    const descriptorState = await handle.stat({ bigint: true });
    const pathnameState = await lstat(path, { bigint: true });
    const descriptor = hostIdentity(descriptorState);
    const pathname = hostIdentity(pathnameState);
    if (!sameHostIdentity(descriptor, pathname) || await realpath(path) !== path) reject();
    const unsignedSha256 = await hashHeld(handle, descriptorState.size);
    return Object.freeze({
      expected: hostIdentity(descriptorState, unsignedSha256),
      handle,
      path,
      uid: descriptorState.uid,
    });
  } catch (error) {
    await handle?.close();
    throw error;
  }
}

async function assertHeldUnsignedHost(host, { requirePath = true } = {}) {
  const state = await host.handle.stat({ bigint: true });
  if (!state.isFile()
    || state.isSymbolicLink()
    || state.dev.toString() !== host.expected.dev
    || state.ino.toString() !== host.expected.ino
    || Number(state.mode & 0o7777n) !== host.expected.mode
    || Number(state.size) !== host.expected.size
    || state.uid !== host.uid
    || await hashHeld(host.handle, state.size) !== host.expected.unsignedSha256) reject();
  if (requirePath) {
    const pathname = hostIdentity(await lstat(host.path, { bigint: true }));
    if (!sameHostIdentity(host.expected, pathname) || await realpath(host.path) !== host.path) reject();
  } else if (state.nlink !== 0n) {
    reject();
  }
}

function protocolPaths(controlRoot, nonce) {
  exactAbsolutePath(controlRoot);
  if (!NONCE.test(nonce)) reject();
  return Object.freeze({
    consumedPath: resolve(controlRoot, `consumed-${nonce}.json`),
    requestPath: resolve(controlRoot, `request-${nonce}.json`),
    responsePath: resolve(controlRoot, `response-${nonce}.json`),
    verificationRoot: resolve(controlRoot, 'verification'),
  });
}

function requestValue(nonce, hostPath, host) {
  return Object.freeze({
    host: Object.freeze({ ...host }),
    hostPath,
    nonce,
    schemaVersion: 1,
    type: 'automation-signing-request',
  });
}

function canonicalBytes(value) {
  const bytes = Buffer.from(`${canonicalArchitectureJson(value)}\n`, 'utf8');
  if (bytes.length < 3 || bytes.length > MAX_PROTOCOL_BYTES) reject();
  return bytes;
}

function parseCanonicalBytes(bytes) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 3
    || bytes.length > MAX_PROTOCOL_BYTES
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)) reject();
  let text;
  let value;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, -1));
    value = JSON.parse(text);
  } catch {
    reject();
  }
  if (`${canonicalArchitectureJson(value)}\n` !== bytes.toString('utf8')) reject();
  return value;
}

function assertRequest(value, expected) {
  exactKeys(value, ['host', 'hostPath', 'nonce', 'schemaVersion', 'type']);
  exactKeys(value.host, ['dev', 'ino', 'mode', 'size', 'unsignedSha256']);
  if (value.schemaVersion !== 1
    || value.type !== 'automation-signing-request'
    || value.nonce !== expected.nonce
    || value.hostPath !== expected.hostPath
    || canonicalArchitectureJson(value.host) !== canonicalArchitectureJson(expected.host)
    || !DECIMAL.test(value.host.dev)
    || !DECIMAL.test(value.host.ino)
    || !Number.isSafeInteger(value.host.mode)
    || ![0o500, 0o700].includes(value.host.mode)
    || !Number.isSafeInteger(value.host.size)
    || value.host.size < 32
    || value.host.size > MAX_HOST_BYTES
    || !SHA256.test(value.host.unsignedSha256)) reject();
  return Object.freeze({ ...value, host: Object.freeze({ ...value.host }) });
}

function assertResponse(value, contract) {
  exactKeys(value, [
    'hostPath',
    'nonce',
    'requestSha256',
    'schemaVersion',
    'signedHost',
    'signingEvidence',
    'state',
  ]);
  exactKeys(value.signedHost, ['dev', 'ino', 'mode', 'sha256', 'size']);
  if (value.schemaVersion !== 1
    || value.state !== 'signed'
    || value.nonce !== contract.nonce
    || value.hostPath !== contract.request.hostPath
    || value.requestSha256 !== sha256Bytes(canonicalBytes(contract.request))
    || !DECIMAL.test(value.signedHost.dev)
    || !DECIMAL.test(value.signedHost.ino)
    || ![0o500, 0o700].includes(value.signedHost.mode)
    || !Number.isSafeInteger(value.signedHost.size)
    || value.signedHost.size < 32
    || value.signedHost.size > MAX_HOST_BYTES
    || !SHA256.test(value.signedHost.sha256)
    || value.signedHost.sha256 === contract.request.host.unsignedSha256) reject();
  const evidence = assertAutomationHostSigningEvidence(value.signingEvidence);
  if (evidence.executableBytes !== value.signedHost.size
    || evidence.executableSha256 !== value.signedHost.sha256) reject();
  return Object.freeze({
    ...value,
    signedHost: Object.freeze({ ...value.signedHost }),
    signingEvidence: evidence,
  });
}

async function openCanonicalProtocolFile(path) {
  let handle;
  try {
    handle = await open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_CLOEXEC ?? 0),
    );
    const state = await handle.stat({ bigint: true });
    const pathname = await lstat(path, { bigint: true });
    if (!state.isFile()
      || state.isSymbolicLink()
      || state.nlink !== 1n
      || state.uid !== BigInt(process.getuid())
      || (state.mode & 0o7777n) !== 0o600n
      || state.size < 3n
      || state.size > BigInt(MAX_PROTOCOL_BYTES)
      || pathname.isSymbolicLink()
      || pathname.dev !== state.dev
      || pathname.ino !== state.ino
      || pathname.mode !== state.mode
      || pathname.size !== state.size
      || await realpath(path) !== path) reject();
    const bytes = await readAt(handle, state.size, MAX_PROTOCOL_BYTES);
    parseCanonicalBytes(bytes);
    return Object.freeze({ bytes, expected: state, handle, path });
  } catch (error) {
    await handle?.close();
    throw error;
  }
}

async function assertCanonicalProtocolFile(file) {
  const state = await file.handle.stat({ bigint: true });
  const pathname = await lstat(file.path, { bigint: true });
  if (!state.isFile()
    || state.isSymbolicLink()
    || state.nlink !== 1n
    || state.dev !== file.expected.dev
    || state.ino !== file.expected.ino
    || state.mode !== file.expected.mode
    || state.size !== file.expected.size
    || pathname.isSymbolicLink()
    || pathname.dev !== state.dev
    || pathname.ino !== state.ino
    || pathname.mode !== state.mode
    || pathname.size !== state.size
    || await realpath(file.path) !== file.path) reject();
  const bytes = await readAt(file.handle, state.size, MAX_PROTOCOL_BYTES);
  if (!bytes.equals(file.bytes)) reject();
  parseCanonicalBytes(bytes);
}

async function writeExclusiveCanonical(path, value) {
  const bytes = canonicalBytes(value);
  let handle;
  try {
    handle = await open(
      path,
      constants.O_CREAT
        | constants.O_EXCL
        | constants.O_RDWR
        | constants.O_NOFOLLOW
        | (constants.O_CLOEXEC ?? 0),
      0o600,
    );
    await handle.writeFile(bytes);
    await handle.sync();
    const file = await openCanonicalProtocolFile(path);
    await handle.close();
    return file;
  } catch (error) {
    await handle?.close();
    throw error;
  }
}

async function assertInventory(control, expectedNames) {
  await assertPrivateDirectory(control);
  const actual = (await readdir(control.path)).sort();
  const expected = [...expectedNames].sort();
  if (canonicalArchitectureJson(actual) !== canonicalArchitectureJson(expected)) reject();
}

async function assertAbsent(path) {
  try {
    await lstat(path);
    reject();
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

async function waitForRequest(control, paths, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const inventory = (await readdir(control.path)).sort();
    const empty = ['verification'];
    const ready = ['verification', paths.requestPath.slice(control.path.length + 1)].sort();
    if (canonicalArchitectureJson(inventory) === canonicalArchitectureJson(ready)) {
      return openCanonicalProtocolFile(paths.requestPath);
    }
    if (canonicalArchitectureJson(inventory) !== canonicalArchitectureJson(empty)) reject();
    await sleep(20);
  }
  reject('Automation signing broker request timed out');
}

function normaliseChildConfiguration(configuration) {
  exactKeys(configuration, [
    'controlRoot',
    'host',
    'hostPath',
    'nonce',
    'requestTimeoutMs',
    'verificationRoot',
  ]);
  exactAbsolutePath(configuration.controlRoot);
  exactAbsolutePath(configuration.hostPath);
  exactAbsolutePath(configuration.verificationRoot);
  if (!NONCE.test(configuration.nonce)
    || configuration.verificationRoot !== resolve(configuration.controlRoot, 'verification')
    || !Number.isSafeInteger(configuration.requestTimeoutMs)
    || configuration.requestTimeoutMs < 100
    || configuration.requestTimeoutMs > 5 * 60_000) reject();
  const expected = requestValue(
    configuration.nonce,
    configuration.hostPath,
    configuration.host,
  );
  assertRequest(expected, expected);
  return Object.freeze({ ...configuration, request: expected });
}

function childDependencies(dependencies) {
  const accepted = {
    applySignature: applyAutomationHostSignatureInBroker,
    authenticateAuthority: authenticateAutomationSigningAuthorityInBroker,
    inspectHost: inspectAppleDevelopmentHost,
    ...dependencies,
  };
  exactKeys(accepted, ['applySignature', 'authenticateAuthority', 'inspectHost']);
  if (Object.values(accepted).some((dependency) => typeof dependency !== 'function')) reject();
  return Object.freeze(accepted);
}

/**
 * Execute one broker transaction. Production launches this entry point beneath
 * the authenticated broker sandbox; injectable functions exist only so the
 * protocol and race checks can be exercised without consuming a real signing
 * identity in unit tests.
 */
export async function runAutomationSigningBrokerChild(configuration, dependencies = {}) {
  const input = normaliseChildConfiguration(configuration);
  const implementation = childDependencies(dependencies);
  const paths = protocolPaths(input.controlRoot, input.nonce);
  let control;
  let verification;
  let unsigned;
  let requestFile;
  let consumedFile;
  let signed;
  let responseFile;
  try {
    control = await openPrivateDirectory(input.controlRoot);
    verification = await openPrivateDirectory(input.verificationRoot);
    if (dirname(input.verificationRoot) !== input.controlRoot) reject();
    unsigned = await openHeldUnsignedHost(input.hostPath);
    if (canonicalArchitectureJson(unsigned.expected)
      !== canonicalArchitectureJson(input.host)) reject();
    await assertAbsent(`${input.hostPath}.cstemp`);
    requestFile = await waitForRequest(control, paths, input.requestTimeoutMs);
    const acceptedRequest = assertRequest(parseCanonicalBytes(requestFile.bytes), input.request);
    await assertCanonicalProtocolFile(requestFile);
    await assertHeldUnsignedHost(unsigned);
    await assertPrivateDirectory(verification);
    await assertInventory(control, ['verification', paths.requestPath.slice(input.controlRoot.length + 1)]);

    const requestSha256 = sha256Bytes(requestFile.bytes);
    consumedFile = await writeExclusiveCanonical(paths.consumedPath, {
      hostPath: input.hostPath,
      nonce: input.nonce,
      requestSha256,
      schemaVersion: 1,
      state: 'consumed',
    });
    await control.handle.sync();
    await assertCanonicalProtocolFile(requestFile);
    await assertCanonicalProtocolFile(consumedFile);
    await assertInventory(control, [
      'verification',
      paths.requestPath.slice(input.controlRoot.length + 1),
      paths.consumedPath.slice(input.controlRoot.length + 1),
    ]);

    const authority = await implementation.authenticateAuthority();
    await assertCanonicalProtocolFile(requestFile);
    await assertCanonicalProtocolFile(consumedFile);
    await assertHeldUnsignedHost(unsigned);
    await implementation.applySignature(input.hostPath, authority);
    await assertCanonicalProtocolFile(requestFile);
    await assertCanonicalProtocolFile(consumedFile);
    await assertHeldUnsignedHost(unsigned, { requirePath: false });
    await assertAbsent(`${input.hostPath}.cstemp`);

    signed = await openHeldUnsignedHost(input.hostPath);
    if (signed.expected.dev === unsigned.expected.dev
      && signed.expected.ino === unsigned.expected.ino) reject();
    if (signed.expected.mode !== unsigned.expected.mode
      || signed.expected.unsignedSha256 === unsigned.expected.unsignedSha256) reject();
    const signingEvidence = assertAutomationHostSigningEvidence(
      await implementation.inspectHost(input.hostPath, {
        verificationParent: input.verificationRoot,
      }),
    );
    if (signingEvidence.executableBytes !== signed.expected.size
      || signingEvidence.executableSha256 !== signed.expected.unsignedSha256) reject();
    await assertHeldUnsignedHost(signed);
    await assertHeldUnsignedHost(unsigned, { requirePath: false });
    await assertCanonicalProtocolFile(requestFile);
    await assertCanonicalProtocolFile(consumedFile);
    await assertPrivateDirectory(verification);

    const response = Object.freeze({
      hostPath: acceptedRequest.hostPath,
      nonce: input.nonce,
      requestSha256,
      schemaVersion: 1,
      signedHost: Object.freeze({
        dev: signed.expected.dev,
        ino: signed.expected.ino,
        mode: signed.expected.mode,
        sha256: signed.expected.unsignedSha256,
        size: signed.expected.size,
      }),
      signingEvidence,
      state: 'signed',
    });
    responseFile = await writeExclusiveCanonical(paths.responsePath, response);
    await control.handle.sync();
    await assertCanonicalProtocolFile(requestFile);
    await assertCanonicalProtocolFile(consumedFile);
    await assertCanonicalProtocolFile(responseFile);
    await assertInventory(control, [
      'verification',
      paths.requestPath.slice(input.controlRoot.length + 1),
      paths.consumedPath.slice(input.controlRoot.length + 1),
      paths.responsePath.slice(input.controlRoot.length + 1),
    ]);
    return assertResponse(response, Object.freeze({ nonce: input.nonce, request: input.request }));
  } finally {
    await Promise.allSettled([
      responseFile?.handle.close(),
      signed?.handle.close(),
      consumedFile?.handle.close(),
      requestFile?.handle.close(),
      unsigned?.handle.close(),
      verification?.handle.close(),
      control?.handle.close(),
    ]);
  }
}

function startDependencies(dependencies) {
  exactKeys(dependencies, []);
  return dependencies;
}

/**
 * Start the sibling broker. The returned contract is deliberately sufficient
 * for a separately sandboxed frozen-proof process: it contains only the exact
 * request/response paths and canonical request value, never the Keychain path,
 * codesign path, sandbox profile or held descriptors.
 */
export async function startAutomationSigningBroker({
  command,
  controlRoot,
  hostPath,
  nonce = randomBytes(32).toString('hex'),
  requestTimeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
  timeoutMs = requestTimeoutMs + 30_000,
}, dependencies = {}) {
  startDependencies(dependencies);
  exactAbsolutePath(command);
  exactAbsolutePath(controlRoot);
  exactAbsolutePath(hostPath);
  if (!NONCE.test(nonce)
    || !Number.isSafeInteger(requestTimeoutMs)
    || requestTimeoutMs < 100
    || requestTimeoutMs > 5 * 60_000
    || !Number.isSafeInteger(timeoutMs)
    || timeoutMs <= requestTimeoutMs
    || timeoutMs > 6 * 60_000) reject();
  // Resolve the local signing pin before any descriptor is held so an
  // unconfigured machine fails closed with its own message, then hand the
  // sandboxed child that exact file rather than its caller's environment.
  const signingPolicyPath = automationSigningPolicyPath();
  automationSigningPolicy();
  const paths = protocolPaths(controlRoot, nonce);
  let control;
  let verification;
  let unsigned;
  try {
    control = await openPrivateDirectory(controlRoot);
    verification = await openPrivateDirectory(paths.verificationRoot);
    unsigned = await openHeldUnsignedHost(hostPath);
    await assertInventory(control, ['verification']);
    await assertAbsent(`${hostPath}.cstemp`);
    const request = requestValue(nonce, hostPath, unsigned.expected);
    const contract = Object.freeze({
      nonce,
      request,
      requestPath: paths.requestPath,
      responsePath: paths.responsePath,
      schemaVersion: 1,
    });
    const {
      createAuthenticatedNodeAutomationSigningBrokerSandboxProfile,
      runOwnedCommand,
    } = await import('./a21-gate-support.mjs');
    const sandboxProfile = createAuthenticatedNodeAutomationSigningBrokerSandboxProfile({
      brokerScript: BROKER_SCRIPT,
      command,
      controlRoot,
      hostPath,
      keychainPath: automationSigningKeychainPath(),
      nonce,
      signingPolicyPath,
      verificationRoot: paths.verificationRoot,
    });
    const childConfiguration = Object.freeze({
      controlRoot,
      host: unsigned.expected,
      hostPath,
      nonce,
      requestTimeoutMs,
      verificationRoot: paths.verificationRoot,
    });
    const argumentsList = brokerArguments(childConfiguration);
    const completion = runOwnedCommand({
      args: argumentsList,
      command,
      cwd: '/',
      env: {
        CFFIXED_USER_HOME: homedir(),
        HOME: homedir(),
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
        PATH: '/usr/bin:/bin',
        [AUTOMATION_SIGNING_POLICY_ENVIRONMENT]: signingPolicyPath,
        TMPDIR: `${paths.verificationRoot}/`,
      },
      label: 'One-use automation-signing broker',
      maxOutputBytes: 64 * 1024,
      sandboxProfile,
      timeoutMs,
    }).then(
      (result) => Object.freeze({ result }),
      (error) => Object.freeze({ error }),
    ).finally(async () => {
      await Promise.allSettled([
        unsigned.handle.close(),
        verification.handle.close(),
        control.handle.close(),
      ]);
    });
    const session = Object.freeze({ contract });
    sessionStates.set(session, {
      completion,
      submitted: false,
    });
    return session;
  } catch (error) {
    await Promise.allSettled([
      unsigned?.handle.close(),
      verification?.handle.close(),
      control?.handle.close(),
    ]);
    throw error;
  }
}

export async function publishAutomationSigningBrokerRequest(contract) {
  exactKeys(contract, ['nonce', 'request', 'requestPath', 'responsePath', 'schemaVersion']);
  if (contract.schemaVersion !== 1 || !NONCE.test(contract.nonce)) reject();
  const controlRoot = dirname(contract.requestPath);
  const paths = protocolPaths(controlRoot, contract.nonce);
  if (paths.requestPath !== contract.requestPath || paths.responsePath !== contract.responsePath) reject();
  assertRequest(contract.request, contract.request);
  let control;
  let requestFile;
  try {
    control = await openPrivateDirectory(controlRoot);
    await assertInventory(control, ['verification']);
    requestFile = await writeExclusiveCanonical(contract.requestPath, contract.request);
    await control.handle.sync();
    await assertCanonicalProtocolFile(requestFile);
    return Object.freeze({
      path: contract.requestPath,
      sha256: sha256Bytes(requestFile.bytes),
    });
  } finally {
    await requestFile?.handle.close();
    await control?.handle.close();
  }
}

export async function awaitAutomationSigningBrokerResponse(session) {
  const state = sessionStates.get(session);
  if (!state) reject('Automation signing broker session is invalid');
  const outcome = await state.completion;
  if (outcome.error) throw outcome.error;
  const result = outcome.result;
  if (result.status !== 0
    || result.signal !== null
    || result.forcedCleanup
    || result.stdout.length !== 0
    || result.stderr.length !== 0) reject('Automation signing broker process failed');
  let responseFile;
  try {
    responseFile = await openCanonicalProtocolFile(session.contract.responsePath);
    return assertResponse(parseCanonicalBytes(responseFile.bytes), session.contract);
  } finally {
    await responseFile?.handle.close();
  }
}

export async function requestAutomationHostSigning(session) {
  const state = sessionStates.get(session);
  if (!state || state.submitted) reject('Automation signing broker session was already consumed');
  state.submitted = true;
  await publishAutomationSigningBrokerRequest(session.contract);
  return awaitAutomationSigningBrokerResponse(session);
}

function brokerArguments(configuration) {
  return Object.freeze([
    BROKER_SCRIPT,
    '--broker-child',
    '--control-root', configuration.controlRoot,
    '--verification-root', configuration.verificationRoot,
    '--nonce', configuration.nonce,
    '--host-path', configuration.hostPath,
    '--host-dev', configuration.host.dev,
    '--host-ino', configuration.host.ino,
    '--host-size', String(configuration.host.size),
    '--host-mode', String(configuration.host.mode),
    '--unsigned-sha256', configuration.host.unsignedSha256,
    '--request-timeout-ms', String(configuration.requestTimeoutMs),
  ]);
}

function parseBrokerArguments(argumentsList) {
  const names = [
    '--broker-child',
    '--control-root',
    '--verification-root',
    '--nonce',
    '--host-path',
    '--host-dev',
    '--host-ino',
    '--host-size',
    '--host-mode',
    '--unsigned-sha256',
    '--request-timeout-ms',
  ];
  if (argumentsList.length !== 21 || argumentsList[0] !== names[0]) reject();
  const values = {};
  for (let index = 1; index < names.length; index += 1) {
    const offset = 1 + (index - 1) * 2;
    if (argumentsList[offset] !== names[index]) reject();
    values[names[index]] = argumentsList[offset + 1];
  }
  for (const key of ['--host-dev', '--host-ino', '--host-size', '--host-mode', '--request-timeout-ms']) {
    if (!DECIMAL.test(values[key])) reject();
  }
  return Object.freeze({
    controlRoot: values['--control-root'],
    host: Object.freeze({
      dev: values['--host-dev'],
      ino: values['--host-ino'],
      mode: Number(values['--host-mode']),
      size: Number(values['--host-size']),
      unsignedSha256: values['--unsigned-sha256'],
    }),
    hostPath: values['--host-path'],
    nonce: values['--nonce'],
    requestTimeoutMs: Number(values['--request-timeout-ms']),
    verificationRoot: values['--verification-root'],
  });
}

if (process.argv[1]
  && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  runAutomationSigningBrokerChild(parseBrokerArguments(process.argv.slice(2))).catch(() => {
    process.stderr.write('Automation signing broker rejected\n');
    process.exitCode = 1;
  });
}
