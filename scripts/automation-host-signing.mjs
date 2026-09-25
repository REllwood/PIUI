import { spawnSync } from 'node:child_process';
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { constants } from 'node:fs';
import {
  lstat,
  mkdtemp,
  open,
  readdir,
  realpath,
  rmdir,
  unlink,
} from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import {
  automationSigningPolicy,
  canonicalArchitectureJson,
} from './architecture-gate-schema.mjs';

export { automationSigningPolicy } from './architecture-gate-schema.mjs';

const MACHO_64_LE_BYTES = 0xcffaedfe;
const CPU_TYPE_ARM64 = 0x0100000c;
const LC_CODE_SIGNATURE = 0x1d;
const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
const CSMAGIC_REQUIREMENTS = 0xfade0c01;
const CSMAGIC_BLOBWRAPPER = 0xfade0b01;
const CSSLOT_CODEDIRECTORY = 0;
const CSSLOT_REQUIREMENTS = 2;
const CSSLOT_SIGNATURESLOT = 0x10000;
const SHA1 = /^[0-9A-F]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const CDHASH = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const VERIFICATION_LABEL = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const MAX_VERIFICATION_BYTES = 512 * 1_048_576;

export const CODE_SIGNATURE_VERIFICATION_TEST_HOOK = Symbol(
  'PIUI code-signature verification test hook',
);

const signingEvidenceKeys = Object.freeze([
  'bundleIdentifier',
  'cdHash',
  'certificateSha1',
  'certificateSha256',
  'cmsSha256',
  'cmsBytes',
  'codeDirectoryFlags',
  'codeDirectorySha256',
  'designatedRequirement',
  'entitlements',
  'executableBytes',
  'executableSha256',
  'nonCmsSignatureSha256',
  'requirementsSha256',
  'schemaVersion',
  'signature',
  'signatureContainerBytes',
  'signatureSlots',
  'teamIdentifier',
]);

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function exactKeys(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

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

function seatbeltPath(path) {
  return path.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
}

function exactMutationAncestors(paths) {
  const ancestors = new Set(['/']);
  for (const path of paths) {
    const spellings = path.startsWith('/private/var/')
      ? [path, path.slice('/private'.length)]
      : [path];
    for (const spelling of spellings) {
      for (let current = dirname(spelling);; current = dirname(current)) {
        ancestors.add(current);
        if (current === dirname(current)) break;
      }
    }
  }
  return [...ancestors].sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
}

export function automationSigningKeychainPath() {
  const home = resolve(homedir());
  if (!home.startsWith('/Users/') || home.split('/').length !== 3 || /[\0\r\n]/u.test(home)) {
    throw new Error('Automation signing home directory is invalid');
  }
  return resolve(home, 'Library/Keychains/login.keychain-db');
}

function keychainIdentity(state) {
  return Object.freeze({
    ctimeNs: state.ctimeNs.toString(),
    dev: state.dev.toString(),
    gid: Number(state.gid),
    ino: state.ino.toString(),
    mode: Number(state.mode & 0o7777n),
    mtimeNs: state.mtimeNs.toString(),
    nlink: Number(state.nlink),
    size: Number(state.size),
    uid: Number(state.uid),
  });
}

export function automationSigningAuthoritySandbox(keychainPath) {
  if (keychainPath !== automationSigningKeychainPath()) {
    throw new Error('Automation signing authority sandbox path is invalid');
  }
  const keychain = seatbeltPath(keychainPath);
  const metadata = exactMutationAncestors([keychainPath, '/usr/bin/security'])
    .map((path) => `      (literal "${seatbeltPath(path)}")`)
    .join('\n');
  return `(version 1)
  (deny default)
  (import "dyld-support.sb")
  (deny network*)
  (deny mach-lookup)
  (allow sysctl-read)
  (with-filter (process-path "/usr/bin/sandbox-exec")
    (allow process-exec (literal "/usr/bin/security")))
  (with-filter (process-path "/usr/bin/security")
    (allow mach-lookup
      (global-name "com.apple.SecurityServer")
      (global-name "com.apple.trustd.agent"))
    (allow file-read* file-test-existence
${metadata}
      (literal "${keychain}")))
  (allow file-read* file-test-existence file-map-executable
    (literal "/usr/bin/security")
    (subpath "/Library/Apple/System/Library")
    (subpath "/System/Library")
    (subpath "/usr/lib"))`;
}

function runSandboxedSecurity(argumentsList, keychainPath) {
  return spawnSync('/usr/bin/sandbox-exec', [
    '-p',
    automationSigningAuthoritySandbox(keychainPath),
    '/usr/bin/security',
    ...argumentsList,
  ], {
    cwd: '/',
    encoding: 'utf8',
    env: {
      HOME: homedir(),
      LANG: 'en_AU.UTF-8',
      LC_ALL: 'en_AU.UTF-8',
      PATH: '/usr/bin:/bin',
    },
    maxBuffer: 256 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 30_000,
  });
}

function runBrokerSecurity(argumentsList, keychainPath) {
  if (keychainPath !== automationSigningKeychainPath()) {
    throw new Error('Automation signing keychain path is invalid');
  }
  return spawnSync('/usr/bin/security', argumentsList, {
    cwd: '/',
    encoding: 'utf8',
    env: {
      HOME: homedir(),
      LANG: 'en_AU.UTF-8',
      LC_ALL: 'en_AU.UTF-8',
      PATH: '/usr/bin:/bin',
    },
    maxBuffer: 256 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 30_000,
  });
}

async function authenticateAutomationSigningAuthorityWith(runSecurity, requirePrivateIdentity) {
  if (typeof requirePrivateIdentity !== 'boolean') {
    throw new Error('Automation signing authentication mode is invalid');
  }
  const policy = automationSigningPolicy();
  const keychainPath = automationSigningKeychainPath();
  let handle;
  try {
    handle = await open(keychainPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    const pathBefore = await lstat(keychainPath, { bigint: true });
    if (!before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1n
      || before.uid !== BigInt(process.getuid())
      || (before.mode & 0o022n) !== 0n
      || before.size < 1n
      || before.size > 64n * 1_048_576n
      || pathBefore.isSymbolicLink()
      || !sameFileState(before, pathBefore)
      || await realpath(keychainPath) !== keychainPath) {
      throw new Error('Automation signing keychain identity is invalid');
    }
    if (requirePrivateIdentity) {
      const result = runSecurity([
        'find-identity',
        '-v',
        '-p',
        'codesigning',
        keychainPath,
      ], keychainPath);
      const identityPattern = new RegExp(
        `^\\s*1\\) ${policy.certificateSha1} "${policy.certificateCommonName.replaceAll(/[.*+?^${}()|[\]\\]/gu, '\\$&')}"\\n\\s*1 valid identities found\\n$`,
        'u',
      );
      if (result.status !== 0
        || result.signal !== null
        || result.error
        || result.stderr !== ''
        || !identityPattern.test(result.stdout)) {
        throw new Error('Pinned Apple Development signing identity is unavailable');
      }
    }
    const certificates = runSecurity([
      'find-certificate',
      '-a',
      '-c',
      policy.certificateCommonName,
      '-p',
      keychainPath,
    ], keychainPath);
    const pemPattern = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gu;
    const pemBlocks = certificates.stdout?.match(pemPattern) ?? [];
    let matchingCertificates;
    try {
      matchingCertificates = pemBlocks
        .map((pem) => new X509Certificate(pem))
        .filter((certificate) => certificate.fingerprint.replaceAll(':', '').toUpperCase()
          === policy.certificateSha1);
    } catch {
      throw new Error('Pinned Apple Development leaf certificate is malformed');
    }
    if (certificates.status !== 0
      || certificates.signal !== null
      || certificates.error
      || certificates.stderr !== ''
      || pemBlocks.length < 1
      || certificates.stdout.replace(pemPattern, '').trim() !== ''
      || matchingCertificates.length !== 1
      || matchingCertificates[0].fingerprint256.replaceAll(':', '').toLowerCase()
        !== policy.certificateSha256) {
      throw new Error('Pinned Apple Development leaf certificate is unavailable');
    }
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(keychainPath, { bigint: true });
    if (!sameFileState(before, after)
      || pathAfter.isSymbolicLink()
      || !sameFileState(after, pathAfter)
      || await realpath(keychainPath) !== keychainPath) {
      throw new Error('Automation signing keychain changed during identity authentication');
    }
    return Object.freeze({
      keychainIdentity: keychainIdentity(after),
      keychainPath,
      policy,
    });
  } finally {
    await handle?.close();
  }
}

export async function authenticateAutomationSigningAuthority() {
  return authenticateAutomationSigningAuthorityWith(runSandboxedSecurity, true);
}

/**
 * Authenticate the pinned identity from inside the typed signing-broker
 * sandbox. This deliberately does not try to nest sandbox-exec (macOS refuses
 * applying a second Seatbelt profile); the outer authenticated broker profile
 * is the authority boundary for the direct security process.
 */
export async function authenticateAutomationSigningAuthorityInBroker() {
  // The subsequent exact codesign invocation is the private-key proof. On the
  // currently tested macOS release, a codesign process descended from a
  // sandboxed Node retains Node as its responsible process and cannot resolve
  // the login-Keychain private identity; that platform case fails closed at
  // signing. A production caller must not treat this certificate check alone
  // as proof that the private key is available.
  return authenticateAutomationSigningAuthorityWith(runBrokerSecurity, false);
}

export async function assertAutomationSigningAuthorityUnchanged(expected) {
  if (!expected
    || expected.keychainPath !== automationSigningKeychainPath()
    || expected.policy !== automationSigningPolicy()) {
    throw new Error('Automation signing authority witness is invalid');
  }
  const current = await authenticateAutomationSigningAuthority();
  if (canonicalArchitectureJson(current.keychainIdentity)
    !== canonicalArchitectureJson(expected.keychainIdentity)) {
    throw new Error('Automation signing authority changed during signing');
  }
  return current;
}

export async function assertAutomationSigningAuthorityUnchangedInBroker(expected) {
  if (!expected
    || expected.keychainPath !== automationSigningKeychainPath()
    || expected.policy !== automationSigningPolicy()) {
    throw new Error('Automation signing authority witness is invalid');
  }
  const current = await authenticateAutomationSigningAuthorityInBroker();
  if (canonicalArchitectureJson(current.keychainIdentity)
    !== canonicalArchitectureJson(expected.keychainIdentity)) {
    throw new Error('Automation signing authority changed during signing');
  }
  return current;
}

export function automationSigningArguments(hostPath, keychainPath) {
  if (typeof hostPath !== 'string'
    || resolve(hostPath) !== hostPath
    || typeof keychainPath !== 'string'
    || keychainPath !== automationSigningKeychainPath()) {
    throw new Error('Automation signing arguments are invalid');
  }
  const policy = automationSigningPolicy();
  return Object.freeze([
    '--force',
    '--timestamp=none',
    '--identifier',
    policy.bundleIdentifier,
    '--requirements',
    `=designated => ${policy.designatedRequirement}`,
    '--keychain',
    keychainPath,
    '--sign',
    policy.certificateSha1,
    hostPath,
  ]);
}

export function automationSigningSandbox(hostPath, keychainPath) {
  if (typeof hostPath !== 'string'
    || !hostPath.startsWith('/')
    || resolve(hostPath) !== hostPath
    || /[\0\r\n]/u.test(hostPath)
    || keychainPath !== automationSigningKeychainPath()) {
    throw new Error('Automation signing sandbox path is invalid');
  }
  const host = seatbeltPath(hostPath);
  const keychain = seatbeltPath(keychainPath);
  const temporary = seatbeltPath(`${hostPath}.cstemp`);
  const metadata = exactMutationAncestors([hostPath, keychainPath, '/usr/bin/codesign'])
    .map((path) => `      (literal "${seatbeltPath(path)}")`)
    .join('\n');
  return `(version 1)
  (deny default)
  (import "dyld-support.sb")
  (deny network*)
  (deny appleevent-send)
  (deny mach-lookup)
  (allow sysctl-read)
  (with-filter (process-path "/usr/bin/sandbox-exec")
    (allow process-exec (literal "/usr/bin/codesign")))
  (with-filter (process-path "/usr/bin/codesign")
    (allow mach-lookup
      (global-name "com.apple.SecurityServer")
      (global-name "com.apple.trustd.agent"))
    (allow system-fsctl)
    (allow file-read* file-test-existence
${metadata}
      (literal "${host}")
      (literal "${keychain}")
      (literal "${temporary}"))
    (allow file-write* file-link
      (literal "${host}")
      (literal "${temporary}")))
  (allow file-read* file-test-existence file-map-executable
    (literal "/usr/bin/codesign")
    (subpath "/Library/Apple/System/Library")
    (subpath "/System/Library")
    (subpath "/usr/lib"))`;
}

/**
 * Apply the pinned Apple Development signature to one exact host path. The
 * caller remains responsible for holding and revalidating the unsigned inode,
 * and for independently inspecting the signed replacement. Keeping that lease
 * policy outside this primitive lets the one-use signing broker enforce its
 * stricter request/response transaction without duplicating signing authority
 * authentication.
 */
async function applyAutomationHostSignatureWith(hostPath, authority, broker) {
  if (!authority
    || authority.keychainPath !== automationSigningKeychainPath()
    || authority.policy !== automationSigningPolicy()
    || typeof broker !== 'boolean') {
    throw new Error('Automation signing authority witness is invalid');
  }
  const signingArguments = automationSigningArguments(hostPath, authority.keychainPath);
  const result = spawnSync(
    broker ? '/usr/bin/codesign' : '/usr/bin/sandbox-exec',
    broker
      ? signingArguments
      : [
        '-p',
        automationSigningSandbox(hostPath, authority.keychainPath),
        '/usr/bin/codesign',
        ...signingArguments,
      ], {
    cwd: '/',
    encoding: 'utf8',
    env: {
      HOME: homedir(),
      LANG: 'en_AU.UTF-8',
      LC_ALL: 'en_AU.UTF-8',
      PATH: '/usr/bin:/bin',
    },
    maxBuffer: 256 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 60_000,
    },
  );
  const expectedReplacementNotice = `${hostPath}: replacing existing signature\n`;
  if (result.status !== 0
    || result.signal !== null
    || result.error
    || result.stdout !== ''
    || !['', expectedReplacementNotice].includes(result.stderr)) {
    throw new Error('Automation host exact-path signing failed');
  }
  if (broker) await assertAutomationSigningAuthorityUnchangedInBroker(authority);
  else await assertAutomationSigningAuthorityUnchanged(authority);
}

export async function applyAutomationHostSignature(hostPath, authority) {
  return applyAutomationHostSignatureWith(hostPath, authority, false);
}

/**
 * Apply the signature from inside the already authenticated, typed broker
 * sandbox. The direct codesign process receives only the broker profile's
 * exact host, Keychain and SecurityServer/trustd capability.
 */
export async function applyAutomationHostSignatureInBroker(hostPath, authority) {
  // This deliberately remains fail-closed when macOS refuses the private
  // identity to a codesign child whose responsible process is sandboxed Node.
  return applyAutomationHostSignatureWith(hostPath, authority, true);
}

function inspectSignatureSlot(blob, slot, offset) {
  if (offset < 12 || offset + 8 > blob.length) {
    throw new Error('Apple Development signature slot is invalid');
  }
  const magic = blob.readUInt32BE(offset);
  const size = blob.readUInt32BE(offset + 4);
  if (size < 8 || offset + size > blob.length) {
    throw new Error('Apple Development signature slot is invalid');
  }
  const expectedMagic = slot === CSSLOT_CODEDIRECTORY
    ? CSMAGIC_CODEDIRECTORY
    : slot === CSSLOT_REQUIREMENTS
      ? CSMAGIC_REQUIREMENTS
      : CSMAGIC_BLOBWRAPPER;
  if (magic !== expectedMagic) throw new Error('Apple Development signature slot type is invalid');
  return Object.freeze({
    bytes: blob.subarray(offset, offset + size),
    offset,
    sha256: sha256(blob.subarray(offset, offset + size)),
    size,
    slot,
  });
}

export function inspectAppleDevelopmentSignatureBytes(bytes) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 32
    || bytes.readUInt32BE(0) !== MACHO_64_LE_BYTES
    || bytes.readUInt32LE(4) !== CPU_TYPE_ARM64) {
    throw new Error('Apple Development host is not a thin arm64 Mach-O');
  }
  const commands = bytes.readUInt32LE(16);
  const commandsBytes = bytes.readUInt32LE(20);
  if (commands < 1 || commands > 4_096 || commandsBytes > bytes.length - 32) {
    throw new Error('Apple Development host load commands are invalid');
  }
  let cursor = 32;
  let signature;
  for (let index = 0; index < commands; index += 1) {
    if (cursor + 8 > 32 + commandsBytes) throw new Error('Apple Development host load command is truncated');
    const command = bytes.readUInt32LE(cursor);
    const size = bytes.readUInt32LE(cursor + 4);
    if (size < 8 || cursor + size > 32 + commandsBytes) {
      throw new Error('Apple Development host load command is invalid');
    }
    if (command === LC_CODE_SIGNATURE) {
      if (signature || size !== 16) throw new Error('Apple Development host signature command is invalid');
      signature = Object.freeze({
        commandOffset: cursor,
        offset: bytes.readUInt32LE(cursor + 8),
        size: bytes.readUInt32LE(cursor + 12),
      });
    }
    cursor += size;
  }
  if (!signature
    || signature.offset < 32 + commandsBytes
    || signature.size < 64
    || signature.offset + signature.size !== bytes.length) {
    throw new Error('Apple Development host signature extent is invalid');
  }
  const container = bytes.subarray(signature.offset, signature.offset + signature.size);
  if (container.readUInt32BE(0) !== CSMAGIC_EMBEDDED_SIGNATURE) {
    throw new Error('Apple Development host signature container is invalid');
  }
  const containerSize = container.readUInt32BE(4);
  const slotCount = container.readUInt32BE(8);
  if (slotCount !== 3
    || containerSize < 12 + slotCount * 8
    || containerSize > container.length
    || container.subarray(containerSize).some((value) => value !== 0)) {
    throw new Error('Apple Development host signature container is invalid');
  }
  const expectedSlots = [CSSLOT_CODEDIRECTORY, CSSLOT_REQUIREMENTS, CSSLOT_SIGNATURESLOT];
  const slots = [];
  const seen = new Set();
  for (let index = 0; index < slotCount; index += 1) {
    const slot = container.readUInt32BE(12 + index * 8);
    const offset = container.readUInt32BE(16 + index * 8);
    if (slot !== expectedSlots[index] || seen.has(slot)) {
      throw new Error('Apple Development host signature slot inventory is invalid');
    }
    seen.add(slot);
    slots.push(inspectSignatureSlot(container.subarray(0, containerSize), slot, offset));
  }
  for (let index = 0; index < slots.length - 1; index += 1) {
    if (slots[index].offset + slots[index].size !== slots[index + 1].offset) {
      throw new Error('Apple Development host signature slots are not contiguous');
    }
  }
  if (slots[0].offset !== 12 + slotCount * 8
    || slots.at(-1).offset + slots.at(-1).size !== containerSize
    || slots[0].size < 16
    || slots[0].bytes.readUInt32BE(12) !== 0
    || slots[2].size <= 8) {
    throw new Error('Apple Development host signature policy is invalid');
  }
  const codeRegion = Buffer.from(bytes.subarray(0, signature.offset));
  codeRegion.writeUInt32LE(0, signature.commandOffset + 12);
  const nonCmsContract = Object.freeze({
    codeDirectoryFlags: slots[0].bytes.readUInt32BE(12),
    codeDirectorySha256: slots[0].sha256,
    codeRegionSha256: sha256(codeRegion),
    requirementsOffset: slots[1].offset,
    requirementsSha256: slots[1].sha256,
    signatureOffset: signature.offset,
    signatureSlots: Object.freeze(slots.map((entry) => Object.freeze({
      offset: entry.offset,
      slot: entry.slot,
    }))),
  });
  return Object.freeze({
    cdHash: slots[0].sha256.slice(0, 40),
    cmsBytes: slots[2].size,
    cmsSha256: slots[2].sha256,
    codeDirectoryFlags: slots[0].bytes.readUInt32BE(12),
    codeDirectorySha256: slots[0].sha256,
    executableBytes: bytes.length,
    executableSha256: sha256(bytes),
    nonCmsSignatureSha256: sha256(Buffer.from(
      canonicalArchitectureJson(nonCmsContract),
      'utf8',
    )),
    requirementsSha256: slots[1].sha256,
    signatureContainerBytes: signature.size,
    signatureSlots: Object.freeze(slots.map((entry) => Object.freeze({
      sha256: entry.sha256,
      size: entry.size,
      slot: entry.slot,
    }))),
  });
}

function lineValue(lines, prefix) {
  const matches = lines.filter((line) => line.startsWith(prefix));
  if (matches.length !== 1) throw new Error('Apple Development signing description is ambiguous');
  return matches[0].slice(prefix.length);
}

export function assertAutomationHostSigningEvidence(value) {
  const policy = automationSigningPolicy();
  if (!exactKeys(value, signingEvidenceKeys)
    || value.schemaVersion !== 1
    || value.bundleIdentifier !== policy.bundleIdentifier
    || value.certificateSha1 !== policy.certificateSha1
    || value.certificateSha256 !== policy.certificateSha256
    || value.designatedRequirement !== policy.designatedRequirement
    || value.teamIdentifier !== policy.teamIdentifier
    || value.signature !== 'apple-development'
    || value.entitlements !== 'none'
    || value.codeDirectoryFlags !== 0
    || !CDHASH.test(value.cdHash ?? '')
    || !SHA256.test(value.cmsSha256 ?? '')
    || !Number.isSafeInteger(value.cmsBytes)
    || value.cmsBytes <= 8
    || !SHA256.test(value.codeDirectorySha256 ?? '')
    || value.cdHash !== value.codeDirectorySha256.slice(0, 40)
    || !Number.isSafeInteger(value.executableBytes)
    || value.executableBytes < 1
    || !SHA256.test(value.executableSha256 ?? '')
    || !SHA256.test(value.nonCmsSignatureSha256 ?? '')
    || !SHA256.test(value.requirementsSha256 ?? '')
    || !SHA1.test(value.certificateSha1)
    || !Number.isSafeInteger(value.signatureContainerBytes)
    || value.signatureContainerBytes < value.cmsBytes
    || value.signatureContainerBytes > value.executableBytes
    || !TEAM_ID.test(value.teamIdentifier)
    || !Array.isArray(value.signatureSlots)
    || value.signatureSlots.length !== 3
    || value.signatureSlots.some((entry, index) => {
      const expectedSlots = [CSSLOT_CODEDIRECTORY, CSSLOT_REQUIREMENTS, CSSLOT_SIGNATURESLOT];
      return !exactKeys(entry, ['sha256', 'size', 'slot'])
        || entry.slot !== expectedSlots[index]
        || !SHA256.test(entry.sha256)
        || !Number.isSafeInteger(entry.size)
        || entry.size < 8;
    })
    || value.signatureSlots[0].sha256 !== value.codeDirectorySha256
    || value.signatureSlots[1].sha256 !== value.requirementsSha256
    || value.signatureSlots[1].size !== policy.requirementsBytes
    || value.signatureSlots[2].sha256 !== value.cmsSha256
    || value.signatureSlots[2].size !== value.cmsBytes
    || value.signatureContainerBytes
      < 36 + value.signatureSlots.reduce((total, slot) => total + slot.size, 0)) {
    throw new Error('Apple Development host signing evidence is invalid');
  }
  return Object.freeze({ ...value });
}

function sameDirectoryAnchor(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid;
}

function assertSafeVerificationParentState(state) {
  if (!state.isDirectory()
    || state.isSymbolicLink()
    || state.nlink < 2n
    || (state.mode & 0o022n) !== 0n
    || (typeof process.getuid === 'function' && state.uid !== BigInt(process.getuid()))) {
    throw new Error('Code-signature verification parent is unsafe');
  }
}

function assertPrivateVerificationDirectoryState(state) {
  if (!state.isDirectory()
    || state.isSymbolicLink()
    || state.nlink < 2n
    || (state.mode & 0o7777n) !== 0o700n
    || (typeof process.getuid === 'function' && state.uid !== BigInt(process.getuid()))) {
    throw new Error(
      `Private code-signature verification directory is invalid (mode=${(state.mode & 0o7777n).toString(8)}, nlink=${state.nlink.toString()}, uid=${state.uid.toString()})`,
    );
  }
}

function assertVerificationFileState(state, expectedMode) {
  if (!state.isFile()
    || state.isSymbolicLink()
    || state.nlink !== 1n
    || state.size < 32n
    || state.size > BigInt(MAX_VERIFICATION_BYTES)
    || (state.mode & 0o7777n) !== BigInt(expectedMode)
    || (typeof process.getuid === 'function' && state.uid !== BigInt(process.getuid()))) {
    throw new Error('Private code-signature verification file is invalid');
  }
}

async function readHeldVerificationBytes(handle, size) {
  if (typeof size !== 'bigint' || size < 1n || size > BigInt(MAX_VERIFICATION_BYTES)) {
    throw new Error('Code-signature verification byte length is invalid');
  }
  const byteLength = Number(size);
  const bytes = Buffer.alloc(byteLength);
  let offset = 0;
  while (offset < byteLength) {
    const { bytesRead } = await handle.read(
      bytes,
      offset,
      Math.min(64 * 1024, byteLength - offset),
      offset,
    );
    if (bytesRead < 1) throw new Error('Held code-signature verification file was truncated');
    offset += bytesRead;
  }
  return bytes;
}

async function assertHeldVerificationPath({
  expected,
  expectedMode,
  expectedSha256,
  handle,
  path,
}) {
  const descriptor = await handle.stat({ bigint: true });
  const pathname = await lstat(path, { bigint: true });
  assertVerificationFileState(descriptor, expectedMode);
  assertVerificationFileState(pathname, expectedMode);
  if (!sameFileState(expected, descriptor)
    || !sameFileState(descriptor, pathname)
    || await realpath(path) !== path) {
    throw new Error('Code-signature verification file path identity changed');
  }
  const bytes = await readHeldVerificationBytes(handle, descriptor.size);
  const digest = sha256(bytes);
  bytes.fill(0);
  if (digest !== expectedSha256) {
    throw new Error('Code-signature verification file bytes changed');
  }
  return digest;
}

async function openCanonicalVerificationParent(requestedPath) {
  const supplied = requestedPath ?? tmpdir();
  if (typeof supplied !== 'string'
    || !supplied.startsWith('/')
    || resolve(supplied) !== supplied
    || /[\0\r\n]/u.test(supplied)) {
    throw new Error('Code-signature verification parent path is invalid');
  }
  const path = await realpath(supplied);
  if (requestedPath !== undefined && path !== supplied) {
    throw new Error('Code-signature verification parent is not canonical');
  }
  let handle;
  try {
    handle = await open(
      path,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    const descriptor = await handle.stat({ bigint: true });
    const pathname = await lstat(path, { bigint: true });
    assertSafeVerificationParentState(descriptor);
    assertSafeVerificationParentState(pathname);
    if (!sameFileState(descriptor, pathname) || await realpath(path) !== path) {
      throw new Error('Code-signature verification parent identity is invalid');
    }
    return Object.freeze({
      expected: descriptor,
      handle,
      path,
    });
  } catch (error) {
    await handle?.close();
    throw error;
  }
}

async function assertVerificationParentUnchanged(parent) {
  const descriptor = await parent.handle.stat({ bigint: true });
  const pathname = await lstat(parent.path, { bigint: true });
  assertSafeVerificationParentState(descriptor);
  assertSafeVerificationParentState(pathname);
  if (!sameFileState(parent.expected, descriptor)
    || !sameFileState(descriptor, pathname)
    || await realpath(parent.path) !== parent.path) {
    throw new Error('Code-signature verification parent identity changed');
  }
}

function codeSignatureVerificationOptions(options) {
  if (options === undefined) return Object.freeze({});
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new Error('Code-signature verification options are invalid');
  }
  const keys = Object.keys(options);
  const symbols = Object.getOwnPropertySymbols(options);
  if (keys.some((key) => key !== 'verificationParent')
    || symbols.some((symbol) => symbol !== CODE_SIGNATURE_VERIFICATION_TEST_HOOK)
    || symbols.length > 1
    || (Object.hasOwn(options, 'verificationParent')
      && typeof options.verificationParent !== 'string')
    || (Object.hasOwn(options, CODE_SIGNATURE_VERIFICATION_TEST_HOOK)
      && typeof options[CODE_SIGNATURE_VERIFICATION_TEST_HOOK] !== 'function')) {
    throw new Error('Code-signature verification options are invalid');
  }
  return Object.freeze({
    testHook: options[CODE_SIGNATURE_VERIFICATION_TEST_HOOK],
    verificationParent: options.verificationParent,
  });
}

async function invokeVerificationTestHook(testHook, call, phase, clonePath) {
  if (testHook) {
    await testHook(Object.freeze({
      call,
      clonePath,
      phase,
      verificationDirectory: dirname(clonePath),
    }));
  }
}

async function createHeldVerificationFile(path, bytes, mode) {
  let handle;
  try {
    handle = await open(
      path,
      constants.O_CREAT
        | constants.O_EXCL
        | constants.O_RDWR
        | constants.O_NOFOLLOW
        | (constants.O_CLOEXEC ?? 0),
      mode,
    );
    await handle.writeFile(bytes);
    await handle.sync();
    const expected = await handle.stat({ bigint: true });
    const pathname = await lstat(path, { bigint: true });
    assertVerificationFileState(expected, mode);
    assertVerificationFileState(pathname, mode);
    if (!sameFileState(expected, pathname)
      || expected.size !== BigInt(bytes.length)
      || await realpath(path) !== path) {
      throw new Error('Private code-signature verification file creation failed');
    }
    return Object.freeze({ expected, handle, path });
  } catch (error) {
    await handle?.close();
    throw error;
  }
}

async function assertCleanupOwnership(lease) {
  await assertVerificationParentUnchanged(lease.parent);
  const directoryDescriptor = await lease.directoryHandle.stat({ bigint: true });
  const directoryPathname = await lstat(lease.directoryPath, { bigint: true });
  if (!directoryDescriptor.isDirectory()
    || directoryDescriptor.isSymbolicLink()
    || (directoryDescriptor.mode & 0o7777n) !== 0o700n
    || !sameDirectoryAnchor(lease.directoryExpected, directoryDescriptor)
    || !sameDirectoryAnchor(directoryDescriptor, directoryPathname)
    || await realpath(lease.directoryPath) !== lease.directoryPath) {
    throw new Error('Private code-signature verification cleanup ownership is invalid');
  }
  for (const item of lease.ownedFiles) {
    const descriptor = await item.handle.stat({ bigint: true });
    const pathname = await lstat(item.path, { bigint: true });
    if (descriptor.dev !== item.expected.dev
      || descriptor.ino !== item.expected.ino
      || pathname.dev !== descriptor.dev
      || pathname.ino !== descriptor.ino
      || pathname.isSymbolicLink()
      || await realpath(item.path) !== item.path) {
      throw new Error('Private code-signature verification cleanup file ownership is invalid');
    }
  }
  const entries = (await readdir(lease.directoryPath)).sort();
  const expectedEntries = lease.ownedFiles
    .map((item) => item.path.slice(lease.directoryPath.length + 1))
    .sort();
  if (canonicalArchitectureJson(entries) !== canonicalArchitectureJson(expectedEntries)) {
    throw new Error('Private code-signature verification cleanup inventory is invalid');
  }
}

async function cleanupPrivateVerificationLease(lease) {
  await assertCleanupOwnership(lease);
  for (const item of lease.ownedFiles) await unlink(item.path);
  await rmdir(lease.directoryPath);
}

async function runCodesignCloneLease({
  bytes,
  describe,
  label,
  options,
  requirement,
  source,
}) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 32
    || bytes.length > MAX_VERIFICATION_BYTES
    || typeof label !== 'string'
    || !VERIFICATION_LABEL.test(label)
    || typeof describe !== 'boolean'
    || (requirement !== undefined
      && (typeof requirement !== 'string' || /[\0\r\n]/u.test(requirement)))) {
    throw new Error('Code-signature verification lease input is invalid');
  }
  const parsedOptions = codeSignatureVerificationOptions(options);
  const ownedParentPath = parsedOptions.verificationParent === undefined
    ? await mkdtemp(resolve(
      await realpath(tmpdir()),
      `piui-codesign-parent-${randomBytes(16).toString('hex')}.`,
    ))
    : undefined;
  const parent = await openCanonicalVerificationParent(
    ownedParentPath ?? parsedOptions.verificationParent,
  );
  let verifiedParent = parent;
  let directoryHandle;
  let directoryPath;
  let sourceLease;
  let cloneLease;
  let sourceOwned = false;
  let primaryError;
  let recoveryError;
  let parentCleanupError;
  let verificationLeaseCleaned = false;
  let result;
  try {
    directoryPath = await mkdtemp(resolve(
      parent.path,
      `piui-codesign-${label}-${randomBytes(16).toString('hex')}.`,
    ));
    if (dirname(directoryPath) !== parent.path || await realpath(directoryPath) !== directoryPath) {
      throw new Error('Private code-signature verification directory escaped its parent');
    }
    directoryHandle = await open(
      directoryPath,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    const createdDirectory = await directoryHandle.stat({ bigint: true });
    const createdDirectoryPath = await lstat(directoryPath, { bigint: true });
    assertPrivateVerificationDirectoryState(createdDirectory);
    assertPrivateVerificationDirectoryState(createdDirectoryPath);
    if (!sameFileState(createdDirectory, createdDirectoryPath)) {
      throw new Error('Private code-signature verification directory identity is invalid');
    }
    const parentExpected = await parent.handle.stat({ bigint: true });
    const parentPathExpected = await lstat(parent.path, { bigint: true });
    assertSafeVerificationParentState(parentExpected);
    assertSafeVerificationParentState(parentPathExpected);
    if (!sameDirectoryAnchor(parent.expected, parentExpected)
      || !sameFileState(parentExpected, parentPathExpected)
      || await realpath(parent.path) !== parent.path) {
      throw new Error('Code-signature verification parent changed during private directory creation');
    }
    verifiedParent = Object.freeze({
      expected: parentExpected,
      handle: parent.handle,
      path: parent.path,
    });

    if (source) {
      sourceLease = source;
      const sourceState = await source.handle.stat({ bigint: true });
      const sourcePathState = await lstat(source.path, { bigint: true });
      if (!sourceState.isFile()
        || sourceState.isSymbolicLink()
        || sourceState.nlink !== 1n
        || sourceState.size !== BigInt(bytes.length)
        || sourcePathState.isSymbolicLink()
        || !sameFileState(source.expected, sourceState)
        || !sameFileState(sourceState, sourcePathState)
        || await realpath(source.path) !== source.path) {
        throw new Error('Held code-signature source identity is invalid');
      }
      sourceLease = Object.freeze({
        expected: sourceState,
        expectedMode: Number(sourceState.mode & 0o7777n),
        handle: source.handle,
        path: source.path,
      });
    } else {
      sourceLease = await createHeldVerificationFile(
        resolve(directoryPath, 'source'),
        bytes,
        0o500,
      );
      sourceLease = Object.freeze({ ...sourceLease, expectedMode: 0o500 });
      sourceOwned = true;
    }
    const sourceBytes = await readHeldVerificationBytes(
      sourceLease.handle,
      sourceLease.expected.size,
    );
    const sourceSha256 = sha256(sourceBytes);
    if (sourceSha256 !== sha256(bytes)) {
      sourceBytes.fill(0);
      throw new Error('Held code-signature source does not match supplied bytes');
    }
    cloneLease = await createHeldVerificationFile(
      resolve(directoryPath, 'verification-host'),
      sourceBytes,
      0o500,
    );
    sourceBytes.fill(0);
    cloneLease = Object.freeze({ ...cloneLease, expectedMode: 0o500 });
    const directoryExpected = await directoryHandle.stat({ bigint: true });
    const directoryPathExpected = await lstat(directoryPath, { bigint: true });
    assertPrivateVerificationDirectoryState(directoryExpected);
    if (!sameFileState(directoryExpected, directoryPathExpected)) {
      throw new Error('Private code-signature verification directory changed during creation');
    }
    const lease = Object.freeze({
      clone: cloneLease,
      directoryExpected,
      directoryHandle,
      directoryPath,
      ownedFiles: Object.freeze([
        ...(sourceOwned ? [sourceLease] : []),
        cloneLease,
      ]),
      parent: verifiedParent,
      source: sourceLease,
      sourceSha256,
    });
    const assertLease = async () => {
      await assertVerificationParentUnchanged(verifiedParent);
      const currentDirectory = await directoryHandle.stat({ bigint: true });
      const currentDirectoryPath = await lstat(directoryPath, { bigint: true });
      assertPrivateVerificationDirectoryState(currentDirectory);
      assertPrivateVerificationDirectoryState(currentDirectoryPath);
      if (!sameFileState(directoryExpected, currentDirectory)
        || !sameFileState(currentDirectory, currentDirectoryPath)
        || await realpath(directoryPath) !== directoryPath) {
        throw new Error('Private code-signature verification directory changed');
      }
      const sourceDigest = await assertHeldVerificationPath({
        ...sourceLease,
        expectedSha256: sourceSha256,
      });
      const cloneDigest = await assertHeldVerificationPath({
        ...cloneLease,
        expectedSha256: sourceSha256,
      });
      if (sourceDigest !== cloneDigest || cloneDigest !== sha256(bytes)) {
        throw new Error('Code-signature source and verification clone differ');
      }
    };
    const runCall = async (call, argumentsList) => {
      await assertLease();
      if (parsedOptions.testHook) {
        await invokeVerificationTestHook(
          parsedOptions.testHook,
          call,
          'after-lease-before-command',
          cloneLease.path,
        );
      }
      const commandResult = spawnSync('/usr/bin/codesign', argumentsList, {
        cwd: '/',
        encoding: 'utf8',
        env: {
          LANG: 'en_AU.UTF-8',
          LC_ALL: 'en_AU.UTF-8',
          PATH: '/usr/bin:/bin',
        },
        maxBuffer: 256 * 1024,
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 30_000,
      });
      if (parsedOptions.testHook) {
        await invokeVerificationTestHook(
          parsedOptions.testHook,
          call,
          'after-command-before-lease',
          cloneLease.path,
        );
      }
      await assertLease();
      return commandResult;
    };
    const verifyArguments = [
      '--verify',
      '--strict',
      describe ? '--verbose=4' : '--verbose=2',
      ...(requirement === undefined ? [] : ['--test-requirement', requirement]),
      cloneLease.path,
    ];
    const verified = await runCall('verify', verifyArguments);
    const described = describe
      ? await runCall('describe', ['-d', '--verbose=4', '-r-', cloneLease.path])
      : undefined;
    result = Object.freeze({
      clonePath: cloneLease.path,
      cloneSha256: sourceSha256,
      described,
      sourceSha256,
      verified,
    });
    await cleanupPrivateVerificationLease(lease);
    verificationLeaseCleaned = true;
  } catch (error) {
    primaryError = error;
    if (directoryHandle && directoryPath && cloneLease) {
      try {
        await cleanupPrivateVerificationLease(Object.freeze({
          clone: cloneLease,
          directoryExpected: await directoryHandle.stat({ bigint: true }),
          directoryHandle,
          directoryPath,
          ownedFiles: Object.freeze([
            ...(sourceOwned && sourceLease ? [sourceLease] : []),
            cloneLease,
          ]),
          parent: verifiedParent,
          source: sourceLease,
        }));
        verificationLeaseCleaned = true;
      } catch (cleanupError) {
        recoveryError = cleanupError;
      }
    }
  } finally {
    await cloneLease?.handle.close();
    if (sourceOwned) await sourceLease?.handle.close();
    await directoryHandle?.close();
    await parent.handle.close();
    if (ownedParentPath && verificationLeaseCleaned) {
      try {
        await rmdir(ownedParentPath);
      } catch (error) {
        parentCleanupError = error;
      }
    }
  }
  if (parentCleanupError) {
    if (primaryError) {
      throw new AggregateError(
        [primaryError, parentCleanupError],
        `Code-signature verification and private-parent cleanup failed: ${primaryError.message}`,
      );
    }
    throw parentCleanupError;
  }
  if (primaryError && recoveryError) {
    throw new AggregateError(
      [primaryError, recoveryError],
      `Code-signature verification failed and its unverified isolate was retained: ${primaryError.message}`,
    );
  }
  if (primaryError) throw primaryError;
  return result;
}

export async function verifyCodeSignatureBytesWithLease(
  bytes,
  verificationParent,
  label,
  options,
) {
  return runCodesignCloneLease({
    bytes,
    describe: false,
    label,
    options: {
      ...options,
      verificationParent,
    },
    requirement: undefined,
    source: undefined,
  });
}

export async function inspectAppleDevelopmentHost(path, options) {
  if (typeof path !== 'string' || resolve(path) !== path || /[\0\r\n]/u.test(path)) {
    throw new Error('Apple Development host path is invalid');
  }
  const policy = automationSigningPolicy();
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    const pathBefore = await lstat(path, { bigint: true });
    if (!before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1n
      || pathBefore.isSymbolicLink()
      || !sameFileState(before, pathBefore)) {
      throw new Error('Apple Development host identity is invalid');
    }
    const bytes = await handle.readFile();
    const signature = inspectAppleDevelopmentSignatureBytes(bytes);
    const requirement = `=anchor apple generic and identifier "${policy.bundleIdentifier}" and certificate leaf[subject.OU] = "${policy.teamIdentifier}"`;
    const leased = await runCodesignCloneLease({
      bytes,
      describe: true,
      label: 'apple-development-host',
      options,
      requirement,
      source: Object.freeze({
        expected: before,
        handle,
        path,
      }),
    });
    const { described, verified } = leased;
    const expectedVerification = [
      `${leased.clonePath}: valid on disk`,
      `${leased.clonePath}: satisfies its Designated Requirement`,
      `${leased.clonePath}: explicit requirement satisfied`,
      '',
    ].join('\n');
    if (verified.status !== 0
      || verified.signal !== null
      || verified.error
      || verified.stdout !== ''
      || verified.stderr !== expectedVerification) {
      throw new Error('Apple Development host failed strict positive-requirement verification');
    }
    const lines = described.stderr.trimEnd().split('\n');
    const authorities = lines
      .filter((line) => line.startsWith('Authority='))
      .map((line) => line.slice('Authority='.length));
    if (described.status !== 0
      || described.signal !== null
      || described.error
      || described.stdout !== `designated => ${policy.designatedRequirement}\n`
      || lineValue(lines, 'Executable=') !== leased.clonePath
      || lineValue(lines, 'Identifier=') !== policy.bundleIdentifier
      || lineValue(lines, 'TeamIdentifier=') !== policy.teamIdentifier
      || lineValue(lines, 'CDHash=') !== signature.cdHash
      || lineValue(lines, 'CandidateCDHash sha256=') !== signature.cdHash
      || lineValue(lines, 'CandidateCDHashFull sha256=') !== signature.codeDirectorySha256
      || lineValue(lines, 'CMSDigest=') !== signature.codeDirectorySha256
      || lineValue(lines, 'Hash type=') !== 'sha256 size=32'
      || lineValue(lines, 'Info.plist=') !== 'not bound'
      || lineValue(lines, 'Sealed Resources=') !== 'none'
      || canonicalArchitectureJson(authorities) !== canonicalArchitectureJson([
        policy.certificateCommonName,
        'Apple Worldwide Developer Relations Certification Authority',
        'Apple Root CA',
      ])
      || lines.some((line) => line === 'Signature=adhoc')
      || leased.sourceSha256 !== signature.executableSha256
      || leased.cloneSha256 !== signature.executableSha256) {
      throw new Error('Apple Development host signing description is invalid');
    }
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (bytes.length !== Number(before.size)
      || !sameFileState(before, after)
      || pathAfter.isSymbolicLink()
      || !sameFileState(after, pathAfter)) {
      throw new Error('Apple Development host changed during signing inspection');
    }
    return assertAutomationHostSigningEvidence({
      bundleIdentifier: policy.bundleIdentifier,
      cdHash: signature.cdHash,
      certificateSha1: policy.certificateSha1,
      certificateSha256: policy.certificateSha256,
      cmsBytes: signature.cmsBytes,
      cmsSha256: signature.cmsSha256,
      codeDirectoryFlags: signature.codeDirectoryFlags,
      codeDirectorySha256: signature.codeDirectorySha256,
      designatedRequirement: policy.designatedRequirement,
      entitlements: 'none',
      executableBytes: signature.executableBytes,
      executableSha256: signature.executableSha256,
      nonCmsSignatureSha256: signature.nonCmsSignatureSha256,
      requirementsSha256: signature.requirementsSha256,
      schemaVersion: 1,
      signature: 'apple-development',
      signatureContainerBytes: signature.signatureContainerBytes,
      signatureSlots: signature.signatureSlots,
      teamIdentifier: policy.teamIdentifier,
    });
  } finally {
    await handle?.close();
  }
}
