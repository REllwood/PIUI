import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  writeFileSync,
} from 'node:fs';
import {
  chmod,
  lstat,
  open,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  unlink,
} from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, posix, relative, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { createGunzip } from 'node:zlib';
import { canonicalArchitectureJson } from './architecture-gate-schema.mjs';

const MiB = 1_048_576;
const SHA256 = /^[0-9a-f]{64}$/u;
const SHA512 = /^[0-9a-f]{128}$/u;
const BASE64_SHA512 = /^[A-Za-z0-9+/]{86}==$/u;
const REGISTRY_SOURCE = 'registry+https://github.com/rust-lang/crates.io-index';
const CACHE_NAME = 'architecture-toolchain-v1';
const duplicateExceptionMetadata = Object.freeze({
  canonicalName: 'package/dist/index.js',
  firstName: 'package/./dist/index.js',
  gid: 0,
  mode: 0o644,
  mtime: 499_162_500,
  secondName: 'package/dist/index.js',
  uid: 0,
});

export const pinnedNpmDuplicateExceptions = Object.freeze([
  Object.freeze({ archiveSha512: '32703e613f1fc1f24f801c779bad0c36a6a49b7d173a4c88a07d72ea1b9342f0b43f0646ee48bc35a70b05cacf6cda28f2f119cbb269ba4efe8cc3be094a2f4d', package: 'agent-base', payloadSha256: 'c6503bd5e007db8b73fedf07b6eaaf4a94d5541953f0d06c8a17d1644c29a0c5', size: 7_324, version: '7.1.4', ...duplicateExceptionMetadata }),
  Object.freeze({ archiveSha512: '4f58240226180d6631dd5e419b2bbb1dc7dcbcbee652b4d688ceb239f6b73c8a6156227f8053dbbe2750faf7aa48e1dc8bf3f105c0da6de50d0b3a4e3832598a', package: 'http-proxy-agent', payloadSha256: 'fd33b43da34da60d4914780e13fae5d52a7faaa996d687eea5335128de148627', size: 6_088, version: '7.0.2', ...duplicateExceptionMetadata }),
  Object.freeze({ archiveSha512: 'bcaf4fe7f8947dd97de4023e255c94b88715b5de287efb6b3abdc736d336cb10bd6e731b11da77c74d4e8503678dbf082588b7f159531379815f071fbf2c2e4b', package: 'https-proxy-agent', payloadSha256: '30165586fac3becbc9dbf2b7b5bdaa802a77ac34af9926208f6e94a3bd87ef31', size: 7_451, version: '7.0.6', ...duplicateExceptionMetadata }),
]);

const pinnedNpmDuplicateExceptionBySha512 = new Map(
  pinnedNpmDuplicateExceptions.map((entry) => [entry.archiveSha512, entry]),
);
export const pinnedNpmDuplicateExceptionsSha256 = createHash('sha256')
  .update(canonicalArchitectureJson(pinnedNpmDuplicateExceptions))
  .digest('hex');

export const pinnedNpmLegacyPaxExceptions = Object.freeze([
  Object.freeze({
    archiveEntries: 14,
    archiveSha512: 'cd1a54883c1dff193a003a8f3004c6f2f73d54fae4724ed3d3b388c748278e62409c79d35573501b7bdfbd636e899224c2ef4aaca740d6224a7ec7d357113a34',
    base256UidGidFields: 28,
    package: 'buffer-equal-constant-time',
    paxRecords: 7,
    records: Object.freeze([
      Object.freeze({ gid: 538645042, headerSha256: '554d69d85b8913a7d7808ebdf261332a27a1d322e5159826d807d520cb9c47ae', index: 0, mode: 420, mtime: 1387224657, payloadSha256: '29be01ed945d58d1c2baf9d42956d7eb8cab3ebb9389ae2c30a8705d6f7c8d37', rawName: 'PaxHeader/package/package.json', size: 984, type: 'x', uid: 2805947 }),
      Object.freeze({ gid: 1774130, headerSha256: 'aca9aea360edc3a494119b6302eb112cae633bd03cf3dda043055dc7b103e382', index: 1, mode: 420, mtime: 1387224657, payloadSha256: '2d3df7ecb57811cf6fc43be180d9801c7c70928e5388391a6f258d889449ef4e', rawName: 'package/package.json', size: 484, type: '0', uid: 2805947 }),
      Object.freeze({ gid: 3491435058, headerSha256: '59ca38612a020556d77af50c54d6579b74b1780a6e551de6c6de05e3ce48cc6a', index: 2, mode: 420, mtime: 1387221480, payloadSha256: 'e67ef544b7b3bb63ae9fc5d16b9ae0c5eb1e0101a0466d63e7b3bcf7c191c0ee', rawName: 'PaxHeader/package/.npmignore', size: 981, type: 'x', uid: 640340155 }),
      Object.freeze({ gid: 2686128690, headerSha256: 'b6aa959e7e0d6de5430abf91afc8468dd94b1e79b6d4d7685636efd73a3d6208', index: 3, mode: 420, mtime: 1387221480, payloadSha256: 'd8f7bf914b1a1e848cd262d967606cc37700f2a4270adcbb89515ed00d0caf22', rawName: 'package/.npmignore', size: 26, type: '0', uid: 1210765499 }),
      Object.freeze({ gid: 1774130, headerSha256: '1a98fe2f487cf0d6bebdc6d0c7605f80c308dc1fe97a312b25105bd73e0f3fa8', index: 4, mode: 420, mtime: 1387223231, payloadSha256: '441a71d89bba12e2ff81e6c2c99700b276309d1041fe239d677cf85f346dc3d9', rawName: 'PaxHeader/package/README.md', size: 982, type: 'x', uid: 2805947 }),
      Object.freeze({ gid: 1774130, headerSha256: '6ab12e357d6b1c50d16e705ea54fad8fa0af5282d486c6a94f0583470a09450b', index: 5, mode: 420, mtime: 1387223231, payloadSha256: 'b4183b472a9f25b0b14a5d6e7e2eb4cc92e7bb944262a98e4775ecf06d8eacf3', rawName: 'package/README.md', size: 1101, type: '0', uid: 2805947 }),
      Object.freeze({ gid: 68882994, headerSha256: 'c61cf1570cb5a1301b7f0d25e70e76b980639434751223421173e4a1ebddbf2a', index: 6, mode: 420, mtime: 1387222233, payloadSha256: '9c145d4774a7562fbaef8b1939e3a2cdb10d97eed6235cb5cad63bef81c7562f', rawName: 'PaxHeader/package/index.js', size: 981, type: 'x', uid: 3492466875 }),
      Object.freeze({ gid: 807080498, headerSha256: 'c445e271f727cc0cd27a3d16205ad1315475b8b0189c2e8f62f1dd191e92f3e7', index: 7, mode: 420, mtime: 1387222233, payloadSha256: '873c585bc4b4373d4e9d8d39bd475f9a0816fb7c8fce0f20335f6897090eb068', rawName: 'package/index.js', size: 1045, type: '0', uid: 2805947 }),
      Object.freeze({ gid: 404427314, headerSha256: '74f5e9591412b4991f72727399920df9d06f880fbf534721c34c49b1a9bd3748', index: 8, mode: 420, mtime: 1387222724, payloadSha256: 'aec5a2f386493dc60575f32bb02eb6ee296e49b3e7563bf1d6fc369518b1fe6f', rawName: 'PaxHeader/package/test.js', size: 980, type: 'x', uid: 2805947 }),
      Object.freeze({ gid: 1774130, headerSha256: '1a412c0141b1111180e95f986aecbf80e61ba744dbb3293a295ee013cd7cef26', index: 9, mode: 420, mtime: 1387222724, payloadSha256: '9563fa194940e1ada764b9b5c0bd652baaec734b3aec6151a1bbe6f999f8bbde', rawName: 'package/test.js', size: 1013, type: '0', uid: 2805947 }),
      Object.freeze({ gid: 2954564146, headerSha256: 'd10c199ae40790290bad93a9e5295491acd1fa91639c2904d2e72518c1ea9cf8', index: 10, mode: 420, mtime: 1387222994, payloadSha256: 'efa87df787cb11f41acb7f917f082b91eae98ea8bf471fbf3837305f26dbdaa1', rawName: 'PaxHeader/package/.travis.yml', size: 982, type: 'x', uid: 1881854139 }),
      Object.freeze({ gid: 1774130, headerSha256: 'd04005b1bd196180f9c54f282e4bbb76a03638bce1daa27f6dd46f9541681bd1', index: 11, mode: 420, mtime: 1387222994, payloadSha256: '36fbdbd408acb19600eda6897a0fa33daed9014a679d166d58203d8083b66f94', rawName: 'package/.travis.yml', size: 45, type: '0', uid: 891998395 }),
      Object.freeze({ gid: 1461391922, headerSha256: '67f0297544561d9a5ebbfd96c5ea1f14383714829c97ef5ad34d0b4adbabfa39', index: 12, mode: 420, mtime: 1387221487, payloadSha256: '440f07b02ad597cf2f7484ec663e107b5993fd2075430ae00de560b290966cb1', rawName: 'PaxHeader/package/LICENSE.txt', size: 984, type: 'x', uid: 1881854139 }),
      Object.freeze({ gid: 1343951410, headerSha256: '72992e4d26f9586e5e0b5acde9e8f29eb4799f80d89b1edfe5e9681127080adc', index: 13, mode: 420, mtime: 1387221487, payloadSha256: '751d0e80fb5c828f8c3de198cc760e1e05377e47c8263ab6ee2f10cdc19ba658', rawName: 'package/LICENSE.txt', size: 1518, type: '0', uid: 2150289595 }),
    ]),
    version: '1.0.1',
  }),
]);
const pinnedNpmLegacyPaxExceptionBySha512 = new Map(
  pinnedNpmLegacyPaxExceptions.map((entry) => [entry.archiveSha512, entry]),
);
export const pinnedNpmLegacyPaxExceptionsSha256 = createHash('sha256')
  .update(canonicalArchitectureJson(pinnedNpmLegacyPaxExceptions))
  .digest('hex');

export const architectureToolchainPins = Object.freeze({
  node: Object.freeze({
    algorithm: 'sha256',
    digest: 'ef28d8fab2c0e4314522d4bb1b7173270aa3937e93b92cb7de79c112ac1fa953',
    executableSha256: '2e3f1286a7eb3736346ed1803e458a0ff909e2b2d5bc746144dcb76970e9b99d',
    filename: 'node-v22.23.1-darwin-arm64.tar.gz',
    kind: 'node',
    maxBytes: 50_067_502,
    member: 'node-v22.23.1-darwin-arm64/bin/node',
    minBytes: 50_067_502,
    url: 'https://nodejs.org/dist/v22.23.1/node-v22.23.1-darwin-arm64.tar.gz',
    version: '22.23.1',
  }),
  pnpm: Object.freeze({
    algorithm: 'sha512',
    digest: '76e2379760a4328ec4415815bcd6628dee727af3779aaa4c914e3944156c4299921a89f976381ee107d41f12cfa4b66681ca9c718f0668fa0831ed4c6d8ba56c',
    filename: 'pnpm-9.15.0.tgz',
    kind: 'pnpm',
    maxBytes: 32 * MiB,
    minBytes: 1 * MiB,
    url: 'https://registry.npmjs.org/pnpm/-/pnpm-9.15.0.tgz',
    version: '9.15.0',
  }),
  rust: Object.freeze([
    Object.freeze({
      algorithm: 'sha256',
      component: 'cargo',
      digest: '178581665d8b3af41f3fe21cb8a48aa7eb65ab4c567f53f3661a3a6c9b182f2e',
      filename: 'cargo-1.96.0-aarch64-apple-darwin.tar.gz',
      kind: 'rust',
      maxBytes: 12_958_161,
      minBytes: 12_958_161,
      url: 'https://static.rust-lang.org/dist/2026-05-28/cargo-1.96.0-aarch64-apple-darwin.tar.gz',
    }),
    Object.freeze({
      algorithm: 'sha256',
      component: 'rust-std-aarch64-apple-darwin',
      digest: 'a5c160197236f68cc8627a573545fd883d4d98856fb654a6d6aa5883ff1bdcc7',
      filename: 'rust-std-1.96.0-aarch64-apple-darwin.tar.gz',
      kind: 'rust',
      maxBytes: 43_094_135,
      minBytes: 43_094_135,
      url: 'https://static.rust-lang.org/dist/2026-05-28/rust-std-1.96.0-aarch64-apple-darwin.tar.gz',
    }),
    Object.freeze({
      algorithm: 'sha256',
      component: 'rustc',
      digest: 'c1a23d0ac24da25eca730d87d74d7f6f771d48167fc93e45d79f0e12f486c8d9',
      filename: 'rustc-1.96.0-aarch64-apple-darwin.tar.gz',
      kind: 'rust',
      maxBytes: 116_049_567,
      minBytes: 116_049_567,
      url: 'https://static.rust-lang.org/dist/2026-05-28/rustc-1.96.0-aarch64-apple-darwin.tar.gz',
    }),
  ]),
  rustChannel: Object.freeze({
    algorithm: 'sha256',
    date: '2026-05-28',
    digest: '9af50610e1d82699f78a40b985c9277ae1a2c5a0bec86ae430cfe58832038285',
    filename: 'channel-rust-1.96.0.toml',
    kind: 'rust-channel',
    maxBytes: 857_570,
    manifestSha256: '9af50610e1d82699f78a40b985c9277ae1a2c5a0bec86ae430cfe58832038285',
    minBytes: 857_570,
    target: 'aarch64-apple-darwin',
    url: 'https://static.rust-lang.org/dist/channel-rust-1.96.0.toml',
    version: '1.96.0',
  }),
});

export const architectureToolchainPinsSha256 = createHash('sha256')
  .update(canonicalArchitectureJson({
    archives: architectureToolchainPins,
    npmDuplicateExceptionsSha256: pinnedNpmDuplicateExceptionsSha256,
    npmLegacyPaxExceptionsSha256: pinnedNpmLegacyPaxExceptionsSha256,
  }))
  .digest('hex');

function digestBytes(bytes, algorithm) {
  return createHash(algorithm).update(bytes).digest('hex');
}

function expectedUid() {
  if (typeof process.getuid !== 'function') throw new Error('Toolchain trust requires a POSIX user identity');
  return process.getuid();
}

async function* heldFileChunks(handle, size) {
  let position = 0;
  while (position < size) {
    const buffer = Buffer.allocUnsafe(Math.min(MiB, size - position));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
    if (bytesRead < 1) throw new Error('Held file ended before its authenticated size');
    position += bytesRead;
    yield bytesRead === buffer.length ? buffer : buffer.subarray(0, bytesRead);
  }
}

async function writeAll(handle, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset);
    if (bytesWritten < 1) throw new Error('Held output accepted a zero-byte write');
    offset += bytesWritten;
  }
}

export function architectureToolchainCacheRoot() {
  return resolve(homedir(), 'Library/Caches/com.piui.app', CACHE_NAME);
}

export function architectureCacheEntryPath(requirement, cacheRoot = architectureToolchainCacheRoot()) {
  if (!requirement
    || !['sha256', 'sha512'].includes(requirement.algorithm)
    || !(requirement.algorithm === 'sha256' ? SHA256 : SHA512).test(requirement.digest)) {
    throw new Error('Architecture toolchain cache requirement is invalid');
  }
  return resolve(cacheRoot, requirement.algorithm, requirement.digest);
}

function parseYamlScalar(value, label) {
  if (value.startsWith("'") && value.endsWith("'")) {
    const body = value.slice(1, -1);
    if (body.includes("''")) return body.replaceAll("''", "'");
    if (body.includes("'")) throw new Error(`${label} contains unsupported quoting`);
    return body;
  }
  if (!/^[A-Za-z0-9@/_.+()-]+$/u.test(value)) {
    throw new Error(`${label} contains an unsupported scalar`);
  }
  return value;
}

function npmPackageFromLockKey(rawKey, label) {
  const key = parseYamlScalar(rawKey, label);
  const withoutPeers = key.replace(/\(.+$/u, '');
  const separator = withoutPeers.lastIndexOf('@');
  if (separator <= 0) throw new Error(`${label} does not identify a registry package`);
  const name = withoutPeers.slice(0, separator);
  const version = withoutPeers.slice(separator + 1);
  if (!/^(@[A-Za-z0-9._~-]+\/[A-Za-z0-9._~-]+|[A-Za-z0-9._~-]+)$/u.test(name)
    || !/^[0-9A-Za-z][0-9A-Za-z._+-]*$/u.test(version)) {
    throw new Error(`${label} does not identify a supported registry package`);
  }
  const leaf = name.startsWith('@') ? name.slice(name.indexOf('/') + 1) : name;
  const encodedName = name.startsWith('@')
    ? `${encodeURIComponent(name.slice(0, name.indexOf('/')))}/${encodeURIComponent(leaf)}`
    : encodeURIComponent(name);
  return Object.freeze({
    name,
    url: `https://registry.npmjs.org/${encodedName}/-/${encodeURIComponent(leaf)}-${encodeURIComponent(version)}.tgz`,
    version,
  });
}

export function parsePnpmLockBytes(bytes, label = 'pnpm lockfile') {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 32
    || bytes.length > 16 * MiB
    || bytes.includes(0)
    || bytes.includes(13)) {
    throw new Error(`${label} bytes are invalid`);
  }
  const lines = bytes.toString('utf8').split('\n');
  if (lines.at(-1) !== '') throw new Error(`${label} must end with one newline`);
  if (lines.filter((line) => line === "lockfileVersion: '9.0'").length !== 1
    || lines.filter((line) => line === 'packages:').length !== 1
    || lines.filter((line) => line === 'snapshots:').length !== 1) {
    throw new Error(`${label} schema is unsupported`);
  }
  const packagesIndex = lines.indexOf('packages:');
  const snapshotsIndex = lines.indexOf('snapshots:');
  if (snapshotsIndex <= packagesIndex + 1) throw new Error(`${label} package section is invalid`);
  const records = [];
  let current;
  const finish = () => {
    if (!current) return;
    if (!current.integrity || current.resolutions !== 1) {
      throw new Error(`${label} package ${current.rawKey} lacks one exact SHA-512 resolution`);
    }
    const packageIdentity = npmPackageFromLockKey(current.rawKey, `${label} package key`);
    const digest = Buffer.from(current.integrity, 'base64').toString('hex');
    if (!SHA512.test(digest)) throw new Error(`${label} contains an invalid SHA-512 resolution`);
    records.push(Object.freeze({
      algorithm: 'sha512',
      digest,
      integrity: `sha512-${current.integrity}`,
      kind: 'npm',
      maxBytes: 128 * MiB,
      minBytes: 64,
      ...packageIdentity,
    }));
  };
  for (const line of lines.slice(packagesIndex + 1, snapshotsIndex)) {
    const heading = line.match(/^  (\S.*):$/u);
    if (heading) {
      finish();
      current = { integrity: undefined, rawKey: heading[1], resolutions: 0 };
      continue;
    }
    const resolution = line.match(/^    resolution: \{integrity: sha512-([^}]+)\}$/u);
    if (resolution) {
      if (!current || !BASE64_SHA512.test(resolution[1])) {
        throw new Error(`${label} contains an unsupported package resolution`);
      }
      current.integrity = resolution[1];
      current.resolutions += 1;
    } else if (/^    resolution:/u.test(line)) {
      throw new Error(`${label} contains a non-SHA-512 package resolution`);
    }
  }
  finish();
  if (records.length < 1) throw new Error(`${label} contains no registry packages`);
  const keys = new Set();
  for (const record of records) {
    const key = `${record.name}@${record.version}`;
    if (keys.has(key)) throw new Error(`${label} contains a duplicate package record`);
    keys.add(key);
  }
  return Object.freeze(records);
}

export async function parsePnpmLocks(sourceRoot) {
  const paths = [
    resolve(sourceRoot, 'pnpm-lock.yaml'),
    resolve(sourceRoot, 'sidecar/production/pnpm-lock.yaml'),
  ];
  const records = [];
  for (const path of paths) {
    records.push(...parsePnpmLockBytes(await readFile(path), relative(sourceRoot, path)));
  }
  if (records.length !== 1_005) {
    throw new Error(`Pinned pnpm lock closure count changed: expected 1005, received ${records.length}`);
  }
  const byDigest = new Map();
  for (const record of records) {
    const existing = byDigest.get(record.digest);
    if (existing && existing.url !== record.url) {
      throw new Error('A pnpm integrity digest is assigned to more than one registry URL');
    }
    byDigest.set(record.digest, record);
  }
  if (byDigest.size !== 868) {
    throw new Error(`Pinned pnpm archive closure count changed: expected 868, received ${byDigest.size}`);
  }
  return Object.freeze([...byDigest.values()].sort((left, right) => left.digest.localeCompare(right.digest)));
}

function parseTomlString(line, field, label) {
  const match = line.match(new RegExp(`^${field} = "([^"]+)"$`, 'u'));
  if (!match || /[\\\r\n\0]/u.test(match[1])) throw new Error(`${label} has an invalid ${field}`);
  return match[1];
}

export function parseCargoLockBytes(bytes, label = 'Cargo.lock') {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 32
    || bytes.length > 16 * MiB
    || bytes.includes(0)
    || bytes.includes(13)) {
    throw new Error(`${label} bytes are invalid`);
  }
  const text = bytes.toString('utf8');
  if (!text.endsWith('\n') || !/^version = 4$/mu.test(text)) {
    throw new Error(`${label} schema is unsupported`);
  }
  const blocks = text.split('[[package]]\n').slice(1);
  const crates = [];
  const tuples = new Set();
  for (const block of blocks) {
    const lines = block.split('\n');
    const nameLine = lines.find((line) => line.startsWith('name = '));
    const versionLine = lines.find((line) => line.startsWith('version = '));
    const sourceLines = lines.filter((line) => line.startsWith('source = '));
    const checksumLines = lines.filter((line) => line.startsWith('checksum = '));
    if (!nameLine || !versionLine) throw new Error(`${label} contains an incomplete package record`);
    const name = parseTomlString(nameLine, 'name', label);
    const version = parseTomlString(versionLine, 'version', label);
    if (!/^[A-Za-z0-9_-]+$/u.test(name)
      || !/^[0-9A-Za-z][0-9A-Za-z.+-]*$/u.test(version)) {
      throw new Error(`${label} contains an unsupported package tuple`);
    }
    if (sourceLines.length === 0 && checksumLines.length === 0) continue;
    if (sourceLines.length !== 1 || checksumLines.length !== 1) {
      throw new Error(`${label} package ${name}@${version} has incomplete source authentication`);
    }
    const source = parseTomlString(sourceLines[0], 'source', label);
    const checksum = parseTomlString(checksumLines[0], 'checksum', label);
    if (source !== REGISTRY_SOURCE || !SHA256.test(checksum)) {
      throw new Error(`${label} contains a git, unlisted, or unsupported registry source`);
    }
    const tuple = `${name}@${version}`;
    if (tuples.has(tuple)) throw new Error(`${label} contains a duplicate registry package tuple`);
    tuples.add(tuple);
    const encodedName = encodeURIComponent(name);
    const encodedVersion = encodeURIComponent(version);
    crates.push(Object.freeze({
      algorithm: 'sha256',
      checksum,
      digest: checksum,
      filename: `${name}-${version}.crate`,
      kind: 'cargo',
      maxBytes: 128 * MiB,
      minBytes: 64,
      name,
      tuple,
      url: `https://static.crates.io/crates/${encodedName}/${encodedName}-${encodedVersion}.crate`,
      version,
    }));
  }
  if (crates.length !== 520) {
    throw new Error(`Pinned Cargo archive closure count changed: expected 520, received ${crates.length}`);
  }
  return Object.freeze(crates.sort((left, right) => left.tuple.localeCompare(right.tuple)));
}

export async function parseCargoLock(sourceRoot) {
  return parseCargoLockBytes(await readFile(resolve(sourceRoot, 'src-tauri/Cargo.lock')));
}

export async function provisionRequirements(sourceRoot) {
  return Object.freeze([
    architectureToolchainPins.node,
    architectureToolchainPins.pnpm,
    architectureToolchainPins.rustChannel,
    ...architectureToolchainPins.rust,
    ...await parsePnpmLocks(sourceRoot),
    ...await parseCargoLock(sourceRoot),
  ]);
}

function exactTomlSection(text, heading, label) {
  const marker = `[${heading}]`;
  const occurrences = text.split(marker).length - 1;
  if (occurrences !== 1) throw new Error(`${label} lacks one exact ${heading} section`);
  const start = text.indexOf(marker) + marker.length;
  const remainder = text.slice(start);
  const next = remainder.search(/^\[/mu);
  return (next < 0 ? remainder : remainder.slice(0, next)).trim();
}

function exactTomlFields(section, required, label) {
  const fields = new Map();
  for (const line of section.split('\n')) {
    const match = line.match(/^([a-z_]+) = (true|"[^"]*")$/u);
    if (!match || fields.has(match[1])) throw new Error(`${label} contains unsupported or duplicate fields`);
    fields.set(match[1], match[2] === 'true' ? true : match[2].slice(1, -1));
  }
  for (const [name, expected] of Object.entries(required)) {
    if (fields.get(name) !== expected) throw new Error(`${label} ${name} does not match the reviewed pin`);
  }
  return fields;
}

export function assertRustChannelManifestBytes(bytes) {
  const pin = architectureToolchainPins.rustChannel;
  if (!Buffer.isBuffer(bytes)
    || bytes.length !== pin.minBytes
    || bytes.includes(0)
    || bytes.includes(13)
    || digestBytes(bytes, 'sha256') !== pin.manifestSha256) {
    throw new Error('Rust channel manifest bytes do not match the reviewed pin');
  }
  const text = bytes.toString('utf8');
  if (!text.startsWith(`manifest-version = "2"\ndate = "${pin.date}"\n`)
    || !text.endsWith('\n')) {
    throw new Error('Rust channel manifest date or schema does not match the reviewed pin');
  }
  const expectedVersions = Object.freeze({
    cargo: '0.97.0 (30a34c682 2026-05-25)',
    rust: '1.96.0 (ac68faa20 2026-05-25)',
    'rust-std': '1.96.0 (ac68faa20 2026-05-25)',
    rustc: '1.96.0 (ac68faa20 2026-05-25)',
  });
  for (const [component, version] of Object.entries(expectedVersions)) {
    const packageSection = exactTomlSection(text, `pkg.${component}`, 'Rust channel manifest');
    const fields = exactTomlFields(packageSection, { version }, `Rust ${component} package`);
    if (fields.size !== 2 || typeof fields.get('git_commit_hash') !== 'string') {
      throw new Error(`Rust ${component} package metadata is not exact`);
    }
  }
  for (const component of architectureToolchainPins.rust) {
    const packageName = component.component.startsWith('rust-std') ? 'rust-std' : component.component;
    const section = exactTomlSection(
      text,
      `pkg.${packageName}.target.${pin.target}`,
      'Rust channel manifest',
    );
    exactTomlFields(section, {
      available: true,
      hash: component.digest,
      url: component.url,
    }, `Rust ${component.component} target`);
  }
  return Object.freeze({
    date: pin.date,
    manifestSha256: pin.manifestSha256,
    target: pin.target,
    version: pin.version,
  });
}

function parseTarNumber(bytes, label, allowBase256 = false) {
  if ((bytes[0] & 0x80) !== 0) {
    if (!allowBase256) throw new Error(`${label} contains a base-256 tar number outside its exact pin`);
    if ((bytes[0] & 0x40) !== 0) throw new Error(`${label} contains a negative base-256 tar number`);
    const encoded = Buffer.from(bytes);
    encoded[0] &= 0x7f;
    const parsed = encoded.reduce((value, byte) => (value * 256n) + BigInt(byte), 0n);
    if (parsed > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error(`${label} contains an unsafe base-256 tar number`);
    }
    return Number(parsed);
  }
  const value = bytes.toString('ascii').replace(/\0.*$/su, '').trim();
  if (value === '') return 0;
  if (!/^[0-7]+$/u.test(value)) throw new Error(`${label} contains a non-octal tar number`);
  const parsed = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new Error(`${label} contains an unsafe tar number`);
  return parsed;
}

function tarText(bytes, label) {
  const value = bytes.toString('utf8').replace(/\0.*$/su, '');
  if (value.includes('\uFFFD') || Buffer.byteLength(value, 'utf8') > bytes.length) {
    throw new Error(`${label} contains invalid UTF-8 metadata`);
  }
  return value;
}

function safeArchivePath(name, label) {
  if (typeof name !== 'string'
    || name.length < 1
    || name.length > 1_024
    || name.startsWith('/')
    || name.includes('\\')
    || name.includes('\0')) {
    throw new Error(`${label} contains an unsafe archive path`);
  }
  const parts = name.replace(/\/+$/u, '').split('/');
  if (parts.length < 1 || parts.some((part) => part === '' || part === '.' || part === '..')) {
    throw new Error(`${label} contains an escaping archive path: ${JSON.stringify(name)}`);
  }
  return parts.join('/');
}

function parsePaxExtendedHeader(bytes, label, allowInertExtensions) {
  const fields = new Map();
  let offset = 0;
  while (offset < bytes.length) {
    if (fields.size >= 64) throw new Error(`${label} contains too many PAX metadata records`);
    const space = bytes.indexOf(0x20, offset);
    if (space < 0) throw new Error(`${label} contains a malformed PAX record length`);
    const lengthText = bytes.subarray(offset, space).toString('ascii');
    if (!/^[1-9][0-9]{1,5}$/u.test(lengthText)) {
      throw new Error(`${label} contains a non-canonical PAX record length`);
    }
    const length = Number.parseInt(lengthText, 10);
    const end = offset + length;
    if (end > bytes.length || bytes[end - 1] !== 0x0a) {
      throw new Error(`${label} contains a truncated PAX record`);
    }
    const record = bytes.subarray(space + 1, end - 1).toString('utf8');
    if (record.includes('\uFFFD') || Buffer.byteLength(record, 'utf8') !== end - space - 2) {
      throw new Error(`${label} contains invalid UTF-8 PAX metadata`);
    }
    const separator = record.indexOf('=');
    const key = separator < 0 ? '' : record.slice(0, separator);
    const value = separator < 0 ? '' : record.slice(separator + 1);
    const semantic = ['gid', 'mtime', 'path', 'size', 'uid'].includes(key);
    const inertExtension = /^(?:NODETAR|SCHILY)\.[A-Za-z0-9._-]{1,128}$/u.test(key);
    if ((!semantic && (!allowInertExtensions || !inertExtension))
      || fields.has(key)
      || value === ''
      || value.length > 1_024
      || /[\0\r\n]/u.test(value)) {
      throw new Error(`${label} contains unsupported or duplicate PAX metadata`);
    }
    fields.set(key, value);
    offset = end;
  }
  if (!fields.has('path') || !fields.has('size')) {
    throw new Error(`${label} lacks required PAX path or size metadata`);
  }
  const numbers = Object.fromEntries(['gid', 'mtime', 'size', 'uid'].map((key) => {
    const value = fields.get(key);
    if (value === undefined) return [key, undefined];
    if (!/^(?:0|[1-9][0-9]{0,15})$/u.test(value)) {
      throw new Error(`${label} contains non-canonical numeric PAX metadata`);
    }
    return [key, Number.parseInt(value, 10)];
  }));
  if (Object.values(numbers).some((value) => (
    value !== undefined && !Number.isSafeInteger(value)
  ))) {
    throw new Error(`${label} contains unsafe PAX numeric metadata`);
  }
  return Object.freeze({
    gid: numbers.gid,
    mtime: numbers.mtime,
    path: safeArchivePath(fields.get('path'), label),
    size: numbers.size,
    uid: numbers.uid,
  });
}

function parseTarHeader(
  header,
  label,
  allowSafeSymlinks,
  pinnedDuplicateException,
  pinnedLegacyPaxException,
) {
  if (header.length !== 512) throw new Error(`${label} contains a truncated tar header`);
  const expectedChecksum = parseTarNumber(header.subarray(148, 156), label);
  let actualChecksum = 0;
  for (let index = 0; index < header.length; index += 1) {
    actualChecksum += index >= 148 && index < 156 ? 0x20 : header[index];
  }
  if (expectedChecksum !== actualChecksum) throw new Error(`${label} contains a corrupt tar header`);
  if (!tarText(header.subarray(257, 263), label).startsWith('ustar')) {
    throw new Error(`${label} is not an exact ustar archive`);
  }
  const size = parseTarNumber(header.subarray(124, 136), label);
  const rawMode = parseTarNumber(header.subarray(100, 108), label);
  const uidBytes = header.subarray(108, 116);
  const gidBytes = header.subarray(116, 124);
  const uid = parseTarNumber(uidBytes, label, pinnedLegacyPaxException !== undefined);
  const gid = parseTarNumber(gidBytes, label, pinnedLegacyPaxException !== undefined);
  const mtime = parseTarNumber(header.subarray(136, 148), label);
  const base256Fields = Number((uidBytes[0] & 0x80) !== 0) + Number((gidBytes[0] & 0x80) !== 0);
  const typeByte = header[156];
  const regularFile = typeByte === 0 || typeByte === 0x30;
  if ((rawMode & ~0o777) !== 0
    && !(regularFile && (rawMode & ~0o777) === 0o100000)) {
    throw new Error(`${label} contains unsupported tar mode bits`);
  }
  const mode = rawMode & 0o777;
  const rawName = tarText(header.subarray(0, 100), label);
  const prefix = tarText(header.subarray(345, 500), label);
  const combinedRawName = prefix ? `${prefix}/${rawName}` : rawName;
  if (typeByte === 0x4c) {
    if (size < 2 || size > 4_096) throw new Error(`${label} contains an invalid GNU long-name record`);
    return Object.freeze({ base256Fields, gid, kind: 'long-name', mode, mtime, name: '././@LongLink', rawName: combinedRawName, size, uid });
  }
  if (typeByte === 0x78) {
    if (size < 1 || size > 4_096) throw new Error(`${label} contains an invalid PAX extended header`);
    return Object.freeze({ base256Fields, gid, kind: 'pax', mode, mtime, name: safeArchivePath(combinedRawName, label), rawName: combinedRawName, size, uid });
  }
  const name = pinnedDuplicateException
    && combinedRawName === pinnedDuplicateException.firstName
    ? pinnedDuplicateException.canonicalName
    : safeArchivePath(combinedRawName, label);
  if (typeByte === 0 || typeByte === 0x30) {
    return Object.freeze({ base256Fields, gid, kind: 'file', mode, mtime, name, rawName: combinedRawName, size, uid });
  }
  if (typeByte === 0x35) {
    if (size !== 0) throw new Error(`${label} contains a non-empty directory record`);
    return Object.freeze({ base256Fields, gid, kind: 'directory', mode, mtime, name, rawName: combinedRawName, size, uid });
  }
  if (typeByte === 0x32 && allowSafeSymlinks) {
    const linkTarget = tarText(header.subarray(157, 257), label);
    if (size !== 0
      || !linkTarget
      || linkTarget.startsWith('/')
      || linkTarget.includes('\\')
      || linkTarget.includes('\0')) {
      throw new Error(`${label} contains an unsafe symbolic link`);
    }
    return Object.freeze({ base256Fields, gid, kind: 'symlink', linkTarget, mode, mtime, name, rawName: combinedRawName, size, uid });
  }
  throw new Error(`${label} contains a link or special archive entry`);
}

async function openPrivateOutput(path, executable) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  return open(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    executable ? 0o700 : 0o600,
  );
}

export async function processTrustedGzipTar(archivePath, {
  allowSafeSymlinks = false,
  destination,
  label = 'archive',
  mapEntry,
  maxEntries = 100_000,
  maxExpandedBytes = 1_024 * MiB,
  maxMemberBytes = 512 * MiB,
  pinnedDuplicateArchiveSha512,
  pinnedLegacyPaxArchiveSha512,
  requiredPrefix,
  singleTopLevel = false,
} = {}) {
  if (typeof archivePath !== 'string' || resolve(archivePath) !== archivePath) {
    throw new Error(`${label} path is not canonical`);
  }
  let archive;
  let source;
  let gunzip;
  let output;
  let current;
  let pending = Buffer.alloc(0);
  let pendingLongName;
  let pendingPax;
  let expandedBytes = 0;
  let entries = 0;
  let extracted = 0;
  let zeroBlocks = 0;
  let ended = false;
  const names = new Set();
  const topLevels = new Set();
  let duplicateExceptionStage = 0;
  let legacyPaxExceptionStage = 0;
  let legacyPaxRecords = 0;
  let legacyBase256Fields = 0;
  const duplicateException = pinnedDuplicateArchiveSha512 === undefined
    ? undefined
    : pinnedNpmDuplicateExceptionBySha512.get(pinnedDuplicateArchiveSha512);
  const legacyPaxException = pinnedLegacyPaxArchiveSha512 === undefined
    ? undefined
    : pinnedNpmLegacyPaxExceptionBySha512.get(pinnedLegacyPaxArchiveSha512);
  if (pinnedDuplicateArchiveSha512 !== undefined && pinnedLegacyPaxArchiveSha512 !== undefined) {
    throw new Error(`${label} selected more than one pin-scoped archive exception`);
  }
  if (pinnedLegacyPaxArchiveSha512 !== undefined && (destination || mapEntry !== undefined)) {
    throw new Error(`${label} attempted to extract the validation-only legacy PAX exception`);
  }
  const compressedHash = pinnedDuplicateArchiveSha512 === undefined
    && pinnedLegacyPaxArchiveSha512 === undefined
    ? undefined
    : createHash('sha512');
  try {
    archive = await open(archivePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const archiveBefore = await archive.stat({ bigint: true });
    const archivePathBefore = await lstat(archivePath, { bigint: true });
    if (!archiveBefore.isFile()
      || archiveBefore.isSymbolicLink()
      || archiveBefore.nlink !== 1n
      || archiveBefore.uid !== BigInt(expectedUid())
      || (archiveBefore.mode & 0o022n) !== 0n
      || archivePathBefore.isSymbolicLink()
      || !sameFileState(archiveBefore, archivePathBefore)) {
      throw new Error(`${label} is not a unique regular archive`);
    }
    if (archiveBefore.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error(`${label} archive is too large to stream safely`);
    }
    source = Readable.from((async function* authenticatedCompressedChunks() {
      for await (const chunk of heldFileChunks(archive, Number(archiveBefore.size))) {
        compressedHash?.update(chunk);
        yield chunk;
      }
    }()));
    gunzip = createGunzip();
    source.pipe(gunzip);
    for await (const chunk of gunzip) {
      expandedBytes += chunk.length;
      if (expandedBytes > maxExpandedBytes) throw new Error(`${label} expanded size exceeds its bound`);
      pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk]);
      let progressed = true;
      while (progressed) {
        progressed = false;
        if (ended) {
          if (pending.length === 0) continue;
          if (pending.some((byte) => byte !== 0)) throw new Error(`${label} contains data after its tar terminator`);
          pending = Buffer.alloc(0);
          progressed = true;
          continue;
        }
        if (!current) {
          if (pending.length < 512) continue;
          const header = pending.subarray(0, 512);
          pending = pending.subarray(512);
          progressed = true;
          if (header.every((byte) => byte === 0)) {
            zeroBlocks += 1;
            if (zeroBlocks === 2) ended = true;
            continue;
          }
          if (zeroBlocks !== 0) throw new Error(`${label} contains a partial tar terminator`);
          if (entries >= maxEntries) throw new Error(`${label} contains too many archive entries`);
          let entry = parseTarHeader(
            header,
            label,
            allowSafeSymlinks,
            duplicateException,
            legacyPaxException,
          );
          let legacyRecord;
          if (legacyPaxException) {
            legacyRecord = legacyPaxException.records[legacyPaxExceptionStage];
            const type = header[156] === 0 ? '\0' : String.fromCharCode(header[156]);
            if (!legacyRecord
              || legacyRecord.index !== legacyPaxExceptionStage
              || legacyRecord.headerSha256 !== createHash('sha256').update(header).digest('hex')
              || legacyRecord.rawName !== entry.rawName
              || legacyRecord.type !== type
              || legacyRecord.mode !== entry.mode
              || legacyRecord.uid !== entry.uid
              || legacyRecord.gid !== entry.gid
              || legacyRecord.mtime !== entry.mtime
              || legacyRecord.size !== entry.size) {
              throw new Error(`${label} changed its exact pin-scoped legacy PAX record sequence`);
            }
            legacyPaxExceptionStage += 1;
            legacyBase256Fields += entry.base256Fields;
            if (entry.kind === 'pax') legacyPaxRecords += 1;
          }
          if (entry.size > maxMemberBytes) throw new Error(`${label} contains an oversized member`);
          entries += 1;
          let longNameBytes;
          let paxBytes;
          let exceptionRole;
          if (entry.kind === 'long-name') {
            if (pendingLongName || pendingPax) throw new Error(`${label} contains consecutive archive metadata records`);
            longNameBytes = Buffer.alloc(entry.size);
          } else if (entry.kind === 'pax') {
            if (pendingLongName || pendingPax) throw new Error(`${label} contains consecutive archive metadata records`);
            paxBytes = Buffer.alloc(entry.size);
          } else {
            if (pendingLongName) {
              entry = Object.freeze({ ...entry, name: pendingLongName, rawName: pendingLongName });
              pendingLongName = undefined;
            }
            if (pendingPax) {
              if (entry.kind !== 'file'
                || (pendingPax.mtime !== undefined && entry.mtime !== pendingPax.mtime)
                || (!legacyPaxException
                  && pendingPax.uid !== undefined
                  && entry.uid !== pendingPax.uid)
                || (!legacyPaxException
                  && pendingPax.gid !== undefined
                  && entry.gid !== pendingPax.gid)
                || entry.size !== pendingPax.size) {
                throw new Error(`${label} PAX metadata does not match its regular-file header`);
              }
              entry = Object.freeze({ ...entry, name: pendingPax.path, rawName: pendingPax.path });
              pendingPax = undefined;
            }
            if (requiredPrefix
              && entry.name !== requiredPrefix
              && !entry.name.startsWith(`${requiredPrefix}/`)) {
              throw new Error(`${label} contains an unexpected top-level entry`);
            }
            if (entry.kind === 'symlink') {
              const resolvedTarget = posix.normalize(posix.join(posix.dirname(entry.name), entry.linkTarget));
              if (!requiredPrefix
                || (resolvedTarget !== requiredPrefix
                  && !resolvedTarget.startsWith(`${requiredPrefix}/`))) {
                throw new Error(`${label} contains an escaping symbolic link`);
              }
            }
            if (duplicateException && entry.name === duplicateException.canonicalName) {
              if (destination || mapEntry !== undefined) {
                throw new Error(`${label} attempted to extract the validation-only duplicate exception`);
              }
              const expectedName = duplicateExceptionStage === 0
                ? duplicateException.firstName
                : duplicateExceptionStage === 1
                  ? duplicateException.secondName
                  : undefined;
              if (entry.rawName !== expectedName
                || entry.kind !== 'file'
                || entry.mode !== duplicateException.mode
                || entry.uid !== duplicateException.uid
                || entry.gid !== duplicateException.gid
                || entry.mtime !== duplicateException.mtime
                || entry.size !== duplicateException.size) {
                throw new Error(`${label} does not match the pin-scoped duplicate exception`);
              }
              duplicateExceptionStage += 1;
              exceptionRole = duplicateExceptionStage;
            } else if (names.has(entry.name)) {
              throw new Error(`${label} contains a duplicate archive path`);
            }
            if (names.has(entry.name) && exceptionRole !== 2) {
              throw new Error(`${label} contains an out-of-order duplicate archive path`);
            }
            names.add(entry.name);
            topLevels.add(entry.name.split('/')[0]);
            if (singleTopLevel && topLevels.size !== 1) {
              throw new Error(`${label} contains more than one top-level payload`);
            }
            const mapped = mapEntry?.(entry);
            if (mapped !== undefined && mapped !== false) {
              if (!destination || typeof mapped !== 'string') {
                throw new Error(`${label} extraction mapping is invalid`);
              }
              const safeMapped = safeArchivePath(mapped, label);
              const outputPath = resolve(destination, ...safeMapped.split('/'));
              if (relative(destination, outputPath).startsWith('..')) {
                throw new Error(`${label} extraction escaped its destination`);
              }
              if (entry.kind === 'symlink') {
                throw new Error(`${label} attempted to materialise a symbolic link`);
              }
              if (entry.kind === 'directory') {
                mkdirSync(outputPath, { recursive: true, mode: 0o700 });
              } else {
                output = await openPrivateOutput(outputPath, (entry.mode & 0o111) !== 0);
                extracted += 1;
              }
            }
          }
          current = {
            entry,
            exceptionHash: exceptionRole ? createHash('sha256') : undefined,
            exceptionRole,
            legacyHash: legacyRecord ? createHash('sha256') : undefined,
            legacyRecord,
            longNameBytes,
            longNameOffset: 0,
            paxBytes,
            paxOffset: 0,
            paddingRemaining: Math.ceil(entry.size / 512) * 512 - entry.size,
            remaining: entry.size,
          };
          if (current.remaining === 0 && output) {
            await output.sync();
            await output.close();
            output = undefined;
          }
          if (current.remaining === 0 && current.paddingRemaining === 0) current = undefined;
        }
        if (current && current.remaining > 0 && pending.length > 0) {
          const length = Math.min(current.remaining, pending.length);
          const bytes = pending.subarray(0, length);
          pending = pending.subarray(length);
          if (output) await writeAll(output, bytes);
          if (current.longNameBytes) {
            bytes.copy(current.longNameBytes, current.longNameOffset);
            current.longNameOffset += bytes.length;
          }
          if (current.paxBytes) {
            bytes.copy(current.paxBytes, current.paxOffset);
            current.paxOffset += bytes.length;
          }
          current.exceptionHash?.update(bytes);
          current.legacyHash?.update(bytes);
          current.remaining -= length;
          progressed = true;
          if (current.remaining === 0 && current.longNameBytes) {
            const nul = current.longNameBytes.indexOf(0);
            if (nul !== current.longNameBytes.length - 1) {
              throw new Error(`${label} contains a malformed GNU long-name record`);
            }
            pendingLongName = safeArchivePath(
              current.longNameBytes.subarray(0, nul).toString('utf8'),
              label,
            );
          }
          if (current.remaining === 0 && current.paxBytes) {
            pendingPax = parsePaxExtendedHeader(
              current.paxBytes,
              label,
              legacyPaxException !== undefined,
            );
          }
          if (current.remaining === 0 && current.exceptionHash
            && current.exceptionHash.digest('hex') !== duplicateException.payloadSha256) {
            throw new Error(`${label} duplicate-exception payload bytes changed`);
          }
          if (current.remaining === 0 && current.legacyHash
            && current.legacyHash.digest('hex') !== current.legacyRecord.payloadSha256) {
            throw new Error(`${label} changed its pin-scoped legacy PAX payload sequence`);
          }
          if (current.remaining === 0 && output) {
            await output.sync();
            await output.close();
            output = undefined;
          }
        }
        if (current && current.remaining === 0 && current.paddingRemaining > 0 && pending.length > 0) {
          const length = Math.min(current.paddingRemaining, pending.length);
          if (pending.subarray(0, length).some((byte) => byte !== 0)) {
            throw new Error(`${label} contains non-zero tar padding`);
          }
          pending = pending.subarray(length);
          current.paddingRemaining -= length;
          progressed = true;
        }
        if (current && current.remaining === 0 && current.paddingRemaining === 0) {
          current = undefined;
          progressed = true;
        }
      }
    }
    if (!ended || current || output || pendingLongName || pendingPax || pending.some((byte) => byte !== 0)) {
      throw new Error(`${label} is truncated or lacks an exact tar terminator`);
    }
    const compressedDigest = compressedHash?.digest('hex');
    if (pinnedDuplicateArchiveSha512 !== undefined
      && (!duplicateException
        || compressedDigest !== duplicateException.archiveSha512
        || duplicateExceptionStage !== 2)) {
      throw new Error(`${label} did not consume its exact pin-scoped duplicate exception`);
    }
    if (pinnedLegacyPaxArchiveSha512 !== undefined
      && (!legacyPaxException
        || compressedDigest !== legacyPaxException.archiveSha512
        || entries !== legacyPaxException.archiveEntries
        || legacyPaxExceptionStage !== legacyPaxException.records.length
        || legacyPaxRecords !== legacyPaxException.paxRecords
        || legacyBase256Fields !== legacyPaxException.base256UidGidFields)) {
      throw new Error(`${label} did not consume its exact pin-scoped legacy PAX exception`);
    }
    const archiveAfter = await archive.stat({ bigint: true });
    const pathAfter = await lstat(archivePath, { bigint: true });
    if (!sameFileState(archiveBefore, archiveAfter)
      || pathAfter.isSymbolicLink()
      || !sameFileState(archiveAfter, pathAfter)) {
      throw new Error(`${label} identity changed during streaming inspection`);
    }
    return Object.freeze({
      entries,
      expandedBytes,
      extracted,
      topLevel: topLevels.size === 1 ? [...topLevels][0] : undefined,
    });
  } finally {
    await output?.close();
    source?.destroy();
    gunzip?.destroy();
    await archive?.close();
  }
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

async function assertPrivateDirectory(path, label, acceptedModes = [0o700, 0o500]) {
  const state = await lstat(path, { bigint: true });
  if (!state.isDirectory()
    || state.isSymbolicLink()
    || state.uid !== BigInt(expectedUid())
    || !acceptedModes.includes(Number(state.mode & 0o777n))
    || await realpath(path) !== path) {
    throw new Error(`${label} is not a canonical private directory`);
  }
  return state;
}

async function openVerifiedCacheEntry(requirement, cacheRoot) {
  await assertPrivateDirectory(cacheRoot, 'Architecture toolchain cache', [0o700]);
  await assertPrivateDirectory(
    resolve(cacheRoot, requirement.algorithm),
    'Architecture toolchain cache algorithm directory',
    [0o700],
  );
  const path = architectureCacheEntryPath(requirement, cacheRoot);
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const state = await handle.stat({ bigint: true });
    if (!state.isFile()
      || state.isSymbolicLink()
      || state.nlink !== 1n
      || state.uid !== BigInt(expectedUid())
      || (state.mode & 0o222n) !== 0n
      || state.size < BigInt(requirement.minBytes)
      || state.size > BigInt(requirement.maxBytes)) {
      throw new Error(`Provisioned ${requirement.kind} archive is not a sealed private file`);
    }
    const pathState = await lstat(path, { bigint: true });
    if (pathState.isSymbolicLink() || !sameFileState(state, pathState)) {
      throw new Error(`Provisioned ${requirement.kind} archive identity is unstable`);
    }
    return Object.freeze({ handle, path, state });
  } catch (error) {
    await handle?.close();
    if (error?.code === 'ENOENT') {
      throw new Error(`Provisioned ${requirement.kind} archive is missing; run pnpm provision:architecture-toolchain`);
    }
    throw error;
  }
}

async function authenticateHeldFile(opened, requirement, destination) {
  const hash = createHash(requirement.algorithm);
  let bytes = 0;
  let destinationHandle;
  try {
    if (destination) {
      mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
      destinationHandle = await open(
        destination,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
    }
    for await (const chunk of heldFileChunks(opened.handle, Number(opened.state.size))) {
      bytes += chunk.length;
      if (bytes > requirement.maxBytes) throw new Error(`Provisioned ${requirement.kind} archive exceeds its bound`);
      hash.update(chunk);
      if (destinationHandle) await writeAll(destinationHandle, chunk);
    }
    if (destinationHandle) {
      await destinationHandle.sync();
      const copied = await destinationHandle.stat({ bigint: true });
      if (copied.size !== BigInt(bytes) || copied.nlink !== 1n) {
        throw new Error(`Private ${requirement.kind} archive copy is incomplete`);
      }
    }
    const after = await opened.handle.stat({ bigint: true });
    const pathAfter = await lstat(opened.path, { bigint: true });
    if (bytes < requirement.minBytes
      || bytes > requirement.maxBytes
      || hash.digest('hex') !== requirement.digest
      || !sameFileState(opened.state, after)
      || pathAfter.isSymbolicLink()
      || !sameFileState(after, pathAfter)) {
      throw new Error(`Provisioned ${requirement.kind} archive failed held-byte authentication`);
    }
    if (destinationHandle) await destinationHandle.chmod(0o400);
    return Object.freeze({ bytes, path: opened.path, state: after });
  } finally {
    await destinationHandle?.close();
  }
}

export async function verifyProvisionedArchive(
  requirement,
  cacheRoot = architectureToolchainCacheRoot(),
) {
  const opened = await openVerifiedCacheEntry(requirement, cacheRoot);
  try {
    return await authenticateHeldFile(opened, requirement);
  } finally {
    await opened.handle.close();
  }
}

export async function copyProvisionedArchive(
  requirement,
  destination,
  cacheRoot = architectureToolchainCacheRoot(),
) {
  if (typeof destination !== 'string' || resolve(destination) !== destination) {
    throw new Error('Private architecture archive destination is not canonical');
  }
  const opened = await openVerifiedCacheEntry(requirement, cacheRoot);
  try {
    await authenticateHeldFile(opened, requirement, destination);
  } finally {
    await opened.handle.close();
  }
  const copied = await verifyRegularFile(destination, {
    algorithm: requirement.algorithm,
    digest: requirement.digest,
    maxBytes: requirement.maxBytes,
    minBytes: requirement.minBytes,
  }, `Private ${requirement.kind} archive`);
  return Object.freeze({ path: destination, state: copied.state });
}

export async function verifyRegularFile(path, expectation, label) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1n
      || before.uid !== BigInt(expectedUid())
      || (before.mode & 0o022n) !== 0n
      || before.size < BigInt(expectation.minBytes)
      || before.size > BigInt(expectation.maxBytes)) {
      throw new Error(`${label} is not a trusted regular file`);
    }
    const hash = createHash(expectation.algorithm);
    let bytes = 0;
    for await (const chunk of heldFileChunks(handle, Number(before.size))) {
      bytes += chunk.length;
      if (bytes > expectation.maxBytes) throw new Error(`${label} exceeds its size bound`);
      hash.update(chunk);
    }
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (bytes < expectation.minBytes
      || bytes > expectation.maxBytes
      || hash.digest('hex') !== expectation.digest
      || !sameFileState(before, after)
      || pathAfter.isSymbolicLink()
      || !sameFileState(after, pathAfter)) {
      throw new Error(`${label} changed during authentication`);
    }
    return Object.freeze({ bytes, state: after });
  } finally {
    await handle?.close();
  }
}

export function sealPrivateTree(root) {
  const directories = [];
  const visit = (path) => {
    const item = lstatSync(path, { bigint: true });
    if (item.isSymbolicLink()) throw new Error('Private toolchain tree contains a symbolic link');
    if (item.isDirectory()) {
      const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      try {
        const exact = fstatSync(fd, { bigint: true });
        if (!exact.isDirectory() || exact.dev !== item.dev || exact.ino !== item.ino) {
          throw new Error('Private toolchain directory identity changed during sealing');
        }
      } finally {
        closeSync(fd);
      }
      for (const name of readdirSync(path).sort((left, right) => left.localeCompare(right))) {
        visit(resolve(path, name));
      }
      directories.push(path);
      return;
    }
    if (!item.isFile() || item.nlink !== 1n) {
      throw new Error('Private toolchain tree contains a special or multiply linked entry');
    }
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const exact = fstatSync(fd, { bigint: true });
      if (!exact.isFile() || exact.dev !== item.dev || exact.ino !== item.ino) {
        throw new Error('Private toolchain file identity changed during sealing');
      }
      fchmodSync(fd, (Number(exact.mode) & 0o111) !== 0 ? 0o500 : 0o400);
    } finally {
      closeSync(fd);
    }
  };
  visit(root);
  for (const path of directories) {
    const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try {
      fchmodSync(fd, 0o500);
    } finally {
      closeSync(fd);
    }
  }
}
