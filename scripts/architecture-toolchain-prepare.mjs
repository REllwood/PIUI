import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  constants,
  mkdirSync,
  writeFileSync,
} from 'node:fs';
import {
  chmod,
  lstat,
  open,
  readdir,
  readFile,
  realpath,
} from 'node:fs/promises';
import { dirname, relative, resolve } from 'node:path';
import {
  architectureToolchainPins,
  architectureToolchainPinsSha256,
  assertRustChannelManifestBytes,
  copyProvisionedArchive,
  parseCargoLock,
  parseCargoLockBytes,
  parsePnpmLockBytes,
  parsePnpmLocks,
  pinnedNpmDuplicateExceptions,
  pinnedNpmDuplicateExceptionsSha256,
  pinnedNpmLegacyPaxExceptions,
  pinnedNpmLegacyPaxExceptionsSha256,
  processTrustedGzipTar,
  sealPrivateTree,
  verifyRegularFile,
} from './architecture-toolchain-trust.mjs';
import { canonicalArchitectureJson } from './architecture-gate-schema.mjs';
import {
  authoriseAuthenticatedNodeSandboxProfile,
  configureAuthenticatedNodeSpawn,
  runOwnedCommand,
} from './a21-gate-support.mjs';
import { snapshotArchitectureSource } from './architecture-source-snapshot.mjs';
import { createAuthenticatedNodeSpawnConfiguration } from './authenticated-node-spawn.mjs';

const MiB = 1_048_576;
const target = 'aarch64-apple-darwin';
const SHA256 = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/u;
const systemOpenSslConfigKeys = Object.freeze([
  'ctimeNs',
  'dev',
  'gid',
  'ino',
  'mode',
  'mtimeNs',
  'nlink',
  'path',
  'sha256',
  'size',
  'type',
  'uid',
]);
export const systemOpenSslConfigPin = Object.freeze({
  gid: 0,
  mode: 0o644,
  nlink: 1,
  path: '/private/etc/ssl/openssl.cnf',
  sha256: '025f5e31cd7b2248a0a661d8d346452c31d98e280f3420c3f6017c74c829ae73',
  size: 745,
  type: 'regular-file',
  uid: 0,
});
const receiptKeys = Object.freeze([
  'cargoArchives',
  'cargoLockSha256',
  'nodeArchiveSha256',
  'nodeExecutableSha256',
  'npmArchives',
  'pnpmArchiveSha512',
  'pnpmLocksSha256',
  'pnpmValidationDuplicateExceptionsSha256',
  'pnpmValidationLegacyPaxExceptionsSha256',
  'rustChannelManifestSha256',
  'rustComponentsSha256',
  'schemaVersion',
  'systemOpenSslConfig',
  'target',
  'toolchainPinsSha256',
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

export function assertSystemOpenSslConfigRecord(value) {
  if (!exactKeys(value, systemOpenSslConfigKeys)
    || value.path !== systemOpenSslConfigPin.path
    || value.sha256 !== systemOpenSslConfigPin.sha256
    || value.size !== systemOpenSslConfigPin.size
    || value.uid !== systemOpenSslConfigPin.uid
    || value.gid !== systemOpenSslConfigPin.gid
    || value.mode !== systemOpenSslConfigPin.mode
    || value.nlink !== systemOpenSslConfigPin.nlink
    || value.type !== systemOpenSslConfigPin.type
    || !DECIMAL.test(value.dev ?? '')
    || !DECIMAL.test(value.ino ?? '')
    || !DECIMAL.test(value.mtimeNs ?? '')
    || !DECIMAL.test(value.ctimeNs ?? '')) {
    throw new Error('Authenticated system OpenSSL config record is invalid');
  }
  return Object.freeze({ ...value });
}

export async function authenticatePinnedRegularSystemInput({ path, pin, testHook } = {}) {
  if (typeof path !== 'string'
    || resolve(path) !== path
    || !exactKeys(pin, ['gid', 'mode', 'nlink', 'sha256', 'size', 'type', 'uid'])
    || !Number.isSafeInteger(pin.uid)
    || pin.uid < 0
    || !Number.isSafeInteger(pin.gid)
    || pin.gid < 0
    || !Number.isSafeInteger(pin.mode)
    || pin.mode < 0
    || pin.mode > 0o777
    || pin.nlink !== 1
    || !Number.isSafeInteger(pin.size)
    || pin.size < 1
    || pin.size > 1_048_576
    || pin.type !== 'regular-file'
    || !SHA256.test(pin.sha256 ?? '')
    || (testHook !== undefined && typeof testHook !== 'function')) {
    throw new Error('Pinned regular system input expectation is invalid');
  }
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    const pathBefore = await lstat(path, { bigint: true });
    if (!before.isFile()
      || before.isSymbolicLink()
      || before.uid !== BigInt(pin.uid)
      || before.gid !== BigInt(pin.gid)
      || (before.mode & 0o7777n) !== BigInt(pin.mode)
      || before.nlink !== BigInt(pin.nlink)
      || before.size !== BigInt(pin.size)
      || !pathBefore.isFile()
      || pathBefore.isSymbolicLink()
      || !sameFileState(before, pathBefore)
      || await realpath(path) !== path) {
      throw new Error('Pinned regular system input identity is invalid');
    }
    const bytes = await handle.readFile();
    if (bytes.length !== pin.size || sha256(bytes) !== pin.sha256) {
      throw new Error('Pinned regular system input bytes are invalid');
    }
    if (testHook) await testHook(Object.freeze({ path }));
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (!sameFileState(before, after)
      || pathAfter.isSymbolicLink()
      || !sameFileState(after, pathAfter)
      || await realpath(path) !== path) {
      throw new Error('Pinned regular system input changed during authentication');
    }
    return Object.freeze({
      ctimeNs: after.ctimeNs.toString(),
      dev: after.dev.toString(),
      gid: Number(after.gid),
      ino: after.ino.toString(),
      mode: Number(after.mode & 0o7777n),
      mtimeNs: after.mtimeNs.toString(),
      nlink: Number(after.nlink),
      path,
      sha256: pin.sha256,
      size: Number(after.size),
      type: 'regular-file',
      uid: Number(after.uid),
    });
  } finally {
    await handle?.close();
  }
}

export async function authenticateSystemOpenSslConfig(testHook) {
  const record = await authenticatePinnedRegularSystemInput({
    path: systemOpenSslConfigPin.path,
    pin: Object.freeze({
      gid: systemOpenSslConfigPin.gid,
      mode: systemOpenSslConfigPin.mode,
      nlink: systemOpenSslConfigPin.nlink,
      sha256: systemOpenSslConfigPin.sha256,
      size: systemOpenSslConfigPin.size,
      type: systemOpenSslConfigPin.type,
      uid: systemOpenSslConfigPin.uid,
    }),
    testHook,
  });
  return assertSystemOpenSslConfigRecord(record);
}

export function systemOpenSslConfigIdentitySha256(value) {
  return sha256(Buffer.from(`${canonicalArchitectureJson(
    assertSystemOpenSslConfigRecord(value),
  )}\n`, 'utf8'));
}

async function readHeldRegularFile(path, maximum, label, exactMode) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    const pathBefore = await lstat(path, { bigint: true });
    if (!before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1n
      || before.uid !== BigInt(process.getuid())
      || (before.mode & 0o022n) !== 0n
      || (exactMode !== undefined && (before.mode & 0o777n) !== BigInt(exactMode))
      || before.size < 1n
      || before.size > BigInt(maximum)
      || pathBefore.isSymbolicLink()
      || !sameFileState(before, pathBefore)) {
      throw new Error(`${label} is not a held trusted regular file`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (bytes.length !== Number(before.size)
      || !sameFileState(before, after)
      || pathAfter.isSymbolicLink()
      || !sameFileState(after, pathAfter)) {
      throw new Error(`${label} changed during its held read`);
    }
    return bytes;
  } finally {
    await handle?.close();
  }
}

export function assertAuthenticatedToolchainReceipt(receiptBytes, lockWitness) {
  if (!Buffer.isBuffer(receiptBytes)
    || receiptBytes.length < 128
    || receiptBytes.length > 64 * 1_024
    || !exactKeys(lockWitness, [
      'cargoArchives',
      'cargoLockSha256',
      'npmArchives',
      'pnpmLocksSha256',
      'systemOpenSslConfig',
    ])
    || !Number.isSafeInteger(lockWitness.cargoArchives)
    || lockWitness.cargoArchives !== 520
    || !Number.isSafeInteger(lockWitness.npmArchives)
    || lockWitness.npmArchives !== 868
    || !SHA256.test(lockWitness.cargoLockSha256 ?? '')
    || !Array.isArray(lockWitness.pnpmLocksSha256)
    || lockWitness.pnpmLocksSha256.length !== 2
    || lockWitness.pnpmLocksSha256.some((digest) => !SHA256.test(digest))) {
    throw new Error('Authenticated toolchain receipt witness is invalid');
  }
  let systemOpenSslConfig;
  try {
    systemOpenSslConfig = assertSystemOpenSslConfigRecord(lockWitness.systemOpenSslConfig);
  } catch {
    throw new Error('Authenticated toolchain receipt witness is invalid');
  }
  let receipt;
  try {
    receipt = JSON.parse(receiptBytes.toString('utf8'));
  } catch {
    throw new Error('Authenticated toolchain receipt is invalid');
  }
  const expected = {
    cargoArchives: lockWitness.cargoArchives,
    cargoLockSha256: lockWitness.cargoLockSha256,
    nodeArchiveSha256: architectureToolchainPins.node.digest,
    nodeExecutableSha256: architectureToolchainPins.node.executableSha256,
    npmArchives: lockWitness.npmArchives,
    pnpmArchiveSha512: architectureToolchainPins.pnpm.digest,
    pnpmLocksSha256: [...lockWitness.pnpmLocksSha256],
    pnpmValidationDuplicateExceptionsSha256: pinnedNpmDuplicateExceptionsSha256,
    pnpmValidationLegacyPaxExceptionsSha256: pinnedNpmLegacyPaxExceptionsSha256,
    rustChannelManifestSha256: architectureToolchainPins.rustChannel.manifestSha256,
    rustComponentsSha256: architectureToolchainPins.rust.map((item) => item.digest),
    schemaVersion: 1,
    systemOpenSslConfig,
    target,
    toolchainPinsSha256: architectureToolchainPinsSha256,
  };
  if (!exactKeys(receipt, receiptKeys)
    || `${canonicalArchitectureJson(receipt)}\n` !== receiptBytes.toString('utf8')
    || canonicalArchitectureJson(receipt) !== canonicalArchitectureJson(expected)) {
    throw new Error('Authenticated toolchain receipt does not match its exact closure pins');
  }
  return Object.freeze(receipt);
}

export function assertAuthenticatedToolchainClosureCounts(value) {
  if (!exactKeys(value, ['cargoArchives', 'npmArchives', 'npmLockRecords'])
    || value.cargoArchives !== 520
    || value.npmArchives !== 868
    || value.npmLockRecords !== 1_005) {
    throw new Error('Authenticated toolchain frozen lock counts are not exact');
  }
  return Object.freeze({ ...value });
}

function seatbeltPath(path) {
  return path.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
}

async function assertFreshPrivateRoot(path, label) {
  const state = await lstat(path);
  if (!state.isDirectory()
    || state.isSymbolicLink()
    || (typeof process.getuid === 'function' && state.uid !== process.getuid())
    || (state.mode & 0o777) !== 0o700
    || await realpath(path) !== path) {
    throw new Error(`${label} is not a fresh canonical private directory`);
  }
}

async function writePrivateFile(path, bytes, mode) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const handle = await open(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    mode,
  );
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function regularFiles(root, current = root, files = []) {
  for (const entry of await readdir(current, { withFileTypes: true })) {
    const path = resolve(current, entry.name);
    if (entry.isSymbolicLink()) throw new Error('Cargo vendor contains a symbolic link');
    if (entry.isDirectory()) {
      await regularFiles(root, path, files);
    } else if (entry.isFile()) {
      files.push(path);
    } else {
      throw new Error('Cargo vendor contains a special entry');
    }
  }
  return files;
}

async function createCargoVendor(sourceRoot, closureRoot, privateArchives) {
  const crates = await parseCargoLock(sourceRoot);
  const vendor = resolve(closureRoot, 'cargo-vendor');
  mkdirSync(vendor, { mode: 0o700 });
  for (const crate of crates) {
    const archive = privateArchives.get(crate.checksum);
    if (!archive) throw new Error(`Cargo archive ${crate.tuple} is absent from the authenticated closure`);
    const prefix = `${crate.name}-${crate.version}`;
    const destination = resolve(vendor, prefix);
    mkdirSync(destination, { mode: 0o700 });
    const inspected = await processTrustedGzipTar(archive, {
      destination,
      label: `Cargo archive ${crate.tuple}`,
      mapEntry: (entry) => {
        if (entry.name === prefix) return false;
        return entry.name.slice(prefix.length + 1);
      },
      maxEntries: 50_000,
      maxExpandedBytes: 512 * MiB,
      requiredPrefix: prefix,
    });
    if (inspected.extracted < 1) throw new Error(`Cargo archive ${crate.tuple} contains no files`);
    const hashes = {};
    for (const path of (await regularFiles(destination)).sort((left, right) => left.localeCompare(right))) {
      const name = relative(destination, path);
      if (name === '.cargo-checksum.json' || name.startsWith('../')) {
        throw new Error(`Cargo archive ${crate.tuple} contains a reserved path`);
      }
      hashes[name] = sha256(await readFile(path));
    }
    await writePrivateFile(
      resolve(destination, '.cargo-checksum.json'),
      Buffer.from(`${canonicalArchitectureJson({ files: hashes, package: crate.checksum })}\n`, 'utf8'),
      0o600,
    );
  }
  return Object.freeze({ crates: crates.length, vendor });
}

function rustArchiveRoot(component) {
  return component.filename.replace(/\.tar\.gz$/u, '');
}

function knownRustMetadata(root, name) {
  return new Set([
    root,
    ...[
      'COPYRIGHT',
      'LICENSE-APACHE',
      'LICENSE-MIT',
      'LICENSE-THIRD-PARTY',
      'README.md',
      'builder-config',
      'components',
      'git-commit-hash',
      'git-commit-info',
      'install.sh',
      'rust-installer-version',
      'version',
    ].map((item) => `${root}/${item}`),
    `${root}/${name}/manifest.in`,
  ]);
}

async function createRustSysroot(closureRoot, archivePaths) {
  const sysroot = resolve(closureRoot, 'rust-toolchain');
  mkdirSync(sysroot, { mode: 0o700 });
  for (const component of architectureToolchainPins.rust) {
    const archive = archivePaths.get(component.digest);
    const root = rustArchiveRoot(component);
    const payload = `${root}/${component.component}`;
    const metadata = knownRustMetadata(root, component.component);
    await processTrustedGzipTar(archive, {
      destination: sysroot,
      label: component.filename,
      mapEntry: (entry) => {
        if (entry.name === payload || metadata.has(entry.name)) return false;
        if (!entry.name.startsWith(`${payload}/`)) {
          throw new Error(`${component.filename} contains undeclared installer metadata`);
        }
        return entry.name.slice(payload.length + 1);
      },
      maxEntries: 1_000,
      maxExpandedBytes: 1_024 * MiB,
      requiredPrefix: root,
    });
  }
  const requiredExecutables = [
    ['cargo', resolve(sysroot, 'bin/cargo')],
    ['rustc', resolve(sysroot, 'bin/rustc')],
    ['rustdoc', resolve(sysroot, 'bin/rustdoc')],
    [
      'rust-objcopy',
      resolve(sysroot, `lib/rustlib/${target}/bin/rust-objcopy`),
    ],
  ];
  for (const [name, path] of requiredExecutables) {
    const state = await lstat(path);
    if (!state.isFile() || state.isSymbolicLink() || (state.mode & 0o111) === 0) {
      throw new Error(`Private Rust sysroot lacks executable ${name}`);
    }
  }
  return sysroot;
}

async function createPinnedNode(closureRoot, archive) {
  const pin = architectureToolchainPins.node;
  const root = resolve(closureRoot, 'node-tool');
  mkdirSync(root, { mode: 0o700 });
  const inspected = await processTrustedGzipTar(archive, {
    allowSafeSymlinks: true,
    destination: root,
    label: pin.filename,
    mapEntry: (entry) => entry.name === pin.member ? 'bin/node' : false,
    maxEntries: 10_000,
    maxExpandedBytes: 256 * MiB,
    requiredPrefix: 'node-v22.23.1-darwin-arm64',
  });
  if (inspected.extracted !== 1) throw new Error('Pinned Node archive did not contain exactly one executable member');
  const node = resolve(root, 'bin/node');
  await verifyRegularFile(node, {
    algorithm: 'sha256',
    digest: pin.executableSha256,
    maxBytes: 256 * MiB,
    minBytes: 10 * MiB,
  }, 'Private pinned Node executable');
  await chmod(node, 0o500);
  return Object.freeze({ node, root });
}

async function createPinnedPnpm(closureRoot, archive) {
  const root = resolve(closureRoot, 'pnpm-tool');
  mkdirSync(root, { mode: 0o700 });
  const inspected = await processTrustedGzipTar(archive, {
    destination: root,
    label: architectureToolchainPins.pnpm.filename,
    mapEntry: (entry) => entry.name === 'package' ? false : entry.name.slice('package/'.length),
    maxEntries: 2_000,
    maxExpandedBytes: 64 * MiB,
    requiredPrefix: 'package',
  });
  if (inspected.extracted !== 901) {
    throw new Error(`Pinned pnpm payload count changed: expected 901, received ${inspected.extracted}`);
  }
  const entry = resolve(root, 'bin/pnpm.cjs');
  const state = await lstat(entry);
  if (!state.isFile() || state.isSymbolicLink() || state.size < 128 || state.size > 16 * 1_024) {
    throw new Error('Private pinned pnpm entry is invalid');
  }
  return Object.freeze({ entry, root });
}

export function pnpmStoreSandbox({ archives, home, node, pnpmRoot, store, temporary, working }) {
  const escaped = (path) => seatbeltPath(path);
  return `(version 1)
  (deny default)
  (import "dyld-support.sb")
  (deny network*)
  (deny process-fork)
  (deny appleevent-send)
  (deny mach-lookup
    (global-name "com.apple.securityd")
    (global-name "com.apple.SecurityServer"))
  (allow process-exec (literal "${escaped(node)}"))
  (allow sysctl-read)
  (allow process-info* (target same-sandbox))
  (allow file-read-metadata file-test-existence (subpath "/"))
  (allow file-read* file-test-existence file-map-executable
    (literal "/dev/null")
    (literal "/dev/random")
    (literal "/dev/urandom")
    (subpath "/Library/Apple/System/Library")
    (subpath "/System/Library")
    (subpath "/usr/lib")
    (literal "${escaped(node)}")
    (subpath "${escaped(archives)}")
    (subpath "${escaped(pnpmRoot)}")
    (subpath "${escaped(home)}")
    (subpath "${escaped(store)}")
    (subpath "${escaped(temporary)}")
    (subpath "${escaped(working)}"))
  (allow file-write* file-link
    (subpath "${escaped(home)}")
    (subpath "${escaped(store)}")
    (subpath "${escaped(temporary)}"))`;
}

async function createPnpmStore(closureRoot, node, pnpm, npmArchives) {
  const store = resolve(closureRoot, 'pnpm-store');
  const working = resolve(closureRoot, 'pnpm-store-control');
  const home = resolve(working, 'home');
  const temporary = resolve(working, 'tmp');
  for (const path of [store, working, home, temporary]) mkdirSync(path, { mode: 0o700 });
  const profile = pnpmStoreSandbox({
    archives: resolve(closureRoot, 'npm-archives'),
    home,
    node,
    pnpmRoot: pnpm.root,
    store,
    temporary,
    working,
  });
  authoriseAuthenticatedNodeSandboxProfile({
    command: node,
    policy: Object.freeze({
      executableFiles: Object.freeze([node]),
      executableRoots: Object.freeze([]),
      kind: 'deny-network',
      metadataFiles: Object.freeze([]),
      metadataRoots: Object.freeze(['/']),
      readableFiles: Object.freeze([
        '/dev/null',
        '/dev/random',
        '/dev/urandom',
        node,
      ]),
      readableRoots: Object.freeze([
        '/Library/Apple/System/Library',
        '/System/Library',
        '/usr/lib',
        resolve(closureRoot, 'npm-archives'),
        pnpm.root,
        home,
        store,
        temporary,
        working,
      ]),
      writableFiles: Object.freeze([]),
      writableRoots: Object.freeze([home, store, temporary]),
    }),
    profile,
  });
  for (let index = 0; index < npmArchives.length; index += 40) {
    const batch = npmArchives.slice(index, index + 40);
    const result = await runOwnedCommand({
      command: node,
      args: [
      pnpm.entry,
      'store',
      'add',
      ...batch,
      `--store-dir=${store}`,
      ],
      cwd: working,
      env: {
        CI: '1',
        COREPACK_ENABLE_DOWNLOAD_PROMPT: '0',
        HOME: home,
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
        PATH: '/usr/bin:/bin',
        TMPDIR: `${temporary}/`,
        XDG_CACHE_HOME: home,
        npm_config_ignore_scripts: 'true',
      },
      label: `Private pnpm store construction batch ${Math.floor(index / 40) + 1}`,
      maxOutputBytes: 4 * MiB,
      sandboxProfile: profile,
      timeoutMs: 10 * 60_000,
    });
    if (result.status !== 0 || result.signal !== null || result.forcedCleanup
      || result.stderr.length > 512 * 1024) {
      throw new Error(`Private pnpm store construction failed at batch ${Math.floor(index / 40) + 1}`);
    }
  }
  return store;
}

export function architectureArchiveDestination(closureRoot, requirement) {
  const namespace = requirement.kind === 'npm'
    ? 'npm-archives'
    : requirement.kind === 'cargo'
      ? 'crate-archives'
    : requirement.kind === 'rust'
      ? 'rust-archives'
      : 'pinned-archives';
  const suffix = requirement.kind === 'npm' ? '.tgz' : '.archive';
  return resolve(closureRoot, namespace, `${requirement.digest}${suffix}`);
}

export function authenticatedToolchainPaths(isolateRoot) {
  const closureRoot = resolve(isolateRoot, 'authenticated-toolchain');
  return Object.freeze({
    cargoBin: resolve(closureRoot, 'rust-toolchain/bin'),
    cargoVendor: resolve(closureRoot, 'cargo-vendor'),
    closureRoot,
    node: resolve(closureRoot, 'node-tool/bin/node'),
    nodeArchive: resolve(
      closureRoot,
      `pinned-archives/${architectureToolchainPins.node.digest}.archive`,
    ),
    pnpmEntry: resolve(closureRoot, 'pnpm-tool/bin/pnpm.cjs'),
    pnpmRoot: resolve(closureRoot, 'pnpm-tool'),
    receipt: resolve(closureRoot, 'receipt.json'),
    rustObjcopy: resolve(
      closureRoot,
      `rust-toolchain/lib/rustlib/${target}/bin/rust-objcopy`,
    ),
    rustToolchain: resolve(closureRoot, 'rust-toolchain'),
    store: resolve(closureRoot, 'pnpm-store'),
  });
}

export async function registerAuthenticatedToolchainNode(nodePath, sourceRoot) {
  configureAuthenticatedNodeSpawn(await createAuthenticatedNodeSpawnConfiguration({
    nodePath,
    snapshot: await snapshotArchitectureSource(sourceRoot),
    sourceRoot,
  }));
}

export async function prepareAuthenticatedToolchain(isolateRoot, sourceRoot) {
  const paths = authenticatedToolchainPaths(isolateRoot);
  mkdirSync(paths.closureRoot, { mode: 0o700 });
  await assertFreshPrivateRoot(paths.closureRoot, 'Authenticated toolchain closure');
  const npm = await parsePnpmLocks(sourceRoot);
  const requirements = [
    architectureToolchainPins.node,
    architectureToolchainPins.pnpm,
    architectureToolchainPins.rustChannel,
    ...architectureToolchainPins.rust,
    ...npm,
    ...await parseCargoLock(sourceRoot),
  ];
  const privateArchives = new Map();
  for (const requirement of requirements) {
    const destination = architectureArchiveDestination(paths.closureRoot, requirement);
    await copyProvisionedArchive(requirement, destination);
    privateArchives.set(requirement.digest, destination);
  }
  const manifestPath = privateArchives.get(architectureToolchainPins.rustChannel.digest);
  assertRustChannelManifestBytes(await readFile(manifestPath));
  const pinnedNode = await createPinnedNode(
    paths.closureRoot,
    privateArchives.get(architectureToolchainPins.node.digest),
  );
  await registerAuthenticatedToolchainNode(pinnedNode.node, sourceRoot);
  const pnpm = await createPinnedPnpm(
    paths.closureRoot,
    privateArchives.get(architectureToolchainPins.pnpm.digest),
  );
  const rustToolchain = await createRustSysroot(paths.closureRoot, privateArchives);
  const cargo = await createCargoVendor(sourceRoot, paths.closureRoot, privateArchives);
  const npmArchivePaths = [];
  for (const archive of npm) {
    const path = privateArchives.get(archive.digest);
    const duplicateException = pinnedNpmDuplicateExceptions.find(
      (entry) => entry.archiveSha512 === archive.digest,
    );
    const legacyPaxException = pinnedNpmLegacyPaxExceptions.find(
      (entry) => entry.archiveSha512 === archive.digest,
    );
    if (duplicateException
      && (duplicateException.package !== archive.name
        || duplicateException.version !== archive.version)) {
      throw new Error('Pinned npm duplicate-exception table does not match the frozen lock record');
    }
    if (legacyPaxException
      && (legacyPaxException.package !== archive.name
        || legacyPaxException.version !== archive.version)) {
      throw new Error('Pinned npm legacy-PAX exception table does not match the frozen lock record');
    }
    const inspected = await processTrustedGzipTar(path, {
      label: `${archive.name}@${archive.version}`,
      maxEntries: 100_000,
      maxExpandedBytes: 512 * MiB,
      pinnedDuplicateArchiveSha512: duplicateException?.archiveSha512,
      pinnedLegacyPaxArchiveSha512: legacyPaxException?.archiveSha512,
      singleTopLevel: true,
    });
    if (inspected.entries < 1) throw new Error(`npm archive ${archive.name}@${archive.version} is empty`);
    npmArchivePaths.push(path);
  }
  const store = await createPnpmStore(paths.closureRoot, pinnedNode.node, pnpm, npmArchivePaths);
  const lockBytes = await Promise.all([
    readFile(resolve(sourceRoot, 'pnpm-lock.yaml')),
    readFile(resolve(sourceRoot, 'sidecar/production/pnpm-lock.yaml')),
    readFile(resolve(sourceRoot, 'src-tauri/Cargo.lock')),
  ]);
  const systemOpenSslConfig = await authenticateSystemOpenSslConfig();
  const receipt = Object.freeze({
    cargoArchives: cargo.crates,
    cargoLockSha256: sha256(lockBytes[2]),
    nodeArchiveSha256: architectureToolchainPins.node.digest,
    nodeExecutableSha256: architectureToolchainPins.node.executableSha256,
    npmArchives: npm.length,
    pnpmArchiveSha512: architectureToolchainPins.pnpm.digest,
    pnpmLocksSha256: lockBytes.slice(0, 2).map(sha256),
    pnpmValidationDuplicateExceptionsSha256: pinnedNpmDuplicateExceptionsSha256,
    pnpmValidationLegacyPaxExceptionsSha256: pinnedNpmLegacyPaxExceptionsSha256,
    rustChannelManifestSha256: architectureToolchainPins.rustChannel.manifestSha256,
    rustComponentsSha256: architectureToolchainPins.rust.map((item) => item.digest),
    schemaVersion: 1,
    systemOpenSslConfig,
    target,
    toolchainPinsSha256: architectureToolchainPinsSha256,
  });
  await writePrivateFile(
    paths.receipt,
    Buffer.from(`${canonicalArchitectureJson(receipt)}\n`, 'utf8'),
    0o600,
  );
  sealPrivateTree(paths.closureRoot);
  return Object.freeze({
    ...paths,
    cargoBin: resolve(rustToolchain, 'bin'),
    cargoVendor: cargo.vendor,
    node: pinnedNode.node,
    pnpmEntry: pnpm.entry,
    pnpmRoot: pnpm.root,
    store,
    systemOpenSslConfig,
  });
}

export async function validateAuthenticatedToolchain(isolateRoot, sourceRoot) {
  const paths = authenticatedToolchainPaths(isolateRoot);
  const root = await lstat(paths.closureRoot);
  if (!root.isDirectory()
    || root.isSymbolicLink()
    || (root.mode & 0o777) !== 0o500
    || await realpath(paths.closureRoot) !== paths.closureRoot) {
    throw new Error('Authenticated toolchain closure is not sealed and canonical');
  }
  await verifyRegularFile(paths.node, {
    algorithm: 'sha256',
    digest: architectureToolchainPins.node.executableSha256,
    maxBytes: 256 * MiB,
    minBytes: 10 * MiB,
  }, 'Authenticated private Node executable');
  const receiptBytes = await readHeldRegularFile(
    paths.receipt,
    64 * 1_024,
    'Authenticated toolchain receipt',
    0o400,
  );
  const locks = await Promise.all([
    readHeldRegularFile(
      resolve(sourceRoot, 'pnpm-lock.yaml'),
      16 * MiB,
      'Frozen root pnpm lock',
    ),
    readHeldRegularFile(
      resolve(sourceRoot, 'sidecar/production/pnpm-lock.yaml'),
      16 * MiB,
      'Frozen sidecar pnpm lock',
    ),
    readHeldRegularFile(
      resolve(sourceRoot, 'src-tauri/Cargo.lock'),
      16 * MiB,
      'Frozen Cargo lock',
    ),
  ]);
  const npmRecords = [
    ...parsePnpmLockBytes(locks[0], 'pnpm-lock.yaml'),
    ...parsePnpmLockBytes(locks[1], 'sidecar/production/pnpm-lock.yaml'),
  ];
  const npmByDigest = new Map();
  for (const record of npmRecords) {
    const existing = npmByDigest.get(record.digest);
    if (existing && existing.url !== record.url) {
      throw new Error('Frozen pnpm locks assign one digest to multiple registry URLs');
    }
    npmByDigest.set(record.digest, record);
  }
  const cargoRecords = parseCargoLockBytes(locks[2], 'src-tauri/Cargo.lock');
  const systemOpenSslConfig = await authenticateSystemOpenSslConfig();
  assertAuthenticatedToolchainClosureCounts({
    cargoArchives: cargoRecords.length,
    npmArchives: npmByDigest.size,
    npmLockRecords: npmRecords.length,
  });
  assertAuthenticatedToolchainReceipt(receiptBytes, {
    cargoArchives: cargoRecords.length,
    cargoLockSha256: sha256(locks[2]),
    npmArchives: npmByDigest.size,
    pnpmLocksSha256: locks.slice(0, 2).map(sha256),
    systemOpenSslConfig,
  });
  for (const executable of [
    paths.pnpmEntry,
    ...['cargo', 'rustc', 'rustdoc'].map((name) => resolve(paths.cargoBin, name)),
    paths.rustObjcopy,
  ]) {
    const state = await lstat(executable);
    if (!state.isFile()
      || state.isSymbolicLink()
      || (state.mode & 0o111) === 0
      || (state.mode & 0o022) !== 0) {
      throw new Error('Authenticated toolchain executable is unsafe');
    }
  }
  return Object.freeze({ ...paths, systemOpenSslConfig });
}

export function createAuthenticatedToolchainContextSha256(
  receiptSha256,
  toolInput,
  systemOpenSslConfig,
) {
  if (!SHA256.test(receiptSha256 ?? '')
    || !exactKeys(toolInput, ['entries', 'inventorySha256', 'leaseSha256'])
    || !Number.isSafeInteger(toolInput.entries)
    || toolInput.entries < 1
    || toolInput.entries > 500_000
    || !SHA256.test(toolInput.inventorySha256 ?? '')
    || !SHA256.test(toolInput.leaseSha256 ?? '')) {
    throw new Error('Authenticated toolchain input witness is invalid');
  }
  const contextBytes = Buffer.from(`${canonicalArchitectureJson({
    receiptSha256,
    schemaVersion: 1,
    systemOpenSslConfigIdentitySha256:
      systemOpenSslConfigIdentitySha256(systemOpenSslConfig),
    toolInputEntries: toolInput.entries,
    toolInputInventorySha256: toolInput.inventorySha256,
    toolInputLeaseSha256: toolInput.leaseSha256,
    toolchainPinsSha256: architectureToolchainPinsSha256,
  })}\n`, 'utf8');
  return sha256(contextBytes);
}

export async function authenticatedToolchainIdentity(isolateRoot, sourceRoot, toolInput) {
  if (!exactKeys(toolInput, ['entries', 'inventorySha256', 'leaseSha256'])
    || !Number.isSafeInteger(toolInput.entries)
    || toolInput.entries < 1
    || toolInput.entries > 500_000
    || !SHA256.test(toolInput.inventorySha256 ?? '')
    || !SHA256.test(toolInput.leaseSha256 ?? '')) {
    throw new Error('Authenticated toolchain input witness is invalid');
  }
  const paths = await validateAuthenticatedToolchain(isolateRoot, sourceRoot);
  const receiptBytes = await readHeldRegularFile(
    paths.receipt,
    64 * 1_024,
    'Authenticated toolchain receipt',
    0o400,
  );
  const receiptSha256 = sha256(receiptBytes);
  return Object.freeze({
    authenticatedToolchainContextSha256: createAuthenticatedToolchainContextSha256(
      receiptSha256,
      toolInput,
      paths.systemOpenSslConfig,
    ),
    authenticatedToolchainReceiptSha256: receiptSha256,
  });
}

export function noForkToolSandbox(paths) {
  const systemOpenSslConfig = assertSystemOpenSslConfigRecord(paths?.systemOpenSslConfig);
  const escaped = (path) => seatbeltPath(path);
  return `(version 1)
  (deny default)
  (import "dyld-support.sb")
  (deny network*)
  (deny process-fork)
  (deny appleevent-send)
  (deny mach-lookup
    (global-name "com.apple.securityd")
    (global-name "com.apple.SecurityServer"))
  (allow process-exec
    (literal "${escaped(paths.node)}")
    (literal "${escaped(resolve(paths.cargoBin, 'cargo'))}"))
  (allow sysctl-read)
  (allow process-info* (target same-sandbox))
  (allow file-read-metadata file-test-existence (subpath "/"))
  (allow file-read* file-test-existence file-map-executable
    (subpath "/Library/Apple/System/Library")
    (subpath "/System/Library")
    (subpath "/usr/lib")
    (literal "${escaped(systemOpenSslConfig.path)}")
    (subpath "${escaped(paths.closureRoot)}"))`;
}

// Each probe is deliberately trivial, but formal packaging invokes it after
// sustained compiler, linker and filesystem activity while process identity
// sampling is also active. Keep the probe finite without making transient host
// load indistinguishable from a toolchain rejection.
const NO_FORK_TOOL_PROBE_TIMEOUT_MS = 120_000;

export async function noForkToolProbe(paths) {
  const expectedSystemOpenSslConfig = assertSystemOpenSslConfigRecord(
    paths?.systemOpenSslConfig,
  );
  const beforeSystemOpenSslConfig = await authenticateSystemOpenSslConfig();
  if (canonicalArchitectureJson(beforeSystemOpenSslConfig)
    !== canonicalArchitectureJson(expectedSystemOpenSslConfig)) {
    throw new Error('Authenticated system OpenSSL config changed before version verification');
  }
  const profile = noForkToolSandbox(paths);
  authoriseAuthenticatedNodeSandboxProfile({
    command: paths.node,
    policy: Object.freeze({
      executableFiles: Object.freeze([
        paths.node,
        resolve(paths.cargoBin, 'cargo'),
      ]),
      executableRoots: Object.freeze([]),
      kind: 'deny-network',
      metadataFiles: Object.freeze([]),
      metadataRoots: Object.freeze(['/']),
      readableFiles: Object.freeze([expectedSystemOpenSslConfig.path]),
      readableRoots: Object.freeze([
        '/Library/Apple/System/Library',
        '/System/Library',
        '/usr/lib',
        paths.closureRoot,
      ]),
      writableFiles: Object.freeze([]),
      writableRoots: Object.freeze([]),
    }),
    profile,
  });
  const environment = {
    HOME: paths.closureRoot,
    LANG: 'en_AU.UTF-8',
    LC_ALL: 'en_AU.UTF-8',
    PATH: `${dirname(paths.node)}:${paths.cargoBin}:/usr/bin:/bin`,
  };
  const node = await runOwnedCommand({
    args: ['-e', "process.stdout.write(`${process.version}\\n`);"],
    command: paths.node,
    cwd: paths.closureRoot,
    env: environment,
    label: 'Authenticated Node version probe',
    maxOutputBytes: 256 * 1_024,
    sandboxProfile: profile,
    timeoutMs: NO_FORK_TOOL_PROBE_TIMEOUT_MS,
  });
  const pnpm = await runOwnedCommand({
    args: [paths.pnpmEntry, '--version'],
    command: paths.node,
    cwd: paths.closureRoot,
    env: environment,
    label: 'Authenticated pnpm version probe',
    maxOutputBytes: 256 * 1_024,
    sandboxProfile: profile,
    timeoutMs: NO_FORK_TOOL_PROBE_TIMEOUT_MS,
  });
  const cargo = spawnSync('/usr/bin/sandbox-exec', ['-p', profile, resolve(paths.cargoBin, 'cargo'), '--version'], {
    cwd: paths.closureRoot,
    encoding: 'utf8',
    env: environment,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: NO_FORK_TOOL_PROBE_TIMEOUT_MS,
  });
  const afterSystemOpenSslConfig = await authenticateSystemOpenSslConfig();
  if (canonicalArchitectureJson(afterSystemOpenSslConfig)
    !== canonicalArchitectureJson(expectedSystemOpenSslConfig)) {
    throw new Error('Authenticated system OpenSSL config changed during version verification');
  }
  if (node.status !== 0 || node.signal !== null || node.forcedCleanup
    || node.stdout.toString('utf8') !== 'v22.23.1\n' || node.stderr.length !== 0
    || pnpm.status !== 0 || pnpm.signal !== null || pnpm.forcedCleanup
    || pnpm.stdout.toString('utf8') !== '9.15.0\n' || pnpm.stderr.length !== 0
    || cargo.status !== 0 || !/^cargo 1\.96\.0 /u.test(cargo.stdout) || cargo.stderr !== '') {
    throw new Error('Authenticated toolchain no-fork version probe failed');
  }
}
