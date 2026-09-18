import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  readlinkSync,
  realpathSync,
} from 'node:fs';
import { arch, platform } from 'node:os';
import { dirname } from 'node:path';
import {
  assertDescriptorHasNoAcl,
  captureSystemDescriptorAclInspector,
  revalidateSystemDescriptorAclInspector,
} from './descriptor-acl.mjs';

const ROOT = '/Library/Developer/CommandLineTools';
const BIN = `${ROOT}/usr/bin`;
const SDK = `${ROOT}/SDKs/MacOSX26.5.sdk`;
const MAX_TREE_ENTRIES = 150_000;
const MAX_TREE_DEPTH = 128;
const MAX_TREE_PATH_BYTES = 4_096;
const MAX_INSPECTOR_OUTPUT_BYTES = 4_096;
// The authenticated CLT contains more than 100,000 entries on the supported
// image. Keep this finite, but allow the complete ACL walk to finish while the
// formal packaging suite is placing sustained load on the same filesystem.
const TREE_INSPECTION_TIMEOUT_MS = 300_000;
// The full-tree inspection establishes the same-UID boundary: every current
// CLT descendant is root-owned, non-writable by group/world and ACL-free, and
// every resolved symlink remains inside that tree. Selected executable bytes
// and SDKSettings.json are pinned below. Privileged Apple/OS replacement of
// other SDK or compiler-resource bytes is an explicit system-trust assumption,
// not a claim that this module hashes the entire CLT tree.
const EXPECTED_SHA256 = Object.freeze({
  ar: 'd26c671be515802ff5a18edde5ca73c6bcaaf87048ef192025f00002be515794',
  clang: 'f30550eab15fdf5ab8c0dc54c52679711241e5d4b636b027e18c09fef531775d',
  dsymutil: '6703190370808e0f75799e805932df4459523fa94801ed8a75bb6b254b064b2b',
  installNameTool: '74910a46431a563a560041fbf64ae922ef458c6c22f14b8c80e2e95ccab42758',
  ld: '28d85b9af18c923db12e0b4ce70b80ee217f2b7cade0e872baa9e8ddc396c08d',
  libtool: '4189d552f0ee7efbd013a56baf1ab8f2865eaa972acc0fc3de6686a7498db393',
  lipo: 'd303f84429d444f62c78da42c10b9fa66575800a62c4acf5e6f3b6888a1b9074',
  llvmNm: '9097f9662024989b801a1448eea2a71a4e916537a595cbaf34d4d051480236f6',
  llvmOtool: '61ff2c63cf68eeeadf9c4700dadb8271740ff4960f98500f30db82b31521c0de',
  otoolClassic: '1f542421b643d10452395bfb80c0b03827724822f56c4d3d8c0c69683861824b',
  sdkSettings: 'f8d005f09381389167f9e0aeaa169bc9e7dff162ef22ca2fd8e98df7ff1acafe',
  strip: '238415edaac7fee82bf54d38d2605c2f294221adc89b253c3e3214b70cb095d9',
});

export const APPLE_TOOLCHAIN_PATHS = Object.freeze({
  ar: `${BIN}/ar`,
  bin: BIN,
  clang: `${BIN}/clang`,
  clangxx: `${BIN}/clang++`,
  dsymutil: `${BIN}/dsymutil`,
  installNameTool: `${BIN}/install_name_tool`,
  ld: `${BIN}/ld`,
  libtool: `${BIN}/libtool`,
  lipo: `${BIN}/lipo`,
  llvmNm: `${BIN}/llvm-nm`,
  llvmOtool: `${BIN}/llvm-otool`,
  nm: `${BIN}/nm`,
  otool: `${BIN}/otool`,
  otoolClassic: `${BIN}/otool-classic`,
  ranlib: `${BIN}/ranlib`,
  root: ROOT,
  sdk: SDK,
  sdkSettings: `${SDK}/SDKSettings.json`,
  strip: `${BIN}/strip`,
});

const RUBY_TREE_INSPECTOR = [
  'series = RUBY_VERSION[/\\A\\d+\\.\\d+/]',
  'base = "/System/Library/Frameworks/Ruby.framework/Versions/#{series}/usr/lib/ruby/#{series}.0"',
  'extensions = Dir[File.join(base, "*", "fiddle.bundle")]',
  'exit 10 unless extensions.length == 1',
  'require extensions[0]',
  'def Fiddle.last_error; Thread.current[:__FIDDLE_LAST_ERROR__]; end',
  'def Fiddle.last_error=(error); Thread.current[:__FIDDLE_LAST_ERROR__] = error; end',
  'library = Fiddle::Handle::DEFAULT',
  'get_acl = Fiddle::Function.new(library["acl_get_file"], [Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT], Fiddle::TYPE_VOIDP)',
  'free_acl = Fiddle::Function.new(library["acl_free"], [Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT)',
  'root = ARGV.fetch(0)',
  'exit 11 unless File.realpath(root) == root',
  'root_state = File.lstat(root)',
  'exit 12 unless root_state.directory? && !root_state.symlink? && root_state.uid == 0',
  'root_device = root_state.dev',
  `max_entries = ${MAX_TREE_ENTRIES}`,
  `max_depth = ${MAX_TREE_DEPTH}`,
  `max_path_bytes = ${MAX_TREE_PATH_BYTES}`,
  'count = 0',
  'stack = [[root, 0]]',
  'until stack.empty?',
  '  path, depth = stack.pop',
  '  exit 13 if depth > max_depth || path.bytesize > max_path_bytes',
  '  state = File.lstat(path)',
  '  count += 1',
  '  exit 14 if count > max_entries || state.uid != 0',
  '  if state.symlink?',
  '    begin',
  '      target = File.realpath(path)',
  '    rescue Errno::ENOENT',
  '      next',
  '    end',
  '    exit 15 unless (target == root || target.start_with?(root + "/")) && File.lstat(target).dev == root_device',
  '    next',
  '  end',
  '  exit 16 unless state.dev == root_device && (state.mode & 0o022) == 0',
  '  Fiddle.last_error = 0',
  '  acl = get_acl.call(path, 0x100)',
  '  if acl.to_i == 0',
  '    exit 17 unless Fiddle.last_error == 2',
  '  else',
  '    free_acl.call(acl)',
  '    exit 18',
  '  end',
  '  if state.directory?',
  '    children = Dir.children(path).sort { |left, right| left.b <=> right.b }',
  '    children.reverse_each { |name| stack << [File.join(path, name), depth + 1] }',
  '  else',
  '    exit 19 unless state.file?',
  '  end',
  'end',
  'STDOUT.write("PIUI_CLT_TREE_OK entries=#{count}\\n")',
].join(';');

const activeAuthorities = new WeakMap();
let cachedTreeIdentity;

function reject(message = 'Apple Command Line Tools authority rejected') {
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

function stateRecord(state) {
  return Object.freeze({
    ctimeNs: state.ctimeNs.toString(10),
    dev: state.dev.toString(10),
    gid: state.gid.toString(10),
    ino: state.ino.toString(10),
    mode: state.mode.toString(10),
    mtimeNs: state.mtimeNs.toString(10),
    nlink: state.nlink.toString(10),
    size: state.size.toString(10),
    uid: state.uid.toString(10),
  });
}

function descriptorSha256(fd, state) {
  if (!state.isFile() || state.size < 1n || state.size > 512n * 1_048_576n) reject();
  const digest = createHash('sha256');
  const buffer = Buffer.allocUnsafe(64 * 1_024);
  let offset = 0;
  const size = Number(state.size);
  try {
    while (offset < size) {
      const count = readSync(fd, buffer, 0, Math.min(buffer.length, size - offset), offset);
      if (count < 1) reject();
      digest.update(buffer.subarray(0, count));
      offset += count;
    }
    return digest.digest('hex');
  } finally {
    buffer.fill(0);
  }
}

function immutableDirectory(path, inspector) {
  if (realpathSync(path) !== path) reject();
  const fd = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY | constants.O_CLOEXEC,
  );
  try {
    const opened = fstatSync(fd, { bigint: true });
    const pathname = lstatSync(path, { bigint: true });
    if (!opened.isDirectory() || opened.isSymbolicLink()
      || opened.uid !== 0n || (opened.mode & 0o022n) !== 0n
      || !sameState(opened, pathname)) reject();
    assertDescriptorHasNoAcl(fd, inspector);
    return Object.freeze({ fd, kind: 'directory', path, state: opened });
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function immutableFile(path, expectedSha256, inspector) {
  if (realpathSync(path) !== path) reject();
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC);
  try {
    const opened = fstatSync(fd, { bigint: true });
    const pathname = lstatSync(path, { bigint: true });
    if (!opened.isFile() || opened.isSymbolicLink() || opened.nlink !== 1n
      || opened.uid !== 0n || (opened.mode & 0o022n) !== 0n
      || !sameState(opened, pathname)
      || descriptorSha256(fd, opened) !== expectedSha256) reject();
    assertDescriptorHasNoAcl(fd, inspector);
    return Object.freeze({
      fd,
      kind: 'file',
      path,
      sha256: expectedSha256,
      state: opened,
    });
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function immutableSymlink(path, expectedTarget) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isSymbolicLink() || before.uid !== 0n
    || readlinkSync(path) !== expectedTarget
    || realpathSync(path) !== realpathSync(`${dirname(path)}/${expectedTarget}`)) reject();
  const after = lstatSync(path, { bigint: true });
  if (!sameState(before, after)) reject();
  return Object.freeze({ kind: 'symlink', link: expectedTarget, path, state: before });
}

function revalidateLease(lease, inspector) {
  if (lease.kind === 'symlink') {
    const current = lstatSync(lease.path, { bigint: true });
    if (!sameState(lease.state, current)
      || readlinkSync(lease.path) !== lease.link
      || realpathSync(lease.path) !== realpathSync(`${dirname(lease.path)}/${lease.link}`)) reject();
    return;
  }
  const descriptor = fstatSync(lease.fd, { bigint: true });
  const pathname = lstatSync(lease.path, { bigint: true });
  if (!sameState(lease.state, descriptor)
    || !sameState(lease.state, pathname)
    || realpathSync(lease.path) !== lease.path) reject();
  if (lease.kind === 'file' && descriptorSha256(lease.fd, descriptor) !== lease.sha256) reject();
  assertDescriptorHasNoAcl(lease.fd, inspector);
}

function runTreeInspection(inspector) {
  revalidateSystemDescriptorAclInspector(inspector);
  const before = lstatSync(ROOT, { bigint: true });
  const result = spawnSync('/usr/bin/ruby', [
    '--disable=gems,rubyopt,did_you_mean',
    '-C/',
    '-e',
    RUBY_TREE_INSPECTOR,
    ROOT,
  ], {
    encoding: 'utf8',
    env: { PATH: '/usr/bin:/bin' },
    maxBuffer: MAX_INSPECTOR_OUTPUT_BYTES,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: TREE_INSPECTION_TIMEOUT_MS,
  });
  const after = lstatSync(ROOT, { bigint: true });
  revalidateSystemDescriptorAclInspector(inspector);
  const match = result.stdout?.match(/^PIUI_CLT_TREE_OK entries=([1-9][0-9]{0,6})\n$/u);
  if (result.error || result.status !== 0 || result.signal !== null
    || result.stderr !== '' || !match || !sameState(before, after)) reject();
  const entries = Number(match[1]);
  if (!Number.isSafeInteger(entries) || entries < 1 || entries > MAX_TREE_ENTRIES) reject();
  return Object.freeze({ entries, root: stateRecord(after) });
}

export function assertRootOwnedImmutableAncestorChain(path, boundary = '/Library') {
  if (typeof path !== 'string' || typeof boundary !== 'string'
    || !path.startsWith(`${boundary}/`) || realpathSync(path) !== path) reject();
  const inspector = captureSystemDescriptorAclInspector();
  const leases = [];
  try {
    let current = path;
    const chain = [];
    while (current !== boundary) {
      chain.push(current);
      current = dirname(current);
      if (current === '/' || !current.startsWith(boundary)) reject();
    }
    chain.push(boundary);
    chain.reverse();
    for (const candidate of chain) leases.push(immutableDirectory(candidate, inspector));
    for (const lease of leases) revalidateLease(lease, inspector);
    return true;
  } finally {
    for (const lease of leases) closeSync(lease.fd);
  }
}

export function appleToolchainBuildEnvironment() {
  return Object.freeze({
    AR: APPLE_TOOLCHAIN_PATHS.ar,
    'AR_aarch64-apple-darwin': APPLE_TOOLCHAIN_PATHS.ar,
    AR_aarch64_apple_darwin: APPLE_TOOLCHAIN_PATHS.ar,
    CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER: APPLE_TOOLCHAIN_PATHS.clang,
    CC: APPLE_TOOLCHAIN_PATHS.clang,
    'CC_aarch64-apple-darwin': APPLE_TOOLCHAIN_PATHS.clang,
    CC_aarch64_apple_darwin: APPLE_TOOLCHAIN_PATHS.clang,
    CXX: APPLE_TOOLCHAIN_PATHS.clangxx,
    'CXX_aarch64-apple-darwin': APPLE_TOOLCHAIN_PATHS.clangxx,
    CXX_aarch64_apple_darwin: APPLE_TOOLCHAIN_PATHS.clangxx,
    DEVELOPER_DIR: APPLE_TOOLCHAIN_PATHS.root,
    DSYMUTIL: APPLE_TOOLCHAIN_PATHS.dsymutil,
    INSTALL_NAME_TOOL: APPLE_TOOLCHAIN_PATHS.installNameTool,
    LD: APPLE_TOOLCHAIN_PATHS.ld,
    LIBTOOL: APPLE_TOOLCHAIN_PATHS.libtool,
    LIPO: APPLE_TOOLCHAIN_PATHS.lipo,
    MACOSX_DEPLOYMENT_TARGET: '13.0',
    NM: APPLE_TOOLCHAIN_PATHS.nm,
    OTOOL: APPLE_TOOLCHAIN_PATHS.otool,
    RANLIB: APPLE_TOOLCHAIN_PATHS.ranlib,
    SDKROOT: APPLE_TOOLCHAIN_PATHS.sdk,
    STRIP: APPLE_TOOLCHAIN_PATHS.strip,
  });
}

export function captureAppleToolchainAuthority() {
  if (platform() !== 'darwin' || arch() !== 'arm64'
    || typeof process.getuid !== 'function' || typeof process.geteuid !== 'function'
    || process.getuid() < 1 || process.getuid() !== process.geteuid()) reject();
  const inspector = captureSystemDescriptorAclInspector();
  const leases = [];
  try {
    for (const path of [
      '/',
      '/Library',
      '/Library/Developer',
      ROOT,
      `${ROOT}/usr`,
      BIN,
      `${ROOT}/SDKs`,
      SDK,
    ]) {
      leases.push(immutableDirectory(path, inspector));
    }
    leases.push(
      immutableFile(APPLE_TOOLCHAIN_PATHS.clang, EXPECTED_SHA256.clang, inspector),
      immutableFile(APPLE_TOOLCHAIN_PATHS.ar, EXPECTED_SHA256.ar, inspector),
      immutableFile(APPLE_TOOLCHAIN_PATHS.dsymutil, EXPECTED_SHA256.dsymutil, inspector),
      immutableFile(
        APPLE_TOOLCHAIN_PATHS.installNameTool,
        EXPECTED_SHA256.installNameTool,
        inspector,
      ),
      immutableFile(APPLE_TOOLCHAIN_PATHS.ld, EXPECTED_SHA256.ld, inspector),
      immutableFile(APPLE_TOOLCHAIN_PATHS.libtool, EXPECTED_SHA256.libtool, inspector),
      immutableFile(APPLE_TOOLCHAIN_PATHS.lipo, EXPECTED_SHA256.lipo, inspector),
      immutableFile(APPLE_TOOLCHAIN_PATHS.llvmNm, EXPECTED_SHA256.llvmNm, inspector),
      immutableFile(APPLE_TOOLCHAIN_PATHS.llvmOtool, EXPECTED_SHA256.llvmOtool, inspector),
      immutableFile(
        APPLE_TOOLCHAIN_PATHS.otoolClassic,
        EXPECTED_SHA256.otoolClassic,
        inspector,
      ),
      immutableFile(APPLE_TOOLCHAIN_PATHS.strip, EXPECTED_SHA256.strip, inspector),
      immutableFile(
        APPLE_TOOLCHAIN_PATHS.sdkSettings,
        EXPECTED_SHA256.sdkSettings,
        inspector,
      ),
      immutableSymlink(APPLE_TOOLCHAIN_PATHS.clangxx, 'clang'),
      immutableSymlink(APPLE_TOOLCHAIN_PATHS.nm, 'llvm-nm'),
      immutableSymlink(APPLE_TOOLCHAIN_PATHS.otool, 'llvm-otool'),
      immutableSymlink(APPLE_TOOLCHAIN_PATHS.ranlib, 'libtool'),
    );
    const currentRoot = stateRecord(lstatSync(ROOT, { bigint: true }));
    if (!cachedTreeIdentity
      || JSON.stringify(cachedTreeIdentity.root) !== JSON.stringify(currentRoot)) {
      cachedTreeIdentity = runTreeInspection(inspector);
    }
    for (const lease of leases) revalidateLease(lease, inspector);
    const authority = Object.freeze({
      entries: cachedTreeIdentity.entries,
      root: ROOT,
      schemaVersion: 1,
    });
    activeAuthorities.set(authority, Object.freeze({ inspector, leases: Object.freeze(leases) }));
    return authority;
  } catch (error) {
    for (const lease of leases) {
      if (lease.kind !== 'symlink') {
        try { closeSync(lease.fd); } catch { /* retain the primary rejection */ }
      }
    }
    throw error;
  }
}

export function revalidateAppleToolchainAuthority(authority) {
  const record = activeAuthorities.get(authority);
  if (!record) reject();
  revalidateSystemDescriptorAclInspector(record.inspector);
  for (const lease of record.leases) revalidateLease(lease, record.inspector);
  return authority;
}

export function releaseAppleToolchainAuthority(authority) {
  const record = activeAuthorities.get(authority);
  if (!record) return;
  activeAuthorities.delete(authority);
  let failure;
  for (const lease of record.leases) {
    if (lease.kind === 'symlink') continue;
    try {
      closeSync(lease.fd);
    } catch (error) {
      failure ??= error;
    }
  }
  if (failure) throw failure;
}
