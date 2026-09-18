#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import {
  chmod,
  cp,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  realpath,
} from 'node:fs/promises';
import { basename, dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import {
  A28_MAX_POLICY_BYTES,
  A28_POLICY_PIN_PATH,
  assertA28PolicyPin,
  assertA28WitnessAppInspection,
  canonicalA28Json,
  canonicalA28Line,
  parseCanonicalA28Line,
  sha256A28,
} from './contract.mjs';
import { readHeldCanonicalA28File } from './verify.mjs';
import {
  APPLE_TOOLCHAIN_PATHS,
  appleToolchainBuildEnvironment,
  captureAppleToolchainAuthority,
  releaseAppleToolchainAuthority,
  revalidateAppleToolchainAuthority,
} from '../apple-toolchain-trust.mjs';

const root = resolve(import.meta.dirname, '../..');
const sourceRoot = resolve(root, 'scripts/a28-witness');
const sourceNames = Object.freeze([
  'A28ProcessIdentity.m',
  'A28RootLauncher.m',
  'A28Witness.entitlements.in',
  'A28WitnessApp.m',
  'Info.plist',
]);
const descriptorCodesignRuby = String.raw`
require 'fiddle/import'

module A28DescriptorCwd
  extend Fiddle::Importer
  dlload Fiddle::Handle::DEFAULT
  extern 'int fchdir(int)'
end

def fail_closed
  exit 90
end

def safe_relative(path)
  return false unless path.is_a?(String) && !path.empty? && !path.start_with?('/')
  parts = path.split('/', -1)
  !path.include?("\0") && parts.none? { |part| part.empty? || part == '.' || part == '..' }
end

def held_io(number)
  IO.for_fd(number, autoclose: false)
rescue StandardError
  fail_closed
end

def same_object(held, pathname, kind)
  state = held.stat
  path_state = File.lstat(pathname)
  expected_type = kind == 'directory' ? state.directory? : state.file?
  path_type = kind == 'directory' ? path_state.directory? : path_state.file?
  fail_closed unless expected_type && path_type && !path_state.symlink?
  fields = %i[dev ino uid gid mode nlink]
  fail_closed unless fields.all? { |field| state.public_send(field) == path_state.public_send(field) }
  fail_closed unless state.uid == Process.euid && (state.mode & 0o7022).zero?
end

mode, certificate_selector, target, entitlements = ARGV
fail_closed unless %w[
  app-sign app-preflight root-sign root-preflight verify display
].include?(mode)
fail_closed if %w[app-sign root-sign].include?(mode) &&
  (!certificate_selector.is_a?(String) ||
   !certificate_selector.match?(/\A[0-9a-fA-F]{40}\z/))
fail_closed unless safe_relative(target) && target.start_with?('build/')
workspace = held_io(3)
build_root = held_io(4)
target_parent = held_io(5)
target_handle = held_io(6)
fail_closed unless workspace.stat.directory? && workspace.stat.uid == Process.euid
fail_closed unless A28DescriptorCwd.fchdir(3).zero?
same_object(build_root, 'build', 'directory')
same_object(target_parent, File.dirname(target), 'directory')
same_object(target_handle, target, %w[app-sign app-preflight].include?(mode) ?
  'directory' : (%w[root-sign root-preflight].include?(mode) ? 'file' :
  (target_handle.stat.directory? ? 'directory' : 'file')))

arguments = case mode
when 'app-sign', 'app-preflight'
  fail_closed unless safe_relative(entitlements) && entitlements.start_with?('build/source/')
  entitlements_parent = held_io(7)
  entitlements_handle = held_io(8)
  same_object(entitlements_parent, File.dirname(entitlements), 'directory')
  same_object(entitlements_handle, entitlements, 'file')
  exit 0 if mode == 'app-preflight'
  ['--force', '--sign', certificate_selector, '--options', 'runtime', '--timestamp',
   '--entitlements', entitlements, target]
when 'root-sign', 'root-preflight'
  exit 0 if mode == 'root-preflight'
  ['--force', '--sign', certificate_selector, '--identifier', 'au.com.piui.a28-root-launcher',
   '--options', 'runtime', '--timestamp', target]
when 'verify'
  ['--verify', '--strict', '--all-architectures', '--verbose=4', target]
when 'display'
  ['--display', '--verbose=4', target]
else
  fail_closed
end

exec({ 'LANG' => 'C', 'LC_ALL' => 'C', 'PATH' => '/usr/bin:/bin' },
     '/usr/bin/codesign', *arguments, close_others: true)
`;
const descriptorInspectorRuby = String.raw`
require 'fiddle/import'

module A28DescriptorCwd
  extend Fiddle::Importer
  dlload Fiddle::Handle::DEFAULT
  extern 'int fchdir(int)'
end

def fail_closed
  exit 90
end

def safe_relative(path)
  return false unless path.is_a?(String) && !path.empty? && !path.start_with?('/')
  parts = path.split('/', -1)
  !path.include?("\0") && parts.none? { |part| part.empty? || part == '.' || part == '..' }
end

def held_io(number)
  IO.for_fd(number, autoclose: false)
rescue StandardError
  fail_closed
end

def same_object(held, pathname, kind)
  state = held.stat
  path_state = File.lstat(pathname)
  expected_type = kind == 'directory' ? state.directory? : state.file?
  path_type = kind == 'directory' ? path_state.directory? : path_state.file?
  fail_closed unless expected_type && path_type && !path_state.symlink?
  fields = %i[dev ino uid gid mode nlink size]
  fail_closed unless fields.all? { |field| state.public_send(field) == path_state.public_send(field) }
  fail_closed unless state.uid == Process.euid && (state.mode & 0o7022).zero?
end

inspector, application, bundle_id, team_id, requirement, preflight = ARGV
fail_closed unless preflight.nil? || preflight == '--preflight'
fail_closed unless safe_relative(inspector) && inspector.start_with?('build/')
fail_closed unless safe_relative(application) && application.start_with?('build/')
workspace = held_io(3)
build_root = held_io(4)
inspector_parent = held_io(5)
inspector_handle = held_io(6)
application_parent = held_io(7)
application_handle = held_io(8)
fail_closed unless workspace.stat.directory? && workspace.stat.uid == Process.euid
fail_closed unless A28DescriptorCwd.fchdir(3).zero?
same_object(build_root, 'build', 'directory')
same_object(inspector_parent, File.dirname(inspector), 'directory')
same_object(inspector_handle, inspector, 'file')
fail_closed unless (inspector_handle.stat.mode & 0o111) != 0
same_object(application_parent, File.dirname(application), 'directory')
same_object(application_handle, application, 'directory')
exit 0 if preflight == '--preflight'

exec({ 'LANG' => 'C', 'LC_ALL' => 'C', 'PATH' => '/usr/bin:/bin' },
     inspector, '--app', application, '--bundle-id', bundle_id,
     '--team-id', team_id, '--reported-requirement', requirement,
     close_others: true)
`;
const exclusivePublishRuby = String.raw`
require 'fiddle/import'

module A28Publish
  extend Fiddle::Importer
  dlload Fiddle::Handle::DEFAULT
  extern 'int renameatx_np(int, const char*, int, const char*, unsigned int)'
  extern 'int fchdir(int)'
end

def fail_closed
  exit 90
end

def safe_name(name)
  name.is_a?(String) && !name.empty? && name != '.' && name != '..' &&
    !name.include?("\0") && !name.include?('/') && name.bytesize <= 255
end

def held_io(number)
  IO.for_fd(number, autoclose: false)
rescue StandardError
  fail_closed
end

def identity(state)
  %i[dev ino uid gid mode nlink].map { |field| state.public_send(field) }
end

source_name, destination_name = ARGV
fail_closed unless safe_name(source_name) && safe_name(destination_name)
source_parent = held_io(3)
destination_parent = held_io(4)
source = held_io(5)
fail_closed unless source_parent.stat.directory? && destination_parent.stat.directory?
fail_closed unless A28Publish.fchdir(3).zero?
fail_closed unless identity(source.stat) == identity(File.lstat(source_name))
fail_closed unless A28Publish.fchdir(4).zero?
begin
  File.lstat(destination_name)
  fail_closed
rescue Errno::ENOENT
end
fail_closed unless A28Publish.renameatx_np(3, source_name, 4, destination_name, 4).zero?
fail_closed unless A28Publish.fchdir(3).zero?
begin
  File.lstat(source_name)
  fail_closed
rescue Errno::ENOENT
end
fail_closed unless A28Publish.fchdir(4).zero?
fail_closed unless identity(source.stat) == identity(File.lstat(destination_name))
`;
const descriptorMetadataRuby = String.raw`
require 'fiddle/import'

module A28DescriptorMetadata
  extend Fiddle::Importer
  dlload Fiddle::Handle::DEFAULT
  extern 'void* acl_get_fd_np(int, int)'
  extern 'int acl_free(void*)'
  extern 'long flistxattr(int, void*, unsigned long, int)'
  extern 'long fgetxattr(int, const char*, void*, unsigned long, unsigned int, int)'
  extern 'int fgetattrlist(int, void*, void*, unsigned long, unsigned long)'
end

def fail_closed
  exit 90
end

descriptor = 3
Fiddle.last_error = 0
acl = A28DescriptorMetadata.acl_get_fd_np(descriptor, 0x00000100)
if acl.to_i.zero?
  fail_closed unless Fiddle.last_error == Errno::ENOENT::Errno
else
  A28DescriptorMetadata.acl_free(acl)
  fail_closed
end

attribute_list = [5, 0, 0x00040000, 0, 0, 0, 0].pack('SSLLLLL')
attribute_buffer = Fiddle::Pointer.malloc(8)
fail_closed unless A28DescriptorMetadata.fgetattrlist(
  descriptor,
  attribute_list,
  attribute_buffer,
  8,
  0
).zero?
attribute_length, flags = attribute_buffer.to_s(8).unpack('LL')
fail_closed unless attribute_length == 8

names_length = A28DescriptorMetadata.flistxattr(descriptor, 0, 0, 0)
fail_closed if names_length.negative? || names_length > 1_048_576
names = []
unless names_length.zero?
  names_buffer = Fiddle::Pointer.malloc(names_length)
  fail_closed unless A28DescriptorMetadata.flistxattr(
    descriptor,
    names_buffer,
    names_length,
    0
  ) == names_length
  names_bytes = names_buffer.to_s(names_length)
  fail_closed unless names_bytes.end_with?("\0")
  names = names_bytes.split("\0", -1)
  fail_closed unless names.pop == ''
  fail_closed if names.any?(&:empty?) || names.uniq.length != names.length
end

records = names.map do |name|
  value_length = A28DescriptorMetadata.fgetxattr(
    descriptor,
    name,
    0,
    0,
    0,
    0
  )
  fail_closed if value_length.negative? || value_length > 16_777_216
  value = ''.b
  unless value_length.zero?
    value_buffer = Fiddle::Pointer.malloc(value_length)
    fail_closed unless A28DescriptorMetadata.fgetxattr(
      descriptor,
      name,
      value_buffer,
      value_length,
      0,
      0
    ) == value_length
    value = value_buffer.to_s(value_length)
  end
  [name.b.unpack1('H*'), value.unpack1('H*')]
end
fail_closed unless records.map(&:first).uniq.length == records.length
records.sort_by!(&:first)
STDOUT.write("flags=#{flags}\n")
records.each { |name, value| STDOUT.write("#{name}=#{value}\n") }
`;
const privateWorkspaceStates = new WeakMap();
const outputPublicationStates = new WeakMap();
const heldTreeStates = new WeakMap();

function reject(message = 'A.28 witness build rejected') {
  throw new Error(message);
}

function processEffectiveUid() {
  if (typeof process.getuid !== 'function'
    || typeof process.geteuid !== 'function') reject();
  const uid = process.getuid();
  const effectiveUid = process.geteuid();
  if (!Number.isSafeInteger(uid)
    || uid < 0
    || effectiveUid !== uid) reject();
  return effectiveUid;
}

function bigintStatIdentity(item) {
  return Object.freeze({
    ctimeNs: item.ctimeNs.toString(),
    dev: item.dev.toString(),
    gid: item.gid.toString(),
    ino: item.ino.toString(),
    mode: Number(item.mode & 0o7777n),
    mtimeNs: item.mtimeNs.toString(),
    nlink: item.nlink.toString(),
    size: item.size.toString(),
    uid: item.uid.toString(),
  });
}

const sameDirectoryIdentity = (left, right, fields) =>
  fields.every((field) => left[field] === right[field]);

const provenanceXattrHex = Buffer.from(
  'com.apple.provenance',
  'utf8',
).toString('hex');

function readDescriptorMetadata(handle) {
  const output = run('/usr/bin/ruby', [
    '--disable-gems',
    '-e',
    descriptorMetadataRuby,
  ], {
    stdio: ['ignore', 'pipe', 'pipe', handle.fd],
    timeout: 30_000,
  }).stdout.toString('utf8');
  const lines = output.split('\n');
  if (lines.pop() !== '' || !/^flags=[0-9]+$/u.test(lines[0] ?? '')) reject();
  const flags = Number.parseInt(lines.shift().slice('flags='.length), 10);
  if (!Number.isSafeInteger(flags) || flags < 0 || flags > 0xffff_ffff) reject();
  const xattrs = lines.map((line) => {
    const match = /^([0-9a-f]+)=([0-9a-f]*)$/u.exec(line);
    if (match === null
      || match[1].length % 2 !== 0
      || match[2].length % 2 !== 0) reject();
    return Object.freeze({ nameHex: match[1], valueHex: match[2] });
  });
  if (new Set(xattrs.map(({ nameHex }) => nameHex)).size !== xattrs.length
    || canonicalA28Json(xattrs)
      !== canonicalA28Json([...xattrs].sort((left, right) =>
        left.nameHex.localeCompare(right.nameHex, 'en')))) reject();
  return Object.freeze({
    flags,
    serialisedXattrs: canonicalA28Json(xattrs),
    xattrs: Object.freeze(xattrs),
  });
}

function buildMetadataPolicy(metadata) {
  if (metadata.flags !== 0
    || metadata.xattrs.length > 1
    || (metadata.xattrs.length === 1
      && metadata.xattrs[0].nameHex !== provenanceXattrHex)) {
    reject('A.28 private build metadata is not permitted');
  }
  return Object.freeze({
    provenanceValueHex: metadata.xattrs[0]?.valueHex,
  });
}

function assertBuildDescriptorMetadata(metadata, policy) {
  if (metadata.flags !== 0
    || metadata.xattrs.length > 1
    || (metadata.xattrs.length === 1
      && (metadata.xattrs[0].nameHex !== provenanceXattrHex
        || metadata.xattrs[0].valueHex !== policy.provenanceValueHex))) {
    reject('A.28 held build metadata is not permitted');
  }
}

function assertPathHasNoExtendedAcl(path) {
  const permissions = run('/bin/ls', ['-lde', path])
    .stdout.toString('utf8').split(/\s/u, 1)[0];
  if (typeof permissions !== 'string'
    || permissions.length < 10
    || permissions.endsWith('+')) reject();
}

async function openDirectoryLease(path, {
  allowedUids,
  exactMode,
  pinnedFields,
}) {
  let handle;
  try {
    if (!isAbsolute(path) || await realpath(path) !== path) reject();
    handle = await open(
      path,
      constants.O_RDONLY
        | constants.O_NOFOLLOW
        | (constants.O_DIRECTORY ?? 0),
    );
    const [held, pathname] = await Promise.all([
      handle.stat({ bigint: true }),
      lstat(path, { bigint: true }),
    ]);
    const heldIdentity = bigintStatIdentity(held);
    const pathnameIdentity = bigintStatIdentity(pathname);
    const metadata = readDescriptorMetadata(handle);
    const identityFields = ['dev', 'gid', 'ino', 'mode', 'uid'];
    if (!held.isDirectory()
      || !pathname.isDirectory()
      || pathname.isSymbolicLink()
      || !sameDirectoryIdentity(heldIdentity, pathnameIdentity, identityFields)
      || !allowedUids.has(heldIdentity.uid)
      || (exactMode !== undefined && heldIdentity.mode !== exactMode)
      || (heldIdentity.mode & 0o7022) !== 0) reject();
    return Object.seal({
      baseline: heldIdentity,
      handle,
      metadata,
      path,
      pinnedFields: Object.freeze([...pinnedFields]),
    });
  } catch (error) {
    await handle?.close();
    throw error;
  }
}

async function assertDirectoryLease(lease) {
  const [held, pathname, canonicalPath] = await Promise.all([
    lease.handle.stat({ bigint: true }),
    lstat(lease.path, { bigint: true }),
    realpath(lease.path),
  ]);
  const heldIdentity = bigintStatIdentity(held);
  const pathnameIdentity = bigintStatIdentity(pathname);
  const metadata = readDescriptorMetadata(lease.handle);
  const identityFields = ['dev', 'gid', 'ino', 'mode', 'uid'];
  if (canonicalPath !== lease.path
    || !held.isDirectory()
    || !pathname.isDirectory()
    || pathname.isSymbolicLink()
    || !sameDirectoryIdentity(heldIdentity, pathnameIdentity, identityFields)
    || !sameDirectoryIdentity(
      heldIdentity,
      lease.baseline,
      lease.pinnedFields,
    )
    || metadata.flags !== lease.metadata.flags
    || metadata.serialisedXattrs !== lease.metadata.serialisedXattrs) {
    reject('A.28 private build workspace lease changed');
  }
}

async function refreshDirectoryLeaseAfterExpectedMutation(lease) {
  const [held, pathname, canonicalPath] = await Promise.all([
    lease.handle.stat({ bigint: true }),
    lstat(lease.path, { bigint: true }),
    realpath(lease.path),
  ]);
  const heldIdentity = bigintStatIdentity(held);
  const pathnameIdentity = bigintStatIdentity(pathname);
  const metadata = readDescriptorMetadata(lease.handle);
  const stableFields = ['dev', 'gid', 'ino', 'mode', 'uid'];
  if (canonicalPath !== lease.path
    || !held.isDirectory()
    || !pathname.isDirectory()
    || pathname.isSymbolicLink()
    || !sameDirectoryIdentity(heldIdentity, pathnameIdentity, stableFields)
    || !sameDirectoryIdentity(heldIdentity, lease.baseline, stableFields)
    || metadata.flags !== lease.metadata.flags
    || metadata.serialisedXattrs !== lease.metadata.serialisedXattrs) reject();
  lease.baseline = heldIdentity;
}

function ancestorPaths(path) {
  const paths = [];
  let current = path;
  for (;;) {
    paths.push(current);
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  paths.reverse();
  return paths;
}

async function canonicalDarwinTemporaryRoot() {
  const reported = run('/usr/bin/getconf', ['DARWIN_USER_TEMP_DIR'])
    .stdout.toString('utf8').trim();
  if (!reported.startsWith('/') || reported.includes('\0')) reject();
  const canonical = await realpath(reported);
  if (!canonical.startsWith('/private/var/folders/')) reject();
  return canonical;
}

async function assertMissingPath(path) {
  try {
    await lstat(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  reject('A.28 output destination already exists');
}

export async function createA28OutputPublicationLease(requestedRoot) {
  if (!isAbsolute(requestedRoot)
    || resolve(requestedRoot) !== requestedRoot
    || dirname(requestedRoot) === requestedRoot
    || basename(requestedRoot) !== basename(resolve(requestedRoot))
    || /[\0\r\n]/u.test(requestedRoot)) reject();
  const parentPath = dirname(requestedRoot);
  if (await realpath(parentPath) !== parentPath) reject();
  const effectiveUid = processEffectiveUid();
  const allowedUids = new Set(['0', String(effectiveUid)]);
  const leases = [];
  try {
    for (const path of ancestorPaths(parentPath)) {
      leases.push(await openDirectoryLease(path, {
        allowedUids,
        exactMode: undefined,
        pinnedFields: ['dev', 'ino', 'mode', 'uid', 'gid'],
      }));
    }
    const lease = Object.freeze({
      destinationName: basename(requestedRoot),
      parentPath,
      requestedRoot,
    });
    outputPublicationStates.set(lease, Object.seal({
      closed: false,
      directoryLeases: Object.freeze(leases),
      publishedIdentity: undefined,
    }));
    await assertA28OutputPublicationLease(lease);
    return lease;
  } catch (error) {
    const closures = await Promise.allSettled(
      leases.reverse().map(({ handle }) => handle.close()),
    );
    const closeFailure = closures.find((result) => result.status === 'rejected');
    if (closeFailure) throw closeFailure.reason;
    throw error;
  }
}

export async function assertA28OutputPublicationLease(lease) {
  const state = outputPublicationStates.get(lease);
  if (!state || state.closed) reject('A.28 output publication lease is invalid');
  for (const directoryLease of state.directoryLeases) {
    await assertDirectoryLease(directoryLease);
  }
  if (state.publishedIdentity === undefined) {
    await assertMissingPath(lease.requestedRoot);
    return;
  }
  const destination = await lstat(lease.requestedRoot, { bigint: true });
  const destinationIdentity = bigintStatIdentity(destination);
  if (!destination.isDirectory()
    || destination.isSymbolicLink()
    || !sameDirectoryIdentity(
      destinationIdentity,
      state.publishedIdentity,
      ['dev', 'ino', 'mode', 'uid', 'gid'],
    )) reject('A.28 published output identity changed');
}

export async function closeA28OutputPublicationLease(lease) {
  const state = outputPublicationStates.get(lease);
  if (!state || state.closed) reject('A.28 output publication lease is invalid');
  state.closed = true;
  const closures = await Promise.allSettled(
    [...state.directoryLeases].reverse().map(({ handle }) => handle.close()),
  );
  const closeFailure = closures.find((result) => result.status === 'rejected');
  if (closeFailure) throw closeFailure.reason;
}

export async function createPrivateA28BuildWorkspace({ publicationLease } = {}) {
  if (publicationLease !== undefined) {
    await assertA28OutputPublicationLease(publicationLease);
  }
  const effectiveUid = processEffectiveUid();
  const allowedUids = new Set(['0', String(effectiveUid)]);
  const temporaryRoot = await canonicalDarwinTemporaryRoot();
  const leases = [];
  try {
    for (const path of ancestorPaths(temporaryRoot)) {
      leases.push(await openDirectoryLease(path, {
        allowedUids: path === temporaryRoot
          ? new Set([String(effectiveUid)])
          : allowedUids,
        exactMode: path === temporaryRoot ? 0o700 : undefined,
        pinnedFields: ['dev', 'ino', 'mode', 'uid', 'gid'],
      }));
    }
    for (const directoryLease of leases) {
      await assertDirectoryLease(directoryLease);
    }
    const builderParentPath = await mkdtemp(resolve(
      temporaryRoot,
      'piui-a28-witness-builder.',
    ));
    for (const directoryLease of leases) {
      await assertDirectoryLease(directoryLease);
    }
    const workspacePath = await mkdtemp(resolve(builderParentPath, 'workspace.'));
    const buildRootPath = resolve(workspacePath, 'build');
    await mkdir(buildRootPath, { mode: 0o700 });
    for (const directoryLease of leases) {
      await assertDirectoryLease(directoryLease);
    }
    leases.push(await openDirectoryLease(builderParentPath, {
      allowedUids: new Set([String(effectiveUid)]),
      exactMode: 0o700,
      pinnedFields: ['ctimeNs', 'dev', 'ino', 'mode', 'nlink', 'uid', 'gid'],
    }));
    leases.push(await openDirectoryLease(workspacePath, {
      allowedUids: new Set([String(effectiveUid)]),
      exactMode: 0o700,
      pinnedFields: ['ctimeNs', 'dev', 'ino', 'mode', 'nlink', 'uid', 'gid'],
    }));
    const buildRootLease = await openDirectoryLease(buildRootPath, {
      allowedUids: new Set([String(effectiveUid)]),
      exactMode: 0o700,
      pinnedFields: ['dev', 'ino', 'mode', 'uid', 'gid'],
    });
    const metadataPolicy = buildMetadataPolicy(buildRootLease.metadata);
    leases.push(buildRootLease);
    const lease = Object.freeze({
      buildRootPath,
      builderParentPath,
      workspacePath,
    });
    privateWorkspaceStates.set(lease, Object.seal({
      closed: false,
      leases: Object.freeze(leases),
      metadataPolicy,
      publicationLease,
      published: false,
    }));
    await assertPrivateA28BuildWorkspace(lease);
    return lease;
  } catch (error) {
    const closures = await Promise.allSettled(
      leases.reverse().map(({ handle }) => handle.close()),
    );
    const closeFailure = closures.find((result) => result.status === 'rejected');
    if (closeFailure) throw closeFailure.reason;
    throw error;
  }
}

export async function assertPrivateA28BuildWorkspace(lease) {
  const state = privateWorkspaceStates.get(lease);
  if (!state || state.closed) reject('A.28 private build workspace lease is invalid');
  for (const directoryLease of state.leases) {
    if (state.published && directoryLease.path === lease.buildRootPath) continue;
    await assertDirectoryLease(directoryLease);
  }
  if (state.publicationLease !== undefined) {
    await assertA28OutputPublicationLease(state.publicationLease);
  }
}

export async function closePrivateA28BuildWorkspace(lease) {
  const state = privateWorkspaceStates.get(lease);
  if (!state || state.closed) reject('A.28 private build workspace lease is invalid');
  state.closed = true;
  const closures = await Promise.allSettled(
    [...state.leases].reverse().map(({ handle }) => handle.close()),
  );
  const closeFailure = closures.find((result) => result.status === 'rejected');
  if (closeFailure) throw closeFailure.reason;
}

function privateWorkspaceState(lease) {
  const state = privateWorkspaceStates.get(lease);
  if (!state || state.closed) reject('A.28 private build workspace lease is invalid');
  return state;
}

function privateBuildMetadataPolicy(lease) {
  return privateWorkspaceState(lease).metadataPolicy;
}

function directoryLeaseAt(lease, path) {
  const match = privateWorkspaceState(lease).leases.find(
    (directoryLease) => directoryLease.path === path,
  );
  if (!match) reject('A.28 required directory is not held');
  return match;
}

async function readFileHandleBytes(handle, size, maximumBytes) {
  if (size < 1n || size > BigInt(maximumBytes)) reject();
  const bytes = Buffer.alloc(Number(size));
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesRead } = await handle.read(
      bytes,
      offset,
      bytes.length - offset,
      offset,
    );
    if (bytesRead < 1) reject();
    offset += bytesRead;
  }
  return bytes;
}

async function openHeldEntry(
  path,
  type,
  maximumBytes = 300 * 1024 * 1024,
  metadataPolicy,
) {
  let handle;
  try {
    handle = await open(
      path,
      constants.O_RDONLY
        | constants.O_NOFOLLOW
        | (type === 'directory' ? (constants.O_DIRECTORY ?? 0) : 0),
    );
    const [held, pathname, canonicalPath] = await Promise.all([
      handle.stat({ bigint: true }),
      lstat(path, { bigint: true }),
      realpath(path),
    ]);
    const heldIdentity = bigintStatIdentity(held);
    const pathnameIdentity = bigintStatIdentity(pathname);
    const metadata = readDescriptorMetadata(handle);
    const fields = [
      'ctimeNs', 'dev', 'gid', 'ino', 'mode', 'mtimeNs', 'nlink', 'size', 'uid',
    ];
    if (canonicalPath !== path
      || pathname.isSymbolicLink()
      || (type === 'directory' && (!held.isDirectory() || !pathname.isDirectory()))
      || (type === 'file' && (!held.isFile() || !pathname.isFile()
        || held.nlink !== 1n))
      || held.uid !== BigInt(processEffectiveUid())
      || (held.mode & 0o7022n) !== 0n
      || !sameDirectoryIdentity(heldIdentity, pathnameIdentity, fields)) reject();
    if (metadataPolicy !== undefined) {
      assertBuildDescriptorMetadata(metadata, metadataPolicy);
    }
    const bytes = type === 'file'
      ? await readFileHandleBytes(handle, held.size, maximumBytes)
      : undefined;
    return Object.seal({
      baseline: heldIdentity,
      handle,
      maximumBytes,
      metadata,
      metadataPolicy,
      path,
      sha256: bytes === undefined ? undefined : sha256A28(bytes),
      type,
    });
  } catch (error) {
    await handle?.close();
    throw error;
  }
}

async function assertHeldEntryAt(entry, path = entry.path, {
  allowContentChange = false,
} = {}) {
  const [held, pathname, canonicalPath] = await Promise.all([
    entry.handle.stat({ bigint: true }),
    lstat(path, { bigint: true }),
    realpath(path),
  ]);
  const heldIdentity = bigintStatIdentity(held);
  const pathnameIdentity = bigintStatIdentity(pathname);
  const metadata = readDescriptorMetadata(entry.handle);
  const stableFields = ['dev', 'gid', 'ino', 'mode', 'nlink', 'uid'];
  const exactFields = [
    'ctimeNs', ...stableFields, 'mtimeNs', 'size',
  ];
  if (canonicalPath !== path
    || pathname.isSymbolicLink()
    || (entry.type === 'directory'
      && (!held.isDirectory() || !pathname.isDirectory()))
    || (entry.type === 'file'
      && (!held.isFile() || !pathname.isFile() || held.nlink !== 1n))
    || !sameDirectoryIdentity(heldIdentity, pathnameIdentity, exactFields)
    || !sameDirectoryIdentity(
      heldIdentity,
      entry.baseline,
      allowContentChange ? stableFields : exactFields,
    )
    || metadata.flags !== entry.metadata.flags
    || metadata.serialisedXattrs !== entry.metadata.serialisedXattrs) {
    reject('A.28 held build object changed');
  }
  if (entry.metadataPolicy !== undefined) {
    assertBuildDescriptorMetadata(metadata, entry.metadataPolicy);
  }
  if (entry.type === 'file' && !allowContentChange) {
    const bytes = await readFileHandleBytes(entry.handle, held.size, entry.maximumBytes);
    if (sha256A28(bytes) !== entry.sha256) reject('A.28 held file bytes changed');
  }
  return Object.freeze({ held, identity: heldIdentity });
}

async function refreshHeldEntryAfterExpectedMutation(entry) {
  const { held, identity } = await assertHeldEntryAt(entry, entry.path, {
    allowContentChange: true,
  });
  entry.baseline = identity;
  if (entry.type === 'file') {
    const bytes = await readFileHandleBytes(entry.handle, held.size, entry.maximumBytes);
    entry.sha256 = sha256A28(bytes);
  }
}

async function closeHeldEntry(entry) {
  await entry.handle.close();
}

async function captureHeldTree(rootPath, metadataPolicy) {
  const entries = [];
  const queue = [{ path: rootPath, relativePath: '' }];
  try {
    while (queue.length > 0) {
      const current = queue.shift();
      const held = await openHeldEntry(
        current.path,
        'directory',
        300 * 1024 * 1024,
        metadataPolicy,
      );
      let children;
      try {
        children = await readdir(current.path, { withFileTypes: true });
      } catch (error) {
        await closeHeldEntry(held);
        throw error;
      }
      children.sort((left, right) => left.name.localeCompare(right.name, 'en'));
      entries.push(Object.freeze({
        childNames: Object.freeze(children.map(({ name }) => name)),
        held,
        relativePath: current.relativePath,
      }));
      for (const child of children) {
        const childPath = resolve(current.path, child.name);
        const relativePath = relative(rootPath, childPath);
        if (child.isSymbolicLink()
          || (!child.isDirectory() && !child.isFile())) reject();
        if (child.isDirectory()) {
          queue.push({ path: childPath, relativePath });
        } else {
          const file = await openHeldEntry(
            childPath,
            'file',
            300 * 1024 * 1024,
            metadataPolicy,
          );
          entries.push(Object.freeze({ held: file, relativePath }));
        }
      }
    }
    const records = entries
      .filter(({ relativePath }) => relativePath.length > 0)
      .map(({ held, relativePath }) => Object.freeze({
        mode: held.baseline.mode & 0o7777,
        path: relativePath,
        ...(held.type === 'file' ? {
          sha256: held.sha256,
          size: Number(held.baseline.size),
        } : {}),
        type: held.type,
      }));
    records.sort((left, right) => left.path.localeCompare(right.path, 'en'));
    const snapshot = Object.freeze({
      records: Object.freeze(records),
      rootPath,
      sha256: sha256A28(canonicalA28Line(records)),
    });
    heldTreeStates.set(snapshot, Object.freeze(entries));
    await assertHeldTreeAt(snapshot, rootPath);
    return snapshot;
  } catch (error) {
    const closures = await Promise.allSettled(
      entries.map(({ held }) => closeHeldEntry(held)),
    );
    const closeFailure = closures.find((result) => result.status === 'rejected');
    if (closeFailure) throw closeFailure.reason;
    throw error;
  }
}

async function assertHeldTreeAt(snapshot, rootPath) {
  const entries = heldTreeStates.get(snapshot);
  if (!entries) reject('A.28 held tree snapshot is invalid');
  for (const entry of entries) {
    const path = entry.relativePath.length === 0
      ? rootPath
      : resolve(rootPath, entry.relativePath);
    await assertHeldEntryAt(entry.held, path);
    if (entry.held.type === 'directory') {
      const childNames = (await readdir(path))
        .sort((left, right) => left.localeCompare(right, 'en'));
      if (canonicalA28Json(childNames)
        !== canonicalA28Json(entry.childNames)) {
        reject('A.28 held tree directory membership changed');
      }
      await assertHeldEntryAt(entry.held, path);
    }
  }
}

async function closeHeldTree(snapshot) {
  const entries = heldTreeStates.get(snapshot);
  if (!entries) reject('A.28 held tree snapshot is invalid');
  heldTreeStates.delete(snapshot);
  const closures = await Promise.allSettled(
    entries.map(({ held }) => closeHeldEntry(held)),
  );
  const closeFailure = closures.find((result) => result.status === 'rejected');
  if (closeFailure) throw closeFailure.reason;
}

export async function captureHeldA28BuildSnapshot(lease) {
  await assertPrivateA28BuildWorkspace(lease);
  let snapshot;
  try {
    snapshot = await captureHeldTree(
      lease.buildRootPath,
      privateBuildMetadataPolicy(lease),
    );
    await assertPrivateA28BuildWorkspace(lease);
    return snapshot;
  } catch (error) {
    if (snapshot !== undefined) await closeHeldTree(snapshot);
    throw error;
  }
}

export async function closeHeldA28BuildSnapshot(snapshot) {
  await closeHeldTree(snapshot);
}

function heldTreeEntry(snapshot, relativePath, type) {
  const entries = heldTreeStates.get(snapshot);
  if (!entries) reject('A.28 held tree snapshot is invalid');
  const entry = entries.find((candidate) =>
    candidate.relativePath === relativePath && candidate.held.type === type);
  if (!entry) reject('A.28 held tree entry is missing');
  return entry;
}

async function readHeldTreeFile(snapshot, relativePath, maximumBytes) {
  const entry = heldTreeEntry(snapshot, relativePath, 'file');
  const { held } = await assertHeldEntryAt(entry.held);
  if (held.size > BigInt(maximumBytes)) reject();
  const bytes = await readFileHandleBytes(entry.held.handle, held.size, maximumBytes);
  if (sha256A28(bytes) !== entry.held.sha256) reject('A.28 held file bytes changed');
  await assertHeldEntryAt(entry.held);
  return bytes;
}

export async function assertHeldA28BuildInputBindings({
  authorisedSourceRecords,
  processInspectorSha256,
  snapshot,
}) {
  if (typeof authorisedSourceRecords !== 'string'
    || !/^[0-9a-f]{64}$/u.test(processInspectorSha256)) reject();
  await assertHeldTreeAt(snapshot, snapshot.rootPath);
  if (canonicalA28Json(heldTreeManifest(snapshot, 'source').records)
      !== authorisedSourceRecords
    || sha256A28(await readHeldTreeFile(
      snapshot,
      'a28-process-identity',
      16 * 1024 * 1024,
    )) !== processInspectorSha256) {
    reject('A.28 held build inputs differ from their authorised bytes');
  }
  await assertHeldTreeAt(snapshot, snapshot.rootPath);
}

export async function assertHeldA28BuildModes(snapshot) {
  await assertHeldTreeAt(snapshot, snapshot.rootPath);
  const expected = [
    ['', 'directory', 0o700],
    ['source', 'directory', 0o700],
    ['PIUI A28 VoiceOver Witness.app', 'directory', 0o700],
    [
      'PIUI A28 VoiceOver Witness.app' + sep + 'Contents/MacOS/A28Witness',
      'file',
      0o500,
    ],
    ['a28-process-identity', 'file', 0o500],
    ['a28-root-launcher', 'file', 0o500],
    ['PIUI A28 VoiceOver Witness reproduction.app', 'directory', 0o700],
    [
      'PIUI A28 VoiceOver Witness reproduction.app'
        + sep + 'Contents/MacOS/A28Witness',
      'file',
      0o500,
    ],
    ['a28-root-launcher-reproduction', 'file', 0o500],
  ];
  for (const [path, type, mode] of expected) {
    const entry = heldTreeEntry(snapshot, path, type);
    if (entry.held.baseline.mode !== mode) {
      reject('A.28 held build mode differs from the required mode');
    }
  }
  await assertHeldTreeAt(snapshot, snapshot.rootPath);
}

function heldTreeManifest(snapshot, directoryRelativePath, excluded = new Set()) {
  heldTreeEntry(snapshot, directoryRelativePath, 'directory');
  const prefix = directoryRelativePath.length === 0
    ? ''
    : directoryRelativePath + sep;
  const records = snapshot.records
    .filter(({ path }) => path.startsWith(prefix) && path !== directoryRelativePath)
    .map((record) => Object.freeze({
      ...record,
      path: record.path.slice(prefix.length),
    }))
    .filter(({ path }) => !excluded.has(path));
  return Object.freeze({
    records: Object.freeze(records),
    sha256: sha256A28(canonicalA28Line(records)),
  });
}

const isAuthorisedApplicationResource = ({ path }) =>
  path !== 'Contents/MacOS/A28Witness'
    && path !== 'Contents/_CodeSignature'
    && path !== 'Contents/_CodeSignature/CodeResources';

export async function assertHeldA28ApplicationResources({
  authorisedApplicationResources,
  snapshot,
}) {
  if (typeof authorisedApplicationResources !== 'string') reject();
  await assertHeldTreeAt(snapshot, snapshot.rootPath);
  for (const applicationName of [
    'PIUI A28 VoiceOver Witness.app',
    'PIUI A28 VoiceOver Witness reproduction.app',
  ]) {
    const completeRecords = heldTreeManifest(snapshot, applicationName).records;
    const signatureRecords = completeRecords
      .filter(({ path }) => path === 'Contents/_CodeSignature'
        || path.startsWith('Contents/_CodeSignature' + sep))
      .map(({ mode, path, type }) => Object.freeze({ mode, path, type }));
    if (canonicalA28Json(signatureRecords) !== canonicalA28Json([
      Object.freeze({
        mode: 0o755,
        path: 'Contents/_CodeSignature',
        type: 'directory',
      }),
      Object.freeze({
        mode: 0o644,
        path: 'Contents/_CodeSignature/CodeResources',
        type: 'file',
      }),
    ])) reject('A.28 generated signature membership is invalid');
    const records = completeRecords.filter(isAuthorisedApplicationResource);
    if (canonicalA28Json(records) !== authorisedApplicationResources) {
      reject('A.28 signed application resources differ from authorised bytes');
    }
  }
  await assertHeldTreeAt(snapshot, snapshot.rootPath);
}

async function refreshHeldTreeRootAfterPublication(snapshot, publishedRoot) {
  const rootEntry = heldTreeEntry(snapshot, '', 'directory').held;
  const previous = rootEntry.baseline;
  const { identity } = await assertHeldEntryAt(rootEntry, publishedRoot, {
    allowContentChange: true,
  });
  if (!sameDirectoryIdentity(identity, previous, [
    'dev', 'gid', 'ino', 'mode', 'mtimeNs', 'nlink', 'size', 'uid',
  ])) reject('A.28 published build root changed beyond rename metadata');
  rootEntry.baseline = identity;
}

function assertPrivateWorkspaceRelativePath(lease, path) {
  if (typeof path !== 'string'
    || path.length < 1
    || isAbsolute(path)
    || path.includes('\0')) reject();
  const absolute = resolve(lease.workspacePath, path);
  const name = relative(lease.workspacePath, absolute);
  const buildRootName = relative(
    lease.workspacePath,
    lease.buildRootPath,
  );
  if (name !== path
    || name === '..'
    || name.startsWith('..' + sep)
    || (name !== buildRootName
      && !name.startsWith(buildRootName + sep))) reject();
  return path;
}

async function runPrivateA28WorkspaceCommand(
  lease,
  commandRunner,
  path,
  arguments_,
  options = {},
) {
  await assertPrivateA28BuildWorkspace(lease);
  const result = await commandRunner(path, arguments_, {
    ...options,
    cwd: lease.workspacePath,
  });
  await assertPrivateA28BuildWorkspace(lease);
  return result;
}

export async function signPrivateA28WorkspaceCopies({
  applicationPreSigningRecords,
  applicationRelativePath,
  beforeSigningCommand,
  commandRunner = run,
  entitlementsRelativePath,
  entitlementsSha256,
  lease,
  reproductionApplicationPreSigningRecords,
  reproductionApplicationRelativePath,
  reproductionRootLauncherUnsignedSha256,
  reproductionRootLauncherRelativePath,
  rootLauncherUnsignedSha256,
  rootLauncherRelativePath,
  signingCertificateSelector,
}) {
  const entitlements = assertPrivateWorkspaceRelativePath(
    lease,
    entitlementsRelativePath,
  );
  const signingTargets = Object.freeze([
    Object.freeze({
      mode: 'app-sign',
      path: assertPrivateWorkspaceRelativePath(lease, applicationRelativePath),
      type: 'directory',
    }),
    Object.freeze({
      mode: 'app-sign',
      path: assertPrivateWorkspaceRelativePath(
        lease,
        reproductionApplicationRelativePath,
      ),
      type: 'directory',
    }),
    Object.freeze({
      mode: 'root-sign',
      path: assertPrivateWorkspaceRelativePath(lease, rootLauncherRelativePath),
      type: 'file',
    }),
    Object.freeze({
      mode: 'root-sign',
      path: assertPrivateWorkspaceRelativePath(
        lease,
        reproductionRootLauncherRelativePath,
      ),
      type: 'file',
    }),
  ]);
  const workspaceDirectory = directoryLeaseAt(lease, lease.workspacePath);
  const buildRootDirectory = directoryLeaseAt(lease, lease.buildRootPath);
  const metadataPolicy = privateBuildMetadataPolicy(lease);
  let sourceDirectory;
  let entitlementsEntry;
  const targets = [];
  const applicationSnapshots = [];
  const closedApplicationSnapshots = new Set();
  try {
    await assertRootOwnedSystemTool('/usr/bin/ruby');
    await assertRootOwnedSystemTool('/usr/bin/codesign');
    sourceDirectory = await openHeldEntry(
      resolve(lease.workspacePath, dirname(entitlements)),
      'directory',
      300 * 1024 * 1024,
      metadataPolicy,
    );
    entitlementsEntry = await openHeldEntry(
      resolve(lease.workspacePath, entitlements),
      'file',
      2 * 1024 * 1024,
      metadataPolicy,
    );
    for (const target of signingTargets) {
      targets.push(await openHeldEntry(
        resolve(lease.workspacePath, target.path),
        target.type,
        32 * 1024 * 1024,
        metadataPolicy,
      ));
    }
    for (const target of signingTargets.slice(0, 2)) {
      applicationSnapshots.push(await captureHeldTree(
        resolve(lease.workspacePath, target.path),
        metadataPolicy,
      ));
    }
    const expectedApplicationRecords = [
      applicationPreSigningRecords,
      reproductionApplicationPreSigningRecords,
    ];
    if (!/^[0-9a-f]{40}$/u.test(signingCertificateSelector)
      || !/^[0-9a-f]{64}$/u.test(entitlementsSha256)
      || !/^[0-9a-f]{64}$/u.test(rootLauncherUnsignedSha256)
      || !/^[0-9a-f]{64}$/u.test(reproductionRootLauncherUnsignedSha256)
      || targets[0].baseline.mode !== 0o700
      || targets[1].baseline.mode !== 0o700
      || targets[2].baseline.mode !== 0o500
      || targets[3].baseline.mode !== 0o500
      || sourceDirectory.baseline.mode !== 0o700
      || entitlementsEntry.baseline.mode !== 0o400
      || entitlementsEntry.sha256 !== entitlementsSha256
      || targets[2].sha256 !== rootLauncherUnsignedSha256
      || targets[3].sha256 !== reproductionRootLauncherUnsignedSha256
      || applicationSnapshots.some((snapshot, index) =>
        typeof expectedApplicationRecords[index] !== 'string'
          || canonicalA28Json(snapshot.records)
            !== expectedApplicationRecords[index])) {
      reject('A.28 pre-sign inputs differ from their authorised bytes');
    }
    for (let ordinal = 0; ordinal < signingTargets.length; ordinal += 1) {
      const definition = signingTargets[ordinal];
      if (beforeSigningCommand !== undefined) {
        await beforeSigningCommand(Object.freeze({
          ordinal,
          targetPath: resolve(lease.workspacePath, definition.path),
          workspacePath: lease.workspacePath,
        }));
      }
      if (ordinal < applicationSnapshots.length) {
        await assertHeldTreeAt(
          applicationSnapshots[ordinal],
          resolve(lease.workspacePath, definition.path),
        );
      }
      await assertPrivateA28BuildWorkspace(lease);
      for (let targetIndex = 0; targetIndex < targets.length; targetIndex += 1) {
        await assertHeldEntryAt(targets[targetIndex]);
      }
      await assertHeldEntryAt(sourceDirectory);
      await assertHeldEntryAt(entitlementsEntry);
      const stdio = [
        'ignore',
        'pipe',
        'pipe',
        workspaceDirectory.handle.fd,
        buildRootDirectory.handle.fd,
        buildRootDirectory.handle.fd,
        targets[ordinal].handle.fd,
      ];
      if (definition.mode === 'app-sign') {
        stdio.push(sourceDirectory.handle.fd, entitlementsEntry.handle.fd);
      }
      await commandRunner('/usr/bin/ruby', [
        '--disable-gems',
        '-e',
        descriptorCodesignRuby,
        definition.mode,
        signingCertificateSelector,
        definition.path,
        definition.mode === 'app-sign' ? entitlements : '',
      ], {
        cwd: '/private/var/empty',
        stdio,
        timeout: 180_000,
      });
      if (ordinal < applicationSnapshots.length) {
        await closeHeldTree(applicationSnapshots[ordinal]);
        closedApplicationSnapshots.add(applicationSnapshots[ordinal]);
      }
      await assertPrivateA28BuildWorkspace(lease);
      await refreshHeldEntryAfterExpectedMutation(targets[ordinal]);
      for (let targetIndex = 0; targetIndex < targets.length; targetIndex += 1) {
        await assertHeldEntryAt(targets[targetIndex]);
      }
      await assertHeldEntryAt(sourceDirectory);
      await assertHeldEntryAt(entitlementsEntry);
    }
  } finally {
    const closures = await Promise.allSettled([
      ...targets.map((target) => closeHeldEntry(target)),
      ...(sourceDirectory === undefined ? [] : [closeHeldEntry(sourceDirectory)]),
      ...(entitlementsEntry === undefined
        ? []
        : [closeHeldEntry(entitlementsEntry)]),
      ...applicationSnapshots
        .filter((snapshot) => !closedApplicationSnapshots.has(snapshot))
        .map((snapshot) => closeHeldTree(snapshot)),
    ]);
    const closeFailure = closures.find((result) => result.status === 'rejected');
    if (closeFailure) throw closeFailure.reason;
  }
}

async function runDescriptorAnchoredCodesign({
  commandRunner = run,
  lease,
  mode,
  snapshot,
  targetRelativePath,
  targetType,
}) {
  if (!['verify', 'display'].includes(mode)) reject();
  await assertRootOwnedSystemTool('/usr/bin/ruby');
  await assertRootOwnedSystemTool('/usr/bin/codesign');
  const target = assertPrivateWorkspaceRelativePath(lease, targetRelativePath);
  const workspaceDirectory = directoryLeaseAt(lease, lease.workspacePath);
  const buildRootDirectory = directoryLeaseAt(lease, lease.buildRootPath);
  const metadataPolicy = privateBuildMetadataPolicy(lease);
  const targetEntry = await openHeldEntry(
    resolve(lease.workspacePath, target),
    targetType,
    32 * 1024 * 1024,
    metadataPolicy,
  );
  try {
    await assertPrivateA28BuildWorkspace(lease);
    if (snapshot !== undefined) {
      await assertHeldTreeAt(snapshot, lease.buildRootPath);
    }
    await assertHeldEntryAt(targetEntry);
    const result = await commandRunner('/usr/bin/ruby', [
      '--disable-gems',
      '-e',
      descriptorCodesignRuby,
      mode,
      '',
      target,
      '',
    ], {
      cwd: '/private/var/empty',
      stdio: [
        'ignore',
        'pipe',
        'pipe',
        workspaceDirectory.handle.fd,
        buildRootDirectory.handle.fd,
        buildRootDirectory.handle.fd,
        targetEntry.handle.fd,
      ],
      timeout: 180_000,
    });
    await assertPrivateA28BuildWorkspace(lease);
    await assertHeldEntryAt(targetEntry);
    if (snapshot !== undefined) {
      await assertHeldTreeAt(snapshot, lease.buildRootPath);
    }
    return result;
  } finally {
    await closeHeldEntry(targetEntry);
  }
}

async function runDescriptorAnchoredInspector({
  applicationRelativePath,
  bundleIdentifier,
  commandRunner = run,
  designatedRequirement,
  inspectorRelativePath,
  lease,
  snapshot,
  teamIdentifier,
}) {
  const inspector = assertPrivateWorkspaceRelativePath(
    lease,
    inspectorRelativePath,
  );
  const application = assertPrivateWorkspaceRelativePath(
    lease,
    applicationRelativePath,
  );
  const workspaceDirectory = directoryLeaseAt(lease, lease.workspacePath);
  const buildRootDirectory = directoryLeaseAt(lease, lease.buildRootPath);
  const metadataPolicy = privateBuildMetadataPolicy(lease);
  let inspectorEntry;
  let applicationEntry;
  try {
    await assertRootOwnedSystemTool('/usr/bin/ruby');
    inspectorEntry = await openHeldEntry(
      resolve(lease.workspacePath, inspector),
      'file',
      32 * 1024 * 1024,
      metadataPolicy,
    );
    applicationEntry = await openHeldEntry(
      resolve(lease.workspacePath, application),
      'directory',
      300 * 1024 * 1024,
      metadataPolicy,
    );
    await assertPrivateA28BuildWorkspace(lease);
    await assertHeldTreeAt(snapshot, lease.buildRootPath);
    await assertHeldEntryAt(inspectorEntry);
    await assertHeldEntryAt(applicationEntry);
    const result = await commandRunner('/usr/bin/ruby', [
      '--disable-gems',
      '-e',
      descriptorInspectorRuby,
      inspector,
      application,
      bundleIdentifier,
      teamIdentifier,
      designatedRequirement,
    ], {
      cwd: '/private/var/empty',
      stdio: [
        'ignore',
        'pipe',
        'pipe',
        workspaceDirectory.handle.fd,
        buildRootDirectory.handle.fd,
        buildRootDirectory.handle.fd,
        inspectorEntry.handle.fd,
        buildRootDirectory.handle.fd,
        applicationEntry.handle.fd,
      ],
      timeout: 30_000,
    });
    await assertPrivateA28BuildWorkspace(lease);
    await assertHeldEntryAt(inspectorEntry);
    await assertHeldEntryAt(applicationEntry);
    await assertHeldTreeAt(snapshot, lease.buildRootPath);
    return result;
  } finally {
    const closures = await Promise.allSettled([
      ...(inspectorEntry === undefined ? [] : [closeHeldEntry(inspectorEntry)]),
      ...(applicationEntry === undefined ? [] : [closeHeldEntry(applicationEntry)]),
    ]);
    const closeFailure = closures.find((result) => result.status === 'rejected');
    if (closeFailure) throw closeFailure.reason;
  }
}

export async function preflightPrivateA28DescriptorHelpers({
  applicationRelativePath,
  entitlementsRelativePath,
  inspectorRelativePath,
  lease,
  rootLauncherRelativePath,
}) {
  const application = assertPrivateWorkspaceRelativePath(
    lease,
    applicationRelativePath,
  );
  const entitlements = assertPrivateWorkspaceRelativePath(
    lease,
    entitlementsRelativePath,
  );
  const inspector = assertPrivateWorkspaceRelativePath(
    lease,
    inspectorRelativePath,
  );
  const rootLauncher = assertPrivateWorkspaceRelativePath(
    lease,
    rootLauncherRelativePath,
  );
  const workspaceDirectory = directoryLeaseAt(lease, lease.workspacePath);
  const buildRootDirectory = directoryLeaseAt(lease, lease.buildRootPath);
  const metadataPolicy = privateBuildMetadataPolicy(lease);
  let applicationEntry;
  let entitlementsEntry;
  let inspectorEntry;
  let rootLauncherEntry;
  let sourceDirectory;
  try {
    await assertRootOwnedSystemTool('/usr/bin/ruby');
    await assertRootOwnedSystemTool('/usr/bin/codesign');
    sourceDirectory = await openHeldEntry(
      resolve(lease.workspacePath, dirname(entitlements)),
      'directory',
      300 * 1024 * 1024,
      metadataPolicy,
    );
    entitlementsEntry = await openHeldEntry(
      resolve(lease.workspacePath, entitlements),
      'file',
      2 * 1024 * 1024,
      metadataPolicy,
    );
    applicationEntry = await openHeldEntry(
      resolve(lease.workspacePath, application),
      'directory',
      300 * 1024 * 1024,
      metadataPolicy,
    );
    rootLauncherEntry = await openHeldEntry(
      resolve(lease.workspacePath, rootLauncher),
      'file',
      32 * 1024 * 1024,
      metadataPolicy,
    );
    inspectorEntry = await openHeldEntry(
      resolve(lease.workspacePath, inspector),
      'file',
      32 * 1024 * 1024,
      metadataPolicy,
    );
    const entries = [
      sourceDirectory,
      entitlementsEntry,
      applicationEntry,
      rootLauncherEntry,
      inspectorEntry,
    ];
    await assertPrivateA28BuildWorkspace(lease);
    for (const entry of entries) await assertHeldEntryAt(entry);
    run('/usr/bin/ruby', [
      '--disable-gems',
      '-e',
      descriptorCodesignRuby,
      'app-preflight',
      '',
      application,
      entitlements,
    ], {
      cwd: '/private/var/empty',
      stdio: [
        'ignore',
        'pipe',
        'pipe',
        workspaceDirectory.handle.fd,
        buildRootDirectory.handle.fd,
        buildRootDirectory.handle.fd,
        applicationEntry.handle.fd,
        sourceDirectory.handle.fd,
        entitlementsEntry.handle.fd,
      ],
      timeout: 30_000,
    });
    run('/usr/bin/ruby', [
      '--disable-gems',
      '-e',
      descriptorCodesignRuby,
      'root-preflight',
      '',
      rootLauncher,
      '',
    ], {
      cwd: '/private/var/empty',
      stdio: [
        'ignore',
        'pipe',
        'pipe',
        workspaceDirectory.handle.fd,
        buildRootDirectory.handle.fd,
        buildRootDirectory.handle.fd,
        rootLauncherEntry.handle.fd,
      ],
      timeout: 30_000,
    });
    run('/usr/bin/ruby', [
      '--disable-gems',
      '-e',
      descriptorInspectorRuby,
      inspector,
      application,
      'au.com.piui.a28-witness',
      'TEAMID1234',
      'anchor apple generic',
      '--preflight',
    ], {
      cwd: '/private/var/empty',
      stdio: [
        'ignore',
        'pipe',
        'pipe',
        workspaceDirectory.handle.fd,
        buildRootDirectory.handle.fd,
        buildRootDirectory.handle.fd,
        inspectorEntry.handle.fd,
        buildRootDirectory.handle.fd,
        applicationEntry.handle.fd,
      ],
      timeout: 30_000,
    });
    await assertPrivateA28BuildWorkspace(lease);
    for (const entry of entries) await assertHeldEntryAt(entry);
  } finally {
    const entries = [
      sourceDirectory,
      entitlementsEntry,
      applicationEntry,
      rootLauncherEntry,
      inspectorEntry,
    ].filter((entry) => entry !== undefined);
    const closures = await Promise.allSettled(entries.map(closeHeldEntry));
    const closeFailure = closures.find((result) => result.status === 'rejected');
    if (closeFailure) throw closeFailure.reason;
  }
}

function outputPublicationState(lease) {
  const state = outputPublicationStates.get(lease);
  if (!state || state.closed) reject('A.28 output publication lease is invalid');
  return state;
}

function outputParentDirectoryLease(lease) {
  const match = outputPublicationState(lease).directoryLeases.find(
    (directoryLease) => directoryLease.path === lease.parentPath,
  );
  if (!match) reject('A.28 output parent is not held');
  return match;
}

export async function publishHeldA28Build({
  beforePublication,
  commandRunner = run,
  lease,
  publicationLease,
  snapshot,
}) {
  const workspaceState = privateWorkspaceState(lease);
  if (workspaceState.publicationLease !== publicationLease
    || workspaceState.published
    || snapshot.rootPath !== lease.buildRootPath
    || !heldTreeStates.has(snapshot)) reject();
  await assertRootOwnedSystemTool('/usr/bin/ruby');
  await assertPrivateA28BuildWorkspace(lease);
  await assertA28OutputPublicationLease(publicationLease);
  await assertHeldTreeAt(snapshot, lease.buildRootPath);
  if (beforePublication !== undefined) await beforePublication();
  await assertPrivateA28BuildWorkspace(lease);
  await assertA28OutputPublicationLease(publicationLease);
  await assertHeldTreeAt(snapshot, lease.buildRootPath);
  const workspaceDirectory = directoryLeaseAt(lease, lease.workspacePath);
  const buildRootDirectory = directoryLeaseAt(lease, lease.buildRootPath);
  const destinationParent = outputParentDirectoryLease(publicationLease);
  const [sourceIdentityBefore, destinationParentIdentity] = await Promise.all([
    buildRootDirectory.handle.stat({ bigint: true }),
    destinationParent.handle.stat({ bigint: true }),
  ]);
  if (sourceIdentityBefore.dev !== destinationParentIdentity.dev) {
    reject('A.28 output publication requires one filesystem');
  }
  await commandRunner('/usr/bin/ruby', [
    '--disable-gems',
    '-e',
    exclusivePublishRuby,
    basename(lease.buildRootPath),
    publicationLease.destinationName,
  ], {
    cwd: '/private/var/empty',
    stdio: [
      'ignore',
      'pipe',
      'pipe',
      workspaceDirectory.handle.fd,
      destinationParent.handle.fd,
      buildRootDirectory.handle.fd,
    ],
    timeout: 30_000,
  });
  await assertMissingPath(lease.buildRootPath);
  const [heldAfter, destinationAfter] = await Promise.all([
    buildRootDirectory.handle.stat({ bigint: true }),
    lstat(publicationLease.requestedRoot, { bigint: true }),
  ]);
  const heldIdentity = bigintStatIdentity(heldAfter);
  const destinationIdentity = bigintStatIdentity(destinationAfter);
  const exactFields = [
    'ctimeNs', 'dev', 'gid', 'ino', 'mode', 'mtimeNs', 'nlink', 'size', 'uid',
  ];
  if (!heldAfter.isDirectory()
    || !destinationAfter.isDirectory()
    || destinationAfter.isSymbolicLink()
    || !sameDirectoryIdentity(heldIdentity, destinationIdentity, exactFields)) reject();
  const publicationState = outputPublicationState(publicationLease);
  publicationState.publishedIdentity = heldIdentity;
  workspaceState.published = true;
  await refreshDirectoryLeaseAfterExpectedMutation(workspaceDirectory);
  await refreshHeldTreeRootAfterPublication(
    snapshot,
    publicationLease.requestedRoot,
  );
  await assertPrivateA28BuildWorkspace(lease);
  await assertA28OutputPublicationLease(publicationLease);
  await assertHeldTreeAt(snapshot, publicationLease.requestedRoot);
}

async function treeManifest(path, excluded = new Set()) {
  const records = [];
  const queue = [path];
  while (queue.length > 0) {
    const directory = queue.shift();
    const children = await readdir(directory, { withFileTypes: true });
    children.sort((left, right) => left.name.localeCompare(right.name, 'en'));
    for (const child of children) {
      const childPath = resolve(directory, child.name);
      const name = relative(path, childPath);
      if (excluded.has(name)) continue;
      const item = await lstat(childPath);
      if (item.isSymbolicLink()
        || (!item.isFile() && !item.isDirectory())
        || (item.mode & 0o7022) !== 0) reject();
      if (item.isDirectory()) {
        records.push({ mode: item.mode & 0o7777, path: name, type: 'directory' });
        queue.push(childPath);
      } else {
        const bytes = await readHeld(childPath, 300 * 1024 * 1024);
        records.push({
          mode: item.mode & 0o7777,
          path: name,
          sha256: sha256A28(bytes),
          size: bytes.length,
          type: 'file',
        });
      }
    }
  }
  return Object.freeze({ records, sha256: sha256A28(canonicalA28Line(records)) });
}

function embeddedCodeSignature(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 64) reject();
  const magic = bytes.readUInt32LE(0);
  const headerSize = magic === 0xfeedfacf ? 32 : magic === 0xfeedface ? 28 : 0;
  if (headerSize === 0) reject('A.28 reproduction requires a thin Mach-O');
  const commands = bytes.readUInt32LE(16);
  if (commands < 1 || commands > 4_096) reject();
  let commandOffset = headerSize;
  let signatureCommand;
  for (let index = 0; index < commands; index += 1) {
    if (commandOffset + 8 > bytes.length) reject();
    const command = bytes.readUInt32LE(commandOffset);
    const commandSize = bytes.readUInt32LE(commandOffset + 4);
    if (commandSize < 8 || commandOffset + commandSize > bytes.length) reject();
    if (command === 0x1d) {
      if (signatureCommand !== undefined || commandSize < 16) reject();
      signatureCommand = commandOffset;
    }
    commandOffset += commandSize;
  }
  if (signatureCommand === undefined) reject();
  const dataOffset = bytes.readUInt32LE(signatureCommand + 8);
  const dataSize = bytes.readUInt32LE(signatureCommand + 12);
  if (dataOffset < commandOffset
    || dataSize < 20
    || dataOffset + dataSize > bytes.length) reject();
  const signature = bytes.subarray(dataOffset, dataOffset + dataSize);
  const superBlobLength = signature.readUInt32BE(4);
  if (signature.readUInt32BE(0) !== 0xfade0cc0
    || superBlobLength < 20
    || superBlobLength > dataSize
    || signature.subarray(superBlobLength).some((byte) => byte !== 0)) reject();
  const superBlob = signature.subarray(0, superBlobLength);
  const count = superBlob.readUInt32BE(8);
  if (count < 1 || count > 64 || 12 + count * 8 > superBlob.length) reject();
  const slots = [];
  const slotTypes = new Set();
  const indexLength = 12 + count * 8;
  for (let index = 0; index < count; index += 1) {
    const type = superBlob.readUInt32BE(12 + index * 8);
    const offset = superBlob.readUInt32BE(16 + index * 8);
    if (slotTypes.has(type)
      || offset < indexLength
      || offset + 8 > superBlob.length) reject();
    slotTypes.add(type);
    const length = superBlob.readUInt32BE(offset + 4);
    if (length < 8 || offset + length > superBlob.length) reject();
    slots.push(Object.freeze({
      length,
      offset,
      sha256: sha256A28(superBlob.subarray(offset, offset + length)),
      type,
    }));
  }
  const slotsByOffset = [...slots]
    .sort((left, right) => left.offset - right.offset);
  let previousEnd = indexLength;
  for (const slot of slotsByOffset) {
    if (slot.offset < previousEnd) reject();
    previousEnd = slot.offset + slot.length;
  }
  const cmsSlots = slots.filter((slot) => slot.type === 0x10000);
  let normalisedContainerSha256;
  if (cmsSlots.length === 1) {
    const [cms] = cmsSlots;
    if (cms.offset + cms.length !== superBlobLength
      || superBlob.readUInt32BE(cms.offset) !== 0xfade0b01) reject();
    const normalisedContainer = Buffer.from(
      superBlob.subarray(0, cms.offset),
    );
    normalisedContainer.writeUInt32BE(0, 4);
    normalisedContainerSha256 = sha256A28(normalisedContainer);
  } else if (cmsSlots.length > 1) {
    reject();
  }
  const reportedSlots = slots
    .map(({ length, sha256, type }) => Object.freeze({ length, sha256, type }))
    .sort((left, right) => left.type - right.type);
  const normalisedPrefix = Buffer.from(bytes.subarray(0, dataOffset));
  normalisedPrefix.writeUInt32LE(0, signatureCommand + 12);
  return Object.freeze({
    cmsSlots: Object.freeze(
      reportedSlots.filter((slot) => slot.type === 0x10000),
    ),
    containerLength: dataSize,
    fullSha256: sha256A28(bytes),
    nonCmsSlots: Object.freeze(
      reportedSlots.filter((slot) => slot.type !== 0x10000),
    ),
    normalisedContainerSha256,
    normalisedPrefixSha256: sha256A28(normalisedPrefix),
    suffixSha256: sha256A28(bytes.subarray(dataOffset + dataSize)),
  });
}

export function compareTimestampedSignatures(leftBytes, rightBytes) {
  const left = embeddedCodeSignature(leftBytes);
  const right = embeddedCodeSignature(rightBytes);
  if (canonicalA28Json(left.nonCmsSlots) !== canonicalA28Json(right.nonCmsSlots)
    || left.normalisedContainerSha256 !== right.normalisedContainerSha256
    || left.normalisedPrefixSha256 !== right.normalisedPrefixSha256
    || left.suffixSha256 !== right.suffixSha256
    || left.cmsSlots.length !== 1
    || right.cmsSlots.length !== 1) reject();
  return Object.freeze({
    allowedVariation: 'cms-and-signature-container-length-only',
    first: left,
    second: right,
  });
}

function assertSignedReproductionMatchesUnsigned(reproduction, unsignedBytes) {
  const unsigned = embeddedCodeSignature(unsignedBytes);
  for (const signed of [reproduction.first, reproduction.second]) {
    if (signed.normalisedPrefixSha256 !== unsigned.normalisedPrefixSha256
      || signed.suffixSha256 !== unsigned.suffixSha256) {
      reject('A.28 signed executable differs outside its signature container');
    }
  }
}

async function readHeld(path, maximumBytes = 2 * 1024 * 1024) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    if (!before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1
      || before.size < 1
      || before.size > maximumBytes
      || (before.mode & 0o7022) !== 0) reject();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mode !== after.mode
      || before.mtimeMs !== after.mtimeMs
      || bytes.length !== before.size) reject();
    return bytes;
  } finally {
    await handle?.close();
  }
}

async function writeExclusive(path, bytes, mode) {
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
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle?.close();
  }
}

function run(path, arguments_, options = {}) {
  const result = spawnSync(path, arguments_, {
    cwd: options.cwd,
    encoding: null,
    env: {
      LANG: 'C',
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
      ...options.env,
    },
    input: options.input,
    maxBuffer: 8 * 1024 * 1024,
    stdio: options.stdio,
    timeout: options.timeout ?? 120_000,
  });
  if (result.error
    || result.signal
    || result.status !== 0
    || !Buffer.isBuffer(result.stdout)
    || !Buffer.isBuffer(result.stderr)) {
    const detail = Buffer.isBuffer(result.stderr)
      ? result.stderr.toString('utf8').trim()
      : '';
    reject('A.28 witness build command failed'
      + (detail.length > 0 ? ': ' + detail : ''));
  }
  return result;
}

async function assertRootOwnedAppleTool(path) {
  if (path !== APPLE_TOOLCHAIN_PATHS.clang
    || await realpath(path) !== path) reject();
  let current = path;
  while (current !== '/') {
    const item = await import('node:fs/promises').then(({ lstat }) => lstat(current));
    if (item.isSymbolicLink()
      || item.uid !== 0
      || (item.mode & 0o7022) !== 0
      || (current === path && (!item.isFile() || (item.mode & 0o111) === 0))) reject();
    current = dirname(current);
  }
}

async function assertRootOwnedSystemTool(path) {
  if (!['/usr/bin/codesign', '/usr/bin/ruby'].includes(path)
    || await realpath(path) !== path) reject();
  let current = path;
  for (;;) {
    const item = await lstat(current);
    const leaf = current === path;
    if (item.isSymbolicLink()
      || item.uid !== 0
      || (item.mode & 0o7022) !== 0
      || (leaf && (!item.isFile() || item.nlink !== 1
        || (item.mode & 0o111) === 0))
      || (!leaf && !item.isDirectory())) reject();
    assertPathHasNoExtendedAcl(current);
    if (current === '/') break;
    current = dirname(current);
  }
}

export async function validateA28DescriptorHelpers() {
  await assertRootOwnedSystemTool('/usr/bin/ruby');
  await assertRootOwnedSystemTool('/usr/bin/codesign');
  for (const source of [
    descriptorCodesignRuby,
    descriptorInspectorRuby,
    descriptorMetadataRuby,
    exclusivePublishRuby,
  ]) {
    run('/usr/bin/ruby', ['--disable-gems', '-c', '-e', source], {
      timeout: 30_000,
    });
  }
}

async function assertRootOwnedAppleSdk(path) {
  if (path !== APPLE_TOOLCHAIN_PATHS.sdk
    || await realpath(path) !== path) reject();
  let current = path;
  while (current !== '/') {
    const item = await import('node:fs/promises').then(({ lstat }) => lstat(current));
    if (item.isSymbolicLink()
      || item.uid !== 0
      || (item.mode & 0o7022) !== 0
      || (current === path && !item.isDirectory())) reject();
    current = dirname(current);
  }
}

function decodePlist(bytes) {
  const output = run('/usr/bin/plutil', [
    '-convert',
    'json',
    '-o',
    '-',
    '--',
    '-',
  ], { input: bytes }).stdout;
  try {
    return JSON.parse(output.toString('utf8'));
  } catch {
    reject();
  }
}

async function validateProfile(profilePath, policy) {
  const bytes = await readHeld(profilePath, 4 * 1024 * 1024);
  if (sha256A28(bytes) !== policy.profileSha256) reject();
  const decoded = decodePlist(run('/usr/bin/security', [
    'cms',
    '-D',
  ], { input: bytes }).stdout);
  const entitlements = decoded.Entitlements;
  if (decoded.UUID !== policy.profileUuid
    || decoded.Name !== policy.profileName
    || JSON.stringify(decoded.TeamIdentifier) !== JSON.stringify([
      policy.teamIdentifier,
    ])
    || !Array.isArray(decoded.Platform)
    || !decoded.Platform.includes('OSX')
    || typeof decoded.ExpirationDate !== 'string'
    || !(Date.parse(decoded.ExpirationDate) > Date.now())
    || !entitlements
    || decoded.ProvisionsAllDevices !== true
    || entitlements['com.apple.application-identifier']
      !== policy.applicationIdentifier
    || entitlements['com.apple.developer.team-identifier'] !== policy.teamIdentifier
    || JSON.stringify(entitlements['keychain-access-groups'])
      !== JSON.stringify([policy.keychainAccessGroup])
    || entitlements['get-task-allow'] === true
    || entitlements['com.apple.security.get-task-allow'] === true
    || !Array.isArray(decoded.DeveloperCertificates)) reject();
  const matchingCertificates = decoded.DeveloperCertificates
    .filter((certificate) => typeof certificate === 'string')
    .map((certificate) => Buffer.from(certificate, 'base64'))
    .filter((certificate) =>
      sha256A28(certificate) === policy.signingCertificateSha256);
  if (matchingCertificates.length !== 1) reject();
  return Object.freeze({
    bytes,
    signingCertificateSha1: createHash('sha1')
      .update(matchingCertificates[0])
      .digest('hex'),
  });
}

export function selectA28SigningCertificateSelector({
  certificateListing,
  identitiesListing,
  signingCertificateSha1,
  signingCertificateSha256,
  signingIdentity,
}) {
  if (typeof certificateListing !== 'string'
    || typeof identitiesListing !== 'string'
    || !/^[0-9a-f]{40}$/u.test(signingCertificateSha1)
    || !/^[0-9a-f]{64}$/u.test(signingCertificateSha256)
    || typeof signingIdentity !== 'string'
    || signingIdentity.length < 3
    || /["\r\n]/u.test(signingIdentity)) reject();
  const certificatePairs = [...certificateListing.matchAll(
    /^SHA-256 hash: ([0-9A-Fa-f]{64})\r?\nSHA-1 hash: ([0-9A-Fa-f]{40})$/gmu,
  )].map((match) => Object.freeze({
    sha1: match[2].toLowerCase(),
    sha256: match[1].toLowerCase(),
  }));
  if (!certificatePairs.some(({ sha1, sha256 }) =>
    sha1 === signingCertificateSha1
      && sha256 === signingCertificateSha256)) reject();
  const identities = identitiesListing.split(/\r?\n/u)
    .map((line) => /^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"([^"\r\n]+)"\s*$/u
      .exec(line))
    .filter((match) => match !== null)
    .map((match) => Object.freeze({
      name: match[2],
      sha1: match[1].toLowerCase(),
    }));
  if (!identities.some(({ name, sha1 }) =>
    name === signingIdentity && sha1 === signingCertificateSha1)) reject();
  return signingCertificateSha1;
}

function assertSigningIdentity(
  policy,
  requestedIdentity,
  signingCertificateSha1,
) {
  if (requestedIdentity !== policy.signingIdentity) reject();
  const identitiesListing = run('/usr/bin/security', [
    'find-identity',
    '-v',
    '-p',
    'codesigning',
  ]).stdout.toString('utf8');
  const certificateListing = run('/usr/bin/security', [
    'find-certificate',
    '-a',
    '-c',
    policy.signingIdentity,
    '-Z',
  ]).stdout.toString('utf8');
  return selectA28SigningCertificateSelector({
    certificateListing,
    identitiesListing,
    signingCertificateSha1,
    signingCertificateSha256: policy.signingCertificateSha256,
    signingIdentity: policy.signingIdentity,
  });
}

async function captureSources(isolate, policy) {
  const buffers = {};
  const sources = [];
  const records = [];
  for (const name of sourceNames) {
    const sourcePath = resolve(sourceRoot, name);
    if (dirname(sourcePath) !== sourceRoot || basename(sourcePath) !== name) reject();
    const bytes = await readHeld(sourcePath);
    buffers[name] = bytes;
    const destination = resolve(isolate, name);
    await writeExclusive(destination, bytes, 0o400);
    sources.push(Object.freeze({
      path: 'scripts/a28-witness/' + name,
      sha256: sha256A28(bytes),
    }));
    records.push(Object.freeze({
      mode: 0o400,
      path: name,
      sha256: sha256A28(bytes),
      size: bytes.length,
      type: 'file',
    }));
  }
  const manifest = Object.freeze({
    schemaVersion: 1,
    sources: Object.freeze(sources),
  });
  if (sha256A28(canonicalA28Line(manifest)) !== policy.sourceSha256) reject();
  return Object.freeze({
    buffers: Object.freeze(buffers),
    manifest,
    records: Object.freeze(records),
    sources: isolate,
  });
}

function canonicalAuthorisedApplicationResources(infoPlist, profileBytes) {
  if (!Buffer.isBuffer(infoPlist) || !Buffer.isBuffer(profileBytes)) reject();
  const records = [
    Object.freeze({ mode: 0o700, path: 'Contents', type: 'directory' }),
    Object.freeze({
      mode: 0o400,
      path: 'Contents/Info.plist',
      sha256: sha256A28(infoPlist),
      size: infoPlist.length,
      type: 'file',
    }),
    Object.freeze({
      mode: 0o700,
      path: 'Contents/MacOS',
      type: 'directory',
    }),
    Object.freeze({
      mode: 0o700,
      path: 'Contents/Resources',
      type: 'directory',
    }),
    Object.freeze({
      mode: 0o400,
      path: 'Contents/embedded.provisionprofile',
      sha256: sha256A28(profileBytes),
      size: profileBytes.length,
      type: 'file',
    }),
  ].sort((left, right) => left.path.localeCompare(right.path, 'en'));
  return canonicalA28Json(records);
}

function canonicalAuthorisedUnsignedApplicationRecords(
  authorisedApplicationResources,
  unsignedWitnessBytes,
) {
  if (typeof authorisedApplicationResources !== 'string'
    || !Buffer.isBuffer(unsignedWitnessBytes)) reject();
  let resources;
  try {
    resources = JSON.parse(authorisedApplicationResources);
  } catch {
    reject();
  }
  if (!Array.isArray(resources)) reject();
  return canonicalA28Json([
    ...resources,
    Object.freeze({
      mode: 0o500,
      path: 'Contents/MacOS/A28Witness',
      sha256: sha256A28(unsignedWitnessBytes),
      size: unsignedWitnessBytes.length,
      type: 'file',
    }),
  ].sort((left, right) => left.path.localeCompare(right.path, 'en')));
}

function canonicalAuthorisedSourceRecords(capturedSources, entitlements) {
  if (!Buffer.isBuffer(entitlements)
    || capturedSources.records.length !== sourceNames.length
    || !capturedSources.records.every(({ path }, index) =>
      path === sourceNames[index])) reject();
  const records = [
    ...capturedSources.records,
    Object.freeze({
      mode: 0o400,
      path: 'A28Witness.entitlements',
      sha256: sha256A28(entitlements),
      size: entitlements.length,
      type: 'file',
    }),
  ].sort((left, right) => left.path.localeCompare(right.path, 'en'));
  return canonicalA28Json(records);
}

function renderEntitlements(template, policy) {
  const source = template.toString('utf8');
  if ((source.match(/__APPLICATION_IDENTIFIER__/gu) ?? []).length !== 1
    || (source.match(/__TEAM_IDENTIFIER__/gu) ?? []).length !== 1
    || (source.match(/__KEYCHAIN_ACCESS_GROUP__/gu) ?? []).length !== 1) reject();
  const rendered = source
    .replace('__APPLICATION_IDENTIFIER__', policy.applicationIdentifier)
    .replace('__TEAM_IDENTIFIER__', policy.teamIdentifier)
    .replace('__KEYCHAIN_ACCESS_GROUP__', policy.keychainAccessGroup);
  const plist = decodePlist(Buffer.from(rendered, 'utf8'));
  if (JSON.stringify(plist) !== JSON.stringify(policy.effectiveEntitlements)) reject();
  return Buffer.from(rendered, 'utf8');
}

function parseArguments(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!['--output-root', '--profile', '--signing-identity'].includes(key)
      || value === undefined
      || Object.hasOwn(values, key)) reject();
    values[key] = value;
  }
  if (Object.keys(values).length !== 3) reject();
  return values;
}

export async function buildPinnedA28Witness({
  outputRoot,
  profilePath,
  signingIdentity,
}) {
  process.stderr.write(
    '[working] Validating the pinned A.28 policy, profile and signing identity.\n',
  );
  const policyFile = await readHeldCanonicalA28File(A28_POLICY_PIN_PATH, {
    maximumBytes: A28_MAX_POLICY_BYTES,
    mode: 0o444,
    uid: 0,
  });
  const policy = assertA28PolicyPin(policyFile.value);
  const validatedProfile = await validateProfile(profilePath, policy);
  const signingCertificateSelector = assertSigningIdentity(
    policy,
    signingIdentity,
    validatedProfile.signingCertificateSha1,
  );
  await validateA28DescriptorHelpers();
  const requestedRoot = resolve(outputRoot);
  if (requestedRoot !== outputRoot || dirname(requestedRoot) === requestedRoot) reject();
  const publicationLease = await createA28OutputPublicationLease(requestedRoot);
  try {
    const workspaceLease = await createPrivateA28BuildWorkspace({
      publicationLease,
    });
    try {
      return await buildPinnedA28WitnessInWorkspace({
        policy,
        policyFile,
        profileBytes: validatedProfile.bytes,
        publicationLease,
        requestedRoot,
        signingCertificateSelector,
        workspaceLease,
      });
    } finally {
      await closePrivateA28BuildWorkspace(workspaceLease);
    }
  } finally {
    await closeA28OutputPublicationLease(publicationLease);
  }
}

async function buildPinnedA28WitnessInWorkspace({
  policy,
  policyFile,
  profileBytes,
  publicationLease,
  requestedRoot,
  signingCertificateSelector,
  workspaceLease,
}) {
  const privateRoot = workspaceLease.buildRootPath;
  const isolate = resolve(privateRoot, 'source');
  const application = resolve(privateRoot, 'PIUI A28 VoiceOver Witness.app');
  const contents = resolve(application, 'Contents');
  const macos = resolve(contents, 'MacOS');
  const resources = resolve(contents, 'Resources');
  await mkdir(isolate, { mode: 0o700 });
  await mkdir(macos, { recursive: true, mode: 0o700 });
  await mkdir(resources, { mode: 0o700 });
  const capturedSources = await captureSources(isolate, policy);
  const clangPath = APPLE_TOOLCHAIN_PATHS.clang;
  const sdkPath = APPLE_TOOLCHAIN_PATHS.sdk;
  await assertRootOwnedAppleTool(clangPath);
  await assertRootOwnedAppleSdk(sdkPath);
  const entitlements = renderEntitlements(
    capturedSources.buffers['A28Witness.entitlements.in'],
    policy,
  );
  const entitlementsPath = resolve(isolate, 'A28Witness.entitlements');
  await writeExclusive(entitlementsPath, entitlements, 0o400);
  const authorisedSourceRecords = canonicalAuthorisedSourceRecords(
    capturedSources,
    entitlements,
  );
  const infoPlist = capturedSources.buffers['Info.plist'];
  const authorisedApplicationResources =
    canonicalAuthorisedApplicationResources(infoPlist, profileBytes);
  await writeExclusive(
    resolve(contents, 'Info.plist'),
    infoPlist,
    0o400,
  );
  await writeExclusive(
    resolve(contents, 'embedded.provisionprofile'),
    profileBytes,
    0o400,
  );
  await assertPrivateA28BuildWorkspace(workspaceLease);
  const witnessExecutable = resolve(macos, 'A28Witness');
  const inspectorExecutable = resolve(privateRoot, 'a28-process-identity');
  const rootLauncherExecutable = resolve(privateRoot, 'a28-root-launcher');
  process.stderr.write(
    '[working] Compiling the two native A.28 authorities and witness app.\n',
  );
  const compilerAuthority = captureAppleToolchainAuthority();
  const compilerOptions = {
    env: {
      ...appleToolchainBuildEnvironment(),
      PATH: `${APPLE_TOOLCHAIN_PATHS.bin}:/usr/bin:/bin`,
    },
  };
  try {
    await runPrivateA28WorkspaceCommand(workspaceLease, run, clangPath, [
      '-fobjc-arc',
      '-std=c17',
      '-Wall',
      '-Wextra',
      '-Werror',
      '-isysroot',
      sdkPath,
      '-mmacosx-version-min=' + policy.minimumMacOSVersion,
      '-framework',
      'AppKit',
      '-framework',
      'LocalAuthentication',
      '-framework',
      'Security',
      relative(workspaceLease.workspacePath, resolve(isolate, 'A28WitnessApp.m')),
      '-o',
      relative(workspaceLease.workspacePath, witnessExecutable),
    ], compilerOptions);
    revalidateAppleToolchainAuthority(compilerAuthority);
    await runPrivateA28WorkspaceCommand(workspaceLease, run, clangPath, [
      '-fobjc-arc',
      '-std=c17',
      '-Wall',
      '-Wextra',
      '-Werror',
      '-isysroot',
      sdkPath,
      '-mmacosx-version-min=' + policy.minimumMacOSVersion,
      '-framework',
      'Foundation',
      '-framework',
      'Security',
      relative(
        workspaceLease.workspacePath,
        resolve(isolate, 'A28ProcessIdentity.m'),
      ),
      '-o',
      relative(workspaceLease.workspacePath, inspectorExecutable),
    ], compilerOptions);
    revalidateAppleToolchainAuthority(compilerAuthority);
    await runPrivateA28WorkspaceCommand(workspaceLease, run, clangPath, [
      '-fobjc-arc',
      '-std=c17',
      '-Wall',
      '-Wextra',
      '-Werror',
      '-isysroot',
      sdkPath,
      '-mmacosx-version-min=' + policy.minimumMacOSVersion,
      '-framework',
      'Foundation',
      '-framework',
      'Security',
      relative(workspaceLease.workspacePath, resolve(isolate, 'A28RootLauncher.m')),
      '-o',
      relative(workspaceLease.workspacePath, rootLauncherExecutable),
    ], compilerOptions);
  } finally {
    try {
      revalidateAppleToolchainAuthority(compilerAuthority);
    } finally {
      releaseAppleToolchainAuthority(compilerAuthority);
    }
  }
  await chmod(witnessExecutable, 0o500);
  await chmod(inspectorExecutable, 0o500);
  await chmod(rootLauncherExecutable, 0o500);
  if (sha256A28(await readHeld(inspectorExecutable, 16 * 1024 * 1024))
    !== policy.processInspectorSha256) reject();
  const unsignedWitnessBytes = await readHeld(
    witnessExecutable,
    16 * 1024 * 1024,
  );
  const unsignedRootLauncherBytes = await readHeld(
    rootLauncherExecutable,
    16 * 1024 * 1024,
  );
  const unsignedWitnessSha256 = sha256A28(unsignedWitnessBytes);
  const unsignedRootLauncherSha256 = sha256A28(unsignedRootLauncherBytes);
  if (unsignedWitnessSha256 !== policy.witnessExecutableUnsignedSha256
    || unsignedRootLauncherSha256 !== policy.rootLauncherUnsignedSha256) reject();
  const authorisedUnsignedApplicationRecords =
    canonicalAuthorisedUnsignedApplicationRecords(
      authorisedApplicationResources,
      unsignedWitnessBytes,
    );
  const reproductionApplication = resolve(
    privateRoot,
    'PIUI A28 VoiceOver Witness reproduction.app',
  );
  const reproductionRootLauncher = resolve(
    privateRoot,
    'a28-root-launcher-reproduction',
  );
  await assertPrivateA28BuildWorkspace(workspaceLease);
  await cp(application, reproductionApplication, {
    errorOnExist: true,
    force: false,
    preserveTimestamps: true,
    recursive: true,
  });
  await cp(rootLauncherExecutable, reproductionRootLauncher, {
    errorOnExist: true,
    force: false,
    preserveTimestamps: true,
  });
  await assertPrivateA28BuildWorkspace(workspaceLease);
  const applicationMainRelativePath = 'Contents/MacOS/A28Witness';
  const [firstUnsignedTree, secondUnsignedTree] = await Promise.all([
    treeManifest(application),
    treeManifest(reproductionApplication),
  ]);
  if (canonicalA28Json(firstUnsignedTree.records)
      !== canonicalA28Json(secondUnsignedTree.records)
    || sha256A28(await readHeld(reproductionRootLauncher, 16 * 1024 * 1024))
      !== unsignedRootLauncherSha256) reject();
  process.stderr.write(
    '[working] Creating and comparing two timestamped Developer ID signatures.\n',
  );
  await signPrivateA28WorkspaceCopies({
    applicationPreSigningRecords: authorisedUnsignedApplicationRecords,
    applicationRelativePath: relative(workspaceLease.workspacePath, application),
    entitlementsRelativePath: relative(
      workspaceLease.workspacePath,
      entitlementsPath,
    ),
    entitlementsSha256: sha256A28(entitlements),
    lease: workspaceLease,
    reproductionApplicationPreSigningRecords:
      authorisedUnsignedApplicationRecords,
    reproductionApplicationRelativePath: relative(
      workspaceLease.workspacePath,
      reproductionApplication,
    ),
    reproductionRootLauncherRelativePath: relative(
      workspaceLease.workspacePath,
      reproductionRootLauncher,
    ),
    reproductionRootLauncherUnsignedSha256: unsignedRootLauncherSha256,
    rootLauncherRelativePath: relative(
      workspaceLease.workspacePath,
      rootLauncherExecutable,
    ),
    rootLauncherUnsignedSha256: unsignedRootLauncherSha256,
    signingCertificateSelector,
  });
  const signedSnapshot = await captureHeldA28BuildSnapshot(workspaceLease);
  try {
    await assertHeldA28BuildInputBindings({
      authorisedSourceRecords,
      processInspectorSha256: policy.processInspectorSha256,
      snapshot: signedSnapshot,
    });
    await assertHeldA28BuildModes(signedSnapshot);
    const verificationTargets = Object.freeze([
      Object.freeze({ path: application, type: 'directory' }),
      Object.freeze({ path: rootLauncherExecutable, type: 'file' }),
      Object.freeze({ path: reproductionApplication, type: 'directory' }),
      Object.freeze({ path: reproductionRootLauncher, type: 'file' }),
    ]);
    for (const target of verificationTargets) {
      await runDescriptorAnchoredCodesign({
        lease: workspaceLease,
        mode: 'verify',
        snapshot: signedSnapshot,
        targetRelativePath: relative(workspaceLease.workspacePath, target.path),
        targetType: target.type,
      });
    }
    const launcherDescription = (await runDescriptorAnchoredCodesign({
      lease: workspaceLease,
      mode: 'display',
      snapshot: signedSnapshot,
      targetRelativePath: relative(
        workspaceLease.workspacePath,
        rootLauncherExecutable,
      ),
      targetType: 'file',
    })).stderr.toString('utf8');
    if (!launcherDescription.includes('Identifier=au.com.piui.a28-root-launcher')
      || !launcherDescription.includes('CDHash=' + policy.rootLauncherCdHash)
      || !launcherDescription.includes('flags=0x10000(runtime)')
      || !launcherDescription.includes(
        'Authority=' + policy.signingIdentity,
      )) reject();
    const reproductionLauncherDescription = (
      await runDescriptorAnchoredCodesign({
        lease: workspaceLease,
        mode: 'display',
        snapshot: signedSnapshot,
        targetRelativePath: relative(
          workspaceLease.workspacePath,
          reproductionRootLauncher,
        ),
        targetType: 'file',
      })
    ).stderr.toString('utf8');
    if (!reproductionLauncherDescription.includes(
      'Identifier=au.com.piui.a28-root-launcher',
    )
      || !reproductionLauncherDescription.includes(
        'CDHash=' + policy.rootLauncherCdHash,
      )
      || !reproductionLauncherDescription.includes('flags=0x10000(runtime)')
      || !reproductionLauncherDescription.includes(
        'Authority=' + policy.signingIdentity,
      )) reject();
    const inspect = async (targetApplication) => parseCanonicalA28Line((
      await runDescriptorAnchoredInspector({
        applicationRelativePath: relative(
          workspaceLease.workspacePath,
          targetApplication,
        ),
        bundleIdentifier: policy.bundleIdentifier,
        designatedRequirement: policy.designatedRequirement,
        inspectorRelativePath: relative(
          workspaceLease.workspacePath,
          inspectorExecutable,
        ),
        lease: workspaceLease,
        snapshot: signedSnapshot,
        teamIdentifier: policy.teamIdentifier,
      })
    ).stdout);
    const staticInspection = await inspect(application);
    const inspection = {
      ...staticInspection,
      installedApplicationPath: policy.installedApplicationPath,
      keychainAccessGroups: [policy.keychainAccessGroup],
      profileName: policy.profileName,
      profileSha256: policy.profileSha256,
      profileTeamIdentifiers: [policy.teamIdentifier],
      profileUuid: policy.profileUuid,
    };
    assertA28WitnessAppInspection(inspection, policy);
    const reproductionStaticInspection = await inspect(reproductionApplication);
    if (canonicalA28Json(reproductionStaticInspection)
        !== canonicalA28Json(staticInspection)) reject();
    const applicationName = relative(privateRoot, application);
    const reproductionApplicationName = relative(
      privateRoot,
      reproductionApplication,
    );
    const rootLauncherName = relative(privateRoot, rootLauncherExecutable);
    const reproductionRootLauncherName = relative(
      privateRoot,
      reproductionRootLauncher,
    );
    const firstSignedResources = heldTreeManifest(
      signedSnapshot,
      applicationName,
      new Set([applicationMainRelativePath]),
    );
    const secondSignedResources = heldTreeManifest(
      signedSnapshot,
      reproductionApplicationName,
      new Set([applicationMainRelativePath]),
    );
    if (canonicalA28Json(firstSignedResources.records)
        !== canonicalA28Json(secondSignedResources.records)) reject();
    await assertHeldA28ApplicationResources({
      authorisedApplicationResources,
      snapshot: signedSnapshot,
    });
    const applicationSignatureReproduction = compareTimestampedSignatures(
      await readHeldTreeFile(
        signedSnapshot,
        applicationName + sep + applicationMainRelativePath,
        16 * 1024 * 1024,
      ),
      await readHeldTreeFile(
        signedSnapshot,
        reproductionApplicationName + sep + applicationMainRelativePath,
        16 * 1024 * 1024,
      ),
    );
    const rootLauncherSignatureReproduction = compareTimestampedSignatures(
      await readHeldTreeFile(
        signedSnapshot,
        rootLauncherName,
        16 * 1024 * 1024,
      ),
      await readHeldTreeFile(
        signedSnapshot,
        reproductionRootLauncherName,
        16 * 1024 * 1024,
      ),
    );
    assertSignedReproductionMatchesUnsigned(
      applicationSignatureReproduction,
      unsignedWitnessBytes,
    );
    assertSignedReproductionMatchesUnsigned(
      rootLauncherSignatureReproduction,
      unsignedRootLauncherBytes,
    );
    const firstSignedTree = heldTreeManifest(signedSnapshot, applicationName);
    const secondSignedTree = heldTreeManifest(
      signedSnapshot,
      reproductionApplicationName,
    );
    const expectedPrivateEntries = Object.freeze([
      'source',
      'PIUI A28 VoiceOver Witness.app',
      'a28-process-identity',
      'a28-root-launcher',
      'PIUI A28 VoiceOver Witness reproduction.app',
      'a28-root-launcher-reproduction',
    ].sort((left, right) => left.localeCompare(right, 'en')));
    const actualPrivateEntries = signedSnapshot.records
      .map(({ path }) => path)
      .filter((path) => !path.includes(sep))
      .sort((left, right) => left.localeCompare(right, 'en'));
    if (canonicalA28Json(actualPrivateEntries)
      !== canonicalA28Json(expectedPrivateEntries)) reject();
    await assertHeldTreeAt(signedSnapshot, privateRoot);
    const result = Object.freeze({
      application: resolve(requestedRoot, 'PIUI A28 VoiceOver Witness.app'),
      authoritative: false,
      humanWitnessed: false,
      inspectorExecutable: resolve(requestedRoot, 'a28-process-identity'),
      rootLauncherExecutable: resolve(requestedRoot, 'a28-root-launcher'),
      reproduction: Object.freeze({
        application: Object.freeze({
          firstFullTreeSha256: firstSignedTree.sha256,
          secondFullTreeSha256: secondSignedTree.sha256,
          signatures: applicationSignatureReproduction,
        }),
        rootLauncher: rootLauncherSignatureReproduction,
      }),
      policyPinSha256: sha256A28(policyFile.bytes),
      rootInstallationRequired: true,
      schemaVersion: 1,
    });
    process.stderr.write(
      '[working] Publishing the exact verified A.28 build directory.\n',
    );
    await publishHeldA28Build({
      lease: workspaceLease,
      publicationLease,
      snapshot: signedSnapshot,
    });
    await assertA28OutputPublicationLease(publicationLease);
    await assertHeldTreeAt(signedSnapshot, requestedRoot);
    process.stdout.write(canonicalA28Line(result));
    return result;
  } finally {
    await closeHeldA28BuildSnapshot(signedSnapshot);
  }
}

async function main() {
  const arguments_ = parseArguments(process.argv.slice(2));
  await buildPinnedA28Witness({
    outputRoot: resolve(arguments_['--output-root']),
    profilePath: resolve(arguments_['--profile']),
    signingIdentity: arguments_['--signing-identity'],
  });
}

if (import.meta.url === new URL(process.argv[1], 'file:').href) {
  main().catch((error) => {
    process.stderr.write('A.28 witness build failed: ' + error.message + '\n');
    process.exitCode = 1;
  });
}
