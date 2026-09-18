import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  realpathSync,
  readSync,
} from 'node:fs';

const SYSTEM_RUBY = '/usr/bin/ruby';
const MAX_INSPECTOR_OUTPUT_BYTES = 64 * 1024;
const ACL_INSPECTOR_TIMEOUT_MS = 30_000;
// Controlled package finalisation can retire two complete production sidecar
// trees while the enclosing proof is still loading the same filesystem. Keep
// removal finite without treating a loaded but progressing unlink walk as a
// security rejection.
const TREE_REMOVAL_TIMEOUT_MS = 180_000;
const RUBY_FIDDLE_PRELUDE = [
  'series = RUBY_VERSION[/\\A\\d+\\.\\d+/]',
  'base = "/System/Library/Frameworks/Ruby.framework/Versions/#{series}/usr/lib/ruby/#{series}.0"',
  'extensions = Dir[File.join(base, "*", "fiddle.bundle")]',
  'exit 1 unless extensions.length == 1',
  'require extensions[0]',
  'def Fiddle.last_error; Thread.current[:__FIDDLE_LAST_ERROR__]; end',
  'def Fiddle.last_error=(error); Thread.current[:__FIDDLE_LAST_ERROR__] = error; end',
  'library = Fiddle::Handle::DEFAULT',
];
const RUBY_ACL_INSPECTOR = [
  ...RUBY_FIDDLE_PRELUDE,
  'get_acl = Fiddle::Function.new(library["acl_get_fd_np"], [Fiddle::TYPE_INT, Fiddle::TYPE_INT], Fiddle::TYPE_VOIDP)',
  'free_acl = Fiddle::Function.new(library["acl_free"], [Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT)',
  'target = IO.for_fd(3, autoclose: false)',
  'before = target.stat',
  'acl = get_acl.call(3, 0x100)',
  'if acl.to_i == 0',
  '  exit 1 unless Fiddle.last_error == 2',
  'else',
  '  free_acl.call(acl)',
  '  exit 1',
  'end',
  'after = target.stat',
  'exit 1 unless [before.dev, before.ino, before.mode, before.uid, before.gid] == [after.dev, after.ino, after.mode, after.uid, after.gid]',
].join(';');
const RUBY_DESCRIPTOR_TREE_REMOVER = [
  ...RUBY_FIDDLE_PRELUDE,
  'removefileat = Fiddle::Function.new(library["removefileat"], [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT], Fiddle::TYPE_INT)',
  'unlinkat = Fiddle::Function.new(library["unlinkat"], [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT], Fiddle::TYPE_INT)',
  'root = IO.for_fd(3, autoclose: false)',
  'parent = IO.for_fd(4, autoclose: false)',
  'root_before = root.stat',
  'parent_before = parent.stat',
  'path_buffer = "\\0" * 1024',
  'exit 1 unless root.fcntl(50, path_buffer) == 0',
  'root_path = path_buffer.split("\\0", 2)[0]',
  'parent_buffer = "\\0" * 1024',
  'exit 1 unless parent.fcntl(50, parent_buffer) == 0',
  'parent_path = parent_buffer.split("\\0", 2)[0]',
  'exit 1 unless File.dirname(root_path) == parent_path',
  'name = File.basename(root_path)',
  'exit 1 if name.empty? || name == "." || name == ".." || name.include?("/")',
  'entry_before = File.lstat(root_path)',
  'exit 1 unless entry_before.directory? && !entry_before.symlink? && [entry_before.dev, entry_before.ino] == [root_before.dev, root_before.ino]',
  'exit 1 unless removefileat.call(3, ".", 0, 3) == 0',
  'root_after = root.stat',
  'exit 1 unless [root_after.dev, root_after.ino, root_after.mode, root_after.uid, root_after.gid] == [root_before.dev, root_before.ino, root_before.mode, root_before.uid, root_before.gid]',
  'path_after_buffer = "\\0" * 1024',
  'exit 1 unless root.fcntl(50, path_after_buffer) == 0',
  'path_after = path_after_buffer.split("\\0", 2)[0]',
  'exit 1 unless path_after == root_path',
  'entry_after = File.lstat(path_after)',
  'exit 1 unless entry_after.directory? && !entry_after.symlink? && [entry_after.dev, entry_after.ino] == [root_before.dev, root_before.ino]',
  'exit 1 unless unlinkat.call(4, name, 0x80) == 0',
  'begin; File.lstat(root_path); exit 1; rescue Errno::ENOENT; end',
  'exit 1 unless [parent.stat.dev, parent.stat.ino] == [parent_before.dev, parent_before.ino]',
].join(';');

function rejected() {
  throw new Error('Descriptor ACL inspection rejected');
}

function sameIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid;
}

function inspectorIdentityMatches(item, inspector) {
  return item.isFile() && !item.isSymbolicLink() && item.nlink === 1
    && item.dev === inspector.dev && item.ino === inspector.ino
    && item.size === inspector.size && item.mode === inspector.mode
    && item.uid === inspector.uid && item.gid === inspector.gid;
}

function descriptorSha256(fd, size) {
  const digest = createHash('sha256');
  const buffer = Buffer.allocUnsafe(64 * 1024);
  let offset = 0;
  while (offset < size) {
    const length = readSync(fd, buffer, 0, Math.min(buffer.length, size - offset), offset);
    if (length <= 0) rejected();
    digest.update(buffer.subarray(0, length));
    offset += length;
  }
  return digest.digest('hex');
}

function openValidatedInspector(inspector) {
  if (!inspector || inspector.path !== SYSTEM_RUBY
    || realpathSync(inspector.path) !== SYSTEM_RUBY) rejected();
  const pathItem = lstatSync(inspector.path);
  if (!inspectorIdentityMatches(pathItem, inspector)
    || (pathItem.mode & 0o022) !== 0 || pathItem.uid !== 0) rejected();
  const fd = openSync(
    inspector.path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
  );
  try {
    const opened = fstatSync(fd);
    if (!inspectorIdentityMatches(opened, inspector)
      || descriptorSha256(fd, opened.size) !== inspector.sha256) rejected();
    return fd;
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

export function assertDescriptorHasNoAcl(fd, inspector) {
  const inspectorFd = openValidatedInspector(inspector);
  try {
    const before = fstatSync(fd);
    const inspectorBefore = fstatSync(inspectorFd);
    const result = spawnSync(SYSTEM_RUBY, [
      '--disable=gems,rubyopt,did_you_mean',
      '-C/',
      '-e',
      RUBY_ACL_INSPECTOR,
    ], {
      env: { PATH: '/usr/bin:/bin' },
      stdio: ['ignore', 'pipe', 'pipe', fd],
      maxBuffer: MAX_INSPECTOR_OUTPUT_BYTES,
      timeout: ACL_INSPECTOR_TIMEOUT_MS,
    });
    const after = fstatSync(fd);
    const inspectorAfter = fstatSync(inspectorFd);
    const pathAfter = lstatSync(inspector.path);
    if (result.error || result.status !== 0 || result.signal !== null
      || !Buffer.isBuffer(result.stdout) || result.stdout.length !== 0
      || !Buffer.isBuffer(result.stderr) || result.stderr.length !== 0
      || !sameIdentity(before, after)
      || !sameIdentity(inspectorBefore, inspectorAfter)
      || !inspectorIdentityMatches(pathAfter, inspector)
      || descriptorSha256(inspectorFd, inspectorAfter.size) !== inspector.sha256) rejected();
  } finally {
    closeSync(inspectorFd);
  }
}

export function revalidateSystemDescriptorAclInspector(inspector) {
  const fd = openValidatedInspector(inspector);
  try {
    assertDescriptorHasNoAcl(fd, inspector);
  } finally {
    closeSync(fd);
  }
}

export function removeDescriptorBoundTree(witness, inspector) {
  if (!witness || !Number.isSafeInteger(witness.fd) || !Number.isSafeInteger(witness.parentFd)) {
    rejected();
  }
  const inspectorFd = openValidatedInspector(inspector);
  try {
    const rootBefore = fstatSync(witness.fd);
    const parentBefore = fstatSync(witness.parentFd);
    if (!rootBefore.isDirectory() || rootBefore.dev !== witness.dev || rootBefore.ino !== witness.ino
      || !parentBefore.isDirectory() || parentBefore.dev !== witness.parentDev
      || parentBefore.ino !== witness.parentIno) rejected();
    const result = spawnSync(SYSTEM_RUBY, [
      '--disable=gems,rubyopt,did_you_mean',
      '-C/',
      '-e',
      RUBY_DESCRIPTOR_TREE_REMOVER,
    ], {
      env: { PATH: '/usr/bin:/bin' },
      stdio: ['ignore', 'pipe', 'pipe', witness.fd, witness.parentFd],
      maxBuffer: MAX_INSPECTOR_OUTPUT_BYTES,
      timeout: TREE_REMOVAL_TIMEOUT_MS,
    });
    const inspectorAfter = fstatSync(inspectorFd);
    if (result.error || result.status !== 0 || result.signal !== null
      || !Buffer.isBuffer(result.stdout) || result.stdout.length !== 0
      || !Buffer.isBuffer(result.stderr) || result.stderr.length !== 0
      || !inspectorIdentityMatches(inspectorAfter, inspector)
      || descriptorSha256(inspectorFd, inspectorAfter.size) !== inspector.sha256) rejected();
  } finally {
    closeSync(inspectorFd);
  }
}

export function captureSystemDescriptorAclInspector() {
  if (process.platform !== 'darwin') rejected();
  const fd = openSync(
    SYSTEM_RUBY,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
  );
  try {
    const item = fstatSync(fd);
    const pathItem = lstatSync(SYSTEM_RUBY);
    if (!item.isFile() || item.nlink !== 1 || (item.mode & 0o022) !== 0
      || item.uid !== 0 || !sameIdentity(item, pathItem)
      || item.size !== pathItem.size || realpathSync(SYSTEM_RUBY) !== SYSTEM_RUBY) rejected();
    if (item.size < 4_096) rejected();
    const inspector = Object.freeze({
      path: SYSTEM_RUBY,
      dev: item.dev,
      ino: item.ino,
      size: item.size,
      mode: item.mode,
      uid: item.uid,
      gid: item.gid,
      sha256: descriptorSha256(fd, item.size),
    });
    assertDescriptorHasNoAcl(fd, inspector);
    const pathAfter = lstatSync(inspector.path);
    if (!inspectorIdentityMatches(pathAfter, inspector)) rejected();
    return inspector;
  } finally {
    closeSync(fd);
  }
}
