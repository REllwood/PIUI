require 'base64'
require 'digest'
require 'fiddle/import'
require 'json'

module A28StageNative
  extend Fiddle::Importer
  dlload Fiddle::Handle::DEFAULT

  extern 'void* acl_get_fd_np(int, int)'
  extern 'int acl_free(void*)'
  extern 'int close(int)'
  extern 'int closedir(void*)'
  extern 'void* fdopendir(int)'
  extern 'int fchmod(int, unsigned int)'
  extern 'int fgetattrlist(int, void*, void*, unsigned long, unsigned long)'
  extern 'long fgetxattr(int, const char*, void*, unsigned long, unsigned int, int)'
  extern 'long flistxattr(int, void*, unsigned long, int)'
  extern 'int fsync(int)'
  extern 'int mkdirat(int, const char*, unsigned int)'
  extern 'int openat(int, const char*, int, unsigned int)'
  extern 'void* readdir(void*)'
end

O_RDONLY = 0x0000
O_RDWR = 0x0002
O_NONBLOCK = 0x0004
O_NOFOLLOW = 0x0100
O_CREAT = 0x0200
O_EXCL = 0x0800
O_RESOLVE_BENEATH = 0x00001000
O_DIRECTORY = 0x00100000
O_CLOEXEC = 0x01000000
O_NOFOLLOW_ANY = 0x20000000
AT_FLAGS = O_CLOEXEC | O_NOFOLLOW | O_NOFOLLOW_ANY | O_RESOLVE_BENEATH
ACL_TYPE_EXTENDED = 0x00000100
PROVENANCE_NAME = 'com.apple.provenance'.b.freeze
MAX_PLAN_BYTES = 16 * 1024 * 1024
MAX_XATTR_NAMES_BYTES = 1024 * 1024
MAX_XATTR_VALUE_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TREE_BYTES = 2 * 1024 * 1024 * 1024
MAX_TREE_ENTRIES = 16_384

def fail_closed(message = 'native stage rejected')
  STDERR.write("#{message}\n")
  exit 90
end

def safe_name?(name)
  name.is_a?(String) && !name.empty? && name != '.' && name != '..' &&
    !name.include?("\0") && !name.include?('/') && name.bytesize <= 255
end

def safe_relative?(path)
  return false unless path.is_a?(String) && !path.empty? && !path.start_with?('/')

  parts = path.split('/', -1)
  !path.include?("\0") && parts.all? { |part| safe_name?(part) }
end

def exact_keys(value, expected)
  fail_closed unless value.is_a?(Hash) && value.keys.sort == expected.sort
end

def held_io(number)
  IO.for_fd(number, autoclose: false)
rescue StandardError
  fail_closed
end

def identity(state)
  {
    'dev' => state.dev.to_s,
    'gid' => state.gid,
    'ino' => state.ino.to_s,
    'mode' => state.mode,
    'uid' => state.uid
  }
end

def same_identity?(left, right)
  %w[dev ino uid gid mode].all? { |field| left[field] == right[field] }
end

def open_at(parent_fd, name, flags, mode = 0)
  fail_closed unless safe_name?(name)

  Fiddle.last_error = 0
  descriptor = A28StageNative.openat(parent_fd, name, flags | AT_FLAGS, mode)
  fail_closed if descriptor.negative?
  IO.for_fd(descriptor)
end

def absent_at?(parent_fd, name)
  Fiddle.last_error = 0
  descriptor = A28StageNative.openat(
    parent_fd,
    name,
    O_RDONLY | O_NONBLOCK | AT_FLAGS,
    0
  )
  unless descriptor.negative?
    A28StageNative.close(descriptor)
    return false
  end
  fail_closed unless Fiddle.last_error == Errno::ENOENT::Errno
  true
end

def metadata_for(descriptor)
  Fiddle.last_error = 0
  acl = A28StageNative.acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED)
  if acl.to_i.zero?
    fail_closed unless Fiddle.last_error == Errno::ENOENT::Errno
  else
    A28StageNative.acl_free(acl)
    fail_closed('extended ACL rejected')
  end

  attribute_list = [5, 0, 0x00040000, 0, 0, 0, 0].pack('SSLLLLL')
  attribute_buffer = Fiddle::Pointer.malloc(8)
  fail_closed unless A28StageNative.fgetattrlist(
    descriptor,
    attribute_list,
    attribute_buffer,
    8,
    0
  ).zero?
  attribute_length, flags = attribute_buffer.to_s(8).unpack('LL')
  fail_closed unless attribute_length == 8

  names_length = A28StageNative.flistxattr(descriptor, 0, 0, 0)
  fail_closed if names_length.negative? || names_length > MAX_XATTR_NAMES_BYTES
  names = []
  unless names_length.zero?
    names_buffer = Fiddle::Pointer.malloc(names_length)
    fail_closed unless A28StageNative.flistxattr(
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

  xattrs = names.map do |name|
    value_length = A28StageNative.fgetxattr(descriptor, name, 0, 0, 0, 0)
    fail_closed if value_length.negative? || value_length > MAX_XATTR_VALUE_BYTES
    value = ''.b
    unless value_length.zero?
      value_buffer = Fiddle::Pointer.malloc(value_length)
      fail_closed unless A28StageNative.fgetxattr(
        descriptor,
        name,
        value_buffer,
        value_length,
        0,
        0
      ) == value_length
      value = value_buffer.to_s(value_length)
    end
    [name.b, value]
  end
  fail_closed unless xattrs.map(&:first).uniq.length == xattrs.length
  {
    'flags' => flags,
    'xattrs' => xattrs.sort_by(&:first).map do |name, value|
      { 'nameHex' => name.unpack1('H*'), 'valueHex' => value.unpack1('H*') }
    end
  }
end

def provenance_hex(metadata)
  fail_closed unless metadata['flags'].zero?
  unexpected = metadata['xattrs'].reject do |record|
    [record['nameHex']].pack('H*') == PROVENANCE_NAME
  end
  fail_closed('unexpected extended attribute rejected') unless unexpected.empty?
  fail_closed if metadata['xattrs'].length > 1
  metadata['xattrs'].first&.fetch('valueHex', nil)
end

def assert_stage_metadata(descriptor, allowed_provenance)
  metadata = metadata_for(descriptor)
  actual = provenance_hex(metadata)
  fail_closed('stage provenance rejected') unless actual.nil? || actual == allowed_provenance
  metadata
end

def read_exact(io, size)
  fail_closed unless size.is_a?(Integer) && size >= 0 && size <= MAX_FILE_BYTES
  output = ''.b
  while output.bytesize < size
    chunk = io.read([1024 * 1024, size - output.bytesize].min)
    fail_closed if chunk.nil? || chunk.empty?
    output << chunk
  end
  output
end

def hash_io(io, expected_size)
  fail_closed unless expected_size.is_a?(Integer) && expected_size >= 0
  io.seek(0, IO::SEEK_SET)
  digest = Digest::SHA256.new
  read_size = 0
  loop do
    chunk = io.read(1024 * 1024)
    break if chunk.nil? || chunk.empty?

    read_size += chunk.bytesize
    fail_closed if read_size > expected_size
    digest.update(chunk)
  end
  fail_closed unless read_size == expected_size
  digest.hexdigest
end

def directory_names(descriptor)
  duplicate = A28StageNative.openat(
    descriptor,
    '.',
    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NOFOLLOW_ANY,
    0
  )
  fail_closed if duplicate.negative?
  stream = A28StageNative.fdopendir(duplicate)
  if stream.to_i.zero?
    A28StageNative.close(duplicate)
    fail_closed
  end
  names = []
  begin
    loop do
      Fiddle.last_error = 0
      pointer = A28StageNative.readdir(stream)
      if pointer.to_i.zero?
        fail_closed unless Fiddle.last_error.zero?
        break
      end
      header = pointer.to_s(21)
      record_length = header.byteslice(16, 2).unpack1('S')
      name_length = header.byteslice(18, 2).unpack1('S')
      fail_closed if record_length < 22 || record_length > 1024 || name_length > 255
      record = pointer.to_s(record_length)
      name = record.byteslice(21, name_length)
      fail_closed if name.nil? || name.include?("\0")
      next if name == '.' || name == '..'

      fail_closed unless safe_name?(name)
      names << name
    end
  ensure
    fail_closed unless A28StageNative.closedir(stream).zero?
  end
  fail_closed unless names.uniq.length == names.length
  names.sort
end

def emit_ready(control, point, logical_path = '')
  STDOUT.write("READY\t#{point}\t#{logical_path}\n")
  STDOUT.flush
  fail_closed unless control.gets == "GO\n"
end

def parse_plan
  line = STDIN.gets(MAX_PLAN_BYTES + 1)
  fail_closed if line.nil? || line.bytesize > MAX_PLAN_BYTES || !line.end_with?("\n")
  JSON.parse(line)
rescue JSON::ParserError
  fail_closed
end

def direct_children(paths)
  children = Hash.new { |hash, key| hash[key] = [] }
  paths.each do |path|
    parent, name = path.include?('/') ? path.rpartition('/').values_at(0, 2) : ['', path]
    children[parent] << name
  end
  children.each_value(&:sort!)
  children
end

def verify_binding(parent, name, held, type)
  flags = O_RDONLY | O_NONBLOCK
  flags |= O_DIRECTORY if type == 'directory'
  reopened = open_at(parent.fileno, name, flags)
  begin
    fail_closed unless same_identity?(identity(held.stat), identity(reopened.stat))
  ensure
    reopened.close
  end
end

def write_stage
  plan = parse_plan
  exact_keys(plan, %w[directories files gid hooks parent rootName uid])
  fail_closed unless safe_name?(plan['rootName'])
  fail_closed unless plan['uid'].is_a?(Integer) && plan['uid'] > 0
  fail_closed unless plan['gid'].is_a?(Integer) && plan['gid'] >= 0
  exact_keys(plan['parent'], %w[dev gid ino mode uid])
  exact_keys(plan['hooks'], %w[afterEntry afterRoot])
  fail_closed unless [true, false].include?(plan['hooks']['afterRoot'])
  after_entry = plan['hooks']['afterEntry']
  fail_closed unless after_entry.nil? || safe_relative?(after_entry)
  parent = held_io(3)
  control = held_io(4)
  fail_closed unless parent.stat.directory?
  fail_closed unless same_identity?(identity(parent.stat), plan['parent'])
  fail_closed unless absent_at?(parent.fileno, plan['rootName'])

  directories = plan['directories']
  files = plan['files']
  fail_closed unless directories.is_a?(Array) && files.is_a?(Array)
  fail_closed unless directories.all? { |path| safe_relative?(path) }
  fail_closed unless directories.uniq.length == directories.length
  file_paths = files.map do |record|
    exact_keys(record, %w[path sha256 size])
    fail_closed unless safe_relative?(record['path'])
    fail_closed unless record['size'].is_a?(Integer) && record['size'] >= 1 &&
      record['size'] <= MAX_FILE_BYTES
    fail_closed unless record['sha256'].is_a?(String) &&
      record['sha256'].match?(/A[0-9a-f]{64}z/)
    record['path']
  end
  fail_closed unless file_paths.uniq.length == file_paths.length
  all_paths = directories + file_paths
  fail_closed unless all_paths.uniq.length == all_paths.length
  fail_closed if all_paths.length > MAX_TREE_ENTRIES
  fail_closed if files.sum { |record| record['size'] } > MAX_TREE_BYTES
  known_directories = [''] + directories
  all_paths.each do |path|
    parent_path = path.include?('/') ? path.rpartition('/').first : ''
    fail_closed unless known_directories.include?(parent_path)
  end
  fail_closed unless directories == directories.sort_by { |path| [path.count('/'), path] }
  fail_closed unless files == files.sort_by { |record| record['path'] }

  fail_closed unless A28StageNative.mkdirat(parent.fileno, plan['rootName'], 0o700).zero?
  root = open_at(parent.fileno, plan['rootName'], O_RDONLY | O_DIRECTORY)
  handles = { '' => root }
  file_records = {}
  begin
    root_state = root.stat
    fail_closed unless root_state.directory? && root_state.uid == plan['uid'] &&
      root_state.gid == plan['gid'] && (root_state.mode & 0o7777) == 0o700
    root_provenance = provenance_hex(metadata_for(root.fileno))
    emit_ready(control, 'after-output-root-create') if plan['hooks']['afterRoot']
    verify_binding(parent, plan['rootName'], root, 'directory')

    directories.each do |path|
      parent_path, name = path.include?('/') ? path.rpartition('/').values_at(0, 2) : ['', path]
      directory_parent = handles.fetch(parent_path)
      fail_closed unless A28StageNative.mkdirat(directory_parent.fileno, name, 0o700).zero?
      handle = open_at(directory_parent.fileno, name, O_RDONLY | O_DIRECTORY)
      state = handle.stat
      fail_closed unless state.directory? && state.uid == plan['uid'] &&
        state.gid == plan['gid'] && (state.mode & 0o7777) == 0o700
      assert_stage_metadata(handle.fileno, root_provenance)
      handles[path] = handle
    end

    files.each do |record|
      path = record['path']
      parent_path, name = path.include?('/') ? path.rpartition('/').values_at(0, 2) : ['', path]
      file_parent = handles.fetch(parent_path)
      handle = open_at(file_parent.fileno, name, O_RDWR | O_CREAT | O_EXCL, 0o600)
      bytes = read_exact(STDIN, record['size'])
      fail_closed unless Digest::SHA256.hexdigest(bytes) == record['sha256']
      written = 0
      while written < bytes.bytesize
        count = handle.write(bytes.byteslice(written, bytes.bytesize - written))
        fail_closed if count.nil? || count <= 0
        written += count
      end
      fail_closed unless A28StageNative.fchmod(handle.fileno, 0o400).zero?
      fail_closed unless A28StageNative.fsync(handle.fileno).zero?
      state = handle.stat
      fail_closed unless state.file? && state.nlink == 1 && state.uid == plan['uid'] &&
        state.gid == plan['gid'] && (state.mode & 0o7777) == 0o400 &&
        state.size == record['size']
      assert_stage_metadata(handle.fileno, root_provenance)
      handles[path] = handle
      file_records[path] = record
      if after_entry == path
        emit_ready(control, 'after-output-entry-create', path)
        verify_binding(file_parent, name, handle, 'file')
      end
    end
    fail_closed unless STDIN.read(1).nil?

    children = direct_children(all_paths)
    handles.each do |path, handle|
      state = handle.stat
      type = file_records.key?(path) ? 'file' : 'directory'
      if type == 'file'
        record = file_records.fetch(path)
        fail_closed unless state.file? && state.nlink == 1 &&
          state.size == record['size'] && hash_io(handle, state.size) == record['sha256']
      else
        fail_closed unless state.directory?
        fail_closed unless directory_names(handle.fileno) == children.fetch(path, [])
      end
      fail_closed unless state.uid == plan['uid'] && state.gid == plan['gid']
      fail_closed unless (state.mode & 0o7777) == (type == 'file' ? 0o400 : 0o700)
      assert_stage_metadata(handle.fileno, root_provenance)
      next if path.empty?

      parent_path, name = path.include?('/') ? path.rpartition('/').values_at(0, 2) : ['', path]
      verify_binding(handles.fetch(parent_path), name, handle, type)
    end
    verify_binding(parent, plan['rootName'], root, 'directory')
    handles.values.select { |handle| handle.stat.directory? }.reverse_each do |handle|
      fail_closed unless A28StageNative.fsync(handle.fileno).zero?
    end
    STDOUT.write("DONE\n")
    STDOUT.flush
  ensure
    handles.values.reverse_each do |handle|
      handle.close unless handle.closed?
    rescue StandardError
      fail_closed
    end
  end
end

def inspect_stage
  plan = parse_plan
  exact_keys(plan, %w[gid hook includePaths rootName uid])
  fail_closed unless plan['uid'].is_a?(Integer) && plan['uid'] > 0
  fail_closed unless plan['gid'].is_a?(Integer) && plan['gid'] >= 0
  fail_closed unless safe_name?(plan['rootName'])
  fail_closed unless [true, false].include?(plan['hook'])
  fail_closed unless plan['includePaths'].is_a?(Array) &&
    plan['includePaths'].all? { |path| safe_relative?(path) } &&
    plan['includePaths'].uniq.length == plan['includePaths'].length

  root = held_io(3)
  parent = held_io(4)
  control = held_io(5)
  fail_closed unless root.stat.directory? && parent.stat.directory?
  verify_binding(parent, plan['rootName'], root, 'directory')
  root_state = root.stat
  fail_closed unless root_state.uid == plan['uid'] && root_state.gid == plan['gid'] &&
    (root_state.mode & 0o7777) == 0o700
  root_provenance = provenance_hex(metadata_for(root.fileno))
  handles = { '' => root }
  parent_paths = {}
  directory_members = {}
  records = []
  total_bytes = 0
  queue = ['']
  begin
    until queue.empty?
      directory_path = queue.shift
      directory = handles.fetch(directory_path)
      names = directory_names(directory.fileno)
      directory_members[directory_path] = names
      names.each do |name|
        path = directory_path.empty? ? name : "#{directory_path}/#{name}"
        fail_closed unless safe_relative?(path)
        handle = open_at(directory.fileno, name, O_RDONLY | O_NONBLOCK)
        state = handle.stat
        type = if state.directory?
          'directory'
        elsif state.file?
          'file'
        else
          fail_closed('special stage entry rejected')
        end
        fail_closed if type == 'file' && state.nlink != 1
        expected_mode = type == 'file' ? 0o400 : 0o700
        fail_closed unless state.uid == plan['uid'] && state.gid == plan['gid'] &&
          (state.mode & 0o7777) == expected_mode
        assert_stage_metadata(handle.fileno, root_provenance)
        handles[path] = handle
        parent_paths[path] = directory_path
        record = {
          'dev' => state.dev.to_s,
          'gid' => state.gid,
          'ino' => state.ino.to_s,
          'mode' => state.mode & 0o7777,
          'path' => path,
          'type' => type,
          'uid' => state.uid
        }
        if type == 'directory'
          queue << path
        else
          fail_closed if state.size < 1 || state.size > MAX_FILE_BYTES
          total_bytes += state.size
          fail_closed if total_bytes > MAX_TREE_BYTES
          record['sha256'] = hash_io(handle, state.size)
          record['size'] = state.size
          if plan['includePaths'].include?(path)
            fail_closed if state.size > 16 * 1024 * 1024
            handle.seek(0, IO::SEEK_SET)
            record['bytesBase64'] = Base64.strict_encode64(read_exact(handle, state.size))
          end
        end
        records << record
        fail_closed if records.length > MAX_TREE_ENTRIES
      end
    end
    fail_closed unless (plan['includePaths'] - records.map { |record| record['path'] }).empty?
    records.sort_by! { |record| record['path'] }
    snapshot = {
      'records' => records,
      'root' => identity(root.stat),
      'rootProvenanceHex' => root_provenance
    }
    STDOUT.write("SNAPSHOT\t#{Base64.strict_encode64(JSON.generate(snapshot))}\n")
    STDOUT.flush
    emit_ready(control, 'after-validation-snapshot') if plan['hook']

    verify_binding(parent, plan['rootName'], root, 'directory')
    handles.each do |path, handle|
      state = handle.stat
      type = path.empty? || state.directory? ? 'directory' : 'file'
      fail_closed unless type == 'directory' ? state.directory? : state.file?
      fail_closed unless state.uid == plan['uid'] && state.gid == plan['gid']
      fail_closed unless (state.mode & 0o7777) == (type == 'file' ? 0o400 : 0o700)
      assert_stage_metadata(handle.fileno, root_provenance)
      if type == 'directory'
        fail_closed unless directory_names(handle.fileno) == directory_members.fetch(path)
      else
        record = records.find { |candidate| candidate['path'] == path }
        fail_closed unless state.nlink == 1 && state.size == record['size'] &&
          hash_io(handle, state.size) == record['sha256']
      end
      next if path.empty?

      parent_path = parent_paths.fetch(path)
      name = path.include?('/') ? path.rpartition('/').last : path
      verify_binding(handles.fetch(parent_path), name, handle, type)
    end
    verify_binding(parent, plan['rootName'], root, 'directory')
    STDOUT.write("DONE\n")
    STDOUT.flush
  ensure
    handles.reject { |path, _handle| path.empty? }.values.reverse_each do |handle|
      handle.close unless handle.closed?
    rescue StandardError
      fail_closed
    end
  end
end

case ARGV
when ['metadata']
  metadata = metadata_for(held_io(3).fileno)
  STDOUT.write("METADATA\t#{Base64.strict_encode64(JSON.generate(metadata))}\n")
when ['write']
  write_stage
when ['inspect']
  inspect_stage
else
  fail_closed
end
