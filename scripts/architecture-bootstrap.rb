#!/usr/bin/ruby --disable-gems

require 'digest'
require 'etc'
require 'fcntl'
require 'fiddle'
require 'json'
require 'tmpdir'
require 'zlib'

RUBY_SHA256 = '9d6ff3e289c7d908e3c785e0bedd6692d1d6a3377965c88c04d847104b7c892c'.freeze
ENV_SHA256 = '6e506aec3c0cff703ac1e66cedc6f1945354ad41339a38db4425c7c88227128f'.freeze
NODE_ARCHIVE_SHA256 = 'ef28d8fab2c0e4314522d4bb1b7173270aa3937e93b92cb7de79c112ac1fa953'.freeze
NODE_ARCHIVE_BYTES = 50_067_502
NODE_EXECUTABLE_SHA256 = '2e3f1286a7eb3736346ed1803e458a0ff909e2b2d5bc746144dcb76970e9b99d'.freeze
NODE_EXECUTABLE_BYTES = 112_928_848
NODE_CDHASH = '59cdea89a982b05f23e756c08115bebc555ff092'.freeze
NODE_IDENTIFIER = 'node'.freeze
NODE_TEAM_IDENTIFIER = 'HX7739G8FX'.freeze
NODE_DESIGNATED_REQUIREMENT = 'identifier node and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = HX7739G8FX'.freeze
NODE_ARCHIVE_MEMBER = 'node-v22.23.1-darwin-arm64/bin/node'.freeze
NODE_ARCHIVE_ENTRIES = 5_866
NODE_ARCHIVE_EXPANDED_BYTES = 189_140_992
NODE_VERSION = '22.23.1'.freeze
POSIX_SPAWN_START_SUSPENDED = 0x0080
POSIX_SPAWN_SETPGROUP = 0x0002
POSIX_SPAWN_CLOEXEC_DEFAULT = 0x4000
BOOTSTRAP_MODES = {
  'build' => 'build-production.mjs',
  'package' => 'package-spike.mjs',
  'record' => 'record-architecture-gate.mjs'
}.freeze
RUBY_DYLIBS = [
  '/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation',
  '/System/Library/Frameworks/Ruby.framework/Versions/2.6/usr/lib/libruby.2.6.dylib',
  '/System/Library/Frameworks/Security.framework/Versions/A/Security',
  '/usr/lib/libSystem.B.dylib',
  '/usr/lib/libobjc.A.dylib'
].sort.freeze
NODE_DYLIBS = [
  '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation',
  '/System/Library/Frameworks/Security.framework/Versions/A/Security',
  '/usr/lib/libSystem.B.dylib',
  '/usr/lib/libc++.1.dylib'
].sort.freeze

def reject(message)
  raise RuntimeError, message
end

def canonical_json(value)
  case value
  when Hash
    '{' + value.keys.sort.map { |key| "#{JSON.generate(key)}:#{canonical_json(value.fetch(key))}" }.join(',') + '}'
  when Array
    '[' + value.map { |item| canonical_json(item) }.join(',') + ']'
  else
    JSON.generate(value)
  end
end

def sha256_file(path)
  digest = Digest::SHA256.new
  File.open(path, File::RDONLY | File::NOFOLLOW) do |file|
    while (chunk = file.read(1_048_576))
      digest.update(chunk)
    end
  end
  digest.hexdigest
end

def exact_file_state(path, label, uid:, mode:, bytes: nil, sha256: nil, gid: 0)
  state = File.lstat(path)
  reject("#{label} is not a trusted regular file") unless state.file?
  reject("#{label} is a symbolic link") if state.symlink?
  reject("#{label} ownership or mode changed") unless state.uid == uid && state.gid == gid && (state.mode & 0o777) == mode
  reject("#{label} has multiple links") unless state.nlink == 1
  reject("#{label} size changed") if bytes && state.size != bytes
  reject("#{label} digest changed") if sha256 && sha256_file(path) != sha256
  state
end

def safe_system_file(path, label, allow_missing: false)
  canonical = begin
    File.realpath(path)
  rescue Errno::ENOENT
    reject("#{label} escaped system roots") unless allow_missing && path.start_with?('/System/Library/', '/usr/lib/')
    return path
  end
  reject("#{label} escaped system roots") unless canonical.start_with?('/System/Library/', '/usr/lib/')
  state = File.lstat(canonical)
  reject("#{label} is not a root-owned regular file") unless state.file? && !state.symlink? && state.uid == 0 && (state.mode & 0o022).zero?
  canonical
end

def u32le(bytes, offset)
  value = bytes.byteslice(offset, 4)
  reject('Mach-O metadata is truncated') unless value && value.bytesize == 4
  value.unpack1('V')
end

def macho_dylibs(slice, expected_cpu, expected_subtype)
  reject('Mach-O slice is not a 64-bit little-endian image') unless u32le(slice, 0) == 0xfeedfacf
  reject('Mach-O CPU identity changed') unless u32le(slice, 4) == expected_cpu && u32le(slice, 8) == expected_subtype
  reject('Mach-O file type changed') unless u32le(slice, 12) == 2
  commands = u32le(slice, 16)
  command_bytes = u32le(slice, 20)
  reject('Mach-O load-command bounds are invalid') unless commands.between?(1, 4_096) && command_bytes.between?(8, slice.bytesize - 32)
  offset = 32
  dylibs = []
  commands.times do
    command = u32le(slice, offset)
    size = u32le(slice, offset + 4)
    reject('Mach-O load command is malformed') unless size >= 8 && (size % 4).zero? && offset + size <= 32 + command_bytes
    if [0x0c, 0x80000018, 0x8000001f, 0x80000023].include?(command)
      name_offset = u32le(slice, offset + 8)
      reject('Mach-O dylib name offset is invalid') unless name_offset >= 24 && name_offset < size
      raw = slice.byteslice(offset + name_offset, size - name_offset)
      terminator = raw.index("\0")
      reject('Mach-O dylib name is unterminated') unless terminator
      name = raw.byteslice(0, terminator)
      reject('Mach-O dylib name is invalid') unless name.valid_encoding?
      reject('Mach-O dylib name is invalid') unless name.start_with?('/')
      reject('Mach-O dylib name is invalid') if ["\0", "\n", "\r"].any? { |character| name.include?(character) }
      dylibs << name
    end
    offset += size
  end
  reject('Mach-O load-command extent changed') unless offset == 32 + command_bytes
  dylibs.sort
end

def verify_ruby_macho(bytes)
  reject('System Ruby is not the reviewed universal image') unless bytes.byteslice(0, 4).unpack1('N') == 0xcafebabe
  count = bytes.byteslice(4, 4).unpack1('N')
  reject('System Ruby architecture count changed') unless count == 2
  architectures = []
  count.times do |index|
    values = bytes.byteslice(8 + (index * 20), 20).unpack('N5')
    cpu, subtype, offset, size, align = values
    reject('System Ruby fat-slice bounds changed') unless align == 14 && size.positive? && offset + size <= bytes.bytesize
    architectures << [cpu, subtype, macho_dylibs(bytes.byteslice(offset, size), cpu, subtype)]
  end
  expected = [[0x01000007, 3], [0x0100000c, 0x80000002]]
  reject('System Ruby architectures changed') unless architectures.map { |row| row.first(2) } == expected
  reject('System Ruby dylib closure changed') unless architectures.all? { |row| row[2] == RUBY_DYLIBS }
  RUBY_DYLIBS.each { |path| safe_system_file(path, 'System Ruby dylib', allow_missing: true) }
end

def verify_node_macho(bytes)
  dylibs = macho_dylibs(bytes, 0x0100000c, 0)
  reject('Private Node dylib closure changed') unless dylibs == NODE_DYLIBS
  NODE_DYLIBS.each { |path| safe_system_file(path, 'Private Node dylib', allow_missing: true) }
end

def stable_state(state)
  [state.dev, state.ino, state.mode, state.uid, state.gid, state.nlink, state.size,
   state.mtime.to_i, state.mtime.nsec, state.ctime.to_i, state.ctime.nsec]
end

def native_function(name, arguments, result = Fiddle::TYPE_INT)
  Fiddle::Function.new(Fiddle::Handle::DEFAULT[name], arguments, result)
rescue Fiddle::DLError
  reject("System native function is unavailable: #{name}")
end

def pointer_slot
  slot = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP)
  slot[0, Fiddle::SIZEOF_VOIDP] = [0].pack('J')
  slot
end

def pointer_value(slot)
  slot[0, Fiddle::SIZEOF_VOIDP].unpack1('J')
end

def null_pointer?(value)
  value.nil? || value.to_i.zero?
end

def system_cf_constant(name)
  address = Fiddle::Handle::DEFAULT[name]
  value = Fiddle::Pointer.new(address)[0, Fiddle::SIZEOF_VOIDP].unpack1('J')
  reject("System CoreFoundation constant is unavailable: #{name}") if value.zero?
  value
rescue Fiddle::DLError
  reject("System CoreFoundation constant is unavailable: #{name}")
end

def c_vector(values)
  strings = values.map do |value|
    reject('Native spawn argument is invalid') unless value.is_a?(String) && !value.include?("\0")
    Fiddle::Pointer[value + "\0"]
  end
  vector = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP * (strings.length + 1))
  vector[0, Fiddle::SIZEOF_VOIDP * (strings.length + 1)] =
    (strings.map(&:to_i) + [0]).pack('J*')
  [strings, vector]
end

def cf_string(value)
  function = native_function(
    'CFStringCreateWithCString',
    [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT],
    Fiddle::TYPE_VOIDP
  )
  result = function.call(0, Fiddle::Pointer[value + "\0"], 0x08000100)
  reject('CoreFoundation string creation failed') if null_pointer?(result)
  result
end

def cf_string_value(value)
  buffer = Fiddle::Pointer.malloc(4_096)
  copied = native_function(
    'CFStringGetCString',
    [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_INT]
  ).call(value, buffer, 4_096, 0x08000100)
  reject('CoreFoundation string conversion failed') if copied.zero?
  buffer.to_s
end

def assert_live_node_code(pid, expected_path)
  reject('Suspended Node PID is invalid') unless pid.is_a?(Integer) && pid >= 2
  process_path = Fiddle::Pointer.malloc(4_096)
  path_bytes = native_function(
    'proc_pidpath',
    [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT]
  ).call(pid, process_path, 4_096)
  reject('Suspended Node process path is unavailable') unless path_bytes.positive?
  reject('Suspended Node process path changed') unless process_path[0, path_bytes] == expected_path

  releases = []
  begin
    pid_bytes = Fiddle::Pointer.malloc(4)
    pid_bytes[0, 4] = [pid].pack('l')
    pid_number = native_function(
      'CFNumberCreate',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP],
      Fiddle::TYPE_VOIDP
    ).call(0, 3, pid_bytes)
    reject('Suspended Node PID number creation failed') if null_pointer?(pid_number)
    releases << pid_number
    attributes = native_function(
      'CFDictionaryCreateMutable',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
      Fiddle::TYPE_VOIDP
    ).call(0, 1, 0, 0)
    reject('Suspended Node attribute dictionary creation failed') if null_pointer?(attributes)
    releases << attributes
    native_function(
      'CFDictionarySetValue',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
      Fiddle::TYPE_VOID
    ).call(attributes, system_cf_constant('kSecGuestAttributePid'), pid_number)

    code_slot = pointer_slot
    status = native_function(
      'SecCodeCopyGuestWithAttributes',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP]
    ).call(0, attributes, 0, code_slot)
    reject('Suspended Node live code is unavailable') unless status.zero?
    code = pointer_value(code_slot)
    reject('Suspended Node live code reference is empty') if null_pointer?(code)
    releases << code

    requirement_text = cf_string(NODE_DESIGNATED_REQUIREMENT)
    releases << requirement_text
    requirement_slot = pointer_slot
    status = native_function(
      'SecRequirementCreateWithString',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP]
    ).call(requirement_text, 0, requirement_slot)
    reject('Suspended Node requirement compilation failed') unless status.zero?
    requirement = pointer_value(requirement_slot)
    reject('Suspended Node requirement reference is empty') if null_pointer?(requirement)
    releases << requirement
    status = native_function(
      'SecCodeCheckValidity',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP]
    ).call(code, 0, requirement)
    reject('Suspended Node live code requirement failed') unless status.zero?

    information_slot = pointer_slot
    status = native_function(
      'SecCodeCopySigningInformation',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP]
    ).call(code, 2, information_slot)
    reject('Suspended Node signing information is unavailable') unless status.zero?
    information = pointer_value(information_slot)
    reject('Suspended Node signing information is empty') if null_pointer?(information)
    releases << information
    dictionary_value = native_function(
      'CFDictionaryGetValue',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
      Fiddle::TYPE_VOIDP
    )
    identifier = dictionary_value.call(
      information,
      system_cf_constant('kSecCodeInfoIdentifier')
    )
    team = dictionary_value.call(
      information,
      system_cf_constant('kSecCodeInfoTeamIdentifier')
    )
    unique = dictionary_value.call(
      information,
      system_cf_constant('kSecCodeInfoUnique')
    )
    reject('Suspended Node signing identity is incomplete') if [identifier, team, unique].any? do |value|
      null_pointer?(value)
    end
    reject('Suspended Node identifier changed') unless cf_string_value(identifier) == NODE_IDENTIFIER
    reject('Suspended Node team identifier changed') unless cf_string_value(team) == NODE_TEAM_IDENTIFIER
    unique_length = native_function(
      'CFDataGetLength',
      [Fiddle::TYPE_VOIDP],
      Fiddle::TYPE_LONG
    ).call(unique)
    unique_bytes = native_function(
      'CFDataGetBytePtr',
      [Fiddle::TYPE_VOIDP],
      Fiddle::TYPE_VOIDP
    ).call(unique)
    reject('Suspended Node CodeDirectory identity is invalid') unless unique_length == 20 &&
      Fiddle::Pointer.new(unique_bytes.to_i)[0, unique_length].unpack1('H*') == NODE_CDHASH
  ensure
    release = native_function('CFRelease', [Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOID)
    releases.reverse_each { |value| release.call(value) unless null_pointer?(value) }
  end
end

def create_suspended_authenticated_node(node_path, node_state, private_root, root_state,
                                        receipt_reader, arguments, environment)
  node_file = File.open(node_path, File::RDONLY | File::NOFOLLOW)
  root_file = File.open(private_root, File::RDONLY | File::NOFOLLOW)
  child_pid = nil
  attributes = pointer_slot
  actions = pointer_slot
  attributes_initialised = false
  actions_initialised = false
  begin
    reject('Private Node held identity changed') unless stable_state(node_file.stat) == stable_state(node_state) &&
      stable_state(File.lstat(node_path)) == stable_state(node_state)
    reject('Bootstrap private root held identity changed') unless stable_state(root_file.stat) == stable_state(root_state) &&
      stable_state(File.lstat(private_root)) == stable_state(root_state)
    initialise_attributes = native_function('posix_spawnattr_init', [Fiddle::TYPE_VOIDP])
    reject('Native spawn attributes could not be initialised') unless initialise_attributes.call(attributes).zero?
    attributes_initialised = true
    flags = POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETPGROUP |
      POSIX_SPAWN_CLOEXEC_DEFAULT
    reject('Native spawn flags could not be set') unless native_function(
      'posix_spawnattr_setflags',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SHORT]
    ).call(attributes, flags).zero?
    reject('Native spawn process group could not be set') unless native_function(
      'posix_spawnattr_setpgroup',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT]
    ).call(attributes, 0).zero?
    reject('Native spawn actions could not be initialised') unless native_function(
      'posix_spawn_file_actions_init',
      [Fiddle::TYPE_VOIDP]
    ).call(actions).zero?
    actions_initialised = true
    inherit_descriptor = native_function(
      'posix_spawn_file_actions_addinherit_np',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT]
    )
    [0, 1, 2, receipt_reader.fileno].uniq.each do |descriptor|
      reject('Native spawn descriptor inheritance failed') unless inherit_descriptor.call(
        actions,
        descriptor
      ).zero?
    end
    argument_strings, argument_vector = c_vector([node_path, *arguments])
    environment_strings, environment_vector = c_vector(
      environment.keys.sort.map { |key| "#{key}=#{environment.fetch(key)}" }
    )
    pid_slot = Fiddle::Pointer.malloc(4)
    pid_slot[0, 4] = [0].pack('l')
    spawn_status = native_function(
      'posix_spawn',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP,
       Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP]
    ).call(
      pid_slot,
      argument_strings.fetch(0),
      actions,
      attributes,
      argument_vector,
      environment_vector
    )
    reject("Authenticated Node suspended spawn failed: #{spawn_status}") unless spawn_status.zero?
    child_pid = pid_slot[0, 4].unpack1('l')
    reject('Authenticated Node suspended spawn returned an invalid PID') unless child_pid >= 2
    reject('Private Node changed across suspended spawn') unless stable_state(node_file.stat) == stable_state(node_state) &&
      stable_state(File.lstat(node_path)) == stable_state(node_state)
    reject('Bootstrap private root changed across suspended spawn') unless stable_state(root_file.stat) == stable_state(root_state) &&
      stable_state(File.lstat(private_root)) == stable_state(root_state)
    assert_live_node_code(child_pid, node_path)
    reject('Private Node changed during live-code inspection') unless stable_state(node_file.stat) == stable_state(node_state) &&
      stable_state(File.lstat(node_path)) == stable_state(node_state)
    reject('Bootstrap private root changed during live-code inspection') unless stable_state(root_file.stat) == stable_state(root_state) &&
      stable_state(File.lstat(private_root)) == stable_state(root_state)
    {
      'nodeFile' => node_file,
      'nodePath' => node_path,
      'nodeState' => node_state,
      'pid' => child_pid,
      'rootFile' => root_file,
      'rootPath' => private_root,
      'rootState' => root_state
    }
  rescue StandardError
    if child_pid
      Process.kill('KILL', -child_pid) rescue nil
      Process.wait(child_pid) rescue nil
    end
    node_file.close rescue nil
    root_file.close rescue nil
    raise
  ensure
    native_function('posix_spawn_file_actions_destroy', [Fiddle::TYPE_VOIDP]).call(actions) if actions_initialised
    native_function('posix_spawnattr_destroy', [Fiddle::TYPE_VOIDP]).call(attributes) if attributes_initialised
  end
end

def assert_suspended_node_lease(lease)
  reject('Suspended Node lease is invalid') unless lease.is_a?(Hash) &&
    lease.keys.sort == %w[nodeFile nodePath nodeState pid rootFile rootPath rootState].sort
  reject('Private Node held lease changed') unless stable_state(lease.fetch('nodeFile').stat) ==
    stable_state(lease.fetch('nodeState')) &&
    stable_state(File.lstat(lease.fetch('nodePath'))) == stable_state(lease.fetch('nodeState'))
  reject('Bootstrap private root lease changed') unless stable_state(lease.fetch('rootFile').stat) ==
    stable_state(lease.fetch('rootState')) &&
    stable_state(File.lstat(lease.fetch('rootPath'))) == stable_state(lease.fetch('rootState'))
  assert_live_node_code(lease.fetch('pid'), lease.fetch('nodePath'))
  reject('Private Node changed while suspended') unless stable_state(lease.fetch('nodeFile').stat) ==
    stable_state(lease.fetch('nodeState')) &&
    stable_state(File.lstat(lease.fetch('nodePath'))) == stable_state(lease.fetch('nodeState'))
  reject('Bootstrap private root changed while suspended') unless stable_state(lease.fetch('rootFile').stat) ==
    stable_state(lease.fetch('rootState')) &&
    stable_state(File.lstat(lease.fetch('rootPath'))) == stable_state(lease.fetch('rootState'))
end

def resume_suspended_node(lease)
  assert_suspended_node_lease(lease)
  Process.kill('CONT', lease.fetch('pid'))
ensure
  lease.fetch('nodeFile').close rescue nil
  lease.fetch('rootFile').close rescue nil
end

def cleanup_bootstrap_private_root(private_root, expected_root)
  return unless private_root && File.exist?(private_root)
  root = File.lstat(private_root)
  reject('Architecture bootstrap cleanup root changed') unless root.directory? &&
    !root.symlink? && root.uid == Process.uid && root.dev == expected_root.dev &&
    root.ino == expected_root.ino && File.realpath(private_root) == private_root
  allowed = %w[held-source-loader.mjs node node.tar.gz receipt.json source-manifest.json]
  entries = Dir.children(private_root).sort
  reject('Architecture bootstrap cleanup found an unexpected entry') unless (entries - allowed).empty?
  entries.each do |name|
    path = File.join(private_root, name)
    item = File.lstat(path)
    reject('Architecture bootstrap cleanup found an unsafe entry') unless item.file? &&
      !item.symlink? && item.uid == Process.uid && item.nlink == 1
    File.chmod(0o600, path)
    File.unlink(path)
  end
  File.chmod(0o700, private_root)
  Dir.rmdir(private_root)
end

def parse_octal(bytes, label)
  text = bytes.sub("\0", '').strip
  return 0 if text.empty?
  reject("#{label} contains a non-octal tar number") unless text.match?(/\A[0-7]+\z/)
  value = text.to_i(8)
  reject("#{label} contains an unsafe tar number") unless value.between?(0, (2**53) - 1)
  value
end

def tar_text(bytes, label)
  text = bytes.sub(/\0.*\z/m, '')
  reject("#{label} contains invalid tar text") unless text.valid_encoding? && !text.include?("\0")
  text
end

def safe_archive_path(name, label)
  reject("#{label} contains an unsafe archive path") unless name.is_a?(String) && name.bytesize.between?(1, 1_024) && !name.start_with?('/')
  reject("#{label} contains an unsafe archive path") if ["\\", "\0"].any? { |character| name.include?(character) }
  parts = name.sub(%r{/+\z}, '').split('/')
  reject("#{label} contains an escaping archive path") if parts.empty? || parts.any? { |part| part.empty? || part == '.' || part == '..' }
  parts.join('/')
end

def read_exact(io, length, label, allow_eof: false)
  bytes = +''
  bytes.force_encoding(Encoding::BINARY)
  while bytes.bytesize < length
    chunk = io.read(length - bytes.bytesize)
    return nil if allow_eof && bytes.empty? && chunk.nil?
    reject("#{label} is truncated") if chunk.nil? || chunk.empty?
    bytes << chunk
  end
  bytes
end

def write_all(file, bytes)
  offset = 0
  while offset < bytes.bytesize
    count = file.write(bytes.byteslice(offset, bytes.bytesize - offset))
    reject('Private Node output accepted a zero-byte write') unless count && count.positive?
    offset += count
  end
end

def safe_symlink_target(name, target, prefix)
  reject('Node archive contains an unsafe symbolic link') if target.empty? || target.start_with?('/')
  reject('Node archive contains an unsafe symbolic link') if ["\\", "\0"].any? { |character| target.include?(character) }
  stack = name.split('/')[0...-1]
  target.split('/').each do |part|
    next if part.empty? || part == '.'
    if part == '..'
      reject('Node archive symbolic link escapes its prefix') if stack.empty?
      stack.pop
    else
      stack << part
    end
  end
  resolved = stack.join('/')
  reject('Node archive symbolic link escapes its prefix') unless resolved == prefix || resolved.start_with?("#{prefix}/")
end

def extract_pinned_node(archive_path, expected_archive_state, destination)
  output = File.open(destination, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o700)
  node_digest = Digest::SHA256.new
  node_bytes = 0
  node_members = 0
  entries = 0
  expanded = 0
  pending_long_name = nil
  zero_blocks = 0
  prefix = 'node-v22.23.1-darwin-arm64'
  File.open(archive_path, File::RDONLY | File::NOFOLLOW) do |archive|
    before = archive.stat
    path_before = File.lstat(archive_path)
    reject('Private Node archive identity changed before extraction') unless stable_state(before) == expected_archive_state && stable_state(before) == stable_state(path_before)
    archive_digest = Digest::SHA256.new
    while (chunk = archive.read(1_048_576))
      archive_digest.update(chunk)
    end
    reject('Private Node archive digest changed before extraction') unless archive_digest.hexdigest == NODE_ARCHIVE_SHA256
    archive.rewind
    gzip = Zlib::GzipReader.new(archive)
    begin
      loop do
        header = read_exact(gzip, 512, 'Pinned Node tar header')
        expanded += 512
        if header.bytes.all?(&:zero?)
          zero_blocks += 1
          break if zero_blocks == 2
          next
        end
        reject('Pinned Node tar terminator is partial') unless zero_blocks.zero?
        checksum = parse_octal(header.byteslice(148, 8), 'Pinned Node archive')
        actual = header.bytes.each_with_index.sum { |byte, index| index.between?(148, 155) ? 0x20 : byte }
        reject('Pinned Node tar header checksum changed') unless checksum == actual
        reject('Pinned Node archive is not ustar') unless tar_text(header.byteslice(257, 6), 'Pinned Node archive').start_with?('ustar')
        size = parse_octal(header.byteslice(124, 12), 'Pinned Node archive')
        mode = parse_octal(header.byteslice(100, 8), 'Pinned Node archive')
        reject('Pinned Node archive mode is unsafe') unless (mode & ~0o777).zero?
        type = header.getbyte(156)
        raw_name = tar_text(header.byteslice(0, 100), 'Pinned Node archive')
        raw_prefix = tar_text(header.byteslice(345, 155), 'Pinned Node archive')
        raw_name = "#{raw_prefix}/#{raw_name}" unless raw_prefix.empty?
        long_link = type == 0x4c
        name = long_link ? '././@LongLink' : safe_archive_path(pending_long_name || raw_name, 'Pinned Node archive')
        pending_long_name = nil unless long_link
        reject('Pinned Node archive contains an unexpected top level') unless long_link || name == prefix || name.start_with?("#{prefix}/")
        unless [0, 0x30, 0x32, 0x35, 0x4c].include?(type)
          reject('Pinned Node archive contains a link or special entry')
        end
        reject('Pinned Node archive member exceeds its bound') if size > 256 * 1_048_576
        entries += 1
        reject('Pinned Node archive has too many entries') if entries > 10_000
        payload = long_link ? +'' : nil
        payload.force_encoding(Encoding::BINARY) if payload
        remaining = size
        while remaining.positive?
          chunk = read_exact(gzip, [remaining, 1_048_576].min, 'Pinned Node member')
          expanded += chunk.bytesize
          if name == NODE_ARCHIVE_MEMBER
            write_all(output, chunk)
            node_digest.update(chunk)
            node_bytes += chunk.bytesize
          elsif payload
            payload << chunk
          end
          remaining -= chunk.bytesize
        end
        if name == NODE_ARCHIVE_MEMBER
          node_members += 1
          reject('Pinned Node executable archive mode changed') if (mode & 0o111).zero?
        end
        if type == 0x32
          target = tar_text(header.byteslice(157, 100), 'Pinned Node archive')
          reject('Pinned Node symbolic link has data') unless size.zero?
          safe_symlink_target(name, target, prefix)
        elsif type == 0x35
          reject('Pinned Node directory has data') unless size.zero?
        elsif long_link
          reject('Pinned Node GNU long name is malformed') unless payload.bytesize.between?(2, 4_096) && payload.end_with?("\0") && !payload.byteslice(0, payload.bytesize - 1).include?("\0")
          pending_long_name = safe_archive_path(payload.byteslice(0, payload.bytesize - 1), 'Pinned Node archive')
        end
        padding = ((size + 511) / 512 * 512) - size
        unless padding.zero?
          bytes = read_exact(gzip, padding, 'Pinned Node tar padding')
          expanded += bytes.bytesize
          reject('Pinned Node tar padding changed') unless bytes.bytes.all?(&:zero?)
        end
      end
      while (remainder = gzip.read(1_048_576))
        break if remainder.empty?
        expanded += remainder.bytesize
        reject('Pinned Node archive has data after its terminator') unless remainder.bytes.all?(&:zero?)
      end
    ensure
      gzip.finish
    end
    after = archive.stat
    path_after = File.lstat(archive_path)
    reject('Private Node archive changed during extraction') unless stable_state(before) == stable_state(after) && stable_state(after) == stable_state(path_after)
  end
  output.flush
  output.fsync
  output.close
  reject('Pinned Node archive metadata changed') unless entries == NODE_ARCHIVE_ENTRIES && expanded == NODE_ARCHIVE_EXPANDED_BYTES && pending_long_name.nil?
  reject('Pinned Node executable member count changed') unless node_members == 1
  reject('Pinned Node executable size changed') unless node_bytes == NODE_EXECUTABLE_BYTES
  reject('Pinned Node executable digest changed') unless node_digest.hexdigest == NODE_EXECUTABLE_SHA256
  File.chmod(0o500, destination)
end

def copy_authenticated_archive(source_path, destination)
  source = File.open(source_path, File::RDONLY | File::NOFOLLOW)
  before = source.stat
  path_before = File.lstat(source_path)
  reject('Provisioned Node archive is unsafe') unless before.file? && !before.symlink? && before.uid == Process.uid && before.nlink == 1 && (before.mode & 0o777) == 0o400 && before.size == NODE_ARCHIVE_BYTES && stable_state(before) == stable_state(path_before)
  output = File.open(destination, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600)
  digest = Digest::SHA256.new
  copied = 0
  while (chunk = source.read(1_048_576))
    digest.update(chunk)
    write_all(output, chunk)
    copied += chunk.bytesize
  end
  output.flush
  output.fsync
  output.close
  after = source.stat
  path_after = File.lstat(source_path)
  source.close
  reject('Provisioned Node archive changed during held copy') unless copied == NODE_ARCHIVE_BYTES && digest.hexdigest == NODE_ARCHIVE_SHA256 && stable_state(before) == stable_state(after) && stable_state(after) == stable_state(path_after)
  File.chmod(0o400, destination)
  private_state = File.lstat(destination)
  reject('Private Node archive copy is unsafe') unless private_state.file? && !private_state.symlink? && private_state.uid == Process.uid && private_state.nlink == 1 && (private_state.mode & 0o777) == 0o400 && private_state.size == NODE_ARCHIVE_BYTES
  stable_state(private_state)
end

def verify_loaded_ruby_features
  builtins = ['complex.so', 'enumerator.so', 'rational.so', 'thread.rb'].freeze
  rows = $LOADED_FEATURES.sort.map do |feature|
    unless feature.start_with?('/')
      reject('System Ruby loaded an unexpected built-in feature') unless builtins.include?(feature)
      next "builtin:#{feature}"
    end
    canonical = safe_system_file(feature, 'System Ruby standard library')
    "#{canonical}:#{sha256_file(canonical)}"
  end
  Digest::SHA256.hexdigest(rows.join("\n"))
end

def held_source_record(repository_root, path)
  relative = path.delete_prefix("#{repository_root}/")
  file = File.open(path, File::RDONLY | File::NOFOLLOW)
  before = file.stat
  path_before = File.lstat(path)
  reject('Bootstrap source manifest contains an unsafe file') unless before.file? && !before.symlink? && before.uid == Process.uid && before.nlink == 1 && (before.mode & 0o022).zero? && stable_state(before) == stable_state(path_before)
  digest = Digest::SHA256.new
  bytes = 0
  while (chunk = file.read(1_048_576))
    digest.update(chunk)
    bytes += chunk.bytesize
    reject('Bootstrap source manifest file exceeds its bound') if bytes > 16 * 1_048_576
  end
  after = file.stat
  path_after = File.lstat(path)
  file.close
  reject('Bootstrap source changed during its held manifest read') unless stable_state(before) == stable_state(after) && stable_state(after) == stable_state(path_after)
  {
    'mode' => before.mode & 0o777,
    'path' => relative,
    'sha256' => digest.hexdigest,
    'size' => bytes
  }
end

def capture_bootstrap_source_manifest(repository_root)
  files = []
  ['scripts', 'tests/packaged'].each do |relative_root|
    root = File.join(repository_root, relative_root)
    Dir.glob(File.join(root, '**', '*'), File::FNM_DOTMATCH).sort.each do |path|
      next if ['.', '..'].include?(File.basename(path))
      state = File.lstat(path)
      reject('Bootstrap source manifest contains a symbolic link') if state.symlink?
      if state.directory?
        reject('Bootstrap source manifest contains a writable directory') unless state.uid == Process.uid && (state.mode & 0o022).zero?
        next
      end
      reject('Bootstrap source manifest contains a special entry') unless state.file?
      next unless ['.js', '.json', '.mjs', '.rb'].include?(File.extname(path))
      files << held_source_record(repository_root, path)
    end
  end
  reject('Bootstrap source manifest count changed') unless files.length.between?(50, 256)
  { 'files' => files, 'schemaVersion' => 1 }
end

def write_private_file(path, bytes, mode)
  File.open(path, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, mode) do |file|
    write_all(file, bytes)
    file.flush
    file.fsync
  end
end

def bootstrap_loader_source(repository_root, manifest_path, manifest_sha256)
  root_literal = JSON.generate(repository_root)
  manifest_literal = JSON.generate(manifest_path)
  digest_literal = JSON.generate(manifest_sha256)
  <<~JAVASCRIPT
    import { createHash } from 'node:crypto';
    import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs';
    import { extname, relative, resolve } from 'node:path';
    import { fileURLToPath } from 'node:url';

    const repositoryRoot = #{root_literal};
    const manifestPath = #{manifest_literal};
    const expectedManifestSha256 = #{digest_literal};
    const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
    const sameState = (left, right) => left.dev === right.dev
      && left.ino === right.ino && left.mode === right.mode && left.uid === right.uid
      && left.gid === right.gid && left.nlink === right.nlink && left.size === right.size
      && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
    const readHeld = (path, maximum) => {
      const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const before = fstatSync(fd, { bigint: true });
        const pathBefore = lstatSync(path, { bigint: true });
        if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
          || before.uid !== BigInt(process.getuid()) || (before.mode & 0o022n) !== 0n
          || before.size > BigInt(maximum) || !sameState(before, pathBefore)) {
          throw new Error('Bootstrap loader rejected an unsafe held source');
        }
        const bytes = Buffer.alloc(Number(before.size));
        let offset = 0;
        while (offset < bytes.length) {
          const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
          if (count < 1) throw new Error('Bootstrap loader source ended early');
          offset += count;
        }
        const after = fstatSync(fd, { bigint: true });
        const pathAfter = lstatSync(path, { bigint: true });
        if (!sameState(before, after) || !sameState(after, pathAfter)) {
          throw new Error('Bootstrap loader source changed during its held read');
        }
        return { bytes, state: after };
      } finally {
        closeSync(fd);
      }
    };
    const manifestHeld = readHeld(manifestPath, 256 * 1024);
    if (sha256(manifestHeld.bytes) !== expectedManifestSha256) {
      throw new Error('Bootstrap loader manifest digest changed');
    }
    const manifest = JSON.parse(manifestHeld.bytes.toString('utf8'));
    if (manifest?.schemaVersion !== 1 || !Array.isArray(manifest.files)) {
      throw new Error('Bootstrap loader manifest schema changed');
    }
    const records = new Map(manifest.files.map((record) => [record.path, record]));
    if (records.size !== manifest.files.length) throw new Error('Bootstrap loader manifest paths are duplicated');

    export async function load(url, context, nextLoad) {
      if (!url.startsWith('file:')) return nextLoad(url, context);
      const path = fileURLToPath(url);
      const pathRelative = relative(repositoryRoot, path).split('\\\\').join('/');
      const protectedSource = pathRelative.startsWith('scripts/')
        || pathRelative.startsWith('tests/packaged/');
      if (!protectedSource) return nextLoad(url, context);
      if (resolve(repositoryRoot, ...pathRelative.split('/')) !== path
        || realpathSync(path) !== path) {
        throw new Error('Bootstrap loader source path escaped its manifest');
      }
      const record = records.get(pathRelative);
      if (!record || !Number.isSafeInteger(record.size) || record.size < 0
        || !Number.isSafeInteger(record.mode) || !/^[0-9a-f]{64}$/u.test(record.sha256)) {
        throw new Error('Bootstrap loader source is absent from its manifest');
      }
      const held = readHeld(path, 16 * 1024 * 1024);
      if (held.bytes.length !== record.size
        || Number(held.state.mode & 0o777n) !== record.mode
        || sha256(held.bytes) !== record.sha256) {
        throw new Error('Bootstrap loader source differs from its held manifest');
      }
      const extension = extname(path);
      const format = extension === '.json' ? 'json' : 'module';
      return { format, shortCircuit: true, source: held.bytes };
    }
  JAVASCRIPT
end

allowed_environment = ['LANG', 'LC_ALL', 'PATH', 'TMPDIR', '__CF_USER_TEXT_ENCODING']
reject('Architecture bootstrap requires a scrubbed environment') unless (ENV.keys - allowed_environment).empty?
reject('Architecture bootstrap received a Ruby injection variable') if ENV.key?('RUBYOPT') || ENV.key?('RUBYLIB')
reject('Architecture bootstrap PATH is not exact') unless ENV.fetch('PATH', nil) == '/usr/bin:/bin'

exact_file_state('/usr/bin/env', 'System env', uid: 0, mode: 0o755, bytes: 102_368, sha256: ENV_SHA256)
ruby_state = exact_file_state('/usr/bin/ruby', 'System Ruby', uid: 0, mode: 0o555, bytes: 135_200, sha256: RUBY_SHA256)
verify_ruby_macho(File.binread('/usr/bin/ruby'))
stdlib_sha256 = verify_loaded_ruby_features

mode = ARGV.shift
target_name = BOOTSTRAP_MODES.fetch(mode) { reject('Architecture bootstrap mode is unsupported') }
reject('Architecture record/build modes accept no additional arguments') if mode != 'package' && !ARGV.empty?
if mode == 'package' && ARGV == ['--authoritative-a28']
  warn('A.28 standalone accessibility proof is unavailable; run `pnpm gate:architecture:record`.')
  exit(2)
end
bootstrap_source = File.realpath(__FILE__)
repository_root = File.realpath(File.join(File.dirname(bootstrap_source), '..'))
target = File.realpath(File.join(repository_root, 'scripts', target_name))
bootstrap_source_state = File.lstat(bootstrap_source)
reject('Architecture bootstrap source is unsafe') unless bootstrap_source_state.file? && !bootstrap_source_state.symlink? && bootstrap_source_state.uid == Process.uid && bootstrap_source_state.nlink == 1 && (bootstrap_source_state.mode & 0o022).zero?

home = File.realpath(Etc.getpwuid(Process.uid).dir)
cache_root = File.join(home, 'Library', 'Caches', 'com.piui.app', 'architecture-toolchain-v1')
[File.dirname(cache_root), cache_root, File.join(cache_root, 'sha256')].each do |path|
  state = File.lstat(path)
  reject('Architecture toolchain cache directory is unsafe') unless state.directory? && !state.symlink? && state.uid == Process.uid && (state.mode & 0o777) == 0o700 && File.realpath(path) == path
end
cache_archive = File.join(cache_root, 'sha256', NODE_ARCHIVE_SHA256)
temporary_parent = File.realpath(Dir.tmpdir)
private_root = nil
root_identity = nil
receipt_reader = nil
receipt_writer = nil
node_lease = nil
child_pid = nil
child_status = nil
signal_handlers = {}
failure = nil
begin
  private_root = Dir.mktmpdir('piui-architecture-bootstrap-', temporary_parent)
  File.chmod(0o700, private_root)
  private_root = File.realpath(private_root)
  root_identity = File.lstat(private_root)
  reject('Architecture bootstrap private root is unsafe') unless root_identity.directory? &&
    !root_identity.symlink? && root_identity.uid == Process.uid &&
    (root_identity.mode & 0o777) == 0o700
  private_archive = File.join(private_root, 'node.tar.gz')
  private_node = File.join(private_root, 'node')
  private_archive_state = copy_authenticated_archive(cache_archive, private_archive)
  extract_pinned_node(private_archive, private_archive_state, private_node)
  node_state = exact_file_state(
    private_node,
    'Private Node',
    uid: Process.uid,
    gid: Process.gid,
    mode: 0o500,
    bytes: NODE_EXECUTABLE_BYTES,
    sha256: NODE_EXECUTABLE_SHA256
  )
  verify_node_macho(File.binread(private_node))

  source_manifest = capture_bootstrap_source_manifest(repository_root)
  source_manifest_bytes = canonical_json(source_manifest) + "\n"
  source_manifest_sha256 = Digest::SHA256.hexdigest(source_manifest_bytes)
  source_manifest_path = File.join(private_root, 'source-manifest.json')
  write_private_file(source_manifest_path, source_manifest_bytes, 0o400)
  loader_path = File.join(private_root, 'held-source-loader.mjs')
  loader_source = bootstrap_loader_source(
    repository_root,
    source_manifest_path,
    source_manifest_sha256
  )
  loader_sha256 = Digest::SHA256.hexdigest(loader_source)
  write_private_file(loader_path, loader_source, 0o400)

  token = File.open('/dev/urandom', 'rb') { |random| random.read(32) }.unpack1('H*')
  pins = {
    'nodeArchiveBytes' => NODE_ARCHIVE_BYTES,
    'nodeArchiveSha256' => NODE_ARCHIVE_SHA256,
    'nodeExecutableBytes' => NODE_EXECUTABLE_BYTES,
    'nodeExecutableSha256' => NODE_EXECUTABLE_SHA256,
    'nodeVersion' => NODE_VERSION,
    'rubySha256' => RUBY_SHA256
  }
  receipt_path = File.join(private_root, 'receipt.json')
  receipt_writer = File.open(
    receipt_path,
    File::RDWR | File::CREAT | File::EXCL | File::NOFOLLOW,
    0o600
  )
  receipt_writer.close_on_exec = true
  receipt_reader = File.open(receipt_path, File::RDONLY | File::NOFOLLOW)
  receipt_reader.close_on_exec = false
  receipt_fd = receipt_reader.fileno
  root_lease_state = File.lstat(private_root)
  child_environment = {
    'HOME' => home,
    'LANG' => 'en_AU.UTF-8',
    'LC_ALL' => 'en_AU.UTF-8',
    'PATH' => '/usr/bin:/bin:/usr/sbin:/sbin',
    'PIUI_ARCHITECTURE_BOOTSTRAP_FD' => receipt_fd.to_s,
    'PIUI_ARCHITECTURE_BOOTSTRAP_TOKEN' => token,
    'TMPDIR' => "#{temporary_parent}/"
  }
  node_lease = create_suspended_authenticated_node(
    private_node,
    node_state,
    private_root,
    root_lease_state,
    receipt_reader,
    ['--no-warnings', '--experimental-loader', loader_path, target, *ARGV],
    child_environment
  )
  child_pid = node_lease.fetch('pid')
  receipt = {
    'bootstrapSourceDev' => bootstrap_source_state.dev.to_s,
    'bootstrapSourceIno' => bootstrap_source_state.ino.to_s,
    'bootstrapSourceSha256' => sha256_file(bootstrap_source),
    'envSha256' => ENV_SHA256,
    'loaderPath' => loader_path,
    'loaderSha256' => loader_sha256,
    'mode' => mode,
    'nodeDev' => node_state.dev.to_s,
    'nodeIno' => node_state.ino.to_s,
    'nodePath' => private_node,
    'nodeSha256' => NODE_EXECUTABLE_SHA256,
    'nodeSize' => NODE_EXECUTABLE_BYTES,
    'pinsSha256' => Digest::SHA256.hexdigest(canonical_json(pins)),
    'privateRoot' => private_root,
    'privateRootDev' => root_identity.dev.to_s,
    'privateRootIno' => root_identity.ino.to_s,
    'repositoryRoot' => repository_root,
    'rootPid' => child_pid,
    'rubyDev' => ruby_state.dev.to_s,
    'rubyIno' => ruby_state.ino.to_s,
    'rubySha256' => RUBY_SHA256,
    'schemaVersion' => 1,
    'stdlibSha256' => stdlib_sha256,
    'sourceManifestEntries' => source_manifest.fetch('files').length,
    'sourceManifestPath' => source_manifest_path,
    'sourceManifestSha256' => source_manifest_sha256,
    'targetPath' => target,
    'token' => token
  }
  receipt_bytes = canonical_json(receipt) + "\n"
  write_all(receipt_writer, receipt_bytes)
  receipt_writer.flush
  receipt_writer.fsync
  File.chmod(0o400, receipt_path)
  receipt_state = receipt_reader.stat
  receipt_path_state = File.lstat(receipt_path)
  reject('Architecture bootstrap receipt identity changed') unless receipt_state.file? &&
    !receipt_path_state.symlink? && receipt_state.nlink == 1 &&
    receipt_state.uid == Process.uid && (receipt_state.mode & 0o777) == 0o400 &&
    receipt_state.size == receipt_bytes.bytesize &&
      stable_state(receipt_state) == stable_state(receipt_path_state)
  receipt_writer.close
  receipt_writer = nil
  signal_handlers = %w[INT TERM HUP].to_h do |signal|
    [signal, Signal.trap(signal) { Process.kill(signal, -child_pid) rescue nil }]
  end
  resume_suspended_node(node_lease)
  node_lease = nil
  loop do
    begin
      _, child_status = Process.wait2(child_pid)
      break
    rescue Errno::EINTR
      next
    end
  end
rescue StandardError => error
  failure = error
ensure
  signal_handlers.each { |signal, handler| Signal.trap(signal, handler) }
  if child_pid && child_status.nil?
    Process.kill('KILL', -child_pid) rescue nil
    Process.wait(child_pid) rescue nil
  end
  if node_lease
    node_lease.fetch('nodeFile').close rescue nil
    node_lease.fetch('rootFile').close rescue nil
  end
  receipt_writer.close rescue nil
  receipt_reader.close rescue nil
  begin
    cleanup_bootstrap_private_root(private_root, root_identity) if root_identity
  rescue StandardError => cleanup_error
    failure = failure ? RuntimeError.new("#{failure.message}; cleanup failed: #{cleanup_error.message}") : cleanup_error
  end
end

raise failure if failure
reject('Authenticated Node child status is unavailable') unless child_status
if child_status.exited?
  exit(child_status.exitstatus)
end
termination_signal = Signal.signame(child_status.termsig)
Signal.trap(termination_signal, 'DEFAULT')
Process.kill(termination_signal, Process.pid)
