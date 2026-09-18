#!/usr/bin/ruby --disable-gems

require 'digest'
require 'fiddle'
require 'base64'
require 'securerandom'

NODE_CDHASH = '59cdea89a982b05f23e756c08115bebc555ff092'.freeze
NODE_DESIGNATED_REQUIREMENT = 'identifier node and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = HX7739G8FX'.freeze
NODE_IDENTIFIER = 'node'.freeze
NODE_TEAM_IDENTIFIER = 'HX7739G8FX'.freeze
SHA256 = /\A[0-9a-f]{64}\z/.freeze
DECIMAL = /\A(?:0|[1-9][0-9]*)\z/.freeze
POSIX_SPAWN_START_SUSPENDED = 0x0080
POSIX_SPAWN_CLOEXEC_DEFAULT = 0x4000
SANDBOX_PROFILE_MAX_BYTES = 512 * 1_024
AUTHENTICATED_HANDSHAKE_MARKER = 'PIUI_AUTHENTICATED_NODE_READY_V1'.b.freeze
AUTHENTICATED_HANDSHAKE_ENVIRONMENT = 'PIUI_AUTHENTICATED_NODE_HANDSHAKE_V1'.freeze
AUTHENTICATED_HANDSHAKE_MAX_NODE_STOPS = 3
A28_ALLOWED_SANDBOX_SERVICES = [
  'com.apple.CARenderServer',
  'com.apple.CoreDisplay.Notification',
  'com.apple.CoreDisplay.master',
  'com.apple.WebKit.GPU',
  'com.apple.WebKit.Networking',
  'com.apple.WebKit.WebContent',
  'com.apple.WebKit.WebContent.EnhancedSecurity',
  'com.apple.appsleep',
  'com.apple.coreservices.appleevents',
  'com.apple.dock.fullscreen',
  'com.apple.dock.server',
  'com.apple.fonts',
  'com.apple.lsd.mapdb',
  'com.apple.pasteboard.1',
  'com.apple.pbs.fetch_services',
  'com.apple.window_proxies',
  'com.apple.windowserver.active'
].freeze

def reject
  raise RuntimeError, 'Authenticated Node launcher rejected'
end

def stable_state(state)
  [state.dev, state.ino, state.mode, state.uid, state.gid, state.nlink, state.size,
   state.mtime.to_i, state.mtime.nsec, state.ctime.to_i, state.ctime.nsec]
end

def native_function(name, arguments, result = Fiddle::TYPE_INT)
  Fiddle::Function.new(Fiddle::Handle::DEFAULT[name], arguments, result)
rescue Fiddle::DLError
  reject
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
  reject if value.zero?
  value
rescue Fiddle::DLError
  reject
end

def c_vector(values)
  strings = values.map do |value|
    reject unless value.is_a?(String) && !value.include?("\0")
    Fiddle::Pointer[value + "\0"]
  end
  vector = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP * (strings.length + 1))
  vector[0, Fiddle::SIZEOF_VOIDP * (strings.length + 1)] =
    (strings.map(&:to_i) + [0]).pack('J*')
  [strings, vector]
end

def cf_string(value)
  result = native_function(
    'CFStringCreateWithCString',
    [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT],
    Fiddle::TYPE_VOIDP
  ).call(0, Fiddle::Pointer[value + "\0"], 0x08000100)
  reject if null_pointer?(result)
  result
end

def cf_string_value(value)
  buffer = Fiddle::Pointer.malloc(4_096)
  copied = native_function(
    'CFStringGetCString',
    [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_INT]
  ).call(value, buffer, 4_096, 0x08000100)
  reject if copied.zero?
  buffer.to_s
end

def assert_live_node_vnode(pid, expected_path, expected_dev, expected_ino)
  region_info_bytes = 1_272
  region_address_offset = 80
  region_size_offset = 88
  vnode_device_offset = 96
  vnode_inode_offset = 104
  vnode_path_offset = 248
  vnode_path_bytes = 1_024
  execute_protection = 0x04
  region = Fiddle::Pointer.malloc(region_info_bytes)
  query = native_function(
    'proc_pidinfo',
    [Fiddle::TYPE_INT, Fiddle::TYPE_INT, Fiddle::TYPE_LONG_LONG,
     Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT]
  )
  address = 0
  16_384.times do
    bytes = query.call(pid, 8, address, region, region_info_bytes)
    break if bytes.zero?
    reject unless bytes == region_info_bytes
    protection = region[0, 4].unpack1('L<')
    mapped_address = region[region_address_offset, 8].unpack1('Q<')
    mapped_size = region[region_size_offset, 8].unpack1('Q<')
    reject unless mapped_size.positive? && mapped_address >= address
    mapped_path = region[vnode_path_offset, vnode_path_bytes].split("\0", 2).fetch(0)
    if (protection & execute_protection).positive? && mapped_path == expected_path
      mapped_dev = region[vnode_device_offset, 4].unpack1('L<')
      mapped_ino = region[vnode_inode_offset, 8].unpack1('Q<')
      reject unless mapped_dev == expected_dev && mapped_ino == expected_ino
      return
    end
    next_address = mapped_address + mapped_size
    reject unless next_address > address && next_address <= ((1 << 64) - 1)
    address = next_address
  end
  reject
end

def assert_live_node_code(pid, expected_path, expected_dev, expected_ino)
  reject unless pid.is_a?(Integer) && pid >= 2
  process_path = Fiddle::Pointer.malloc(4_096)
  path_bytes = native_function(
    'proc_pidpath',
    [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT]
  ).call(pid, process_path, 4_096)
  reject unless path_bytes.positive? && process_path[0, path_bytes] == expected_path
  assert_live_node_vnode(pid, expected_path, expected_dev, expected_ino)

  releases = []
  begin
    pid_bytes = Fiddle::Pointer.malloc(4)
    pid_bytes[0, 4] = [pid].pack('l')
    pid_number = native_function(
      'CFNumberCreate',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP],
      Fiddle::TYPE_VOIDP
    ).call(0, 3, pid_bytes)
    reject if null_pointer?(pid_number)
    releases << pid_number
    attributes = native_function(
      'CFDictionaryCreateMutable',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
      Fiddle::TYPE_VOIDP
    ).call(0, 1, 0, 0)
    reject if null_pointer?(attributes)
    releases << attributes
    native_function(
      'CFDictionarySetValue',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
      Fiddle::TYPE_VOID
    ).call(attributes, system_cf_constant('kSecGuestAttributePid'), pid_number)
    code_slot = pointer_slot
    reject unless native_function(
      'SecCodeCopyGuestWithAttributes',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP]
    ).call(0, attributes, 0, code_slot).zero?
    code = pointer_value(code_slot)
    reject if null_pointer?(code)
    releases << code
    requirement_text = cf_string(NODE_DESIGNATED_REQUIREMENT)
    releases << requirement_text
    requirement_slot = pointer_slot
    reject unless native_function(
      'SecRequirementCreateWithString',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP]
    ).call(requirement_text, 0, requirement_slot).zero?
    requirement = pointer_value(requirement_slot)
    reject if null_pointer?(requirement)
    releases << requirement
    reject unless native_function(
      'SecCodeCheckValidity',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP]
    ).call(code, 0, requirement).zero?
    information_slot = pointer_slot
    reject unless native_function(
      'SecCodeCopySigningInformation',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP]
    ).call(code, 2, information_slot).zero?
    information = pointer_value(information_slot)
    reject if null_pointer?(information)
    releases << information
    dictionary_value = native_function(
      'CFDictionaryGetValue',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
      Fiddle::TYPE_VOIDP
    )
    identifier = dictionary_value.call(information, system_cf_constant('kSecCodeInfoIdentifier'))
    team = dictionary_value.call(information, system_cf_constant('kSecCodeInfoTeamIdentifier'))
    unique = dictionary_value.call(information, system_cf_constant('kSecCodeInfoUnique'))
    reject if [identifier, team, unique].any? { |value| null_pointer?(value) }
    reject unless cf_string_value(identifier) == NODE_IDENTIFIER
    reject unless cf_string_value(team) == NODE_TEAM_IDENTIFIER
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
    reject unless unique_length == 20 &&
      Fiddle::Pointer.new(unique_bytes.to_i)[0, unique_length].unpack1('H*') == NODE_CDHASH
  ensure
    release = native_function('CFRelease', [Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOID)
    releases.reverse_each { |value| release.call(value) unless null_pointer?(value) }
  end
end

def assert_live_apple_tool_code(pid, expected_path, designated_requirement)
  reject unless pid.is_a?(Integer) && pid >= 2
  process_path = Fiddle::Pointer.malloc(4_096)
  path_bytes = native_function(
    'proc_pidpath',
    [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT]
  ).call(pid, process_path, 4_096)
  reject unless path_bytes.positive? && process_path[0, path_bytes] == expected_path

  releases = []
  begin
    pid_bytes = Fiddle::Pointer.malloc(4)
    pid_bytes[0, 4] = [pid].pack('l')
    pid_number = native_function(
      'CFNumberCreate',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP],
      Fiddle::TYPE_VOIDP
    ).call(0, 3, pid_bytes)
    reject if null_pointer?(pid_number)
    releases << pid_number
    attributes = native_function(
      'CFDictionaryCreateMutable',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
      Fiddle::TYPE_VOIDP
    ).call(0, 1, 0, 0)
    reject if null_pointer?(attributes)
    releases << attributes
    native_function(
      'CFDictionarySetValue',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
      Fiddle::TYPE_VOID
    ).call(attributes, system_cf_constant('kSecGuestAttributePid'), pid_number)
    code_slot = pointer_slot
    reject unless native_function(
      'SecCodeCopyGuestWithAttributes',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP]
    ).call(0, attributes, 0, code_slot).zero?
    code = pointer_value(code_slot)
    reject if null_pointer?(code)
    releases << code
    requirement_text = cf_string(designated_requirement)
    releases << requirement_text
    requirement_slot = pointer_slot
    reject unless native_function(
      'SecRequirementCreateWithString',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP]
    ).call(requirement_text, 0, requirement_slot).zero?
    requirement = pointer_value(requirement_slot)
    reject if null_pointer?(requirement)
    releases << requirement
    reject unless native_function(
      'SecCodeCheckValidity',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP]
    ).call(code, 0, requirement).zero?
  ensure
    release = native_function('CFRelease', [Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOID)
    releases.reverse_each { |value| release.call(value) unless null_pointer?(value) }
  end
end

def parse_inputs(arguments)
  reject unless arguments.length >= 12
  source_path, expected_dev, expected_ino, expected_size, expected_sha256,
    inherited_text, sandbox_marker, sandbox_sha256, sandbox_base64,
    policy_marker, sandbox_policy, separator, *node_arguments = arguments
  reject unless sandbox_marker == '--sandbox-profile' &&
    policy_marker == '--sandbox-policy' && separator == '--node-args' &&
    source_path.start_with?('/') &&
    File.expand_path(source_path) == source_path && expected_dev.match?(DECIMAL) &&
    expected_ino.match?(DECIMAL) && expected_size.match?(DECIMAL) &&
    expected_sha256.match?(SHA256)
  inherited = inherited_text.empty? ? [] : inherited_text.split(',').map do |value|
    reject unless value.match?(DECIMAL)
    descriptor = Integer(value, 10)
    reject unless descriptor.between?(3, 255) && descriptor.to_s == value
    descriptor
  end
  reject unless inherited.uniq.length == inherited.length && inherited.length <= 8
  valid_script_entry = lambda do |value|
    next false if value.empty? || value.start_with?('-') || value.end_with?('/')
    if value.start_with?('/')
      File.expand_path(value) == value
    else
      components = value.split('/', -1)
      value.start_with?('scripts/') &&
        components.none? { |component| component.empty? || ['.', '..'].include?(component) }
    end
  end
  valid_node_arguments = node_arguments == ['--version'] ||
    (node_arguments.length == 2 && node_arguments.fetch(0) == '-e' && !node_arguments.fetch(1).empty?) ||
    (!node_arguments.empty? && valid_script_entry.call(node_arguments.fetch(0)))
  reject unless node_arguments.length <= 8_192 &&
    node_arguments.all? { |value| value.valid_encoding? && !value.include?("\0") && value.bytesize <= 256 * 1_024 } &&
    node_arguments.sum(&:bytesize) <= 2 * 1_048_576 &&
    valid_node_arguments
  sandbox_profile = nil
  if sandbox_sha256 == '-' || sandbox_base64 == '-'
    reject unless sandbox_sha256 == '-' && sandbox_base64 == '-' && sandbox_policy == '-'
  else
    reject unless sandbox_sha256.match?(SHA256) &&
      sandbox_base64.bytesize.between?(344, (SANDBOX_PROFILE_MAX_BYTES * 4 / 3) + 8)
    begin
      sandbox_profile = Base64.strict_decode64(sandbox_base64)
    rescue ArgumentError
      reject
    end
    reject unless sandbox_profile.bytesize.between?(256, SANDBOX_PROFILE_MAX_BYTES) &&
      sandbox_profile.valid_encoding? && !sandbox_profile.include?("\0") &&
      !sandbox_profile.include?("\r") &&
      Digest::SHA256.hexdigest(sandbox_profile) == sandbox_sha256 &&
      Base64.strict_encode64(sandbox_profile) == sandbox_base64 &&
      sandbox_profile.scan('(version 1)').length == 1 &&
      sandbox_profile.scan('(deny default)').length == 1 &&
      sandbox_profile.scan('(deny network*)').length == 1 &&
      sandbox_profile.scan('(deny appleevent-send)').length == 1
    if ['deny-network', 'guarded-production'].include?(sandbox_policy)
      reject unless sandbox_profile.include?("(deny mach-lookup\n    (global-name \"com.apple.securityd\")\n    (global-name \"com.apple.SecurityServer\"))") &&
        !sandbox_profile.match?(/\(allow\s+(?:network[^\s)]*|appleevent-send|mach-lookup|default)\b/)
    elsif sandbox_policy.match?(/\Aa28-loopback:(?:4915[2-9]|491[6-9][0-9]|49[2-9][0-9]{2}|5[0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])\z/)
      port = sandbox_policy.split(':', 2).fetch(1)
      expected_network = [
        "(allow network-inbound (local tcp4 \"localhost:#{port}\"))",
        "(allow network-outbound (remote tcp4 \"localhost:#{port}\"))"
      ]
      network_allows = sandbox_profile.lines.map(&:strip).select do |line|
        line.start_with?('(allow network')
      end
      services = sandbox_profile.scan(/\((?:global-name|xpc-service-name) \"([^\"]+)\"\)/).flatten
      reject unless network_allows.sort == expected_network.sort &&
        sandbox_profile.scan('(allow mach-lookup').length == 2 &&
        services.all? { |service| A28_ALLOWED_SANDBOX_SERVICES.include?(service) } &&
        sandbox_profile.scan('(local-name "com.apple.CFPasteboardClient")').length == 1 &&
        !sandbox_profile.include?('com.apple.securityd') &&
        !sandbox_profile.include?('com.apple.SecurityServer') &&
        !sandbox_profile.match?(/\(allow\s+(?:appleevent-send|default)\b/)
    elsif sandbox_policy.match?(/\Aautomation-signing-broker:[0-9a-f]{64}\z/)
      nonce = sandbox_policy.split(':', 2).fetch(1)
      services = sandbox_profile.scan(/\((?:global-name|xpc-service-name) "([^"]+)"\)/).flatten
      process_filters = sandbox_profile.scan(/\(with-filter \(process-path "([^"]+)"\)/).flatten
      process_exec = sandbox_profile.match(
        /\(allow process-exec\s+((?:\(literal "[^"]+"\)\s*)+)\)/m
      )
      process_exec_paths = process_exec ? process_exec[1].scan(/\(literal "([^"]+)"\)/).flatten : []
      keychain_paths = sandbox_profile.scan(
        /"(\/Users\/[^\/\0\r\n]+\/Library\/Keychains\/login\.keychain-db)"/
      ).flatten.uniq
      reject unless sandbox_profile.include?("request-#{nonce}.json") &&
        sandbox_profile.include?("consumed-#{nonce}.json") &&
        sandbox_profile.include?("response-#{nonce}.json") &&
        sandbox_profile.scan('(allow mach-lookup').length == 1 &&
        process_filters.empty? &&
        services.count('com.apple.securityd').zero? &&
        services.count('com.apple.SecurityServer') == 1 &&
        services.count('com.apple.trustd.agent') == 1 &&
        (services - [
          'com.apple.securityd',
          'com.apple.SecurityServer',
          'com.apple.trustd.agent'
        ]).empty? &&
        process_exec_paths.sort == [source_path, '/usr/bin/codesign', '/usr/bin/security'].sort &&
        keychain_paths.length == 1 &&
        sandbox_profile.scan('(literal "/usr/bin/codesign")').length == 2 &&
        sandbox_profile.scan('(literal "/usr/bin/security")').length == 2 &&
        !sandbox_profile.include?('(literal "/usr/bin/sandbox-exec")') &&
        sandbox_profile.scan('(allow system-fsctl)').length == 1 &&
        !sandbox_profile.match?(/\(allow\s+(?:network[^\s)]*|appleevent-send|default)\b/)
    else
      reject
    end
  end
  {
    inherited: inherited,
    node_arguments: node_arguments,
    sandbox_policy: sandbox_policy,
    sandbox_profile: sandbox_profile,
    source_dev: Integer(expected_dev, 10),
    source_ino: Integer(expected_ino, 10),
    source_path: source_path,
    source_sha256: expected_sha256,
    source_size: Integer(expected_size, 10)
  }
end

def assert_file_lease(file, path, expected)
  held = file.stat
  pathname = File.lstat(path)
  reject unless held.file? && !pathname.symlink? && held.nlink == 1 &&
    held.uid == Process.uid && (held.mode & 0o777) == 0o500 &&
    stable_state(held) == stable_state(pathname) && stable_state(held) == stable_state(expected)
end

def assert_directory_lease(file, path, expected, exact_mode = nil)
  held = file.stat
  pathname = File.lstat(path)
  reject unless held.directory? && !pathname.symlink? && held.uid == Process.uid &&
    (exact_mode ? (held.mode & 0o777) == exact_mode : (held.mode & 0o022).zero?) &&
    stable_state(held) == stable_state(pathname) &&
    stable_state(held) == stable_state(expected) && File.realpath(path) == path
end

def descriptor_sha256(file)
  digest = Digest::SHA256.new
  offset = 0
  size = file.stat.size
  while offset < size
    file.seek(offset, IO::SEEK_SET)
    chunk = file.read([1_048_576, size - offset].min)
    reject unless chunk && !chunk.empty?
    digest.update(chunk)
    offset += chunk.bytesize
  end
  digest.hexdigest
end

def seatbelt_literal(value)
  reject unless value.is_a?(String) && value.start_with?('/') &&
    !value.match?(/[\0\r\n]/)
  value.gsub('\\', '\\\\').gsub('"', '\\"')
end

def sandbox_profile_for(profile, node_path)
  escaped_node = seatbelt_literal(node_path)
  reject unless profile.include?("(literal \"#{escaped_node}\")")
  profile
end

def sandbox_handshake_preload(handshake_descriptor, handshake_nonce)
  reject unless handshake_descriptor.is_a?(Integer) &&
    handshake_descriptor.between?(3, 1_048_575) &&
    handshake_nonce.match?(/\A[0-9a-f]{64}\z/)
  source = [
    "import{closeSync,writeSync}from'node:fs';",
    "import{isMainThread}from'node:worker_threads';",
    "const self='--import='+import.meta.url;",
    'if(process.execArgv[0]!==self||process.execArgv.filter((value)=>value===self).length!==1)process.exit(125);',
    'process.execArgv.shift();',
    "const handshake=process.env[#{AUTHENTICATED_HANDSHAKE_ENVIRONMENT.inspect}]===#{handshake_nonce.inspect};",
    'if(handshake){',
    "delete process.env[#{AUTHENTICATED_HANDSHAKE_ENVIRONMENT.inspect}];",
    'if(!isMainThread)process.exit(125);',
    "const marker=#{AUTHENTICATED_HANDSHAKE_MARKER.inspect};",
    "if(writeSync(#{handshake_descriptor},marker)!==#{AUTHENTICATED_HANDSHAKE_MARKER.bytesize})process.exit(125);",
    "closeSync(#{handshake_descriptor});",
    "process.kill(process.pid,'SIGSTOP');",
    '}'
  ].join
  "--import=data:text/javascript;base64,#{Base64.strict_encode64(source)}"
end

def authenticated_handshake_state(reader)
  value = reader.read_nonblock(
    AUTHENTICATED_HANDSHAKE_MARKER.bytesize + 1,
    exception: false
  )
  return :pending if value == :wait_readable
  reject unless value == AUTHENTICATED_HANDSHAKE_MARKER
  reject unless reader.read_nonblock(1, exception: false).nil?
  :complete
end

def wait_for_suspended_child(pid, deadline)
  loop do
    remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
    reject unless remaining.positive?
    waited = Process.waitpid2(pid, Process::WNOHANG | Process::WUNTRACED)
    if waited
      status = waited.fetch(1)
      reject unless waited.fetch(0) == pid && status.stopped?
      return status
    end
    sleep([remaining, 0.005].min)
  end
end

def wait_for_child_completion(pid)
  waited = Process.waitpid2(pid, Process::WUNTRACED)
  status = waited.fetch(1)
  reject unless waited.fetch(0) == pid && !status.stopped? &&
    (status.exited? || status.signaled?)
  status
end

def assert_live_sandbox_denials(pid, policy)
  check = native_function(
    'sandbox_check',
    [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP]
  )
  denied = [
    ['network-outbound', 0, nil],
    ['appleevent-send', 0, nil],
    ['mach-lookup', 0, nil]
  ]
  denied.each do |operation, filter, value|
    operation_pointer = Fiddle::Pointer[operation + "\0"]
    value_pointer = value ? Fiddle::Pointer[value + "\0"] : 0
    result = check.call(pid, operation_pointer, filter, value_pointer)
    reject unless result.positive?
  end
end

def create_suspended_node(path, node_arguments, environment, inherited)
  attributes = pointer_slot
  actions = pointer_slot
  attributes_initialised = false
  actions_initialised = false
  child_pid = nil
  begin
    reject unless native_function('posix_spawnattr_init', [Fiddle::TYPE_VOIDP]).call(attributes).zero?
    attributes_initialised = true
    reject unless native_function(
      'posix_spawnattr_setflags',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SHORT]
    ).call(
      attributes,
      POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_CLOEXEC_DEFAULT
    ).zero?
    reject unless native_function(
      'posix_spawn_file_actions_init',
      [Fiddle::TYPE_VOIDP]
    ).call(actions).zero?
    actions_initialised = true
    inherit_descriptor = native_function(
      'posix_spawn_file_actions_addinherit_np',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT]
    )
    [0, 1, 2, *inherited].uniq.each do |descriptor|
      reject unless inherit_descriptor.call(actions, descriptor).zero?
    end
    argument_strings, argument_vector = c_vector([path, *node_arguments])
    environment_strings, environment_vector = c_vector(
      environment.keys.sort.map { |key| "#{key}=#{environment.fetch(key)}" }
    )
    pid_slot = Fiddle::Pointer.malloc(4)
    pid_slot[0, 4] = [0].pack('l')
    status = native_function(
      'posix_spawn',
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP,
       Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP]
    ).call(pid_slot, argument_strings.fetch(0), actions, attributes,
           argument_vector, environment_vector)
    reject unless status.zero?
    child_pid = pid_slot[0, 4].unpack1('l')
    reject unless child_pid >= 2
    child_pid
  rescue StandardError
    if child_pid
      Process.kill('KILL', child_pid) rescue nil
      Process.wait(child_pid) rescue nil
    end
    raise
  ensure
    native_function('posix_spawn_file_actions_destroy', [Fiddle::TYPE_VOIDP]).call(actions) if actions_initialised
    native_function('posix_spawnattr_destroy', [Fiddle::TYPE_VOIDP]).call(attributes) if attributes_initialised
  end
end

def create_sandboxed_suspended_node(
  path,
  node_arguments,
  environment,
  inherited,
  profile,
  handshake_descriptor,
  handshake_nonce
)
  reject if environment.key?(AUTHENTICATED_HANDSHAKE_ENVIRONMENT)
  create_suspended_node(
    '/usr/bin/sandbox-exec',
    [
      '-p',
      sandbox_profile_for(profile, path),
      '--',
      path,
      sandbox_handshake_preload(handshake_descriptor, handshake_nonce),
      *node_arguments
    ],
    environment.merge(AUTHENTICATED_HANDSHAKE_ENVIRONMENT => handshake_nonce),
    [*inherited, handshake_descriptor]
  )
end

input = parse_inputs(ARGV)
ENV.delete('RUBYOPT')
ENV.delete('RUBYLIB')
reject if ENV.keys.any? do |key|
  key.match?(/\A(?:RUBY|GEM|BUNDLE|DYLD_|LD_|NODE_(?!ENV\z)|OPENSSL_CONF\z|SSL_CERT_(?:FILE|DIR)\z|UV_THREADPOOL_SIZE\z)/)
end
reject if ENV.key?(AUTHENTICATED_HANDSHAKE_ENVIRONMENT)
source_parent_path = File.dirname(input.fetch(:source_path))
source_parent = nil
source = nil
child_pid = nil
child_status = nil
handshake_reader = nil
handshake_writer = nil
handshake_nonce = nil
failure = nil
begin
  source_parent = File.open(source_parent_path, File::RDONLY | File::NOFOLLOW)
  source_parent_state = source_parent.stat
  source = File.open(input.fetch(:source_path), File::RDONLY | File::NOFOLLOW)
  source_state = source.stat
  source_path_state = File.lstat(input.fetch(:source_path))
  reject unless source_state.file? && !source_path_state.symlink? && source_state.nlink == 1 &&
    source_state.uid == Process.uid && (source_state.mode & 0o777) == 0o500 &&
    source_state.dev == input.fetch(:source_dev) && source_state.ino == input.fetch(:source_ino) &&
    source_state.size == input.fetch(:source_size) &&
    stable_state(source_state) == stable_state(source_path_state) &&
    descriptor_sha256(source) == input.fetch(:source_sha256)
  leases = lambda do
    assert_file_lease(source, input.fetch(:source_path), source_state)
    reject unless descriptor_sha256(source) == input.fetch(:source_sha256)
    assert_file_lease(source, input.fetch(:source_path), source_state)
    assert_directory_lease(source_parent, source_parent_path, source_parent_state)
  end
  leases.call
  if input.fetch(:sandbox_profile)
    handshake_reader, handshake_writer = IO.pipe
    handshake_reader.binmode
    handshake_writer.binmode
    handshake_nonce = SecureRandom.hex(32)
    child_pid = create_sandboxed_suspended_node(
      input.fetch(:source_path),
      input.fetch(:node_arguments),
      ENV.to_h,
      input.fetch(:inherited),
      input.fetch(:sandbox_profile),
      handshake_writer.fileno,
      handshake_nonce
    )
    handshake_writer.close
    handshake_writer = nil
  else
    child_pid = create_suspended_node(
      input.fetch(:source_path),
      input.fetch(:node_arguments),
      ENV.to_h,
      input.fetch(:inherited)
    )
  end
  handshake_deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10.0
  initial_status = wait_for_suspended_child(child_pid, handshake_deadline)
  reject unless initial_status.stopsig.zero?
  leases.call
  if input.fetch(:sandbox_profile)
    assert_live_apple_tool_code(
      child_pid,
      '/usr/bin/sandbox-exec',
      'identifier "com.apple.sandbox-exec" and anchor apple'
    )
    leases.call
    Process.kill('CONT', child_pid)
    authenticated_stops = 0
    loop do
      authenticated_status = wait_for_suspended_child(child_pid, handshake_deadline)
      authenticated_stops += 1
      leases.call
      assert_live_node_code(
        child_pid,
        input.fetch(:source_path),
        input.fetch(:source_dev),
        input.fetch(:source_ino)
      )
      assert_live_sandbox_denials(child_pid, input.fetch(:sandbox_policy))
      handshake_state = authenticated_handshake_state(handshake_reader)
      if handshake_state == :complete
        reject unless authenticated_status.stopsig == Signal.list.fetch('STOP')
        break
      end
      reject unless authenticated_status.stopsig.zero?
      reject unless authenticated_stops < AUTHENTICATED_HANDSHAKE_MAX_NODE_STOPS
      leases.call
      Process.kill('CONT', child_pid)
    end
    handshake_reader.close
    handshake_reader = nil
    leases.call
    Process.kill('CONT', child_pid)
    child_status = wait_for_child_completion(child_pid)
  else
    reject unless initial_status.stopsig.zero?
    assert_live_node_code(
      child_pid,
      input.fetch(:source_path),
      input.fetch(:source_dev),
      input.fetch(:source_ino)
    )
    leases.call
    Process.kill('CONT', child_pid)
    child_status = wait_for_child_completion(child_pid)
  end
  leases.call
rescue StandardError => error
  failure = error
ensure
  if child_pid && child_status.nil?
    Process.kill('KILL', child_pid) rescue nil
    Process.wait(child_pid) rescue nil
  end
  handshake_writer.close rescue nil
  handshake_reader.close rescue nil
  source.close rescue nil
  source_parent.close rescue nil
end

raise failure if failure
reject unless child_status
if child_status.exited?
  exit(child_status.exitstatus)
end
signal = Signal.signame(child_status.termsig)
Signal.trap(signal, 'DEFAULT')
Process.kill(signal, Process.pid)
