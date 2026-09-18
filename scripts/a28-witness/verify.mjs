#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import {
  lstat,
  open,
  readdir,
  realpath,
} from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import {
  A28_MAX_ATTESTATION_BYTES,
  A28_MAX_CHALLENGE_BYTES,
  A28_MAX_ENROLMENT_BYTES,
  A28_MAX_POLICY_BYTES,
  A28_POLICY_PIN_PATH,
  assertA28Challenge,
  assertA28Enrolment,
  assertA28EnrolmentAuthorityConfig,
  assertA28EnrolmentAuthorityReceipt,
  assertA28PolicyPin,
  assertA28RootLaunchConfig,
  assertA28WitnessAppInspection,
  canonicalA28Json,
  canonicalA28Line,
  parseCanonicalA28Line,
  sha256A28,
  verifyA28WitnessAttestation,
} from './contract.mjs';

const MAX_BUNDLE_ENTRIES = 2_048;
const SYSTEM_TOOLS = Object.freeze({
  codesign: '/usr/bin/codesign',
  otool: '/Library/Developer/CommandLineTools/usr/bin/otool-classic',
  plutil: '/usr/bin/plutil',
  ruby: '/usr/bin/ruby',
  security: '/usr/bin/security',
  swVers: '/usr/bin/sw_vers',
});
const SYSTEM_TOOL_SHA256 = Object.freeze({
  otool: '1f542421b643d10452395bfb80c0b03827724822f56c4d3d8c0c69683861824b',
});
const NO_EXTENDED_ACL_RUBY = [
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
  'path = ARGV.fetch(0)',
  'Fiddle.last_error = 0',
  'acl = get_acl.call(path, 0x100)',
  'if acl.to_i == 0',
  '  exit 11 unless Fiddle.last_error == 2',
  'else',
  '  free_acl.call(acl)',
  '  exit 12',
  'end',
].join(';');

function reject(message = 'A.28 authenticated witness system verification rejected') {
  throw new Error(message);
}

function exactKeys(value, expected) {
  if (!value
    || typeof value !== 'object'
    || Array.isArray(value)
    || !isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort())) reject();
}

function assertAbsolutePath(path) {
  if (typeof path !== 'string'
    || !path.startsWith('/')
    || resolve(path) !== path
    || /[\0\r\n]/u.test(path)) reject();
}

function sameFile(before, after) {
  return before.dev === after.dev
    && before.ino === after.ino
    && before.uid === after.uid
    && before.gid === after.gid
    && before.nlink === after.nlink
    && before.size === after.size
    && before.mode === after.mode
    && before.mtimeMs === after.mtimeMs
    && before.ctimeMs === after.ctimeMs;
}

function assertPathHasNoExtendedAcl(path) {
  const result = runSystemTool(SYSTEM_TOOLS.ruby, [
    '--disable=gems,rubyopt,did_you_mean',
    '-e',
    NO_EXTENDED_ACL_RUBY,
    '--',
    path,
  ], { maxBuffer: 64 * 1024 });
  if (result.stdout.length !== 0 || result.stderr.length !== 0) reject();
}

async function assertPathChain(path, {
  leafMode,
  leafUid,
  requireDirectory = false,
}) {
  assertAbsolutePath(path);
  const canonical = await realpath(path);
  if (canonical !== path) reject();
  const chain = [];
  let current = path;
  while (true) {
    chain.push(current);
    if (current === '/') break;
    current = dirname(current);
  }
  chain.reverse();
  const observations = [];
  for (const candidate of chain) {
    const leaf = candidate === path;
    const item = await lstat(candidate);
    if (item.isSymbolicLink()
      || (item.mode & 0o022) !== 0
      || (leaf && item.uid !== leafUid)
      || (!leaf && leafUid === 0 && item.uid !== 0)
      || (!leaf
        && leafUid === 0
        && ![0o555, 0o755].includes(item.mode & 0o777))
      || (leaf && (item.mode & 0o777) !== leafMode)
      || (leaf && requireDirectory && !item.isDirectory())
      || (leaf && !requireDirectory && (!item.isFile() || item.nlink !== 1))
      || (!leaf && !item.isDirectory())) reject();
    assertPathHasNoExtendedAcl(candidate);
    const afterAcl = await lstat(candidate);
    if (!sameFile(item, afterAcl)) reject();
    observations.push(Object.freeze({ path: candidate, state: item }));
  }
  for (const observation of observations) {
    if (!sameFile(observation.state, await lstat(observation.path))) reject();
  }
  return Object.freeze(observations);
}

export async function readHeldCanonicalA28File(path, {
  maximumBytes = A28_MAX_ATTESTATION_BYTES,
  mode,
  uid,
}) {
  if (!Number.isSafeInteger(maximumBytes)
    || maximumBytes < 3
    || maximumBytes > A28_MAX_ATTESTATION_BYTES) reject();
  await assertPathChain(path, { leafMode: mode, leafUid: uid });
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    if (!before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1
      || before.uid !== uid
      || (before.mode & 0o777) !== mode
      || before.size < 3
      || before.size > maximumBytes) reject();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const pathname = await lstat(path);
    if (!sameFile(before, after)
      || !sameFile(before, pathname)
      || bytes.length !== before.size) reject();
    const value = parseCanonicalA28Line(bytes);
    return Object.freeze({
      bytes,
      identity: Object.freeze({
        dev: before.dev,
        gid: before.gid,
        ino: before.ino,
        mode: before.mode & 0o777,
        path,
        sha256: sha256A28(bytes),
        size: before.size,
        uid: before.uid,
      }),
      value,
    });
  } finally {
    await handle?.close();
  }
}

async function assertRootOwnedExecutable(
  path,
  expectedSha256,
  mode = 0o500,
  maximumBytes = 16 * 1024 * 1024,
) {
  await assertPathChain(path, { leafMode: mode, leafUid: 0 });
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    if (!before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1
      || before.uid !== 0
      || (before.mode & 0o777) !== mode
      || before.size < 8_192
      || before.size > maximumBytes) reject();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (!sameFile(before, after)
      || bytes.length !== before.size
      || sha256A28(bytes) !== expectedSha256) reject();
  } finally {
    await handle?.close();
  }
}

async function assertRootOwnedPinnedFile(path, expectedSha256, mode, maximumBytes) {
  await assertPathChain(path, { leafMode: mode, leafUid: 0 });
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (!before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1
      || before.uid !== 0
      || (before.mode & 0o777) !== mode
      || before.size < 1
      || before.size > maximumBytes
      || !sameFile(before, after)
      || bytes.length !== before.size
      || sha256A28(bytes) !== expectedSha256) reject();
  } finally {
    await handle?.close();
  }
}

async function assertPinnedExecutableIdentity(expected) {
  await assertPathChain(expected.path, {
    leafMode: 0o555,
    leafUid: 0,
  });
  let handle;
  try {
    handle = await open(expected.path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    const pathnameBefore = await lstat(expected.path);
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const pathnameAfter = await lstat(expected.path);
    if (!before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1
      || before.uid !== 0
      || (before.mode & 0o777) !== 0o555
      || !sameFile(before, pathnameBefore)
      || !sameFile(before, after)
      || !sameFile(before, pathnameAfter)
      || before.dev !== expected.dev
      || before.ino !== expected.ino
      || before.size !== expected.size
      || bytes.length !== expected.size
      || sha256A28(bytes) !== expected.sha256) reject();
  } finally {
    await handle?.close();
  }
}

async function assertInstalledRootVerifier(policy) {
  if (typeof process.getuid !== 'function'
    || typeof process.geteuid !== 'function'
    || process.getuid() !== 0
    || process.geteuid() !== 0
    || process.execPath !== policy.rootVerifierNodePath
    || process.execArgv.length !== 0
    || resolve(process.argv[1]) !== policy.rootVerifierEntrypointPath
    || fileURLToPath(import.meta.url) !== policy.rootVerifierEntrypointPath
    || resolve(import.meta.dirname, 'contract.mjs')
      !== policy.rootVerifierContractPath
    || process.cwd() !== '/private/var/empty'
    || process.env.PATH !== '/usr/bin:/bin'
    || process.env.HOME !== '/var/root'
    || process.env.LANG !== 'C'
    || process.env.LC_ALL !== 'C') reject();
  const forbiddenEnvironment = Object.keys(process.env).filter((name) =>
    name.startsWith('NODE_')
      || name.startsWith('DYLD_')
      || name.startsWith('LD_')
      || ['BASH_ENV', 'ENV', 'OPENSSL_CONF', 'SSLKEYLOGFILE'].includes(name));
  if (forbiddenEnvironment.length !== 0) reject();
  await assertRootOwnedExecutable(
    SYSTEM_TOOLS.otool,
    SYSTEM_TOOL_SHA256.otool,
    0o755,
    2 * 1024 * 1024,
  );
  await assertRootOwnedExecutable(
    policy.rootVerifierNodePath,
    policy.rootVerifierNodeSha256,
    0o500,
    256 * 1024 * 1024,
  );
  assertSystemOnlyDynamicLibraries(policy.rootVerifierNodePath);
  await assertRootOwnedPinnedFile(
    policy.rootVerifierEntrypointPath,
    policy.rootVerifierEntrypointSha256,
    0o444,
    512 * 1024,
  );
  await assertRootOwnedPinnedFile(
    policy.rootVerifierContractPath,
    policy.rootVerifierContractSha256,
    0o444,
    512 * 1024,
  );
  await assertRootOwnedExecutable(
    policy.rootLauncherPath,
    policy.rootLauncherSha256,
    0o555,
  );
  assertSystemOnlyDynamicLibraries(policy.rootLauncherPath);
  const launchConfigFile = await readHeldCanonicalA28File(
    policy.rootVerifierLaunchConfigPath,
    {
      maximumBytes: A28_MAX_POLICY_BYTES,
      mode: 0o444,
      uid: 0,
    },
  );
  if (sha256A28(launchConfigFile.bytes)
      !== policy.rootVerifierLaunchConfigSha256) reject();
  assertA28RootLaunchConfig(launchConfigFile.value, policy, 'verify');
  runSystemTool(SYSTEM_TOOLS.codesign, [
    '--verify',
    '--strict',
    '--all-architectures',
    '--verbose=4',
    '-R=anchor apple generic and identifier "au.com.piui.a28-root-launcher" and certificate leaf[subject.OU] = '
      + policy.teamIdentifier,
    policy.rootLauncherPath,
  ]);
}

export async function assertOwnedA28Bundle(root, ownerUid) {
  assertAbsolutePath(root);
  if (!Number.isSafeInteger(ownerUid) || ownerUid < 0) reject();
  const observations = [...await assertPathChain(root, {
    leafMode: 0o755,
    leafUid: ownerUid,
    requireDirectory: true,
  })];
  const queue = [root];
  let entries = 0;
  while (queue.length > 0) {
    const directory = queue.shift();
    const children = await readdir(directory, { withFileTypes: true });
    children.sort((left, right) => left.name.localeCompare(right.name, 'en'));
    for (const child of children) {
      entries += 1;
      if (entries > MAX_BUNDLE_ENTRIES
        || child.isSymbolicLink()
        || (!child.isDirectory() && !child.isFile())) reject();
      const path = resolve(directory, child.name);
      if (dirname(path) !== directory || await realpath(path) !== path) reject();
      const item = await lstat(path);
      const exactMode = item.mode & 0o777;
      if (item.uid !== ownerUid
        || (item.mode & 0o022) !== 0
        || (child.isFile() && (!item.isFile() || item.nlink !== 1))
        || (child.isDirectory() && (!item.isDirectory() || exactMode !== 0o755))
        || (child.isFile() && ![0o444, 0o555].includes(exactMode))) reject();
      assertPathHasNoExtendedAcl(path);
      const afterAcl = await lstat(path);
      if (!sameFile(item, afterAcl)) reject();
      observations.push(Object.freeze({ path, state: item }));
      if (child.isDirectory()) queue.push(path);
    }
  }
  for (const observation of observations) {
    if (!sameFile(observation.state, await lstat(observation.path))) reject();
  }
}

async function assertRootOwnedBundle(root) {
  await assertOwnedA28Bundle(root, 0);
}

function runSystemTool(path, arguments_, {
  input,
  maxBuffer = 4 * 1024 * 1024,
} = {}) {
  const result = spawnSync(path, arguments_, {
    encoding: null,
    env: {
      LANG: 'C',
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
    },
    input,
    maxBuffer,
    timeout: 15_000,
  });
  if (result.error
    || result.signal
    || result.status !== 0
    || !Buffer.isBuffer(result.stdout)
    || !Buffer.isBuffer(result.stderr)) reject();
  return result;
}

function assertSystemOnlyDynamicLibraries(path) {
  const result = runSystemTool(SYSTEM_TOOLS.otool, ['-L', path], {
    maxBuffer: 1024 * 1024,
  });
  const lines = result.stdout.toString('utf8').trimEnd().split('\n');
  if (result.stderr.length !== 0
    || lines.length < 2
    || lines[0] !== path + ':') reject();
  for (const line of lines.slice(1)) {
    const match = /^\t(\/\S+) \(compatibility version [^)]+\)$/u.exec(line);
    if (!match
      || (!match[1].startsWith('/usr/lib/')
        && !match[1].startsWith('/System/Library/'))) reject();
  }
}

function parsePlist(bytes) {
  const converted = runSystemTool(
    SYSTEM_TOOLS.plutil,
    ['-convert', 'json', '-o', '-', '--', '-'],
    { input: bytes },
  ).stdout;
  let value;
  try {
    value = JSON.parse(converted.toString('utf8'));
  } catch {
    reject();
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject();
  return value;
}

function parseHelperLine(result) {
  if (result.stderr.length !== 0) reject();
  return parseCanonicalA28Line(result.stdout);
}

function versionAtLeast(actual, minimum) {
  const left = actual.split('.').map(Number);
  const right = minimum.split('.').map(Number);
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const actualPart = left[index] ?? 0;
    const minimumPart = right[index] ?? 0;
    if (actualPart !== minimumPart) return actualPart > minimumPart;
  }
  return true;
}

function assertLiveSystemVersions(challenge, policy) {
  const macosVersion = runSystemTool(
    SYSTEM_TOOLS.swVers,
    ['-productVersion'],
  ).stdout.toString('utf8').trim();
  const voiceOverVersion = runSystemTool(SYSTEM_TOOLS.plutil, [
    '-extract',
    'CFBundleShortVersionString',
    'raw',
    '-o',
    '-',
    '--',
    '/System/Library/CoreServices/VoiceOver.app/Contents/Info.plist',
  ]).stdout.toString('utf8').trim();
  if (macosVersion !== challenge.macosVersion
    || !versionAtLeast(macosVersion, policy.minimumMacOSVersion)
    || voiceOverVersion !== challenge.voiceOverVersion) reject();
}

async function inspectProfile(policy) {
  const profilePath = resolve(
    policy.installedApplicationPath,
    'Contents/embedded.provisionprofile',
  );
  await assertPathChain(profilePath, { leafMode: 0o444, leafUid: 0 });
  const profileBytes = await open(profilePath, constants.O_RDONLY | constants.O_NOFOLLOW)
    .then(async (handle) => {
      try {
        const before = await handle.stat();
        const bytes = await handle.readFile();
        const after = await handle.stat();
        if (!sameFile(before, after)
          || bytes.length !== before.size
          || sha256A28(bytes) !== policy.profileSha256) reject();
        return bytes;
      } finally {
        await handle.close();
      }
    });
  const decoded = runSystemTool(
    SYSTEM_TOOLS.security,
    ['cms', '-D', '-i', profilePath],
  ).stdout;
  const profile = parsePlist(decoded);
  const entitlements = profile.Entitlements;
  if (profile.UUID !== policy.profileUuid
    || profile.Name !== policy.profileName
    || !isDeepStrictEqual(profile.TeamIdentifier, [policy.teamIdentifier])
    || !Array.isArray(profile.Platform)
    || !profile.Platform.includes('OSX')
    || typeof profile.ExpirationDate !== 'string'
    || !(Date.parse(profile.ExpirationDate) > Date.now())
    || !entitlements
    || typeof entitlements !== 'object'
    || Array.isArray(entitlements)
    || profile.ProvisionsAllDevices !== true
    || entitlements['com.apple.application-identifier']
      !== policy.applicationIdentifier
    || entitlements['com.apple.developer.team-identifier'] !== policy.teamIdentifier
    || !isDeepStrictEqual(
      entitlements['keychain-access-groups'],
      [policy.keychainAccessGroup],
    )
    || entitlements['get-task-allow'] === true
    || entitlements['com.apple.security.get-task-allow'] === true
    || !Array.isArray(profile.DeveloperCertificates)
    || !profile.DeveloperCertificates.some((certificate) =>
      typeof certificate === 'string'
        && createHash('sha256')
          .update(Buffer.from(certificate, 'base64'))
          .digest('hex') === policy.signingCertificateSha256)) reject();
  return Object.freeze({
    keychainAccessGroups: Object.freeze([
      ...entitlements['keychain-access-groups'],
    ]),
    profileName: profile.Name,
    profileSha256: sha256A28(profileBytes),
    profileTeamIdentifiers: Object.freeze([...profile.TeamIdentifier]),
    profileUuid: profile.UUID,
  });
}

export async function inspectPinnedA28WitnessApp(policyPin) {
  const policy = assertA28PolicyPin(policyPin);
  await assertRootOwnedBundle(policy.installedApplicationPath);
  await assertPinnedExecutableIdentity(policy.witnessExecutable);
  await assertRootOwnedExecutable(
    policy.processInspectorPath,
    policy.processInspectorSha256,
    0o555,
  );
  runSystemTool(SYSTEM_TOOLS.codesign, [
    '--verify',
    '--strict',
    '--all-architectures',
    '--verbose=4',
    policy.installedApplicationPath,
  ]);
  await assertPinnedExecutableIdentity(policy.witnessExecutable);
  const staticInspection = parseHelperLine(runSystemTool(
    policy.processInspectorPath,
    [
      '--app',
      policy.installedApplicationPath,
      '--bundle-id',
      policy.bundleIdentifier,
      '--team-id',
      policy.teamIdentifier,
      '--reported-requirement',
      policy.designatedRequirement,
    ],
  ));
  await assertPinnedExecutableIdentity(policy.witnessExecutable);
  const profile = await inspectProfile(policy);
  await assertPinnedExecutableIdentity(policy.witnessExecutable);
  const inspection = {
    ...staticInspection,
    ...profile,
    installedApplicationPath: policy.installedApplicationPath,
  };
  return assertA28WitnessAppInspection(inspection, policy);
}

async function inspectLiveIdentities(policy, challenge, payload) {
  await assertRootOwnedExecutable(
    policy.processInspectorPath,
    policy.processInspectorSha256,
    0o555,
  );
  const host = parseHelperLine(runSystemTool(
    policy.processInspectorPath,
    [
      '--pid',
      String(challenge.applicationPid),
      '--bundle-id',
      challenge.hostBundleIdentifier,
      '--team-id',
      policy.hostTeamIdentifier,
      '--reported-requirement',
      policy.hostDesignatedRequirement,
    ],
  ));
  const runner = parseHelperLine(runSystemTool(
    policy.processInspectorPath,
    [
      '--pid',
      String(challenge.runnerPid),
      '--bundle-id',
      challenge.runnerBundleIdentifier,
      '--team-id',
      policy.runnerTeamIdentifier,
      '--reported-requirement',
      policy.runnerDesignatedRequirement,
    ],
  ));
  const voiceOver = parseHelperLine(runSystemTool(
    policy.processInspectorPath,
    [
      '--pid',
      String(challenge.voiceOverPid),
      '--bundle-id',
      'com.apple.VoiceOver',
      '--team-id',
      'APPLE-SYSTEM',
      '--reported-requirement',
      policy.voiceOverDesignatedRequirement,
    ],
  ));
  const witness = parseHelperLine(runSystemTool(
    policy.processInspectorPath,
    [
      '--pid',
      String(payload.witnessApplicationPid),
      '--bundle-id',
      policy.bundleIdentifier,
      '--team-id',
      policy.teamIdentifier,
      '--reported-requirement',
      policy.designatedRequirement,
    ],
  ));
  await assertRootOwnedExecutable(
    policy.processInspectorPath,
    policy.processInspectorSha256,
    0o555,
  );
  return Object.freeze({ host, runner, voiceOver, witness });
}

async function writeRootOwnedReceipt(
  directoryPath,
  directoryMode,
  receiptMode,
  record,
) {
  if (typeof process.getuid !== 'function' || process.getuid() !== 0) reject();
  await assertPathChain(directoryPath, {
    leafMode: directoryMode,
    leafUid: 0,
    requireDirectory: true,
  });
  const receiptPath = resolve(directoryPath, record.witnessNonce + '.json');
  if (dirname(receiptPath) !== directoryPath) reject();
  const bytes = canonicalA28Line(record);
  let handle;
  try {
    handle = await open(
      receiptPath,
      constants.O_CREAT
        | constants.O_EXCL
        | constants.O_WRONLY
        | constants.O_NOFOLLOW,
      receiptMode,
    );
    await handle.writeFile(bytes);
    await handle.chmod(receiptMode);
    await handle.sync();
  } catch (error) {
    if (error?.code === 'EEXIST') reject('A.28 witness nonce was already consumed');
    throw error;
  } finally {
    await handle?.close();
  }
  await assertPathChain(receiptPath, { leafMode: receiptMode, leafUid: 0 });
  const directoryHandle = await open(directoryPath, constants.O_RDONLY);
  try {
    await directoryHandle.sync();
  } finally {
    await directoryHandle.close();
  }
  return receiptPath;
}

async function consumeRootOwnedOnce(policy, record) {
  await writeRootOwnedReceipt(
    policy.auditDirectoryPath,
    0o700,
    0o400,
    record,
  );
  await writeRootOwnedReceipt(
    policy.resultDirectoryPath,
    0o755,
    0o444,
    record,
  );
  return record;
}

async function writeCheckpointAuthorisationRequest(policy, request) {
  await assertPathChain(policy.checkpointAuthorityDirectoryPath, {
    leafMode: 0o700,
    leafUid: 0,
    requireDirectory: true,
  });
  const path = resolve(
    policy.checkpointAuthorityDirectoryPath,
    request.checkpointSessionId + '-' + request.checkpointChecksSha256
      + '.authorise-request.json',
  );
  if (dirname(path) !== policy.checkpointAuthorityDirectoryPath) reject();
  const value = {
    challengeSha256: request.challengeSha256,
    challengeRequestSha256: request.challengeRequestSha256,
    checkpointChecksSha256: request.checkpointChecksSha256,
    checkpointSessionId: request.checkpointSessionId,
    checks: request.checks,
    completedAt: request.completedAt,
    schemaVersion: 1,
    witnessPid: request.witnessApplicationPid,
  };
  const bytes = canonicalA28Line(value);
  let handle;
  try {
    handle = await open(
      path,
      constants.O_CREAT
        | constants.O_EXCL
        | constants.O_WRONLY
        | constants.O_NOFOLLOW,
      0o400,
    );
    await handle.chown(0, 0);
    await handle.chmod(0o400);
    await handle.writeFile(bytes);
    await handle.sync();
  } catch (error) {
    if (error?.code === 'EEXIST') {
      reject('A.28 checkpoint authorisation request was already used');
    }
    throw error;
  } finally {
    await handle?.close();
  }
  return path;
}

async function authoriseRootCheckpoints(
  policy,
  challengePath,
  request,
) {
  const requestPath = await writeCheckpointAuthorisationRequest(
    policy,
    request,
  );
  process.stderr.write(
    '[working] Consuming the four root-issued checkpoint reveals.\n',
  );
  const result = spawnSync(policy.rootLauncherPath, [
    '--mode',
    'checkpoint',
    '--action',
    'authorise',
    '--input',
    challengePath,
    '--output',
    requestPath,
  ], {
    encoding: null,
    env: {
      HOME: '/var/root',
      LANG: 'C',
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
    },
    maxBuffer: 256 * 1024,
    timeout: 120_000,
  });
  if (result.error
    || result.signal
    || result.status !== 0
    || !Buffer.isBuffer(result.stdout)
    || !Buffer.isBuffer(result.stderr)
    || result.stderr.length !== 0) reject();
  return parseCanonicalA28Line(result.stdout);
}

export async function verifyA28WitnessFiles({
  attestationPath,
  challengePath,
  expectedChallengeSha256,
  now = Date.now(),
  policyPath = A28_POLICY_PIN_PATH,
}) {
  if (typeof process.getuid !== 'function'
    || typeof process.geteuid !== 'function'
    || process.getuid() !== 0
    || process.geteuid() !== 0
    || policyPath !== A28_POLICY_PIN_PATH
    || typeof expectedChallengeSha256 !== 'string'
    || !/^[0-9a-f]{64}$/u.test(expectedChallengeSha256)) reject();
  const policyFile = await readHeldCanonicalA28File(policyPath, {
    maximumBytes: A28_MAX_POLICY_BYTES,
    mode: 0o444,
    uid: 0,
  });
  const policy = assertA28PolicyPin(policyFile.value);
  await assertInstalledRootVerifier(policy);
  const [authorityConfigFile, enrolmentFile, enrolmentAuthorityReceiptFile] =
    await Promise.all([
      readHeldCanonicalA28File(policy.enrolmentAuthorityConfigPath, {
        maximumBytes: A28_MAX_POLICY_BYTES,
        mode: 0o444,
        uid: 0,
      }),
      readHeldCanonicalA28File(policy.enrolmentManifestPath, {
        maximumBytes: A28_MAX_ENROLMENT_BYTES,
        mode: 0o444,
        uid: 0,
      }),
      readHeldCanonicalA28File(policy.enrolmentAuthorityReceiptPath, {
        maximumBytes: A28_MAX_ENROLMENT_BYTES,
        mode: 0o400,
        uid: 0,
      }),
    ]);
  if (sha256A28(authorityConfigFile.bytes)
      !== policy.enrolmentAuthorityConfigSha256
    || sha256A28(enrolmentFile.bytes) !== policy.enrolmentManifestSha256
    || sha256A28(enrolmentAuthorityReceiptFile.bytes)
      !== policy.enrolmentAuthorityReceiptSha256) reject();
  const authorityConfig = assertA28EnrolmentAuthorityConfig(
    authorityConfigFile.value,
  );
  const enrolment = assertA28Enrolment(enrolmentFile.value, policy, now);
  const enrolmentAuthorityReceipt = assertA28EnrolmentAuthorityReceipt(
    enrolmentAuthorityReceiptFile.value,
    {
      authorityConfig,
      enrolment,
      now,
      policyPin: policy,
    },
  );
  const challengeFile = await readHeldCanonicalA28File(challengePath, {
    maximumBytes: A28_MAX_CHALLENGE_BYTES,
    mode: 0o444,
    uid: 0,
  });
  if (sha256A28(challengeFile.bytes) !== expectedChallengeSha256) reject();
  const challenge = assertA28Challenge(challengeFile.value, now, policy);
  if (challenge.policyPinSha256 !== sha256A28(policyFile.bytes)
    || challenge.reviewerIdentity !== enrolment.reviewerIdentity
    || challenge.reviewerKeyId !== enrolment.reviewerKeyId) reject();
  if (attestationPath !== challenge.attestationSlot.path) reject();
  assertLiveSystemVersions(challenge, policy);
  const attestationFile = await readHeldCanonicalA28File(attestationPath, {
    maximumBytes: A28_MAX_ATTESTATION_BYTES,
    mode: 0o400,
    uid: policy.witnessUid,
  });
  if (attestationFile.identity.dev !== challenge.attestationSlot.dev
    || attestationFile.identity.gid !== challenge.attestationSlot.gid
    || attestationFile.identity.ino !== challenge.attestationSlot.ino
    || attestationFile.identity.path !== challenge.attestationSlot.path
    || attestationFile.identity.uid !== challenge.attestationSlot.uid
    || attestationFile.identity.mode !== 0o400
    || attestationFile.identity.size !== attestationFile.bytes.length
    || attestationFile.identity.sha256 !== sha256A28(attestationFile.bytes)) {
    reject();
  }
  const inspection = await inspectPinnedA28WitnessApp(policy);
  process.stderr.write(
    '[working] Validating the signed witness and live process identities.\n',
  );
  const verification = await verifyA28WitnessAttestation({
    attestationBytes: attestationFile.bytes,
    attestationOutputIdentity: attestationFile.identity,
    authoriseCheckpoints: (request) =>
      authoriseRootCheckpoints(policy, challengePath, request),
    authorityConfig,
    challenge,
    consumeOnce: (record) =>
      consumeRootOwnedOnce(policy, record),
    enrolment,
    enrolmentAuthorityReceipt,
    inspection,
    now,
    observeLiveIdentities: (_stage, payload) =>
      inspectLiveIdentities(policy, challenge, payload),
    policyPin: policy,
  });
  const publishedReceiptPath = resolve(
    policy.resultDirectoryPath,
    verification.witnessNonce + '.json',
  );
  if (dirname(publishedReceiptPath) !== policy.resultDirectoryPath) reject();
  return Object.freeze({
    ...verification,
    publishedReceiptPath,
    publishedReceiptSha256: sha256A28(canonicalA28Line(verification.audit)),
  });
}

function parseArguments(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!['--attestation', '--challenge', '--expected-challenge-sha256']
      .includes(flag)
      || value === undefined
      || Object.hasOwn(values, flag)) reject();
    values[flag] = value;
  }
  exactKeys(values, [
    '--attestation',
    '--challenge',
    '--expected-challenge-sha256',
  ]);
  return values;
}

async function main() {
  const arguments_ = parseArguments(process.argv.slice(2));
  const result = await verifyA28WitnessFiles({
    attestationPath: resolve(arguments_['--attestation']),
    challengePath: resolve(arguments_['--challenge']),
    expectedChallengeSha256: arguments_['--expected-challenge-sha256'],
  });
  process.stdout.write(canonicalA28Line(result));
}

if (import.meta.url === new URL(process.argv[1], 'file:').href) {
  main().catch((error) => {
    process.stderr.write('A.28 authenticated witness verification failed: '
      + error.message + '\n');
    process.exitCode = 1;
  });
}
