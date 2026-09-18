import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, resolve, sep } from 'node:path';
import test from 'node:test';
import {
  assertHeldA28ApplicationResources,
  assertHeldA28BuildInputBindings,
  assertHeldA28BuildModes,
  captureHeldA28BuildSnapshot,
  closeA28OutputPublicationLease,
  closeHeldA28BuildSnapshot,
  closePrivateA28BuildWorkspace,
  compareTimestampedSignatures,
  createA28OutputPublicationLease,
  createPrivateA28BuildWorkspace,
  preflightPrivateA28DescriptorHelpers,
  publishHeldA28Build,
  selectA28SigningCertificateSelector,
  signPrivateA28WorkspaceCopies,
  validateA28DescriptorHelpers,
} from '../../scripts/a28-witness/build.mjs';
import {
  canonicalA28Json,
  sha256A28,
} from '../../scripts/a28-witness/contract.mjs';
import {
  APPLE_TOOLCHAIN_PATHS,
  appleToolchainBuildEnvironment,
  captureAppleToolchainAuthority,
  releaseAppleToolchainAuthority,
  revalidateAppleToolchainAuthority,
} from '../../scripts/apple-toolchain-trust.mjs';
import {
  assertOwnedA28Bundle,
} from '../../scripts/a28-witness/verify.mjs';

const root = resolve(import.meta.dirname, '../..');
const witnessRoot = resolve(root, 'scripts/a28-witness');

async function source(name) {
  return readFile(resolve(witnessRoot, name), 'utf8');
}

async function populateSigningFixture(buildRoot) {
  const sourceDirectory = resolve(buildRoot, 'source');
  await mkdir(sourceDirectory, { mode: 0o700 });
  await mkdir(resolve(buildRoot, 'PIUI A28 VoiceOver Witness.app'), {
    mode: 0o700,
  });
  await mkdir(
    resolve(buildRoot, 'PIUI A28 VoiceOver Witness reproduction.app'),
    { mode: 0o700 },
  );
  await writeFile(
    resolve(sourceDirectory, 'A28Witness.entitlements'),
    '<plist/>',
    { flag: 'wx', mode: 0o400 },
  );
  await writeFile(resolve(buildRoot, 'a28-root-launcher'), 'first', {
    flag: 'wx',
    mode: 0o500,
  });
  await writeFile(
    resolve(buildRoot, 'a28-root-launcher-reproduction'),
    'second',
    { flag: 'wx', mode: 0o500 },
  );
}

async function populateModeFixture(buildRoot) {
  await populateSigningFixture(buildRoot);
  for (const name of [
    'PIUI A28 VoiceOver Witness.app',
    'PIUI A28 VoiceOver Witness reproduction.app',
  ]) {
    const macos = resolve(buildRoot, name, 'Contents/MacOS');
    await mkdir(macos, { recursive: true, mode: 0o700 });
    await writeFile(resolve(macos, 'A28Witness'), 'witness', {
      flag: 'wx',
      mode: 0o500,
    });
  }
  await writeFile(resolve(buildRoot, 'a28-process-identity'), 'inspector', {
    flag: 'wx',
    mode: 0o500,
  });
}

function signingFixtureArguments(lease, overrides = {}) {
  return {
    applicationPreSigningRecords: canonicalA28Json([]),
    applicationRelativePath: 'build/PIUI A28 VoiceOver Witness.app',
    entitlementsRelativePath: 'build/source/A28Witness.entitlements',
    entitlementsSha256: sha256A28(Buffer.from('<plist/>', 'utf8')),
    lease,
    reproductionApplicationPreSigningRecords: canonicalA28Json([]),
    reproductionApplicationRelativePath:
      'build/PIUI A28 VoiceOver Witness reproduction.app',
    reproductionRootLauncherUnsignedSha256:
      sha256A28(Buffer.from('second', 'utf8')),
    reproductionRootLauncherRelativePath:
      'build/a28-root-launcher-reproduction',
    rootLauncherUnsignedSha256: sha256A28(Buffer.from('first', 'utf8')),
    rootLauncherRelativePath: 'build/a28-root-launcher',
    signingCertificateSelector: 'a'.repeat(40),
    ...overrides,
  };
}

function syntheticTimestampedMachO(cmsPayload, gapByte = 0) {
  const nonCms = Buffer.alloc(12);
  nonCms.writeUInt32BE(0xfade0c02, 0);
  nonCms.writeUInt32BE(nonCms.length, 4);
  nonCms.writeUInt32BE(0x01020304, 8);
  const gap = Buffer.from([gapByte, 0, 0, 0]);
  const cms = Buffer.alloc(8 + cmsPayload.length);
  cms.writeUInt32BE(0xfade0b01, 0);
  cms.writeUInt32BE(cms.length, 4);
  cmsPayload.copy(cms, 8);
  const indexLength = 28;
  const nonCmsOffset = indexLength;
  const cmsOffset = nonCmsOffset + nonCms.length + gap.length;
  const superBlob = Buffer.alloc(cmsOffset + cms.length);
  superBlob.writeUInt32BE(0xfade0cc0, 0);
  superBlob.writeUInt32BE(superBlob.length, 4);
  superBlob.writeUInt32BE(2, 8);
  superBlob.writeUInt32BE(0, 12);
  superBlob.writeUInt32BE(nonCmsOffset, 16);
  superBlob.writeUInt32BE(0x10000, 20);
  superBlob.writeUInt32BE(cmsOffset, 24);
  nonCms.copy(superBlob, nonCmsOffset);
  gap.copy(superBlob, nonCmsOffset + nonCms.length);
  cms.copy(superBlob, cmsOffset);
  const machO = Buffer.alloc(48);
  machO.writeUInt32LE(0xfeedfacf, 0);
  machO.writeUInt32LE(1, 16);
  machO.writeUInt32LE(16, 20);
  machO.writeUInt32LE(0x1d, 32);
  machO.writeUInt32LE(16, 36);
  machO.writeUInt32LE(machO.length, 40);
  machO.writeUInt32LE(superBlob.length, 44);
  return Buffer.concat([machO, superBlob]);
}

function successfulSigningRunner(calls, lease) {
  return (path, arguments_, options) => {
    assert.equal(path, '/usr/bin/ruby');
    assert.equal(arguments_[0], '--disable-gems');
    assert.equal(arguments_[1], '-e');
    assert.match(arguments_[2], /\/usr\/bin\/codesign/u);
    assert.equal(['app-sign', 'root-sign'].includes(arguments_[3]), true);
    assert.equal(arguments_[4], 'a'.repeat(40));
    assert.equal(options.cwd, '/private/var/empty');
    assert.equal(Array.isArray(options.stdio), true);
    assert.equal(options.stdio.slice(0, 3).join(','), 'ignore,pipe,pipe');
    assert.equal(
      options.stdio.slice(3).every((descriptor) =>
        Number.isSafeInteger(descriptor) && descriptor >= 0),
      true,
    );
    const target = arguments_[5];
    assert.equal(target.startsWith('build' + sep), true);
    assert.equal(
      resolve(lease.workspacePath, target)
        .startsWith(lease.buildRootPath + sep),
      true,
    );
    calls.push(Object.freeze({
      arguments_: Object.freeze([...arguments_]),
      cwd: options.cwd,
      path,
    }));
    return Object.freeze({
      signal: null,
      status: 0,
      stderr: Buffer.alloc(0),
      stdout: Buffer.alloc(0),
    });
  };
}

async function createPublicationFixture(prefix) {
  const fixtureRoot = await realpath(
    await mkdtemp(resolve(tmpdir(), prefix)),
  );
  const outputParent = resolve(fixtureRoot, 'output-parent');
  await mkdir(outputParent, { mode: 0o700 });
  const requestedRoot = resolve(outputParent, 'published-build');
  const publicationLease = await createA28OutputPublicationLease(requestedRoot);
  try {
    const workspaceLease = await createPrivateA28BuildWorkspace({
      publicationLease,
    });
    return Object.freeze({
      fixtureRoot,
      outputParent,
      publicationLease,
      requestedRoot,
      workspaceLease,
    });
  } catch (error) {
    await closeA28OutputPublicationLease(publicationLease);
    throw error;
  }
}

async function closePublicationFixture(fixture) {
  try {
    await closePrivateA28BuildWorkspace(fixture.workspaceLease);
  } finally {
    await closeA28OutputPublicationLease(fixture.publicationLease);
  }
}

async function replaceSigningObject(path, type, ordinal) {
  const displaced = resolve(
    dirname(path),
    `displaced-${ordinal}-${basename(path)}`,
  );
  await rename(path, displaced);
  if (type === 'directory') {
    await mkdir(path, { mode: 0o700 });
  } else {
    await writeFile(path, `attacker-${ordinal}`, { flag: 'wx', mode: 0o500 });
  }
  return displaced;
}

test('native witness and process inspector compile cleanly with Apple clang', () => {
  const authority = captureAppleToolchainAuthority();
  try {
    for (const definition of [
      {
        frameworks: ['AppKit', 'LocalAuthentication', 'Security'],
        source: 'A28WitnessApp.m',
      },
      {
        frameworks: ['Foundation', 'Security'],
        source: 'A28ProcessIdentity.m',
      },
      {
        frameworks: ['Foundation', 'Security'],
        source: 'A28RootLauncher.m',
      },
    ]) {
      const arguments_ = [
        '-fobjc-arc',
        '-std=c17',
        '-Wall',
        '-Wextra',
        '-Werror',
        '-isysroot',
        APPLE_TOOLCHAIN_PATHS.sdk,
      ];
      for (const framework of definition.frameworks) {
        arguments_.push('-framework', framework);
      }
      arguments_.push(
        resolve(witnessRoot, definition.source),
        '-o',
        '/dev/null',
      );
      const result = spawnSync(APPLE_TOOLCHAIN_PATHS.clang, arguments_, {
        encoding: 'utf8',
        env: {
          ...appleToolchainBuildEnvironment(),
          LANG: 'C',
          LC_ALL: 'C',
          PATH: `${APPLE_TOOLCHAIN_PATHS.bin}:/usr/bin:/bin`,
        },
        timeout: 30_000,
      });
      revalidateAppleToolchainAuthority(authority);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.signal, null);
      assert.equal(result.stdout, '');
      assert.equal(result.stderr, '');
    }
  } finally {
    releaseAppleToolchainAuthority(authority);
  }
});

test('native app owns all four decisions and requires Secure Enclave biometric use', async () => {
  const native = await source('A28WitnessApp.m');
  for (const requirement of [
    'kSecAttrTokenIDSecureEnclave',
    'kSecAccessControlBiometryCurrentSet',
    'kSecAccessControlPrivateKeyUsage',
    'kSecAttrAccessGroup',
    'kSecUseAuthenticationContext',
    'kSecUseDataProtectionKeychain',
    'authenticationContext.localizedReason',
    'VoiceOverIsRunning',
    'com.apple.VoiceOver',
    '/System/Library/CoreServices/VoiceOver.app',
    'RejectExistingSecureEnclaveKey',
    'kSecMatchLimitAll',
    '@"dataProtectionKeychain": @YES',
    'SecKeyCopyExternalRepresentation',
    'SecKeyCreateSignature',
    'PIUI-A28-VOICEOVER-WITNESS\\0v1\\0',
    'PIUI-A28-SECURE-ENCLAVE-ENROLMENT\\0v1\\0',
    '@[@"Dark", @"Accessible"]',
    '@[@"Dark", @"Virtualised"]',
    '@[@"Light", @"Accessible"]',
    '@[@"Light", @"Virtualised"]',
    'payload[@"checks"] = decisions',
    'payload[@"witnessAuditTokenSha256"]',
    'payload[@"witnessExecutable"]',
    'payload[@"witnessStartTime"]',
    '[self.spinner startAnimation:nil]',
    'Waiting for Secure Enclave biometric authentication',
    'attestationSlot',
    'challengeRequestSha256',
    'external-final-consumer-required',
    'excludes-run-source-artifact-fingerprint-authentication',
    'WriteHeldAttestationSlot',
    'O_NOFOLLOW',
    '(before.st_mode & 0777) != S_IWUSR',
    'fchmod(descriptor, S_IRUSR)',
    'O_NOFOLLOW',
    'WriteHeldCanonicalDescriptor',
    'pwrite(',
  ]) {
    assert.ok(native.includes(requirement), requirement);
  }
  assert.doesNotMatch(native, /kSecUseOperationPrompt/u);
  assert.doesNotMatch(native, /SecItemDelete|removeItemAtPath|unlink\s*\(/u);
  assert.doesNotMatch(native, /humanWitnessed/u);
  assert.doesNotMatch(native, /O_WRONLY \| O_CREAT \| O_EXCL/u);
  assert.match(native, /self\.signButton\.enabled = NO/u);
  assert.match(native, /self\.signButton\.enabled = allComplete/u);
});

test('process inspector binds audit token, start time, code identity and held bytes', async () => {
  const inspector = await source('A28ProcessIdentity.m');
  for (const requirement of [
    'TASK_AUDIT_TOKEN',
    'pbi_start_tvsec',
    'pbi_start_tvusec',
    'kSecCodeInfoIdentifier',
    'kSecCodeInfoUnique',
    'CopyPositiveRequirement',
    'SecCodeCheckValidity',
    'SecStaticCodeCheckValidity',
    'O_NOFOLLOW',
    'SameExecutableStat(heldBefore, pathnameBefore)',
    'SameExecutableStat(heldBefore, heldAfter)',
    'SameExecutableStat(heldBefore, pathnameAfter)',
    'st_ctimespec.tv_nsec',
    'information.pbi_start_tvsec != after.pbi_start_tvsec',
    'A.28 process changed during inspection',
    '@"cdHash": Hex(cdHash)',
  ]) {
    assert.ok(inspector.includes(requirement), requirement);
  }
  assert.doesNotMatch(inspector, /kill\s*\([^,]+,\s*SIG/u);
});

test('root verifier is install-first, pinned, environment-scrubbed and single-use', async () => {
  const [contract, verifier] = await Promise.all([
    source('contract.mjs'),
    source('verify.mjs'),
  ]);
  for (const requirement of [
    'rootVerifierNodePath',
    'rootVerifierNodeSha256',
    'rootVerifierEntrypointPath',
    'rootVerifierEntrypointSha256',
    'rootVerifierContractPath',
    'rootVerifierContractSha256',
    'rootLauncherUnsignedSha256',
    'witnessExecutableUnsignedSha256',
    'witnessExecutable',
    'resultDirectoryPath',
    'A28_POLICY_PIN_PATH',
    'A28_MAX_POLICY_BYTES',
    'A28_MAX_ENROLMENT_BYTES',
    'A28_MAX_PUBLISHED_RECEIPT_BYTES',
  ]) {
    assert.ok(contract.includes(requirement), requirement);
  }
  for (const requirement of [
    'process.getuid() !== 0',
    'process.geteuid() !== 0',
    'process.execPath !== policy.rootVerifierNodePath',
    'process.execArgv.length !== 0',
    'fileURLToPath(import.meta.url) !== policy.rootVerifierEntrypointPath',
    "process.cwd() !== '/private/var/empty'",
    "process.env.PATH !== '/usr/bin:/bin'",
    "process.env.HOME !== '/var/root'",
    "name.startsWith('NODE_')",
    "name.startsWith('DYLD_')",
    'constants.O_EXCL',
    'constants.O_NOFOLLOW',
    'await handle.chmod(receiptMode)',
    'A.28 witness nonce was already consumed',
    'policy.resultDirectoryPath',
    'assertSystemOnlyDynamicLibraries(policy.rootVerifierNodePath)',
    '/Library/Developer/CommandLineTools/usr/bin/otool-classic',
    '1f542421b643d10452395bfb80c0b03827724822f56c4d3d8c0c69683861824b',
    'SYSTEM_TOOL_SHA256.otool',
    'acl_get_file',
    'assertPathHasNoExtendedAcl(candidate)',
    'assertPathHasNoExtendedAcl(path)',
    'if (!sameFile(item, afterAcl)) reject()',
    '256 * 1024 * 1024',
    'policy.minimumMacOSVersion',
    'ProvisionsAllDevices',
    "entitlements['com.apple.application-identifier']",
    '0o755',
    '0o444',
    "'--pid',",
    "'--bundle-id',",
    "'--team-id',",
    "'--reported-requirement',",
    'attestationPath !== challenge.attestationSlot.path',
    'attestationOutputIdentity: attestationFile.identity',
    'challengeRequestSha256: request.challengeRequestSha256',
    '/System/Library/CoreServices/VoiceOver.app/Contents/Info.plist',
    '(before.mode & 0o777) !== 0o555',
  ]) {
    assert.ok(verifier.includes(requirement), requirement);
  }
  assert.doesNotMatch(verifier, /Documents\/Code\/PIUI|process\.env\.NODE_PATH/u);
  assert.doesNotMatch(verifier, /['"]\/usr\/bin\/otool['"]/u);
  assert.doesNotMatch(verifier, /sudo|execSync|shell:\s*true/u);
  assert.match(verifier, /from '\.\/contract\.mjs'/u);
  assert.equal(
    [...verifier.matchAll(/^import .* from '([^']+)'/gmu)]
      .every((match) => match[1].startsWith('node:')
        || match[1] === './contract.mjs'),
    true,
  );
});

test('bundle trust rejects extended ACLs on descendant directories and files', async () => {
  if (process.platform !== 'darwin' || typeof process.getuid !== 'function') return;
  const ownerUid = process.getuid();
  const usernameResult = spawnSync('/usr/bin/id', ['-un'], {
    encoding: 'utf8',
    env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
  });
  assert.equal(usernameResult.status, 0, usernameResult.stderr);
  const username = usernameResult.stdout.trim();
  assert.match(username, /^[A-Za-z0-9._-]+$/u);

  for (const targetKind of ['directory', 'file']) {
    const fixtureRoot = await realpath(await mkdtemp(resolve(
      tmpdir(),
      `piui-a28-bundle-acl-${targetKind}-`,
    )));
    const contents = resolve(fixtureRoot, 'Contents');
    const executable = resolve(contents, 'A28Witness');
    await mkdir(contents, { mode: 0o755 });
    await writeFile(executable, 'witness\n', { flag: 'wx', mode: 0o444 });
    await chmod(fixtureRoot, 0o755);
    let baselineError;
    for (let attempt = 0; attempt < 8; attempt += 1) {
      try {
        await assertOwnedA28Bundle(fixtureRoot, ownerUid);
        baselineError = undefined;
        break;
      } catch (error) {
        baselineError = error;
        await new Promise((resolveRetry) => setTimeout(resolveRetry, 25));
      }
    }
    if (baselineError) throw baselineError;

    const target = targetKind === 'directory' ? contents : executable;
    const acl = `user:${username} allow write,delete,writeattr,writeextattr`;
    const aclResult = spawnSync('/bin/chmod', ['+a', acl, target], {
      encoding: 'utf8',
      env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
    });
    assert.equal(aclResult.status, 0, aclResult.stderr);
    await assert.rejects(
      assertOwnedA28Bundle(fixtureRoot, ownerUid),
      /A\.28 authenticated witness system verification rejected/u,
    );
  }
});

test('native root launcher validates before Node and creates a bounded root prepare slot', async () => {
  const launcher = await source('A28RootLauncher.m');
  for (const requirement of [
    'getuid() != 0 || geteuid() != 0',
    'kSecCodeSignatureRuntime',
    'SecStaticCodeCheckValidity',
    'positiveRequirementText',
    'kSecCodeInfoTeamIdentifier',
    'ReadPinnedFile(config[@"nodePath"], 0500',
    'ReadPinnedFile(\n      config[@"entrypointPath"],\n      0444',
    'ReadBoundedPrepareRequest',
    'O_NONBLOCK',
    'poll(&observed, 1, remaining)',
    'A28PrepareReadTimeoutMilliseconds',
    'openat(',
    'O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW',
    'fchmod(descriptor, 0400)',
    'AT_SYMLINK_NOFOLLOW',
    'held.st_ctimespec.tv_nsec != pathname.st_ctimespec.tv_nsec',
    'fsync(directory)',
    'CloseInheritedDescriptors',
    'ResetEnvironment',
    'chdir("/private/var/empty")',
    'execve(',
    '[working] Waiting for one complete A.28 challenge request',
  ]) assert.ok(launcher.includes(requirement), requirement);
  assert.doesNotMatch(launcher, /system\s*\(|popen\s*\(|execvp\s*\(/u);

  const privateBuildDirectory = await realpath(
    await mkdtemp(resolve(tmpdir(), 'piui-a28-root-launcher-test-')),
  );
  await chmod(privateBuildDirectory, 0o700);
  const privateBuildDirectoryState = await lstat(privateBuildDirectory);
  assert.equal(privateBuildDirectoryState.isDirectory(), true);
  assert.equal(privateBuildDirectoryState.isSymbolicLink(), false);
  assert.equal(privateBuildDirectoryState.mode & 0o777, 0o700);
  if (typeof process.getuid === 'function') {
    assert.equal(privateBuildDirectoryState.uid, process.getuid());
  }
  const output = resolve(privateBuildDirectory, 'a28-root-launcher');
  const authority = captureAppleToolchainAuthority();
  let compile;
  try {
    compile = spawnSync(APPLE_TOOLCHAIN_PATHS.clang, [
      '-fobjc-arc',
      '-std=c17',
      '-Wall',
      '-Wextra',
      '-Werror',
      '-isysroot',
      APPLE_TOOLCHAIN_PATHS.sdk,
      '-framework',
      'Foundation',
      '-framework',
      'Security',
      resolve(witnessRoot, 'A28RootLauncher.m'),
      '-o',
      output,
    ], {
      encoding: 'utf8',
      env: {
        ...appleToolchainBuildEnvironment(),
        LANG: 'C',
        LC_ALL: 'C',
        PATH: `${APPLE_TOOLCHAIN_PATHS.bin}:/usr/bin:/bin`,
      },
      timeout: 30_000,
    });
    revalidateAppleToolchainAuthority(authority);
  } finally {
    releaseAppleToolchainAuthority(authority);
  }
  assert.equal(compile.status, 0, compile.stderr);
  const outputHandle = await open(output, 'r');
  try {
    const outputState = await outputHandle.stat();
    const outputPathState = await lstat(output);
    assert.equal(outputState.isFile(), true);
    assert.equal(outputPathState.isSymbolicLink(), false);
    assert.equal(outputState.nlink, 1);
    assert.equal(outputState.dev, outputPathState.dev);
    assert.equal(outputState.ino, outputPathState.ino);
    assert.equal(outputState.size, outputPathState.size);
    assert.equal(outputState.mode & 0o777, 0o755);
    if (typeof process.getuid === 'function') {
      assert.equal(outputState.uid, process.getuid());
    }
    const hostile = spawnSync(output, ['--mode', 'checkpoint', '--action', 'prepare'], {
      encoding: 'utf8',
      env: {
        LANG: 'C',
        LC_ALL: 'C',
        NODE_OPTIONS: '--require=/definitely/not/a/real/preload.cjs',
        PATH: '/usr/bin:/bin',
      },
      input: '{}\n',
      timeout: 10_000,
    });
    assert.equal(hostile.status, 1);
    assert.match(hostile.stderr, /requires root and an exact mode/u);
    assert.doesNotMatch(hostile.stderr, /Cannot find module|preload\.cjs/u);
    const after = await outputHandle.stat();
    assert.equal(after.dev, outputState.dev);
    assert.equal(after.ino, outputState.ino);
    assert.equal(after.size, outputState.size);
    assert.equal(after.mtimeMs, outputState.mtimeMs);
  } finally {
    await outputHandle.close();
  }
});

test('build proves timestamp variation twice and legacy enrolment is retired', async () => {
  const [buildSource, enrolSource] = await Promise.all([
    source('build.mjs'),
    source('enrol.mjs'),
  ]);
  for (const buildRequirement of [
    'assertRootOwnedAppleTool',
    'assertRootOwnedAppleSdk',
    'APPLE_TOOLCHAIN_PATHS.clang',
    'APPLE_TOOLCHAIN_PATHS.sdk',
    'captureAppleToolchainAuthority',
    'revalidateAppleToolchainAuthority',
    'releaseAppleToolchainAuthority',
    "'-isysroot'",
    'validateProfile',
    'assertSigningIdentity',
    'policy.processInspectorSha256',
    'policy.witnessExecutableUnsignedSha256',
    'policy.rootLauncherUnsignedSha256',
    'compareTimestampedSignatures',
    "allowedVariation: 'cms-and-signature-container-length-only'",
    'canonicalDarwinTemporaryRoot',
    'createPrivateA28BuildWorkspace',
    'runPrivateA28WorkspaceCommand',
    'signPrivateA28WorkspaceCopies',
    'descriptorCodesignRuby',
    'descriptorInspectorRuby',
    'descriptorMetadataRuby',
    'preflightPrivateA28DescriptorHelpers',
    'selectA28SigningCertificateSelector',
    'assertHeldA28BuildInputBindings',
    'assertHeldA28BuildModes',
    'canonicalAuthorisedSourceRecords',
    'canonicalAuthorisedApplicationResources',
    'assertSignedReproductionMatchesUnsigned',
    'captureHeldA28BuildSnapshot',
    'publishHeldA28Build',
    'renameatx_np',
    'nonCmsSlots',
    'normalisedContainerSha256',
    'normalisedPrefixSha256',
    "humanWitnessed: false",
    "rootInstallationRequired: true",
  ]) {
    assert.ok(buildSource.includes(buildRequirement), buildRequirement);
  }
  assert.doesNotMatch(buildSource, /\/usr\/bin\/(?:clang|xcrun)/u);
  assert.match(
    buildSource,
    /import \{[\s\S]*?canonicalA28Json,[\s\S]*?\} from '\.\/contract\.mjs';/u,
  );
  for (const enrolRequirement of [
    'user-owned candidate enrolment is retired',
    'installed root launcher with --mode enrol',
  ]) {
    assert.ok(enrolSource.includes(enrolRequirement), enrolRequirement);
  }
  assert.doesNotMatch(
    enrolSource,
    /candidateHandle|--candidate|--output-fd|humanWitnessed|find-identity|find-certificate/u,
  );
  for (const [script, arguments_] of [
    ['build.mjs', []],
    ['enrol.mjs', []],
    ['verify.mjs', []],
  ]) {
    const result = spawnSync(process.execPath, [
      resolve(witnessRoot, script),
      ...arguments_,
    ], {
      encoding: 'utf8',
      env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
      timeout: 10_000,
    });
    assert.equal(result.status, 1, script);
    assert.equal(result.stdout, '', script);
    assert.doesNotMatch(result.stderr, /"humanWitnessed":true/u);
  }
  assert.doesNotMatch(buildSource + enrolSource, /sudo|chown|chmodSync/u);
  assert.ok(
    buildSource.indexOf('await signPrivateA28WorkspaceCopies({')
      < buildSource.indexOf(
        'const signedSnapshot = await captureHeldA28BuildSnapshot(',
      ),
  );
  assert.ok(
    buildSource.indexOf(
      'const signedSnapshot = await captureHeldA28BuildSnapshot(',
    ) < buildSource.indexOf('await publishHeldA28Build({'),
  );
  assert.doesNotMatch(buildSource, /exportVerifiedA28Build/u);
  await validateA28DescriptorHelpers();
});

test('descriptor helpers execute their real success checks without external tools', async () => {
  const lease = await createPrivateA28BuildWorkspace();
  try {
    await populateSigningFixture(lease.buildRootPath);
    await writeFile(
      resolve(lease.buildRootPath, 'a28-process-identity'),
      'inspector',
      { flag: 'wx', mode: 0o500 },
    );
    await preflightPrivateA28DescriptorHelpers({
      applicationRelativePath: 'build/PIUI A28 VoiceOver Witness.app',
      entitlementsRelativePath: 'build/source/A28Witness.entitlements',
      inspectorRelativePath: 'build/a28-process-identity',
      lease,
      rootLauncherRelativePath: 'build/a28-root-launcher',
    });
  } finally {
    await closePrivateA28BuildWorkspace(lease);
  }
});

test('timestamp comparison normalises CMS only and retains container gaps', () => {
  const first = syntheticTimestampedMachO(Buffer.from('first-cms', 'utf8'));
  const second = syntheticTimestampedMachO(
    Buffer.from('a-different-longer-cms', 'utf8'),
  );
  const reproduction = compareTimestampedSignatures(first, second);
  assert.equal(
    reproduction.allowedVariation,
    'cms-and-signature-container-length-only',
  );
  assert.equal(
    reproduction.first.normalisedContainerSha256,
    reproduction.second.normalisedContainerSha256,
  );
  assert.throws(
    () => compareTimestampedSignatures(
      first,
      syntheticTimestampedMachO(Buffer.from('second-cms', 'utf8'), 1),
    ),
    /A\.28 witness build rejected/u,
  );
});

test('certificate selection uses the profile-pinned fingerprint, not a shared name', () => {
  const signingIdentity = 'Developer ID Application: renewed fixture (TEAMID1234)';
  const expectedSha1 = '2'.repeat(40);
  const expectedSha256 = 'b'.repeat(64);
  const certificateListing = [
    `SHA-256 hash: ${'A'.repeat(64)}`,
    `SHA-1 hash: ${'1'.repeat(40)}`,
    'keychain: "/fixture/old.keychain-db"',
    `SHA-256 hash: ${expectedSha256.toUpperCase()}`,
    `SHA-1 hash: ${expectedSha1.toUpperCase()}`,
    'keychain: "/fixture/current.keychain-db"',
  ].join('\n');
  const identitiesListing = [
    `  1) ${'1'.repeat(40)} "${signingIdentity}"`,
    `  2) ${expectedSha1.toUpperCase()} "${signingIdentity}"`,
    '     2 valid identities found',
  ].join('\n');
  assert.equal(selectA28SigningCertificateSelector({
    certificateListing,
    identitiesListing,
    signingCertificateSha1: expectedSha1,
    signingCertificateSha256: expectedSha256,
    signingIdentity,
  }), expectedSha1);
  assert.throws(() => selectA28SigningCertificateSelector({
    certificateListing,
    identitiesListing: identitiesListing.split('\n')[0],
    signingCertificateSha1: expectedSha1,
    signingCertificateSha256: expectedSha256,
    signingIdentity,
  }), /A\.28 witness build rejected/u);
});

test('all four signing commands use held descriptors and private relative paths', async () => {
  const lease = await createPrivateA28BuildWorkspace();
  const calls = [];
  try {
    await populateSigningFixture(lease.buildRootPath);
    await signPrivateA28WorkspaceCopies(signingFixtureArguments(lease, {
      commandRunner: successfulSigningRunner(calls, lease),
    }));
    assert.equal(calls.length, 4);
    assert.deepEqual(calls.map(({ arguments_ }) => arguments_[3]), [
      'app-sign',
      'app-sign',
      'root-sign',
      'root-sign',
    ]);
  } finally {
    await closePrivateA28BuildWorkspace(lease);
  }
});

test('pre-invocation signing-input changes cannot reach the runner', async (context) => {
  const attacks = [
    'application',
    'reproduction-application',
    'root-launcher',
    'reproduction-root-launcher',
    'entitlements',
  ];
  for (const attack of attacks) {
    await context.test(attack, async () => {
      const lease = await createPrivateA28BuildWorkspace();
      const calls = [];
      try {
        await populateSigningFixture(lease.buildRootPath);
        if (attack.endsWith('application')) {
          const name = attack === 'application'
            ? 'PIUI A28 VoiceOver Witness.app'
            : 'PIUI A28 VoiceOver Witness reproduction.app';
          await writeFile(resolve(lease.buildRootPath, name, 'pre-entry-change'),
            'attacker', { flag: 'wx', mode: 0o400 });
        } else {
          const names = {
            entitlements: 'source/A28Witness.entitlements',
            'root-launcher': 'a28-root-launcher',
            'reproduction-root-launcher': 'a28-root-launcher-reproduction',
          };
          const target = resolve(lease.buildRootPath, names[attack]);
          await rename(
            target,
            resolve(dirname(target), 'pre-entry-' + basename(target)),
          );
          await writeFile(
            target,
            attack === 'entitlements' ? '<pre-entry-attacker/>' : 'attacker',
            { flag: 'wx', mode: attack === 'entitlements' ? 0o400 : 0o500 },
          );
        }
        await assert.rejects(
          signPrivateA28WorkspaceCopies(signingFixtureArguments(lease, {
            commandRunner: successfulSigningRunner(calls, lease),
          })),
          /pre-sign inputs differ from their authorised bytes/u,
        );
        assert.equal(calls.length, 0);
      } finally {
        await closePrivateA28BuildWorkspace(lease);
      }
    });
  }
});

test('replacement of each exact signing target is rejected before that call', async (context) => {
  const targets = [
    { type: 'directory' },
    { type: 'directory' },
    { type: 'file' },
    { type: 'file' },
  ];
  for (let attackOrdinal = 0; attackOrdinal < targets.length; attackOrdinal += 1) {
    await context.test(`signing call ${attackOrdinal + 1}`, async () => {
      const lease = await createPrivateA28BuildWorkspace();
      const calls = [];
      try {
        await populateSigningFixture(lease.buildRootPath);
        await assert.rejects(
          signPrivateA28WorkspaceCopies(signingFixtureArguments(lease, {
            beforeSigningCommand: async ({ ordinal, targetPath }) => {
              if (ordinal === attackOrdinal) {
                await replaceSigningObject(
                  targetPath,
                  targets[ordinal].type,
                  ordinal,
                );
              }
            },
            commandRunner: successfulSigningRunner(calls, lease),
          })),
          /held build object changed/u,
        );
        assert.equal(calls.length, attackOrdinal);
      } finally {
        await closePrivateA28BuildWorkspace(lease);
      }
    });
  }
});

test('replacement during each pathname-only signing call stops all later calls', async (context) => {
  const targetTypes = ['directory', 'directory', 'file', 'file'];
  for (let attackOrdinal = 0; attackOrdinal < targetTypes.length; attackOrdinal += 1) {
    await context.test(`signing call ${attackOrdinal + 1}`, async () => {
      const lease = await createPrivateA28BuildWorkspace();
      const calls = [];
      const recordCall = successfulSigningRunner(calls, lease);
      try {
        await populateSigningFixture(lease.buildRootPath);
        await assert.rejects(
          signPrivateA28WorkspaceCopies(signingFixtureArguments(lease, {
            commandRunner: async (path, arguments_, options) => {
              const result = recordCall(path, arguments_, options);
              const ordinal = calls.length - 1;
              if (ordinal === attackOrdinal) {
                await replaceSigningObject(
                  resolve(lease.workspacePath, arguments_[5]),
                  targetTypes[ordinal],
                  10 + ordinal,
                );
              }
              return result;
            },
          })),
          /held build object changed/u,
        );
        assert.equal(calls.length, attackOrdinal + 1);
      } finally {
        await closePrivateA28BuildWorkspace(lease);
      }
    });
  }
});

test('replacement of held entitlements is rejected at every signing boundary', async (context) => {
  for (let attackOrdinal = 0; attackOrdinal < 4; attackOrdinal += 1) {
    await context.test(`signing call ${attackOrdinal + 1}`, async () => {
      const lease = await createPrivateA28BuildWorkspace();
      const calls = [];
      try {
        await populateSigningFixture(lease.buildRootPath);
        const entitlements = resolve(
          lease.buildRootPath,
          'source/A28Witness.entitlements',
        );
        await assert.rejects(
          signPrivateA28WorkspaceCopies(signingFixtureArguments(lease, {
            beforeSigningCommand: async ({ ordinal }) => {
              if (ordinal !== attackOrdinal) return;
              await rename(
                entitlements,
                resolve(
                  dirname(entitlements),
                  `displaced-${ordinal}-A28Witness.entitlements`,
                ),
              );
              await writeFile(entitlements, '<attacker/>', {
                flag: 'wx',
                mode: 0o400,
              });
            },
            commandRunner: successfulSigningRunner(calls, lease),
          })),
          /held build object changed/u,
        );
        assert.equal(calls.length, attackOrdinal);
      } finally {
        await closePrivateA28BuildWorkspace(lease);
      }
    });
  }
});

test('entitlements mutation during each signing call stops all later calls', async (context) => {
  for (let attackOrdinal = 0; attackOrdinal < 4; attackOrdinal += 1) {
    await context.test(`signing call ${attackOrdinal + 1}`, async () => {
      const lease = await createPrivateA28BuildWorkspace();
      const calls = [];
      const recordCall = successfulSigningRunner(calls, lease);
      try {
        await populateSigningFixture(lease.buildRootPath);
        const entitlements = resolve(
          lease.buildRootPath,
          'source/A28Witness.entitlements',
        );
        await assert.rejects(
          signPrivateA28WorkspaceCopies(signingFixtureArguments(lease, {
            commandRunner: async (path, arguments_, options) => {
              const result = recordCall(path, arguments_, options);
              const ordinal = calls.length - 1;
              if (ordinal === attackOrdinal) {
                await rename(
                  entitlements,
                  resolve(
                    dirname(entitlements),
                    `during-${ordinal}-A28Witness.entitlements`,
                  ),
                );
                await writeFile(entitlements, '<during-attacker/>', {
                  flag: 'wx',
                  mode: 0o400,
                });
              }
              return result;
            },
          })),
          /held build object changed/u,
        );
        assert.equal(calls.length, attackOrdinal + 1);
      } finally {
        await closePrivateA28BuildWorkspace(lease);
      }
    });
  }
});

test('output leaf and ancestor replacement cannot reach signing', async (context) => {
  for (const attack of ['leaf', 'parent', 'ancestor']) {
    await context.test(attack, async () => {
      const fixture = await createPublicationFixture(
        'piui-a28-output-lease-attack-',
      );
      const calls = [];
      try {
        await populateSigningFixture(fixture.workspaceLease.buildRootPath);
        await assert.rejects(
          signPrivateA28WorkspaceCopies(signingFixtureArguments(
            fixture.workspaceLease,
            {
              beforeSigningCommand: async ({ ordinal }) => {
                if (ordinal !== 0) return;
                if (attack === 'leaf') {
                  await mkdir(fixture.requestedRoot, { mode: 0o700 });
                  return;
                }
                if (attack === 'parent') {
                  await rename(
                    fixture.outputParent,
                    resolve(fixture.fixtureRoot, 'displaced-output-parent'),
                  );
                  await mkdir(fixture.outputParent, { mode: 0o700 });
                  return;
                }
                const displacedRoot = resolve(
                  dirname(fixture.fixtureRoot),
                  'displaced-' + basename(fixture.fixtureRoot),
                );
                await rename(fixture.fixtureRoot, displacedRoot);
                await mkdir(fixture.fixtureRoot, { mode: 0o700 });
                await mkdir(fixture.outputParent, { mode: 0o700 });
              },
              commandRunner: successfulSigningRunner(
                calls,
                fixture.workspaceLease,
              ),
            },
          )),
        );
        assert.equal(calls.length, 0);
      } finally {
        await closePublicationFixture(fixture);
      }
    });
  }
});

test('post-verification source mutation cannot be published', async () => {
  const fixture = await createPublicationFixture(
    'piui-a28-pre-publication-attack-',
  );
  let snapshot;
  let publicationCalls = 0;
  try {
    await populateSigningFixture(fixture.workspaceLease.buildRootPath);
    snapshot = await captureHeldA28BuildSnapshot(fixture.workspaceLease);
    const source = resolve(
      fixture.workspaceLease.buildRootPath,
      'a28-root-launcher',
    );
    await assert.rejects(
      publishHeldA28Build({
        beforePublication: async () => {
          await replaceSigningObject(source, 'file', 99);
        },
        commandRunner: () => {
          publicationCalls += 1;
          return Object.freeze({
            signal: null,
            status: 0,
            stderr: Buffer.alloc(0),
            stdout: Buffer.alloc(0),
          });
        },
        lease: fixture.workspaceLease,
        publicationLease: fixture.publicationLease,
        snapshot,
      }),
      /held build object changed/u,
    );
    assert.equal(publicationCalls, 0);
    await assert.rejects(lstat(fixture.requestedRoot), { code: 'ENOENT' });
  } finally {
    if (snapshot !== undefined) await closeHeldA28BuildSnapshot(snapshot);
    await closePublicationFixture(fixture);
  }
});

test('pre-snapshot source and inspector replacement cannot become authorised', async (context) => {
  for (const attack of ['none', 'source', 'inspector']) {
    await context.test(attack, async () => {
      const lease = await createPrivateA28BuildWorkspace();
      let snapshot;
      try {
        await populateSigningFixture(lease.buildRootPath);
        const inspector = resolve(lease.buildRootPath, 'a28-process-identity');
        const trustedInspector = Buffer.from('trusted-inspector', 'utf8');
        const trustedEntitlements = Buffer.from('<plist/>', 'utf8');
        await writeFile(inspector, trustedInspector, { flag: 'wx', mode: 0o500 });
        if (attack === 'source') {
          const entitlements = resolve(
            lease.buildRootPath,
            'source/A28Witness.entitlements',
          );
          await rename(
            entitlements,
            resolve(dirname(entitlements), 'pre-snapshot-entitlements'),
          );
          await writeFile(entitlements, '<pre-snapshot-attacker/>', {
            flag: 'wx',
            mode: 0o400,
          });
        } else if (attack === 'inspector') {
          await replaceSigningObject(inspector, 'file', 77);
        }
        const authorisedSourceRecords = canonicalA28Json([
          Object.freeze({
            mode: 0o400,
            path: 'A28Witness.entitlements',
            sha256: sha256A28(trustedEntitlements),
            size: trustedEntitlements.length,
            type: 'file',
          }),
        ]);
        snapshot = await captureHeldA28BuildSnapshot(lease);
        const assertion = assertHeldA28BuildInputBindings({
          authorisedSourceRecords,
          processInspectorSha256: sha256A28(trustedInspector),
          snapshot,
        });
        if (attack === 'none') {
          await assertion;
        } else {
          await assert.rejects(
            assertion,
            /held build inputs differ from their authorised bytes/u,
          );
        }
      } finally {
        if (snapshot !== undefined) await closeHeldA28BuildSnapshot(snapshot);
        await closePrivateA28BuildWorkspace(lease);
      }
    });
  }
});

test('matching pre-snapshot additions to both apps remain unauthorised', async (context) => {
  for (const attack of [
    'none',
    'matching-extra-resources',
    'matching-signature-extras',
  ]) {
    await context.test(attack, async () => {
      const lease = await createPrivateA28BuildWorkspace();
      let snapshot;
      try {
        await populateSigningFixture(lease.buildRootPath);
        for (const name of [
          'PIUI A28 VoiceOver Witness.app',
          'PIUI A28 VoiceOver Witness reproduction.app',
        ]) {
          const contentsDirectory = resolve(lease.buildRootPath, name, 'Contents');
          await mkdir(contentsDirectory, { mode: 0o700 });
          const signatureDirectory = resolve(
            contentsDirectory,
            '_CodeSignature',
          );
          await mkdir(signatureDirectory, { mode: 0o755 });
          await writeFile(resolve(signatureDirectory, 'CodeResources'), 'seal', {
            flag: 'wx',
            mode: 0o644,
          });
          if (attack === 'matching-extra-resources') {
            await writeFile(
              resolve(lease.buildRootPath, name, 'matching-attacker-resource'),
              'attacker',
              { flag: 'wx', mode: 0o400 },
            );
          } else if (attack === 'matching-signature-extras') {
            await writeFile(
              resolve(signatureDirectory, 'attacker'),
              'attacker',
              { flag: 'wx', mode: 0o400 },
            );
          }
        }
        snapshot = await captureHeldA28BuildSnapshot(lease);
        const assertion = assertHeldA28ApplicationResources({
          authorisedApplicationResources: canonicalA28Json([
            Object.freeze({
              mode: 0o700,
              path: 'Contents',
              type: 'directory',
            }),
          ]),
          snapshot,
        });
        if (attack === 'none') {
          await assertion;
        } else {
          await assert.rejects(
            assertion,
            /signed application resources differ|generated signature membership/u,
          );
        }
      } finally {
        if (snapshot !== undefined) await closeHeldA28BuildSnapshot(snapshot);
        await closePrivateA28BuildWorkspace(lease);
      }
    });
  }
});

test('required published modes are rebound after signing', async (context) => {
  const attacks = [
    undefined,
    ['source', 0o500],
    ['PIUI A28 VoiceOver Witness.app', 0o500],
    ['PIUI A28 VoiceOver Witness.app/Contents/MacOS/A28Witness', 0o400],
    ['a28-process-identity', 0o400],
    ['a28-root-launcher-reproduction', 0o400],
  ];
  for (const attack of attacks) {
    await context.test(attack?.[0] ?? 'valid modes', async () => {
      const lease = await createPrivateA28BuildWorkspace();
      let snapshot;
      try {
        await populateModeFixture(lease.buildRootPath);
        if (attack !== undefined) {
          await chmod(resolve(lease.buildRootPath, attack[0]), attack[1]);
        }
        snapshot = await captureHeldA28BuildSnapshot(lease);
        const assertion = assertHeldA28BuildModes(snapshot);
        if (attack === undefined) {
          await assertion;
        } else {
          await assert.rejects(
            assertion,
            /held build mode differs from the required mode/u,
          );
        }
      } finally {
        if (snapshot !== undefined) await closeHeldA28BuildSnapshot(snapshot);
        await closePrivateA28BuildWorkspace(lease);
      }
    });
  }
});

test('held build snapshots reject unapproved Darwin metadata', async (context) => {
  for (const attack of [
    'extended-acl',
    'extended-attribute',
    'bsd-flags',
    'special-mode-bits',
  ]) {
    await context.test(attack, async () => {
      const lease = await createPrivateA28BuildWorkspace();
      try {
        await populateModeFixture(lease.buildRootPath);
        const launcher = resolve(lease.buildRootPath, 'a28-root-launcher');
        if (attack === 'extended-acl') {
          const result = spawnSync('/bin/chmod', [
            '+a',
            'everyone deny delete',
            resolve(lease.buildRootPath, 'source'),
          ], {
            encoding: 'utf8',
            env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
            timeout: 10_000,
          });
          assert.equal(result.status, 0, result.stderr);
        } else if (attack === 'extended-attribute') {
          const result = spawnSync('/usr/bin/xattr', [
            '-w',
            'com.piui.a28-hostile',
            'unverified',
            resolve(lease.buildRootPath, 'source'),
          ], {
            encoding: 'utf8',
            env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
            timeout: 10_000,
          });
          assert.equal(result.status, 0, result.stderr);
        } else if (attack === 'bsd-flags') {
          const result = spawnSync('/usr/bin/chflags', ['hidden', launcher], {
            encoding: 'utf8',
            env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
            timeout: 10_000,
          });
          assert.equal(result.status, 0, result.stderr);
        } else {
          await chmod(launcher, 0o4500);
        }
        await assert.rejects(
          captureHeldA28BuildSnapshot(lease),
          /held build metadata|witness build (?:command failed|rejected)/u,
        );
      } finally {
        await closePrivateA28BuildWorkspace(lease);
      }
    });
  }
});

test('post-verification extra bytes cannot be published', async () => {
  const fixture = await createPublicationFixture(
    'piui-a28-pre-publication-extra-',
  );
  let snapshot;
  let publicationCalls = 0;
  try {
    await populateSigningFixture(fixture.workspaceLease.buildRootPath);
    snapshot = await captureHeldA28BuildSnapshot(fixture.workspaceLease);
    await assert.rejects(
      publishHeldA28Build({
        beforePublication: async () => {
          await writeFile(
            resolve(fixture.workspaceLease.buildRootPath, 'unverified-extra'),
            'unverified',
            { flag: 'wx', mode: 0o400 },
          );
        },
        commandRunner: () => {
          publicationCalls += 1;
          return Object.freeze({
            signal: null,
            status: 0,
            stderr: Buffer.alloc(0),
            stdout: Buffer.alloc(0),
          });
        },
        lease: fixture.workspaceLease,
        publicationLease: fixture.publicationLease,
        snapshot,
      }),
    );
    assert.equal(publicationCalls, 0);
    await assert.rejects(lstat(fixture.requestedRoot), { code: 'ENOENT' });
  } finally {
    if (snapshot !== undefined) await closeHeldA28BuildSnapshot(snapshot);
    await closePublicationFixture(fixture);
  }
});

test('post-verification extended metadata cannot be published', async () => {
  const fixture = await createPublicationFixture(
    'piui-a28-pre-publication-metadata-',
  );
  let snapshot;
  let publicationCalls = 0;
  try {
    await populateSigningFixture(fixture.workspaceLease.buildRootPath);
    snapshot = await captureHeldA28BuildSnapshot(fixture.workspaceLease);
    await assert.rejects(
      publishHeldA28Build({
        beforePublication: async () => {
          const result = spawnSync('/usr/bin/xattr', [
            '-w',
            'com.piui.a28-hostile',
            'unverified',
            resolve(fixture.workspaceLease.buildRootPath, 'source'),
          ], {
            encoding: 'utf8',
            env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
            timeout: 10_000,
          });
          assert.equal(result.status, 0, result.stderr);
        },
        commandRunner: () => {
          publicationCalls += 1;
          return Object.freeze({
            signal: null,
            status: 0,
            stderr: Buffer.alloc(0),
            stdout: Buffer.alloc(0),
          });
        },
        lease: fixture.workspaceLease,
        publicationLease: fixture.publicationLease,
        snapshot,
      }),
      /held build object changed|held build metadata/u,
    );
    assert.equal(publicationCalls, 0);
    await assert.rejects(lstat(fixture.requestedRoot), { code: 'ENOENT' });
  } finally {
    if (snapshot !== undefined) await closeHeldA28BuildSnapshot(snapshot);
    await closePublicationFixture(fixture);
  }
});

test('output leaf and ancestors remain leased at publication', async (context) => {
  for (const attack of ['leaf', 'parent', 'ancestor']) {
    await context.test(attack, async () => {
      const fixture = await createPublicationFixture(
        'piui-a28-publication-output-attack-',
      );
      let snapshot;
      let publicationCalls = 0;
      try {
        await populateSigningFixture(fixture.workspaceLease.buildRootPath);
        snapshot = await captureHeldA28BuildSnapshot(fixture.workspaceLease);
        await assert.rejects(publishHeldA28Build({
          beforePublication: async () => {
            if (attack === 'leaf') {
              await mkdir(fixture.requestedRoot, { mode: 0o700 });
              return;
            }
            if (attack === 'parent') {
              await rename(
                fixture.outputParent,
                resolve(fixture.fixtureRoot, 'publication-displaced-parent'),
              );
              await mkdir(fixture.outputParent, { mode: 0o700 });
              return;
            }
            const displacedRoot = resolve(
              dirname(fixture.fixtureRoot),
              'publication-displaced-' + basename(fixture.fixtureRoot),
            );
            await rename(fixture.fixtureRoot, displacedRoot);
            await mkdir(fixture.fixtureRoot, { mode: 0o700 });
            await mkdir(fixture.outputParent, { mode: 0o700 });
          },
          commandRunner: () => {
            publicationCalls += 1;
            return Object.freeze({
              signal: null,
              status: 0,
              stderr: Buffer.alloc(0),
              stdout: Buffer.alloc(0),
            });
          },
          lease: fixture.workspaceLease,
          publicationLease: fixture.publicationLease,
          snapshot,
        }));
        assert.equal(publicationCalls, 0);
      } finally {
        if (snapshot !== undefined) await closeHeldA28BuildSnapshot(snapshot);
        await closePublicationFixture(fixture);
      }
    });
  }
});

test('publication atomically moves the exact held build inode', async () => {
  const fixture = await createPublicationFixture('piui-a28-publication-');
  let snapshot;
  try {
    await populateSigningFixture(fixture.workspaceLease.buildRootPath);
    snapshot = await captureHeldA28BuildSnapshot(fixture.workspaceLease);
    const before = await lstat(fixture.workspaceLease.buildRootPath);
    await publishHeldA28Build({
      lease: fixture.workspaceLease,
      publicationLease: fixture.publicationLease,
      snapshot,
    });
    const after = await lstat(fixture.requestedRoot);
    assert.equal(after.dev, before.dev);
    assert.equal(after.ino, before.ino);
    assert.equal(
      await readFile(resolve(fixture.requestedRoot, 'a28-root-launcher'), 'utf8'),
      'first',
    );
    await assert.rejects(
      lstat(fixture.workspaceLease.buildRootPath),
      { code: 'ENOENT' },
    );
  } finally {
    if (snapshot !== undefined) await closeHeldA28BuildSnapshot(snapshot);
    await closePublicationFixture(fixture);
  }
});

test('private workspace leaf and parent replacements fail before codesign', async (context) => {
  for (const target of ['workspace', 'builder-parent']) {
    await context.test(target, async () => {
      const lease = await createPrivateA28BuildWorkspace();
      await populateSigningFixture(lease.buildRootPath);
      let signingCalls = 0;
      try {
        await assert.rejects(
          signPrivateA28WorkspaceCopies(signingFixtureArguments(lease, {
            beforeSigningCommand: async ({ ordinal }) => {
              if (ordinal !== 0) return;
              if (target === 'workspace') {
                const displacedWorkspace = resolve(
                  lease.builderParentPath,
                  'displaced-' + basename(lease.workspacePath),
                );
                await rename(lease.workspacePath, displacedWorkspace);
                await mkdir(lease.workspacePath, { mode: 0o700 });
              } else {
                const displacedBuilderParent = resolve(
                  dirname(lease.builderParentPath),
                  'displaced-' + basename(lease.builderParentPath),
                );
                await rename(lease.builderParentPath, displacedBuilderParent);
                await mkdir(lease.builderParentPath, { mode: 0o700 });
                await mkdir(lease.workspacePath, { mode: 0o700 });
              }
              await mkdir(lease.buildRootPath, { mode: 0o700 });
              await populateSigningFixture(lease.buildRootPath);
            },
            commandRunner: () => {
              signingCalls += 1;
              return Object.freeze({
                signal: null,
                status: 0,
                stderr: Buffer.alloc(0),
                stdout: Buffer.alloc(0),
              });
            },
          })),
          (error) => {
            assert.match(
              error.message,
              /private build workspace lease changed|held build object changed|pre-sign inputs differ/u,
            );
            return true;
          },
        );
        assert.equal(signingCalls, 0);
      } finally {
        await closePrivateA28BuildWorkspace(lease);
      }
    });
  }
});

test('root registrar and checkpoint authority hold the full ceremony boundary', async () => {
  const [registrar, checkpoint, verifier, contract] = await Promise.all([
    source('register-enrolment.mjs'),
    source('checkpoint-authority.mjs'),
    source('verify.mjs'),
    source('contract.mjs'),
  ]);
  for (const requirement of [
    "process.getuid() !== 0",
    'constants.O_EXCL',
    'constants.O_NOFOLLOW',
    "stdio: ['pipe', 'pipe', 'pipe', candidateHandle.fd]",
    "readProtocolLine(iterator, protocol, 'READY')",
    "child.stdin.write('G\\n')",
    "readProtocolLine(iterator, protocol, 'SIGNED')",
    "child.stdin.end('A\\n')",
    'applicationIdentityBefore',
    'applicationIdentityAfter',
    '[working] Waiting for the witness app',
  ]) assert.ok(registrar.includes(requirement), requirement);
  for (const requirement of [
    'MAX_AUTHORITY_DIRECTORY_ENTRIES',
    'a28ChallengeRequestSha256(requestFile.value)',
    "'request-sha256-' + challengeRequestSha256 + '.consumed.json'",
    'createAttestationSlot',
    'constants.O_CREAT',
    'await handle.chown(policy.witnessUid, policy.witnessGid)',
    'await handle.chmod(0o200)',
    'challengeRequestSha256',
    'A28_GATE_CONTEXT_AUTHORITY',
    'a28CheckpointCommitmentSha256',
    "challenge.checkpointSessionId + '.consumed.json'",
    'A28_HUMAN_ASSERTION_SCOPE',
    'runnerAuthority: \'continuity-only\'',
  ]) assert.ok(checkpoint.includes(requirement), requirement);
  for (const requirement of [
    'attestationPath !== challenge.attestationSlot.path',
    'attestationFile.identity.dev !== challenge.attestationSlot.dev',
    'attestationOutputIdentity: attestationFile.identity',
    'publishedReceiptPath',
    'publishedReceiptSha256',
  ]) assert.ok(verifier.includes(requirement), requirement);
  for (const requirement of [
    'PIUI-A28-CHALLENGE-REQUEST\\0v1\\0',
    'gateContextComparisonRequired',
    'excludes-run-source-artifact-fingerprint-authentication',
    'parseA28CheckpointAuthorityArguments',
  ]) assert.ok(contract.includes(requirement), requirement);
  assert.doesNotMatch(
    registrar + checkpoint + verifier,
    /unlink\s*\(|rmSync|removeItemAtPath|shell:\s*true|execSync/u,
  );
});

test('provisioning assets are valid, concise and contain no junk probe', async () => {
  const files = await readdir(witnessRoot);
  assert.equal(files.includes('.patch-probe'), false);
  assert.ok(files.includes('README.md'));
  const readme = await source('README.md');
  assert.doesNotMatch(readme, /\p{Extended_Pictographic}/u);
  assert.match(readme, /real reviewer has exercised VoiceOver/u);
  assert.match(readme, /Automated accessibility-tree output is supplementary/u);
  for (const plist of ['Info.plist', 'A28Witness.entitlements.in']) {
    const result = spawnSync('/usr/bin/plutil', [
      '-lint',
      resolve(witnessRoot, plist),
    ], {
      encoding: 'utf8',
      env: { PATH: '/usr/bin:/bin' },
    });
    assert.equal(result.status, 0, result.stderr);
  }
});
