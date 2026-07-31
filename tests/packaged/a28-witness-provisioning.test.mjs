import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';

const root = resolve(import.meta.dirname, '../..');
const witnessRoot = resolve(root, 'scripts/a28-witness');

async function source(name) {
  return readFile(resolve(witnessRoot, name), 'utf8');
}

test('native witness and process inspector compile cleanly with Apple clang', () => {
  for (const definition of [
    {
      frameworks: ['AppKit', 'LocalAuthentication', 'Security'],
      source: 'A28WitnessApp.m',
    },
    {
      frameworks: ['Foundation', 'Security'],
      source: 'A28ProcessIdentity.m',
    },
  ]) {
    const arguments_ = [
      'clang',
      '-fobjc-arc',
      '-std=c17',
      '-Wall',
      '-Wextra',
      '-Werror',
    ];
    for (const framework of definition.frameworks) {
      arguments_.push('-framework', framework);
    }
    arguments_.push(
      resolve(witnessRoot, definition.source),
      '-o',
      '/dev/null',
    );
    const result = spawnSync('/usr/bin/xcrun', arguments_, {
      encoding: 'utf8',
      env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
      timeout: 30_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.signal, null);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, '');
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
    'authenticationContext.localizedReason',
    'VoiceOverIsRunning',
    'com.apple.VoiceOver',
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
    'O_EXCL',
    'O_NOFOLLOW',
    'WriteHeldCanonicalDescriptor',
    'pwrite(',
  ]) {
    assert.ok(native.includes(requirement), requirement);
  }
  assert.doesNotMatch(native, /kSecUseOperationPrompt/u);
  assert.doesNotMatch(native, /SecItemDelete|removeItemAtPath|unlink\s*\(/u);
  assert.doesNotMatch(native, /humanWitnessed/u);
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
    'O_NOFOLLOW',
    'before.st_dev != after.st_dev',
    'before.st_ino != after.st_ino',
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
    'witnessExecutable',
    'resultDirectoryPath',
  ]) {
    assert.ok(contract.includes(requirement), requirement);
  }
  for (const requirement of [
    'process.getuid() !== 0',
    'process.geteuid() !== 0',
    'process.execPath !== policy.rootVerifierNodePath',
    'process.execArgv.length !== 0',
    'fileURLToPath(import.meta.url) !== policy.rootVerifierEntrypointPath',
    "process.cwd() !== '/var/empty'",
    "process.env.PATH !== '/usr/bin:/bin'",
    "process.env.HOME !== '/var/root'",
    "name.startsWith('NODE_')",
    "name.startsWith('DYLD_')",
    'constants.O_EXCL',
    'constants.O_NOFOLLOW',
    'A.28 witness nonce was already consumed',
    'policy.resultDirectoryPath',
    '0o755',
    '0o444',
    "['--pid', String(payload.witnessApplicationPid)]",
    '/System/Library/CoreServices/VoiceOver.app/Contents/Info.plist',
    '(before.mode & 0o777) !== 0o555',
  ]) {
    assert.ok(verifier.includes(requirement), requirement);
  }
  assert.doesNotMatch(verifier, /Documents\/Code\/PIUI|process\.env\.NODE_PATH/u);
  assert.doesNotMatch(verifier, /sudo|execSync|shell:\s*true/u);
  assert.match(verifier, /from '\.\/contract\.mjs'/u);
  assert.equal(
    [...verifier.matchAll(/^import .* from '([^']+)'/gmu)]
      .every((match) => match[1].startsWith('node:')
        || match[1] === './contract.mjs'),
    true,
  );
});

test('build and enrolment fail closed and cannot claim a human witness', async () => {
  const [buildSource, enrolSource] = await Promise.all([
    source('build.mjs'),
    source('enrol.mjs'),
  ]);
  for (const buildRequirement of [
    'assertRootOwnedAppleTool',
    'validateProfile',
    'assertSigningIdentity',
    'policy.processInspectorSha256',
    "humanWitnessed: false",
    "rootInstallationRequired: true",
  ]) {
    assert.ok(buildSource.includes(buildRequirement), buildRequirement);
  }
  for (const enrolRequirement of [
    'inspectPinnedA28WitnessApp',
    'assertAvailableSigningIdentity',
    'A28_POLICY_PIN_PATH',
    "humanWitnessed: false",
    'rootInstallationRequired: true',
    "'--output-fd'",
    'candidateHandle.fd',
  ]) {
    assert.ok(enrolSource.includes(enrolRequirement), enrolRequirement);
  }
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
