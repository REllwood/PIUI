import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmod,
  copyFile,
  lstat,
  mkdtemp,
  mkdir,
  readFile,
  realpath,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import { platform, tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  a28AccessibilityHelperSandbox,
} from '../../scripts/run-packaged-accessibility-probe.mjs';
import {
  a27ReopenHelperSandbox,
} from '../../scripts/run-packaged-lifecycle-probe.mjs';
import {
  assertPrivateExecutableLease,
  capturePrivateExecutable,
} from '../../scripts/private-executable-lease.mjs';
import {
  captureCredentialCleanupHarness,
  credentialCleanupSandbox,
} from '../../scripts/run-packaged-credential-probe.mjs';
import {
  canaryScannerSandbox,
} from '../../scripts/scan-secret-canary.mjs';
import {
  APPLE_TOOLCHAIN_PATHS,
  appleToolchainBuildEnvironment,
  captureAppleToolchainAuthority,
  releaseAppleToolchainAuthority,
  revalidateAppleToolchainAuthority,
} from '../../scripts/apple-toolchain-trust.mjs';

async function fixture(t, prefix) {
  const requested = await mkdtemp(resolve(tmpdir(), prefix));
  await chmod(requested, 0o700);
  const root = await realpath(requested);
  t.after(async () => {
    try {
      await chmod(resolve(root, 'control'), 0o700);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    await rm(root, { recursive: true, force: true });
  });
  return root;
}

test('held private executable lease survives source replacement and rejects control replacement', async (t) => {
  const root = await fixture(t, 'piui-private-executable-');
  const source = resolve(root, 'build-helper');
  const sourceBytes = Buffer.concat([
    Buffer.from('#!/bin/sh\nexit 0\n', 'utf8'),
    Buffer.alloc(4_096, 0x20),
  ]);
  await writeFile(source, sourceBytes, { flag: 'wx', mode: 0o500 });
  const lease = await capturePrivateExecutable({
    controlRoot: resolve(root, 'control'),
    executableName: 'held-helper',
    sourcePath: source,
  });
  assert.equal(await assertPrivateExecutableLease(lease), true);
  assert.equal((await lstat(lease.path)).mode & 0o777, 0o500);
  assert.equal((await lstat(lease.controlRoot.path)).mode & 0o777, 0o500);

  const sourceReplacement = resolve(root, 'source-replacement');
  await writeFile(sourceReplacement, Buffer.alloc(sourceBytes.length, 0x41), {
    flag: 'wx',
    mode: 0o500,
  });
  await rename(sourceReplacement, source);
  assert.equal(await assertPrivateExecutableLease(lease), true);

  await chmod(lease.controlRoot.path, 0o700);
  const controlReplacement = resolve(lease.controlRoot.path, 'replacement');
  await copyFile(lease.path, controlReplacement);
  await chmod(controlReplacement, 0o500);
  await rename(controlReplacement, lease.path);
  await chmod(lease.controlRoot.path, 0o500);
  await assert.rejects(
    assertPrivateExecutableLease(lease),
    /Private executable lease rejected/u,
  );
});

test('private helper sandboxes grant only their named broker authority', {
  skip: platform() !== 'darwin',
}, async (t) => {
  const root = await fixture(t, 'piui-private-helper-sandbox-');
  const helper = resolve(root, 'authority-probe');
  const authority = captureAppleToolchainAuthority();
  let compilation;
  try {
    compilation = spawnSync(APPLE_TOOLCHAIN_PATHS.clang, [
      '--no-default-config',
      '-std=c17',
      '-Wall',
      '-Wextra',
      '-Werror',
      '-isysroot',
      APPLE_TOOLCHAIN_PATHS.sdk,
      '-x',
      'c',
      '-',
      '-o',
      helper,
    ], {
      encoding: 'utf8',
      env: {
        ...appleToolchainBuildEnvironment(),
        LANG: 'C',
        LC_ALL: 'C',
        PATH: `${APPLE_TOOLCHAIN_PATHS.bin}:/usr/bin:/bin`,
      },
      input: String.raw`
#include <stdio.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

extern int sandbox_check(pid_t pid, const char *operation, int type, ...);

int main(int argc, char **argv) {
  const pid_t pid = getpid();
  const char *allowed_file = argc == 2 ? argv[1] : "/etc/hosts";
  pid_t child = 0;
  char *const arguments[] = { "/usr/bin/true", NULL };
  const int spawn_status = posix_spawn(&child, "/usr/bin/true", NULL, NULL, arguments, environ);
  if (spawn_status == 0) {
    int child_status = 0;
    (void)waitpid(child, &child_status, 0);
  }
  printf(
    "{\"allowedFile\":%d,\"appleEvent\":%d,\"ax\":%d,\"credential\":%d,\"file\":%d,\"fork\":%d,"
    "\"network\":%d,\"otherMach\":%d,\"processExec\":%d}\n",
    sandbox_check(pid, "file-read-data", 1, allowed_file),
    sandbox_check(pid, "appleevent-send", 0),
    sandbox_check(pid, "mach-lookup", 2, "com.apple.axserver"),
    sandbox_check(pid, "mach-lookup", 2, "com.apple.securityd.xpc"),
    sandbox_check(pid, "file-read-data", 1, "/etc/hosts"),
    sandbox_check(pid, "process-fork", 0),
    sandbox_check(pid, "network-outbound", 0),
    sandbox_check(pid, "mach-lookup", 2, "com.apple.notificationcenterui.agent"),
    spawn_status == 0 ? 0 : 1
  );
  return 0;
}
`,
      timeout: 30_000,
    });
    revalidateAppleToolchainAuthority(authority);
  } finally {
    releaseAppleToolchainAuthority(authority);
  }
  assert.equal(compilation.status, 0, compilation.stderr);
  assert.equal(compilation.stdout, '');
  assert.equal(compilation.stderr, '');
  await chmod(helper, 0o500);
  const scanWorkspace = resolve(root, 'scan-workspace');
  const scanRoot = resolve(scanWorkspace, 'scan-root');
  const scanFile = resolve(scanRoot, 'capture.bin');
  await mkdir(scanRoot, { recursive: true, mode: 0o700 });
  await writeFile(scanFile, 'safe', { flag: 'wx', mode: 0o600 });

  const definitions = [
    {
      expected: { appleEvent: 1, ax: 1, credential: 0 },
      profile: credentialCleanupSandbox(helper),
    },
    {
      expected: { appleEvent: 0, ax: 1, credential: 1 },
      profile: a27ReopenHelperSandbox(helper),
    },
    {
      expected: { appleEvent: 1, ax: 0, credential: 1 },
      profile: a28AccessibilityHelperSandbox(helper),
    },
    {
      arguments: [scanFile],
      expected: { appleEvent: 1, ax: 1, credential: 1 },
      profile: canaryScannerSandbox(helper, scanWorkspace, [scanRoot]),
    },
  ];
  for (const { arguments: helperArguments = [], expected, profile } of definitions) {
    assert.match(profile, /\(deny default\)/u);
    assert.match(profile, /\(deny network\*\)/u);
    assert.doesNotMatch(profile, /\(allow (?:file-write|network|process-fork)/u);
    const result = spawnSync('/usr/bin/sandbox-exec', [
      '-p',
      profile,
      helper,
      ...helperArguments,
    ], {
      cwd: root,
      encoding: 'utf8',
      env: { PATH: '/usr/bin:/bin' },
      timeout: 5_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '');
    const observed = JSON.parse(result.stdout);
    assert.deepEqual({
      appleEvent: observed.appleEvent,
      ax: observed.ax,
      credential: observed.credential,
    }, expected);
    assert.equal(observed.allowedFile, helperArguments.length === 1 ? 0 : 1);
    assert.equal(observed.file, 1);
    assert.equal(observed.fork, 1);
    assert.equal(observed.network, 1);
    assert.equal(observed.otherMach, 1);
    assert.equal(observed.processExec, 1);
  }
  assert.equal((await readFile(helper)).length > 0, true);
});

test('credential cleanup sandbox can perform a non-mutating Keychain lookup', {
  skip: platform() !== 'darwin',
}, async (t) => {
  const root = await fixture(t, 'piui-credential-keychain-sandbox-');
  const helper = resolve(root, 'keychain-lookup-probe');
  const authority = captureAppleToolchainAuthority();
  let compilation;
  try {
    compilation = spawnSync(APPLE_TOOLCHAIN_PATHS.clang, [
      '--no-default-config',
      '-std=c17',
      '-Wall',
      '-Wextra',
      '-Werror',
      '-Wno-deprecated-declarations',
      '-isysroot',
      APPLE_TOOLCHAIN_PATHS.sdk,
      '-framework',
      'CoreFoundation',
      '-framework',
      'Security',
      '-x',
      'c',
      '-',
      '-o',
      helper,
    ], {
      encoding: 'utf8',
      env: {
        ...appleToolchainBuildEnvironment(),
        LANG: 'C',
        LC_ALL: 'C',
        PATH: `${APPLE_TOOLCHAIN_PATHS.bin}:/usr/bin:/bin`,
      },
      input: String.raw`
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 3) return 64;
  if (sysconf(_SC_PAGESIZE) <= 0) return 67;
  SecKeychainRef keychain = NULL;
  OSStatus status = SecKeychainCopyDomainDefault(kSecPreferencesDomainUser, &keychain);
  if (status != errSecSuccess || keychain == NULL) {
    printf("%d\n", (int)status);
    return 65;
  }
  UInt32 password_length = 0;
  void *password_data = NULL;
  SecKeychainItemRef item = NULL;
  status = SecKeychainFindGenericPassword(
    keychain,
    (UInt32)strlen(argv[1]),
    argv[1],
    (UInt32)strlen(argv[2]),
    argv[2],
    &password_length,
    &password_data,
    &item
  );
  if (password_data != NULL) SecKeychainItemFreeContent(NULL, password_data);
  if (item != NULL) CFRelease(item);
  CFRelease(keychain);
  printf("%d\n", (int)status);
  return status == errSecItemNotFound ? 0 : 66;
}
`,
      timeout: 30_000,
    });
    revalidateAppleToolchainAuthority(authority);
  } finally {
    releaseAppleToolchainAuthority(authority);
  }
  assert.equal(compilation.status, 0, compilation.stderr);
  assert.equal(compilation.stdout, '');
  assert.equal(compilation.stderr, '');
  await chmod(helper, 0o500);

  const service = `au.com.piui.desktop.credential-index.test.profile-${process.pid}-${Date.now()}`;
  const baseline = spawnSync(helper, [service, 'provider-index-v1'], {
    cwd: root,
    encoding: 'utf8',
    env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
    timeout: 30_000,
  });
  assert.equal(baseline.status, 0, JSON.stringify({
    signal: baseline.signal,
    stderr: baseline.stderr,
    stdout: baseline.stdout,
  }));
  assert.equal(baseline.signal, null);
  assert.equal(baseline.stderr, '');
  assert.equal(baseline.stdout, '-25300\n');

  const capturedHelper = await capturePrivateExecutable({
    controlRoot: resolve(root, 'control'),
    executableName: 'keychain-lookup-probe',
    sourcePath: helper,
  });
  assert.equal(await assertPrivateExecutableLease(capturedHelper), true);
  const profile = credentialCleanupSandbox(capturedHelper.path);
  assert.match(
    profile,
    /\(allow sysctl-read\s+\(sysctl-name "hw\.pagesize_compat"\)\s+\(sysctl-name "security\.mac\.sandbox\.sentinel"\)\)/u,
  );
  assert.doesNotMatch(profile, /\(allow sysctl-read\)\s/u);
  assert.match(profile, /com\.apple\.system\.opendirectoryd\.libinfo/u);
  assert.match(profile, /Library\/Keychains\/login\.keychain-db/u);
  const result = spawnSync('/usr/bin/sandbox-exec', [
    '-p',
    profile,
    capturedHelper.path,
    service,
    'provider-index-v1',
  ], {
    cwd: root,
    encoding: 'utf8',
    env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
    timeout: 30_000,
  });
  assert.equal(result.status, 0, JSON.stringify({
    signal: result.signal,
    stderr: result.stderr,
    stdout: result.stdout,
  }));
  assert.equal(result.signal, null);
  assert.equal(result.stderr, '');
  assert.equal(result.stdout, '-25300\n');
  assert.equal(await assertPrivateExecutableLease(capturedHelper), true);
});

test('captured credential cleanup harness can clear a fresh namespace in its sandbox', {
  skip: platform() !== 'darwin',
}, async (t) => {
  const projectRoot = resolve(import.meta.dirname, '../..');
  const source = resolve(
    projectRoot,
    'src-tauri/target/aarch64-apple-darwin/release/credential-cleanup-harness',
  );
  try {
    await lstat(source);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    t.skip('release credential cleanup harness is not built');
    return;
  }

  const root = await fixture(t, 'piui-captured-credential-cleanup-');
  const capturedHelper = await captureCredentialCleanupHarness(
    projectRoot,
    resolve(root, 'control'),
  );
  const namespace = `a23-${Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('hex')}`;
  const result = spawnSync('/usr/bin/sandbox-exec', [
    '-p',
    credentialCleanupSandbox(capturedHelper.path),
    capturedHelper.path,
  ], {
    cwd: '/',
    encoding: 'utf8',
    env: { LANG: 'en_AU.UTF-8', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' },
    input: `${namespace}\n`,
    timeout: 30_000,
  });
  assert.deepEqual({
    error: result.error?.code,
    signal: result.signal,
    status: result.status,
    stderr: result.stderr,
    stdout: result.stdout,
  }, {
    error: undefined,
    signal: null,
    status: 0,
    stderr: '',
    stdout: '{"schemaVersion":1,"cleanupSucceeded":true,"indexAbsent":true}\n',
  });
  assert.equal(await assertPrivateExecutableLease(capturedHelper), true);
});
