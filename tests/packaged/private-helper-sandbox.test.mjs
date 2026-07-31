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
  credentialCleanupSandbox,
} from '../../scripts/run-packaged-credential-probe.mjs';
import {
  canaryScannerSandbox,
} from '../../scripts/scan-secret-canary.mjs';

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
  const compilation = spawnSync('/usr/bin/clang', [
    '-std=c17',
    '-Wall',
    '-Wextra',
    '-Werror',
    '-x',
    'c',
    '-',
    '-o',
    helper,
  ], {
    encoding: 'utf8',
    env: { PATH: '/usr/bin:/bin' },
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
  });
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
