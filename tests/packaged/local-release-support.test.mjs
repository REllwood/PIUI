import assert from 'node:assert/strict';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import test from 'node:test';
import {
  localReleaseLaunchEnvironment,
  localReleasePaths,
  replaceDirectory,
} from '../../scripts/local-release-support.mjs';

test('local release output uses one fixed path per target', () => {
  const root = '/private/piui-checkout';
  const first = localReleasePaths(root);
  assert.deepEqual(localReleasePaths(root), first);
  assert.deepEqual(
    Object.fromEntries(Object.entries(first).map(([key, path]) => [key, relative(root, path)])),
    {
      appPath: 'src-tauri/target/aarch64-apple-darwin/release/bundle/macos/PIUI.app',
      evidencePath: '.build/evidence/release-local/release-evidence.json',
      evidenceRoot: '.build/evidence/release-local',
      previousAppPath: '.build/release-local-previous/PIUI.app',
      previousRoot: '.build/release-local-previous',
      runtimeRoot: '.build/release-local-runtime',
    },
  );
});

test('the smoke launch inherits only an allowlisted environment', () => {
  const launch = localReleaseLaunchEnvironment({
    ANTHROPIC_API_KEY: 'fixture-anthropic-key',
    AWS_SECRET_ACCESS_KEY: 'fixture',
    DYLD_INSERT_LIBRARIES: '/private/inject.dylib',
    GITHUB_TOKEN: 'fixture',
    HOME: '/Users/example',
    LANG: 'en_AU.UTF-8',
    NODE_OPTIONS: '--require /private/inject.js',
    OPENAI_API_KEY: 'fixture-openai-key',
    PATH: '/opt/untrusted/bin:/usr/bin',
    PIUI_AGENT_ROOT: '/Users/example/.pi/agent',
    TMPDIR: '/private/var/folders/xx/T/',
    USER: 'example',
  }, '/private/runtime');
  assert.deepEqual(launch, {
    HOME: '/Users/example',
    LANG: 'en_AU.UTF-8',
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    PIUI_AGENT_ROOT: '/private/runtime/agent',
    PIUI_SESSION_ROOT: '/private/runtime/sessions',
    TMPDIR: '/private/var/folders/xx/T/',
    USER: 'example',
    XDG_CACHE_HOME: '/private/runtime/cache',
    XDG_CONFIG_HOME: '/private/runtime/config',
    XDG_DATA_HOME: '/private/runtime/data',
  });
  assert.ok(Object.isFrozen(launch));
});

test('a fixed output directory is emptied in place, including read-only bundles', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'piui-local-release.')));
  t.after(async () => {
    await chmod(root, 0o700).catch(() => {});
    await rm(root, { force: true, recursive: true });
  });
  const outside = join(root, 'outside');
  await mkdir(outside, { mode: 0o700 });
  await writeFile(join(outside, 'kept.txt'), 'kept\n');

  const previous = join(root, '.build', 'release-local-previous');
  const bundle = join(previous, 'PIUI.app', 'Contents', 'Resources');
  await mkdir(bundle, { recursive: true });
  await writeFile(join(bundle, 'resource.txt'), 'old\n', { mode: 0o444 });
  await symlink(outside, join(previous, 'PIUI.app', 'Contents', 'link'));
  await chmod(bundle, 0o555);
  await chmod(join(previous, 'PIUI.app', 'Contents'), 0o555);

  await replaceDirectory(previous);
  assert.deepEqual(await readdir(previous), []);
  assert.equal((await lstat(previous)).mode & 0o777, 0o700);
  assert.deepEqual(await readdir(outside), ['kept.txt']);
  assert.equal((await lstat(outside)).mode & 0o777, 0o700);

  await replaceDirectory(previous);
  assert.deepEqual(await readdir(join(root, '.build')), ['release-local-previous']);

  const absent = join(root, '.build', 'evidence', 'release-local');
  await replaceDirectory(absent);
  assert.deepEqual(await readdir(absent), []);
});
