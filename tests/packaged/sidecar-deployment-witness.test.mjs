import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, constants, fchmodSync, openSync } from 'node:fs';
import {
  chmod,
  copyFile,
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import {
  assertSidecarDeploymentMatchesReceipt,
  captureSidecarDeploymentReceipt,
  readHeldSidecarDeploymentReceipt,
} from '../../scripts/sidecar-deployment-witness.mjs';

test('binds controlled sidecar finalisation to the exact post-install deployment', async (t) => {
  const root = await realpath(
    await mkdtemp(resolve(tmpdir(), 'piui-sidecar-deployment-witness.')),
  );
  t.after(async () => rm(root, { force: true, recursive: true }));
  await chmod(root, 0o700);
  const deployment = resolve(root, 'deployment');
  await mkdir(resolve(deployment, 'node_modules/example'), {
    recursive: true,
    mode: 0o700,
  });
  await mkdir(resolve(deployment, 'node_modules/example-native'), {
    recursive: true,
    mode: 0o700,
  });
  const packagePath = resolve(deployment, 'package.json');
  const bangPath = resolve(deployment, '!pre-dot.js');
  const dashPath = resolve(deployment, '-pre-dot.js');
  const modulePath = resolve(deployment, 'node_modules/example/index.js');
  const literalBackslashTargetName = 'target\\literal.js';
  const literalBackslashTargetPath = resolve(
    deployment,
    'node_modules/example',
    literalBackslashTargetName,
  );
  const literalBackslashLinkPath = resolve(
    deployment,
    'node_modules/example/target-link.js',
  );
  const interleavedSiblingPath = resolve(
    deployment,
    'node_modules/example-native/index.js',
  );
  await writeFile(packagePath, '{"private":true}\n', { flag: 'wx', mode: 0o400 });
  await writeFile(bangPath, 'export const bang = true;\n', { flag: 'wx', mode: 0o400 });
  await writeFile(dashPath, 'export const dash = true;\n', { flag: 'wx', mode: 0o400 });
  await writeFile(modulePath, 'export const value = 1;\n', { flag: 'wx', mode: 0o400 });
  await writeFile(literalBackslashTargetPath, 'export const target = true;\n', {
    flag: 'wx',
    mode: 0o400,
  });
  await symlink(literalBackslashTargetName, literalBackslashLinkPath);
  await writeFile(interleavedSiblingPath, 'export const native = true;\n', {
    flag: 'wx',
    mode: 0o400,
  });
  const receipt = await captureSidecarDeploymentReceipt(deployment);
  const receiptPath = resolve(root, 'receipt.json');
  await writeFile(receiptPath, receipt.bytes, { flag: 'wx', mode: 0o400 });
  const descriptor = openSync(receiptPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const held = readHeldSidecarDeploymentReceipt({
      descriptor,
      expectedRoot: deployment,
      receiptSha256: receipt.sha256,
    });
    assert.ok(held.bytes.equals(receipt.bytes));
    const heldPaths = held.value.entries.map((entry) => entry.path);
    assert.equal(heldPaths[0], '.');
    assert.deepEqual(heldPaths.slice(1), [...heldPaths.slice(1)].sort((left, right) => (
      Buffer.from(left).compare(Buffer.from(right))
    )));
    assert.deepEqual(heldPaths.slice(0, 3), ['.', '!pre-dot.js', '-pre-dot.js']);
    const literalBackslashLink = held.value.entries.find(
      (entry) => entry.path === 'node_modules/example/target-link.js',
    );
    assert.equal(literalBackslashLink?.kind, 'symlink');
    assert.equal(literalBackslashLink.link, literalBackslashTargetName);
    assert.equal(
      literalBackslashLink.target,
      `node_modules/example/${literalBackslashTargetName}`,
    );
    await assertSidecarDeploymentMatchesReceipt(deployment, held.bytes);

    await chmod(modulePath, 0o600);
    await writeFile(modulePath, 'export const value = 2;\n');
    await chmod(modulePath, 0o400);
    await assert.rejects(
      assertSidecarDeploymentMatchesReceipt(deployment, held.bytes),
      /changed after installation/u,
    );
  } finally {
    closeSync(descriptor);
  }
});

test('rejects a controlled sidecar deployment link outside its private root', async (t) => {
  const root = await realpath(
    await mkdtemp(resolve(tmpdir(), 'piui-sidecar-deployment-link.')),
  );
  t.after(async () => rm(root, { force: true, recursive: true }));
  await chmod(root, 0o700);
  const deployment = resolve(root, 'deployment');
  await mkdir(deployment, { mode: 0o700 });
  await writeFile(resolve(deployment, 'package.json'), '{"private":true}\n', {
    flag: 'wx',
    mode: 0o400,
  });
  await symlink('/etc/hosts', resolve(deployment, 'escaped'));
  await assert.rejects(
    captureSidecarDeploymentReceipt(deployment),
    /link escaped its root/u,
  );
});

const controlledFinaliserScripts = [
  'a21-gate-support.mjs',
  'apple-toolchain-trust.mjs',
  'architecture-gate-schema.mjs',
  'descriptor-acl.mjs',
  'exclusive-rename.c',
  'exclusive-rename.mjs',
  'sidecar-closure-policy.mjs',
  'sidecar-deployment-witness.mjs',
  'sidecar-publication-policy.mjs',
  'stage-sidecar.mjs',
];
const CONTROLLED_FINALISATION_TIMEOUT_MS = 900_000;
const CONTROLLED_PUBLICATION_PHASE_TIMEOUT_MS = 840_000;

const controlledFinaliserRuntimeFiles = [
  'index.js',
  'runtime.js',
  'pi/ai-public-sdk.js',
  'pi/deterministic-turn.js',
  'pi/packaged-sdk-probe-entry.js',
  'pi/packaged-sdk-probe.js',
  'pi/session-spike.js',
  'pi/trust-gate.js',
  'pi/trust-loader-executor.js',
  'pi/trust-loader-project-thread.js',
  'pi/trust-loader-worker.js',
  'pi/trust-loader.js',
  'spike/approval-entry.js',
  'spike/approval-matrix.js',
  'spike/approval-probes.js',
];

const controlledFinaliserInstalledFiles = [
  '@earendil-works/pi-ai/dist/index.js',
  '@earendil-works/pi-ai/package.json',
  '@earendil-works/pi-coding-agent/dist/index.js',
  '@earendil-works/pi-coding-agent/dist/modes/interactive/theme/dark.json',
  '@earendil-works/pi-coding-agent/dist/modes/interactive/theme/light.json',
  '@earendil-works/pi-coding-agent/dist/modes/interactive/theme/theme-schema.json',
  '@earendil-works/pi-coding-agent/dist/utils/changelog.js',
  'yaml/dist/doc/Document.js',
  'yaml/dist/doc/directives.js',
];

async function writeFixtureFile(path, bytes = 'export {};\n') {
  await mkdir(dirname(path), { mode: 0o700, recursive: true });
  await writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
}

async function unlockFixtureDirectories(path) {
  let state;
  try {
    state = await lstat(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  if (state.isSymbolicLink() || !state.isDirectory()) return;
  await chmod(path, 0o700);
  for (const name of await readdir(path)) {
    await unlockFixtureDirectories(resolve(path, name));
  }
}

async function removeFixture(path) {
  await unlockFixtureDirectories(path);
  await rm(path, { force: true, recursive: true });
}

test('controlled finalisation retires an exact reset placeholder and preserves a sealed prior inode on collision', async (t) => {
  const fixtureRoot = await realpath(
    await mkdtemp(resolve(tmpdir(), 'piui-sidecar-finaliser-fixture.')),
  );
  const workspace = await realpath(
    await mkdtemp(resolve(tmpdir(), 'piui-sidecar-stage-control-')),
  );
  t.after(async () => {
    await removeFixture(workspace);
    await removeFixture(fixtureRoot);
  });
  await chmod(fixtureRoot, 0o700);
  await chmod(workspace, 0o700);

  const scripts = resolve(fixtureRoot, 'scripts');
  await mkdir(scripts, { mode: 0o700 });
  for (const name of controlledFinaliserScripts) {
    await copyFile(new URL(`../../scripts/${name}`, import.meta.url), resolve(scripts, name));
  }
  for (const relativePath of controlledFinaliserRuntimeFiles) {
    await writeFixtureFile(resolve(fixtureRoot, 'sidecar/dist', relativePath));
  }
  await writeFixtureFile(
    resolve(fixtureRoot, 'packages/protocol/schema/envelope.schema.json'),
    '{}\n',
  );
  await writeFixtureFile(
    resolve(fixtureRoot, 'packages/protocol/dist/codec.js'),
  );
  await writeFixtureFile(
    resolve(fixtureRoot, 'tests/fixtures/pi-sessions/active-branch-v3.jsonl'),
    '{}\n',
  );

  const deployment = resolve(workspace, 'deployment');
  await mkdir(resolve(deployment, 'node_modules'), { mode: 0o700, recursive: true });
  const importerPath = resolve(deployment, 'package.json');
  await writeFile(
    importerPath,
    `${JSON.stringify({
      dependencies: { yaml: '2.8.0' },
      name: '@piui/frozen-importer-fixture',
      private: true,
      type: 'module',
    }, null, 2)}\n`,
    { flag: 'wx', mode: 0o400 },
  );
  await chmod(importerPath, 0o400);
  for (const relativePath of controlledFinaliserInstalledFiles) {
    const bytes = relativePath.endsWith('.json') ? '{}\n' : 'export {};\n';
    await writeFixtureFile(resolve(deployment, 'node_modules', relativePath), bytes);
  }
  assert.equal((await lstat(importerPath)).mode & 0o777, 0o400);
  const deploymentTemplate = resolve(fixtureRoot, 'deployment-template');
  await cp(deployment, deploymentTemplate, { recursive: true });

  const priorPublished = resolve(fixtureRoot, 'src-tauri/resources/sidecar');
  await mkdir(priorPublished, { mode: 0o700, recursive: true });
  const resetPlaceholderState = await lstat(priorPublished, { bigint: true });

  const receipt = await captureSidecarDeploymentReceipt(deployment);
  const cache = resolve(fixtureRoot, '.cache');
  await mkdir(cache, { mode: 0o700 });
  const lockPath = resolve(cache, 'sidecar-stage.lock');
  const receiptPath = resolve(fixtureRoot, 'deployment-receipt.json');
  const progressPath = resolve(fixtureRoot, 'finalisation-progress.txt');
  await writeFile(lockPath, 'held\n', { flag: 'wx', mode: 0o600 });
  await chmod(lockPath, 0o600);
  await writeFile(receiptPath, receipt.bytes, { flag: 'wx', mode: 0o400 });
  await chmod(receiptPath, 0o400);
  const lockFd = openSync(lockPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  const receiptFd = openSync(receiptPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  const progressFd = openSync(
    progressPath,
    constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
    0o600,
  );
  fchmodSync(progressFd, 0o600);
  let finalisation;
  try {
    finalisation = spawnSync(
      process.execPath,
      [
        resolve(scripts, 'stage-sidecar.mjs'),
        '--finalise-controlled',
        workspace,
        '3',
        '4',
        receipt.sha256,
        '5',
      ],
      {
        cwd: fixtureRoot,
        encoding: 'utf8',
        env: {
          ...process.env,
          TMPDIR: `${await realpath(tmpdir())}/`,
        },
        stdio: ['ignore', 'pipe', 'pipe', lockFd, receiptFd, progressFd],
        timeout: CONTROLLED_FINALISATION_TIMEOUT_MS,
      },
    );
  } finally {
    closeSync(progressFd);
    closeSync(receiptFd);
    closeSync(lockFd);
  }
  const diagnostics = `${finalisation.stdout ?? ''}\n${finalisation.stderr ?? ''}`;
  assert.equal(finalisation.error, undefined, diagnostics);
  assert.equal(finalisation.signal, null, diagnostics);
  assert.equal(finalisation.status, 0, diagnostics);
  assert.equal(
    await readFile(progressPath, 'utf8'),
    'PIUI_SIDECAR_FINALISATION_PHASE=complete\n',
  );

  const published = resolve(fixtureRoot, 'src-tauri/resources/sidecar');
  const publishedPackagePath = resolve(published, 'package.json');
  const publishedPackage = JSON.parse(await readFile(publishedPackagePath, 'utf8'));
  assert.equal(publishedPackage.dependencies['@piui/protocol'], '0.1.0');
  assert.equal((await lstat(published)).mode & 0o777, 0o555);
  assert.equal((await lstat(resolve(published, 'node_modules'))).mode & 0o777, 0o555);
  assert.equal((await lstat(publishedPackagePath)).mode & 0o777, 0o644);
  assert.equal((await lstat(resolve(published, 'manifest.json'))).mode & 0o777, 0o644);
  assert.notEqual((await lstat(published, { bigint: true })).ino, resetPlaceholderState.ino);
  await assert.rejects(lstat(resolve(published, 'prior-only.txt')), { code: 'ENOENT' });
  assert.equal(
    (await lstat(resolve(fixtureRoot, 'src-tauri/target/a25-sidecar-fixture/package.json'))).mode & 0o777,
    0o400,
  );

  const rollbackWorkspace = await realpath(
    await mkdtemp(resolve(tmpdir(), 'piui-sidecar-stage-control-')),
  );
  t.after(async () => removeFixture(rollbackWorkspace));
  await chmod(rollbackWorkspace, 0o700);
  const rollbackDeployment = resolve(rollbackWorkspace, 'deployment');
  await cp(deploymentTemplate, rollbackDeployment, { recursive: true });
  const rollbackReceipt = await captureSidecarDeploymentReceipt(rollbackDeployment);
  const rollbackReceiptPath = resolve(fixtureRoot, 'rollback-deployment-receipt.json');
  const rollbackProgressPath = resolve(fixtureRoot, 'rollback-finalisation-progress.txt');
  await writeFile(rollbackReceiptPath, rollbackReceipt.bytes, { flag: 'wx', mode: 0o400 });
  await chmod(rollbackReceiptPath, 0o400);
  const rollbackLockFd = openSync(lockPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  const rollbackReceiptFd = openSync(
    rollbackReceiptPath,
    constants.O_RDONLY | constants.O_NOFOLLOW,
  );
  const rollbackProgressFd = openSync(
    rollbackProgressPath,
    constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
    0o600,
  );
  fchmodSync(rollbackProgressFd, 0o600);
  const priorPublishedState = await lstat(published, { bigint: true });
  const rollback = spawn(
    process.execPath,
    [
      resolve(scripts, 'stage-sidecar.mjs'),
      '--finalise-controlled',
      rollbackWorkspace,
      '3',
      '4',
      rollbackReceipt.sha256,
      '5',
    ],
    {
      cwd: fixtureRoot,
      env: {
        ...process.env,
        TMPDIR: `${await realpath(tmpdir())}/`,
      },
      stdio: [
        'ignore',
        'pipe',
        'pipe',
        rollbackLockFd,
        rollbackReceiptFd,
        rollbackProgressFd,
      ],
      timeout: CONTROLLED_FINALISATION_TIMEOUT_MS,
    },
  );
  closeSync(rollbackProgressFd);
  closeSync(rollbackReceiptFd);
  closeSync(rollbackLockFd);
  const rollbackStdout = [];
  const rollbackStderr = [];
  rollback.stdout.on('data', (bytes) => rollbackStdout.push(bytes));
  rollback.stderr.on('data', (bytes) => rollbackStderr.push(bytes));
  const rollbackExit = new Promise((resolveExit, rejectExit) => {
    rollback.once('error', rejectExit);
    rollback.once('exit', (code, signal) => resolveExit({ code, signal }));
  });
  const phaseDeadline = Date.now() + CONTROLLED_PUBLICATION_PHASE_TIMEOUT_MS;
  let candidatePublishObserved = false;
  while (Date.now() < phaseDeadline && rollback.exitCode === null) {
    const phase = await readFile(rollbackProgressPath, 'utf8');
    if (phase === 'PIUI_SIDECAR_FINALISATION_PHASE=candidate-publish\n') {
      candidatePublishObserved = true;
      break;
    }
    await delay(5);
  }
  assert.equal(candidatePublishObserved, true, 'candidate publication phase must be observable');
  await assert.rejects(lstat(published), { code: 'ENOENT' });
  await mkdir(published, { mode: 0o700 });
  await writeFile(resolve(published, 'attacker-owned.txt'), 'attacker\n', {
    flag: 'wx',
    mode: 0o644,
  });
  await chmod(published, 0o555);
  const attackerState = await lstat(published, { bigint: true });
  const rollbackResult = await rollbackExit;
  const rollbackDiagnostics = Buffer.concat([
    ...rollbackStdout,
    Buffer.from('\n'),
    ...rollbackStderr,
  ]).toString('utf8');
  assert.equal(rollbackResult.signal, null, rollbackDiagnostics);
  assert.notEqual(rollbackResult.code, 0, rollbackDiagnostics);
  assert.match(rollbackDiagnostics, /leased rollback failed|cleanup authority is unavailable/u);
  const attackerAfter = await lstat(published, { bigint: true });
  assert.equal(attackerAfter.dev, attackerState.dev);
  assert.equal(attackerAfter.ino, attackerState.ino);
  assert.equal(await readFile(resolve(published, 'attacker-owned.txt'), 'utf8'), 'attacker\n');
  const retired = resolve(rollbackWorkspace, 'retired');
  const retiredState = await lstat(retired, { bigint: true });
  assert.equal(retiredState.dev, priorPublishedState.dev);
  assert.equal(retiredState.ino, priorPublishedState.ino);
  assert.ok((await lstat(resolve(retired, 'manifest.json'))).isFile());
  assert.equal(
    await readFile(rollbackProgressPath, 'utf8'),
    'PIUI_SIDECAR_FINALISATION_PHASE=candidate-publish\n',
  );
});
