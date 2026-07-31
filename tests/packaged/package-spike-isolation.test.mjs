import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { architectureVariantDefinition } from '../../scripts/architecture-artifact-evidence.mjs';
import { inventoryBundle } from './bundle-inspection.mjs';
import {
  buildSandboxFor,
  copyBundleToPrivateControl,
  captureDependencyTree,
  captureToolInputTree,
  preparePinnedNodeTool,
  relocateAcceptedBundle,
  sealBundle,
  signAutomationHost,
} from '../../scripts/package-spike.mjs';

const packageSource = await readFile(
  new URL('../../scripts/package-spike.mjs', import.meta.url),
  'utf8',
);

test('packages only from a byte-verified isolated source copy', () => {
  assert.match(
    packageSource,
    /const isolatedSource = await createIsolatedBuildSource\(\s*bootstrapIsolate,\s*bootstrapTools,\s*cutoffs\.signal,\s*\)/u,
  );
  assert.match(packageSource, /await copyFrozenSourceFile\(repositoryRoot, cloneRoot, entry\)/u);
  assert.match(packageSource, /const copied = await snapshotArchitectureSource\(cloneRoot\)/u);
  assert.match(packageSource, /const finalRepository = await snapshotArchitectureSource\(repositoryRoot\)/u);
  assert.match(packageSource, /materialiseFrozenDependencies\(/u);
  assert.match(packageSource, /'--frozen-lockfile'/u);
  assert.match(packageSource, /'--ignore-scripts'/u);
  assert.match(packageSource, /'--config\.package-import-method=copy'/u);
  assert.doesNotMatch(packageSource, /installTrustedNodeModules/u);
  assert.doesNotMatch(packageSource, /resolve\(repositoryRoot, 'node_modules'\)/u);
  assert.match(packageSource, /await installPinnedNodeArchive\(cloneRoot\)/u);
  assert.match(packageSource, /function dependencyInstallRoots\(cloneRoot\)/u);
  assert.match(packageSource, /Private dependency link escaped the frozen source/u);
  assert.match(packageSource, /if \(!copied\.equals\(bytes\) \|\| sha256Bytes\(copied\) !== pin\.sha256\)/u);
  assert.doesNotMatch(packageSource, /resolve\(repositoryRoot, '\.cache\/a21-package\.lock'\)/u);
  assert.match(packageSource, /const temporaryRoot = await realpath\(tmpdir\(\)\)/u);
  assert.match(packageSource, /temporaryRoot,\s*'piui-architecture-gate-locks'/u);
  assert.match(packageSource, /mkdtemp\(resolve\(temporaryRoot, prefix\)\)/u);
  assert.match(packageSource, /await realpath\(path\) !== path/u);
  assert.match(packageSource, /TMPDIR: `\$\{temporaryRoot\}\/`/u);
  assert.match(packageSource, /generated = generatedOutputsFor\(sourceRoot\)/u);
  assert.match(packageSource, /\(deny default\)/u);
  assert.doesNotMatch(packageSource, /\(allow default\)/u);
  assert.match(packageSource, /await sealFrozenSourceInputs\(cloneRoot, beforeSourceSeal\)/u);
  assert.match(packageSource, /await sealDependencyTree\(dependencyRoot\)/u);
  assert.match(packageSource, /await assertFrozenBuildInputs\(\)/u);
});

test('never persists or passes raw ambient private values into the frozen child', () => {
  assert.doesNotMatch(packageSource, /private-values\.json/u);
  assert.doesNotMatch(packageSource, /privateValuesPath|privateValuesSha256/u);
  assert.match(packageSource, /boundedAmbientPrivateValues\(process\.env, repositoryRoot\)/u);
  assert.match(packageSource, /assertBuffersExcludeValues\(\s*\[child\.stdout, child\.stderr\]/u);
  assert.match(packageSource, /PIUI_PACKAGE_SYNTHETIC_CANARIES/u);
  assert.match(packageSource, /PIUI_BUILD_SECRET_CANARY_A/u);
  assert.match(packageSource, /delete process\.env\.PIUI_PACKAGE_SYNTHETIC_CANARIES/u);
});

async function removeFixture(path) {
  try {
    const state = await lstat(path);
    if (state.isDirectory() && !state.isSymbolicLink()) {
      await chmod(path, 0o700);
      for (const entry of await readdir(path)) {
        await removeFixture(resolve(path, entry));
      }
    }
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  await rm(path, { force: true, recursive: true });
}

test('deny-default build sandbox permits only declared build paths', async (t) => {
  if (process.platform !== 'darwin') {
    t.skip('macOS sandbox-exec is required');
    return;
  }
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-build-sandbox-test.'));
  t.after(async () => removeFixture(root));
  const isolate = resolve(root, 'isolate');
  const source = resolve(isolate, 'source');
  const generated = resolve(source, 'dist');
  const tools = resolve(isolate, 'tools');
  const working = resolve(isolate, 'work');
  const controls = resolve(isolate, 'build-controls');
  const credentialControls = resolve(isolate, 'credential-cleanup-control');
  const bundleControls = resolve(isolate, 'accepted-bundle-private-control');
  const forbiddenHome = resolve(root, 'forbidden-home');
  const forbiddenTemporary = resolve(root, 'forbidden-tmp');
  for (const path of [
    source,
    generated,
    tools,
    working,
    controls,
    credentialControls,
    bundleControls,
    forbiddenHome,
    forbiddenTemporary,
  ]) {
    await mkdir(path, { recursive: true, mode: 0o700 });
  }
  const pinnedNode = await preparePinnedNodeTool(isolate);
  const privateNode = pinnedNode.node;
  const input = resolve(source, 'input.txt');
  const overlay = resolve(controls, 'automation-twin.json');
  const undeclaredControl = resolve(controls, 'undeclared.json');
  const credentialHelper = resolve(credentialControls, 'credential-cleanup-harness');
  const privateBundleFile = resolve(bundleControls, 'accepted.app/Contents/private.txt');
  const homeSecret = resolve(forbiddenHome, 'secret.txt');
  const otherSecret = resolve(forbiddenTemporary, 'secret.txt');
  await writeFile(input, 'input\n', { mode: 0o400 });
  await writeFile(
    overlay,
    '{"identifier":"au.com.piui.desktop.architecture-test"}\n',
    { mode: 0o400 },
  );
  await writeFile(undeclaredControl, '{"hostile":true}\n', { mode: 0o400 });
  await copyFile('/usr/bin/true', credentialHelper);
  await chmod(credentialHelper, 0o500);
  await chmod(credentialControls, 0o500);
  await mkdir(resolve(privateBundleFile, '..'), { recursive: true, mode: 0o700 });
  await writeFile(privateBundleFile, 'private-bundle\n', { mode: 0o400 });
  await writeFile(homeSecret, 'home-secret\n', { mode: 0o600 });
  await writeFile(otherSecret, 'other-secret\n', { mode: 0o600 });
  const repositoryRoot = fileURLToPath(new URL('../..', import.meta.url));
  const pnpmEntries = await readdir(resolve(repositoryRoot, 'node_modules/.pnpm'));
  const esbuildPackages = pnpmEntries.filter((name) => (
    /^@esbuild\+darwin-arm64@[^/]+$/u.test(name)
  ));
  assert.equal(esbuildPackages.length, 1);
  const dependencyExecutable = resolve(
    source,
    'node_modules/@esbuild/darwin-arm64/bin/esbuild',
  );
  await mkdir(resolve(dependencyExecutable, '..'), { recursive: true, mode: 0o700 });
  await copyFile(
    resolve(
      repositoryRoot,
      'node_modules/.pnpm',
      esbuildPackages[0],
      'node_modules/@esbuild/darwin-arm64/bin/esbuild',
    ),
    dependencyExecutable,
  );
  await chmod(dependencyExecutable, 0o500);
  const probe = resolve(source, 'probe.mjs');
  await writeFile(probe, `
    import { spawnSync } from 'node:child_process';
    import { readFileSync, writeFileSync } from 'node:fs';
    const denied = (operation) => {
      try { operation(); return false; }
      catch (error) { return error?.code === 'EPERM' || error?.code === 'EACCES'; }
    };
    const shell = spawnSync('/bin/sh', ['-c', 'printf shell > "$1"', 'probe', process.env.SHELL_OUTPUT]);
    const dependencyTool = spawnSync(
      process.env.DEPENDENCY_EXECUTABLE,
      ['--version'],
      { encoding: 'utf8' },
    );
    const result = {
      allowedRead: readFileSync(process.env.ALLOWED_INPUT, 'utf8') === 'input\\n',
      allowedWrite: (() => { writeFileSync(process.env.ALLOWED_OUTPUT, 'allowed\\n'); return true; })(),
      bundleControlReadDenied: denied(() => readFileSync(process.env.BUNDLE_CONTROL)),
      bundleControlWriteDenied: denied(() => writeFileSync(process.env.BUNDLE_CONTROL, 'mutated')),
      dependencyExecutableWorked: dependencyTool.status === 0
        && /^\\d+\\.\\d+\\.\\d+\\n$/u.test(dependencyTool.stdout),
      credentialControlReadDenied: denied(() => readFileSync(process.env.CREDENTIAL_HELPER)),
      credentialControlWriteDenied: denied(() => writeFileSync(process.env.CREDENTIAL_HELPER, 'mutated')),
      homeReadDenied: denied(() => readFileSync(process.env.HOME_SECRET)),
      homeWriteDenied: denied(() => writeFileSync(process.env.HOME_WRITE, 'denied', { flag: 'wx' })),
      otherReadDenied: denied(() => readFileSync(process.env.OTHER_SECRET)),
      otherWriteDenied: denied(() => writeFileSync(process.env.OTHER_WRITE, 'denied', { flag: 'wx' })),
      overlayRead: JSON.parse(readFileSync(process.env.OVERLAY_INPUT, 'utf8')).identifier
        === 'au.com.piui.desktop.architecture-test',
      sourceWriteDenied: denied(() => writeFileSync(process.env.ALLOWED_INPUT, 'mutated')),
      shellWorked: shell.status === 0,
      undeclaredControlReadDenied: denied(() => readFileSync(process.env.UNDECLARED_CONTROL)),
    };
    process.stdout.write(JSON.stringify(result) + '\\n');
  `, { mode: 0o400 });
  const profile = buildSandboxFor({
    executableFiles: [dependencyExecutable, privateNode, '/bin/bash', '/bin/sh'],
    executableRoots: [],
    readableFiles: [...new Set([
      privateNode,
      dependencyExecutable,
      '/bin/bash',
      '/bin/sh',
      '/private/var/select/sh',
      overlay,
      '/dev/null',
      '/dev/random',
      '/dev/urandom',
      ...pinnedNode.nodeRuntimeFiles,
    ])],
    readableRoots: [source, tools, working, '/Library/Apple/System/Library', '/System/Library', '/usr/lib'],
    writableFiles: [generated, working],
    writableRoots: [generated, working],
  });
  assert.match(profile, /\(deny default\)/u);
  assert.doesNotMatch(profile, /\(allow default\)/u);
  const result = spawnSync('/usr/bin/sandbox-exec', [
    '-p', profile, privateNode, probe,
  ], {
    encoding: 'utf8',
    env: {
      ALLOWED_INPUT: input,
      ALLOWED_OUTPUT: resolve(generated, 'output.txt'),
      BUNDLE_CONTROL: privateBundleFile,
      CREDENTIAL_HELPER: credentialHelper,
      DEPENDENCY_EXECUTABLE: dependencyExecutable,
      HOME: forbiddenHome,
      HOME_SECRET: homeSecret,
      HOME_WRITE: resolve(forbiddenHome, 'write.txt'),
      OTHER_SECRET: otherSecret,
      OTHER_WRITE: resolve(forbiddenTemporary, 'write.txt'),
      OVERLAY_INPUT: overlay,
      SHELL_OUTPUT: resolve(generated, 'shell.txt'),
      UNDECLARED_CONTROL: undeclaredControl,
      TMPDIR: `${working}/`,
      PATH: '/usr/bin:/bin',
    },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  assert.deepEqual(JSON.parse(result.stdout), {
    allowedRead: true,
    allowedWrite: true,
    bundleControlReadDenied: true,
    bundleControlWriteDenied: true,
    credentialControlReadDenied: true,
    credentialControlWriteDenied: true,
    dependencyExecutableWorked: true,
    homeReadDenied: true,
    homeWriteDenied: true,
    otherReadDenied: true,
    otherWriteDenied: true,
    overlayRead: true,
    sourceWriteDenied: true,
    shellWorked: true,
    undeclaredControlReadDenied: true,
  });
  await assert.rejects(lstat(resolve(forbiddenHome, 'write.txt')), { code: 'ENOENT' });
  await assert.rejects(lstat(resolve(forbiddenTemporary, 'write.txt')), { code: 'ENOENT' });
});

test('bundle sealing rejects links and forbidden xattrs without mutating external metadata', async (t) => {
  if (process.platform !== 'darwin') {
    t.skip('macOS sandbox-exec and xattr are required');
    return;
  }
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-bundle-seal-test.'));
  t.after(async () => removeFixture(root));
  const app = resolve(root, 'PIUI.app');
  const contents = resolve(app, 'Contents');
  const payload = resolve(contents, 'payload.txt');
  const outside = resolve(root, 'outside.txt');
  await mkdir(contents, { recursive: true, mode: 0o755 });
  await writeFile(payload, 'payload\n', { mode: 0o644 });
  await writeFile(outside, 'outside\n', { mode: 0o600 });
  assert.equal(spawnSync('/usr/bin/xattr', ['-w', 'au.com.piui.test', 'inside', payload]).status, 0);
  assert.equal(spawnSync('/usr/bin/xattr', ['-w', 'au.com.piui.test', 'outside', outside]).status, 0);
  await symlink(outside, resolve(contents, 'escape'));

  await assert.rejects(sealBundle(app), /Symlink forbidden|unsafe bundle entry/u);
  assert.equal(
    spawnSync('/usr/bin/xattr', ['-p', 'au.com.piui.test', outside], { encoding: 'utf8' }).stdout,
    'outside\n',
  );
  await rm(resolve(contents, 'escape'));
  await assert.rejects(sealBundle(app), /Extended attributes/u);
  assert.equal(
    spawnSync('/usr/bin/xattr', ['-p', 'au.com.piui.test', outside], { encoding: 'utf8' }).stdout,
    'outside\n',
  );
  assert.equal(spawnSync('/usr/bin/xattr', ['-c', payload]).status, 0);
  await sealBundle(app);
  assert.equal((await lstat(app)).mode & 0o777, 0o555);
  assert.equal((await lstat(contents)).mode & 0o777, 0o555);
  assert.equal((await lstat(payload)).mode & 0o777, 0o444);
  assert.equal(
    spawnSync('/usr/bin/xattr', ['-p', 'au.com.piui.test', outside], { encoding: 'utf8' }).stdout,
    'outside\n',
  );
});

test('automation signing rejects same-byte host pathname replacement while held', async (t) => {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-sign-host-test.'));
  t.after(async () => removeFixture(root));
  const signedApp = resolve(root, 'Signed.app');
  const signedRoot = resolve(signedApp, 'Contents/MacOS');
  const signedHost = resolve(signedRoot, 'piui');
  await mkdir(signedRoot, { recursive: true, mode: 0o700 });
  const compilation = spawnSync('/usr/bin/clang', ['-x', 'c', '-', '-o', signedHost], {
    encoding: 'utf8',
    input: 'int main(void) { return 0; }\n',
  });
  assert.equal(compilation.status, 0, compilation.stderr);
  await chmod(signedHost, 0o500);
  await signAutomationHost(signedApp, {});
  const verifiedSignature = spawnSync('/usr/bin/codesign', ['--verify', signedHost], {
    encoding: 'utf8',
  });
  assert.equal(verifiedSignature.status, 0, verifiedSignature.stderr);

  const app = resolve(root, 'PIUI.app');
  const executableRoot = resolve(app, 'Contents/MacOS');
  const host = resolve(executableRoot, 'piui');
  const replacement = resolve(executableRoot, 'replacement');
  const bytes = Buffer.from('#!/bin/sh\nexit 0\n');
  await mkdir(executableRoot, { recursive: true, mode: 0o700 });
  await writeFile(host, bytes, { mode: 0o500 });
  await writeFile(replacement, bytes, { mode: 0o500 });
  await assert.rejects(
    signAutomationHost(app, {}, async () => {
      await rename(replacement, host);
    }),
    /signed host transition is invalid/u,
  );
});

test('private bundle capture copies held bytes to fresh inodes and rejects target replacement', async (t) => {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-private-bundle-copy.'));
  t.after(async () => removeFixture(root));
  const createCandidate = async (name) => {
    const app = resolve(root, name);
    await mkdir(resolve(app, 'Contents/MacOS'), { recursive: true, mode: 0o755 });
    await writeFile(resolve(app, 'Contents/Info.plist'), '<plist/>\n', { mode: 0o644 });
    await writeFile(resolve(app, 'Contents/MacOS/piui'), 'host-bytes\n', { mode: 0o755 });
    await writeFile(resolve(app, 'Contents/MacOS/piui-node'), 'node-bytes\n', { mode: 0o755 });
    return app;
  };

  const candidate = await createCandidate('candidate.app');
  const candidateHost = resolve(candidate, 'Contents/MacOS/piui');
  const candidateHostBefore = await lstat(candidateHost);
  const privateApp = await copyBundleToPrivateControl(
    candidate,
    resolve(root, 'control-one'),
  );
  const privateHost = resolve(privateApp, 'Contents/MacOS/piui');
  const privateHostState = await lstat(privateHost);
  assert.notEqual(privateHostState.ino, candidateHostBefore.ino);
  assert.equal(privateHostState.mode & 0o777, 0o700);
  assert.equal(
    (await lstat(candidateHost)).mode & 0o777,
    candidateHostBefore.mode & 0o777,
  );
  await writeFile(candidateHost, 'candidate-mutated\n');
  assert.equal(await readFile(privateHost, 'utf8'), 'host-bytes\n');

  const replacementCandidate = await createCandidate('replacement-candidate.app');
  let replaced = false;
  await assert.rejects(
    copyBundleToPrivateControl(
      replacementCandidate,
      resolve(root, 'control-two'),
      async ({ destination, entry }) => {
        if (replaced || entry.kind !== 'file') return;
        replaced = true;
        const target = resolve(destination, entry.path);
        const replacement = `${target}.replacement`;
        await copyFile(target, replacement);
        await chmod(replacement, (await lstat(target)).mode & 0o777);
        await rename(replacement, target);
      },
    ),
    /exact held-byte copy/u,
  );
  assert.equal(replaced, true);
});

test('accepted bundle relocation preserves inode and rejects a source pathname replacement', async (t) => {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-bundle-relocate.'));
  t.after(async () => removeFixture(root));
  const createAccepted = async (name) => {
    const parent = resolve(root, `${name}-source`);
    const app = resolve(parent, `${name}.app`);
    await mkdir(resolve(app, 'Contents/MacOS'), { recursive: true, mode: 0o700 });
    await writeFile(resolve(app, 'Contents/MacOS/piui'), 'host\n', { mode: 0o500 });
    await writeFile(resolve(app, 'Contents/MacOS/piui-node'), 'node\n', { mode: 0o500 });
    await chmod(app, 0o555);
    const inventory = await inventoryBundle(app);
    const host = inventory.entries.find((entry) => entry.path === 'Contents/MacOS/piui');
    const node = inventory.entries.find((entry) => entry.path === 'Contents/MacOS/piui-node');
    return {
      app,
      bundle: Object.freeze({
        appPath: app,
        fingerprint: inventory.fingerprint,
        hostIdentity: Object.freeze({ dev: host.dev, ino: host.ino, bytes: host.bytes, sha256: host.sha256 }),
        hostPath: resolve(app, 'Contents/MacOS/piui'),
        nodeIdentity: Object.freeze({ dev: node.dev, ino: node.ino, bytes: node.bytes, sha256: node.sha256 }),
        nodePath: resolve(app, 'Contents/MacOS/piui-node'),
      }),
    };
  };

  const destinationParent = resolve(root, 'published');
  await mkdir(destinationParent, { mode: 0o700 });
  const accepted = await createAccepted('first');
  const before = await lstat(accepted.app);
  const destination = resolve(destinationParent, 'first.app');
  const relocated = await relocateAcceptedBundle(accepted.bundle, destination);
  const after = await lstat(destination);
  assert.equal(after.dev, before.dev);
  assert.equal(after.ino, before.ino);
  assert.equal(after.mode & 0o777, 0o555);
  assert.equal(relocated.appPath, destination);

  const attacked = await createAccepted('attacked');
  const attackedBefore = await lstat(attacked.app);
  const attackedDestination = resolve(destinationParent, 'attacked.app');
  const displaced = `${attacked.app}.displaced`;
  await assert.rejects(
    relocateAcceptedBundle(attacked.bundle, attackedDestination, async ({ source }) => {
      await rename(source, displaced);
      await mkdir(source, { mode: 0o700 });
    }),
  );
  const displacedAfter = await lstat(displaced);
  assert.equal(displacedAfter.dev, attackedBefore.dev);
  assert.equal(displacedAfter.ino, attackedBefore.ino);
  await assert.rejects(lstat(attackedDestination), { code: 'ENOENT' });

  const cleanupFault = await createAccepted('cleanup-fault');
  const cleanupFaultBefore = await lstat(cleanupFault.app);
  const cleanupFaultDestination = resolve(destinationParent, 'cleanup-fault.app');
  const helperTemporaryRoot = resolve(root, 'exclusive-helper-temporary');
  await mkdir(helperTemporaryRoot, { mode: 0o700 });
  const helperPrefix = `piui-exclusive-rename-${process.pid}-`;
  const attacker = spawn(process.execPath, ['-e', [
    "const { readdirSync, writeFileSync } = require('node:fs');",
    "const { join } = require('node:path');",
    'const [root, prefix] = process.argv.slice(1);',
    'for (let attempt = 0; attempt < 5000; attempt += 1) {',
    '  const name = readdirSync(root).find((entry) => entry.startsWith(prefix));',
    "  if (name) { writeFileSync(join(root, name, 'unexpected'), 'injected\\n', { mode: 0o600 }); process.exit(0); }",
    '  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1);',
    '}',
    'process.exit(2);',
  ].join('\n'), helperTemporaryRoot, helperPrefix], { stdio: 'ignore' });
  const attackerClose = new Promise((resolveExit, rejectExit) => {
    attacker.once('error', rejectExit);
    attacker.once('exit', resolveExit);
  });
  const previousTemporary = process.env.TMPDIR;
  process.env.TMPDIR = helperTemporaryRoot;
  let completionError;
  try {
    await relocateAcceptedBundle(cleanupFault.bundle, cleanupFaultDestination);
  } catch (error) {
    completionError = error;
  } finally {
    if (previousTemporary === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = previousTemporary;
  }
  const attackerExit = await attackerClose;
  assert.equal(attackerExit, 0);
  assert.equal(completionError?.operationCompleted, true);
  assert.equal(completionError?.receipt?.destination, cleanupFaultDestination);
  await assert.rejects(lstat(cleanupFault.app), { code: 'ENOENT' });
  const completedDestination = await lstat(cleanupFaultDestination);
  assert.equal(completedDestination.dev, cleanupFaultBefore.dev);
  assert.equal(completedDestination.ino, cleanupFaultBefore.ino);
  assert.equal(completedDestination.mode & 0o777, 0o555);
});

test('dependency witness rejects external links and detects same-byte replacement', async (t) => {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-dependency-witness.'));
  t.after(async () => removeFixture(root));
  const dependencyRoot = resolve(root, 'node_modules');
  const packageRoot = resolve(dependencyRoot, 'package');
  await mkdir(packageRoot, { recursive: true, mode: 0o700 });
  const dependencyFile = resolve(packageRoot, 'index.js');
  await writeFile(dependencyFile, 'export {};\n', { mode: 0o400 });
  const dependencyExecutable = resolve(packageRoot, 'tool');
  await writeFile(dependencyExecutable, '#!/bin/sh\nexit 0\n', { mode: 0o500 });
  await chmod(packageRoot, 0o500);
  await chmod(dependencyRoot, 0o500);
  const initial = await captureDependencyTree(root, dependencyRoot, { includeHashes: true });
  assert.deepEqual(initial.executables, [dependencyExecutable]);
  await chmod(dependencyRoot, 0o700);
  await chmod(packageRoot, 0o700);
  const replacement = resolve(packageRoot, 'replacement.js');
  await writeFile(replacement, 'export {};\n', { mode: 0o400 });
  await rename(replacement, dependencyFile);
  await chmod(packageRoot, 0o500);
  await chmod(dependencyRoot, 0o500);
  const replaced = await captureDependencyTree(root, dependencyRoot, { includeHashes: false });
  assert.notEqual(replaced.leaseSha256, initial.leaseSha256);

  const externalRoot = `${root}-outside`;
  await mkdir(externalRoot, { recursive: true, mode: 0o700 });
  t.after(async () => removeFixture(externalRoot));
  await chmod(dependencyRoot, 0o700);
  await symlink(externalRoot, resolve(dependencyRoot, 'escape'));
  await chmod(dependencyRoot, 0o500);
  await assert.rejects(
    captureDependencyTree(root, dependencyRoot, { includeHashes: true }),
    /escaped the frozen source/u,
  );
});

test('tool input witness detects mutation and same-inode ABA restoration', async (t) => {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-tool-input-witness.'));
  t.after(async () => removeFixture(root));
  const input = resolve(root, 'tool');
  await writeFile(input, 'trusted-input\n', { mode: 0o400 });
  const initial = await captureToolInputTree(root, { includeHashes: true });
  await chmod(input, 0o600);
  await writeFile(input, 'hostile-data!\n');
  await chmod(input, 0o400);
  const mutated = await captureToolInputTree(root, { includeHashes: true });
  assert.notEqual(mutated.inventorySha256, initial.inventorySha256);
  assert.notEqual(mutated.leaseSha256, initial.leaseSha256);

  await chmod(input, 0o600);
  await writeFile(input, 'trusted-input\n');
  await chmod(input, 0o400);
  const restored = await captureToolInputTree(root, { includeHashes: true });
  assert.equal(restored.inventorySha256, initial.inventorySha256);
  assert.notEqual(restored.leaseSha256, initial.leaseSha256);
});

test('executes the formal package runner from the authenticated frozen source clone', () => {
  assert.match(packageSource, /resolve\(isolatedSource\.root, 'scripts\/package-spike\.mjs'\),\s*'--isolated-child',\s*requestedMode/u);
  assert.match(packageSource, /cwd: isolatedSource\.root/u);
  assert.match(packageSource, /runnerRoot !== expectedSourceRoot/u);
  assert.match(packageSource, /throw new Error\('Package child is not executing from the frozen source root'\)/u);
  assert.match(packageSource, /const snapshot = await snapshotArchitectureSource\(runnerRoot\)/u);
  assert.match(packageSource, /snapshot\.source\.digest !== sourceDigest/u);
  assert.match(packageSource, /sourceRoot = childContext\.sourceRoot/u);
  assert.match(packageSource, /projectTrustModule = await import\(pathToFileURL\(\s*resolve\(sourceRoot, 'scripts\/run-packaged-trust-probe\.mjs'\)/u);
});

test('publishes proof output only after the owned build isolate is absent', () => {
  const childCleanup = packageSource.indexOf('await removeOwnedTree(buildIsolate);');
  const childAbsent = packageSource.indexOf("await assertPathAbsent(buildIsolate, 'Owned build isolate');", childCleanup);
  const finalise = packageSource.indexOf('resultDocument = finaliseResultAfterCleanup(resultDocument);', childAbsent);
  const childOutput = packageSource.indexOf('canonicalArchitectureJson(resultDocument)', finalise);
  const parentAbsent = packageSource.indexOf("await assertPathAbsent(bootstrapIsolate, 'Owned build isolate');");
  const parentOutput = packageSource.lastIndexOf('canonicalArchitectureJson(childResult)');
  assert.ok(
    childCleanup >= 0
      && childAbsent > childCleanup
      && finalise > childAbsent
      && childOutput > finalise
      && parentAbsent > childOutput
      && parentOutput > parentAbsent,
  );
  assert.match(packageSource, /generatedOutputsRemoved: true/u);
  assert.match(packageSource, /if \(id === 'A\.27'\)[\s\S]*?lifecycleModule\.finaliseLifecycleEvidence\(evidence\)/u);
  assert.match(packageSource, /\(item\.mode & 0o777\) !== 0o700/u);
  assert.match(packageSource, /item\.dev !== expectedIdentity\.dev \|\| item\.ino !== expectedIdentity\.ino/u);
  assert.match(packageSource, /ensurePrivateEvidenceDirectory\(forge, 'evidence', 'A\.28 evidence directory'\)/u);
  assert.match(packageSource, /'architecture-accessibility',\s*'A\.28 accessibility evidence root'/u);
  assert.match(
    packageSource,
    /evidenceRootIdentity = await optionalAccessibilityEvidenceRoot\(\);[\s\S]*?createIsolatedBuildSource\(\s*bootstrapIsolate,/u,
  );
  assert.match(packageSource, /if \(evidenceRoot\) environment\.PIUI_A28_HUMAN_EVIDENCE_ROOT = evidenceRoot/u);
});

test('builds the exact controlled twins and removes every packaged harness before inspection', () => {
  assert.match(packageSource, /const definition = architectureVariantDefinition\(kind\)/u);
  assert.match(packageSource, /definition\.cargoFeatures\.join\(','\)/u);
  assert.match(packageSource, /variant: definition/u);
  assert.doesNotMatch(packageSource, /function variantDefinition/u);
  assert.deepEqual(
    architectureVariantDefinition('credential-twin').cargoFeatures,
    ['a23-credential-test'],
  );
  assert.deepEqual(
    architectureVariantDefinition('approval-twin').cargoFeatures,
    ['a25-approval-test'],
  );
  assert.deepEqual(
    architectureVariantDefinition('automation-twin').cargoFeatures,
    ['a27-lifecycle-test', 'architecture-test'],
  );
  assert.deepEqual(
    architectureVariantDefinition('automation-twin').frontend,
    {
      VITE_PIUI_A26_MARKDOWN_TEST: '1',
      VITE_PIUI_A27_LIFECYCLE_TEST: '1',
      VITE_PIUI_A28_ACCESSIBILITY_TEST: '1',
    },
  );
  assert.equal(
    architectureVariantDefinition('automation-twin').overlay.identifier,
    'au.com.piui.desktop.architecture-test',
  );

  const removeKnown = packageSource.indexOf('await removeKnownTestHarnesses(appPath);');
  const removeApproval = packageSource.indexOf("definition.postBuild.externalHarness === 'approval-matrix-harness'");
  const seal = packageSource.indexOf('await sealBundle(appPath);', removeKnown);
  const inspect = packageSource.indexOf('const accepted = await inspectBundle({', seal);
  assert.ok(removeKnown >= 0 && removeApproval > removeKnown && seal > removeApproval && inspect > seal);
  assert.match(packageSource, /resolve\(appPath, 'Contents\/MacOS', 'approval-matrix-harness'\)/u);
  assert.match(packageSource, /await unlink\(path\)/u);
});

test('measures every gate twin against clean production and exact repeat builds', () => {
  assert.match(packageSource, /import \{ measureTwinDelta \} from '\.\/measured-twin-delta\.mjs'/u);
  assert.doesNotMatch(packageSource, /controlledTwinDeltaSha256/u);
  assert.match(
    packageSource,
    /async function rebuildFreshStageAnchors[\s\S]*?await resetGeneratedOutputs\(\);[\s\S]*?Fresh pinned Node provisioning[\s\S]*?Fresh sidecar closure staging[\s\S]*?equalStageAnchors\(referenceAnchors, fresh\)/u,
  );
  assert.match(packageSource, /const repeatAutomationBuild = await buildAndInspectVariant\(/u);
  assert.match(packageSource, /const repeatTwinBuild = await buildAndInspectVariant\(/u);
  assert.match(packageSource, /captureProbeHarness: false/u);
  assert.match(
    packageSource,
    /const preSignHostBytes = await readTrustedRegularFile\([\s\S]*?if \(definition\.postBuild\.hostSigning === 'adhoc'\) \{[\s\S]*?await signAutomationHost/u,
  );
  assert.match(
    packageSource,
    /measureTwinDelta\(\{[\s\S]*?productionPreSignHostBytes: productionBuild\.preSignHostBytes,[\s\S]*?twinPreSignHostBytes: automationBuild\.preSignHostBytes,[\s\S]*?twinRepeatPreSignHostBytes: repeatAutomationBuild\.preSignHostBytes/u,
  );
  assert.match(
    packageSource,
    /measureTwinDelta\(\{[\s\S]*?twinPreSignHostBytes: twinBuild\.preSignHostBytes,[\s\S]*?twinRepeatPreSignHostBytes: repeatTwinBuild\.preSignHostBytes/u,
  );
  assert.match(packageSource, /const deltaSha256 = measuredDelta\.sha256/u);
  assert.ok((packageSource.match(/\n\s*measuredDelta,\n/gu) ?? []).length >= 2);
  assert.match(
    packageSource,
    /else if \(gateCredential \|\| gateApproval\)[\s\S]*?assertExactProductionArtifact\(localProductionArtifact, receivedProductionArtifact\)/u,
  );
});

test('wires individual and append-only architecture proof modes without skipping A.27', () => {
  for (const argument of [
    '--authoritative-a26',
    '--authoritative-a27',
    '--authoritative-a28',
    '--architecture-gate-production',
    '--architecture-gate-credential',
    '--architecture-gate-approval',
    '--architecture-gate-automation',
  ]) assert.match(packageSource, new RegExp(argument, 'u'));
  assert.match(packageSource, /executeAuthoritativeMarkdownProbe/u);
  assert.match(packageSource, /executeAuthoritativeAccessibilityProbe/u);
  assert.match(packageSource, /executeRequiredLifecycleProbe/u);
  assert.match(packageSource, /resolve\(sourceRoot, 'scripts\/run-packaged-lifecycle-probe\.mjs'\)/u);
  assert.match(packageSource, /typeof lifecycleModule\.executeAuthoritativeLifecycleProbe !== 'function'/u);
  assert.match(packageSource, /typeof lifecycleModule\.finaliseLifecycleEvidence !== 'function'/u);
  assert.match(packageSource, /throw new Error\('A\.27 packaged lifecycle executor is unavailable'\)/u);
  assert.match(packageSource, /canonicalArchitectureJson\(resultDocument\)/u);
});
