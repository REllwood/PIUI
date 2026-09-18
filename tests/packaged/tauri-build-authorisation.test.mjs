import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmod,
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  realpath,
  rename,
  rm,
  readFile,
  writeFile,
} from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  createTauriBuildAuthorisation,
  preparePrivateTauriBuildTools,
  revalidateTauriBuildAuthorisation,
  validateTauriBuildAuthorisation,
} from '../../scripts/tauri-build-authorisation.mjs';
import {
  canonicalArchitectureJson,
  sha256Bytes,
} from '../../scripts/architecture-gate-schema.mjs';
import { snapshotArchitectureSource } from '../../scripts/architecture-source-snapshot.mjs';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const sha = (character) => character.repeat(64);

async function captureToolchainClosureWitness(root) {
  const inventory = [];
  async function visit(path, pathLabel) {
    const state = await lstat(path);
    if (state.isDirectory() && !state.isSymbolicLink()) {
      inventory.push({ kind: 'directory', path: pathLabel });
      const entries = await readdir(path, { withFileTypes: true });
      entries.sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
      for (const entry of entries) {
        await visit(
          join(path, entry.name),
          pathLabel === '.' ? entry.name : `${pathLabel}/${entry.name}`,
        );
      }
      return;
    }
    assert.equal(state.isFile() && !state.isSymbolicLink(), true);
    const bytes = await readFile(path);
    inventory.push({
      executable: (state.mode & 0o111) !== 0,
      path: pathLabel,
      sha256: sha256Bytes(bytes),
      size: bytes.length,
    });
  }
  await visit(root, '.');
  const inventoryBytes = Buffer.from(`${canonicalArchitectureJson(inventory)}\n`, 'utf8');
  return Object.freeze({
    entries: inventory.length,
    inventoryBytes,
    inventorySha256: sha256Bytes(inventoryBytes),
    root,
  });
}

function withInventoryEntries(witness, addedEntries) {
  const inventory = JSON.parse(
    witness.inventoryBytes.subarray(0, -1).toString('utf8'),
  );
  inventory.push(...addedEntries);
  const inventoryBytes = Buffer.from(
    `${canonicalArchitectureJson(inventory)}\n`,
    'utf8',
  );
  return Object.freeze({
    entries: inventory.length,
    inventoryBytes,
    inventorySha256: sha256Bytes(inventoryBytes),
    root: witness.root,
  });
}

async function createPrivateBuildToolsFixture(t, prefix) {
  const canonicalTemporaryRoot = await realpath(tmpdir());
  const root = await mkdtemp(join(canonicalTemporaryRoot, prefix));
  t.after(async () => rm(root, { force: true, recursive: true }));
  const buildIsolate = join(root, 'build');
  const pnpmRoot = join(root, 'pnpm', '9.15.0');
  await mkdir(buildIsolate, { mode: 0o700 });
  await mkdir(join(pnpmRoot, 'bin'), { mode: 0o700, recursive: true });
  await mkdir(join(pnpmRoot, 'dist'), { mode: 0o700 });
  const pnpmEntry = join(pnpmRoot, 'bin', 'pnpm.cjs');
  const pnpmNode = join(root, 'source-node');
  await writeFile(pnpmEntry, 'require("../dist/pnpm.cjs");\n', { mode: 0o700 });
  await writeFile(join(pnpmRoot, 'dist', 'pnpm.cjs'), 'module.exports = {};\n', { mode: 0o600 });
  await writeFile(pnpmNode, '#!/bin/sh\nexit 0\n', { mode: 0o700 });
  const authenticatedToolchainWitness = await captureToolchainClosureWitness(root);
  return {
    authenticatedToolchainWitness,
    buildIsolate,
    pnpmEntry,
    pnpmNode,
  };
}

async function createFixture(t) {
  const canonicalTemporaryRoot = await realpath(tmpdir());
  const buildIsolate = await mkdtemp(join(canonicalTemporaryRoot, 'piui-build-authorisation.'));
  t.after(async () => rm(buildIsolate, { force: true, recursive: true }));
  await chmod(buildIsolate, 0o700);
  const sourceRoot = join(buildIsolate, 'source');
  await mkdir(sourceRoot, { mode: 0o700 });
  const tools = join(buildIsolate, 'tools');
  await mkdir(tools, { mode: 0o700 });
  const pnpmEntry = join(tools, 'pnpm.cjs');
  const pnpmNode = join(tools, 'node');
  await writeFile(pnpmEntry, 'export {};\n', { mode: 0o700 });
  await writeFile(pnpmNode, '#!/bin/sh\nexit 0\n', { mode: 0o700 });
  const created = await createTauriBuildAuthorisation({
    buildIsolate,
    mode: 'guarded-production',
    nonce: sha('1'),
    pnpmEntry,
    pnpmNode,
    sourceDigest: sha('2'),
    sourceRoot,
  });
  return { buildIsolate, created, pnpmEntry, pnpmNode, sourceRoot };
}

test('accepts a hash-bound authorisation rooted beside the private frozen source', async (t) => {
  const fixture = await createFixture(t);
  const validated = await validateTauriBuildAuthorisation(
    fixture.sourceRoot,
    fixture.created.environment,
  );
  assert.equal(validated.mode, 'guarded-production');
  assert.equal(validated.sourceDigest, sha('2'));
  assert.equal(validated.pnpmEntry.path, fixture.pnpmEntry);
  assert.equal(validated.pnpmNode.path, fixture.pnpmNode);
  assert.match(validated.pnpmEntry.sha256, /^[0-9a-f]{64}$/u);
  await revalidateTauriBuildAuthorisation(validated);
});

test('rejects missing, forged and mutable build authorisation', async (t) => {
  await t.test('missing environment', async (nested) => {
    const fixture = await createFixture(nested);
    await assert.rejects(
      validateTauriBuildAuthorisation(fixture.sourceRoot, {}),
      /rejected/u,
    );
  });

  await t.test('forged hash', async (nested) => {
    const fixture = await createFixture(nested);
    await assert.rejects(validateTauriBuildAuthorisation(fixture.sourceRoot, {
      ...fixture.created.environment,
      PIUI_TAURI_BUILD_AUTHORISATION_SHA256: sha('f'),
    }), /rejected/u);
  });

  await t.test('group-writable source root', async (nested) => {
    const fixture = await createFixture(nested);
    await chmod(fixture.sourceRoot, 0o770);
    await assert.rejects(
      validateTauriBuildAuthorisation(fixture.sourceRoot, fixture.created.environment),
      /private canonical directory|identity changed/u,
    );
  });
});

test('binds tool bytes and identities across claim, spawn boundary and replay', async (t) => {
  await t.test('same-path replacement before claim', async (nested) => {
    const fixture = await createFixture(nested);
    const replacement = `${fixture.pnpmEntry}.replacement`;
    await writeFile(replacement, 'throw new Error("replacement");\n', { mode: 0o700 });
    await rename(replacement, fixture.pnpmEntry);
    await assert.rejects(
      validateTauriBuildAuthorisation(fixture.sourceRoot, fixture.created.environment),
      /identity or bytes changed/u,
    );
  });

  await t.test('same-path replacement after atomic claim', async (nested) => {
    const fixture = await createFixture(nested);
    const claimed = await validateTauriBuildAuthorisation(
      fixture.sourceRoot,
      fixture.created.environment,
    );
    const replacement = `${fixture.pnpmNode}.replacement`;
    await writeFile(replacement, '#!/bin/sh\nexit 9\n', { mode: 0o700 });
    await rename(replacement, fixture.pnpmNode);
    await assert.rejects(
      revalidateTauriBuildAuthorisation(claimed),
      /identity or bytes changed/u,
    );
  });

  await t.test('single-use authorisation replay', async (nested) => {
    const fixture = await createFixture(nested);
    await validateTauriBuildAuthorisation(fixture.sourceRoot, fixture.created.environment);
    await assert.rejects(
      validateTauriBuildAuthorisation(fixture.sourceRoot, fixture.created.environment),
      /already claimed|could not be claimed/u,
    );
  });
});

test('binds the private build-isolate and frozen-source directory identities', async (t) => {
  const fixture = await createFixture(t);
  const replacement = `${fixture.buildIsolate}.replacement`;
  const original = `${fixture.buildIsolate}.original`;
  t.after(async () => rm(replacement, { force: true, recursive: true }));
  t.after(async () => rm(original, { force: true, recursive: true }));
  await cp(fixture.buildIsolate, replacement, { preserveTimestamps: true, recursive: true });
  await rename(fixture.buildIsolate, original);
  await rename(replacement, fixture.buildIsolate);
  await assert.rejects(
    validateTauriBuildAuthorisation(fixture.sourceRoot, fixture.created.environment),
    /identity changed/u,
  );
});

test('copies the Node and complete pnpm package into the private build isolate', async (t) => {
  const canonicalTemporaryRoot = await realpath(tmpdir());
  const root = await mkdtemp(join(canonicalTemporaryRoot, 'piui-private-build-tools.'));
  t.after(async () => rm(root, { force: true, recursive: true }));
  const buildIsolate = join(root, 'build');
  const pnpmRoot = join(root, 'pnpm', '9.15.0');
  await mkdir(buildIsolate, { mode: 0o700 });
  await mkdir(join(pnpmRoot, 'bin'), { mode: 0o700, recursive: true });
  await mkdir(join(pnpmRoot, 'dist'), { mode: 0o700 });
  const pnpmEntry = join(pnpmRoot, 'bin', 'pnpm.cjs');
  const pnpmNode = join(root, 'source-node');
  await writeFile(pnpmEntry, 'require("../dist/pnpm.cjs");\n', { mode: 0o700 });
  await writeFile(join(pnpmRoot, 'dist', 'pnpm.cjs'), 'module.exports = {};\n', { mode: 0o600 });
  await writeFile(pnpmNode, '#!/bin/sh\nexit 0\n', { mode: 0o700 });
  const authenticatedToolchainWitness = await captureToolchainClosureWitness(root);

  const copied = await preparePrivateTauriBuildTools({
    authenticatedToolchainWitness,
    buildIsolate,
    pnpmEntry,
    pnpmNode,
  });
  assert.match(copied.pnpmEntry, /\/tauri-build-tools\/pnpm\/bin\/pnpm\.cjs$/u);
  assert.match(copied.pnpmNode, /\/tauri-build-tools\/node$/u);
  await writeFile(pnpmEntry, 'throw new Error("replaced");\n', { mode: 0o700 });
  assert.equal(
    await readFile(copied.pnpmEntry, 'utf8'),
    'require("../dist/pnpm.cjs");\n',
  );
});

test('toolchain witness permits the pinned Rust driver without broadening copied-tool bounds', async (t) => {
  const source = await readFile(
    resolve(repositoryRoot, 'scripts/tauri-build-authorisation.mjs'),
    'utf8',
  );
  assert.match(source, /const MAX_TOOL_BYTES = 128 \* 1_048_576;/u);
  assert.match(source, /const MAX_TOOLCHAIN_ENTRY_BYTES = 256 \* 1_048_576;/u);
  assert.match(source, /entry\.size > MAX_TOOLCHAIN_ENTRY_BYTES/u);
  assert.match(source, /before\.size > BigInt\(MAX_TOOL_BYTES\)/u);
  assert.ok(204_378_184 < 256 * 1_048_576);
  assert.ok(204_378_184 > 128 * 1_048_576);

  const fixture = await createPrivateBuildToolsFixture(
    t,
    'piui-large-toolchain-witness-entry.',
  );
  const authenticatedToolchainWitness = withInventoryEntries(
    fixture.authenticatedToolchainWitness,
    [
      { kind: 'directory', path: 'rust-toolchain' },
      { kind: 'directory', path: 'rust-toolchain/lib' },
      {
        executable: false,
        path: 'rust-toolchain/lib/librustc_driver-test.dylib',
        sha256: sha('a'),
        size: 204_378_184,
      },
    ],
  );
  const copied = await preparePrivateTauriBuildTools({
    ...fixture,
    authenticatedToolchainWitness,
  });
  assert.equal(await readFile(copied.pnpmNode, 'utf8'), '#!/bin/sh\nexit 0\n');
});

test('toolchain witness rejects an individual entry above 256 MiB', async (t) => {
  const fixture = await createPrivateBuildToolsFixture(
    t,
    'piui-oversized-toolchain-witness-entry.',
  );
  const authenticatedToolchainWitness = withInventoryEntries(
    fixture.authenticatedToolchainWitness,
    [{
      executable: false,
      path: 'rust-toolchain/lib/oversized.dylib',
      sha256: sha('b'),
      size: (256 * 1_048_576) + 1,
    }],
  );
  await assert.rejects(preparePrivateTauriBuildTools({
    ...fixture,
    authenticatedToolchainWitness,
  }), /Authenticated toolchain closure witness is invalid/u);
});

test('rejects a replacement pnpm ancestor that is absent from the authenticated witness', async (t) => {
  const canonicalTemporaryRoot = await realpath(tmpdir());
  const root = await mkdtemp(join(canonicalTemporaryRoot, 'piui-private-tools-ancestor.'));
  t.after(async () => rm(root, { force: true, recursive: true }));
  const buildIsolate = join(root, 'build');
  const closureRoot = join(root, 'authenticated-toolchain');
  const originalRoot = join(root, 'authenticated-toolchain.original');
  const replacementRoot = join(root, 'authenticated-toolchain.replacement');
  const pnpmEntry = join(closureRoot, 'pnpm-tool', 'bin', 'pnpm.cjs');
  const pnpmNode = join(closureRoot, 'node-tool', 'bin', 'node');
  await mkdir(buildIsolate, { mode: 0o700 });
  await mkdir(dirname(pnpmEntry), { mode: 0o700, recursive: true });
  await mkdir(join(closureRoot, 'pnpm-tool', 'dist'), { mode: 0o700 });
  await mkdir(dirname(pnpmNode), { mode: 0o700, recursive: true });
  await writeFile(pnpmEntry, 'require("../dist/pnpm.cjs");\n', { mode: 0o700 });
  await writeFile(
    join(closureRoot, 'pnpm-tool', 'dist', 'pnpm.cjs'),
    'module.exports = { trusted: true };\n',
    { mode: 0o600 },
  );
  await writeFile(pnpmNode, '#!/bin/sh\nexit 0\n', { mode: 0o700 });
  const authenticatedToolchainWitness = await captureToolchainClosureWitness(closureRoot);

  await cp(closureRoot, replacementRoot, { preserveTimestamps: true, recursive: true });
  await writeFile(
    join(replacementRoot, 'pnpm-tool', 'dist', 'pnpm.cjs'),
    'module.exports = { trusted: false };\n',
    { mode: 0o600 },
  );
  await rename(closureRoot, originalRoot);
  await rename(replacementRoot, closureRoot);

  await assert.rejects(preparePrivateTauriBuildTools({
    authenticatedToolchainWitness,
    buildIsolate,
    pnpmEntry,
    pnpmNode,
  }), /does not match the authenticated toolchain closure witness/u);
});

test('the real private Node and pnpm copies execute the pinned package manager', async (t) => {
  const canonicalTemporaryRoot = await realpath(tmpdir());
  const root = await mkdtemp(join(canonicalTemporaryRoot, 'piui-real-private-tools.'));
  t.after(async () => rm(root, { force: true, recursive: true }));
  const buildIsolate = join(root, 'build');
  const closureRoot = join(root, 'authenticated-toolchain');
  const pnpmRoot = join(closureRoot, 'pnpm-tool');
  const pnpmNode = join(closureRoot, 'node-tool', 'bin', 'node');
  await mkdir(buildIsolate, { mode: 0o700 });
  await mkdir(dirname(pnpmNode), { mode: 0o700, recursive: true });
  const realPnpmRoot = await realpath(join(
    homedir(),
    '.cache/node/corepack/v1/pnpm/9.15.0',
  ));
  await cp(realPnpmRoot, pnpmRoot, { recursive: true });
  await cp(process.execPath, pnpmNode);
  const pnpmEntry = join(pnpmRoot, 'bin', 'pnpm.cjs');
  const authenticatedToolchainWitness = await captureToolchainClosureWitness(closureRoot);
  const copied = await preparePrivateTauriBuildTools({
    authenticatedToolchainWitness,
    buildIsolate,
    pnpmEntry,
    pnpmNode,
  });
  const version = spawnSync(copied.pnpmNode, [copied.pnpmEntry, '--version'], {
    encoding: 'utf8',
    env: { PATH: '/usr/bin:/bin' },
  });
  assert.equal(version.status, 0, version.stderr);
  assert.equal(version.stdout.trim(), '9.15.0');
});

test('real hook build preserves the pre-created generated-root lease and rejects replay', async (t) => {
  const canonicalTemporaryRoot = await realpath(tmpdir());
  const buildIsolate = await mkdtemp(join(canonicalTemporaryRoot, 'piui-real-build-hook.'));
  t.after(async () => rm(buildIsolate, { force: true, recursive: true }));
  const sourceRoot = join(buildIsolate, 'source');
  const scripts = join(sourceRoot, 'scripts');
  const forge = join(sourceRoot, '.forge');
  const cargo = join(sourceRoot, 'src-tauri');
  const dist = join(sourceRoot, 'dist');
  const tools = join(buildIsolate, 'tools');
  for (const path of [sourceRoot, scripts, forge, cargo, dist, tools]) {
    await mkdir(path, { mode: 0o700 });
  }
  for (const name of [
    'architecture-gate-schema.mjs',
    'architecture-source-snapshot.mjs',
    'tauri-build-authorisation.mjs',
    'tauri-build-hook.mjs',
  ]) {
    await cp(join(repositoryRoot, 'scripts', name), join(scripts, name));
  }
  for (const name of ['ARCHITECTURE-GATE', 'FORGE', 'PLAN', 'SPEC', 'UI-DESIGN']) {
    await writeFile(join(forge, `${name}.md`), `${name}\n`, { mode: 0o600 });
  }
  await writeFile(join(sourceRoot, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n', { mode: 0o600 });
  await writeFile(join(cargo, 'Cargo.lock'), 'version = 4\n', { mode: 0o600 });
  const pnpmEntry = join(tools, 'pnpm.cjs');
  await writeFile(pnpmEntry, [
    "const { writeFileSync } = require('node:fs');",
    "const { resolve } = require('node:path');",
    "writeFileSync(resolve(__dirname, '../source/dist/frontend.js'), 'built\\n');",
  ].join('\n'), { mode: 0o700 });
  const snapshot = await snapshotArchitectureSource(sourceRoot);
  const created = await createTauriBuildAuthorisation({
    buildIsolate,
    mode: 'guarded-production',
    nonce: sha('7'),
    pnpmEntry,
    pnpmNode: process.execPath,
    sourceDigest: snapshot.source.digest,
    sourceRoot,
  });
  const environment = {
    ...process.env,
    ...created.environment,
  };
  const first = spawnSync(process.execPath, [join(scripts, 'tauri-build-hook.mjs')], {
    cwd: sourceRoot,
    encoding: 'utf8',
    env: environment,
  });
  assert.equal(first.status, 0, first.stderr);
  assert.equal(await readFile(join(dist, 'frontend.js'), 'utf8'), 'built\n');
  const replay = spawnSync(process.execPath, [join(scripts, 'tauri-build-hook.mjs')], {
    cwd: sourceRoot,
    encoding: 'utf8',
    env: environment,
  });
  assert.notEqual(replay.status, 0);
  assert.match(replay.stderr, /already claimed|could not be claimed/u);
});

test('the raw Tauri frontend hook fails closed despite legacy path variables', () => {
  const result = spawnSync(process.execPath, ['scripts/tauri-build-hook.mjs'], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    env: {
      HOME: process.env.HOME ?? '',
      PATH: process.env.PATH ?? '/usr/bin:/bin',
      PIUI_PNPM_ENTRY: '/usr/bin/true',
      PIUI_PNPM_NODE: '/usr/bin/true',
    },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /authorisation rejected/u);
});
