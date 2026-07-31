import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile, readdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const virtualStore = resolve(repositoryRoot, 'node_modules/.pnpm');
const require = createRequire(import.meta.url);

async function installedPackageRoots(packageName) {
  const prefix = `${packageName.replace('/', '+')}@`;
  const entries = await readdir(virtualStore, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isDirectory() && entry.name.startsWith(prefix))
    .map((entry) => resolve(virtualStore, entry.name, 'node_modules', packageName))
    .sort();
}

async function activeLockVersions(packageName) {
  const lockfile = await readFile(resolve(repositoryRoot, 'pnpm-lock.yaml'), 'utf8');
  const packages = lockfile.slice(lockfile.indexOf('\npackages:\n'));
  const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  return new Set([...packages.matchAll(
    new RegExp(`^  ${escaped}@([^:]+):`, 'gmu'),
  )].map((match) => match[1]));
}

test('every installed brace-expansion line enforces the maintained output bound', async () => {
  const packageRoots = await installedPackageRoots('brace-expansion');
  const activeVersions = await activeLockVersions('brace-expansion');
  const versions = [];
  for (const packageRoot of packageRoots) {
    const manifest = JSON.parse(await readFile(resolve(packageRoot, 'package.json'), 'utf8'));
    if (!activeVersions.has(manifest.version)) continue;
    versions.push(manifest.version);
    const probe = spawnSync(process.execPath, [
      '--max-old-space-size=256',
      '--input-type=commonjs',
      '--eval',
      `
        const loaded = require(process.argv[1]);
        const expand = typeof loaded === 'function' ? loaded : loaded.expand;
        if (typeof expand !== 'function') throw new Error('missing expansion entry point');
        const ordinary = expand('a{b,c}d');
        if (JSON.stringify(ordinary) !== '["abd","acd"]') {
          throw new Error('ordinary expansion compatibility changed');
        }
        const expanded = expand('{a,b}'.repeat(1500));
        const characters = expanded.reduce((total, value) => total + value.length, 0);
        if (expanded.length > 100000 || characters > 4000000) {
          throw new Error('expansion output exceeded its maintained bound');
        }
        const part = '{' + '0'.repeat(50) + '1..100000}';
        const alternatives = expand('{' + Array(400).fill(part).join(',') + '}');
        const alternativeCharacters = alternatives.reduce(
          (total, value) => total + value.length,
          0,
        );
        if (alternativeCharacters > 4000000) {
          throw new Error('aggregate comma alternatives exceeded the maintained bound');
        }
        const padded = expand('{' + '0'.repeat(400000) + '1..100000}');
        const paddedCharacters = padded.reduce((total, value) => total + value.length, 0);
        if (paddedCharacters > 4000000) {
          throw new Error('padded sequence exceeded the maintained bound');
        }
      `,
      packageRoot,
    ], {
      encoding: 'utf8',
      maxBuffer: 64 * 1024,
      timeout: 10_000,
    });
    assert.equal(
      probe.status,
      0,
      `brace-expansion ${manifest.version} bound probe failed: ${probe.error?.message ?? probe.stderr}`,
    );
    assert.equal(probe.signal, null);
  }
  assert.deepEqual([...activeVersions].sort(), ['1.1.18', '2.1.4', '5.0.9']);
  assert.deepEqual([...new Set(versions)].sort(), [...activeVersions].sort());
});

test('the WebdriverIO Mocha closure uses the fixed serializer line', async () => {
  const packageRoots = await installedPackageRoots('serialize-javascript');
  const installed = await Promise.all(packageRoots.map(async (packageRoot) => ({
    manifest: JSON.parse(await readFile(resolve(packageRoot, 'package.json'), 'utf8')),
    packageRoot,
  })));
  const active = installed.filter(({ manifest }) => manifest.version === '7.0.5');
  assert.equal(active.length, 1);
  const [{ manifest, packageRoot }] = active;
  assert.equal(manifest.version, '7.0.5');
  const serialize = require(packageRoot);
  assert.equal(typeof serialize, 'function');
  assert.doesNotMatch(serialize({ value: '</script>' }), /<\/script>/u);
  const lockfile = await readFile(resolve(repositoryRoot, 'pnpm-lock.yaml'), 'utf8');
  assert.doesNotMatch(lockfile, /^\s{2}serialize-javascript@6\./mu);
  assert.match(lockfile, /^\s{2}serialize-javascript@7\.0\.5:/mu);
});

test('the audit exception is limited to verified brace-expansion backports', async () => {
  const manifest = JSON.parse(await readFile(resolve(repositoryRoot, 'package.json'), 'utf8'));
  assert.deepEqual(manifest.pnpm?.auditConfig?.ignoreGhsas, [
    'GHSA-mh99-v99m-4gvg',
  ]);
  const workspace = await readFile(resolve(repositoryRoot, 'pnpm-workspace.yaml'), 'utf8');
  assert.match(workspace, /1\.1\.18 and 2\.1\.4 releases are maintained security backports/u);
  assert.match(workspace, /5\.0\.9 closes both known v5 mitigation bypasses/u);
});
