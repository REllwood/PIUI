import { afterEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { chmod, link, lstat, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import {
  cloneRuntimeClosureNative,
  verifyExecutionCopy,
} from '../../scripts/run-packaged-probe.mjs';
import { NODE_PATH, SIDECAR_ROOT, sha256 } from './bundle-inspection.mjs';

const roots = [];
afterEach(async () => {
  while (roots.length) {
    const root = roots.pop();
    await chmod(root, 0o700).catch(() => {});
    await rm(root, { recursive: true, force: true });
  }
});

async function fixture() {
  const root = await mkdtemp(resolve(tmpdir(), 'piui-a22-copy-test-'));
  roots.push(root);
  const bundleRoot = resolve(root, 'bundle');
  const runtimeRoot = resolve(root, 'isolate/runtime');
  const node = Buffer.from('native-node');
  const entry = Buffer.from('export const packaged = true;\n');
  await mkdir(resolve(bundleRoot, 'Contents/MacOS'), { recursive: true });
  await mkdir(resolve(bundleRoot, SIDECAR_ROOT, 'dist'), { recursive: true });
  await writeFile(resolve(bundleRoot, NODE_PATH), node, { mode: 0o555 });
  await writeFile(resolve(bundleRoot, SIDECAR_ROOT, 'dist/entry.js'), entry, { mode: 0o444 });
  await mkdir(resolve(root, 'isolate'), { mode: 0o700 });
  await cloneRuntimeClosureNative({ bundleRoot, runtimeRoot });
  const rootItem = await lstat(runtimeRoot);
  const copy = {
    runtimeRoot,
    rootIdentity: { dev: rootItem.dev, ino: rootItem.ino },
    expectedDirectories: ['sidecar/', 'sidecar/dist/'],
    expectedFiles: new Map([
      ['node', { bytes: node.length, sha256: sha256(node) }],
      ['sidecar/dist/entry.js', { bytes: entry.length, sha256: sha256(entry) }],
    ]),
  };
  copy.witnesses = await verifyExecutionCopy(copy);
  return { runtimeRoot, copy };
}

test('native runtime clone is exact, private and identity-bound on revalidation', async () => {
  const { runtimeRoot, copy } = await fixture();
  await verifyExecutionCopy(copy);
  assert.equal(copy.witnesses.size, 2);
  assert.equal((await lstat(resolve(runtimeRoot, 'node'))).mode & 0o777, 0o500);
  assert.equal((await lstat(resolve(runtimeRoot, 'sidecar/dist/entry.js'))).mode & 0o777, 0o400);

  await chmod(resolve(runtimeRoot, 'sidecar/dist/entry.js'), 0o600);
  await writeFile(resolve(runtimeRoot, 'sidecar/dist/entry.js'), 'forged content with another length');
  await chmod(resolve(runtimeRoot, 'sidecar/dist/entry.js'), 0o400);
  await assert.rejects(verifyExecutionCopy(copy), /A\.22 packaged probe rejected/);
});

test('execution-copy verification rejects links and extra directory entries', async () => {
  let value = await fixture();
  await link(resolve(value.runtimeRoot, 'sidecar/dist/entry.js'), resolve(value.runtimeRoot, 'sidecar/dist/alias.js'));
  await assert.rejects(verifyExecutionCopy(value.copy), /A\.22 packaged probe rejected/);

  value = await fixture();
  await symlink('entry.js', resolve(value.runtimeRoot, 'sidecar/dist/alias.js'));
  await assert.rejects(verifyExecutionCopy(value.copy), /A\.22 packaged probe rejected/);

  value = await fixture();
  await mkdir(resolve(value.runtimeRoot, 'sidecar/extra'));
  await assert.rejects(verifyExecutionCopy(value.copy), /A\.22 packaged probe rejected/);
});
