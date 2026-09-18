import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, link, mkdir, mkdtemp, rename, rm, symlink, writeFile, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';
import {
  architectureSourceAclListingHasExtendedAcl,
  equalArchitectureSourceLease,
  snapshotArchitectureSource,
} from '../../scripts/architecture-source-snapshot.mjs';

const A29_HEADING = '### A.29 — Record and enforce the architecture gate decision\n';
const PLAN_PREFIX = `# Plan

### A.28 — Prove packaged automation and virtualised accessibility feasibility
- [ ] done

${A29_HEADING}- **Goal:** Prevent broad implementation from proceeding on an unproved architecture.
`;
const PLAN_SUFFIX = `
## Phase B — Production foundations
`;
const PLAN_UNCHECKED = `${PLAN_PREFIX}- [ ] done\n${PLAN_SUFFIX}`;
const PLAN_CHECKED = `${PLAN_PREFIX}- [x] done\n${PLAN_SUFFIX}`;

async function createSourceFixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'piui-source-snapshot.'));
  t.after(async () => rm(root, { force: true, recursive: true }));
  await mkdir(join(root, '.forge'), { recursive: true });
  await mkdir(join(root, 'scripts'), { recursive: true });
  await mkdir(join(root, 'src-tauri'), { recursive: true });
  for (const name of ['ARCHITECTURE-GATE', 'FORGE', 'PLAN', 'SPEC', 'UI-DESIGN']) {
    await writeFile(
      join(root, '.forge', `${name}.md`),
      name === 'PLAN' ? PLAN_UNCHECKED : `${name}\n`,
      { mode: 0o600 },
    );
  }
  await writeFile(join(root, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n', { mode: 0o600 });
  await writeFile(join(root, 'src-tauri', 'Cargo.lock'), 'version = 4\n', { mode: 0o600 });
  await writeFile(join(root, 'scripts', 'gate.mjs'), 'export {};\n', { mode: 0o600 });
  return root;
}

test('creates a deterministic snapshot and ignores declared generated output', async (t) => {
  const root = await createSourceFixture(t);
  const initial = await snapshotArchitectureSource(root);
  assert.equal(JSON.parse(initial.inventoryBytes.toString('utf8')).schemaVersion, 2);
  assert.equal(
    initial.source.digest,
    createHash('sha256')
      .update(Buffer.concat([
        Buffer.from('PIUI architecture source snapshot v2\0', 'utf8'),
        initial.inventoryBytes,
      ]))
      .digest('hex'),
  );
  const repeated = await snapshotArchitectureSource(root);
  assert.deepEqual(repeated.source, initial.source);
  assert.deepEqual(repeated.inventory, initial.inventory);

  await mkdir(join(root, 'dist'), { recursive: true });
  await writeFile(join(root, 'dist', 'generated.js'), 'changed\n');
  await mkdir(join(root, 'src-tauri', 'gen', 'schemas'), { recursive: true });
  await writeFile(
    join(root, 'src-tauri', 'gen', 'schemas', 'desktop-schema.json'),
    '{"generated":true}\n',
  );
  const afterGeneratedOutput = await snapshotArchitectureSource(root);
  assert.deepEqual(afterGeneratedOutput.source, initial.source);

  await writeFile(join(root, 'scripts', 'gate.mjs'), 'export const changed = true;\n');
  const afterSourceChange = await snapshotArchitectureSource(root);
  assert.notEqual(afterSourceChange.source.digest, initial.source.digest);
  assert.notEqual(afterSourceChange.source.inventorySha256, initial.source.inventorySha256);
});

test('canonicalises only the exact A.29 completion state byte', async (t) => {
  const root = await createSourceFixture(t);
  const unchecked = await snapshotArchitectureSource(root);
  await writeFile(join(root, '.forge', 'PLAN.md'), PLAN_CHECKED, { mode: 0o600 });
  const checked = await snapshotArchitectureSource(root);

  assert.deepEqual(checked.source, unchecked.source);
  assert.deepEqual(checked.inventory, unchecked.inventory);
  assert.equal(equalArchitectureSourceLease(unchecked, checked), false);
});

test('does not exempt a non-terminal completion-looking line in A.29', async (t) => {
  const root = await createSourceFixture(t);
  const uncheckedExample = `${PLAN_PREFIX}\`\`\`markdown\n- [ ] done\n\`\`\`\n${PLAN_SUFFIX}`;
  const checkedExample = `${PLAN_PREFIX}\`\`\`markdown\n- [x] done\n\`\`\`\n${PLAN_SUFFIX}`;
  await writeFile(join(root, '.forge', 'PLAN.md'), uncheckedExample, { mode: 0o600 });
  const unchecked = await snapshotArchitectureSource(root);
  await writeFile(join(root, '.forge', 'PLAN.md'), checkedExample, { mode: 0o600 });
  const checked = await snapshotArchitectureSource(root);

  assert.notEqual(checked.source.planSha256, unchecked.source.planSha256);
  assert.notEqual(checked.source.inventorySha256, unchecked.source.inventorySha256);
  assert.notEqual(checked.source.digest, unchecked.source.digest);
});

test('binds every PLAN byte outside the unique exact A.29 completion state', async (t) => {
  const variants = [
    ['surrounding A.29 text', PLAN_CHECKED.replace(
      'Prevent broad implementation',
      'Prevent any broad implementation',
    )],
    ['second A.29 checkbox', PLAN_CHECKED.replace(
      '- [x] done\n',
      '- [ ] done\n- [x] done\n',
    )],
    ['A.28 checkbox', PLAN_UNCHECKED.replace(
      '### A.28 — Prove packaged automation and virtualised accessibility feasibility\n- [ ] done',
      '### A.28 — Prove packaged automation and virtualised accessibility feasibility\n- [x] done',
    )],
    ['uppercase A.29 checkbox', PLAN_UNCHECKED.replace(
      `${A29_HEADING}- **Goal:** Prevent broad implementation from proceeding on an unproved architecture.\n- [ ] done`,
      `${A29_HEADING}- **Goal:** Prevent broad implementation from proceeding on an unproved architecture.\n- [X] done`,
    )],
    ['duplicate A.29 heading', PLAN_CHECKED.replace(
      A29_HEADING,
      `${A29_HEADING}${A29_HEADING}`,
    )],
    ['appended byte', `${PLAN_CHECKED}x`],
  ];

  for (const [label, plan] of variants) {
    await t.test(label, async (nested) => {
      const root = await createSourceFixture(nested);
      const initial = await snapshotArchitectureSource(root);
      await writeFile(join(root, '.forge', 'PLAN.md'), plan, { mode: 0o600 });
      const changed = await snapshotArchitectureSource(root);
      assert.notEqual(changed.source.planSha256, initial.source.planSha256);
      assert.notEqual(changed.source.inventorySha256, initial.source.inventorySha256);
      assert.notEqual(changed.source.digest, initial.source.digest);
    });
  }
});

test('binds executable state and the exact architecture control documents', async (t) => {
  const root = await createSourceFixture(t);
  const initial = await snapshotArchitectureSource(root);
  await chmod(join(root, 'scripts', 'gate.mjs'), 0o700);
  const executable = await snapshotArchitectureSource(root);
  assert.notEqual(executable.source.digest, initial.source.digest);

  await mkdir(join(root, '.forge', 'ui-mockups'), { recursive: true });
  await writeFile(join(root, '.forge', 'ui-mockups', 'draft.html'), 'ignored\n');
  const ignoredPlanningOutput = await snapshotArchitectureSource(root);
  assert.deepEqual(ignoredPlanningOutput.source, executable.source);

  await writeFile(join(root, '.forge', 'FORGE.md'), 'changed control document\n');
  const changedControl = await snapshotArchitectureSource(root);
  assert.notEqual(changedControl.source.forgeSha256, executable.source.forgeSha256);
  assert.notEqual(changedControl.source.digest, executable.source.digest);
});

test('rejects symlinks, hard links, secret-shaped files and unclassified roots', async (t) => {
  await t.test('symlink', async (nested) => {
    const root = await createSourceFixture(nested);
    await symlink(join(root, 'scripts', 'gate.mjs'), join(root, 'scripts', 'alias.mjs'));
    await assert.rejects(snapshotArchitectureSource(root), /unsupported entry/u);
  });

  await t.test('hard link', async (nested) => {
    const root = await createSourceFixture(nested);
    await link(join(root, 'scripts', 'gate.mjs'), join(root, 'scripts', 'alias.mjs'));
    await assert.rejects(snapshotArchitectureSource(root), /single-link regular files/u);
  });

  await t.test('secret-shaped file', async (nested) => {
    const root = await createSourceFixture(nested);
    await writeFile(join(root, '.env.production'), 'TOKEN=fixture\n');
    await assert.rejects(snapshotArchitectureSource(root), /secret-shaped file/u);
  });

  await t.test('unclassified root directory', async (nested) => {
    const root = await createSourceFixture(nested);
    await mkdir(join(root, 'misc'), { recursive: true });
    await assert.rejects(snapshotArchitectureSource(root), /unclassified root directory/u);
  });
});

test('rejects source files and directories writable by group or world', async (t) => {
  await t.test('file', async (nested) => {
    const root = await createSourceFixture(nested);
    await chmod(join(root, 'scripts', 'gate.mjs'), 0o666);
    await assert.rejects(snapshotArchitectureSource(root), /non-writable by group or world/u);
  });

  await t.test('directory', async (nested) => {
    const root = await createSourceFixture(nested);
    await chmod(join(root, 'scripts'), 0o777);
    await assert.rejects(snapshotArchitectureSource(root), /non-writable by group or world/u);
  });
});

test('detects extended ACL listings and rejects an actual source ACL on macOS', async (t) => {
  assert.equal(architectureSourceAclListingHasExtendedAcl(
    '-rw-r--r--+ 1 owner staff 12 Jul 31 00:00 source.mjs\n 0: everyone allow read\n',
    1,
  ), true);
  assert.equal(architectureSourceAclListingHasExtendedAcl(
    '-rw-r--r--@ 1 owner staff 12 Jul 31 00:00 source.mjs\n',
    1,
  ), false);

  if (process.platform !== 'darwin') return;
  const root = await createSourceFixture(t);
  const path = join(root, 'scripts', 'gate.mjs');
  const acl = spawnSync('/bin/chmod', ['+a', 'everyone allow read', path], {
    encoding: 'utf8',
  });
  assert.equal(acl.status, 0, acl.stderr);
  await assert.rejects(snapshotArchitectureSource(root), /extended ACL/u);
});

test('the non-reproducible lease detects ABA rewrites and same-byte root replacement', async (t) => {
  await t.test('file rewrite and restore', async (nested) => {
    const root = await createSourceFixture(nested);
    const path = join(root, 'scripts', 'gate.mjs');
    const initial = await snapshotArchitectureSource(root);
    await writeFile(path, 'export const transient = true;\n', { mode: 0o600 });
    await writeFile(path, 'export {};\n', { mode: 0o600 });
    const restored = await snapshotArchitectureSource(root);
    assert.deepEqual(restored.source, initial.source);
    assert.equal(equalArchitectureSourceLease(initial, restored), false);
  });

  await t.test('root replacement', async (nested) => {
    const root = await createSourceFixture(nested);
    const replacement = `${root}.replacement`;
    const original = `${root}.original`;
    nested.after(async () => rm(replacement, { force: true, recursive: true }));
    nested.after(async () => rm(original, { force: true, recursive: true }));
    const initial = await snapshotArchitectureSource(root);
    await cp(root, replacement, { preserveTimestamps: true, recursive: true });
    await rename(root, original);
    await rename(replacement, root);
    const replaced = await snapshotArchitectureSource(root);
    assert.deepEqual(replaced.source, initial.source);
    assert.equal(equalArchitectureSourceLease(initial, replaced), false);
  });
});
