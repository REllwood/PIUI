import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  copyFile,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

const repositoryRoot = resolve(import.meta.dirname, '../..');
const skipped = 'skipped: local-only documentation trail not present';
const scripts = [
  'check-docs.mjs',
  'check-forge-close.mjs',
  'check-security-record.mjs',
  'local-documentation-trail.mjs',
  'security-command-inventory.mjs',
];
const trackedFiles = [
  'CHANGELOG.md',
  'README.md',
  'src-tauri/capabilities/default.json',
  'src-tauri/src/lib.rs',
  'src-tauri/tauri.conf.json',
];
const docsTrail = {
  'docs/PRIVACY.md': '# Privacy\n\nNo telemetry leaves the machine.\n',
  'docs/RELEASING.md': '# Releasing\n\nDeveloper ID signing, notarisation, the updater and hosting are external gates.\n',
  'docs/SECURITY.md': '# Security\n\nThe WebView holds no Keychain secret. OAuth, workspace trust and update checks are native.\n',
  'docs/TROUBLESHOOTING.md': '# Troubleshooting\n\nSee [security](SECURITY.md).\n',
  'docs/UPDATES.md': '# Updates\n\nUpdates are disabled until a signed update channel exists.\n',
  'docs/architecture/README.md': '# Architecture\n\nSee [data flow](data-flow.md).\n',
  'docs/architecture/data-flow.md': '# Data flow\n\nEvery executable approval and process lifecycle step is native.\n',
  'docs/testing/MANUAL-ACCESSIBILITY.md': '# Manual accessibility\n\nVoiceOver review is manual.\n',
  'docs/testing/README.md': '# Testing\n\nSee [manual accessibility](MANUAL-ACCESSIBILITY.md).\n',
};
const forgeSecurity = '# Security record\n\nRound 1\nRound 2\nRound 3\nRound 4\n';

async function fixtureRoot(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'piui-local-trail.')));
  t.after(async () => rm(root, { force: true, recursive: true }));
  for (const name of scripts) {
    await mkdir(join(root, 'scripts'), { recursive: true });
    await copyFile(join(repositoryRoot, 'scripts', name), join(root, 'scripts', name));
  }
  for (const path of trackedFiles) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await copyFile(join(repositoryRoot, path), join(root, path));
  }
  return root;
}

async function write(root, files) {
  for (const [path, text] of Object.entries(files)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), text);
  }
}

function run(root, script, ...args) {
  const result = spawnSync(process.execPath, [join('scripts', script), ...args], {
    cwd: root,
    encoding: 'utf8',
    env: { PATH: '/usr/bin:/bin' },
    timeout: 60_000,
  });
  return { output: `${result.stdout}${result.stderr}`, status: result.status };
}

async function completeTrail(root) {
  await write(root, { ...docsTrail, '.forge/SECURITY.md': forgeSecurity });
  const generated = run(root, 'security-command-inventory.mjs');
  assert.equal(generated.status, 0, generated.output);
}

test('a fresh clone without the local trail skips each trail check', async (t) => {
  const root = await fixtureRoot(t);
  // Gate evidence alone does not make the planning record present.
  await mkdir(join(root, '.forge', 'evidence', 'architecture-gate'), { recursive: true });
  for (const [script, ...args] of [
    ['check-docs.mjs'],
    ['check-security-record.mjs'],
    ['check-forge-close.mjs'],
    ['security-command-inventory.mjs', '--check'],
  ]) {
    const result = run(root, script, ...args);
    assert.equal(result.status, 0, `${script}: ${result.output}`);
    assert.ok(result.output.includes(skipped), `${script}: ${result.output}`);
  }
  assert.match(run(root, 'check-docs.mjs').output, /2 tracked files checked/u);
  assert.match(run(root, 'check-security-record.mjs').output, /Native capability and CSP: current/u);
});

test('tracked capability and CSP are still enforced without the trail', async (t) => {
  const root = await fixtureRoot(t);
  await writeFile(
    join(root, 'src-tauri/capabilities/default.json'),
    `${JSON.stringify({ permissions: ['core:default', 'shell:allow-open'] })}\n`,
  );
  const result = run(root, 'check-security-record.mjs');
  assert.notEqual(result.status, 0);
  assert.match(result.output, /Main capability broadened/u);
});

test('a complete trail is validated strictly', async (t) => {
  const root = await fixtureRoot(t);
  await completeTrail(root);
  const docs = run(root, 'check-docs.mjs');
  assert.equal(docs.status, 0, docs.output);
  assert.match(docs.output, /Documentation: 12 files checked/u);
  const security = run(root, 'check-security-record.mjs');
  assert.equal(security.status, 0, security.output);
  assert.match(security.output, /Native command inventory: current/u);
  assert.match(security.output, /Security threat model and data-flow inventory: current/u);

  await writeFile(join(root, 'docs/UPDATES.md'), '# Updates\n\nThe color of the icon changes.\n');
  const spelling = run(root, 'check-docs.mjs');
  assert.notEqual(spelling.status, 0);
  assert.match(spelling.output, /use Australian English/u);

  await writeFile(join(root, '.forge/SECURITY.md'), '# Security record\n\nRound 1\n');
  const rounds = run(root, 'check-security-record.mjs');
  assert.notEqual(rounds.status, 0);
  assert.match(rounds.output, /Security record is missing Round 2/u);
});

test('a partially present trail fails instead of skipping', async (t) => {
  const partialDocs = await fixtureRoot(t);
  await write(partialDocs, { 'docs/PRIVACY.md': docsTrail['docs/PRIVACY.md'] });
  const docs = run(partialDocs, 'check-docs.mjs');
  assert.notEqual(docs.status, 0);
  assert.match(docs.output, /Local documentation trail is incomplete: docs\/SECURITY\.md is missing/u);
  const inventory = run(partialDocs, 'security-command-inventory.mjs', '--check');
  assert.notEqual(inventory.status, 0);
  assert.match(inventory.output, /Native command inventory is stale/u);

  const forgeOnly = await fixtureRoot(t);
  await write(forgeOnly, { '.forge/SECURITY.md': forgeSecurity });
  const security = run(forgeOnly, 'check-security-record.mjs');
  assert.notEqual(security.status, 0);
  assert.match(security.output, /Local documentation trail is incomplete: docs\/SECURITY\.md is missing/u);

  const planOnly = await fixtureRoot(t);
  await write(planOnly, { '.forge/PLAN.md': '# Plan\n' });
  const close = run(planOnly, 'check-forge-close.mjs');
  assert.notEqual(close.status, 0);
  assert.match(close.output, /Local documentation trail is incomplete: \.forge\/FORGE\.md is missing/u);
});
