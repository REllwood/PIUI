import assert from 'node:assert/strict';
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { canonicalArchitectureJson } from '../../scripts/architecture-gate-schema.mjs';
import { recordArchitectureGate } from '../../scripts/record-architecture-gate.mjs';
import {
  architectureProofBatch,
  architectureSha,
} from './architecture-proof-fixtures.mjs';

const sha = architectureSha;

async function createRepository(t) {
  const root = await mkdtemp(join(tmpdir(), 'piui-gate-record.'));
  t.after(async () => rm(root, { force: true, recursive: true }));
  await mkdir(join(root, '.forge'), { recursive: true, mode: 0o700 });
  await mkdir(join(root, 'src-tauri'), { recursive: true, mode: 0o700 });
  for (const name of ['ARCHITECTURE-GATE', 'FORGE', 'PLAN', 'SPEC', 'UI-DESIGN']) {
    await writeFile(join(root, '.forge', `${name}.md`), `${name}\n`, { mode: 0o600 });
  }
  await writeFile(join(root, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n', { mode: 0o600 });
  await writeFile(join(root, 'src-tauri', 'Cargo.lock'), 'version = 4\n', { mode: 0o600 });
  return root;
}

function fakeExecutor() {
  let production;
  return async ({ batchId, productionArtifact, sourceDigest }) => {
    if (batchId === 'production') {
      const batch = architectureProofBatch(batchId, undefined, sourceDigest);
      production = batch.artifact;
      return Buffer.from(`${canonicalArchitectureJson(batch)}\n`);
    }
    assert.deepEqual(productionArtifact, production);
    const value = architectureProofBatch(batchId, production, sourceDigest);
    return Buffer.from(`${canonicalArchitectureJson(value)}\n`);
  };
}

test('records an append-only, self-validating architecture decision', async (t) => {
  const root = await createRepository(t);
  const result = await recordArchitectureGate(root, {
    executeBatch: fakeExecutor(),
    nonce: '11111111111111111111111111111111',
    now: () => new Date('2026-07-31T12:00:00.000Z'),
  });
  assert.equal(result.decision, 'pass');
  assert.equal(result.distributionAuthorised, false);
  assert.equal(result.productionFingerprint, sha('1'));
  assert.equal(result.runId, '20260731T120000000Z-11111111111111111111111111111111');

  const run = join(root, '.forge/evidence/architecture-gate/runs', result.runId);
  assert.deepEqual((await readdir(run)).sort(), [
    'pass-marker.json',
    'proofs',
    'results.json',
    'started.json',
  ]);
  assert.equal((await readdir(join(run, 'proofs'))).length, 8);
});

test('refuses semantically invalid proof evidence before publishing a pass marker', async (t) => {
  const root = await createRepository(t);
  const validExecutor = fakeExecutor();
  const executeBatch = async (request) => {
    const bytes = await validExecutor(request);
    if (request.batchId !== 'production') return bytes;
    const value = JSON.parse(bytes.toString('utf8'));
    value.proofs['A.21'].evidence = {};
    return Buffer.from(`${canonicalArchitectureJson(value)}\n`);
  };
  await assert.rejects(recordArchitectureGate(root, {
    executeBatch,
    nonce: '33333333333333333333333333333333',
    now: () => new Date('2026-07-31T12:00:02.000Z'),
  }));
  const runs = join(root, '.forge/evidence/architecture-gate/runs');
  const [runId] = await readdir(runs);
  assert.deepEqual((await readdir(join(runs, runId))).sort(), [
    'failure.json',
    'started.json',
  ]);
});

test('retains a failed latest run as a blocker without leaking diagnostics', async (t) => {
  const root = await createRepository(t);
  const executeBatch = async (request) => {
    if (request.batchId === 'credential') throw new Error('/private/secret diagnostic');
    return fakeExecutor()(request);
  };
  await assert.rejects(recordArchitectureGate(root, {
    executeBatch,
    nonce: '22222222222222222222222222222222',
    now: () => new Date('2026-07-31T12:00:01.000Z'),
  }));
  const runs = join(root, '.forge/evidence/architecture-gate/runs');
  const [runId] = await readdir(runs);
  const failure = JSON.parse(await readFile(join(runs, runId, 'failure.json'), 'utf8'));
  assert.deepEqual(failure, {
    batchId: 'credential',
    reasonCode: 'architecture-proof-failed',
    runId,
    schemaVersion: 1,
    status: 'failed',
  });
});
