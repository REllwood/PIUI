import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
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
import { useFixtureAutomationSigningPolicy } from './helpers/automation-signing-policy.mjs';

useFixtureAutomationSigningPolicy();

const sha = architectureSha;
const recordSource = await readFile(
  new URL('../../scripts/record-architecture-gate.mjs', import.meta.url),
  'utf8',
);

test('forwards only an exact validated transcript for the automation batch', () => {
  const executor = recordSource.slice(
    recordSource.indexOf('async function executeDefaultBatch'),
    recordSource.indexOf('export async function recordArchitectureGate'),
  );
  assert.match(
    executor,
    /batchId === 'automation'\s*\? createA28ProgressTranscriptForwarder/u,
  );
  assert.match(executor, /stderrObserver: \(bytes\) => progress\.push\(bytes\)/u);
  assert.match(executor, /progress\.finish\(\{ allowEmpty: true \}\)/u);
  assert.match(executor, /!result\.stderr\.equals\(forwardedStderr\)/u);
  assert.doesNotMatch(executor, /\.\.\.process\.env/u);
  for (const key of ['HOME', 'LANG', 'LC_ALL', 'PATH', 'TMPDIR']) {
    assert.match(executor, new RegExp(`\\b${key}:`, 'u'));
  }
});

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

function fakeExecutor(requests = []) {
  let production;
  return async (request) => {
    requests.push(request);
    const { batchId, productionArtifact, sourceDigest } = request;
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
  const requests = [];
  const result = await recordArchitectureGate(root, {
    executeBatch: fakeExecutor(requests),
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
  const startedBytes = await readFile(join(run, 'started.json'));
  const contextSha256 = createHash('sha256').update(startedBytes).digest('hex');
  assert.equal(requests.length, 4);
  for (const request of requests) {
    assert.equal(request.architectureGateRunId, result.runId);
    assert.equal(request.architectureGateRunContextSha256, contextSha256);
  }
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
