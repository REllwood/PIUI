import assert from 'node:assert/strict';
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  ARCHITECTURE_PROOF_CONTRACTS,
  ARCHITECTURE_PROOF_IDS,
  canonicalArchitectureJson,
  createArchitecturePassMarker,
  sha256Bytes,
} from '../../scripts/architecture-gate-schema.mjs';
import { snapshotArchitectureSource } from '../../scripts/architecture-source-snapshot.mjs';
import { validateLatestArchitectureGate } from '../../scripts/check-architecture-gate.mjs';
import {
  architectureProofBatch,
  architectureSha,
} from './architecture-proof-fixtures.mjs';

const sha = architectureSha;
function line(value) {
  return Buffer.from(`${canonicalArchitectureJson(value)}\n`, 'utf8');
}

async function createRepository(t) {
  const root = await mkdtemp(join(tmpdir(), 'piui-gate-check.'));
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

async function recordPassingRun(root, runId = '20260731T120000000Z-11111111111111111111111111111111') {
  const source = (await snapshotArchitectureSource(root)).source;
  const productionBatch = architectureProofBatch('production', undefined, source.digest);
  const credentialBatch = architectureProofBatch(
    'credential',
    productionBatch.artifact,
    source.digest,
  );
  const approvalBatch = architectureProofBatch(
    'approval',
    productionBatch.artifact,
    source.digest,
  );
  const automationBatch = architectureProofBatch(
    'automation',
    productionBatch.artifact,
    source.digest,
  );
  const batches = {
    approval: approvalBatch,
    automation: automationBatch,
    credential: credentialBatch,
    production: productionBatch,
  };
  const proofValues = Object.assign({}, ...Object.values(batches).map((batch) => batch.proofs));
  const evidence = Object.fromEntries(
    ARCHITECTURE_PROOF_IDS.map((id) => [id, line(proofValues[id])]),
  );
  const proofs = Object.fromEntries(ARCHITECTURE_PROOF_IDS.map((id) => {
    const contract = ARCHITECTURE_PROOF_CONTRACTS[id];
    const artifact = batches[contract.batchId].artifact;
    return [id, {
      artifactFingerprint: artifact.fingerprint,
      artifactKind: contract.artifactKind,
      commandId: contract.commandId,
      evidenceSha256: sha256Bytes(evidence[id]),
      sourceDigest: source.digest,
      status: 'pass',
    }];
  }));
  const results = {
    artifacts: {
      approvalTwin: approvalBatch.artifact,
      automationTwin: automationBatch.artifact,
      credentialTwin: credentialBatch.artifact,
      production: productionBatch.artifact,
    },
    externalReleaseGates: {
      developerId: 'not-provided',
      distributionAuthorised: false,
      notarisation: 'not-provided',
      updaterHosting: 'not-provided',
      updaterSigning: 'not-provided',
    },
    limitations: {
      automationConformanceEquivalence: 'not-claimed',
      publicDistribution: 'not-authorised',
      trustedExtensionContainment: 'not-claimed',
    },
    proofs,
    schemaVersion: 1,
    source,
    target: 'aarch64-apple-darwin',
  };
  const run = join(root, '.forge', 'evidence', 'architecture-gate', 'runs', runId);
  await mkdir(join(run, 'proofs'), { recursive: true, mode: 0o700 });
  const startedAt = '2026-07-31T12:00:00.000Z';
  await writeFile(join(run, 'started.json'), line({
    runId,
    schemaVersion: 1,
    sourceDigest: source.digest,
    startedAt,
    status: 'started',
    target: 'aarch64-apple-darwin',
  }), { mode: 0o600 });
  for (const id of ARCHITECTURE_PROOF_IDS) {
    await writeFile(join(run, 'proofs', `${id}.json`), evidence[id], { mode: 0o600 });
  }
  await writeFile(join(run, 'results.json'), line(results), { mode: 0o600 });
  await writeFile(join(run, 'pass-marker.json'), line(createArchitecturePassMarker(results)), {
    mode: 0o600,
  });
  return { results, run };
}

test('accepts only the complete latest same-source architecture run', async (t) => {
  const root = await createRepository(t);
  const { results } = await recordPassingRun(root);
  const accepted = await validateLatestArchitectureGate(root);
  assert.deepEqual(accepted, {
    decision: 'pass',
    distributionAuthorised: false,
    productionFingerprint: results.artifacts.production.fingerprint,
    runId: '20260731T120000000Z-11111111111111111111111111111111',
    sourceDigest: results.source.digest,
    target: 'aarch64-apple-darwin',
  });
});

test('rejects stale source and altered proof bytes', async (t) => {
  await t.test('stale source', async (nested) => {
    const root = await createRepository(nested);
    await recordPassingRun(root);
    await writeFile(join(root, '.forge', 'PLAN.md'), 'changed\n', { mode: 0o600 });
    await assert.rejects(validateLatestArchitectureGate(root), /proof source is stale/u);
  });

  await t.test('altered proof', async (nested) => {
    const root = await createRepository(nested);
    const { run } = await recordPassingRun(root);
    await writeFile(join(run, 'proofs', 'A.25.json'), line({ proof: 'A.25', status: 'changed' }), {
      mode: 0o600,
    });
    await assert.rejects(validateLatestArchitectureGate(root), /Architecture gate blocked/u);
  });

  await t.test('semantically invalid proof with a matching hash and marker', async (nested) => {
    const root = await createRepository(nested);
    const { results, run } = await recordPassingRun(root);
    const forgedEvidence = line({});
    results.proofs['A.25'].evidenceSha256 = sha256Bytes(forgedEvidence);
    await writeFile(join(run, 'proofs', 'A.25.json'), forgedEvidence, { mode: 0o600 });
    await writeFile(join(run, 'results.json'), line(results), { mode: 0o600 });
    await writeFile(join(run, 'pass-marker.json'), line(createArchitecturePassMarker(results)), {
      mode: 0o600,
    });
    await assert.rejects(validateLatestArchitectureGate(root), /Architecture gate blocked/u);
  });
});

test('rejects every valid-looking replay after results and marker hashes are recomputed', async (t) => {
  for (const id of ARCHITECTURE_PROOF_IDS) {
    await t.test(id, async (nested) => {
      const root = await createRepository(nested);
      const { results, run } = await recordPassingRun(root);
      const proofPath = join(run, 'proofs', `${id}.json`);
      const envelope = JSON.parse(await readFile(proofPath, 'utf8'));
      envelope.sourceDigest = sha('f');
      const replayedEvidence = line(envelope);
      results.proofs[id].evidenceSha256 = sha256Bytes(replayedEvidence);
      await writeFile(proofPath, replayedEvidence, { mode: 0o600 });
      await writeFile(join(run, 'results.json'), line(results), { mode: 0o600 });
      await writeFile(join(run, 'pass-marker.json'), line(createArchitecturePassMarker(results)), {
        mode: 0o600,
      });
      await assert.rejects(validateLatestArchitectureGate(root), /Architecture gate blocked/u);
    });
  }
});

test('rejects altered artefact runtime metadata after the marker is recomputed', async (t) => {
  const root = await createRepository(t);
  const { results, run } = await recordPassingRun(root);
  for (const artifact of Object.values(results.artifacts)) {
    artifact.nodeSha256 = sha('c');
    artifact.sidecarSha256 = sha('d');
  }
  await writeFile(join(run, 'results.json'), line(results), { mode: 0o600 });
  await writeFile(join(run, 'pass-marker.json'), line(createArchitecturePassMarker(results)), {
    mode: 0o600,
  });
  await assert.rejects(validateLatestArchitectureGate(root), /Architecture gate blocked/u);
});

test('a newer incomplete run prevents reuse of an older pass', async (t) => {
  const root = await createRepository(t);
  await recordPassingRun(root);
  const latest = join(
    root,
    '.forge/evidence/architecture-gate/runs',
    '20260731T120001000Z-22222222222222222222222222222222',
  );
  await mkdir(latest, { recursive: true, mode: 0o700 });
  await assert.rejects(validateLatestArchitectureGate(root), /Architecture gate blocked/u);
});

test('rejects linked or extra run material', async (t) => {
  await t.test('hard-linked proof', async (nested) => {
    const root = await createRepository(nested);
    const { run } = await recordPassingRun(root);
    await link(join(run, 'proofs', 'A.21.json'), join(run, 'linked-proof.json'));
    await assert.rejects(validateLatestArchitectureGate(root), /Architecture gate blocked/u);
  });

  await t.test('group-writable result', async (nested) => {
    const root = await createRepository(nested);
    const { run } = await recordPassingRun(root);
    await chmod(join(run, 'results.json'), 0o620);
    await assert.rejects(validateLatestArchitectureGate(root), /Architecture gate blocked/u);
  });
});
