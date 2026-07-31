import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ARCHITECTURE_PROOF_CONTRACTS,
  ARCHITECTURE_PROOF_IDS,
  canonicalArchitectureJson,
} from '../../scripts/architecture-gate-schema.mjs';
import {
  assertArchitectureProofBatch,
  createArchitectureProofEnvelope,
  parseArchitectureProofBatch,
} from '../../scripts/architecture-proof-batch.mjs';
import {
  architectureProofBatch,
  architectureSha,
} from './architecture-proof-fixtures.mjs';

const sha = architectureSha;

function batch() {
  return architectureProofBatch('production', undefined, sha('4'));
}

test('accepts only canonical, closed architecture proof batches', () => {
  const value = batch();
  const bytes = Buffer.from(`${canonicalArchitectureJson(value)}\n`);
  assert.equal(assertArchitectureProofBatch(value, 'production'), value);
  assert.deepEqual(parseArchitectureProofBatch(bytes, 'production'), value);
});

test('rejects mixed source, artefact, proof and batch contracts', () => {
  const mutations = [
    (value) => { value.sourceDigest = sha('F'); },
    (value) => { value.batchId = 'credential'; },
    (value) => { value.artifact.webdriverIncluded = true; },
    (value) => { value.artifact.kind = 'credential-twin'; },
    (value) => { delete value.proofs['A.24']; },
    (value) => { value.proofs['A.25'] = { status: 'pass' }; },
    (value) => { value.unexpected = true; },
  ];
  for (const mutate of mutations) {
    const value = structuredClone(batch());
    mutate(value);
    assert.throws(() => assertArchitectureProofBatch(value, 'production'));
  }
});

test('rejects non-canonical and multi-line batch bytes', () => {
  const value = batch();
  assert.throws(() => parseArchitectureProofBatch(
    Buffer.from(`${JSON.stringify(value, null, 2)}\n`),
    'production',
  ));
  const line = `${canonicalArchitectureJson(value)}\n`;
  assert.throws(() => parseArchitectureProofBatch(Buffer.from(`${line}${line}`), 'production'));
});

test('requires final semantically valid evidence for every proof ID', () => {
  const sourceDigest = sha('4');
  const production = architectureProofBatch('production', undefined, sourceDigest);
  const batches = [
    production,
    architectureProofBatch('credential', production.artifact, sourceDigest),
    architectureProofBatch('approval', production.artifact, sourceDigest),
    architectureProofBatch('automation', production.artifact, sourceDigest),
  ];
  for (const value of batches) {
    const bytes = Buffer.from(`${canonicalArchitectureJson(value)}\n`);
    assert.deepEqual(parseArchitectureProofBatch(bytes, value.batchId), value);
    for (const id of Object.keys(value.proofs)) {
      for (const proof of [{}, { status: 'blocked' }, { status: 'fail' }]) {
        const malformed = structuredClone(value);
        malformed.proofs[id].evidence = proof;
        assert.throws(() => parseArchitectureProofBatch(
          Buffer.from(`${canonicalArchitectureJson(malformed)}\n`),
          value.batchId,
        ));
      }
      const mismatched = structuredClone(value);
      mismatched.proofs[id] = structuredClone(production.proofs['A.21']);
      if (id === 'A.21') mismatched.proofs[id] = structuredClone(production.proofs['A.22']);
      assert.throws(() => parseArchitectureProofBatch(
        Buffer.from(`${canonicalArchitectureJson(mismatched)}\n`),
        value.batchId,
      ));
    }
  }
});

test('binds proof identities to the recorded source and artefacts', () => {
  const sourceDigest = sha('4');
  const production = architectureProofBatch('production', undefined, sourceDigest);
  const cases = [
    ['production', (value) => { value.proofs['A.21'].evidence.bundleFingerprint = sha('b'); }],
    ['production', (value) => { value.proofs['A.21'].evidence.bundleEntries += 1; }],
    ['credential', (value) => { value.proofs['A.23'].evidence.bundleFingerprint = sha('b'); }],
    ['credential', (value) => {
      value.proofs['A.23'].evidence.credentialCleanupHelper.sourceDigest = sha('b');
    }],
    ['credential', (value) => {
      value.proofs['A.23'].evidence.credentialCleanupHelper.variantDefinitionSha256 = sha('b');
    }],
    ['automation', (value) => { value.proofs['A.26'].evidence.identity.sourceDigest = sha('b'); }],
    ['automation', (value) => { value.proofs['A.26'].evidence.identity.productionFingerprint = sha('b'); }],
    ['automation', (value) => { value.proofs['A.26'].evidence.identity.automationFingerprint = sha('b'); }],
    ['automation', (value) => { value.proofs['A.26'].evidence.identity.controlledDeltaSha256 = sha('b'); }],
    ['automation', (value) => { value.proofs['A.28'].evidence.identity.sourceDigest = sha('b'); }],
    ['automation', (value) => { value.proofs['A.28'].evidence.identity.productionFingerprint = sha('b'); }],
    ['automation', (value) => { value.proofs['A.28'].evidence.identity.automationFingerprint = sha('b'); }],
    ['automation', (value) => { value.proofs['A.28'].evidence.identity.controlledDeltaSha256 = sha('b'); }],
  ];
  for (const [batchId, mutate] of cases) {
    const value = architectureProofBatch(
      batchId,
      batchId === 'production' ? undefined : production.artifact,
      sourceDigest,
    );
    mutate(value);
    assert.throws(() => parseArchitectureProofBatch(
      Buffer.from(`${canonicalArchitectureJson(value)}\n`),
      batchId,
    ));
  }
});

test('rejects otherwise valid proof replay after artefact metadata changes', () => {
  const sourceDigest = sha('4');
  const production = architectureProofBatch('production', undefined, sourceDigest);
  const batches = [
    production,
    architectureProofBatch('credential', production.artifact, sourceDigest),
    architectureProofBatch('approval', production.artifact, sourceDigest),
    architectureProofBatch('automation', production.artifact, sourceDigest),
  ];
  for (const value of batches) {
    value.artifact.nodeSha256 = sha('c');
    value.artifact.sidecarSha256 = sha('d');
    assert.throws(() => parseArchitectureProofBatch(
      Buffer.from(`${canonicalArchitectureJson(value)}\n`),
      value.batchId,
    ));
  }
});

test('rejects valid lowercase envelope replay and identity mutations for every proof', () => {
  const originalSourceDigest = sha('4');
  const replaySourceDigest = sha('5');
  const production = architectureProofBatch('production', undefined, originalSourceDigest);
  const replayProduction = architectureProofBatch('production', undefined, replaySourceDigest);
  for (const id of ARCHITECTURE_PROOF_IDS) {
    const contract = ARCHITECTURE_PROOF_CONTRACTS[id];
    const original = architectureProofBatch(
      contract.batchId,
      contract.batchId === 'production' ? undefined : production.artifact,
      originalSourceDigest,
    );
    const replay = architectureProofBatch(
      contract.batchId,
      contract.batchId === 'production' ? undefined : replayProduction.artifact,
      replaySourceDigest,
    );
    replay.proofs[id] = structuredClone(original.proofs[id]);
    assert.throws(() => parseArchitectureProofBatch(
      Buffer.from(`${canonicalArchitectureJson(replay)}\n`),
      contract.batchId,
    ));

    const mutations = [
      (envelope) => { envelope.sourceDigest = sha('b'); },
      (envelope) => { envelope.artifactFingerprint = sha('c'); },
      (envelope) => { envelope.artifactSha256 = sha('d'); },
      (envelope) => { envelope.proofId = id === 'A.21' ? 'A.22' : 'A.21'; },
    ];
    if (contract.artifactKind !== 'production') {
      mutations.push(
        (envelope) => { envelope.baseProductionFingerprint = sha('e'); },
        (envelope) => { envelope.controlledDeltaSha256 = sha('f'); },
      );
    }
    for (const mutate of mutations) {
      const changed = structuredClone(original);
      mutate(changed.proofs[id]);
      assert.throws(() => parseArchitectureProofBatch(
        Buffer.from(`${canonicalArchitectureJson(changed)}\n`),
        contract.batchId,
      ));
    }
  }
});

test('binds every proof envelope to the full artefact runtime identity', () => {
  const sourceDigest = sha('4');
  const production = architectureProofBatch('production', undefined, sourceDigest);
  for (const id of ARCHITECTURE_PROOF_IDS) {
    const contract = ARCHITECTURE_PROOF_CONTRACTS[id];
    const value = architectureProofBatch(
      contract.batchId,
      contract.batchId === 'production' ? undefined : production.artifact,
      sourceDigest,
    );
    const replayedEnvelope = structuredClone(value.proofs[id]);
    value.artifact.nodeSha256 = sha('c');
    value.artifact.sidecarSha256 = sha('d');
    for (const siblingId of Object.keys(value.proofs)) {
      if (siblingId === id) continue;
      value.proofs[siblingId] = createArchitectureProofEnvelope({
        artifact: value.artifact,
        evidence: value.proofs[siblingId].evidence,
        proofId: siblingId,
        sourceDigest,
      });
    }
    value.proofs[id] = replayedEnvelope;
    assert.throws(() => parseArchitectureProofBatch(
      Buffer.from(`${canonicalArchitectureJson(value)}\n`),
      contract.batchId,
    ));
  }
});

test('allows semantically valid pre-cleanup batches only for in-process finalisation', () => {
  const sourceDigest = sha('4');
  const production = architectureProofBatch('production', undefined, sourceDigest);
  production.proofs['A.21'].evidence.cleanup = 'emitted-after-owned-temporary-cleanup';
  delete production.proofs['A.24'].evidence.generatedOutputsRemoved;
  assert.throws(() => assertArchitectureProofBatch(production, 'production'));
  assert.equal(assertArchitectureProofBatch(production, 'production', {
    requireFinalProofs: false,
  }), production);

  const credential = architectureProofBatch('credential', production.artifact, sourceDigest);
  delete credential.proofs['A.23'].evidence.generatedOutputsRemoved;
  assert.throws(() => assertArchitectureProofBatch(credential, 'credential'));
  assert.equal(assertArchitectureProofBatch(credential, 'credential', {
    requireFinalProofs: false,
  }), credential);

  const approval = architectureProofBatch('approval', production.artifact, sourceDigest);
  delete approval.proofs['A.25'].evidence.generatedOutputsRemoved;
  assert.throws(() => assertArchitectureProofBatch(approval, 'approval'));
  assert.equal(assertArchitectureProofBatch(approval, 'approval', {
    requireFinalProofs: false,
  }), approval);

  const automation = architectureProofBatch('automation', production.artifact, sourceDigest);
  delete automation.proofs['A.26'].evidence.generatedOutputsRemoved;
  delete automation.proofs['A.27'].evidence.generatedOutputsRemoved;
  assert.throws(() => assertArchitectureProofBatch(automation, 'automation'));
  assert.equal(assertArchitectureProofBatch(automation, 'automation', {
    requireFinalProofs: false,
  }), automation);

  for (const value of [production, credential, approval, automation]) {
    assert.throws(() => parseArchitectureProofBatch(
      Buffer.from(`${canonicalArchitectureJson(value)}\n`),
      value.batchId,
    ));
  }
});
