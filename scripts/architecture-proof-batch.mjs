import {
  ARCHITECTURE_GATE_SCHEMA_VERSION,
  ARCHITECTURE_PROOF_CONTRACTS,
  ARCHITECTURE_PROOF_IDS,
  assertArchitectureArtifact,
  canonicalArchitectureJson,
  sha256Bytes,
} from './architecture-gate-schema.mjs';
import { assertSafeEvidence } from './run-packaged-probe.mjs';
import { assertSafeCredentialEvidence } from './run-packaged-credential-probe.mjs';
import {
  parsePackagedTrustEvidence,
  parseProjectTrustHarnessEvidence,
} from './run-packaged-trust-probe.mjs';
import {
  parseApprovalMatrixHarnessEvidence,
  parsePackagedApprovalMatrixEvidence,
} from './run-packaged-approval-probe.mjs';
import {
  assertAuthoritativeMarkdownEvidence,
  parsePackagedMarkdownEvidence,
} from './run-packaged-markdown-probe.mjs';
import {
  assertPreCleanupLifecycleEvidence,
  parsePackagedLifecycleEvidence,
} from './run-packaged-lifecycle-probe.mjs';
import {
  assertA28AccessibilityEvidence,
} from './run-packaged-accessibility-probe.mjs';

const MAX_BATCH_BYTES = 2 * 1_048_576;
const SHA256 = /^[0-9a-f]{64}$/u;

const batchIds = [...new Set(ARCHITECTURE_PROOF_IDS.map(
  (id) => ARCHITECTURE_PROOF_CONTRACTS[id].batchId,
))];
export const ARCHITECTURE_BATCH_CONTRACTS = Object.freeze(Object.fromEntries(
  batchIds.map((batchId) => {
    const proofIds = ARCHITECTURE_PROOF_IDS.filter(
      (id) => ARCHITECTURE_PROOF_CONTRACTS[id].batchId === batchId,
    );
    const artifactKind = ARCHITECTURE_PROOF_CONTRACTS[proofIds[0]]?.artifactKind;
    return [batchId, Object.freeze({
      artifactKind,
      proofIds: Object.freeze(proofIds),
    })];
  }),
));

function reject() {
  throw new Error('Architecture proof batch rejected');
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject();
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])) reject();
}

function parseCanonicalOneLine(bytes) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 3
    || bytes.length > MAX_BATCH_BYTES
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
    || bytes.includes(0x00)) reject();
  let value;
  try {
    value = JSON.parse(bytes.subarray(0, -1).toString('utf8'));
  } catch {
    reject();
  }
  if (`${canonicalArchitectureJson(value)}\n` !== bytes.toString('utf8')) reject();
  return value;
}

function evidenceLine(value) {
  return Buffer.from(`${canonicalArchitectureJson(value)}\n`, 'utf8');
}

export function architectureArtifactSha256(artifact) {
  return sha256Bytes(Buffer.from(canonicalArchitectureJson(artifact), 'utf8'));
}

export function architectureEvidenceSha256(evidence) {
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) reject();
  return sha256Bytes(evidenceLine(evidence));
}

export function createArchitectureProofEnvelope({
  artifact,
  evidence,
  proofId,
  sourceDigest,
}) {
  const contract = ARCHITECTURE_PROOF_CONTRACTS[proofId];
  if (!contract
    || typeof sourceDigest !== 'string'
    || !SHA256.test(sourceDigest)
    || !evidence
    || typeof evidence !== 'object'
    || Array.isArray(evidence)) reject();
  assertArchitectureArtifact(artifact, contract.artifactKind);
  canonicalArchitectureJson(evidence);
  return Object.freeze({
    artifactFingerprint: artifact.fingerprint,
    artifactKind: artifact.kind,
    artifactSha256: architectureArtifactSha256(artifact),
    baseProductionFingerprint: artifact.baseProductionFingerprint,
    controlledDeltaSha256: artifact.controlledDeltaSha256,
    evidence,
    evidenceSha256: architectureEvidenceSha256(evidence),
    proofId,
    sourceDigest,
  });
}

function assertA21Evidence(value, artifact, requireFinal) {
  exactKeys(value, [
    'buildProcessBoundary',
    'bundleEntries',
    'bundleFiles',
    'bundleFingerprint',
    'candidateRetention',
    'cleanup',
    'fingerprintClaim',
    'hostSignature',
    'machoFiles',
    'networkPolicy',
    'nodeSignature',
    'nodeVersion',
    'piVersion',
    'runtimeObservedIdentities',
    'sidecarFiles',
    'signingAction',
    'status',
    'target',
  ]);
  const cleanupAccepted = requireFinal
    ? value.cleanup === 'passed'
    : ['emitted-after-owned-temporary-cleanup', 'passed'].includes(value.cleanup);
  if (value.status !== 'pass'
    || value.target !== 'aarch64-apple-darwin'
    || value.bundleFingerprint !== artifact.fingerprint
    || value.bundleEntries !== artifact.bundleEntries
    || value.bundleFiles !== artifact.bundleFiles
    || value.machoFiles !== artifact.machoFiles
    || !Number.isSafeInteger(value.sidecarFiles)
    || value.sidecarFiles < 1
    || !Number.isSafeInteger(value.runtimeObservedIdentities)
    || value.runtimeObservedIdentities < 2
    || value.nodeVersion !== 'v22.23.1'
    || value.piVersion !== '0.82.0'
    || !['none', 'adhoc'].includes(value.hostSignature)
    || !['none', 'adhoc', 'cms'].includes(value.nodeSignature)
    || value.fingerprintClaim !== 'identity of this accepted sealed build; cross-build byte reproducibility is not claimed'
    || value.networkPolicy !== 'inherited OS sandbox denial plus periodic descriptor defence-in-depth observation'
    || value.buildProcessBoundary !== 'sampled PID/start/executable descendant ledger across observed reparenting and process-group changes; adversarial gapless containment is not claimed'
    || value.candidateRetention !== 'none; the inspected package is ephemeral and removed after the same-lease proof'
    || value.signingAction !== 'none; build used Tauri --no-sign and product signature states were parsed without codesign'
    || !cleanupAccepted) reject();
}

function assertRunnerFinalisedEvidence(value, {
  finalParser,
  harnessParser,
  requireFinal,
}) {
  if (Object.hasOwn(value, 'generatedOutputsRemoved')) {
    finalParser(evidenceLine(value));
    return;
  }
  if (requireFinal || value.runnerIsolateRemoved !== true) reject();
  const { runnerIsolateRemoved: _removed, ...harness } = value;
  harnessParser(evidenceLine(harness));
}

function assertAutomationIdentity(identity, artifact, sourceDigest) {
  if (identity.sourceDigest !== sourceDigest
    || identity.productionFingerprint !== artifact.baseProductionFingerprint
    || identity.automationFingerprint !== artifact.fingerprint
    || identity.controlledDeltaSha256 !== artifact.controlledDeltaSha256
    || identity.sameFrozenSource !== true) reject();
}

export function assertArchitectureProofEvidence(id, value, {
  artifact,
  requireFinal = true,
  sourceDigest,
}) {
  const proofContract = ARCHITECTURE_PROOF_CONTRACTS[id];
  if (!proofContract
    || typeof sourceDigest !== 'string'
    || !SHA256.test(sourceDigest)
    || typeof requireFinal !== 'boolean'
    || !value
    || typeof value !== 'object'
    || Array.isArray(value)) reject();
  assertArchitectureArtifact(artifact, proofContract.artifactKind);
  canonicalArchitectureJson(value);
  if (id === 'A.21') {
    assertA21Evidence(value, artifact, requireFinal);
  } else if (id === 'A.22') {
    assertSafeEvidence(value);
  } else if (id === 'A.23') {
    const final = Object.hasOwn(value, 'generatedOutputsRemoved');
    if (requireFinal && !final) reject();
    const accepted = assertSafeCredentialEvidence(value, final, artifact.fingerprint);
    if (accepted.credentialCleanupHelper.sourceDigest !== sourceDigest
      || accepted.credentialCleanupHelper.variantDefinitionSha256
        !== artifact.controlledDelta.variantDefinitionSha256) reject();
  } else if (id === 'A.24') {
    assertRunnerFinalisedEvidence(value, {
      finalParser: parsePackagedTrustEvidence,
      harnessParser: parseProjectTrustHarnessEvidence,
      requireFinal,
    });
  } else if (id === 'A.25') {
    assertRunnerFinalisedEvidence(value, {
      finalParser: parsePackagedApprovalMatrixEvidence,
      harnessParser: parseApprovalMatrixHarnessEvidence,
      requireFinal,
    });
  } else if (id === 'A.26') {
    const final = Object.hasOwn(value, 'generatedOutputsRemoved');
    if (requireFinal && !final) reject();
    const accepted = final
      ? parsePackagedMarkdownEvidence(evidenceLine(value))
      : assertAuthoritativeMarkdownEvidence(value);
    assertAutomationIdentity(accepted.identity, artifact, sourceDigest);
  } else if (id === 'A.27') {
    const final = Object.hasOwn(value, 'generatedOutputsRemoved');
    if (requireFinal && !final) reject();
    const accepted = final
      ? parsePackagedLifecycleEvidence(evidenceLine(value))
      : assertPreCleanupLifecycleEvidence(value);
    assertAutomationIdentity(accepted.identity, artifact, sourceDigest);
  } else if (id === 'A.28') {
    const accepted = assertA28AccessibilityEvidence(value);
    assertAutomationIdentity(accepted.identity, artifact, sourceDigest);
  } else {
    reject();
  }
  return value;
}

export function assertArchitectureProofEnvelope(value, expectedProofId, {
  artifact,
  requireFinalEvidence = true,
  sourceDigest,
} = {}) {
  const contract = ARCHITECTURE_PROOF_CONTRACTS[expectedProofId];
  if (!contract || typeof requireFinalEvidence !== 'boolean') reject();
  exactKeys(value, [
    'artifactFingerprint',
    'artifactKind',
    'artifactSha256',
    'baseProductionFingerprint',
    'controlledDeltaSha256',
    'evidence',
    'evidenceSha256',
    'proofId',
    'sourceDigest',
  ]);
  assertArchitectureArtifact(artifact, contract.artifactKind);
  if (value.proofId !== expectedProofId
    || value.sourceDigest !== sourceDigest
    || value.artifactKind !== contract.artifactKind
    || value.artifactKind !== artifact.kind
    || value.artifactFingerprint !== artifact.fingerprint
    || value.artifactSha256 !== architectureArtifactSha256(artifact)
    || value.baseProductionFingerprint !== artifact.baseProductionFingerprint
    || value.controlledDeltaSha256 !== artifact.controlledDeltaSha256
    || value.evidenceSha256 !== architectureEvidenceSha256(value.evidence)
    || typeof value.artifactSha256 !== 'string'
    || !SHA256.test(value.artifactSha256)
    || typeof value.evidenceSha256 !== 'string'
    || !SHA256.test(value.evidenceSha256)) reject();
  assertArchitectureProofEvidence(expectedProofId, value.evidence, {
    artifact,
    requireFinal: requireFinalEvidence,
    sourceDigest,
  });
  return value;
}

export function assertArchitectureProofBatch(value, expectedBatchId, {
  requireFinalProofs = true,
} = {}) {
  const contract = ARCHITECTURE_BATCH_CONTRACTS[expectedBatchId];
  if (!contract || typeof requireFinalProofs !== 'boolean') reject();
  exactKeys(value, [
    'artifact',
    'batchId',
    'proofs',
    'schemaVersion',
    'sourceDigest',
  ]);
  if (value.schemaVersion !== ARCHITECTURE_GATE_SCHEMA_VERSION
    || value.batchId !== expectedBatchId
    || typeof value.sourceDigest !== 'string'
    || !SHA256.test(value.sourceDigest)) reject();
  assertArchitectureArtifact(value.artifact, contract.artifactKind);
  exactKeys(value.proofs, contract.proofIds);
  for (const id of contract.proofIds) {
    assertArchitectureProofEnvelope(value.proofs[id], id, {
      artifact: value.artifact,
      requireFinalEvidence: requireFinalProofs,
      sourceDigest: value.sourceDigest,
    });
  }
  return value;
}

export function parseArchitectureProofBatch(bytes, expectedBatchId) {
  return assertArchitectureProofBatch(parseCanonicalOneLine(bytes), expectedBatchId);
}
