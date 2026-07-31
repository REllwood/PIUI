import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assertArchitectureGateResults,
  canonicalArchitectureJson,
  createArchitecturePassMarker,
  parseArchitectureGateResults,
  parseArchitecturePassMarker,
  sha256Bytes,
} from '../../scripts/architecture-gate-schema.mjs';
import {
  architectureMeasuredDelta,
} from './architecture-proof-fixtures.mjs';

const sha = (character) => character.repeat(64);

function artifact({
  kind,
  fingerprint,
  baseProductionFingerprint = null,
  controlledDelta = null,
  distribution,
  signature,
  webdriverIncluded,
}) {
  return {
    baseProductionFingerprint,
    bundleEntries: 101,
    bundleFiles: 93,
    controlledDelta: controlledDelta?.record ?? null,
    controlledDeltaSha256: controlledDelta?.sha256 ?? null,
    distribution,
    fingerprint,
    kind,
    machoFiles: 2,
    nodeSha256: sha('a'),
    sidecarSha256: sha('b'),
    signature,
    webdriverIncluded,
  };
}

function validResults() {
  const sourceDigest = sha('1');
  const productionFingerprint = sha('2');
  const credentialFingerprint = sha('3');
  const approvalFingerprint = sha('4');
  const automationFingerprint = sha('5');
  const proof = (commandId, artifactKind, artifactFingerprint, evidence) => ({
    artifactFingerprint,
    artifactKind,
    commandId,
    evidenceSha256: sha(evidence),
    sourceDigest,
    status: 'pass',
  });
  return {
    artifacts: {
      approvalTwin: artifact({
        kind: 'approval-twin',
        fingerprint: approvalFingerprint,
        baseProductionFingerprint: productionFingerprint,
        controlledDelta: architectureMeasuredDelta('approval-twin', {
          baseFingerprint: productionFingerprint,
          twinFingerprint: approvalFingerprint,
        }),
        distribution: 'non-distributable',
        signature: 'unsigned-or-adhoc',
        webdriverIncluded: false,
      }),
      automationTwin: artifact({
        kind: 'automation-twin',
        fingerprint: automationFingerprint,
        baseProductionFingerprint: productionFingerprint,
        controlledDelta: architectureMeasuredDelta('automation-twin', {
          baseFingerprint: productionFingerprint,
          twinFingerprint: automationFingerprint,
        }),
        distribution: 'non-distributable',
        signature: 'adhoc',
        webdriverIncluded: true,
      }),
      credentialTwin: artifact({
        kind: 'credential-twin',
        fingerprint: credentialFingerprint,
        baseProductionFingerprint: productionFingerprint,
        controlledDelta: architectureMeasuredDelta('credential-twin', {
          baseFingerprint: productionFingerprint,
          twinFingerprint: credentialFingerprint,
        }),
        distribution: 'non-distributable',
        signature: 'unsigned-or-adhoc',
        webdriverIncluded: false,
      }),
      production: artifact({
        kind: 'production',
        fingerprint: productionFingerprint,
        distribution: 'local-candidate',
        signature: 'unsigned-or-adhoc',
        webdriverIncluded: false,
      }),
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
    proofs: {
      'A.21': proof('spike:package:inspect', 'production', productionFingerprint, 'a'),
      'A.22': proof('spike:packaged:sdk', 'production', productionFingerprint, 'b'),
      'A.23': proof(
        'spike:packaged:credentials',
        'credential-twin',
        credentialFingerprint,
        'c',
      ),
      'A.24': proof('spike:packaged:trust', 'production', productionFingerprint, 'd'),
      'A.25': proof(
        'spike:packaged:approvals',
        'approval-twin',
        approvalFingerprint,
        'e',
      ),
      'A.26': proof(
        'spike:packaged:markdown',
        'automation-twin',
        automationFingerprint,
        'f',
      ),
      'A.27': proof(
        'spike:packaged:lifecycle',
        'automation-twin',
        automationFingerprint,
        '7',
      ),
      'A.28': proof(
        'spike:packaged:accessibility',
        'automation-twin',
        automationFingerprint,
        '8',
      ),
    },
    schemaVersion: 1,
    source: {
      cargoLockSha256: sha('9'),
      digest: sourceDigest,
      forgeSha256: sha('a'),
      inventorySha256: sha('b'),
      packageLockSha256: sha('c'),
      planSha256: sha('d'),
      specSha256: sha('e'),
    },
    target: 'aarch64-apple-darwin',
  };
}

function bytes(value) {
  return Buffer.from(`${canonicalArchitectureJson(value)}\n`, 'utf8');
}

test('accepts only the complete same-source and same-artifact architecture decision', () => {
  const results = validResults();
  assert.equal(assertArchitectureGateResults(results), results);
  assert.deepEqual(parseArchitectureGateResults(bytes(results)), results);
  const marker = createArchitecturePassMarker(results);
  assert.deepEqual(parseArchitecturePassMarker(bytes(marker), results), marker);
});

test('rejects missing, non-pass, extra, stale, mixed and incorrectly authorised evidence', () => {
  const mutations = [
    (value) => { delete value.proofs['A.23']; },
    (value) => { value.proofs['A.25'].status = 'blocked'; },
    (value) => { value.proofs['A.26'].unexpected = true; },
    (value) => { value.proofs['A.22'].sourceDigest = sha('f'); },
    (value) => { value.proofs['A.28'].artifactFingerprint = sha('3'); },
    (value) => { value.artifacts.automationTwin.nodeSha256 = sha('7'); },
    (value) => { value.artifacts.credentialTwin.baseProductionFingerprint = sha('8'); },
    (value) => { value.artifacts.approvalTwin.webdriverIncluded = true; },
    (value) => {
      value.artifacts.automationTwin.controlledDelta.variantDefinitionSha256 = sha('f');
      value.artifacts.automationTwin.controlledDeltaSha256 = sha256Bytes(Buffer.from(
        canonicalArchitectureJson(value.artifacts.automationTwin.controlledDelta),
        'utf8',
      ));
    },
    (value) => { value.proofs['A.25'].artifactKind = 'production'; },
    (value) => { value.externalReleaseGates.distributionAuthorised = true; },
    (value) => { value.externalReleaseGates.developerId = 'available'; },
  ];
  for (const mutate of mutations) {
    const candidate = structuredClone(validResults());
    mutate(candidate);
    assert.throws(() => assertArchitectureGateResults(candidate));
  }
});

test('rejects non-canonical, duplicate-key, CRLF, multi-line and oversized result records', () => {
  const results = validResults();
  const canonical = bytes(results);
  assert.throws(() => parseArchitectureGateResults(
    Buffer.from(`${JSON.stringify(results, null, 2)}\n`, 'utf8'),
  ));
  assert.throws(() => parseArchitectureGateResults(
    Buffer.from(canonical.toString('utf8').replace(/\n$/, '\r\n'), 'utf8'),
  ));
  assert.throws(() => parseArchitectureGateResults(Buffer.concat([canonical, canonical])));
  assert.throws(() => parseArchitectureGateResults(
    Buffer.from('{"schemaVersion":1,"schemaVersion":1}\n', 'utf8'),
  ));
  assert.throws(() => parseArchitectureGateResults(
    Buffer.alloc(1_048_577, 0x20),
  ));
});

test('rejects a marker after any result or source identity changes', () => {
  const results = validResults();
  const marker = createArchitecturePassMarker(results);
  const changed = structuredClone(results);
  changed.proofs['A.24'].evidenceSha256 = sha('f');
  assert.throws(() => parseArchitecturePassMarker(bytes(marker), changed));

  const staleMarker = { ...marker, sourceDigest: sha('0') };
  assert.throws(() => parseArchitecturePassMarker(bytes(staleMarker), results));
});
