import assert from 'node:assert/strict';
import test from 'node:test';
import {
  architectureArtifactFromBundle,
  architectureVariantDefinitionSha256,
  architectureVariantDefinition,
} from '../../scripts/architecture-artifact-evidence.mjs';
import {
  architectureMeasuredDelta,
} from './architecture-proof-fixtures.mjs';
import {
  ARCHITECTURE_VARIANT_DEFINITION_SHA256,
  canonicalArchitectureJson,
  sha256Bytes,
} from '../../scripts/architecture-gate-schema.mjs';

const sha = (character) => character.repeat(64);

function bundle(overrides = {}) {
  return {
    entries: 101,
    files: 93,
    fingerprint: sha('1'),
    hostSignature: 'none',
    machoFiles: 2,
    nodeSha256: sha('2'),
    sidecarSha256: sha('3'),
    ...overrides,
  };
}

test('pins every measured twin record to the exact applied variant definition', () => {
  for (const kind of ['approval-twin', 'automation-twin', 'credential-twin']) {
    assert.equal(
      architectureVariantDefinitionSha256(kind, architectureVariantDefinition(kind)),
      ARCHITECTURE_VARIANT_DEFINITION_SHA256[kind],
    );
  }
});

test('derives closed production and controlled-twin artefact records', () => {
  const productionVariant = architectureVariantDefinition('production');
  const automationVariant = architectureVariantDefinition('automation-twin');
  const production = architectureArtifactFromBundle(bundle(), {
    appliedVariant: productionVariant,
    kind: 'production',
  });
  assert.equal(production.baseProductionFingerprint, null);
  assert.equal(production.controlledDelta, null);
  assert.equal(production.controlledDeltaSha256, null);
  assert.equal(production.webdriverIncluded, false);

  const automation = architectureArtifactFromBundle(bundle({
    fingerprint: sha('4'),
    hostSignature: 'adhoc',
  }), {
    appliedVariant: automationVariant,
    baseProductionFingerprint: production.fingerprint,
    kind: 'automation-twin',
    measuredDelta: architectureMeasuredDelta('automation-twin', {
      baseFingerprint: production.fingerprint,
      twinFingerprint: sha('4'),
    }),
  });
  assert.equal(automation.baseProductionFingerprint, production.fingerprint);
  assert.equal(
    automation.controlledDeltaSha256,
    architectureMeasuredDelta('automation-twin', {
      baseFingerprint: production.fingerprint,
      twinFingerprint: sha('4'),
    }).sha256,
  );
  assert.equal(automation.webdriverIncluded, true);
  assert.equal(automation.distribution, 'non-distributable');
});

test('rejects production aliases, missing hashes and unsigned automation twins', () => {
  const productionVariant = architectureVariantDefinition('production');
  const credentialVariant = architectureVariantDefinition('credential-twin');
  const automationVariant = architectureVariantDefinition('automation-twin');
  assert.throws(() => architectureArtifactFromBundle(bundle(), {
    appliedVariant: productionVariant,
    baseProductionFingerprint: sha('9'),
    kind: 'production',
  }));
  assert.throws(() => architectureArtifactFromBundle(bundle(), {
    appliedVariant: credentialVariant,
    baseProductionFingerprint: sha('1'),
    kind: 'credential-twin',
  }));
  assert.throws(() => architectureArtifactFromBundle(bundle({ nodeSha256: 'invalid' }), {
    appliedVariant: productionVariant,
    kind: 'production',
  }));
  assert.throws(() => architectureArtifactFromBundle(bundle({ fingerprint: sha('4') }), {
    appliedVariant: automationVariant,
    baseProductionFingerprint: sha('1'),
    kind: 'automation-twin',
    measuredDelta: architectureMeasuredDelta('automation-twin', {
      baseFingerprint: sha('1'),
      twinFingerprint: sha('4'),
    }),
  }));
});

test('rejects a declared delta that differs from the exact applied build variant', () => {
  const applied = structuredClone(architectureVariantDefinition('automation-twin'));
  applied.frontend.VITE_UNDECLARED_BUILD_INPUT = '1';

  assert.throws(
    () => architectureVariantDefinitionSha256('automation-twin', applied),
    /rejected/u,
  );
  assert.throws(() => architectureArtifactFromBundle(bundle({
    fingerprint: sha('4'),
    hostSignature: 'adhoc',
  }), {
    appliedVariant: applied,
    baseProductionFingerprint: sha('1'),
    kind: 'automation-twin',
    measuredDelta: architectureMeasuredDelta('automation-twin', {
      baseFingerprint: sha('1'),
      twinFingerprint: sha('4'),
    }),
  }), /rejected/u);
});

test('rejects measured-record substitutions even when their digest is recomputed', () => {
  const appliedVariant = architectureVariantDefinition('automation-twin');
  const mutations = [
    (record) => { record.variantDefinitionSha256 = sha('f'); },
    (record) => { record.baseFingerprint = sha('e'); },
    (record) => { record.changes[1].postSignSlots[0].sha256 = sha('d'); },
    (record) => { record.changes[0].twinSha256 = record.changes[0].baseSha256; },
    (record) => { record.changes[1].twinSha256 = record.changes[1].baseSha256; },
    (record) => {
      record.changes[1].twinUuid = record.changes[1].baseUuid;
      record.changes[1].repeatTwinUuid = record.changes[1].baseUuid;
    },
  ];
  for (const mutate of mutations) {
    const measuredDelta = structuredClone(architectureMeasuredDelta('automation-twin', {
      baseFingerprint: sha('1'),
      twinFingerprint: sha('4'),
    }));
    mutate(measuredDelta.record);
    measuredDelta.sha256 = sha256Bytes(Buffer.from(
      canonicalArchitectureJson(measuredDelta.record),
      'utf8',
    ));
    assert.throws(() => architectureArtifactFromBundle(bundle({
      fingerprint: sha('4'),
      hostSignature: 'adhoc',
    }), {
      appliedVariant,
      baseProductionFingerprint: sha('1'),
      kind: 'automation-twin',
      measuredDelta,
    }), /rejected/u);
  }
});
