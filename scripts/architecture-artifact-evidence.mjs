import {
  ARCHITECTURE_VARIANT_DEFINITION_SHA256,
  assertArchitectureArtifact,
  assertMeasuredTwinDeltaRecord,
  canonicalArchitectureJson,
  sha256Bytes,
} from './architecture-gate-schema.mjs';

const SHA256 = /^[0-9a-f]{64}$/u;

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

const ARCHITECTURE_VARIANTS = deepFreeze({
  'approval-twin': {
    cargoFeatures: ['a25-approval-test'],
    frontend: {},
    overlay: {
      identifier: 'au.com.piui.desktop.a25-test',
      productName: 'PIUI A25 Architecture Test',
    },
    postBuild: {
      externalHarness: 'approval-matrix-harness',
      hostSigning: 'none',
    },
    schemaVersion: 1,
    title: 'PIUI A25 Architecture Test',
  },
  'automation-twin': {
    cargoFeatures: [
      'a27-lifecycle-test',
      'architecture-test',
    ],
    frontend: {
      VITE_PIUI_A26_MARKDOWN_TEST: '1',
      VITE_PIUI_A27_LIFECYCLE_TEST: '1',
      VITE_PIUI_A28_ACCESSIBILITY_TEST: '1',
    },
    overlay: {
      identifier: 'au.com.piui.desktop.architecture-test',
      productName: 'PIUI Architecture Test',
    },
    postBuild: {
      externalHarness: null,
      hostSigning: 'apple-development',
    },
    schemaVersion: 1,
    title: 'PIUI Architecture Test',
  },
  'credential-twin': {
    cargoFeatures: ['a23-credential-test'],
    frontend: {
      VITE_PIUI_A23_CREDENTIAL_TEST: '1',
    },
    overlay: {
      app: {
        windows: [{
          center: true,
          decorations: true,
          height: 680,
          hiddenTitle: true,
          label: 'main',
          minHeight: 560,
          minWidth: 680,
          resizable: true,
          title: 'PIUI A23 Architecture Test',
          titleBarStyle: 'Overlay',
          trafficLightPosition: { x: 18, y: 18 },
          url: 'index.html?spike=credential',
          width: 960,
        }],
      },
      identifier: 'au.com.piui.desktop.a23-test',
      productName: 'PIUI A23 Architecture Test',
    },
    postBuild: {
      externalHarness: 'credential-cleanup-harness',
      hostSigning: 'none',
    },
    schemaVersion: 1,
    title: 'PIUI A23 Architecture Test',
  },
  production: {
    cargoFeatures: [],
    frontend: {},
    overlay: null,
    postBuild: {
      externalHarness: null,
      hostSigning: 'none',
    },
    schemaVersion: 1,
    title: 'PIUI',
  },
});

function reject() {
  throw new Error('Architecture artefact evidence rejected');
}

export function architectureVariantDefinition(kind) {
  const definition = ARCHITECTURE_VARIANTS[kind];
  if (!definition) reject();
  return definition;
}

export const ARCHITECTURE_TWIN_DELTAS = deepFreeze(Object.fromEntries(
  Object.entries(ARCHITECTURE_VARIANTS)
    .filter(([kind]) => kind !== 'production'),
));

export function assertAppliedArchitectureVariant(kind, appliedVariant) {
  const expected = architectureVariantDefinition(kind);
  if (canonicalArchitectureJson(appliedVariant)
    !== canonicalArchitectureJson(expected)) reject();
  return expected;
}

export function architectureVariantDefinitionSha256(kind, appliedVariant) {
  if (kind === 'production') reject();
  const delta = assertAppliedArchitectureVariant(kind, appliedVariant);
  const digest = sha256Bytes(Buffer.from(`${canonicalArchitectureJson(delta)}\n`, 'utf8'));
  if (digest !== ARCHITECTURE_VARIANT_DEFINITION_SHA256[kind]) reject();
  return digest;
}

function exactBundle(bundle) {
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) reject();
  for (const value of [
    bundle.fingerprint,
    bundle.nodeSha256,
    bundle.sidecarSha256,
  ]) {
    if (typeof value !== 'string' || !SHA256.test(value)) reject();
  }
  for (const value of [bundle.entries, bundle.files, bundle.machoFiles]) {
    if (!Number.isSafeInteger(value) || value < 1) reject();
  }
  if (!['none', 'adhoc', 'apple-development'].includes(bundle.hostSignature)) reject();
}

export function architectureArtifactFromBundle(bundle, {
  appliedVariant,
  baseProductionFingerprint = null,
  kind,
  measuredDelta = null,
}) {
  exactBundle(bundle);
  assertAppliedArchitectureVariant(kind, appliedVariant);
  if (kind === 'production') {
    if (baseProductionFingerprint !== null || measuredDelta !== null) reject();
  } else if (typeof baseProductionFingerprint !== 'string'
    || !SHA256.test(baseProductionFingerprint)
    || baseProductionFingerprint === bundle.fingerprint) reject();
  if (kind === 'automation-twin' && bundle.hostSignature !== 'apple-development') reject();
  if (kind !== 'production') {
    if (!measuredDelta
      || typeof measuredDelta !== 'object'
      || Array.isArray(measuredDelta)
      || Object.keys(measuredDelta).sort().join('\0') !== 'record\0sha256'
      || typeof measuredDelta.sha256 !== 'string'
      || !SHA256.test(measuredDelta.sha256)) reject();
    assertMeasuredTwinDeltaRecord(measuredDelta.record, kind, {
      baseFingerprint: baseProductionFingerprint,
      twinFingerprint: bundle.fingerprint,
      variantDefinitionSha256: architectureVariantDefinitionSha256(kind, appliedVariant),
    });
    if (measuredDelta.sha256 !== sha256Bytes(Buffer.from(
      canonicalArchitectureJson(measuredDelta.record),
      'utf8',
    ))) reject();
  }
  const artifact = {
    baseProductionFingerprint,
    bundleEntries: bundle.entries,
    bundleFiles: bundle.files,
    controlledDelta: kind === 'production' ? null : measuredDelta.record,
    controlledDeltaSha256: kind === 'production' ? null : measuredDelta.sha256,
    distribution: kind === 'production' ? 'local-candidate' : 'non-distributable',
    fingerprint: bundle.fingerprint,
    kind,
    machoFiles: bundle.machoFiles,
    nodeSha256: bundle.nodeSha256,
    sidecarSha256: bundle.sidecarSha256,
    signature: kind === 'automation-twin' ? 'apple-development' : 'unsigned-or-adhoc',
    webdriverIncluded: kind === 'automation-twin',
  };
  return deepFreeze(assertArchitectureArtifact(artifact, kind));
}
