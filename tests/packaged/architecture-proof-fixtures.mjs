import {
  APPROVAL_MATRIX_EXPECTED_EVIDENCE,
} from '../../scripts/run-packaged-approval-probe.mjs';
import {
  A26_EXPECTED_NATIVE_EVIDENCE,
  A26_HOSTILE_FIXTURE_SHA256,
  A26_RASTER_FIXTURE_SHA256,
} from '../../scripts/run-packaged-markdown-probe.mjs';
import {
  A27_EXPECTED_EVIDENCE,
} from '../../scripts/assert-process-cleanup.mjs';
import {
  A23_CLEANUP_HELPER_BUILD_RECIPE_SHA256,
} from '../../scripts/run-packaged-credential-probe.mjs';
import {
  createArchitectureProofEnvelope,
} from '../../scripts/architecture-proof-batch.mjs';
import {
  ARCHITECTURE_VARIANT_DEFINITION_SHA256,
  canonicalArchitectureJson,
  sha256Bytes,
} from '../../scripts/architecture-gate-schema.mjs';

export const architectureSha = (character) => character.repeat(64);

export function architectureMeasuredDelta(kind, {
  baseFingerprint,
  twinFingerprint,
} = {}) {
  const identities = {
    'approval-twin': {
      identifier: 'au.com.piui.desktop.a25-test',
      productName: 'PIUI A25 Architecture Test',
    },
    'automation-twin': {
      identifier: 'au.com.piui.desktop.architecture-test',
      productName: 'PIUI Architecture Test',
    },
    'credential-twin': {
      identifier: 'au.com.piui.desktop.a23-test',
      productName: 'PIUI A23 Architecture Test',
    },
  };
  const identity = identities[kind];
  if (!identity || !baseFingerprint || !twinFingerprint) {
    throw new Error('Invalid measured architecture delta fixture');
  }
  const automation = kind === 'automation-twin';
  const codeDirectorySha256 = architectureSha(automation ? 'c' : 'a');
  const twinHostSha256 = architectureSha(automation ? 'd' : 'c');
  const deterministicSigningIdentitySha256 = automation
    ? sha256Bytes(Buffer.from(canonicalArchitectureJson({
      bundleIdentifier: 'au.com.piui.desktop.architecture-test',
      cdHash: codeDirectorySha256.slice(0, 40),
      certificateSha1: '140176A6796D69938D9E84C7121FAACBC13779C4',
      certificateSha256: 'e297ea4e5e9536fda83fa2989a45b393b9abb19cfd821c022e77b72429727bcd',
      codeDirectoryFlags: 0,
      codeDirectorySha256,
      designatedRequirement: 'anchor apple generic and identifier "au.com.piui.desktop.architecture-test" and certificate leaf[subject.OU] = "3478YKFMRY"',
      entitlements: 'none',
      nonCmsSignatureSha256: architectureSha('1'),
      nonCmsSignatureSlots: [
        { sha256: codeDirectorySha256, size: 265, slot: 0 },
        { sha256: architectureSha('e'), size: 136, slot: 2 },
      ],
      requirementsSha256: architectureSha('e'),
      schemaVersion: 1,
      signature: 'apple-development',
      teamIdentifier: '3478YKFMRY',
    }), 'utf8'))
    : null;
  const record = {
    added: [],
    baseFingerprint,
    changes: [
      {
        baseSha256: architectureSha('4'),
        path: 'Contents/Info.plist',
        semanticPatch: [
          {
            base: 'au.com.piui.desktop',
            key: 'CFBundleIdentifier',
            twin: identity.identifier,
          },
          {
            base: 'PIUI',
            key: 'CFBundleName',
            twin: identity.productName,
          },
        ],
        twinSha256: architectureSha('5'),
        type: 'plist',
      },
      {
        baseCodeDirectoryFlags: 0x20002,
        baseCodeDirectorySha256: architectureSha('6'),
        basePreSignNormalisedSha256: architectureSha('7'),
        baseSha256: architectureSha('8'),
        baseSignature: 'adhoc',
        baseSignatureForm: 'superblob',
        baseUuid: '01'.repeat(16),
        loadCommandContractSha256: architectureSha('9'),
        path: 'Contents/MacOS/piui',
        postSignBundleIdentifier: automation
          ? 'au.com.piui.desktop.architecture-test'
          : null,
        postSignCdHash: automation ? codeDirectorySha256.slice(0, 40) : null,
        postSignCertificateSha1: automation
          ? '140176A6796D69938D9E84C7121FAACBC13779C4'
          : null,
        postSignCertificateSha256: automation
          ? 'e297ea4e5e9536fda83fa2989a45b393b9abb19cfd821c022e77b72429727bcd'
          : null,
        postSignCmsBytes: automation ? 4_801 : null,
        postSignCmsSha256: automation ? architectureSha('f') : null,
        postSignCodeDirectoryFlags: automation ? 0 : 0x20002,
        postSignCodeDirectorySha256: codeDirectorySha256,
        postSignDesignatedRequirement: automation
          ? 'anchor apple generic and identifier "au.com.piui.desktop.architecture-test" and certificate leaf[subject.OU] = "3478YKFMRY"'
          : null,
        postSignDeterministicIdentitySha256: deterministicSigningIdentitySha256,
        postSignEntitlements: automation ? 'none' : null,
        postSignExecutableBytes: automation ? 35_008 : null,
        postSignForm: automation ? 'superblob' : 'code-directory',
        postSignNonCmsSignatureSha256: automation ? architectureSha('1') : null,
        postSignRequirementsSha256: automation ? architectureSha('e') : null,
        postSignSignatureContainerBytes: automation ? 18_448 : null,
        postSignSlots: automation
          ? [
            { sha256: codeDirectorySha256, size: 265, slot: 0 },
            { sha256: architectureSha('e'), size: 136, slot: 2 },
            { sha256: architectureSha('f'), size: 4_801, slot: 0x10000 },
          ]
          : [{ sha256: codeDirectorySha256, size: 16, slot: 0 }],
        postSignTeamIdentifier: automation ? '3478YKFMRY' : null,
        repeatPreSignCodeDirectorySha256: architectureSha('a'),
        repeatPostSignCmsBytes: automation ? 4_802 : null,
        repeatPostSignCmsSha256: automation ? architectureSha('0') : null,
        repeatPostSignCodeDirectorySha256: automation ? codeDirectorySha256 : null,
        repeatPostSignDeterministicIdentitySha256: deterministicSigningIdentitySha256,
        repeatPostSignExecutableBytes: automation ? 35_024 : null,
        repeatPostSignNonCmsSignatureSha256: automation ? architectureSha('1') : null,
        repeatPostSignSignatureContainerBytes: automation ? 18_464 : null,
        repeatPostSignSlots: automation
          ? [
            { sha256: codeDirectorySha256, size: 265, slot: 0 },
            { sha256: architectureSha('e'), size: 136, slot: 2 },
            { sha256: architectureSha('0'), size: 4_802, slot: 0x10000 },
          ]
          : null,
        repeatTwinSha256: automation ? architectureSha('0') : null,
        repeatTwinUuid: '02'.repeat(16),
        twinPreSignCodeDirectoryFlags: 0x20002,
        twinPreSignCodeDirectorySha256: architectureSha('a'),
        twinPreSignForm: 'code-directory',
        twinPreSignNormalisedSha256: architectureSha('b'),
        twinSha256: twinHostSha256,
        twinSignature: automation ? 'cms' : 'adhoc',
        twinUuid: '02'.repeat(16),
        type: 'macho',
      },
    ],
    equalEntriesSha256: architectureSha('3'),
    kind,
    removed: [],
    repeatTwinFingerprint: automation ? architectureSha('0') : twinFingerprint,
    schemaVersion: 1,
    twinFingerprint,
    variantDefinitionSha256: ARCHITECTURE_VARIANT_DEFINITION_SHA256[kind],
  };
  return {
    record,
    sha256: sha256Bytes(Buffer.from(canonicalArchitectureJson(record), 'utf8')),
  };
}

const PROOF_IDS_BY_BATCH = Object.freeze({
  approval: Object.freeze(['A.25']),
  automation: Object.freeze(['A.26', 'A.27', 'A.28']),
  credential: Object.freeze(['A.23']),
  production: Object.freeze(['A.21', 'A.22', 'A.24']),
});

export function architectureArtifact(batchId, productionArtifact) {
  const definitions = {
    approval: ['approval-twin', architectureSha('7'), 'unsigned-or-adhoc', false],
    automation: ['automation-twin', architectureSha('9'), 'apple-development', true],
    credential: ['credential-twin', architectureSha('5'), 'unsigned-or-adhoc', false],
    production: ['production', architectureSha('1'), 'unsigned-or-adhoc', false],
  };
  const definition = definitions[batchId];
  if (!definition) throw new Error('Unknown architecture fixture batch');
  const [kind, fingerprint, signature, webdriverIncluded] = definition;
  const measuredDelta = batchId === 'production'
    ? null
    : architectureMeasuredDelta(kind, {
      baseFingerprint: productionArtifact?.fingerprint,
      twinFingerprint: fingerprint,
    });
  return {
    baseProductionFingerprint: batchId === 'production'
      ? null
      : productionArtifact?.fingerprint,
    bundleEntries: 101,
    bundleFiles: 93,
    controlledDelta: measuredDelta?.record ?? null,
    controlledDeltaSha256: measuredDelta?.sha256 ?? null,
    distribution: batchId === 'production' ? 'local-candidate' : 'non-distributable',
    fingerprint,
    kind,
    machoFiles: 2,
    nodeSha256: architectureSha('2'),
    sidecarSha256: architectureSha('3'),
    signature,
    webdriverIncluded,
  };
}

function a21Evidence(artifact) {
  return {
    buildProcessBoundary: 'sampled PID/start/executable descendant ledger across observed reparenting and process-group changes; adversarial gapless containment is not claimed',
    bundleEntries: artifact.bundleEntries,
    bundleFiles: artifact.bundleFiles,
    bundleFingerprint: artifact.fingerprint,
    candidateRetention: 'none; the inspected package is ephemeral and removed after the same-lease proof',
    cleanup: 'passed',
    fingerprintClaim: 'identity of this accepted sealed build; cross-build byte reproducibility is not claimed',
    hostSignature: 'none',
    machoFiles: artifact.machoFiles,
    networkPolicy: 'inherited OS sandbox denial plus periodic descriptor defence-in-depth observation',
    nodeSignature: 'cms',
    nodeVersion: 'v22.23.1',
    piVersion: '0.82.0',
    runtimeObservedIdentities: 2,
    sidecarFiles: 80,
    signingAction: 'none; build used Tauri --no-sign and product signature states were parsed without codesign',
    status: 'pass',
    target: 'aarch64-apple-darwin',
  };
}

function a22Evidence() {
  const sourceSha256 = architectureSha('e');
  return {
    fixtureSha256: 'ea8814148eccb23250f92af2bf9f42a89e38f3f137d3fb380f42f830ac47a742',
    forkEntriesAfterTurn: 7,
    forkEntriesBeforeTurn: 4,
    forkedAtSelection: true,
    publicSdkImported: true,
    repositoryFixtureUnchanged: true,
    resumed: true,
    schemaVersion: 1,
    selectedBranchEntries: 4,
    sourceAfterTurnSha256: sourceSha256,
    sourceBeforeTurnSha256: sourceSha256,
    sourceEntries: 9,
    sourceUnchanged: true,
    turn: {
      abortedTerminals: 1,
      approvalHostCalls: 0,
      cancellationLatencyMilliseconds: 10,
      completeTerminals: 0,
      credentialAccess: {
        deletes: 0,
        lists: 8,
        modifies: 0,
        providerIds: 39,
        reads: 1_400,
        unexpectedProviderIds: 0,
      },
      forbiddenFinalChunkAbsent: true,
      messageStarts: 1,
      partialBytes: 4,
      partialSha256: '668e1c03090afbe4491469529c26b0f21aac187f63f0187bef8f17906abc783c',
      postAbortRequestUpdates: 0,
      postTerminalEvents: 0,
      providerAbortObserved: true,
      providerCalls: 1,
      textDeltas: 1,
    },
    zeroTools: true,
  };
}

function a23Evidence(artifact, sourceDigest) {
  return {
    bundleFingerprint: artifact.fingerprint,
    cleanup: {
      credentialInputDescriptorClosed: true,
      helperExecutionResidual: 'private-precheck-and-same-accepted-host-creator-cleanup-keychain-sandboxed',
      keychainEntriesRemoved: true,
      keychainIndexRemoved: true,
      ownedProcessesRemoved: true,
      privateCapturesRemoved: true,
      runnerIsolateRemoved: true,
    },
    credentialCleanupHelper: {
      buildRecipeSha256: A23_CLEANUP_HELPER_BUILD_RECIPE_SHA256,
      executableSha256: architectureSha('a'),
      executableSize: 1_048_576,
      helperSourceSha256: architectureSha('b'),
      schemaVersion: 1,
      sourceDigest,
      toolchainContextSha256: architectureSha('c'),
      toolchainReceiptSha256: architectureSha('d'),
      variantDefinitionSha256:
        artifact.controlledDelta.variantDefinitionSha256,
    },
    execution: 'genuine-packaged-app',
    generatedOutputsRemoved: true,
    keychain: 'stored-refreshed-deleted',
    lifecycle: {
      initialGet: 1,
      logoutDelete: 1,
      postDeleteMiss: 1,
      postRefreshGet: 1,
      refreshReads: 1,
      refreshWrites: 1,
    },
    namespaceIsolation: 'isolated-test-keychain',
    nativeSheet: 'appkit-accessibility-driven',
    privateChannel: {
      authorisedFiles: 1,
      authorisedOccurrences: 4,
      quiescedBeforeScan: true,
      rawFrames: 12,
      unauthorisedOccurrences: 0,
    },
    publicSurfaces: {
      accessibilityControls: 'runner-owned-after-quiescence-scanned',
      arbitraryJavascriptHeap: 'not-enumerable-not-claimed',
      childBrowsingContexts: 'trusted-webview-self-attested-zero-iframe-and-frame-elements',
      documentDom: 'bounded-document-light-dom-native-boundary-host-scanned',
      logsAndCrashArtefacts: 'isolated-runtime-and-owned-stdio-only',
      nativeInvokeBoundary: 'all-entries-and-expected-results-scanned',
      ordinaryAppData: 'isolated-runtime-only',
      rustEventBoundary: 'piui-stream-probe-native-admission-and-trusted-webview-self-attested-delivery-host-scanned',
      shadowRoots: 'trusted-webview-self-attested-zero-observable-open-closed-not-observable-not-claimed',
      webStorage: 'bounded-local-and-session-native-boundary-host-scanned',
      webViewInspectionAuthority: 'trusted-webview-self-serialised-self-attested-not-independent-live-browser-inspection',
    },
    schemaVersion: 1,
    status: 'pass',
  };
}

function a24Evidence() {
  return {
    ancestorCanaryLoads: 0,
    approvalRecordsAfterTrust: 0,
    approvalRecordsBeforeTrust: 0,
    approvalSentinelUnchangedThroughTrustedLoad: true,
    authoriseExecutions: 0,
    blanketApprovalScopes: 0,
    cachedReplayResults: 16,
    concurrentReplayRequests: 16,
    fixtureInventoryUnchanged: true,
    generatedOutputsRemoved: true,
    groupApprovalScopes: 0,
    markerBytes: 9,
    markerLines: 1,
    metadataInspections: 1,
    packageCanaryExecutions: 0,
    packagedRuntimeValidated: true,
    postRevokeLoadRejections: 1,
    projectTrustApprovalPolicyMutations: 0,
    projectTrustAuthorisations: 1,
    rememberedApprovalScopes: 0,
    revocations: 1,
    runnerIsolateRemoved: true,
    schemaVersion: 1,
    sentinelWorkspaceAuthorisations: 1,
    settingsCanaryLoads: 0,
    sidecarGenerationRestarted: true,
    sidecarGenerationRestarts: 2,
    skillCanaryExecutions: 0,
    sourceMarkerExecutions: 0,
    staleGenerationRejections: 1,
    staleLeaseRejections: 1,
    staleRevisionRejections: 1,
    trustedLoadExecutions: 1,
    untrustedLoadRejections: 1,
  };
}

function a25Evidence() {
  return {
    ...APPROVAL_MATRIX_EXPECTED_EVIDENCE,
    generatedOutputsRemoved: true,
    runnerIsolateRemoved: true,
  };
}

function a26Evidence(artifact, sourceDigest) {
  const automationFrontend = {
    fileCount: 18,
    inventorySha256: architectureSha('b'),
    javascriptRegexEngineChunks: 1,
    moduleProvenanceSha256: architectureSha('f'),
    onigurumaEngineChunks: 0,
    resourceAllowlistEntries: 17,
    resourceAllowlistSha256: architectureSha('c'),
    wasmFiles: 0,
    wasmMagicFrontendFiles: 0,
    wasmPayloadReferences: 0,
  };
  return {
    browser: {
      codeLoadingIndicatorPresented: true,
      cspViolations: 0,
      disclosedExternalOpens: 0,
      duplicateResourceEntries: 0,
      eventCanaryExecuted: false,
      hostileSameOriginResourceEntries: 0,
      loadingIndicatorPresented: true,
      locationUnchanged: true,
      navigationApiAttempts: 0,
      networkApiAttempts: 0,
      missingResourceEntries: 0,
      observedResourceEntries: 17,
      observedResourceSha256: architectureSha('c'),
      popupAttempts: 0,
      rasterResourceEntries: 1,
      resourceAllowlistEntries: 17,
      runtimeErrors: 0,
      schemaVersion: 1,
      scriptCanaryExecuted: false,
      unexpectedResourceEntries: 0,
      unhandledRejections: 0,
      wasmApiAttempts: 0,
    },
    bundle: {
      automationFrontend,
      automationWebdriverIncluded: true,
      cspExact: true,
      piuiRasterOnlyImageAddition: true,
      productionFrontend: {
        ...automationFrontend,
        inventorySha256: architectureSha('a'),
        moduleProvenanceSha256: architectureSha('e'),
        resourceAllowlistSha256: architectureSha('d'),
      },
      productionWebdriverIncluded: false,
      repeatAutomationFrontend: { ...automationFrontend },
    },
    cleanup: {
      bundlesRevalidated: true,
      listenerRemoved: true,
      runnerIsolatesRemoved: true,
      webdriverSessionDeleted: true,
    },
    dom: {
      blockedLinks: 31,
      engine: 'javascript-regex',
      externalLinkButtons: 3,
      fallbackSourceTextExact: true,
      highlightTokenNodes: 12,
      highlightedBlocks: 2,
      hostileFixtureSha256: A26_HOSTILE_FIXTURE_SHA256,
      loadedRasterImages: 1,
      languageFallbacks: 1,
      omittedAssets: 19,
      plainCodeBlocks: 3,
      probeReady: true,
      rasterFixtureSha256: A26_RASTER_FIXTURE_SHA256,
      rasterImages: 1,
      rasterSourcesExact: true,
      rawAuditRegions: 1,
      renderBudgetFallbacks: 1,
      schemaVersion: 1,
      unsafeActiveAttributes: 0,
      unsafeActiveElements: 0,
      wasmModules: 0,
      workBudgetFallbacks: 1,
    },
    driver: {
      activatedTwinIpv4LoopbackListeners: 1,
      activatedTwinOtherListeners: 0,
      activationNonceValidated: true,
      dormantTwinListeners: 0,
      legacyEnvPortListeners: 0,
      legacyWebdriverPortIgnored: true,
      productionHostileActivationListeners: 0,
      randomHighPort: true,
      webdriverSessions: 1,
    },
    generatedOutputsRemoved: true,
    identity: {
      automationFingerprint: artifact.fingerprint,
      controlledDeltaSha256: artifact.controlledDeltaSha256,
      productionFingerprint: artifact.baseProductionFingerprint,
      sameFrozenSource: true,
      sourceDigest,
    },
    native: A26_EXPECTED_NATIVE_EVIDENCE,
    schemaVersion: 1,
    status: 'pass',
  };
}

function a27Evidence(artifact, sourceDigest) {
  return {
    ...A27_EXPECTED_EVIDENCE,
    identity: {
      automationFingerprint: artifact.fingerprint,
      controlledDeltaSha256: artifact.controlledDeltaSha256,
      productionFingerprint: artifact.baseProductionFingerprint,
      sameFrozenSource: true,
      sourceDigest,
    },
  };
}

function a28DomEvidence() {
  return {
    accessibleOrderedRowsObserved: 100,
    appearances: 2,
    ariaPositionErrors: 0,
    arrowTransitions: 101,
    duplicateRows: 0,
    focusRetentionChecks: 4,
    focusRetentionFailures: 0,
    homeEndTransitions: 3,
    loadingIndicatorObserved: true,
    missingRows: 0,
    modes: 2,
    nameErrors: 0,
    outOfOrderRows: 0,
    pageTransitions: 7,
    roleErrors: 0,
    schemaVersion: 1,
    stableSelectionCount: 18,
    transcriptItems: 100,
    virtualOrderedRowsObserved: 100,
    webdriverSessions: 1,
  };
}

function a28Evidence(artifact, sourceDigest) {
  const dom = a28DomEvidence();
  return {
    accessibilityTree: {
      bounded: true,
      exactPid: true,
      focusErrors: 0,
      focusedRowOrdinal: 51,
      focusedRows: 1,
      listRoles: 1,
      nameErrors: 0,
      nodesVisited: 91,
      observedTranscriptRows: 13,
      orderErrors: 0,
      roleErrors: 0,
      trusted: true,
    },
    automation: Object.fromEntries(Object.entries(dom).filter(([key]) =>
      !['schemaVersion', 'stableSelectionCount', 'webdriverSessions'].includes(key))),
    cleanup: {
      bundlesRevalidated: true,
      listenerRemoved: true,
      ownedProcessesAfterCleanup: 0,
      runnerIsolateRemoved: true,
      webdriverSessionDeleted: true,
    },
    driver: {
      activatedTwinIpv4LoopbackListeners: 1,
      activatedTwinOtherListeners: 0,
      cleanupListeners: 0,
      dormantTwinListeners: 0,
      ipv4LoopbackOnly: true,
      productionHostileActivationListeners: 0,
      randomHighPort: true,
      stableSelectionCount: dom.stableSelectionCount,
      webdriverSessions: 1,
    },
    identity: {
      automationFingerprint: artifact.fingerprint,
      controlledDeltaSha256: artifact.controlledDeltaSha256,
      productionFingerprint: artifact.baseProductionFingerprint,
      sameFrozenSource: true,
      sourceDigest,
    },
    limitations: {
      automationConformanceEquivalence: 'not-claimed',
      voiceOverAutomationEquivalence: 'not-claimed',
      wcagConformance: 'not-claimed',
    },
    schemaVersion: 1,
    status: 'pass',
    voiceOver: {
      architectureGateRunContextSha256: 'e'.repeat(64),
      attestationSha256: 'f'.repeat(64),
      blockingDefects: 0,
      challengeRequestSha256: '1'.repeat(64),
      comparisonReceiptSha256: '2'.repeat(64),
      evidenceValidated: true,
      expectedContextSha256: '3'.repeat(64),
      gateContextCompared: true,
      humanWitnessed: true,
      modesChecked: 4,
      publishedReceiptSha256: '4'.repeat(64),
    },
  };
}

export function architectureProofEvidence(id, artifact, sourceDigest) {
  const factories = {
    'A.21': () => a21Evidence(artifact),
    'A.22': a22Evidence,
    'A.23': () => a23Evidence(artifact, sourceDigest),
    'A.24': a24Evidence,
    'A.25': a25Evidence,
    'A.26': () => a26Evidence(artifact, sourceDigest),
    'A.27': () => a27Evidence(artifact, sourceDigest),
    'A.28': () => a28Evidence(artifact, sourceDigest),
  };
  const factory = factories[id];
  if (!factory) throw new Error('Unknown architecture fixture proof');
  return factory();
}

export function architectureProofBatch(batchId, productionArtifact, sourceDigest) {
  const artifact = batchId === 'production'
    ? architectureArtifact(batchId)
    : architectureArtifact(batchId, productionArtifact);
  return {
    artifact,
    batchId,
    proofs: Object.fromEntries(PROOF_IDS_BY_BATCH[batchId].map((id) => [
      id,
      createArchitectureProofEnvelope({
        artifact,
        evidence: architectureProofEvidence(id, artifact, sourceDigest),
        proofId: id,
        sourceDigest,
      }),
    ])),
    schemaVersion: 1,
    sourceDigest,
  };
}
