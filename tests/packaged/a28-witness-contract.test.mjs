import assert from 'node:assert/strict';
import {
  generateKeyPairSync,
  sign,
} from 'node:crypto';
import test from 'node:test';
import {
  A28_ENROLMENT_DOMAIN,
  A28_ENROLMENT_SIGNING_PREFIX,
  A28_GATE_CONTEXT_AUTHORITY,
  A28_HUMAN_ASSERTION_SCOPE,
  A28_WITNESS_DOMAIN,
  A28_WITNESS_SIGNING_PREFIX,
  a28CheckpointCommitmentSha256,
  a28ChallengeRequestSha256,
  assertA28Challenge,
  assertA28ChallengeRequest,
  assertA28Enrolment,
  assertA28EnrolmentAuthorityConfig,
  assertA28EnrolmentAuthorityReceipt,
  assertA28PolicyPin,
  assertA28PublishedReceipt,
  assertA28WitnessAppInspection,
  canonicalA28Json,
  canonicalA28Line,
  parseCanonicalA28Line,
  parseA28CheckpointAuthorityArguments,
  sha256A28,
  verifyA28WitnessAttestation,
} from '../../scripts/a28-witness/contract.mjs';

const now = Date.parse('2026-07-31T12:07:00.000Z');
const sha = (character) => character.repeat(64);
const cdHash = (character) => character.repeat(40);

function executable(path, character, ino) {
  return {
    dev: 16777233,
    ino,
    path,
    sha256: sha(character),
    size: 270_605_984,
  };
}

function makeAuthorityConfig() {
  const teamIdentifier = 'AB12CD34EF';
  const bundleIdentifier = 'au.com.piui.a28-witness';
  const applicationIdentifier = teamIdentifier + '.' + bundleIdentifier;
  const keychainAccessGroup = applicationIdentifier + '.secure-enclave';
  const effectiveEntitlements = {
    'com.apple.application-identifier': applicationIdentifier,
    'com.apple.developer.team-identifier': teamIdentifier,
    'keychain-access-groups': [keychainAccessGroup],
  };
  return {
    applicationIdentifier,
    auditDirectoryPath: '/Library/Application Support/PIUI/A28Witness/consumed',
    bundleIdentifier,
    cdHash: cdHash('a'),
    checkpointAuthorityDirectoryPath:
      '/Library/Application Support/PIUI/A28Witness/checkpoint-private',
    checkpointCommitmentDirectoryPath:
      '/Library/Application Support/PIUI/A28Witness/checkpoint-commitments',
    checkpointDeliveryDirectoryPath:
      '/Library/Application Support/PIUI/A28Witness/checkpoint-deliveries',
    designatedRequirement:
      'identifier "au.com.piui.a28-witness" and anchor apple generic and certificate leaf[subject.OU] = AB12CD34EF',
    effectiveEntitlements,
    effectiveEntitlementsSha256: sha256A28(
      Buffer.from(canonicalA28Json(effectiveEntitlements), 'utf8'),
    ),
    enrolmentAuthorityReceiptPath:
      '/Library/Application Support/PIUI/A28Witness/enrolment-authority-receipt.json',
    enrolmentManifestPath:
      '/Library/Application Support/PIUI/A28Witness/enrolment.json',
    hostDesignatedRequirement:
      'anchor apple generic and identifier "au.com.piui.desktop.architecture-test" and certificate leaf[subject.OU] = "3478YKFMRY"',
    hostTeamIdentifier: '3478YKFMRY',
    installedApplicationPath:
      '/Library/Application Support/PIUI/A28Witness/app/PIUI A28 VoiceOver Witness.app',
    keychainAccessGroup,
    minimumMacOSVersion: '14.0',
    policyId: 'piui-a28-witness-policy-v1',
    processInspectorPath:
      '/Library/Application Support/PIUI/A28Witness/bin/a28-process-identity',
    processInspectorSha256: sha('1'),
    profileName: 'PIUI A28 VoiceOver Witness',
    profileSha256: sha('2'),
    profileUuid: '12345678-1234-1234-1234-123456789ABC',
    reviewerIdentity: 'Rhys Ellwood',
    resultDirectoryPath:
      '/Library/Application Support/PIUI/A28Witness/results',
    rootCheckpointAuthorityPath:
      '/Library/Application Support/PIUI/A28Witness/authority/checkpoint-authority.mjs',
    rootCheckpointAuthoritySha256: sha('9'),
    rootCheckpointLaunchConfigPath:
      '/Library/Application Support/PIUI/A28Witness/launcher/checkpoint-launch.json',
    rootCheckpointLaunchConfigSha256: sha('c'),
    rootEnrolmentLaunchConfigPath:
      '/Library/Application Support/PIUI/A28Witness/launcher/enrolment-launch.json',
    rootEnrolmentLaunchConfigSha256: sha('d'),
    rootEnrolmentRegistrarPath:
      '/Library/Application Support/PIUI/A28Witness/authority/register-enrolment.mjs',
    rootEnrolmentRegistrarSha256: sha('a'),
    rootLauncherCdHash: cdHash('d'),
    rootLauncherDesignatedRequirement:
      'identifier "au.com.piui.a28-root-launcher" and anchor apple generic and certificate leaf[subject.OU] = AB12CD34EF',
    rootLauncherPath:
      '/Library/Application Support/PIUI/A28Witness/bin/a28-root-launcher',
    rootLauncherSha256: sha('b'),
    rootLauncherUnsignedSha256: sha('a'),
    rootVerifierContractPath:
      '/Library/Application Support/PIUI/A28Witness/verifier/contract.mjs',
    rootVerifierContractSha256: sha('3'),
    rootVerifierEntrypointPath:
      '/Library/Application Support/PIUI/A28Witness/verifier/verify.mjs',
    rootVerifierEntrypointSha256: sha('4'),
    rootVerifierLaunchConfigPath:
      '/Library/Application Support/PIUI/A28Witness/launcher/verifier-launch.json',
    rootVerifierLaunchConfigSha256: sha('e'),
    rootVerifierNodePath:
      '/Library/Application Support/PIUI/A28Witness/bin/node',
    rootVerifierNodeSha256: sha('5'),
    runnerBundleIdentifier: 'node',
    runnerDesignatedRequirement:
      'identifier node and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "HX7739G8FX"',
    runnerTeamIdentifier: 'HX7739G8FX',
    schemaVersion: 1,
    signingCertificateSha256: sha('6'),
    signingIdentity: 'Developer ID Application: Rhys Ellwood (AB12CD34EF)',
    sourceSha256: sha('7'),
    teamIdentifier,
    voiceOverDesignatedRequirement:
      'identifier "com.apple.VoiceOver" and anchor apple',
    witnessExecutable: executable(
      '/Library/Application Support/PIUI/A28Witness/app/PIUI A28 VoiceOver Witness.app/Contents/MacOS/A28Witness',
      '8',
      4101,
    ),
    witnessExecutableUnsignedSha256: sha('9'),
    witnessGid: 20,
    witnessHomeDirectory: '/Users/rhysellwood',
    witnessUid: 501,
    witnessUsername: 'rhysellwood',
  };
}

function makeFixture() {
  const keyPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicSpki = keyPair.publicKey.export({ format: 'der', type: 'spki' });
  const publicKeySha256 = sha256A28(publicSpki);
  const authorityConfig = makeAuthorityConfig();
  const enrolmentAuthorityConfigSha256 = sha256A28(
    canonicalA28Line(authorityConfig),
  );
  const keyAttributes = {
    accessControlFlags: ['biometryCurrentSet', 'privateKeyUsage'],
    accessGroup: authorityConfig.keychainAccessGroup,
    applicationTag: 'au.com.piui.a28-witness.secure-enclave.v1',
    canSign: true,
    dataProtectionKeychain: true,
    isPermanent: true,
    keyClass: 'private',
    keySizeInBits: 256,
    keyType: 'ECSECPrimeRandom',
    tokenId: 'com.apple.setoken',
  };
  const enrolmentProofPayload = {
    algorithm: 'ES256',
    domain: A28_ENROLMENT_DOMAIN,
    enrolledAt: '2026-07-31T11:00:00.000Z',
    enrolmentAuthorityConfigSha256,
    enrolmentNonce: sha('9'),
    keyAttributes,
    publicKeySha256,
    reviewerIdentity: authorityConfig.reviewerIdentity,
    reviewerKeyId: publicKeySha256,
    schemaVersion: 1,
    witnessUid: authorityConfig.witnessUid,
  };
  const enrolmentSignature = sign(
    'sha256',
    Buffer.concat([
      A28_ENROLMENT_SIGNING_PREFIX,
      Buffer.from(canonicalA28Json(enrolmentProofPayload), 'utf8'),
    ]),
    keyPair.privateKey,
  );
  const enrolment = {
    algorithm: 'ES256',
    enrolledAt: enrolmentProofPayload.enrolledAt,
    enrolmentAuthorityConfigSha256,
    enrolmentProof: {
      algorithm: enrolmentProofPayload.algorithm,
      enrolledAt: enrolmentProofPayload.enrolledAt,
      enrolmentAuthorityConfigSha256,
      enrolmentNonce: enrolmentProofPayload.enrolmentNonce,
      keyAttributes,
      publicKeySha256,
      reviewerIdentity: enrolmentProofPayload.reviewerIdentity,
      reviewerKeyId: enrolmentProofPayload.reviewerKeyId,
      signatureDerBase64: enrolmentSignature.toString('base64'),
      witnessUid: authorityConfig.witnessUid,
    },
    keyAttributes,
    publicKeySha256,
    publicKeySpkiDerBase64: publicSpki.toString('base64'),
    reviewerIdentity: authorityConfig.reviewerIdentity,
    reviewerKeyId: publicKeySha256,
    schemaVersion: 1,
    witnessUid: authorityConfig.witnessUid,
  };
  const enrolmentBytes = canonicalA28Line(enrolment);
  const enrolmentIdentity = {
    auditTokenSha256: sha('a'),
    bundleIdentifier: authorityConfig.bundleIdentifier,
    cdHash: authorityConfig.cdHash,
    designatedRequirement: authorityConfig.designatedRequirement,
    executable: authorityConfig.witnessExecutable,
    pid: 1101,
    startTime: '1785451000.100000',
  };
  const enrolmentAuthorityReceipt = {
    applicationIdentityAfter: enrolmentIdentity,
    applicationIdentityBefore: enrolmentIdentity,
    authorisedAt: '2026-07-31T11:01:00.000Z',
    enrolmentAuthorityConfigSha256,
    enrolmentManifestSha256: sha256A28(enrolmentBytes),
    event: 'a28-secure-enclave-enrolment-authorised',
    keyAttributes,
    outputIdentity: {
      dev: 16777233,
      gid: 0,
      ino: 4001,
      mode: 0o400,
      path: authorityConfig.enrolmentManifestPath,
      sha256: sha256A28(enrolmentBytes),
      size: enrolmentBytes.length,
      uid: 0,
    },
    publicKeySha256,
    reviewerIdentity: authorityConfig.reviewerIdentity,
    reviewerKeyId: publicKeySha256,
    schemaVersion: 1,
    witnessGid: authorityConfig.witnessGid,
    witnessUid: authorityConfig.witnessUid,
  };
  const policy = {
    ...authorityConfig,
    enrolmentAuthorityConfigPath:
      '/Library/Application Support/PIUI/A28Witness/enrolment-authority.json',
    enrolmentAuthorityConfigSha256,
    enrolmentAuthorityReceiptSha256: sha256A28(
      canonicalA28Line(enrolmentAuthorityReceipt),
    ),
    enrolmentManifestSha256: sha256A28(enrolmentBytes),
  };
  const policyPinSha256 = sha256A28(canonicalA28Line(policy));
  const hostExecutable = executable(
    '/private/var/piui/PIUI Architecture Test.app/Contents/MacOS/piui',
    'a',
    5101,
  );
  const runnerExecutable = executable(
    '/private/tmp/piui-authenticated-toolchain/run/node-tool/bin/node',
    'b',
    5102,
  );
  const voiceOverExecutable = executable(
    '/System/Library/CoreServices/VoiceOver.app/Contents/MacOS/VoiceOver',
    'c',
    5103,
  );
  const architectureGateRunId =
    '20260731T120000000Z-cccccccccccccccccccccccccccccccc';
  const checkpointSessionId = sha('4');
  const witnessNonce = sha('3');
  const challengeRequest = {
    applicationPid: 1201,
    architectureGateRunContextSha256: sha('c'),
    architectureGateRunId,
    automationTwinFingerprint: sha('d'),
    gateId: 'A.28',
    hostAuditTokenSha256: sha('e'),
    hostBundleFingerprint: sha('d'),
    hostBundleIdentifier: 'au.com.piui.desktop.architecture-test',
    hostBundlePath: '/private/var/piui/PIUI Architecture Test.app',
    hostCdHash: cdHash('b'),
    hostDesignatedRequirement: policy.hostDesignatedRequirement,
    hostExecutable,
    hostStartTime: '1785453000.123456',
    macosVersion: '26.5.2',
    measuredTwinDeltaSha256: sha('f'),
    policyPinSha256,
    productionFingerprint: sha('0'),
    reviewerIdentity: policy.reviewerIdentity,
    reviewerKeyId: publicKeySha256,
    runnerAuditTokenSha256: sha('1'),
    runnerAuthority: 'continuity-only',
    runnerBundleIdentifier: policy.runnerBundleIdentifier,
    runnerCdHash: cdHash('c'),
    runnerDesignatedRequirement: policy.runnerDesignatedRequirement,
    runnerExecutable,
    runnerPid: 1202,
    runnerStartTime: '1785452990.654321',
    schemaVersion: 1,
    sourceDigest: sha('2'),
    voiceOverAuditTokenSha256: sha('a'),
    voiceOverBundleIdentifier: 'com.apple.VoiceOver',
    voiceOverCdHash: cdHash('e'),
    voiceOverDesignatedRequirement: policy.voiceOverDesignatedRequirement,
    voiceOverExecutable,
    voiceOverPid: 1204,
    voiceOverStartTime: '1785452980.222222',
    voiceOverVersion: '11.0.1',
  };
  const challengeRequestSha256 = a28ChallengeRequestSha256(challengeRequest);
  const checkpointTokens = [sha('5'), sha('6'), sha('7'), sha('8')];
  const stateCheckpoints = [
    ['dark', 'accessible'],
    ['dark', 'virtualised'],
    ['light', 'accessible'],
    ['light', 'virtualised'],
  ].map(([appearance, mode], index) => {
    const checkpointId = sha(String(index + 1));
    return {
      appearance,
      checkpointId,
      mode,
      ordinal: index + 1,
      tokenSha256: a28CheckpointCommitmentSha256({
        appearance,
        architectureGateRunId,
        challengeRequestSha256,
        checkpointId,
        checkpointSessionId,
        mode,
        ordinal: index + 1,
        token: checkpointTokens[index],
        witnessNonce,
      }),
    };
  });
  const challenge = {
    ...challengeRequest,
    attestationSlot: {
      dev: 16777233,
      gid: policy.witnessGid,
      ino: 6101,
      path: policy.checkpointDeliveryDirectoryPath
        + '/' + checkpointSessionId + '.attestation.json',
      uid: policy.witnessUid,
    },
    challengeExpiresAt: '2026-07-31T12:20:00.000Z',
    challengeIssuedAt: '2026-07-31T12:00:00.000Z',
    challengeRequestSha256,
    checkpointSessionId,
    gateContextAuthority: A28_GATE_CONTEXT_AUTHORITY,
    stateCheckpoints,
    witnessNonce,
  };
  const checks = [
    ['dark', 'accessible', '2026-07-31T12:02:00.000Z'],
    ['dark', 'virtualised', '2026-07-31T12:03:00.000Z'],
    ['light', 'accessible', '2026-07-31T12:04:00.000Z'],
    ['light', 'virtualised', '2026-07-31T12:05:00.000Z'],
  ].map(([appearance, mode, observedAt], index) => ({
    announcements: 'pass',
    assertionScope: A28_HUMAN_ASSERTION_SCOPE,
    appearance,
    blockingDefects: [],
    checkpointId: stateCheckpoints[index].checkpointId,
    checkpointOrdinal: index + 1,
    checkpointToken: checkpointTokens[index],
    checkpointTokenSha256: stateCheckpoints[index].tokenSha256,
    focusRetention: 'pass',
    humanAssertion: true,
    keyboardOrder: 'pass',
    mode,
    observedAt,
  }));
  const payload = {
    ...challenge,
    challengeSha256: sha256A28(canonicalA28Line(challenge)),
    checks,
    completedAt: '2026-07-31T12:06:00.000Z',
    domain: A28_WITNESS_DOMAIN,
    observationStartedAt: '2026-07-31T12:01:00.000Z',
    status: 'pass',
    witnessApplicationPid: 1203,
    witnessAuditTokenSha256: sha('4'),
    witnessBundleIdentifier: policy.bundleIdentifier,
    witnessCdHash: policy.cdHash,
    witnessDesignatedRequirement: policy.designatedRequirement,
    witnessExecutable: policy.witnessExecutable,
    witnessKeySha256: publicKeySha256,
    witnessStartTime: '1785453010.111111',
    witnessUid: policy.witnessUid,
  };
  const inspection = {
    applicationIdentifier: policy.applicationIdentifier,
    appleCertificateChain: [
      policy.signingIdentity,
      'Developer ID Certification Authority',
      'Apple Root CA',
    ],
    bundleIdentifier: policy.bundleIdentifier,
    cdHash: policy.cdHash,
    designatedRequirement: policy.designatedRequirement,
    effectiveEntitlements: policy.effectiveEntitlements,
    effectiveEntitlementsSha256: policy.effectiveEntitlementsSha256,
    hardenedRuntime: true,
    installedApplicationPath: policy.installedApplicationPath,
    keychainAccessGroups: [policy.keychainAccessGroup],
    profileName: policy.profileName,
    profileSha256: policy.profileSha256,
    profileTeamIdentifiers: [policy.teamIdentifier],
    profileUuid: policy.profileUuid,
    signingCertificateSha256: policy.signingCertificateSha256,
    signingIdentity: policy.signingIdentity,
    teamIdentifier: policy.teamIdentifier,
  };
  const live = {
    host: {
      auditTokenSha256: challenge.hostAuditTokenSha256,
      bundleIdentifier: challenge.hostBundleIdentifier,
      cdHash: challenge.hostCdHash,
      designatedRequirement: challenge.hostDesignatedRequirement,
      executable: challenge.hostExecutable,
      pid: challenge.applicationPid,
      startTime: challenge.hostStartTime,
    },
    runner: {
      auditTokenSha256: challenge.runnerAuditTokenSha256,
      bundleIdentifier: challenge.runnerBundleIdentifier,
      cdHash: challenge.runnerCdHash,
      designatedRequirement: challenge.runnerDesignatedRequirement,
      executable: challenge.runnerExecutable,
      pid: challenge.runnerPid,
      startTime: challenge.runnerStartTime,
    },
    voiceOver: {
      auditTokenSha256: challenge.voiceOverAuditTokenSha256,
      bundleIdentifier: challenge.voiceOverBundleIdentifier,
      cdHash: challenge.voiceOverCdHash,
      designatedRequirement: challenge.voiceOverDesignatedRequirement,
      executable: challenge.voiceOverExecutable,
      pid: challenge.voiceOverPid,
      startTime: challenge.voiceOverStartTime,
    },
    witness: {
      auditTokenSha256: payload.witnessAuditTokenSha256,
      bundleIdentifier: payload.witnessBundleIdentifier,
      cdHash: payload.witnessCdHash,
      designatedRequirement: payload.witnessDesignatedRequirement,
      executable: payload.witnessExecutable,
      pid: payload.witnessApplicationPid,
      startTime: payload.witnessStartTime,
    },
  };
  function attestationBytes(payloadValue = payload) {
    const signature = sign(
      'sha256',
      Buffer.concat([
        A28_WITNESS_SIGNING_PREFIX,
        Buffer.from(canonicalA28Json(payloadValue), 'utf8'),
      ]),
      keyPair.privateKey,
    );
    return canonicalA28Line({
      algorithm: 'ES256',
      payload: payloadValue,
      schemaVersion: 1,
      signatureDerBase64: signature.toString('base64'),
    });
  }
  return {
    attestationBytes,
    authorityConfig,
    challenge,
    challengeRequest,
    enrolment,
    enrolmentAuthorityReceipt,
    inspection,
    keyPair,
    live,
    payload,
    policy,
  };
}

function verificationInput(fixture, overrides = {}) {
  const attestationBytes = overrides.attestationBytes
    ?? fixture.attestationBytes();
  return {
    attestationBytes,
    attestationOutputIdentity: {
      ...fixture.challenge.attestationSlot,
      mode: 0o400,
      sha256: sha256A28(attestationBytes),
      size: attestationBytes.length,
    },
    authoriseCheckpoints: async (record) => ({
      authorised: true,
      authorisedAt: '2026-07-31T12:06:30.000Z',
      challengeSha256: record.challengeSha256,
      challengeRequestSha256: record.challengeRequestSha256,
      checkpointChecksSha256: record.checkpointChecksSha256,
      checkpointSessionId: record.checkpointSessionId,
    }),
    authorityConfig: fixture.authorityConfig,
    challenge: fixture.challenge,
    consumeOnce: async (record) => record,
    enrolment: fixture.enrolment,
    enrolmentAuthorityReceipt: fixture.enrolmentAuthorityReceipt,
    inspection: fixture.inspection,
    now,
    observeLiveIdentities: async () => fixture.live,
    policyPin: fixture.policy,
    ...overrides,
    attestationBytes,
    attestationOutputIdentity: overrides.attestationOutputIdentity ?? {
      ...fixture.challenge.attestationSlot,
      mode: 0o400,
      sha256: sha256A28(attestationBytes),
      size: attestationBytes.length,
    },
  };
}

test('accepts one canonical, fresh, passing witness bound to every live identity', async () => {
  const fixture = makeFixture();
  const attestationBytes = fixture.attestationBytes();
  assert.deepEqual(assertA28PolicyPin(fixture.policy), fixture.policy);
  assert.deepEqual(
    assertA28EnrolmentAuthorityConfig(fixture.authorityConfig),
    fixture.authorityConfig,
  );
  assert.deepEqual(assertA28Enrolment(fixture.enrolment, fixture.policy, now), fixture.enrolment);
  assert.deepEqual(assertA28EnrolmentAuthorityReceipt(
    fixture.enrolmentAuthorityReceipt,
    {
      authorityConfig: fixture.authorityConfig,
      enrolment: fixture.enrolment,
      now,
      policyPin: fixture.policy,
    },
  ), fixture.enrolmentAuthorityReceipt);
  assert.deepEqual(assertA28Challenge(fixture.challenge, now), fixture.challenge);
  assert.deepEqual(
    assertA28WitnessAppInspection(fixture.inspection, fixture.policy),
    fixture.inspection,
  );
  const stages = [];
  let consumedRecord;
  const result = await verifyA28WitnessAttestation(verificationInput(fixture, {
    attestationBytes,
    consumeOnce: async (record) => {
      consumedRecord = record;
      return record;
    },
    observeLiveIdentities: async (stage) => {
      stages.push(stage);
      return fixture.live;
    },
  }));
  assert.equal(result.humanWitnessed, true);
  assert.equal(result.status, 'pass');
  assert.deepEqual(stages, [
    'before-signature-verification',
    'after-signature-verification',
  ]);
  assert.equal(consumedRecord.architectureGateRunId, fixture.challenge.architectureGateRunId);
  assert.equal(
    consumedRecord.architectureGateRunContextSha256,
    fixture.challenge.architectureGateRunContextSha256,
  );
  assert.equal(consumedRecord.measuredTwinDeltaSha256, fixture.challenge.measuredTwinDeltaSha256);
  assert.equal(consumedRecord.hostBundleIdentifier, fixture.challenge.hostBundleIdentifier);
  assert.equal(consumedRecord.macosVersion, fixture.challenge.macosVersion);
  assert.equal(consumedRecord.runnerExecutableSha256, fixture.challenge.runnerExecutable.sha256);
  assert.equal(consumedRecord.witnessBundleIdentifier, fixture.policy.bundleIdentifier);
  assert.equal(consumedRecord.witnessExecutableSha256, fixture.policy.witnessExecutable.sha256);
  assert.deepEqual(assertA28PublishedReceipt(consumedRecord, {
    attestationBytes,
    challenge: fixture.challenge,
    enrolment: fixture.enrolment,
    now,
    policyPin: fixture.policy,
  }), consumedRecord);
  for (const changed of [
    { ...consumedRecord, consumed: false },
    { ...consumedRecord, challengeRequestSha256: sha('f') },
    { ...consumedRecord, gateContextAuthority: 'root-authenticated' },
    { ...consumedRecord, gateContextComparisonRequired: false },
    {
      ...consumedRecord,
      attestationOutputIdentity: {
        ...consumedRecord.attestationOutputIdentity,
        ino: consumedRecord.attestationOutputIdentity.ino + 1,
      },
    },
    {
      ...consumedRecord,
      attestationOutputIdentity: {
        ...consumedRecord.attestationOutputIdentity,
        mode: 0o600,
      },
    },
    { ...consumedRecord, humanWitnessed: false },
    { ...consumedRecord, status: 'fail' },
    { ...consumedRecord, architectureGateRunContextSha256: sha('a') },
    { ...consumedRecord, hostBundleIdentifier: 'au.com.piui.forged' },
    { ...consumedRecord, macosVersion: '1.0' },
    { ...consumedRecord, runnerExecutableSha256: sha('a') },
    { ...consumedRecord, witnessBundleIdentifier: 'au.com.piui.forged' },
    { ...consumedRecord, witnessExecutableSha256: sha('a') },
    { ...consumedRecord, completedAt: '2026-07-31T12:05:59.000Z' },
    { ...consumedRecord, observationStartedAt: '2026-07-31T12:01:01.000Z' },
    { ...consumedRecord, witnessApplicationPid: 9999 },
    { ...consumedRecord, witnessAuditTokenSha256: sha('a') },
    { ...consumedRecord, witnessStartTime: '1785453011.111111' },
    { ...consumedRecord, receiptPath: '/private/forged' },
  ]) {
    assert.throws(() => assertA28PublishedReceipt(changed, {
      attestationBytes,
      challenge: fixture.challenge,
      enrolment: fixture.enrolment,
      now,
      policyPin: fixture.policy,
    }));
  }
});

test('rejects replay even when the original signature remains cryptographically valid', async () => {
  const fixture = makeFixture();
  const consumed = new Set();
  const input = verificationInput(fixture, {
    consumeOnce: async (record) => {
      if (consumed.has(record.witnessNonce)) throw new Error('already consumed');
      consumed.add(record.witnessNonce);
      return record;
    },
  });
  await verifyA28WitnessAttestation(input);
  await assert.rejects(verifyA28WitnessAttestation(input), /already consumed/u);
});

test('rejects canonical and cryptographic substitution attacks', async () => {
  const fixture = makeFixture();
  const validBytes = fixture.attestationBytes();
  assert.throws(() => parseCanonicalA28Line(Buffer.from(
    JSON.stringify(JSON.parse(validBytes.toString('utf8')), null, 2) + '\n',
  )));
  assert.throws(() => parseCanonicalA28Line(Buffer.concat([
    validBytes.subarray(0, -1),
    Buffer.from('\r\n'),
  ])));
  const envelope = JSON.parse(validBytes.toString('utf8'));
  const signature = Buffer.from(envelope.signatureDerBase64, 'base64');
  signature[signature.length - 1] ^= 1;
  envelope.signatureDerBase64 = signature.toString('base64');
  await assert.rejects(verifyA28WitnessAttestation(verificationInput(fixture, {
    attestationBytes: canonicalA28Line(envelope),
  })));

  const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const otherSpki = other.publicKey.export({ format: 'der', type: 'spki' });
  const forgedEnrolment = {
    ...fixture.enrolment,
    publicKeySha256: sha256A28(otherSpki),
    publicKeySpkiDerBase64: otherSpki.toString('base64'),
    reviewerKeyId: sha256A28(otherSpki),
  };
  await assert.rejects(verifyA28WitnessAttestation(verificationInput(fixture, {
    enrolment: forgedEnrolment,
  })));

  const forgedSecurityClaims = {
    ...fixture.enrolment,
    dataProtectionKeychain: false,
    enrolmentProof: {
      ...fixture.enrolment.enrolmentProof,
      dataProtectionKeychain: false,
    },
  };
  await assert.rejects(verifyA28WitnessAttestation(verificationInput(fixture, {
    enrolment: forgedSecurityClaims,
  })));
});

test('rejects re-signed semantic forgeries across gate, runner, host, witness and review bindings', async () => {
  const mutations = [
    (payload) => ({ ...payload, architectureGateRunContextSha256: sha('a') }),
    (payload) => ({
      ...payload,
      architectureGateRunId:
        '20260731T120000000Z-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    }),
    (payload) => ({ ...payload, measuredTwinDeltaSha256: sha('a') }),
    (payload) => ({ ...payload, reviewerIdentity: 'Mallory Example' }),
    (payload) => ({ ...payload, reviewerKeyId: sha('a') }),
    (payload) => ({ ...payload, runnerCdHash: cdHash('d') }),
    (payload) => ({
      ...payload,
      runnerExecutable: { ...payload.runnerExecutable, sha256: sha('a') },
    }),
    (payload) => ({ ...payload, hostStartTime: '1785453001.123456' }),
    (payload) => ({ ...payload, hostCdHash: cdHash('d') }),
    (payload) => ({ ...payload, witnessStartTime: '1785453011.111111' }),
    (payload) => ({ ...payload, witnessAuditTokenSha256: sha('a') }),
    (payload) => ({ ...payload, witnessCdHash: cdHash('d') }),
    (payload) => ({
      ...payload,
      witnessExecutable: { ...payload.witnessExecutable, ino: 9999 },
    }),
    (payload) => ({ ...payload, voiceOverVersion: 'forged' }),
    (payload) => ({
      ...payload,
      checks: [payload.checks[1], payload.checks[0], ...payload.checks.slice(2)],
    }),
    (payload) => ({
      ...payload,
      checks: payload.checks.map((check, index) => index === 0
        ? { ...check, observedAt: '2026-07-31T12:05:30.000Z' }
        : check),
    }),
    (payload) => ({ ...payload, injected: true }),
  ];
  for (const mutate of mutations) {
    const fixture = makeFixture();
    const changed = mutate(fixture.payload);
    await assert.rejects(verifyA28WitnessAttestation(verificationInput(fixture, {
      attestationBytes: fixture.attestationBytes(changed),
    })));
  }
});

test('rejects live process replacement before consumption', async () => {
  const mutations = [
    (live) => ({
      ...live,
      runner: {
        ...live.runner,
        executable: { ...live.runner.executable, ino: 9999 },
      },
    }),
    (live) => ({
      ...live,
      witness: { ...live.witness, auditTokenSha256: sha('a') },
    }),
    (live) => ({
      ...live,
      host: { ...live.host, startTime: '1785453001.123456' },
    }),
  ];
  for (const mutate of mutations) {
    const fixture = makeFixture();
    let calls = 0;
    await assert.rejects(verifyA28WitnessAttestation(verificationInput(fixture, {
      observeLiveIdentities: async () => {
        calls += 1;
        return calls === 1 ? fixture.live : mutate(fixture.live);
      },
    })));
  }
});

test('a signed failing observation remains auditable but cannot pass the gate', async () => {
  const fixture = makeFixture();
  const checks = fixture.payload.checks.map((check, index) => index === 0
    ? {
      ...check,
      announcements: 'fail',
      blockingDefects: ['VoiceOver did not announce the focused row.'],
    }
    : check);
  const failing = { ...fixture.payload, checks, status: 'fail' };
  const input = verificationInput(fixture, {
    attestationBytes: fixture.attestationBytes(failing),
  });
  await assert.rejects(verifyA28WitnessAttestation(input));
  const result = await verifyA28WitnessAttestation({
    ...input,
    requirePassing: false,
  });
  assert.equal(result.humanWitnessed, true);
  assert.equal(result.status, 'fail');
});

test('requires the pinned root enrolment authority receipt and rejects candidate substitution', async () => {
  const fixture = makeFixture();
  await assert.rejects(verifyA28WitnessAttestation(verificationInput(fixture, {
    enrolmentAuthorityReceipt: undefined,
  })));
  const substituted = makeFixture();
  await assert.rejects(verifyA28WitnessAttestation(verificationInput(fixture, {
    enrolment: substituted.enrolment,
  })));
  assert.throws(() => assertA28EnrolmentAuthorityReceipt({
    ...fixture.enrolmentAuthorityReceipt,
    enrolmentManifestSha256: sha('f'),
  }, {
    authorityConfig: fixture.authorityConfig,
    enrolment: fixture.enrolment,
    now,
    policyPin: fixture.policy,
  }));
});

test('root-issued checkpoint commitments reject cross-session, replay, order and authorisation substitution', async () => {
  const fixture = makeFixture();
  const changedToken = {
    ...fixture.payload,
    checks: fixture.payload.checks.map((check, index) => index === 0
      ? { ...check, checkpointToken: sha('f') }
      : check),
  };
  await assert.rejects(verifyA28WitnessAttestation(verificationInput(fixture, {
    attestationBytes: fixture.attestationBytes(changedToken),
  })));

  const replayedToken = {
    ...fixture.payload,
    checks: fixture.payload.checks.map((check, index) => index === 1
      ? { ...check, checkpointToken: fixture.payload.checks[0].checkpointToken }
      : check),
  };
  await assert.rejects(verifyA28WitnessAttestation(verificationInput(fixture, {
    attestationBytes: fixture.attestationBytes(replayedToken),
  })));

  const crossSessionChallenge = {
    ...fixture.challenge,
    checkpointSessionId: sha('f'),
  };
  const crossSessionPayload = {
    ...fixture.payload,
    ...crossSessionChallenge,
    challengeSha256: sha256A28(canonicalA28Line(crossSessionChallenge)),
  };
  await assert.rejects(verifyA28WitnessAttestation(verificationInput(fixture, {
    attestationBytes: fixture.attestationBytes(crossSessionPayload),
    challenge: crossSessionChallenge,
  })));

  await assert.rejects(verifyA28WitnessAttestation(verificationInput(fixture, {
    authoriseCheckpoints: async (record) => ({
      authorised: true,
      authorisedAt: '2026-07-31T12:06:30.000Z',
      challengeSha256: record.challengeSha256,
      challengeRequestSha256: record.challengeRequestSha256,
      checkpointChecksSha256: sha('f'),
      checkpointSessionId: record.checkpointSessionId,
    }),
  })));

  let consumed = false;
  const input = verificationInput(fixture, {
    authoriseCheckpoints: async (record) => {
      if (consumed) throw new Error('checkpoint session already consumed');
      consumed = true;
      return {
        authorised: true,
        authorisedAt: '2026-07-31T12:06:30.000Z',
        challengeSha256: record.challengeSha256,
        challengeRequestSha256: record.challengeRequestSha256,
        checkpointChecksSha256: record.checkpointChecksSha256,
        checkpointSessionId: record.checkpointSessionId,
      };
    },
  });
  await verifyA28WitnessAttestation(input);
  await assert.rejects(
    verifyA28WitnessAttestation(input),
    /checkpoint session already consumed/u,
  );
});

test('pins non-ad-hoc requirements and the exact VoiceOver process', async () => {
  const fixture = makeFixture();
  for (const policy of [
    {
      ...fixture.policy,
      hostDesignatedRequirement:
        'identifier "au.com.piui.desktop.architecture-test" and anchor apple generic or always',
    },
    {
      ...fixture.policy,
      runnerDesignatedRequirement:
        'identifier node and anchor apple generic',
    },
    {
      ...fixture.policy,
      voiceOverDesignatedRequirement:
        'identifier "com.apple.VoiceOver" and anchor apple generic',
    },
    {
      ...fixture.policy,
      hostDesignatedRequirement:
        'identifier "au.com.piui.desktop.architecture-test" and not anchor apple generic and certificate leaf[subject.OU] = AB12CD34EF',
    },
    {
      ...fixture.policy,
      voiceOverDesignatedRequirement:
        'identifier "com.apple.VoiceOver" and not anchor apple',
    },
    {
      ...fixture.policy,
      hostDesignatedRequirement:
        '(anchor apple generic and identifier "au.com.piui.desktop.architecture-test" and certificate leaf[subject.OU] = AB12CD34EF)or(identifier "au.com.piui.desktop.architecture-test")',
    },
    {
      ...fixture.policy,
      hostDesignatedRequirement:
        '((anchor apple generic and identifier "au.com.piui.desktop.architecture-test" and certificate leaf[subject.OU] = AB12CD34EF)or(identifier "au.com.piui.desktop.architecture-test"))',
    },
  ]) assert.throws(() => assertA28PolicyPin(policy));

  await assert.rejects(verifyA28WitnessAttestation(verificationInput(fixture, {
    observeLiveIdentities: async () => ({
      ...fixture.live,
      voiceOver: {
        ...fixture.live.voiceOver,
        executable: { ...fixture.live.voiceOver.executable, ino: 9999 },
      },
    }),
  })));
});

test('validates the runner request but reserves nonce, timestamps and checkpoint tokens for root', () => {
  const fixture = makeFixture();
  const request = Object.fromEntries(Object.entries(fixture.challenge).filter(
    ([key]) => ![
      'challengeExpiresAt',
      'challengeIssuedAt',
      'challengeRequestSha256',
      'checkpointSessionId',
      'attestationSlot',
      'gateContextAuthority',
      'stateCheckpoints',
      'witnessNonce',
    ].includes(key),
  ));
  assert.deepEqual(
    assertA28ChallengeRequest(request, fixture.policy, now),
    request,
  );
  assert.throws(() => assertA28ChallengeRequest({
    ...request,
    witnessNonce: sha('f'),
  }, fixture.policy, now));
  assert.equal(
    fixture.challenge.challengeRequestSha256,
    a28ChallengeRequestSha256(request),
  );
  for (const changed of [
    { ...fixture.challenge, sourceDigest: sha('f') },
    { ...fixture.challenge, challengeRequestSha256: sha('f') },
    { ...fixture.challenge, gateContextAuthority: 'root-authenticated' },
    {
      ...fixture.challenge,
      attestationSlot: { ...fixture.challenge.attestationSlot, ino: 0 },
    },
  ]) assert.throws(() => assertA28Challenge(changed, now, fixture.policy));
});

test('checkpoint authority argument parsing rejects omissions, duplicates, extras and cross-action fields', () => {
  const input = '/Library/Application Support/PIUI/A28Witness/input.json';
  const output = '/Library/Application Support/PIUI/A28Witness/output';
  assert.deepEqual(parseA28CheckpointAuthorityArguments([
    '--action', 'prepare', '--input', input, '--output', output,
  ]), {
    action: 'prepare', input, output, witnessPid: undefined,
  });
  assert.deepEqual(parseA28CheckpointAuthorityArguments([
    '--action', 'reveal', '--input', input, '--output', output,
    '--witness-pid', '1203',
  ]), {
    action: 'reveal', input, output, witnessPid: 1203,
  });
  for (const argv of [
    ['--action', 'prepare', '--input', input],
    ['--action', 'prepare', '--input', input, '--output', output,
      '--witness-pid', '1203'],
    ['--action', 'reveal', '--input', input, '--output', output],
    ['--action', 'authorise', '--input', input, '--output', output,
      '--witness-pid', '1203'],
    ['--action', 'prepare', '--input', input, '--input', input,
      '--output', output],
    ['--action', 'prepare', '--input', 'relative.json', '--output', output],
    ['--action', 'unknown', '--input', input, '--output', output],
    ['--action', 'prepare', '--input', input, '--output', output,
      '--extra', 'value'],
  ]) assert.throws(() => parseA28CheckpointAuthorityArguments(argv));
});

test('deterministic test authority completes prepare, four reveals, slot sealing, authorisation and one-use consumption', async () => {
  const fixture = makeFixture();
  const request = assertA28ChallengeRequest(
    fixture.challengeRequest,
    fixture.policy,
    now,
  );
  const requestDigest = a28ChallengeRequestSha256(request);
  assert.equal(requestDigest, fixture.challenge.challengeRequestSha256);

  const testAuthority = {
    consumed: false,
    nextOrdinal: 1,
    requestDigest,
    reveals: [],
    slot: {
      ...fixture.challenge.attestationSlot,
      mode: 0o200,
      size: 0,
    },
  };
  for (const decision of fixture.payload.checks) {
    assert.equal(decision.checkpointOrdinal, testAuthority.nextOrdinal);
    const checkpoint = fixture.challenge.stateCheckpoints[
      testAuthority.nextOrdinal - 1
    ];
    assert.equal(a28CheckpointCommitmentSha256({
      appearance: checkpoint.appearance,
      architectureGateRunId: fixture.challenge.architectureGateRunId,
      challengeRequestSha256: requestDigest,
      checkpointId: checkpoint.checkpointId,
      checkpointSessionId: fixture.challenge.checkpointSessionId,
      mode: checkpoint.mode,
      ordinal: checkpoint.ordinal,
      token: decision.checkpointToken,
      witnessNonce: fixture.challenge.witnessNonce,
    }), checkpoint.tokenSha256);
    testAuthority.reveals.push(Object.freeze({
      challengeRequestSha256: requestDigest,
      checkpointId: checkpoint.checkpointId,
      ordinal: checkpoint.ordinal,
      token: decision.checkpointToken,
      tokenSha256: checkpoint.tokenSha256,
    }));
    testAuthority.nextOrdinal += 1;
  }
  assert.equal(testAuthority.reveals.length, 4);

  const attestationBytes = fixture.attestationBytes();
  testAuthority.slot = {
    ...testAuthority.slot,
    mode: 0o400,
    sha256: sha256A28(attestationBytes),
    size: attestationBytes.length,
  };
  let authorisationConsumed = false;
  const input = verificationInput(fixture, {
    attestationBytes,
    attestationOutputIdentity: testAuthority.slot,
    authoriseCheckpoints: async (record) => {
      if (authorisationConsumed) throw new Error('test checkpoint already consumed');
      assert.equal(record.challengeRequestSha256, testAuthority.requestDigest);
      assert.equal(testAuthority.nextOrdinal, 5);
      assert.equal(record.checks.length, testAuthority.reveals.length);
      for (let index = 0; index < record.checks.length; index += 1) {
        assert.equal(
          record.checks[index].checkpointToken,
          testAuthority.reveals[index].token,
        );
      }
      authorisationConsumed = true;
      return {
        authorised: true,
        authorisedAt: '2026-07-31T12:06:30.000Z',
        challengeRequestSha256: record.challengeRequestSha256,
        challengeSha256: record.challengeSha256,
        checkpointChecksSha256: record.checkpointChecksSha256,
        checkpointSessionId: record.checkpointSessionId,
      };
    },
    consumeOnce: async (record) => {
      if (testAuthority.consumed) throw new Error('test witness already consumed');
      testAuthority.consumed = true;
      return record;
    },
  });
  const result = await verifyA28WitnessAttestation(input);
  assert.equal(result.status, 'pass');
  assert.equal(testAuthority.consumed, true);
  await assert.rejects(
    verifyA28WitnessAttestation(input),
    /test checkpoint already consumed/u,
  );

  assert.throws(() => assertA28Challenge({
    ...fixture.challenge,
    challengeRequestSha256: sha('f'),
  }, now, fixture.policy));
  assert.throws(() => assertA28ChallengeRequest({
    ...request,
    sourceDigest: sha('f'),
    unexpected: true,
  }, fixture.policy, now));
});
