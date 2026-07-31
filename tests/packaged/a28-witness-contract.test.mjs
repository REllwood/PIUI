import assert from 'node:assert/strict';
import {
  generateKeyPairSync,
  sign,
} from 'node:crypto';
import test from 'node:test';
import {
  A28_ENROLMENT_DOMAIN,
  A28_ENROLMENT_SIGNING_PREFIX,
  A28_WITNESS_DOMAIN,
  A28_WITNESS_SIGNING_PREFIX,
  assertA28Challenge,
  assertA28Enrolment,
  assertA28PolicyPin,
  assertA28PublishedReceipt,
  assertA28WitnessAppInspection,
  canonicalA28Json,
  canonicalA28Line,
  parseCanonicalA28Line,
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

function makePolicy() {
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
    designatedRequirement:
      'identifier "au.com.piui.a28-witness" and anchor apple generic and certificate leaf[subject.OU] = AB12CD34EF',
    effectiveEntitlements,
    effectiveEntitlementsSha256: sha256A28(
      Buffer.from(canonicalA28Json(effectiveEntitlements), 'utf8'),
    ),
    enrolmentManifestPath:
      '/Library/Application Support/PIUI/A28Witness/enrolment.json',
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
    rootVerifierContractPath:
      '/Library/Application Support/PIUI/A28Witness/verifier/contract.mjs',
    rootVerifierContractSha256: sha('3'),
    rootVerifierEntrypointPath:
      '/Library/Application Support/PIUI/A28Witness/verifier/verify.mjs',
    rootVerifierEntrypointSha256: sha('4'),
    rootVerifierNodePath:
      '/Library/Application Support/PIUI/A28Witness/bin/node',
    rootVerifierNodeSha256: sha('5'),
    schemaVersion: 1,
    signingCertificateSha256: sha('6'),
    signingIdentity: 'Apple Development: Rhys Ellwood (AB12CD34EF)',
    sourceSha256: sha('7'),
    teamIdentifier,
    witnessExecutable: executable(
      '/Library/Application Support/PIUI/A28Witness/app/PIUI A28 VoiceOver Witness.app/Contents/MacOS/A28Witness',
      '8',
      4101,
    ),
    witnessUid: 501,
  };
}

function makeFixture() {
  const keyPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicSpki = keyPair.publicKey.export({ format: 'der', type: 'spki' });
  const publicKeySha256 = sha256A28(publicSpki);
  const policy = makePolicy();
  const policyPinSha256 = sha256A28(canonicalA28Line(policy));
  const enrolmentProofPayload = {
    domain: A28_ENROLMENT_DOMAIN,
    enrolledAt: '2026-07-31T11:00:00.000Z',
    enrolmentNonce: sha('9'),
    policyPinSha256,
    publicKeySha256,
    schemaVersion: 1,
    witnessUid: policy.witnessUid,
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
    accessControlFlags: ['biometryCurrentSet', 'privateKeyUsage'],
    algorithm: 'ES256',
    applicationTag: 'au.com.piui.a28-witness.secure-enclave.v1',
    enrolledAt: enrolmentProofPayload.enrolledAt,
    enrolmentProof: {
      enrolledAt: enrolmentProofPayload.enrolledAt,
      enrolmentNonce: enrolmentProofPayload.enrolmentNonce,
      policyPinSha256,
      publicKeySha256,
      signatureDerBase64: enrolmentSignature.toString('base64'),
      witnessUid: policy.witnessUid,
    },
    policyPinSha256,
    publicKeySha256,
    publicKeySpkiDerBase64: publicSpki.toString('base64'),
    reviewerIdentity: policy.reviewerIdentity,
    reviewerKeyId: publicKeySha256,
    schemaVersion: 1,
    secureEnclave: true,
    tokenId: 'com.apple.setoken',
    witnessUid: policy.witnessUid,
  };
  const hostExecutable = executable(
    '/private/var/piui/PIUI Architecture Test.app/Contents/MacOS/piui',
    'a',
    5101,
  );
  const runnerExecutable = executable(
    '/Library/Application Support/PIUI/A28Witness/bin/node',
    'b',
    5102,
  );
  const challenge = {
    applicationPid: 1201,
    architectureGateRunContextSha256: sha('c'),
    architectureGateRunId:
      '20260731T120000000Z-cccccccccccccccccccccccccccccccc',
    automationTwinFingerprint: sha('d'),
    challengeExpiresAt: '2026-07-31T12:20:00.000Z',
    challengeIssuedAt: '2026-07-31T12:00:00.000Z',
    gateId: 'A.28',
    hostAuditTokenSha256: sha('e'),
    hostBundleFingerprint: sha('d'),
    hostBundleIdentifier: 'au.com.piui.desktop.architecture-test',
    hostBundlePath: '/private/var/piui/PIUI Architecture Test.app',
    hostCdHash: cdHash('b'),
    hostExecutable,
    hostStartTime: '1785453000.123456',
    macosVersion: '26.5.2',
    measuredTwinDeltaSha256: sha('f'),
    policyPinSha256,
    productionFingerprint: sha('0'),
    reviewerIdentity: policy.reviewerIdentity,
    reviewerKeyId: publicKeySha256,
    runnerAuditTokenSha256: sha('1'),
    runnerBundleIdentifier: 'org.nodejs.node',
    runnerCdHash: cdHash('c'),
    runnerExecutable,
    runnerPid: 1202,
    runnerStartTime: '1785452990.654321',
    schemaVersion: 1,
    sourceDigest: sha('2'),
    voiceOverVersion: '11.0.1',
    witnessNonce: sha('3'),
  };
  const checks = [
    ['dark', 'accessible', '2026-07-31T12:02:00.000Z'],
    ['dark', 'virtualised', '2026-07-31T12:03:00.000Z'],
    ['light', 'accessible', '2026-07-31T12:04:00.000Z'],
    ['light', 'virtualised', '2026-07-31T12:05:00.000Z'],
  ].map(([appearance, mode, observedAt]) => ({
    announcements: 'pass',
    appearance,
    blockingDefects: [],
    focusRetention: 'pass',
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
    witnessExecutable: policy.witnessExecutable,
    witnessKeySha256: publicKeySha256,
    witnessStartTime: '1785453010.111111',
    witnessUid: policy.witnessUid,
  };
  const inspection = {
    applicationIdentifier: policy.applicationIdentifier,
    appleCertificateChain: [
      policy.signingIdentity,
      'Apple Worldwide Developer Relations Certification Authority',
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
      executable: challenge.hostExecutable,
      pid: challenge.applicationPid,
      startTime: challenge.hostStartTime,
    },
    runner: {
      auditTokenSha256: challenge.runnerAuditTokenSha256,
      bundleIdentifier: challenge.runnerBundleIdentifier,
      cdHash: challenge.runnerCdHash,
      executable: challenge.runnerExecutable,
      pid: challenge.runnerPid,
      startTime: challenge.runnerStartTime,
    },
    witness: {
      auditTokenSha256: payload.witnessAuditTokenSha256,
      bundleIdentifier: payload.witnessBundleIdentifier,
      cdHash: payload.witnessCdHash,
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
    challenge,
    enrolment,
    inspection,
    keyPair,
    live,
    payload,
    policy,
  };
}

function verificationInput(fixture, overrides = {}) {
  return {
    attestationBytes: fixture.attestationBytes(),
    challenge: fixture.challenge,
    consumeOnce: async (record) => ({
      attestationSha256: record.attestationSha256,
      consumed: true,
      witnessNonce: record.witnessNonce,
    }),
    enrolment: fixture.enrolment,
    inspection: fixture.inspection,
    now,
    observeLiveIdentities: async () => fixture.live,
    policyPin: fixture.policy,
    ...overrides,
  };
}

test('accepts one canonical, fresh, passing witness bound to every live identity', async () => {
  const fixture = makeFixture();
  const attestationBytes = fixture.attestationBytes();
  assert.deepEqual(assertA28PolicyPin(fixture.policy), fixture.policy);
  assert.deepEqual(assertA28Enrolment(fixture.enrolment, fixture.policy, now), fixture.enrolment);
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
      return {
        attestationSha256: record.attestationSha256,
        consumed: true,
        witnessNonce: record.witnessNonce,
      };
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
  assert.equal(consumedRecord.runnerExecutableSha256, fixture.challenge.runnerExecutable.sha256);
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
    { ...consumedRecord, humanWitnessed: false },
    { ...consumedRecord, status: 'fail' },
    { ...consumedRecord, architectureGateRunContextSha256: sha('a') },
    { ...consumedRecord, runnerExecutableSha256: sha('a') },
    { ...consumedRecord, witnessExecutableSha256: sha('a') },
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
      return {
        attestationSha256: record.attestationSha256,
        consumed: true,
        witnessNonce: record.witnessNonce,
      };
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
