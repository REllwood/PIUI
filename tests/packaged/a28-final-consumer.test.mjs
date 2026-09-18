import assert from 'node:assert/strict';
import { chmod, lstat, mkdir, mkdtemp, realpath, rename, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import {
  a28FinalConsumerGateOwnedRequest,
  assertA28ComparedVoiceOverEvidence,
  assertA28FinalConsumerContextLease,
  compareA28FinalConsumerReceipt,
  createA28FinalConsumerContext,
  executeA28FinalConsumerCeremony,
  releaseA28FinalConsumerContext,
} from '../../scripts/a28-final-consumer.mjs';
import { canonicalA28Line } from '../../scripts/a28-witness/contract.mjs';
import {
  canonicalArchitectureJson,
  sha256Bytes,
} from '../../scripts/architecture-gate-schema.mjs';

const digest = (character) => character.repeat(64);
const runId = '20260731T120000000Z-11111111111111111111111111111111';

async function fixture() {
  const repositoryRoot = await realpath(
    await mkdtemp(join(tmpdir(), 'piui-a28-consumer-test-')),
  );
  await chmod(repositoryRoot, 0o700);
  const runDirectory = resolve(
    repositoryRoot,
    '.forge/evidence/architecture-gate/runs',
    runId,
  );
  await mkdir(runDirectory, { recursive: true, mode: 0o700 });
  for (const path of [
    resolve(repositoryRoot, '.forge'),
    resolve(repositoryRoot, '.forge/evidence'),
    resolve(repositoryRoot, '.forge/evidence/architecture-gate'),
    resolve(repositoryRoot, '.forge/evidence/architecture-gate/runs'),
    runDirectory,
  ]) await chmod(path, 0o700);
  const sourceDigest = digest('1');
  const startedBytes = Buffer.from(`${canonicalArchitectureJson({
    runId,
    schemaVersion: 1,
    sourceDigest,
    startedAt: '2026-07-31T12:00:00.000Z',
    status: 'started',
    target: 'aarch64-apple-darwin',
  })}\n`);
  await writeFile(resolve(runDirectory, 'started.json'), startedBytes, { mode: 0o600 });

  const productionApp = resolve(repositoryRoot, 'production.app');
  const automationApp = resolve(repositoryRoot, 'automation.app');
  const contextDirectory = resolve(repositoryRoot, 'consumer');
  await mkdir(productionApp, { mode: 0o700 });
  await mkdir(resolve(automationApp, 'Contents/MacOS'), { recursive: true, mode: 0o700 });
  await mkdir(contextDirectory, { mode: 0o700 });
  const hostPath = resolve(automationApp, 'Contents/MacOS/piui');
  const runnerPath = resolve(repositoryRoot, 'runner');
  const hostBytes = Buffer.from('held automation host');
  await writeFile(hostPath, hostBytes, { mode: 0o555 });
  const runnerBytes = Buffer.from('held runner');
  await writeFile(runnerPath, runnerBytes, { mode: 0o500 });
  await chmod(productionApp, 0o555);
  await chmod(automationApp, 0o555);
  const host = await lstat(hostPath);
  const productionFingerprint = digest('2');
  const automationFingerprint = digest('3');
  const measuredRecord = { kind: 'automation-twin', schemaVersion: 1 };
  const measuredDelta = {
    record: measuredRecord,
    sha256: sha256Bytes(Buffer.from(canonicalArchitectureJson(measuredRecord))),
  };
  const input = {
    architectureGateRun: {
      contextSha256: sha256Bytes(startedBytes),
      runId,
    },
    automationBundle: {
      appPath: automationApp,
      bundleIdentifier: 'au.com.piui.desktop.architecture-test',
      fingerprint: automationFingerprint,
      hostIdentity: {
        bytes: host.size,
        dev: host.dev,
        ino: host.ino,
        sha256: sha256Bytes(hostBytes),
      },
      hostPath,
      hostSigningIdentity: {
        bundleIdentifier: 'au.com.piui.desktop.architecture-test',
        cdHash: 'a'.repeat(40),
        designatedRequirement: 'anchor apple generic and identifier "au.com.piui.desktop.architecture-test"',
        executableSha256: sha256Bytes(hostBytes),
      },
    },
    consumerAnchors: {
      architectureBootstrapPinsSha256: digest('4'),
      architectureBootstrapReceiptSha256: digest('5'),
      authenticatedToolchainContextSha256: digest('6'),
      authenticatedToolchainReceiptSha256: digest('7'),
      dependencyInventorySha256: digest('8'),
      dependencyLeaseSha256: digest('9'),
      frozenSourceInventorySha256: digest('a'),
      frozenSourceLeaseSha256: digest('b'),
      packageChildContextLeaseSha256: digest('c'),
      packageChildContextSha256: digest('d'),
      sourceInputLeaseSha256: digest('e'),
      toolInputInventorySha256: digest('f'),
      toolInputLeaseSha256: digest('0'),
    },
    contextDirectory,
    hostPid: 101,
    measuredDelta,
    productionBundle: {
      appPath: productionApp,
      fingerprint: productionFingerprint,
    },
    repositoryRoot,
    runner: {
      executablePath: runnerPath,
      executableSha256: sha256Bytes(runnerBytes),
      executableSize: runnerBytes.length,
      pid: 102,
      signingIdentity: {
        bundleIdentifier: 'node',
        cdHash: 'b'.repeat(40),
        designatedRequirement: 'identifier node and anchor apple generic',
        teamIdentifier: 'HX7739G8FX',
      },
    },
    sourceDigest,
  };
  let automationEntrySha256 = sha256Bytes(hostBytes);
  let productionEntrySha256 = digest('6');
  const inventoryBundle = async (appPath) => ({
    entries: [{
      bytes: appPath === automationApp ? hostBytes.length : 1,
      dev: 1,
      ino: appPath === automationApp ? 2 : 3,
      kind: 'file',
      mode: appPath === automationApp ? 0o555 : 0o444,
      path: appPath === automationApp ? 'Contents/MacOS/piui' : 'Contents/Info.plist',
      provenance: null,
      sha256: appPath === automationApp
        ? automationEntrySha256
        : productionEntrySha256,
    }],
    fingerprint: appPath === automationApp
      ? automationFingerprint
      : productionFingerprint,
    rootProvenance: null,
  });
  let peersLive = true;
  const processInspector = async (pid) => {
    if (!peersLive) throw new Error('retained peer is no longer live');
    return {
      executable: pid === input.hostPid ? hostPath : runnerPath,
      pid,
      start: (pid === input.hostPid ? 'host-start' : 'runner-start').padEnd(24),
    };
  };
  return {
    contextDirectory,
    input,
    inventoryBundle,
    processInspector,
    repositoryRoot,
    setAutomationInventorySha256(value) { automationEntrySha256 = value; },
    setPeersLive(value) { peersLive = value; },
    setProductionInventorySha256(value) { productionEntrySha256 = value; },
  };
}

async function comparisonFixture({ changeReceipt, changeRequest } = {}) {
  const base = await fixture();
  const contextLease = await createA28FinalConsumerContext(base.input, {
    inventoryBundle: base.inventoryBundle,
    processInspector: base.processInspector,
  });
  const gate = JSON.parse(JSON.stringify(a28FinalConsumerGateOwnedRequest(contextLease)));
  const challengeRequest = {
    ...gate,
    hostAuditTokenSha256: digest('1'),
    hostCdHash: 'a'.repeat(40),
    hostDesignatedRequirement:
      'anchor apple generic and identifier "au.com.piui.desktop.architecture-test"',
    hostStartTime: '100.000001',
    runnerAuditTokenSha256: digest('2'),
    runnerBundleIdentifier: 'node',
    runnerCdHash: 'b'.repeat(40),
    runnerDesignatedRequirement: 'identifier node and anchor apple generic',
    runnerStartTime: '101.000001',
    voiceOverAuditTokenSha256: digest('3'),
    voiceOverBundleIdentifier: 'com.apple.VoiceOver',
    voiceOverCdHash: 'c'.repeat(40),
    voiceOverDesignatedRequirement:
      'identifier "com.apple.VoiceOver" and anchor apple',
    voiceOverExecutable: {
      dev: 1,
      ino: 2,
      path: '/System/Library/CoreServices/VoiceOver.app/Contents/MacOS/VoiceOver',
      sha256: digest('4'),
      size: 1_000,
    },
    voiceOverPid: 103,
    voiceOverStartTime: '102.000001',
    voiceOverVersion: '12.0',
  };
  changeRequest?.(challengeRequest);
  const challengeRequestSha256 = sha256Bytes(Buffer.from(
    `PIUI-A28-TEST-REQUEST\0${canonicalArchitectureJson(challengeRequest)}`,
  ));
  const witnessNonce = digest('5');
  const challenge = { challengeRequestSha256, witnessNonce };
  const receipt = {
    applicationPid: challengeRequest.applicationPid,
    architectureGateRunContextSha256:
      challengeRequest.architectureGateRunContextSha256,
    architectureGateRunId: challengeRequest.architectureGateRunId,
    automationTwinFingerprint: challengeRequest.automationTwinFingerprint,
    challengeRequestSha256,
    hostAuditTokenSha256: challengeRequest.hostAuditTokenSha256,
    hostBundleFingerprint: challengeRequest.hostBundleFingerprint,
    hostBundleIdentifier: challengeRequest.hostBundleIdentifier,
    hostCdHash: challengeRequest.hostCdHash,
    hostExecutableSha256: challengeRequest.hostExecutable.sha256,
    hostStartTime: challengeRequest.hostStartTime,
    measuredTwinDeltaSha256: challengeRequest.measuredTwinDeltaSha256,
    productionFingerprint: challengeRequest.productionFingerprint,
    runnerAuditTokenSha256: challengeRequest.runnerAuditTokenSha256,
    runnerAuthority: challengeRequest.runnerAuthority,
    runnerBundleIdentifier: challengeRequest.runnerBundleIdentifier,
    runnerCdHash: challengeRequest.runnerCdHash,
    runnerExecutableSha256: challengeRequest.runnerExecutable.sha256,
    runnerPid: challengeRequest.runnerPid,
    runnerStartTime: challengeRequest.runnerStartTime,
    sourceDigest: challengeRequest.sourceDigest,
    voiceOverAuditTokenSha256: challengeRequest.voiceOverAuditTokenSha256,
    voiceOverBundleIdentifier: challengeRequest.voiceOverBundleIdentifier,
    voiceOverCdHash: challengeRequest.voiceOverCdHash,
    voiceOverPid: challengeRequest.voiceOverPid,
    voiceOverStartTime: challengeRequest.voiceOverStartTime,
    voiceOverVersion: challengeRequest.voiceOverVersion,
  };
  changeReceipt?.(receipt);
  const resultDirectoryPath = resolve(base.repositoryRoot, 'root-results');
  await mkdir(resultDirectoryPath, { mode: 0o755 });
  const publishedReceiptPath = resolve(resultDirectoryPath, `${witnessNonce}.json`);
  await writeFile(publishedReceiptPath, canonicalA28Line(receipt), { mode: 0o444 });
  await chmod(publishedReceiptPath, 0o444);
  const receiptUid = typeof process.getuid === 'function' ? process.getuid() : 0;
  const dependencies = {
    assertChallengeRequest: (value) => value,
    assertPublishedReceipt: (value) => value,
    challengeRequestSha256: () => challengeRequestSha256,
    receiptRoot: base.repositoryRoot,
    receiptUid,
  };
  const input = {
    attestationBytes: Buffer.from('{}\n'),
    challenge,
    challengeRequest,
    contextLease,
    enrolment: {},
    now: Date.parse('2026-07-31T12:01:00.000Z'),
    policyPin: { resultDirectoryPath },
    publishedReceiptPath,
  };
  return { ...base, challengeRequestSha256, dependencies, input, receipt };
}

test('holds the original started context and rejects pathname substitution', async () => {
  const { contextDirectory, input, inventoryBundle, processInspector } = await fixture();
  const lease = await createA28FinalConsumerContext(input, {
    inventoryBundle,
    processInspector,
  });
  assert.equal(await assertA28FinalConsumerContextLease(lease), true);
  await assert.rejects(assertA28FinalConsumerContextLease({
    path: lease.path,
    sha256: lease.sha256,
  }));

  const original = resolve(contextDirectory, 'expected-context.opened');
  await rename(lease.path, original);
  await writeFile(lease.path, Buffer.from('{}\n'), { mode: 0o600 });
  await assert.rejects(assertA28FinalConsumerContextLease(lease));
  await releaseA28FinalConsumerContext(lease);
});

test('rejects a circular object before creating a context authority', async () => {
  const { input, inventoryBundle, processInspector } = await fixture();
  const circular = {};
  circular.self = circular;
  input.automationBundle.hostSigningIdentity = circular;
  await assert.rejects(createA28FinalConsumerContext(input, {
    inventoryBundle,
    processInspector,
  }));
});

test('only a one-use comparison receipt can produce humanWitnessed true', async () => {
  const value = await comparisonFixture();
  const voiceOver = await compareA28FinalConsumerReceipt(
    value.input,
    value.dependencies,
  );
  assert.equal(voiceOver.humanWitnessed, true);
  assert.equal(voiceOver.gateContextCompared, true);
  assert.equal(voiceOver.challengeRequestSha256, value.challengeRequestSha256);
  await assert.rejects(compareA28FinalConsumerReceipt(
    value.input,
    value.dependencies,
  ));
});

test('rejects the legacy five-key VoiceOver true object', () => {
  assert.throws(() => assertA28ComparedVoiceOverEvidence({
    blockingDefects: 0,
    checksumsValidated: true,
    evidenceValidated: true,
    humanWitnessed: true,
    modesChecked: 4,
  }));
});

function substitute(value, key) {
  if (typeof value === 'number') return value + 1_000;
  if (key === 'architectureGateRunId') {
    return `${value.slice(0, -1)}${value.endsWith('1') ? '2' : '1'}`;
  }
  if (key === 'gateId') return 'A.29';
  if (key === 'runnerAuthority') return 'attacker-owned';
  if (key === 'schemaVersion') return 2;
  if (typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value)) {
    return `${value.startsWith('f') ? 'e' : 'f'}${value.slice(1)}`;
  }
  if (typeof value === 'string' && value.startsWith('/')) return `${value}.substitute`;
  if (typeof value === 'string') return `${value}.substitute`;
  if (value && typeof value === 'object') {
    return { ...value, sha256: digest(value.sha256 === digest('f') ? 'e' : 'f') };
  }
  throw new Error(`No substitution for ${key}`);
}

test('rejects context-B substitution for every gate-owned challenge field', async (t) => {
  const keys = [
    'applicationPid',
    'architectureGateRunContextSha256',
    'architectureGateRunId',
    'automationTwinFingerprint',
    'gateId',
    'hostBundleFingerprint',
    'hostBundleIdentifier',
    'hostBundlePath',
    'hostExecutable',
    'measuredTwinDeltaSha256',
    'productionFingerprint',
    'runnerAuthority',
    'runnerExecutable',
    'runnerPid',
    'schemaVersion',
    'sourceDigest',
  ];
  for (const key of keys) {
    await t.test(key, async () => {
      const value = await comparisonFixture({
        changeRequest(request) {
          request[key] = substitute(request[key], key);
        },
      });
      await assert.rejects(compareA28FinalConsumerReceipt(
        value.input,
        value.dependencies,
      ));
    });
  }
});

test('rejects context-B substitution for every gate field copied to the receipt', async (t) => {
  const keys = [
    'applicationPid',
    'architectureGateRunContextSha256',
    'architectureGateRunId',
    'automationTwinFingerprint',
    'challengeRequestSha256',
    'hostBundleFingerprint',
    'hostBundleIdentifier',
    'hostExecutableSha256',
    'measuredTwinDeltaSha256',
    'productionFingerprint',
    'runnerAuthority',
    'runnerBundleIdentifier',
    'runnerExecutableSha256',
    'runnerPid',
    'sourceDigest',
  ];
  for (const key of keys) {
    await t.test(key, async () => {
      const value = await comparisonFixture({
        changeReceipt(receipt) {
          receipt[key] = substitute(receipt[key], key);
        },
      });
      await assert.rejects(compareA28FinalConsumerReceipt(
        value.input,
        value.dependencies,
      ));
    });
  }
});

test('rejects challenge-request mutation after equality and before comparison', async () => {
  const value = await comparisonFixture();
  value.dependencies.assertChallengeRequest = (accepted) => {
    value.input.challengeRequest.hostStartTime = '999.000001';
    return accepted;
  };
  await assert.rejects(compareA28FinalConsumerReceipt(
    value.input,
    value.dependencies,
  ));
});

test('rejects a root-receipt pathname swap after opening its descriptor', async () => {
  const value = await comparisonFixture();
  value.dependencies.afterReceiptOpen = async ({ path }) => {
    await rename(path, `${path}.opened`);
    await writeFile(path, canonicalA28Line(value.receipt), { mode: 0o444 });
    await chmod(path, 0o444);
  };
  await assert.rejects(compareA28FinalConsumerReceipt(
    value.input,
    value.dependencies,
  ));
});

test('rejects comparison after the retained host and runner are cleaned up', async () => {
  const value = await comparisonFixture();
  value.dependencies.assertPublishedReceipt = (receipt) => {
    value.setPeersLive(false);
    return receipt;
  };
  await assert.rejects(compareA28FinalConsumerReceipt(
    value.input,
    value.dependencies,
  ));
});

test('refuses to replace a pre-existing comparison receipt', async () => {
  const value = await comparisonFixture();
  await writeFile(
    resolve(value.contextDirectory, 'comparison-receipt.json'),
    Buffer.from('{}\n'),
    { mode: 0o600 },
  );
  await assert.rejects(compareA28FinalConsumerReceipt(
    value.input,
    value.dependencies,
  ));
});

test('re-inventories both retained bundles before accepting the receipt', async (t) => {
  await t.test('production bundle', async () => {
    const value = await comparisonFixture();
    value.setProductionInventorySha256(digest('a'));
    await assert.rejects(compareA28FinalConsumerReceipt(
      value.input,
      value.dependencies,
    ));
  });
  await t.test('automation bundle', async () => {
    const value = await comparisonFixture();
    value.setAutomationInventorySha256(digest('b'));
    await assert.rejects(compareA28FinalConsumerReceipt(
      value.input,
      value.dependencies,
    ));
  });
});

test('runs prepare, four reveals, authorise, consume and compare in order', async () => {
  const value = await comparisonFixture();
  const phases = [];
  const voiceOver = await executeA28FinalConsumerCeremony({
    ceremony: {
      async prepare() {
        return {
          challenge: value.input.challenge,
          challengeRequest: value.input.challengeRequest,
          policyPin: value.input.policyPin,
        };
      },
      async reveal({ ordinal }) {
        return { ordinal };
      },
      async authorise() {
        return { authorised: true };
      },
      async consume() {
        return {
          attestationBytes: value.input.attestationBytes,
          enrolment: value.input.enrolment,
          publishedReceiptPath: value.input.publishedReceiptPath,
        };
      },
    },
    contextLease: value.input.contextLease,
    now: value.input.now,
  }, {
    ...value.dependencies,
    onPhase(phase) { phases.push(phase); },
  });
  assert.equal(voiceOver.gateContextCompared, true);
  assert.deepEqual(phases, [
    'prepare',
    'reveal-1',
    'reveal-2',
    'reveal-3',
    'reveal-4',
    'authorise',
    'consume',
    'compare',
  ]);
});
