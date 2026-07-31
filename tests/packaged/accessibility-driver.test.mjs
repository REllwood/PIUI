import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  A28AccessibilityBlockedError,
  assertA28PinnedLeaseObservation,
  assertA28AccessibilityEvidence,
  classifyA28AuthoritativeCommandResult,
  classifyA28AccessibilityHelperResult,
  parseA28AccessibilityEvidence,
  parseA28DomEvidence,
  validateA28ActivationEnvironment,
} from '../../scripts/run-packaged-accessibility-probe.mjs';
import {
  canonicalArchitectureJson,
} from '../../scripts/architecture-gate-schema.mjs';

const root = resolve(import.meta.dirname, '../..');
const sha = (character) => character.repeat(64);
const line = (value) => Buffer.from(`${canonicalArchitectureJson(value)}\n`, 'utf8');

function domEvidence() {
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

function aggregateEvidence() {
  const dom = domEvidence();
  return {
    schemaVersion: 1,
    status: 'pass',
    identity: {
      sourceDigest: sha('a'),
      productionFingerprint: sha('b'),
      automationFingerprint: sha('c'),
      controlledDeltaSha256: sha('d'),
      sameFrozenSource: true,
    },
    driver: {
      productionHostileActivationListeners: 0,
      dormantTwinListeners: 0,
      activatedTwinIpv4LoopbackListeners: 1,
      activatedTwinOtherListeners: 0,
      cleanupListeners: 0,
      ipv4LoopbackOnly: true,
      randomHighPort: true,
      webdriverSessions: 1,
      stableSelectionCount: dom.stableSelectionCount,
    },
    automation: Object.fromEntries(Object.entries(dom).filter(([key]) =>
      !['schemaVersion', 'stableSelectionCount', 'webdriverSessions'].includes(key))),
    accessibilityTree: {
      trusted: true,
      exactPid: true,
      bounded: true,
      nodesVisited: 91,
      listRoles: 1,
      observedTranscriptRows: 13,
      roleErrors: 0,
      nameErrors: 0,
      orderErrors: 0,
      focusErrors: 0,
      focusedRows: 1,
      focusedRowOrdinal: 51,
    },
    voiceOver: {
      evidenceValidated: true,
      checksumsValidated: true,
      humanWitnessed: true,
      modesChecked: 4,
      blockingDefects: 0,
    },
    limitations: {
      automationConformanceEquivalence: 'not-claimed',
      voiceOverAutomationEquivalence: 'not-claimed',
      wcagConformance: 'not-claimed',
    },
    cleanup: {
      bundlesRevalidated: true,
      webdriverSessionDeleted: true,
      listenerRemoved: true,
      runnerIsolateRemoved: true,
      ownedProcessesAfterCleanup: 0,
    },
  };
}

test('accepts only an exact atomic A.28 activation', () => {
  assert.deepEqual(validateA28ActivationEnvironment({
    PIUI_ARCHITECTURE_TEST_MODE: 'a28-accessibility',
    PIUI_ARCHITECTURE_TEST_NONCE: sha('a'),
    PIUI_ARCHITECTURE_TEST_PORT: '49152',
  }), {
    mode: 'a28-accessibility',
    nonce: sha('a'),
    port: 49_152,
  });
  assert.deepEqual(validateA28ActivationEnvironment({
    PIUI_ARCHITECTURE_TEST_MODE: 'a28-accessibility',
    PIUI_ARCHITECTURE_TEST_NONCE: sha('f'),
    PIUI_ARCHITECTURE_TEST_PORT: '65535',
  }).port, 65_535);
  for (const rejected of [
    {},
    {
      PIUI_ARCHITECTURE_TEST_MODE: 'a28-accessibility',
      PIUI_ARCHITECTURE_TEST_NONCE: sha('a'),
    },
    {
      PIUI_ARCHITECTURE_TEST_MODE: 'a26-markdown',
      PIUI_ARCHITECTURE_TEST_NONCE: sha('a'),
      PIUI_ARCHITECTURE_TEST_PORT: '49152',
    },
    {
      PIUI_ARCHITECTURE_TEST_MODE: 'a28-accessibility',
      PIUI_ARCHITECTURE_TEST_NONCE: sha('A'),
      PIUI_ARCHITECTURE_TEST_PORT: '49152',
    },
    {
      PIUI_ARCHITECTURE_TEST_MODE: 'a28-accessibility',
      PIUI_ARCHITECTURE_TEST_NONCE: sha('a'),
      PIUI_ARCHITECTURE_TEST_PORT: '49151',
    },
    {
      PIUI_ARCHITECTURE_TEST_MODE: 'a28-accessibility',
      PIUI_ARCHITECTURE_TEST_NONCE: sha('a'),
      PIUI_ARCHITECTURE_TEST_PORT: '65536',
    },
    {
      PIUI_ARCHITECTURE_TEST_MODE: 'a28-accessibility',
      PIUI_ARCHITECTURE_TEST_NONCE: sha('a'),
      PIUI_ARCHITECTURE_TEST_PORT: '049152',
    },
  ]) {
    assert.throws(() => validateA28ActivationEnvironment(rejected));
  }
});

test('strictly validates bounded WDIO DOM evidence', () => {
  const evidence = domEvidence();
  assert.deepEqual(parseA28DomEvidence(line(evidence)), evidence);
  for (const changed of [
    { ...evidence, loadingIndicatorObserved: false },
    { ...evidence, virtualOrderedRowsObserved: 99 },
    { ...evidence, focusRetentionFailures: 1 },
    { ...evidence, arrowTransitions: 0 },
    { ...evidence, privatePath: '/private/example' },
  ]) {
    assert.throws(() => parseA28DomEvidence(line(changed)));
  }
  assert.throws(() => parseA28DomEvidence(
    Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`, 'utf8'),
  ));
});

test('keeps the aggregate canonical, path-free and limitation-bounded', () => {
  const evidence = aggregateEvidence();
  assert.deepEqual(assertA28AccessibilityEvidence(evidence), evidence);
  assert.deepEqual(parseA28AccessibilityEvidence(line(evidence)), evidence);
  assert.equal(line(evidence).includes(Buffer.from('/Users/')), false);
  for (const changed of [
    { ...evidence, privatePath: '/private/example' },
    {
      ...evidence,
      limitations: {
        ...evidence.limitations,
        wcagConformance: 'pass',
      },
    },
    {
      ...evidence,
      cleanup: {
        ...evidence.cleanup,
        ownedProcessesAfterCleanup: 1,
      },
    },
    {
      ...evidence,
      voiceOver: {
        ...evidence.voiceOver,
        humanWitnessed: false,
      },
    },
  ]) {
    assert.throws(() => parseA28AccessibilityEvidence(line(changed)));
  }
});

test('classifies missing macOS Accessibility permission as blocked, never pass', () => {
  assert.throws(() => classifyA28AccessibilityHelperResult({
    forcedCleanup: false,
    signal: null,
    status: 77,
    stderr: Buffer.from('A.28 accessibility permission is required.\n'),
    stdout: Buffer.alloc(0),
  }, 1234), (error) => {
    assert.equal(error instanceof A28AccessibilityBlockedError, true);
    assert.equal(error.code, 'PIUI_A28_ACCESSIBILITY_BLOCKED');
    return true;
  });
  assert.throws(() => classifyA28AccessibilityHelperResult({
    forcedCleanup: false,
    signal: null,
    status: 77,
    stderr: Buffer.from('unexpected\n'),
    stdout: Buffer.alloc(0),
  }, 1234));
});

test('preserves only the exact package child blocked result as A.28 blocked', () => {
  const blocked = {
    forcedCleanup: false,
    signal: null,
    status: 2,
    stderr: Buffer.from(
      'A.21 package gate failed: A.28 accessibility proof blocked\n',
      'utf8',
    ),
    stdout: Buffer.alloc(0),
  };
  assert.throws(() => classifyA28AuthoritativeCommandResult(blocked), (error) => {
    assert.equal(error instanceof A28AccessibilityBlockedError, true);
    assert.equal(error.code, 'PIUI_A28_ACCESSIBILITY_BLOCKED');
    return true;
  });
  for (const changed of [
    { ...blocked, status: 1 },
    { ...blocked, forcedCleanup: true },
    { ...blocked, stderr: Buffer.from('unexpected\n', 'utf8') },
    { ...blocked, stdout: line(aggregateEvidence()) },
  ]) {
    assert.throws(
      () => classifyA28AuthoritativeCommandResult(changed),
      (error) => !(error instanceof A28AccessibilityBlockedError),
    );
  }
  const accepted = aggregateEvidence();
  assert.deepEqual(classifyA28AuthoritativeCommandResult({
    forcedCleanup: false,
    signal: null,
    status: 0,
    stderr: Buffer.alloc(0),
    stdout: line(accepted),
  }), accepted);
});

test('pins the exact A.28 lease inode and canonical bytes', () => {
  const observation = {
    bytes: Buffer.from('{"schemaVersion":1}\n', 'utf8'),
    identity: { dev: 7, ino: 11 },
  };
  const pin = {
    canonicalLine: observation.bytes.toString('utf8'),
    identity: { ...observation.identity },
  };
  assert.equal(assertA28PinnedLeaseObservation(pin, observation), true);
  for (const changed of [
    { ...observation, identity: { dev: 7, ino: 12 } },
    { ...observation, bytes: Buffer.from('{"schemaVersion":2}\n', 'utf8') },
  ]) {
    assert.throws(() => assertA28PinnedLeaseObservation(pin, changed));
  }
});

test('uses only the exact embedded service and ordinary WebDriver surface', async () => {
  const [configuration, spec, runner, manual] = await Promise.all([
    readFile(resolve(root, 'wdio.conf.ts'), 'utf8'),
    readFile(resolve(root, 'tests/packaged/accessibility-spike.spec.ts'), 'utf8'),
    readFile(resolve(root, 'scripts/run-packaged-accessibility-probe.mjs'), 'utf8'),
    readFile(resolve(root, 'tests/manual/architecture-gate-voiceover.md'), 'utf8'),
  ]);
  assert.match(configuration, /A28_TAURI_SERVICE_VERSION = '1\.2\.0'/);
  assert.match(configuration, /'@wdio\/tauri-service'/);
  assert.match(configuration, /driverProvider: 'embedded'/);
  assert.match(configuration, /browserName: 'tauri'/);
  assert.match(configuration, /embeddedPort: a28\.port/);
  assert.match(spec, /browser\.execute/);
  assert.match(spec, /browser\.keys/);
  assert.match(spec, /loadingIndicatorObserved/);
  assert.match(spec, /virtualOrderedRowsObserved/);
  assert.match(runner, /EXPECTED_TAURI_SERVICE_VERSION = '1\.2\.0'/);
  assert.match(runner, /readPackageVersion\('@wdio\/globals', EXPECTED_WDIO_VERSION\)/);
  assert.match(runner, /readPackageVersion\('@wdio\/spec-reporter', EXPECTED_WDIO_VERSION\)/);
  assert.match(configuration, /PIUI_A28_HUMAN_READY: 'human-ready\.json'/);
  assert.match(configuration, /PIUI_A28_HUMAN_VISIBLE: 'human-visible\.json'/);
  assert.match(configuration, /timeout: 32 \* 60_000/);
  assert.match(spec, /waitForHumanReadyOrRelease/);
  assert.match(spec, /A28_HUMAN_WITNESS_READY_EVENT/);
  assert.match(spec, /Waiting for human VoiceOver evidence/);
  assert.match(spec, /control\.isEnabled\(\)/);
  assert.match(runner, /PIUI_A28_HUMAN_EVIDENCE_ROOT/);
  assert.match(runner, /createHumanWitnessLease/);
  assert.match(runner, /assertExactRetainedHumanWitnessHost/);
  assert.match(runner, /parseA28VoiceOverCompletion/);
  assert.match(runner, /voiceOverSha256: sha256Bytes\(voiceOverBytes\)/);
  assert.match(runner, /timeoutMs: 35 \* 60_000/);
  assert.match(manual, /pnpm spike:packaged:accessibility/);
  assert.match(manual, /Create `completion\.json` last/);
  assert.match(manual, /Do not create `checksums\.json` yourself/);
  assert.match(manual, /times out after 30 minutes/);
  assert.equal(runner.indexOf('voiceOver = await waitForHumanWitness({')
    < runner.indexOf('await publishAxRelease(axReleasePath, nonce)'), true);
  assert.equal(runner.indexOf('const identity = Object.freeze({')
    < runner.indexOf('const observed = await executeWdioObservation('), true);
  for (const source of [configuration, spec]) {
    assert.doesNotMatch(source, /@wdio\/tauri-plugin/u);
    assert.doesNotMatch(source, /withGlobalTauri/u);
    assert.doesNotMatch(source, /(?:^|['"])wdio:/mu);
    assert.doesNotMatch(source, /browser\.tauri/u);
    assert.doesNotMatch(source, /__TAURI_INTERNALS__/u);
    assert.doesNotMatch(source, /tauri:options/u);
  }
  assert.doesNotMatch(spec, /PIUI_ARCHITECTURE_TEST_NONCE.*(?:textContent|innerHTML)/u);
});
