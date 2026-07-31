import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import {
  A27_REOPEN_HELPER_SOURCE,
  assertPreCleanupLifecycleEvidence,
  createA27LifecycleNetworkPolicy,
  finaliseLifecycleEvidence,
  validateA27ActivationEnvironment,
} from '../../scripts/run-packaged-lifecycle-probe.mjs';
import {
  A27_EXPECTED_EVIDENCE,
} from '../../scripts/assert-process-cleanup.mjs';

function preCleanupEvidence() {
  return Object.freeze(Object.fromEntries(
    Object.entries(A27_EXPECTED_EVIDENCE)
      .filter(([key]) => key !== 'generatedOutputsRemoved'),
  ));
}

test('A.27 keeps package cleanup evidence false-by-construction until finalisation', () => {
  const preCleanup = preCleanupEvidence();
  assert.deepEqual(
    assertPreCleanupLifecycleEvidence(preCleanup),
    preCleanup,
  );
  assert.equal(
    Object.hasOwn(
      assertPreCleanupLifecycleEvidence(preCleanup),
      'generatedOutputsRemoved',
    ),
    false,
  );
  assert.deepEqual(
    finaliseLifecycleEvidence(preCleanup),
    A27_EXPECTED_EVIDENCE,
  );

  const missing = { ...preCleanup };
  delete missing.runnerIsolateRemoved;
  for (const malformed of [
    missing,
    { ...preCleanup, generatedOutputsRemoved: true },
    { ...preCleanup, runnerIsolateRemoved: false },
    { ...preCleanup, sourceDigest: 'private-path-bearing-field' },
  ]) {
    assert.throws(
      () => assertPreCleanupLifecycleEvidence(malformed),
      { message: 'A.27 packaged lifecycle probe rejected' },
    );
  }
});

test('A.27 activation accepts only the exact mode, lower-case nonce and high port', () => {
  const valid = {
    PIUI_ARCHITECTURE_TEST_MODE: 'a27-lifecycle',
    PIUI_ARCHITECTURE_TEST_NONCE: 'a'.repeat(64),
    PIUI_ARCHITECTURE_TEST_PORT: '53421',
  };
  assert.deepEqual(validateA27ActivationEnvironment(valid), {
    mode: 'a27-lifecycle',
    nonce: 'a'.repeat(64),
    port: 53_421,
  });
  for (const malformed of [
    { ...valid, PIUI_ARCHITECTURE_TEST_MODE: 'a26-markdown' },
    { ...valid, PIUI_ARCHITECTURE_TEST_NONCE: 'A'.repeat(64) },
    { ...valid, PIUI_ARCHITECTURE_TEST_NONCE: 'a'.repeat(63) },
    { ...valid, PIUI_ARCHITECTURE_TEST_PORT: '49151' },
    { ...valid, PIUI_ARCHITECTURE_TEST_PORT: '053421' },
    { ...valid, TAURI_WEBDRIVER_PORT: '53421' },
  ]) {
    assert.throws(
      () => validateA27ActivationEnvironment(malformed),
      { message: 'A.27 packaged lifecycle probe rejected' },
    );
  }
});

test('A.27 network policy allows startup silence then permanently enforces one loopback driver', () => {
  const hostPid = 401;
  const sidecarPid = 402;
  const driverPort = 53_421;
  const listings = new Map([
    [hostPid, ''],
    [sidecarPid, ''],
  ]);
  const policy = createA27LifecycleNetworkPolicy({
    hostPid,
    driverPort,
    listingForPid: (pid) => listings.get(pid),
  });
  assert.equal(policy(hostPid), 0);
  assert.equal(policy(sidecarPid), 0);
  assert.equal(policy.listenerObserved, false);

  listings.set(hostPid, [
    `p${hostPid}`,
    'f11',
    'PTCP',
    `n127.0.0.1:${driverPort}`,
    'TST=LISTEN',
    'f12',
    'PTCP',
    `n127.0.0.1:${driverPort}->127.0.0.1:61234`,
    'TST=ESTABLISHED',
    '',
  ].join('\n'));
  assert.equal(policy(hostPid), 0);
  assert.equal(policy.listenerObserved, true);

  listings.set(hostPid, '');
  assert.throws(
    () => policy(hostPid),
    { message: 'A.27 packaged lifecycle probe rejected' },
  );
  listings.set(sidecarPid, [
    `p${sidecarPid}`,
    'f9',
    'PTCP',
    'n127.0.0.1:62000',
    'TST=LISTEN',
    '',
  ].join('\n'));
  assert.throws(
    () => policy(sidecarPid),
    { message: 'A.27 packaged lifecycle probe rejected' },
  );
});

test('A.27 exact-PID reopen helper compiles with no broad application launch fallback', () => {
  assert.match(A27_REOPEN_HELPER_SOURCE, /GetProcessForPID/);
  assert.match(A27_REOPEN_HELPER_SOURCE, /kAEReopenApplication/);
  assert.match(A27_REOPEN_HELPER_SOURCE, /kAENoReply \| kAENeverInteract/);
  assert.doesNotMatch(A27_REOPEN_HELPER_SOURCE, /\bNSWorkspace\b/);
  assert.doesNotMatch(A27_REOPEN_HELPER_SOURCE, /\bopen\s*\(/);

  const result = spawnSync(
    '/usr/bin/clang',
    [
      '-std=c17',
      '-Wall',
      '-Wextra',
      '-Werror',
      '-Wno-deprecated-declarations',
      '-fsyntax-only',
      '-x',
      'c',
      '-',
    ],
    {
      input: Buffer.from(A27_REOPEN_HELPER_SOURCE, 'utf8'),
      encoding: 'utf8',
      env: {
        PATH: '/usr/bin:/bin',
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
      },
      timeout: 30_000,
    },
  );
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
});

test('A.27 runner uses WebDriver only for lifecycle UI and external process observation for identity', async () => {
  const source = await readFile(
    new URL('../../scripts/run-packaged-lifecycle-probe.mjs', import.meta.url),
    'utf8',
  );
  assert.match(source, /class A27RuntimeProcessLedger extends ProcessLedger/);
  assert.match(source, /new A27RuntimeProcessLedger/);
  assert.match(source, /new LifecycleObservation/);
  assert.match(source, /waitForOwnedProcessesToExit/);
  assert.match(source, /assertOwnershipLockContended/);
  assert.match(source, /assertOwnershipLockReleased/);
  assert.match(source, /sendExactPidReopen/);
  assert.ok(source.includes("`/session/${this.sessionId}/element`"));
  assert.match(source, /generatedOutputsRemoved: true/);
  assert.doesNotMatch(source, /sidecar_status/);
  assert.equal(source.includes('/usr/bin/open'), false);

  const executeStart = source.indexOf('export async function executeAuthoritativeLifecycleProbe');
  const finaliseStart = source.indexOf('export function finaliseLifecycleEvidence');
  const executeSource = source.slice(executeStart);
  assert.ok(executeStart > 0);
  assert.ok(finaliseStart > 0);
  assert.doesNotMatch(executeSource, /generatedOutputsRemoved:\s*true/);
});
