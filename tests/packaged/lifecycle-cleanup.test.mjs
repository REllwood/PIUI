import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import {
  chmod,
  lstat,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { test } from 'node:test';
import {
  A27_EXPECTED_EVIDENCE,
  A27_NATIVE_EVIDENCE_KEYS,
  assertLifecycleNetworkBoundaryFromListing,
  assertLifecycleTopology,
  assertOwnershipLockContended,
  assertOwnershipLockReleased,
  closeLifecycleOwnershipDescriptor,
  mergeLifecycleEvidence,
  openLifecycleOwnershipDescriptor,
  parseLifecycleEvidence,
  parseNativeLifecycleEvidence,
} from '../../scripts/assert-process-cleanup.mjs';
import { terminateFailedRuntime } from '../../scripts/run-packaged-lifecycle-probe.mjs';

function line(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`);
}

function nativeEvidence() {
  return Object.fromEntries(
    A27_NATIVE_EVIDENCE_KEYS.map((key) => [key, A27_EXPECTED_EVIDENCE[key]]),
  );
}

function externalEvidence() {
  return Object.fromEntries(
    Object.entries(A27_EXPECTED_EVIDENCE)
      .filter(([key]) => !A27_NATIVE_EVIDENCE_KEYS.includes(key)),
  );
}

function waitForChildExit(child) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolveExit, rejectExit) => {
    child.once('exit', resolveExit);
    child.once('error', rejectExit);
  });
}

test('A.27 accepts only the exact path-free one-line evidence schema', () => {
  assert.deepEqual(parseLifecycleEvidence(line(A27_EXPECTED_EVIDENCE)), A27_EXPECTED_EVIDENCE);
  assert.deepEqual(parseNativeLifecycleEvidence(line(nativeEvidence())), nativeEvidence());
  assert.deepEqual(
    mergeLifecycleEvidence(nativeEvidence(), externalEvidence()),
    A27_EXPECTED_EVIDENCE,
  );
  assert.equal(JSON.stringify(A27_EXPECTED_EVIDENCE).includes('/'), false);

  const missing = { ...A27_EXPECTED_EVIDENCE };
  delete missing.gracefulQuit;
  const malformed = [
    Buffer.alloc(0),
    Buffer.from([0xff, 0x0a]),
    Buffer.from(`${JSON.stringify(A27_EXPECTED_EVIDENCE)}\r\n`),
    Buffer.from(`${JSON.stringify(A27_EXPECTED_EVIDENCE)}\n{}\n`),
    line(missing),
    line({ ...A27_EXPECTED_EVIDENCE, status: 'partial' }),
    line({ ...A27_EXPECTED_EVIDENCE, hostPid: 42 }),
    line({ ...A27_EXPECTED_EVIDENCE, lockPath: '/private/fixture' }),
    line({ ...A27_EXPECTED_EVIDENCE, rawApprovalId: 'approval-private' }),
    Buffer.alloc(65_537, 0x20),
  ];
  for (const candidate of malformed) {
    assert.throws(
      () => parseLifecycleEvidence(candidate),
      { message: 'A.27 packaged lifecycle probe rejected' },
    );
  }
});

test('A.27 topology rejects duplicate hosts, duplicate sidecars and unrelated descendants', () => {
  const hostPath = '/Applications/PIUI.app/Contents/MacOS/piui';
  const nodePath = '/Applications/PIUI.app/Contents/MacOS/piui-node';
  const host = {
    pid: 101,
    ppid: 1,
    pgid: 101,
    state: 'S',
    start: 'Mon Jul 28 10:00:00 2026',
    command: hostPath,
    executable: hostPath,
  };
  const sidecar = {
    pid: 102,
    ppid: 101,
    pgid: 102,
    state: 'S',
    start: 'Mon Jul 28 10:00:01 2026',
    command: `${nodePath} index.js`,
    executable: nodePath,
  };
  assert.deepEqual(
    assertLifecycleTopology({
      live: [host],
      hostPath,
      nodePath,
      hostPid: host.pid,
      expectedSidecars: 0,
    }),
    { hosts: 1, sidecars: 0 },
  );
  assert.deepEqual(
    assertLifecycleTopology({
      live: [host, sidecar],
      hostPath,
      nodePath,
      hostPid: host.pid,
      expectedSidecars: 1,
    }),
    { hosts: 1, sidecars: 1 },
  );

  for (const live of [
    [host, { ...host, pid: 103 }],
    [host, sidecar, { ...sidecar, pid: 104, start: 'Mon Jul 28 10:00:02 2026' }],
    [host, { ...sidecar, pid: 105, executable: '/bin/sleep', command: '/bin/sleep 30' }],
  ]) {
    assert.throws(
      () => assertLifecycleTopology({
        live,
        hostPath,
        nodePath,
        hostPid: host.pid,
        expectedSidecars: 1,
      }),
      { message: 'A.27 packaged lifecycle probe rejected' },
    );
  }
});

test('A.27 permits only the declared host loopback driver and no sidecar socket', () => {
  const hostPid = 101;
  const driverPort = 53_421;
  const listener = [
    `p${hostPid}`,
    'f12',
    'PTCP',
    `n127.0.0.1:${driverPort}`,
    'TST=LISTEN',
    'f13',
    'PTCP',
    `n127.0.0.1:${driverPort}->127.0.0.1:61234`,
    'TST=ESTABLISHED',
    '',
  ].join('\n');
  assert.equal(
    assertLifecycleNetworkBoundaryFromListing({
      pid: hostPid,
      hostPid,
      driverPort,
      listing: listener,
    }),
    0,
  );
  assert.equal(
    assertLifecycleNetworkBoundaryFromListing({
      pid: 102,
      hostPid,
      driverPort,
      listing: '',
    }),
    0,
  );
  for (const [pid, listing] of [
    [hostPid, listener.replace(String(driverPort), String(driverPort + 1))],
    [hostPid, listener.replace('127.0.0.1', '*')],
    [hostPid, listener.replace('PTCP', 'PUDP')],
    [102, 'p102\nf9\nPTCP\nn127.0.0.1:62000\nTST=LISTEN\n'],
  ]) {
    assert.throws(
      () => assertLifecycleNetworkBoundaryFromListing({
        pid,
        hostPid,
        driverPort,
        listing,
      }),
      { message: 'A.27 packaged lifecycle probe rejected' },
    );
  }
});

test('A.27 descriptor-3 BSD lock is contended while owned and released after owner exit', async () => {
  const requestedRoot = await mkdtemp(resolve(tmpdir(), 'piui-a27-lock-'));
  await chmod(requestedRoot, 0o700);
  const root = await realpath(requestedRoot);
  const lockPath = resolve(root, 'application.lock');
  const descriptor = openLifecycleOwnershipDescriptor(lockPath);
  let holder;
  try {
    holder = spawn(
      '/usr/bin/lockf',
      [
        '-s',
        '-t',
        '0',
        '/dev/fd/3',
        process.execPath,
        '--eval',
        "process.stdout.write('A27_LOCK_HELD\\n'); process.stdin.resume();",
      ],
      {
        env: { PATH: '/usr/bin:/bin' },
        stdio: ['pipe', 'pipe', 'ignore', descriptor.fd],
      },
    );
    const [ready] = await once(holder.stdout, 'data', {
      signal: AbortSignal.timeout(2_000),
    });
    assert.equal(ready.toString('utf8'), 'A27_LOCK_HELD\n');
    closeLifecycleOwnershipDescriptor(descriptor);

    const deadline = Date.now() + 2_000;
    let contended = false;
    while (Date.now() < deadline && !contended) {
      try {
        contended = assertOwnershipLockContended(lockPath);
      } catch {
        await new Promise((resolvePause) => setTimeout(resolvePause, 20));
      }
    }
    assert.equal(contended, true);

    holder.stdin.end();
    await waitForChildExit(holder);
    holder = undefined;
    assert.equal(assertOwnershipLockReleased(lockPath), true);
  } finally {
    if (!descriptor.closed) closeLifecycleOwnershipDescriptor(descriptor);
    if (holder) {
      holder.stdin.end();
      await waitForChildExit(holder);
    }
    await rm(root, { recursive: true, force: true });
  }
});

test('A.27 removes a failed runtime after ProcessLedger confirms forced cleanup completed', async () => {
  const requestedRoot = await mkdtemp(resolve(tmpdir(), 'piui-a27-forced-cleanup-'));
  await chmod(requestedRoot, 0o700);
  const root = await realpath(requestedRoot);
  const stdoutPath = resolve(root, 'stdout.log');
  const stderrPath = resolve(root, 'stderr.log');
  await Promise.all([
    writeFile(stdoutPath, '', { flag: 'wx', mode: 0o600 }),
    writeFile(stderrPath, '', { flag: 'wx', mode: 0o600 }),
  ]);
  const runtime = {
    childPid: 41_001,
    isolate: root,
    ledger: {
      groups: new Set([41_001]),
      async sample() {
        return Object.freeze([]);
      },
      async terminate() {
        return Object.freeze({ forced: true });
      },
    },
    removed: false,
    stderrPath,
    stdoutPath,
  };
  try {
    await terminateFailedRuntime(runtime);
    assert.equal(runtime.removed, true);
    await assert.rejects(lstat(root), { code: 'ENOENT' });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
