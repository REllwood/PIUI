import { randomBytes } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import {
  appendFileSync,
  chmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CANARY_SCAN_LIMITS,
  CANARY_SCAN_RUNTIME_TEST_HOOK,
  CANARY_SCAN_TEST_HOOK,
  CanaryScanError,
  encodeCanaryScanFrame,
  runCanaryScannerFrame,
  scanSecretCanary,
} from '../../scripts/scan-secret-canary.mjs';

const repositoryRoot = resolve(import.meta.dirname, '../..');
const scannerPath = resolve(repositoryRoot, 'scripts/scan-secret-canary.mjs');
const scannerSource = readFileSync(scannerPath, 'utf8');
const helperSource = readFileSync(resolve(repositoryRoot, 'scripts/scan-secret-canary-helper.c'), 'utf8');
const disposables = new Set();

function fixture() {
  const workspace = realpathSync(mkdtempSync(join(tmpdir(), 'piui-a23-scan-workspace-')));
  chmodSync(workspace, 0o700);
  const root = join(workspace, 'scan-root');
  privateDirectory(root);
  disposables.add(workspace);
  return { workspace, root };
}

function privateDirectory(path) {
  mkdirSync(path, { mode: 0o700 });
  chmodSync(path, 0o700);
}

function privateFile(path, bytes) {
  writeFileSync(path, bytes, { mode: 0o600 });
  chmodSync(path, 0o600);
}

async function waitUntil(predicate, timeoutMs = 3_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 25));
  }
  assert.fail('bounded wait expired');
}

function uniqueCanary() {
  return Buffer.concat([Buffer.from('PIUI_A23_', 'ascii'), randomBytes(24)]);
}

function scanOptions(workspace, root, capture, canary, count = 1) {
  return {
    workspace,
    canary,
    roots: [root],
    authorised: [{ path: capture, count }],
  };
}

function assertRejected(error) {
  assert.ok(error instanceof CanaryScanError);
  assert.equal(error.code, 'canary-scan-rejected');
  assert.equal(error.message, 'Secret canary scan rejected');
  assert.equal(error.stack, 'CanaryScanError: Secret canary scan rejected');
  return true;
}

function containsBytes(haystack, needle) {
  return haystack.indexOf(needle) !== -1;
}

function currentProcessHelperWorkspaces() {
  const prefix = `piui-a23-scanner-helper-${process.pid}-`;
  return readdirSync(tmpdir()).filter((entry) => entry.startsWith(prefix));
}

test.afterEach(() => {
  for (const root of disposables) rmSync(root, { recursive: true, force: true });
  disposables.clear();
});

test('streams raw binary bytes across chunk boundaries and accepts only exact authorised content', async () => {
  const { workspace, root } = fixture();
  const canary = Buffer.concat([Buffer.from([0x00, 0xff, 0x80, 0x01]), randomBytes(28)]);
  const canaryWitness = Buffer.from(canary);
  const capture = join(root, 'rust-sidecar.capture');
  const binary = Buffer.concat([
    Buffer.alloc(65_521, 0xa5),
    canary.subarray(0, 11),
    canary.subarray(11),
    Buffer.from([0x00, 0xfe, 0x7f]),
    canary,
  ]);
  privateFile(capture, binary);
  privateFile(join(root, 'ordinary-app-data.bin'), Buffer.from([0xff, 0x00, 0x80]));

  try {
    const report = await scanSecretCanary(scanOptions(workspace, root, capture, canary, 2));
    assert.deepEqual(report, {
      schemaVersion: 1,
      status: 'pass',
      rootsScanned: 1,
      entriesScanned: 3,
      filesScanned: 2,
      fileDataBytesScanned: binary.length + 3,
      metadataBytesScanned: report.metadataBytesScanned,
      authorisedFiles: 1,
      authorisedOccurrences: 2,
      unauthorisedOccurrences: 0,
    });
    assert.ok(report.metadataBytesScanned > 0);
    assert.ok(report.metadataBytesScanned <= CANARY_SCAN_LIMITS.maxMetadataBytes);
    const serialised = Buffer.from(JSON.stringify(report));
    assert.equal(containsBytes(serialised, canaryWitness), false, 'safe report predicate failed');
    assert.equal(serialised.includes(Buffer.from(workspace)), false, 'path predicate failed');
    serialised.fill(0);
    assert.equal(canary.every((byte) => byte === 0), true, 'caller canary was not cleared');
  } finally {
    binary.fill(0);
    canaryWitness.fill(0);
  }
});

test('rejects WebView, event, log, crash and ordinary app-data occurrences', async (context) => {
  for (const surface of ['webview-state', 'webview-events', 'application-logs', 'crash-artefacts', 'ordinary-app-data']) {
    await context.test(surface, async () => {
      const { workspace, root } = fixture();
      const canary = uniqueCanary();
      const capture = join(root, 'authorised-private-channel.capture');
      privateFile(capture, canary);
      const surfaceRoot = join(root, surface);
      privateDirectory(surfaceRoot);
      const leaked = Buffer.concat([Buffer.from([0xff, 0x00]), canary]);
      privateFile(join(surfaceRoot, 'evidence.bin'), leaked);
      leaked.fill(0);

      await assert.rejects(
        scanSecretCanary(scanOptions(workspace, root, capture, canary)),
        assertRejected,
      );
      assert.equal(canary.every((byte) => byte === 0), true, 'rejected canary was not cleared');
    });
  }
});

test('rejects absent, under-counted, over-counted and unauthorised exact content', async (context) => {
  for (const [label, actual, expected] of [
    ['absent', 0, 1],
    ['under-counted', 1, 2],
    ['over-counted', 2, 1],
  ]) {
    await context.test(label, async () => {
      const { workspace, root } = fixture();
      const canary = uniqueCanary();
      const capture = join(root, 'capture.bin');
      const content = Buffer.concat(Array.from({ length: actual }, () => canary));
      privateFile(capture, content);
      content.fill(0);
      await assert.rejects(
        scanSecretCanary(scanOptions(workspace, root, capture, canary, expected)),
        assertRejected,
      );
    });
  }
});

test('requires canonical roots strictly below an exact private workspace', async (context) => {
  await context.test('workspace itself is not a root', async () => {
    const { workspace } = fixture();
    const canary = uniqueCanary();
    const capture = join(workspace, 'capture.bin');
    privateFile(capture, canary);
    await assert.rejects(
      scanSecretCanary(scanOptions(workspace, workspace, capture, canary)),
      assertRejected,
    );
  });

  await context.test('sibling escape is rejected', async () => {
    const { workspace } = fixture();
    const escaped = realpathSync(mkdtempSync(join(tmpdir(), 'piui-a23-scan-escape-')));
    chmodSync(escaped, 0o700);
    disposables.add(escaped);
    const canary = uniqueCanary();
    const capture = join(escaped, 'capture.bin');
    privateFile(capture, canary);
    await assert.rejects(
      scanSecretCanary(scanOptions(workspace, escaped, capture, canary)),
      assertRejected,
    );
  });

  await context.test('non-canonical root spelling is rejected', async () => {
    const { workspace, root } = fixture();
    const canary = uniqueCanary();
    const capture = join(root, 'capture.bin');
    privateFile(capture, canary);
    await assert.rejects(
      scanSecretCanary(scanOptions(workspace, `${root}/../scan-root`, capture, canary)),
      assertRejected,
    );
  });
});

test('exact-root sandbox fails closed on a transient parent ABA', async () => {
  const { workspace, root: unusedRoot } = fixture();
  rmSync(unusedRoot, { recursive: true });
  const container = join(workspace, 'container');
  const holder = join(container, 'holder');
  const movedHolder = join(container, 'holder-moved');
  const root = join(holder, 'scan-root');
  privateDirectory(container);
  privateDirectory(holder);
  privateDirectory(root);

  const outside = realpathSync(mkdtempSync(join(tmpdir(), 'piui-a23-aba-outside-')));
  chmodSync(outside, 0o700);
  disposables.add(outside);
  const outsideRoot = join(outside, 'scan-root');
  privateDirectory(outsideRoot);

  const canary = uniqueCanary();
  const capture = join(root, 'capture.bin');
  privateFile(capture, canary);
  privateFile(join(outsideRoot, 'capture.bin'), canary);
  const phases = [];

  await assert.rejects(
    scanSecretCanary({
      ...scanOptions(workspace, root, capture, canary),
      [CANARY_SCAN_TEST_HOOK]: (phase) => {
        phases.push(phase);
        if (phase === 'roots-held') {
          renameSync(holder, movedHolder);
          symlinkSync(outside, holder);
        }
      },
    }),
    assertRejected,
  );
  assert.deepEqual(phases, ['roots-held']);
});

test('pass-time authority rejects a persistent intermediate and root replacement', async () => {
  const { workspace, root: unusedRoot } = fixture();
  rmSync(unusedRoot, { recursive: true });
  const container = join(workspace, 'container');
  const holder = join(container, 'holder');
  const movedHolder = join(container, 'holder-moved');
  const root = join(holder, 'scan-root');
  privateDirectory(container);
  privateDirectory(holder);
  privateDirectory(root);

  const canary = uniqueCanary();
  const capture = join(root, 'capture.bin');
  privateFile(capture, canary);
  const phases = [];
  await assert.rejects(
    scanSecretCanary({
      ...scanOptions(workspace, root, capture, canary),
      [CANARY_SCAN_TEST_HOOK]: (phase) => {
        phases.push(phase);
        if (phase === 'roots-held') {
          renameSync(holder, movedHolder);
          privateDirectory(holder);
          const replacementRoot = join(holder, 'scan-root');
          privateDirectory(replacementRoot);
          privateFile(join(replacementRoot, 'capture.bin'), canary);
          privateFile(join(replacementRoot, 'unauthorised.bin'), canary);
        }
      },
    }),
    assertRejected,
  );
  assert.deepEqual(phases, ['roots-held']);
});

test('pass-time authority rejects a persistent ancestor-of-workspace replacement', async () => {
  const authority = realpathSync(mkdtempSync(join(tmpdir(), 'piui-a23-workspace-authority-')));
  chmodSync(authority, 0o700);
  disposables.add(authority);
  const container = join(authority, 'container');
  const movedContainer = join(authority, 'container-moved');
  const workspace = join(container, 'workspace');
  const root = join(workspace, 'scan-root');
  privateDirectory(container);
  privateDirectory(workspace);
  privateDirectory(root);

  const canary = uniqueCanary();
  const capture = join(root, 'capture.bin');
  privateFile(capture, canary);
  const phases = [];
  await assert.rejects(
    scanSecretCanary({
      ...scanOptions(workspace, root, capture, canary),
      [CANARY_SCAN_TEST_HOOK]: (phase) => {
        phases.push(phase);
        if (phase === 'roots-held') {
          renameSync(container, movedContainer);
          privateDirectory(container);
          const replacementWorkspace = join(container, 'workspace');
          const replacementRoot = join(replacementWorkspace, 'scan-root');
          privateDirectory(replacementWorkspace);
          privateDirectory(replacementRoot);
          privateFile(join(replacementRoot, 'capture.bin'), canary);
          privateFile(join(replacementRoot, 'unauthorised.bin'), canary);
        }
      },
    }),
    assertRejected,
  );
  assert.deepEqual(phases, ['roots-held']);
});

test('rejects custom xattrs and permits provenance without a canary on workspace, root and entries', async (context) => {
  for (const target of ['workspace', 'root', 'entry']) {
    await context.test(`${target} custom xattr`, async () => {
      const { workspace, root } = fixture();
      const canary = uniqueCanary();
      const capture = join(root, 'capture.bin');
      privateFile(capture, canary);
      const selected = target === 'workspace' ? workspace : target === 'root' ? root : capture;
      const custom = spawnSync('/usr/bin/xattr', ['-w', 'com.piui.a23.fixture', 'safe', selected], { encoding: 'utf8' });
      assert.equal(custom.status, 0, 'custom xattr fixture setup failed');
      await assert.rejects(scanSecretCanary(scanOptions(workspace, root, capture, canary)), assertRejected);
    });

    await context.test(`${target} safe provenance`, async () => {
      const { workspace, root } = fixture();
      const canary = uniqueCanary();
      const capture = join(root, 'capture.bin');
      privateFile(capture, canary);
      const selected = target === 'workspace' ? workspace : target === 'root' ? root : capture;
      const provenance = spawnSync('/usr/bin/xattr', ['-w', 'com.apple.provenance', 'safe', selected], { encoding: 'utf8' });
      assert.equal(provenance.status, 0, 'provenance xattr fixture setup failed');
      const report = await scanSecretCanary(scanOptions(workspace, root, capture, canary));
      assert.equal(report.status, 'pass');
      assert.equal(report.unauthorisedOccurrences, 0);
      assert.ok(report.metadataBytesScanned > 0);
      assert.ok(report.metadataBytesScanned <= CANARY_SCAN_LIMITS.maxMetadataBytes);
    });
  }
});

test('rejects provenance xattrs that contain the canary when safely constructible', async (context) => {
  for (const target of ['workspace', 'root', 'entry']) {
    await context.test(target, async (testContext) => {
      const { workspace, root } = fixture();
      const canary = Buffer.from('PIUI_A23_PROVENANCE_CANARY_01', 'ascii');
      const capture = join(root, 'capture.bin');
      privateFile(capture, canary);
      const selected = target === 'workspace' ? workspace : target === 'root' ? root : capture;
      const result = spawnSync('/usr/bin/xattr', ['-w', 'com.apple.provenance', 'PIUI_A23_PROVENANCE_CANARY_01', selected], { encoding: 'utf8' });
      assert.equal(result.status, 0, 'provenance xattr fixture setup failed');
      const readback = spawnSync('/usr/bin/xattr', ['-px', 'com.apple.provenance', selected], { encoding: 'utf8' });
      const observedHex = readback.stdout.replace(/[^0-9a-f]/gi, '').toLowerCase();
      if (readback.status !== 0 || observedHex !== canary.toString('hex')) {
        testContext.skip('macOS protects com.apple.provenance from caller-selected fixture values');
        return;
      }
      await assert.rejects(scanSecretCanary(scanOptions(workspace, root, capture, canary)), assertRejected);
    });
  }
});

test('enforces the scan-wide provenance metadata byte cap', async (context) => {
  const { workspace, root } = fixture();
  const canary = uniqueCanary();
  const capture = join(root, 'capture.bin');
  privateFile(capture, canary);
  const paths = [];
  for (let index = 0; index < 400; index += 1) {
    const path = join(root, `metadata-${String(index).padStart(3, '0')}.bin`);
    privateFile(path, Buffer.alloc(0));
    paths.push(path);
  }
  const provenance = spawnSync(
    '/usr/bin/xattr',
    ['-w', 'com.apple.provenance', 'safe', ...paths],
    { encoding: 'utf8' },
  );
  assert.equal(provenance.status, 0, 'provenance xattr fixture setup failed');
  const readback = spawnSync('/usr/bin/xattr', ['-p', 'com.apple.provenance', paths[0]], {
    encoding: null,
  });
  if (readback.status !== 0 || readback.stdout.length === 0) {
    context.skip('macOS did not retain the permitted provenance fixture');
    return;
  }
  readback.stdout.fill(0);
  readback.stderr.fill(0);
  await assert.rejects(
    scanSecretCanary(scanOptions(workspace, root, capture, canary)),
    assertRejected,
  );
});

test('rejects macOS ACL grants even when POSIX mode bits remain private', () => {
  const probe = spawnSync(process.execPath, [resolve(repositoryRoot, 'tests/packaged/helpers/acl-scanner-probe.mjs')], {
    encoding: null,
    env: { PATH: '/usr/bin:/bin' },
    maxBuffer: 8_192,
  });
  assert.equal(probe.status, 0);
  assert.equal(probe.stdout.length, 0);
  assert.equal(probe.stderr.length, 0);
});

test('scans each root basename as raw bytes', async () => {
  const { workspace, root: unusedRoot } = fixture();
  rmSync(unusedRoot, { recursive: true });
  const canary = Buffer.from('PIUI_A23_ROOT_BASENAME_CANARY', 'ascii');
  const workspaceBytes = Buffer.from(workspace);
  const rootBytes = Buffer.concat([workspaceBytes, Buffer.from('/'), canary]);
  const captureBytes = Buffer.concat([rootBytes, Buffer.from('/capture.bin')]);
  try {
    privateDirectory(rootBytes);
    privateFile(captureBytes, canary);
    await assert.rejects(
      scanSecretCanary(scanOptions(workspaceBytes, rootBytes, captureBytes, canary)),
      assertRejected,
    );
  } finally {
    workspaceBytes.fill(0);
    rootBytes.fill(0);
    captureBytes.fill(0);
    canary.fill(0);
  }
});

test('rejects unsafe permissions, links and special files without following them', async (context) => {
  await context.test('owner-private permissions', async () => {
    const { workspace, root } = fixture();
    const canary = uniqueCanary();
    const capture = join(root, 'capture.bin');
    privateFile(capture, canary);
    chmodSync(capture, 0o640);
    await assert.rejects(scanSecretCanary(scanOptions(workspace, root, capture, canary)), assertRejected);
  });

  await context.test('symlink', async () => {
    const { workspace, root } = fixture();
    const canary = uniqueCanary();
    const capture = join(root, 'capture.bin');
    privateFile(capture, canary);
    symlinkSync(capture, join(root, 'linked-capture'));
    await assert.rejects(scanSecretCanary(scanOptions(workspace, root, capture, canary)), assertRejected);
  });

  await context.test('hard link', async () => {
    const { workspace, root } = fixture();
    const canary = uniqueCanary();
    const capture = join(root, 'capture.bin');
    const linked = join(root, 'hard-linked.bin');
    privateFile(capture, canary);
    privateFile(linked, Buffer.from('safe'));
    linkSync(linked, join(root, 'hard-linked-alias.bin'));
    await assert.rejects(scanSecretCanary(scanOptions(workspace, root, capture, canary)), assertRejected);
  });

  await context.test('FIFO', async () => {
    const { workspace, root } = fixture();
    const canary = uniqueCanary();
    const capture = join(root, 'capture.bin');
    privateFile(capture, canary);
    const fifo = join(root, 'special-fifo');
    const made = spawnSync('/usr/bin/mkfifo', [fifo], { encoding: 'utf8' });
    assert.equal(made.status, 0, 'FIFO fixture setup failed');
    chmodSync(fifo, 0o600);
    await assert.rejects(scanSecretCanary(scanOptions(workspace, root, capture, canary)), assertRejected);
  });
});

test('enforces incremental entry, depth, file and aggregate limits', async (context) => {
  await context.test('large directory stops at maxEntries + 1', async () => {
    const { workspace, root } = fixture();
    const canary = uniqueCanary();
    const capture = join(root, 'capture.bin');
    privateFile(capture, canary);
    for (let index = 0; index < CANARY_SCAN_LIMITS.maxEntries + 64; index += 1) {
      privateFile(join(root, `entry-${String(index).padStart(3, '0')}`), Buffer.alloc(0));
    }
    await assert.rejects(scanSecretCanary(scanOptions(workspace, root, capture, canary)), assertRejected);
  });

  await context.test('declared relative path depth', async () => {
    const { workspace, root: unusedRoot } = fixture();
    rmSync(unusedRoot, { recursive: true });
    const canary = uniqueCanary();
    let root = workspace;
    for (let depth = 0; depth < CANARY_SCAN_LIMITS.maxDepth + 1; depth += 1) {
      root = join(root, 'r');
      privateDirectory(root);
    }
    const capture = join(root, 'capture.bin');
    privateFile(capture, canary);
    await assert.rejects(
      scanSecretCanary(scanOptions(workspace, root, capture, canary)),
      assertRejected,
    );
  });

  await context.test('traversal depth', async () => {
    const { workspace, root } = fixture();
    const canary = uniqueCanary();
    let current = root;
    for (let depth = 0; depth < CANARY_SCAN_LIMITS.maxDepth; depth += 1) {
      current = join(current, 'd');
      privateDirectory(current);
    }
    const capture = join(current, 'capture.bin');
    privateFile(capture, canary);
    await assert.rejects(scanSecretCanary(scanOptions(workspace, root, capture, canary)), assertRejected);
  });

  await context.test('file', async () => {
    const { workspace, root } = fixture();
    const canary = uniqueCanary();
    const capture = join(root, 'capture.bin');
    privateFile(capture, canary);
    privateFile(join(root, 'oversized.bin'), Buffer.alloc(CANARY_SCAN_LIMITS.maxFileBytes + 1));
    await assert.rejects(scanSecretCanary(scanOptions(workspace, root, capture, canary)), assertRejected);
  });

  await context.test('aggregate', async () => {
    const { workspace, root } = fixture();
    const canary = uniqueCanary();
    const capture = join(root, 'capture.bin');
    privateFile(capture, canary);
    const fileCount = CANARY_SCAN_LIMITS.maxAggregateFileDataBytes / CANARY_SCAN_LIMITS.maxFileBytes;
    for (let index = 0; index < fileCount; index += 1) {
      privateFile(join(root, `data-${String(index).padStart(2, '0')}.bin`), Buffer.alloc(CANARY_SCAN_LIMITS.maxFileBytes));
    }
    await assert.rejects(scanSecretCanary(scanOptions(workspace, root, capture, canary)), assertRejected);
  });
});

test('rejects file growth through the one-byte overflow probe at the file-opened hook', async () => {
  const { workspace, root } = fixture();
  rmSync(root, { recursive: true });
  const canary = uniqueCanary();
  const capture = join(workspace, 'capture-root.bin');
  privateFile(capture, canary);
  const phases = [];
  await assert.rejects(
    scanSecretCanary({
      ...scanOptions(workspace, capture, capture, canary),
      [CANARY_SCAN_TEST_HOOK]: (phase) => {
        phases.push(phase);
        if (phase === 'file-opened') {
          appendFileSync(capture, Buffer.alloc(CANARY_SCAN_LIMITS.maxFileBytes + 1));
        }
      },
    }),
    assertRejected,
  );
  assert.deepEqual(phases, ['roots-held', 'file-opened']);
});

test('fixed CLI receives only a bounded binary stdin frame and clears observable inputs', async () => {
  const { workspace, root } = fixture();
  const canary = uniqueCanary();
  const canaryWitness = Buffer.from(canary);
  const capture = join(root, 'capture.bin');
  privateFile(capture, canary);
  const frame = encodeCanaryScanFrame(scanOptions(workspace, root, capture, canary));
  const passed = spawnSync(process.execPath, [scannerPath], {
    input: frame,
    encoding: null,
    env: {},
    maxBuffer: 8 * 1024,
  });
  try {
    assert.equal(passed.status, 0);
    assert.equal(passed.stderr.length, 0);
    assert.equal(passed.stdout.toString('utf8').trim().split('\n').length, 1);
    assert.equal(JSON.parse(passed.stdout.toString('utf8')).status, 'pass');
    assert.equal(containsBytes(passed.stdout, canaryWitness), false, 'CLI output predicate failed');
    assert.equal(containsBytes(Buffer.from(JSON.stringify([scannerPath])), canaryWitness), false, 'argv predicate failed');
    assert.equal(scannerSource.includes('canary-hex'), false);
    assert.equal(scannerSource.includes("toString('hex')"), false);
  } finally {
    frame.fill(0);
    canary.fill(0);
    canaryWitness.fill(0);
    passed.stdout.fill(0);
    passed.stderr.fill(0);
  }

  const rejectedInput = Buffer.alloc(32, 0xa5);
  const rejected = spawnSync(process.execPath, [scannerPath], {
    input: rejectedInput,
    encoding: 'utf8',
    env: {},
  });
  rejectedInput.fill(0);
  assert.equal(rejected.status, 1);
  assert.equal(rejected.stderr, '');
  assert.deepEqual(JSON.parse(rejected.stdout), {
    schemaVersion: 1,
    status: 'rejected',
    errorCode: 'canary-scan-rejected',
  });

  const directCanary = uniqueCanary();
  const directFrame = encodeCanaryScanFrame(scanOptions(workspace, root, capture, directCanary));
  await assert.rejects(runCanaryScannerFrame(directFrame), assertRejected);
  assert.equal(directFrame.every((byte) => byte === 0), true, 'stdin frame was not cleared');
  directCanary.fill(0);
});

test('compiler failure and timeout release the local helper workspace lease', async (context) => {
  for (const mode of ['compiler-failure', 'compiler-timeout']) {
    await context.test(mode, async () => {
      const { workspace, root } = fixture();
      const canary = uniqueCanary();
      const capture = join(root, 'capture.bin');
      privateFile(capture, canary);
      await assert.rejects(
        scanSecretCanary({
          ...scanOptions(workspace, root, capture, canary),
          [CANARY_SCAN_RUNTIME_TEST_HOOK]: { mode },
        }),
        assertRejected,
      );
      assert.deepEqual(currentProcessHelperWorkspaces(), []);
      assert.equal(canary.every((byte) => byte === 0), true);
    });
  }
});

test('helper and asynchronous hook hard timeouts kill the child and release all leases', async (context) => {
  await context.test('helper timeout', async () => {
    const { workspace, root } = fixture();
    const canary = uniqueCanary();
    const capture = join(root, 'capture.bin');
    privateFile(capture, canary);
    await assert.rejects(
      scanSecretCanary({
        ...scanOptions(workspace, root, capture, canary),
        [CANARY_SCAN_RUNTIME_TEST_HOOK]: { mode: 'helper-timeout' },
      }),
      assertRejected,
    );
    assert.equal(canary.every((byte) => byte === 0), true);
    assert.deepEqual(currentProcessHelperWorkspaces(), []);
  });

  await context.test('hook timeout', async () => {
    const { workspace, root } = fixture();
    const canary = uniqueCanary();
    const capture = join(root, 'capture.bin');
    privateFile(capture, canary);
    await assert.rejects(
      scanSecretCanary({
        ...scanOptions(workspace, root, capture, canary),
        [CANARY_SCAN_TEST_HOOK]: () => new Promise(() => undefined),
        [CANARY_SCAN_RUNTIME_TEST_HOOK]: { mode: 'hook-timeout' },
      }),
      assertRejected,
    );
    assert.equal(canary.every((byte) => byte === 0), true);
    assert.deepEqual(currentProcessHelperWorkspaces(), []);
  });
});

test('same-byte private helper replacement is rejected before execution and releases its lease', async () => {
  const { workspace, root } = fixture();
  const canary = uniqueCanary();
  const capture = join(root, 'capture.bin');
  privateFile(capture, canary);
  await assert.rejects(
    scanSecretCanary({
      ...scanOptions(workspace, root, capture, canary),
      [CANARY_SCAN_RUNTIME_TEST_HOOK]: { mode: 'helper-replacement' },
    }),
    assertRejected,
  );
  assert.equal(canary.every((byte) => byte === 0), true);
  assert.deepEqual(currentProcessHelperWorkspaces(), []);
});

test('native watchdog terminates after parent death and the next run reclaims its stale lease', async () => {
  const probe = spawn(process.execPath, [resolve(repositoryRoot, 'tests/packaged/helpers/scanner-parent-death-probe.mjs')], {
    env: { PATH: '/usr/bin:/bin', TMPDIR: tmpdir() },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const probeClose = new Promise((resolveClose) => probe.once('close', resolveClose));
  let output = Buffer.alloc(0);
  try {
    await new Promise((resolveReady, rejectReady) => {
      const timeout = setTimeout(() => rejectReady(new Error('probe readiness timeout')), 5_000);
      probe.stdout.on('data', (chunk) => {
        const previous = output;
        output = Buffer.concat([output, chunk]);
        previous.fill(0);
        chunk.fill(0);
        if (output.includes(Buffer.from('READY\n'))) {
          clearTimeout(timeout);
          resolveReady();
        }
      });
      probe.once('error', rejectReady);
    });

    const temporaryRoot = realpathSync(tmpdir());
    const leasePrefix = `piui-a23-scanner-helper-${probe.pid}-`;
    const fixturePrefix = `piui-a23-parent-death-fixture-${probe.pid}-`;
    const leaseNames = readdirSync(temporaryRoot).filter((name) => name.startsWith(leasePrefix));
    assert.equal(leaseNames.length, 1);
    const lease = join(temporaryRoot, leaseNames[0]);
    const executable = join(lease, 'control', 'scan-secret-canary-helper');
    const escapedExecutable = executable.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const pgrep = spawnSync('/usr/bin/pgrep', ['-f', `^${escapedExecutable}$`], { encoding: 'utf8' });
    assert.equal(pgrep.status, 0);
    const helperPids = pgrep.stdout.trim().split(/\s+/).filter(Boolean).map(Number);
    assert.ok(helperPids.length >= 1);

    assert.equal(probe.kill('SIGKILL'), true);
    await probeClose;
    await waitUntil(() => helperPids.every((pid) => {
      try {
        process.kill(pid, 0);
        return false;
      } catch (error) {
        return error?.code === 'ESRCH';
      }
    }));

    const { workspace, root } = fixture();
    const canary = uniqueCanary();
    const capture = join(root, 'capture.bin');
    privateFile(capture, canary);
    assert.equal((await scanSecretCanary(scanOptions(workspace, root, capture, canary))).status, 'pass');
    assert.equal(readdirSync(temporaryRoot).some((name) => name.startsWith(leasePrefix)), false);
    for (const name of readdirSync(temporaryRoot).filter((entry) => entry.startsWith(fixturePrefix))) {
      rmSync(join(temporaryRoot, name), { recursive: true, force: true });
    }
  } finally {
    if (probe.exitCode === null && probe.signalCode === null) probe.kill('SIGKILL');
    await probeClose;
    output.fill(0);
  }
});

test('native helper statically uses descriptor-relative bounded traversal and explicit clearing', () => {
  assert.match(helperSource, /openat\(/);
  assert.match(helperSource, /fdopendir\(/);
  assert.match(helperSource, /fstatat\([^;]+AT_SYMLINK_NOFOLLOW/);
  assert.match(helperSource, /readdir\(/);
  assert.match(helperSource, /allowed \+ 1/);
  assert.match(helperSource, /MAX_AGGREGATE_FILE_DATA_BYTES - aggregate_used - total/);
  assert.match(helperSource, /validate_pass_authority\(/);
  assert.match(helperSource, /fstatfs\(/);
  assert.match(helperSource, /flistxattr\(/);
  assert.match(helperSource, /acl_get_fd_np\(/);
  assert.match(helperSource, /secure_zero\(chunk, sizeof\(chunk\)\)/);
  assert.match(helperSource, /secure_zero\(state, sizeof\(\*state\)\)/);
  assert.equal(scannerSource.includes('readFile('), false);
  assert.equal(scannerSource.includes('readdir('), false);
  assert.equal(scannerSource.includes('homedir'), false);
  assert.equal(dirname(scannerPath), resolve(repositoryRoot, 'scripts'));
});
