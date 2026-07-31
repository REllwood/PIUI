import { afterEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { chmod, link, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  SIDECAR_MANIFEST,
  inspectBundle,
  inspectMachOBytes,
  inventoryBundle,
  parseStrictManifest,
  revalidateBundle,
  safeRelative,
  sha256,
} from './bundle-inspection.mjs';
import {
  ProcessLedger,
  acquireOwnedLock,
  buildSignalPlan,
  identityKey,
  observeProcesses,
  releaseOwnedLock,
  runOwnedCommand,
} from '../../scripts/a21-gate-support.mjs';

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const roots = [];
afterEach(async () => {
  while (roots.length) await rm(roots.pop(), { recursive: true, force: true });
});

function thinMachO(cpu = 0x0100000c) {
  const bytes = Buffer.alloc(32);
  bytes.writeUInt32LE(0xfeedfacf, 0);
  bytes.writeUInt32LE(cpu, 4);
  bytes.writeUInt32LE(0, 8);
  bytes.writeUInt32LE(2, 12);
  return bytes;
}

function cmsMachO(withCmsPayload = true) {
  const wrapperLength = withCmsPayload ? 9 : 8;
  const blob = Buffer.alloc(44 + wrapperLength);
  blob.writeUInt32BE(0xfade0cc0, 0);
  blob.writeUInt32BE(blob.length, 4);
  blob.writeUInt32BE(2, 8);
  blob.writeUInt32BE(0, 12);
  blob.writeUInt32BE(28, 16);
  blob.writeUInt32BE(0x10000, 20);
  blob.writeUInt32BE(44, 24);
  blob.writeUInt32BE(0xfade0c02, 28);
  blob.writeUInt32BE(16, 32);
  blob.writeUInt32BE(0x2, 40);
  blob.writeUInt32BE(0xfade0b01, 44);
  blob.writeUInt32BE(wrapperLength, 48);
  const bytes = Buffer.alloc(48 + blob.length);
  thinMachO().copy(bytes);
  bytes.writeUInt32LE(1, 16);
  bytes.writeUInt32LE(16, 20);
  bytes.writeUInt32LE(0x1d, 32);
  bytes.writeUInt32LE(16, 36);
  bytes.writeUInt32LE(48, 40);
  bytes.writeUInt32LE(blob.length, 44);
  blob.copy(bytes, 48);
  return bytes;
}

async function basicFixture() {
  const root = await mkdtemp(resolve(tmpdir(), 'piui-a21-inspection-'));
  roots.push(root);
  await mkdir(resolve(root, 'Contents/MacOS'), { recursive: true, mode: 0o755 });
  await writeFile(resolve(root, 'Contents/MacOS/piui'), thinMachO(), { mode: 0o755 });
  await writeFile(resolve(root, 'Contents/value.json'), '{}\n', { mode: 0o644 });
  assert.equal(spawnSync('/usr/bin/xattr', ['-cr', root]).status, 0);
  return root;
}

async function closedFixture({ sidecarPath = 'dist/index.js', sidecarBytes = Buffer.from('export {};\n'), hostBytes = thinMachO() } = {}) {
  const root = await mkdtemp(resolve(tmpdir(), 'piui-a21-closed-'));
  roots.push(root);
  const sidecarRoot = resolve(root, 'Contents/Resources/resources/sidecar');
  await mkdir(resolve(root, 'Contents/MacOS'), { recursive: true, mode: 0o755 });
  await mkdir(resolve(sidecarRoot, dirname(sidecarPath)), { recursive: true, mode: 0o755 });
  await writeFile(resolve(root, 'Contents/Info.plist'), '<plist/>\n', { mode: 0o644 });
  await writeFile(resolve(root, 'Contents/MacOS/piui'), hostBytes, { mode: 0o755 });
  const nodeBytes = thinMachO();
  await writeFile(resolve(root, 'Contents/MacOS/piui-node'), nodeBytes, { mode: 0o755 });
  await writeFile(resolve(sidecarRoot, sidecarPath), sidecarBytes, { mode: 0o644 });
  const manifest = { node: '22.23.1', piSdk: '0.82.0', closure: 'isolated-v1', files: [{ path: sidecarPath, bytes: sidecarBytes.length, sha256: sha256(sidecarBytes) }] };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  await writeFile(resolve(root, SIDECAR_MANIFEST), manifestBytes, { mode: 0o644 });
  const anchors = { manifestBytes, manifestSha256: sha256(manifestBytes), manifest, nodeSha256: sha256(nodeBytes), nodeBytes: nodeBytes.length };
  assert.equal(spawnSync('/usr/bin/xattr', ['-cr', root]).status, 0);
  return { root, anchors, sidecarRoot };
}

async function inspectFixture(fixture, extra = {}) {
  return inspectBundle({ appPath: fixture.root, sourceRoot, anchors: fixture.anchors, ...extra });
}

test('inventories a closed regular bundle deterministically', async () => {
  const root = await basicFixture();
  const first = await inventoryBundle(root);
  const second = await inventoryBundle(root);
  assert.equal(first.fingerprint, second.fingerprint);
  assert.equal(safeRelative(first.root, resolve(first.root, 'Contents/value.json')), 'Contents/value.json');
});

test('rejects root/child symlinks, hard links, writable modes and xattrs', async () => {
  let root = await basicFixture();
  const aliasRoot = `${root}-alias`;
  roots.push(aliasRoot);
  await symlink(root, aliasRoot);
  await assert.rejects(inventoryBundle(aliasRoot), /root must be a real directory/);
  await symlink('value.json', resolve(root, 'Contents/alias.json'));
  await assert.rejects(inventoryBundle(root), /Symlink forbidden/);

  await rm(root, { recursive: true, force: true }); roots.splice(roots.indexOf(root), 1);
  root = await basicFixture();
  await link(resolve(root, 'Contents/value.json'), resolve(root, 'Contents/alias.json'));
  await assert.rejects(inventoryBundle(root), /Hard-linked/);

  await rm(root, { recursive: true, force: true }); roots.splice(roots.indexOf(root), 1);
  root = await basicFixture();
  await chmod(resolve(root, 'Contents/value.json'), 0o664);
  await assert.rejects(inventoryBundle(root), /group\/world writable/);

  await chmod(resolve(root, 'Contents/value.json'), 0o644);
  const xattr = spawnSync('/usr/bin/xattr', ['-w', 'au.com.piui.test', 'forbidden', root]);
  assert.equal(xattr.status, 0);
  await assert.rejects(inventoryBundle(root), /Extended attributes/);
});

test('strict manifest rejects duplicate, reserved, unsorted and non-canonical paths', () => {
  const base = { node: '22.23.1', piSdk: '0.82.0', closure: 'isolated-v1' };
  const entry = { path: 'dist/a.js', bytes: 1, sha256: '0'.repeat(64) };
  assert.throws(() => parseStrictManifest(Buffer.from(JSON.stringify({ ...base, files: [entry, entry] }))), /duplicate|sorted/);
  assert.throws(() => parseStrictManifest(Buffer.from(JSON.stringify({ ...base, files: [{ ...entry, path: '../a' }] }))), /non-canonical/);
  assert.throws(() => parseStrictManifest(Buffer.from(JSON.stringify({ ...base, files: [{ ...entry, path: 'manifest.json' }] }))), /reserved/);
  assert.throws(() => parseStrictManifest(Buffer.from(JSON.stringify({ ...base, files: [{ ...entry, path: 'z' }, { ...entry, path: 'a' }] }))), /sorted/);
});

test('requires exact anchored canonical sidecar and whole-bundle layout', async () => {
  let fixture = await closedFixture();
  let legacyRunnerCalled = false;
  const accepted = await inspectFixture(fixture, {
    nodeVersionRunner: () => {
      legacyRunnerCalled = true;
      throw new Error('writable packaged Node must not execute during inspection');
    },
  });
  assert.equal(legacyRunnerCalled, false);
  assert.equal(accepted.sidecarFiles, 1);
  assert.equal(accepted.nodeSha256, fixture.anchors.nodeSha256);
  assert.match(accepted.sidecarSha256, /^[0-9a-f]{64}$/);

  await writeFile(resolve(fixture.sidecarRoot, 'extra.txt'), 'extra');
  await assert.rejects(inspectFixture(fixture), /missing or extra|explicit layout/);
  await rm(fixture.root, { recursive: true, force: true }); roots.splice(roots.indexOf(fixture.root), 1);

  fixture = await closedFixture();
  await rm(resolve(fixture.sidecarRoot, 'dist/index.js'));
  await assert.rejects(inspectFixture(fixture), /missing or extra/);

  await rm(fixture.root, { recursive: true, force: true }); roots.splice(roots.indexOf(fixture.root), 1);
  fixture = await closedFixture();
  const altered = Buffer.from((await readFile(resolve(fixture.root, SIDECAR_MANIFEST), 'utf8')).replace('0.82.0', '0.82.1'));
  await writeFile(resolve(fixture.root, SIDECAR_MANIFEST), altered);
  await assert.rejects(inspectFixture(fixture), /differs from independently captured/);

  await rm(fixture.root, { recursive: true, force: true }); roots.splice(roots.indexOf(fixture.root), 1);
  fixture = await closedFixture();
  await rename(resolve(fixture.root, SIDECAR_MANIFEST), resolve(fixture.sidecarRoot, 'decoy.json'));
  await assert.rejects(inspectFixture(fixture), /manifest missing/);
});

test('detects every Mach-O regardless of mode and enforces signature policy', async () => {
  assert.equal(inspectMachOBytes(thinMachO()).architecture, 'arm64');
  assert.throws(() => inspectMachOBytes(thinMachO(0x01000007)), /Non-arm64/);
  for (const magic of ['cefaedfe', 'feedface', 'feedfacf']) {
    assert.throws(
      () => inspectMachOBytes(Buffer.concat([Buffer.from(magic, 'hex'), Buffer.alloc(28)])),
      /Unsupported 32-bit or byte-swapped Mach-O/,
    );
  }
  assert.deepEqual(inspectMachOBytes(cmsMachO()).signature, 'cms');
  assert.deepEqual(inspectMachOBytes(cmsMachO(false)).signature, 'adhoc');

  let fixture = await closedFixture({ sidecarPath: 'native/addon.node', sidecarBytes: thinMachO() });
  await chmod(resolve(fixture.sidecarRoot, 'native/addon.node'), 0o444);
  const accepted = await inspectFixture(fixture);
  assert.equal(accepted.machoFiles, 3);

  await rm(fixture.root, { recursive: true, force: true }); roots.splice(roots.indexOf(fixture.root), 1);
  fixture = await closedFixture({ sidecarPath: 'native/addon.node', sidecarBytes: thinMachO(0x01000007) });
  await assert.rejects(inspectFixture(fixture), /Non-arm64/);

  await rm(fixture.root, { recursive: true, force: true }); roots.splice(roots.indexOf(fixture.root), 1);
  fixture = await closedFixture({ hostBytes: cmsMachO() });
  await assert.rejects(inspectFixture(fixture), /Local host has identity-bearing/);
});

test('secret defence and post-inspection mutation are fail closed', async () => {
  let fixture = await closedFixture({ sidecarPath: '.netrc', sidecarBytes: Buffer.from('machine example') });
  await assert.rejects(inspectFixture(fixture), /Secret-bearing filename/);
  await rm(fixture.root, { recursive: true, force: true }); roots.splice(roots.indexOf(fixture.root), 1);

  fixture = await closedFixture({ sidecarBytes: Buffer.from('openai_api_key=secret-value') });
  await assert.rejects(inspectFixture(fixture), /Credential-shaped/);
  await rm(fixture.root, { recursive: true, force: true }); roots.splice(roots.indexOf(fixture.root), 1);

  fixture = await closedFixture();
  const accepted = await inspectFixture(fixture);
  await writeFile(resolve(fixture.root, 'Contents/Info.plist'), '<changed/>');
  await assert.rejects(revalidateBundle(accepted), /mutated/);
});

test('process signal planning handles leader-first exit, separate groups and PID reuse', () => {
  const leader = { pid: 100, ppid: 1, pgid: 100, start: 'Tue 28 Jul 00:00:00 2026', command: '/bundle/piui' };
  const node = { pid: 101, ppid: 100, pgid: 101, start: 'Tue 28 Jul 00:00:01 2026', command: '/bundle/piui-node' };
  const ledger = new Map([[identityKey(leader), leader], [identityKey(node), node]]);
  const leaderFirst = buildSignalPlan({ ledger, rows: [node], ownedGroups: new Set([100, 101]) });
  assert.deepEqual(leaderFirst.groups, [101]);
  const neutralSurvivor = { pid: 102, ppid: 1, pgid: 101, start: 'Tue 28 Jul 00:00:02 2026', command: '/bin/sleep 60' };
  const groupOnly = buildSignalPlan({ ledger, rows: [neutralSurvivor], ownedGroups: new Set([100, 101]) });
  assert.deepEqual(groupOnly.groups, []);
  assert.deepEqual(groupOnly.ambiguousGroups, [101]);
  assert.deepEqual(groupOnly.pids, []);

  const reused = { ...node, ppid: 1, command: '/usr/bin/unrelated' };
  assert.notEqual(identityKey(reused), identityKey(node));
  const reusePlan = buildSignalPlan({ ledger, rows: [reused], ownedGroups: new Set([100, 101]) });
  assert.deepEqual(reusePlan.groups, []);
  assert.deepEqual(reusePlan.ambiguousGroups, [101]);
  assert.deepEqual(reusePlan.pids, []);
  const reparented = { ...node, ppid: 1 };
  assert.deepEqual(buildSignalPlan({ ledger, rows: [reparented], ownedGroups: new Set([101]) }).pids, [101]);
});

test('process ledger binds a newly observed independently grouped sidecar before cleanup', async () => {
  const host = {
    pid: 4100,
    ppid: 1,
    pgid: 4100,
    state: 'S',
    start: 'Tue 28 Jul 00:00:00 2026',
    command: '/sealed/PIUI.app/Contents/MacOS/PIUI',
  };
  const sidecar = {
    pid: 4101,
    ppid: 4100,
    pgid: 4101,
    state: 'S',
    start: 'Tue 28 Jul 00:00:01 2026',
    command: '/sealed/PIUI.app/Contents/Resources/sidecar/node index.js',
  };
  const unrelated = {
    ...sidecar,
    pid: 4102,
    ppid: 1,
    pgid: 4102,
    start: 'Tue 28 Jul 00:00:02 2026',
  };
  let rows = [host];
  const executables = new Map([
    [host.pid, '/sealed/PIUI.app/Contents/MacOS/PIUI'],
    [sidecar.pid, '/sealed/PIUI.app/Contents/Resources/sidecar/node'],
    [unrelated.pid, '/sealed/PIUI.app/Contents/Resources/sidecar/node'],
  ]);
  const ledger = new ProcessLedger({
    bundleRoot: '/sealed/PIUI.app',
    isolateRoot: '/private/tmp/piui-isolate',
    hostPath: executables.get(host.pid),
    nodePath: executables.get(sidecar.pid),
    observer: () => rows,
    executableResolver: (pid) => executables.get(pid),
    networkChecker: () => undefined,
  });
  await ledger.initialise(host.pid);
  rows = [host, sidecar, unrelated];
  const live = await ledger.sample();
  assert.deepEqual(live.map((entry) => entry.pid), [host.pid, sidecar.pid]);
  assert.deepEqual([...ledger.groups].sort((a, b) => a - b), [host.pgid, sidecar.pgid]);
  rows = [host, { ...sidecar, ppid: 1 }, unrelated];
  const reparentedLive = await ledger.sample();
  assert.deepEqual(reparentedLive.map((entry) => entry.pid), [host.pid, sidecar.pid]);
  const plan = buildSignalPlan({
    ledger: ledger.entries,
    rows,
    ownedGroups: ledger.groups,
  });
  assert.deepEqual(plan.pids, [host.pid, sidecar.pid]);
  assert.deepEqual(plan.groups, [host.pgid, sidecar.pgid]);
  assert.ok(!plan.pids.includes(unrelated.pid));
  assert.ok(!plan.groups.includes(unrelated.pgid));
});

test('process ledger refuses an ambiguous historical group without signalling it', async () => {
  const unrelated = spawn('/bin/sleep', ['30'], {
    detached: true,
    stdio: 'ignore',
  });
  await new Promise((resolveSpawn, rejectSpawn) => {
    unrelated.once('spawn', resolveSpawn);
    unrelated.once('error', rejectSpawn);
  });
  const row = {
    pid: unrelated.pid,
    ppid: process.pid,
    pgid: unrelated.pid,
    state: 'S',
    start: 'Tue 28 Jul 00:00:00 2026',
    command: '/bin/sleep 30',
  };
  const ledger = new ProcessLedger({
    bundleRoot: '/sealed/PIUI.app',
    isolateRoot: '/private/tmp/piui-isolate',
    hostPath: '/sealed/PIUI.app/Contents/MacOS/PIUI',
    nodePath: '/sealed/PIUI.app/Contents/Resources/sidecar/node',
    observer: () => [row],
    executableResolver: () => '/bin/sleep',
    networkChecker: () => undefined,
  });
  ledger.groups.add(unrelated.pid);
  try {
    await assert.rejects(
      ledger.terminate(),
      (error) => error?.code === 'PIUI_PROCESS_GROUP_IDENTITY_AMBIGUOUS'
        && error.ambiguousGroups.length === 1
        && error.ambiguousGroups[0] === unrelated.pid,
    );
    assert.doesNotThrow(() => process.kill(unrelated.pid, 0));
  } finally {
    try { process.kill(-unrelated.pid, 'SIGKILL'); } catch (error) {
      if (error?.code !== 'ESRCH') throw error;
    }
    await waitForExit(unrelated);
  }
});

function waitForLine(child, expected) {
  return new Promise((resolveLine, rejectLine) => {
    let text = '';
    const timeout = setTimeout(() => rejectLine(new Error(`Timed out waiting for ${expected}`)), 5_000);
    child.stdout.on('data', (chunk) => {
      text += chunk.toString('utf8');
      if (text.split(/\r?\n/).includes(expected)) {
        clearTimeout(timeout);
        resolveLine();
      }
    });
    child.once('error', rejectLine);
    child.once('exit', (status) => {
      if (!text.split(/\r?\n/).includes(expected)) rejectLine(new Error(`Lock helper exited ${status}`));
    });
  });
}

function waitForExit(child) {
  return new Promise((resolveExit, rejectExit) => {
    child.once('error', rejectExit);
    child.once('exit', (status, signal) => resolveExit({ status, signal }));
  });
}

test('kernel lock serialises live contenders and recovers a dead owner without pathname retirement', async () => {
  const root = await mkdtemp(resolve(tmpdir(), 'piui-a21-lock-'));
  roots.push(root);
  const lockPath = resolve(root, 'gate.lock');
  const modulePath = resolve(sourceRoot, 'scripts/a21-gate-support.mjs');
  const holderSource = `import { acquireOwnedLock } from ${JSON.stringify(modulePath)}; const lock = await acquireOwnedLock(process.env.LOCK); process.stdout.write('ready\\n'); setInterval(() => {}, 1000);`;
  const holder = spawn(process.execPath, ['--input-type=module', '--eval', holderSource], {
    env: { ...process.env, LOCK: lockPath },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await waitForLine(holder, 'ready');
  await assert.rejects(acquireOwnedLock(lockPath), /already held/);
  holder.kill('SIGKILL');
  const dead = await waitForExit(holder);
  assert.equal(dead.signal, 'SIGKILL');
  const recovered = await acquireOwnedLock(lockPath);
  await releaseOwnedLock(recovered);

  const startPath = resolve(root, 'start');
  const eventsPath = resolve(root, 'events');
  await writeFile(eventsPath, '');
  const contenderSource = `import { appendFile, access } from 'node:fs/promises'; import { setTimeout as sleep } from 'node:timers/promises'; import { acquireOwnedLock, releaseOwnedLock } from ${JSON.stringify(modulePath)}; while (true) { try { await access(process.env.START); break; } catch { await sleep(5); } } const lock = await acquireOwnedLock(process.env.LOCK, { timeoutMs: 5000 }); await appendFile(process.env.EVENTS, process.env.ID + '-in\\n'); await sleep(150); await appendFile(process.env.EVENTS, process.env.ID + '-out\\n'); await releaseOwnedLock(lock);`;
  const contenders = ['a', 'b'].map((id) => spawn(process.execPath, ['--input-type=module', '--eval', contenderSource], {
    env: { ...process.env, LOCK: lockPath, START: startPath, EVENTS: eventsPath, ID: id },
    stdio: ['ignore', 'pipe', 'pipe'],
  }));
  await writeFile(startPath, 'start');
  const exits = await Promise.all(contenders.map(waitForExit));
  assert.deepEqual(exits, [{ status: 0, signal: null }, { status: 0, signal: null }]);
  const events = (await readFile(eventsPath, 'utf8')).trim().split('\n');
  assert.ok(
    JSON.stringify(events) === JSON.stringify(['a-in', 'a-out', 'b-in', 'b-out'])
    || JSON.stringify(events) === JSON.stringify(['b-in', 'b-out', 'a-in', 'a-out']),
  );
  const item = await readFile(lockPath);
  assert.equal(item.length, 0, 'persistent lock inode is never retired or replaced');
});

test('owned build commands enforce deadlines and remove inherited-group survivors', async () => {
  await assert.rejects(
    runOwnedCommand({ command: '/bin/sleep', args: ['30'], timeoutMs: 100, label: 'deadline probe' }),
    /deadline/,
  );
  await assert.rejects(
    runOwnedCommand({
      command: '/bin/sh',
      args: ['-c', `(trap '' TERM; sleep 30) </dev/null >/dev/null 2>&1 & exit 0`],
      timeoutMs: 5_000,
      label: 'survivor probe',
    }),
    /survivor/,
  );
});

test('owned build output remains bounded while a TERM-ignoring child is removed', async () => {
  const floodSource = String.raw`
    process.on('SIGTERM', () => undefined);
    let pipeClosed = false;
    process.stdout.on('error', () => { pipeClosed = true; });
    const block = 'x'.repeat(64 * 1024);
    function flood() {
      if (!pipeClosed) {
        for (let index = 0; index < 32; index += 1) process.stdout.write(block);
      }
      setImmediate(flood);
    }
    flood();
  `;
  await assert.rejects(
    runOwnedCommand({
      command: process.execPath,
      args: ['--eval', floodSource],
      timeoutMs: 15_000,
      maxOutputBytes: 1_024,
      label: 'bounded output flood probe',
    }),
    /output bound/,
  );
});

test('owned build command reports a sampler failure after a child exit wins the race', async () => {
  let observations = 0;
  const observer = async () => {
    observations += 1;
    if (observations <= 3) {
      if (observations === 1) await sleep(200);
      throw new Error('injected observer failure');
    }
    return [];
  };
  await assert.rejects(
    runOwnedCommand({
      command: '/usr/bin/true',
      timeoutMs: 5_000,
      label: 'sampler failure probe',
      observer,
    }),
    /descendant identity observation failed/,
  );
  assert.ok(observations > 3, 'the final observation and cleanup ran after the retried sampler failed');
});

test('owned build command kills its isolated group when process observation remains unavailable', async () => {
  const root = await mkdtemp(resolve(tmpdir(), 'piui-a21-observer-failure-'));
  roots.push(root);
  const marker = resolve(root, 'pid');
  await assert.rejects(
    runOwnedCommand({
      command: '/bin/sh',
      args: ['-c', `echo $$ > ${JSON.stringify(marker)}; exec /bin/sleep 30`],
      timeoutMs: 5_000,
      label: 'persistent sampler failure probe',
      observer: async () => { throw new Error('persistent observer failure'); },
    }),
    /descendant identity observation failed/,
  );
  const pid = Number.parseInt(await readFile(marker, 'utf8'), 10);
  assert.ok(Number.isSafeInteger(pid));
  assert.throws(() => process.kill(pid, 0), (error) => error?.code === 'ESRCH');
});

async function compileSetsidSurvivor() {
  const root = await mkdtemp(resolve(tmpdir(), 'piui-a21-setsid-'));
  roots.push(root);
  const executable = resolve(root, 'setsid-survivor');
  const source = resolve(sourceRoot, 'tests/packaged/helpers/setsid-survivor.c');
  const compiled = spawnSync('/usr/bin/clang', ['-std=c11', '-Wall', '-Wextra', '-Werror', source, '-o', executable], {
    encoding: 'utf8',
    env: { PATH: '/usr/bin:/bin' },
  });
  assert.equal(compiled.status, 0, compiled.stderr);
  return { root, executable };
}

async function waitForMarker(path) {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    try { return await readFile(path, 'utf8'); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
    await sleep(20);
  }
  throw new Error('Timed out waiting for setsid helper marker');
}

async function assertPidGone(pid) {
  const deadline = Date.now() + 3_000;
  while (Date.now() < deadline) {
    try { process.kill(pid, 0); } catch (error) { if (error?.code === 'ESRCH') return; throw error; }
    await sleep(20);
  }
  assert.fail(`Recorded helper PID ${pid} survived cleanup`);
}

function parseSetsidEvidence(text) {
  const values = text.trim().split(' ').map(Number);
  assert.equal(values.length, 4);
  assert.ok(values.every(Number.isSafeInteger));
  const [pid, parentPid, sid, pgid] = values;
  assert.equal(sid, pid, 'setsid helper created a new session');
  assert.equal(pgid, pid, 'setsid helper created a new process group');
  assert.notEqual(parentPid, 1, 'helper recorded its direct parent before reparenting');
  return { pid, parentPid };
}

test('persistent observer failure kills every previously recorded setsid group', async () => {
  const { root, executable } = await compileSetsidSurvivor();
  const marker = resolve(root, 'observer-failure-setsid-marker');
  let markerSamples = 0;
  const observer = async () => {
    if (markerSamples >= 2) throw new Error('persistent observer failure after setsid record');
    const rows = observeProcesses();
    if (existsSync(marker)) markerSamples += 1;
    return rows;
  };
  await assert.rejects(
    runOwnedCommand({
      command: executable,
      args: [marker, '30000'],
      timeoutMs: 35_000,
      label: 'setsid observer failure probe',
      observer,
    }),
    /descendant identity observation failed/,
  );
  const evidence = parseSetsidEvidence(await waitForMarker(marker));
  await assertPidGone(evidence.pid);
  await assertPidGone(evidence.parentPid);
});

test('owned build ledger finds and kills a reparented setsid descendant after direct-parent success', async () => {
  const { root, executable } = await compileSetsidSurvivor();
  const marker = resolve(root, 'success-marker');
  await assert.rejects(
    runOwnedCommand({ command: executable, args: [marker, '750'], timeoutMs: 5_000, label: 'setsid survivor probe' }),
    /recorded descendant survivor/,
  );
  const evidence = parseSetsidEvidence(await waitForMarker(marker));
  await assertPidGone(evidence.pid);
  await assertPidGone(evidence.parentPid);
});

test('parent abort cleans recorded root and setsid descendant identities', async () => {
  const { root, executable } = await compileSetsidSurvivor();
  const marker = resolve(root, 'abort-marker');
  const controller = new AbortController();
  const running = runOwnedCommand({
    command: executable,
    args: [marker, '30000'],
    timeoutMs: 35_000,
    signal: controller.signal,
    label: 'setsid cutoff probe',
  });
  const evidence = parseSetsidEvidence(await waitForMarker(marker));
  await sleep(150);
  controller.abort();
  await assert.rejects(running, /cut off by its parent/);
  await assertPidGone(evidence.pid);
  await assertPidGone(evidence.parentPid);
});
