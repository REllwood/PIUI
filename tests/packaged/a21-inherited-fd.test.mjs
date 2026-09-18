import assert from 'node:assert/strict';
import { closeSync, constants, openSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';
import { runOwnedCommand } from '../../scripts/a21-gate-support.mjs';

test('owned commands preserve an explicitly inherited held descriptor at its exact number', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'piui-inherited-fd.'));
  t.after(async () => rm(root, { force: true, recursive: true }));
  const path = resolve(root, 'capability.txt');
  await writeFile(path, 'held-capability\n', { flag: 'wx', mode: 0o400 });
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const result = await runOwnedCommand({
      args: [
        '-e',
        "const fs=require('node:fs'); process.stdout.write(fs.readFileSync(Number(process.env.HELD_FD)));",
      ],
      command: process.execPath,
      cwd: root,
      env: {
        HELD_FD: String(fd),
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
        PATH: '/usr/bin:/bin',
      },
      inheritedFds: [fd],
      label: 'Inherited descriptor probe',
      timeoutMs: 10_000,
    });
    assert.equal(result.status, 0);
    assert.equal(result.signal, null);
    assert.equal(result.stderr.length, 0);
    assert.equal(result.stdout.toString('utf8'), 'held-capability\n');
  } finally {
    closeSync(fd);
  }
});

test('owned commands reject duplicate and out-of-range inherited descriptors', async () => {
  await assert.rejects(
    runOwnedCommand({
      command: '/usr/bin/true',
      inheritedFds: [10, 10],
      timeoutMs: 1_000,
    }),
    /inherited descriptors are invalid/u,
  );
  await assert.rejects(
    runOwnedCommand({
      command: '/usr/bin/true',
      inheritedFds: [256],
      timeoutMs: 1_000,
    }),
    /inherited descriptors are invalid/u,
  );
});

test('owned commands expose retained stderr chunks to a bounded synchronous observer', async () => {
  const observed = [];
  const result = await runOwnedCommand({
    args: [
      '-e',
      "process.stderr.write('[working] A.28 first\\n'); setTimeout(()=>process.stderr.write('[working] A.28 second\\n'), 20);",
    ],
    command: process.execPath,
    cwd: resolve(import.meta.dirname, '../..'),
    env: {
      LANG: 'en_AU.UTF-8',
      LC_ALL: 'en_AU.UTF-8',
      PATH: '/usr/bin:/bin',
    },
    label: 'Observed stderr probe',
    stderrObserver(chunk) {
      assert.ok(Buffer.isBuffer(chunk));
      observed.push(chunk);
    },
    timeoutMs: 10_000,
  });
  assert.equal(result.status, 0);
  assert.equal(result.signal, null);
  assert.ok(result.stderr.equals(Buffer.concat(observed)));
  assert.equal(
    result.stderr.toString('utf8'),
    '[working] A.28 first\n[working] A.28 second\n',
  );
});

test('owned commands fail closed when a stderr observer rejects a chunk', async () => {
  await assert.rejects(
    runOwnedCommand({
      args: ['-e', "process.stderr.write('not accepted\\n'); setInterval(()=>{}, 1_000);"],
      command: process.execPath,
      cwd: resolve(import.meta.dirname, '../..'),
      env: {
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
        PATH: '/usr/bin:/bin',
      },
      label: 'Rejected stderr probe',
      stderrObserver() {
        throw new Error('stderr transcript rejected');
      },
      timeoutMs: 10_000,
    }),
    /stderr transcript rejected/u,
  );
});
