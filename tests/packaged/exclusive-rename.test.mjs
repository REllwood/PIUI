import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  ExclusiveRenameError,
  exclusiveDirectoryRename,
} from '../../scripts/exclusive-rename.mjs';

function fixture(t) {
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'piui-exclusive-rename-test-'));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { force: true, recursive: true }));
  return root;
}

test('renames a private directory to a missing sibling without changing its inode', {
  skip: process.platform !== 'darwin',
}, (t) => {
  const root = fixture(t);
  const source = join(root, 'incoming');
  const destination = join(root, 'published');
  mkdirSync(source, { mode: 0o700 });
  writeFileSync(join(source, 'record.txt'), 'original\n', { mode: 0o600 });
  const sourceBefore = lstatSync(source, { bigint: true });

  exclusiveDirectoryRename(source, destination);

  assert.throws(() => lstatSync(source), { code: 'ENOENT' });
  const destinationAfter = lstatSync(destination, { bigint: true });
  assert.equal(destinationAfter.dev, sourceBefore.dev);
  assert.equal(destinationAfter.ino, sourceBefore.ino);
  assert.equal(readFileSync(join(destination, 'record.txt'), 'utf8'), 'original\n');
});

test('renames across two held private parents without changing the source inode', {
  skip: process.platform !== 'darwin',
}, (t) => {
  const root = fixture(t);
  const sourceParent = join(root, 'source-parent');
  const destinationParent = join(root, 'destination-parent');
  const source = join(sourceParent, 'incoming');
  const destination = join(destinationParent, 'published');
  mkdirSync(sourceParent, { mode: 0o700 });
  mkdirSync(destinationParent, { mode: 0o700 });
  mkdirSync(source, { mode: 0o700 });
  writeFileSync(join(source, 'record.txt'), 'cross-parent\n', { mode: 0o600 });
  const sourceBefore = lstatSync(source, { bigint: true });
  const sourceParentBefore = lstatSync(sourceParent, { bigint: true });
  const destinationParentBefore = lstatSync(destinationParent, { bigint: true });

  exclusiveDirectoryRename(source, destination, {
    expectedDestinationParentIdentity: destinationParentBefore,
    expectedSourceIdentity: sourceBefore,
    expectedSourceParentIdentity: sourceParentBefore,
  });

  assert.throws(() => lstatSync(source), { code: 'ENOENT' });
  const destinationAfter = lstatSync(destination, { bigint: true });
  assert.equal(destinationAfter.dev, sourceBefore.dev);
  assert.equal(destinationAfter.ino, sourceBefore.ino);
  assert.equal(readFileSync(join(destination, 'record.txt'), 'utf8'), 'cross-parent\n');
});

test('rejects a destination collision without replacing either directory', {
  skip: process.platform !== 'darwin',
}, (t) => {
  const root = fixture(t);
  const source = join(root, 'incoming');
  const destination = join(root, 'published');
  mkdirSync(source, { mode: 0o700 });
  mkdirSync(destination, { mode: 0o700 });
  writeFileSync(join(source, 'record.txt'), 'source\n', { mode: 0o600 });
  writeFileSync(join(destination, 'record.txt'), 'destination\n', { mode: 0o600 });
  const sourceBefore = lstatSync(source, { bigint: true });
  const destinationBefore = lstatSync(destination, { bigint: true });

  assert.throws(
    () => exclusiveDirectoryRename(source, destination),
    (error) => error instanceof ExclusiveRenameError
      && error.code === 'exclusive-rename-rejected',
  );

  const sourceAfter = lstatSync(source, { bigint: true });
  const destinationAfter = lstatSync(destination, { bigint: true });
  assert.equal(sourceAfter.dev, sourceBefore.dev);
  assert.equal(sourceAfter.ino, sourceBefore.ino);
  assert.equal(destinationAfter.dev, destinationBefore.dev);
  assert.equal(destinationAfter.ino, destinationBefore.ino);
  assert.equal(readFileSync(join(source, 'record.txt'), 'utf8'), 'source\n');
  assert.equal(readFileSync(join(destination, 'record.txt'), 'utf8'), 'destination\n');
});

test('refuses to delete an unexpected same-UID helper-workspace entry', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  const root = fixture(t);
  const helperTemporaryRoot = join(root, 'helper-temporary');
  mkdirSync(helperTemporaryRoot, { mode: 0o700 });
  const source = join(root, 'incoming');
  const destination = join(root, 'published');
  mkdirSync(source, { mode: 0o700 });
  const prefix = `piui-exclusive-rename-${process.pid}-`;
  const attacker = spawn(process.execPath, ['-e', [
    "const { readdirSync, writeFileSync } = require('node:fs');",
    "const { join } = require('node:path');",
    'const [root, prefix] = process.argv.slice(1);',
    'for (let attempt = 0; attempt < 5000; attempt += 1) {',
    '  const name = readdirSync(root).find((entry) => entry.startsWith(prefix));',
    "  if (name) { writeFileSync(join(root, name, 'unexpected'), 'injected\\n', { mode: 0o600 }); process.exit(0); }",
    '  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1);',
    '}',
    'process.exit(2);',
  ].join('\n'), helperTemporaryRoot, prefix], {
    stdio: 'ignore',
  });
  const previousTemporary = process.env.TMPDIR;
  process.env.TMPDIR = helperTemporaryRoot;
  try {
    assert.throws(
      () => exclusiveDirectoryRename(source, destination),
      (error) => error instanceof ExclusiveRenameError
        && error.operationCompleted === true
        && error.code === 'exclusive-rename-completed-finalisation-rejected'
        && error.receipt?.operationCompleted === true
        && error.receipt?.destination === destination,
    );
  } finally {
    if (previousTemporary === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = previousTemporary;
  }
  const attackerStatus = await new Promise((resolveStatus, rejectStatus) => {
    attacker.once('error', rejectStatus);
    attacker.once('exit', resolveStatus);
  });
  assert.equal(attackerStatus, 0);
  assert.throws(() => lstatSync(source), { code: 'ENOENT' });
  assert.ok(lstatSync(destination).isDirectory());
  const retained = readdirSync(helperTemporaryRoot);
  assert.equal(retained.length, 1);
  assert.match(retained[0], /^piui-exclusive-rename-/u);
  assert.equal(
    readFileSync(join(helperTemporaryRoot, retained[0], 'unexpected'), 'utf8'),
    'injected\n',
  );
});
