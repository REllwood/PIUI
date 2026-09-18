import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  ExclusiveRenameError,
  assertHeldEmptyDirectoryPlaceholder,
  assertHeldPathHasNoAcl,
  assertHeldTreeHasNoAcl,
  beginExclusiveRenameCompilerSession,
  endExclusiveRenameCompilerSession,
  exclusiveDirectoryRename,
  rewriteHeldRegularFile,
} from '../../scripts/exclusive-rename.mjs';

const exclusiveRenameSource = readFileSync(
  new URL('../../scripts/exclusive-rename.mjs', import.meta.url),
  'utf8',
);

test('compiler cleanup preserves preparation failures and cannot skip local cleanup', () => {
  assert.match(exclusiveRenameSource, /const COMPILER_TIMEOUT_MS = 120_000;/u);
  assert.match(exclusiveRenameSource, /const HELPER_TIMEOUT_MS = 30_000;/u);
  const compileStart = exclusiveRenameSource.indexOf('function compileHelper(');
  const compileEnd = exclusiveRenameSource.indexOf('\nfunction createHelperWorkspace(', compileStart);
  assert.ok(compileStart >= 0 && compileEnd > compileStart);
  const compileSource = exclusiveRenameSource.slice(compileStart, compileEnd);
  const releaseStart = compileSource.indexOf('releaseAppleToolchainAuthority(compilerAuthority);');
  const bufferCleanupStart = compileSource.indexOf(
    'for (const buffer of [sourceBytes, compilation?.stdout, compilation?.stderr])',
  );
  const descriptorCleanupStart = compileSource.indexOf(
    'for (const descriptor of [outputFd, helperFd, sourceFd])',
  );
  assert.ok(releaseStart >= 0);
  assert.ok(bufferCleanupStart > releaseStart);
  assert.ok(descriptorCleanupStart > bufferCleanupStart);
  assert.match(
    compileSource,
    /if \(compilerAuthorityOwned && compilerAuthority\) \{\s*try \{\s*releaseAppleToolchainAuthority\(compilerAuthority\);\s*\} catch \(error\) \{\s*cleanupErrors\.push\(error\);/u,
  );
  assert.match(
    compileSource,
    /const session = compilerSession === undefined[\s\S]*?COMPILER_SESSIONS\.get\(compilerSession\)[\s\S]*?if \(compilerSession !== undefined && !session\) reject\(\);[\s\S]*?compilerAuthority = session\.authority;[\s\S]*?spawnSync\([\s\S]*?revalidateAppleToolchainAuthority\(compilerAuthority\);/u,
  );
  assert.match(compileSource, /constants\.O_RDWR \| constants\.O_CREAT \| constants\.O_EXCL/u);
  assert.match(compileSource, /'-dynamiclib',[\s\S]*?'-x',[\s\S]*?'c',[\s\S]*?'-',[\s\S]*?'\/dev\/fd\/3'/u);
  assert.match(compileSource, /input: sourceBytes,[\s\S]*?stdio: \['pipe', 'pipe', 'pipe', outputFd\]/u);
  assert.match(compileSource, /helperSha256 !== EXPECTED_HELPER_DYLIB_SHA256/u);
  assert.match(exclusiveRenameSource, /spawnSync\(rubyLease\.inspector\.path,[\s\S]*?RUBY_DYLIB_BROKER/u);
  assert.match(exclusiveRenameSource, /Fiddle::Handle\.new\("\/dev\/fd\/9"\)/u);
  assert.match(
    compileSource,
    /if \(primaryError && cleanupError\) \{\s*throw new AggregateError\(/u,
  );
  assert.match(
    compileSource,
    /PATH: `\$\{APPLE_TOOLCHAIN_PATHS\.bin\}:\/usr\/bin:\/bin`/u,
  );
});

test('scoped compiler sessions permit independent scopes and require exact opaque tokens', {
  skip: process.platform !== 'darwin',
}, () => {
  const first = beginExclusiveRenameCompilerSession();
  const second = beginExclusiveRenameCompilerSession();
  let firstEnded = false;
  let secondEnded = false;
  try {
    assert.equal(Object.isFrozen(first), true);
    assert.equal(Object.isFrozen(second), true);
    assert.notEqual(first, second);
    assert.throws(
      () => endExclusiveRenameCompilerSession(Object.freeze({})),
      ExclusiveRenameError,
    );
    endExclusiveRenameCompilerSession(first);
    firstEnded = true;
    assert.throws(
      () => endExclusiveRenameCompilerSession(first),
      ExclusiveRenameError,
    );
    endExclusiveRenameCompilerSession(second);
    secondEnded = true;
  } finally {
    if (!firstEnded) endExclusiveRenameCompilerSession(first);
    if (!secondEnded) endExclusiveRenameCompilerSession(second);
  }
});

function fixture(t) {
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'piui-exclusive-rename-test-'));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { force: true, recursive: true }));
  return root;
}

function waitForChild(child) {
  return new Promise((resolveStatus, rejectStatus) => {
    child.once('error', rejectStatus);
    child.once('exit', resolveStatus);
  });
}

function synchronisedAttacker(script, argumentsList) {
  return spawn(process.execPath, ['-e', [
    "const { existsSync } = require('node:fs');",
    'const sleep = () => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1);',
    'const [ready] = process.argv.slice(1);',
    'for (let attempt = 0; attempt < 30000 && !existsSync(ready); attempt += 1) sleep();',
    'if (!existsSync(ready)) process.exit(3);',
    script,
  ].join('\n'), ...argumentsList], { stdio: 'ignore' });
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

test('empty-placeholder rename policy rejects a child injected at the final syscall boundary', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  const root = fixture(t);
  const synchronisation = join(root, 'synchronisation');
  const source = join(root, 'incoming');
  const destination = join(root, 'retired');
  const readyPath = join(synchronisation, 'ready');
  const continuePath = join(synchronisation, 'continue');
  mkdirSync(synchronisation, { mode: 0o700 });
  mkdirSync(source, { mode: 0o700 });
  const sourceBefore = lstatSync(source, { bigint: true });
  const attacker = synchronisedAttacker([
    "const { writeFileSync } = require('node:fs');",
    "const { join } = require('node:path');",
    'const [, source, continuePath] = process.argv.slice(1);',
    "writeFileSync(join(source, 'injected.txt'), 'injected\\n', { mode: 0o600 });",
    "writeFileSync(continuePath, 'continue\\n', { mode: 0o600 });",
  ].join('\n'), [readyPath, source, continuePath]);

  assert.throws(
    () => exclusiveDirectoryRename(source, destination, {
      helperWorkspaceParent: root,
      sourcePolicy: 'empty-placeholder',
      testOnlySynchronization: {
        native: { continuePath, phase: 'after-final-check', readyPath },
      },
    }),
    (error) => error instanceof ExclusiveRenameError && error.operationCompleted === false,
  );
  assert.equal(await waitForChild(attacker), 0);
  assert.equal(lstatSync(source, { bigint: true }).ino, sourceBefore.ino);
  assert.equal(readFileSync(join(source, 'injected.txt'), 'utf8'), 'injected\n');
  assert.throws(() => lstatSync(destination), { code: 'ENOENT' });
});

test('empty-placeholder rename policy reports a completed rejection for a post-rename child', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  const root = fixture(t);
  const synchronisation = join(root, 'synchronisation');
  const source = join(root, 'incoming');
  const destination = join(root, 'retired');
  const readyPath = join(synchronisation, 'ready');
  const continuePath = join(synchronisation, 'continue');
  mkdirSync(synchronisation, { mode: 0o700 });
  mkdirSync(source, { mode: 0o700 });
  const sourceBefore = lstatSync(source, { bigint: true });
  const attacker = synchronisedAttacker([
    "const { writeFileSync } = require('node:fs');",
    "const { join } = require('node:path');",
    'const [, destination, continuePath] = process.argv.slice(1);',
    "writeFileSync(join(destination, 'injected.txt'), 'injected\\n', { mode: 0o600 });",
    "writeFileSync(continuePath, 'continue\\n', { mode: 0o600 });",
  ].join('\n'), [readyPath, destination, continuePath]);

  assert.throws(
    () => exclusiveDirectoryRename(source, destination, {
      helperWorkspaceParent: root,
      sourcePolicy: 'empty-placeholder',
      testOnlySynchronization: {
        native: { continuePath, phase: 'after-rename', readyPath },
      },
    }),
    (error) => error instanceof ExclusiveRenameError
      && error.operationCompleted === true
      && error.receipt?.destinationVerified === true,
  );
  assert.equal(await waitForChild(attacker), 0);
  assert.throws(() => lstatSync(source), { code: 'ENOENT' });
  assert.equal(lstatSync(destination, { bigint: true }).ino, sourceBefore.ino);
  assert.equal(readFileSync(join(destination, 'injected.txt'), 'utf8'), 'injected\n');
});

test('empty-placeholder rename policy rejects final custom-xattr and BSD-flag mutations', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  for (const variant of ['custom-xattr', 'bsd-flag']) {
    await t.test(variant, async (childTest) => {
      const root = fixture(childTest);
      const synchronisation = join(root, 'synchronisation');
      const source = join(root, 'incoming');
      const destination = join(root, 'retired');
      const readyPath = join(synchronisation, 'ready');
      const continuePath = join(synchronisation, 'continue');
      mkdirSync(synchronisation, { mode: 0o700 });
      mkdirSync(source, { mode: 0o700 });
      const mutation = variant === 'custom-xattr'
        ? [
            "const changed = spawnSync('/usr/bin/xattr', ['-w', 'au.com.piui.rename-test', 'present', source]);",
            'if (changed.status !== 0) process.exit(4);',
          ]
        : [
            "const changed = spawnSync('/usr/bin/chflags', ['hidden', source]);",
            'if (changed.status !== 0) process.exit(4);',
          ];
      const attacker = synchronisedAttacker([
        "const { spawnSync } = require('node:child_process');",
        "const { writeFileSync } = require('node:fs');",
        'const [, source, continuePath] = process.argv.slice(1);',
        ...mutation,
        "writeFileSync(continuePath, 'continue\\n', { mode: 0o600 });",
      ].join('\n'), [readyPath, source, continuePath]);

      assert.throws(
        () => exclusiveDirectoryRename(source, destination, {
          helperWorkspaceParent: root,
          sourcePolicy: 'empty-placeholder',
          testOnlySynchronization: {
            native: { continuePath, phase: 'after-final-check', readyPath },
          },
        }),
        (error) => error instanceof ExclusiveRenameError && error.operationCompleted === false,
      );
      assert.equal(await waitForChild(attacker), 0);
      assert.ok(lstatSync(source).isDirectory());
      assert.throws(() => lstatSync(destination), { code: 'ENOENT' });
      if (variant === 'custom-xattr') {
        assert.match(
          spawnSync('/usr/bin/xattr', [source], { encoding: 'utf8' }).stdout,
          /au\.com\.piui\.rename-test/u,
        );
      } else {
        assert.equal(spawnSync('/usr/bin/chflags', ['nohidden', source]).status, 0);
      }
    });
  }
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

test('reports a completed rejection when the source leaf is swapped at the final syscall boundary', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  const root = fixture(t);
  const synchronisation = join(root, 'synchronisation');
  const source = join(root, 'incoming');
  const retainedSource = join(root, 'expected-retained');
  const destination = join(root, 'published');
  const readyPath = join(synchronisation, 'ready');
  const continuePath = join(synchronisation, 'continue');
  mkdirSync(synchronisation, { mode: 0o700 });
  mkdirSync(source, { mode: 0o700 });
  writeFileSync(join(source, 'record.txt'), 'expected\n', { mode: 0o600 });
  const expectedIdentity = lstatSync(source, { bigint: true });
  const attacker = synchronisedAttacker([
    "const { mkdirSync, renameSync, writeFileSync } = require('node:fs');",
    'const [, source, retainedSource, continuePath] = process.argv.slice(1);',
    'renameSync(source, retainedSource);',
    'mkdirSync(source, { mode: 0o700 });',
    "writeFileSync(require('node:path').join(source, 'record.txt'), 'decoy\\n', { mode: 0o600 });",
    "writeFileSync(continuePath, 'continue\\n', { mode: 0o600 });",
  ].join('\n'), [readyPath, source, retainedSource, continuePath]);

  assert.throws(
    () => exclusiveDirectoryRename(source, destination, {
      helperWorkspaceParent: root,
      testOnlySynchronization: {
        native: { continuePath, phase: 'after-final-check', readyPath },
      },
    }),
    (error) => error instanceof ExclusiveRenameError
      && error.operationCompleted === true
      && error.receipt?.operationCompleted === true
      && error.receipt?.nativePostconditionAccepted === false
      && error.receipt?.destinationVerified !== true,
  );
  assert.equal(await waitForChild(attacker), 0);
  const retainedAfter = lstatSync(retainedSource, { bigint: true });
  const destinationAfter = lstatSync(destination, { bigint: true });
  assert.equal(retainedAfter.dev, expectedIdentity.dev);
  assert.equal(retainedAfter.ino, expectedIdentity.ino);
  assert.notEqual(destinationAfter.ino, expectedIdentity.ino);
  assert.equal(readFileSync(join(retainedSource, 'record.txt'), 'utf8'), 'expected\n');
  assert.equal(readFileSync(join(destination, 'record.txt'), 'utf8'), 'decoy\n');
});

test('reports an authenticated completion receipt when a post-rename ACL check rejects', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  const root = fixture(t);
  const synchronisation = join(root, 'synchronisation');
  const source = join(root, 'incoming');
  const destination = join(root, 'published');
  const readyPath = join(synchronisation, 'ready');
  const continuePath = join(synchronisation, 'continue');
  mkdirSync(synchronisation, { mode: 0o700 });
  mkdirSync(source, { mode: 0o700 });
  const expectedIdentity = lstatSync(source, { bigint: true });
  const attacker = synchronisedAttacker([
    "const { spawnSync } = require('node:child_process');",
    "const { writeFileSync } = require('node:fs');",
    'const [, destination, continuePath] = process.argv.slice(1);',
    "const changed = spawnSync('/bin/chmod', ['+a', 'everyone allow read', destination]);",
    'if (changed.status !== 0) process.exit(4);',
    "writeFileSync(continuePath, 'continue\\n', { mode: 0o600 });",
  ].join('\n'), [readyPath, destination, continuePath]);

  assert.throws(
    () => exclusiveDirectoryRename(source, destination, {
      helperWorkspaceParent: root,
      testOnlySynchronization: {
        native: { continuePath, phase: 'after-rename', readyPath },
      },
    }),
    (error) => error instanceof ExclusiveRenameError
      && error.operationCompleted === true
      && error.receipt?.destinationVerified === true
      && error.receipt?.nativePostconditionAccepted === false
      && error.receipt?.destinationIdentity?.ino === expectedIdentity.ino,
  );
  assert.equal(await waitForChild(attacker), 0);
  assert.throws(() => lstatSync(source), { code: 'ENOENT' });
  assert.equal(lstatSync(destination, { bigint: true }).ino, expectedIdentity.ino);
  assert.equal(spawnSync('/bin/chmod', ['-RN', destination]).status, 0);
});

test('rejects a final source ACL mutation before rename', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  const root = fixture(t);
  const synchronisation = join(root, 'synchronisation');
  const source = join(root, 'incoming');
  const destination = join(root, 'published');
  const readyPath = join(synchronisation, 'ready');
  const continuePath = join(synchronisation, 'continue');
  mkdirSync(synchronisation, { mode: 0o700 });
  mkdirSync(source, { mode: 0o700 });
  const sourceBefore = lstatSync(source, { bigint: true });
  const attacker = synchronisedAttacker([
    "const { spawnSync } = require('node:child_process');",
    "const { writeFileSync } = require('node:fs');",
    'const [, source, continuePath] = process.argv.slice(1);',
    "const changed = spawnSync('/bin/chmod', ['+a', 'everyone allow read', source]);",
    'if (changed.status !== 0) process.exit(4);',
    "writeFileSync(continuePath, 'continue\\n', { mode: 0o600 });",
  ].join('\n'), [readyPath, source, continuePath]);

  assert.throws(
    () => exclusiveDirectoryRename(source, destination, {
      helperWorkspaceParent: root,
      testOnlySynchronization: {
        native: { continuePath, phase: 'before-final-check', readyPath },
      },
    }),
    (error) => error instanceof ExclusiveRenameError && error.operationCompleted === false,
  );
  assert.equal(await waitForChild(attacker), 0);
  assert.equal(lstatSync(source, { bigint: true }).ino, sourceBefore.ino);
  assert.throws(() => lstatSync(destination), { code: 'ENOENT' });
  assert.equal(spawnSync('/bin/chmod', ['-RN', source]).status, 0);
});

test('rejects compiler-output substitution before accepting or invoking the replacement', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  const root = fixture(t);
  const helperRoot = join(root, 'helper-root');
  const synchronisation = join(root, 'synchronisation');
  const source = join(root, 'incoming');
  const destination = join(root, 'published');
  const sentinel = join(root, 'compiler-replacement-ran');
  const readyPath = join(synchronisation, 'ready');
  const continuePath = join(synchronisation, 'continue');
  mkdirSync(helperRoot, { mode: 0o700 });
  mkdirSync(synchronisation, { mode: 0o700 });
  mkdirSync(source, { mode: 0o700 });
  const attacker = synchronisedAttacker([
    "const { chmodSync, readdirSync, renameSync, writeFileSync } = require('node:fs');",
    "const { join } = require('node:path');",
    'const [, helperRoot, sentinel, continuePath] = process.argv.slice(1);',
    "const workspaceName = readdirSync(helperRoot).find((name) => name.startsWith('piui-exclusive-rename-'));",
    'if (!workspaceName) process.exit(4);',
    'const workspace = join(helperRoot, workspaceName);',
    "const helperName = readdirSync(workspace).find((name) => name.endsWith('.dylib'));",
    'if (!helperName) process.exit(5);',
    'const helper = join(workspace, helperName);',
    "renameSync(helper, `${helper}.retained`);",
    "writeFileSync(helper, `#!/bin/sh\\nprintf replacement > '${sentinel}'\\n`, { mode: 0o700 });",
    'chmodSync(helper, 0o700);',
    "writeFileSync(continuePath, 'continue\\n', { mode: 0o600 });",
  ].join('\n'), [readyPath, helperRoot, sentinel, continuePath]);

  assert.throws(() => exclusiveDirectoryRename(source, destination, {
    helperWorkspaceParent: helperRoot,
    testOnlySynchronization: {
      compiler: { continuePath, readyPath },
    },
  }));
  assert.equal(await waitForChild(attacker), 0);
  assert.throws(() => lstatSync(sentinel), { code: 'ENOENT' });
  assert.ok(lstatSync(source).isDirectory());
  assert.throws(() => lstatSync(destination), { code: 'ENOENT' });
});

test('rejects helper-entry ABA at the execution boundary without running the replacement', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  const root = fixture(t);
  const helperRoot = join(root, 'helper-root');
  const synchronisation = join(root, 'synchronisation');
  const source = join(root, 'incoming');
  const destination = join(root, 'published');
  const sentinel = join(root, 'replacement-ran');
  const readyPath = join(synchronisation, 'ready');
  const continuePath = join(synchronisation, 'continue');
  mkdirSync(helperRoot, { mode: 0o700 });
  mkdirSync(synchronisation, { mode: 0o700 });
  mkdirSync(source, { mode: 0o700 });
  const attacker = synchronisedAttacker([
    "const { chmodSync, readdirSync, renameSync, writeFileSync } = require('node:fs');",
    "const { join } = require('node:path');",
    'const [, helperRoot, sentinel, continuePath] = process.argv.slice(1);',
    "const workspaceName = readdirSync(helperRoot).find((name) => name.startsWith('piui-exclusive-rename-'));",
    'if (!workspaceName) process.exit(4);',
    'const workspace = join(helperRoot, workspaceName);',
    "const helperName = readdirSync(workspace).find((name) => !name.endsWith('.c'));",
    'if (!helperName) process.exit(5);',
    'const helper = join(workspace, helperName);',
    "renameSync(helper, `${helper}.retained`);",
    "writeFileSync(helper, `#!/bin/sh\\nprintf replacement > '${sentinel}'\\n`, { mode: 0o700 });",
    'chmodSync(helper, 0o700);',
    "writeFileSync(continuePath, 'continue\\n', { mode: 0o600 });",
  ].join('\n'), [readyPath, helperRoot, sentinel, continuePath]);

  assert.throws(() => exclusiveDirectoryRename(source, destination, {
    helperWorkspaceParent: helperRoot,
    testOnlySynchronization: {
      helperExec: { continuePath, phase: 'after-final-check', readyPath },
    },
  }));
  assert.equal(await waitForChild(attacker), 0);
  assert.throws(() => lstatSync(sentinel), { code: 'ENOENT' });
  assert.ok(lstatSync(source).isDirectory());
  assert.throws(() => lstatSync(destination), { code: 'ENOENT' });
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

test('native helper cleanup rejects entry ABA without deleting the replacement inode', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  const root = fixture(t);
  const helperRoot = join(root, 'helper-root');
  const synchronisation = join(root, 'synchronisation');
  const source = join(root, 'incoming');
  const destination = join(root, 'published');
  const readyPath = join(synchronisation, 'ready');
  const continuePath = join(synchronisation, 'continue');
  mkdirSync(helperRoot, { mode: 0o700 });
  mkdirSync(synchronisation, { mode: 0o700 });
  mkdirSync(source, { mode: 0o700 });
  const attacker = synchronisedAttacker([
    "const { readdirSync, renameSync, writeFileSync } = require('node:fs');",
    "const { join } = require('node:path');",
    'const [, helperRoot, continuePath] = process.argv.slice(1);',
    "const workspaceName = readdirSync(helperRoot).find((name) => name.startsWith('piui-exclusive-rename-'));",
    'if (!workspaceName) process.exit(4);',
    'const workspace = join(helperRoot, workspaceName);',
    "const sourceName = readdirSync(workspace).find((name) => name.endsWith('.c'));",
    'if (!sourceName) process.exit(5);',
    'const sourcePath = join(workspace, sourceName);',
    "renameSync(sourcePath, `${sourcePath}.retained`);",
    "writeFileSync(sourcePath, 'attacker-owned replacement\\n', { mode: 0o600 });",
    "writeFileSync(continuePath, 'continue\\n', { mode: 0o600 });",
  ].join('\n'), [readyPath, helperRoot, continuePath]);

  assert.throws(
    () => exclusiveDirectoryRename(source, destination, {
      helperWorkspaceParent: helperRoot,
      testOnlySynchronization: {
        cleanup: { continuePath, readyPath },
      },
    }),
    (error) => error instanceof ExclusiveRenameError
      && error.operationCompleted === true
      && error.receipt?.destinationVerified === true,
  );
  assert.equal(await waitForChild(attacker), 0);
  assert.throws(() => lstatSync(source), { code: 'ENOENT' });
  assert.ok(lstatSync(destination).isDirectory());
  const retainedWorkspaces = readdirSync(helperRoot)
    .filter((name) => name.startsWith('piui-exclusive-rename-'));
  assert.equal(retainedWorkspaces.length, 1);
  const retainedWorkspace = join(helperRoot, retainedWorkspaces[0]);
  const replacementName = readdirSync(retainedWorkspace).find((name) => name.endsWith('.c'));
  assert.ok(replacementName);
  assert.equal(
    readFileSync(join(retainedWorkspace, replacementName), 'utf8'),
    'attacker-owned replacement\n',
  );
});

test('native helper cleanup rejects workspace-root ABA without deleting the replacement directory', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  const root = fixture(t);
  const helperRoot = join(root, 'helper-root');
  const synchronisation = join(root, 'synchronisation');
  const source = join(root, 'incoming');
  const destination = join(root, 'published');
  const replacementInode = join(root, 'replacement-inode');
  const readyPath = join(synchronisation, 'ready');
  const continuePath = join(synchronisation, 'continue');
  mkdirSync(helperRoot, { mode: 0o700 });
  mkdirSync(synchronisation, { mode: 0o700 });
  mkdirSync(source, { mode: 0o700 });
  const attacker = synchronisedAttacker([
    "const { lstatSync, mkdirSync, readdirSync, renameSync, writeFileSync } = require('node:fs');",
    "const { join } = require('node:path');",
    'const [, helperRoot, replacementInode, continuePath] = process.argv.slice(1);',
    "const workspaceName = readdirSync(helperRoot).find((name) => name.startsWith('piui-exclusive-rename-'));",
    'if (!workspaceName) process.exit(4);',
    'const workspace = join(helperRoot, workspaceName);',
    'renameSync(workspace, `${workspace}.retained`);',
    'mkdirSync(workspace, { mode: 0o700 });',
    "writeFileSync(replacementInode, `${lstatSync(workspace, { bigint: true }).ino}\\n`, { mode: 0o600 });",
    "writeFileSync(continuePath, 'continue\\n', { mode: 0o600 });",
  ].join('\n'), [readyPath, helperRoot, replacementInode, continuePath]);

  assert.throws(
    () => exclusiveDirectoryRename(source, destination, {
      helperWorkspaceParent: helperRoot,
      testOnlySynchronization: {
        cleanup: { continuePath, readyPath },
      },
    }),
    (error) => error instanceof ExclusiveRenameError
      && error.operationCompleted === true
      && error.receipt?.destinationVerified === true,
  );
  assert.equal(await waitForChild(attacker), 0);
  const replacementName = readdirSync(helperRoot)
    .find((name) => name.startsWith('piui-exclusive-rename-') && !name.endsWith('.retained'));
  const retainedName = readdirSync(helperRoot).find((name) => name.endsWith('.retained'));
  assert.ok(replacementName);
  assert.ok(retainedName);
  assert.equal(
    lstatSync(join(helperRoot, replacementName), { bigint: true }).ino.toString(10),
    readFileSync(replacementInode, 'utf8').trim(),
  );
  assert.equal(readdirSync(join(helperRoot, replacementName)).length, 0);
  assert.equal(readdirSync(join(helperRoot, retainedName)).length, 2);
});

test('inspects held paths and trees and rewrites the exact held importer bytes', {
  skip: process.platform !== 'darwin',
}, (t) => {
  const root = fixture(t);
  const parent = join(root, 'prepared');
  const importer = join(parent, 'package.json');
  mkdirSync(parent, { mode: 0o700 });
  writeFileSync(importer, '{"before":true}\n', { mode: 0o600 });
  const parentFd = openSync(parent, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  const importerFd = openSync(importer, constants.O_RDONLY | constants.O_NOFOLLOW);
  t.after(() => {
    closeSync(importerFd);
    closeSync(parentFd);
  });
  const parentIdentity = fstatSync(parentFd, { bigint: true });
  const importerIdentity = fstatSync(importerFd, { bigint: true });

  assertHeldPathHasNoAcl({
    fd: parentFd,
    helperWorkspaceParent: root,
    identity: parentIdentity,
    kind: 'directory',
    path: parent,
  });
  assertHeldTreeHasNoAcl({
    fd: parentFd,
    helperWorkspaceParent: root,
    identity: parentIdentity,
    path: parent,
  });
  const expected = Buffer.alloc(1024 * 1024, 0x61);
  rewriteHeldRegularFile({
    bytes: expected,
    fileFd: importerFd,
    fileIdentity: importerIdentity,
    helperWorkspaceParent: root,
    name: 'package.json',
    parentFd,
    parentIdentity,
    parentPath: parent,
  });

  assert.deepEqual(readFileSync(importer), expected);
  assert.equal(lstatSync(importer).mode & 0o777, 0o600);
});

test('binds an empty reset placeholder to its exact allowed held metadata', {
  skip: process.platform !== 'darwin',
}, (t) => {
  const root = fixture(t);
  const inspect = (path) => {
    const fd = openSync(
      path,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    try {
      assertHeldEmptyDirectoryPlaceholder({
        fd,
        helperWorkspaceParent: root,
        identity: fstatSync(fd, { bigint: true }),
        path,
      });
    } finally {
      closeSync(fd);
    }
  };

  const accepted = join(root, 'accepted');
  mkdirSync(accepted, { mode: 0o700 });
  inspect(accepted);

  const nonEmpty = join(root, 'non-empty');
  mkdirSync(nonEmpty, { mode: 0o700 });
  writeFileSync(join(nonEmpty, 'manifest.json'), '{}\n', { mode: 0o600 });
  assert.throws(() => inspect(nonEmpty), (error) => error instanceof ExclusiveRenameError);

  const wrongMode = join(root, 'wrong-mode');
  mkdirSync(wrongMode, { mode: 0o755 });
  assert.throws(() => inspect(wrongMode), (error) => error instanceof ExclusiveRenameError);

  const customXattr = join(root, 'custom-xattr');
  mkdirSync(customXattr, { mode: 0o700 });
  assert.equal(
    spawnSync('/usr/bin/xattr', ['-w', 'au.com.piui.placeholder-test', 'present', customXattr]).status,
    0,
  );
  assert.throws(() => inspect(customXattr), (error) => error instanceof ExclusiveRenameError);

  const extendedAcl = join(root, 'extended-acl');
  mkdirSync(extendedAcl, { mode: 0o700 });
  assert.equal(spawnSync('/bin/chmod', ['+a', 'everyone allow read', extendedAcl]).status, 0);
  assert.throws(() => inspect(extendedAcl), (error) => error instanceof ExclusiveRenameError);
  assert.equal(spawnSync('/bin/chmod', ['-RN', extendedAcl]).status, 0);

  const bsdFlags = join(root, 'bsd-flags');
  mkdirSync(bsdFlags, { mode: 0o700 });
  assert.equal(spawnSync('/usr/bin/chflags', ['hidden', bsdFlags]).status, 0);
  assert.throws(() => inspect(bsdFlags), (error) => error instanceof ExclusiveRenameError);
  assert.equal(spawnSync('/usr/bin/chflags', ['nohidden', bsdFlags]).status, 0);

  const original = join(root, 'aba');
  const retained = join(root, 'aba-retained');
  mkdirSync(original, { mode: 0o700 });
  const originalFd = openSync(
    original,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  t.after(() => closeSync(originalFd));
  const originalIdentity = fstatSync(originalFd, { bigint: true });
  renameSync(original, retained);
  mkdirSync(original, { mode: 0o700 });
  assert.throws(
    () => assertHeldEmptyDirectoryPlaceholder({
      fd: originalFd,
      helperWorkspaceParent: root,
      identity: originalIdentity,
      path: original,
    }),
    (error) => error instanceof ExclusiveRenameError,
  );
});

test('permits only stable provenance on an otherwise exact empty reset placeholder', {
  skip: process.platform !== 'darwin',
}, (t) => {
  const root = fixture(t);
  const target = join(root, 'placeholder');
  mkdirSync(target, { mode: 0o700 });
  assert.equal(
    spawnSync('/usr/bin/xattr', ['-w', 'com.apple.provenance', 'formal-reset', target]).status,
    0,
  );
  const fd = openSync(
    target,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  t.after(() => closeSync(fd));
  assertHeldEmptyDirectoryPlaceholder({
    fd,
    helperWorkspaceParent: root,
    identity: fstatSync(fd, { bigint: true }),
    path: target,
  });
  assert.equal(
    spawnSync('/usr/bin/xattr', [target], { encoding: 'utf8' }).stdout,
    'com.apple.provenance\n',
  );

  const rejected = join(root, 'rejected-custom-xattr');
  mkdirSync(rejected, { mode: 0o700 });
  assert.equal(
    spawnSync('/usr/bin/xattr', ['-w', 'au.com.piui.placeholder-test', 'present', rejected]).status,
    0,
  );
  const rejectedFd = openSync(
    rejected,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  t.after(() => closeSync(rejectedFd));
  assert.throws(
    () => assertHeldEmptyDirectoryPlaceholder({
      fd: rejectedFd,
      helperWorkspaceParent: root,
      identity: fstatSync(rejectedFd, { bigint: true }),
      path: rejected,
    }),
    (error) => error instanceof ExclusiveRenameError,
  );
});

test('held inspection rejects a symlink spelling and an ancestor ABA replacement', {
  skip: process.platform !== 'darwin',
}, (t) => {
  const root = fixture(t);
  const originalParent = join(root, 'original-parent');
  const aliasParent = join(root, 'alias-parent');
  const target = join(originalParent, 'held');
  mkdirSync(originalParent, { mode: 0o700 });
  mkdirSync(target, { mode: 0o700 });
  symlinkSync(originalParent, aliasParent);
  const fd = openSync(target, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  t.after(() => closeSync(fd));
  const identity = fstatSync(fd, { bigint: true });

  assert.throws(
    () => assertHeldPathHasNoAcl({
      fd,
      helperWorkspaceParent: root,
      identity,
      kind: 'directory',
      path: join(aliasParent, 'held'),
    }),
    (error) => error instanceof ExclusiveRenameError,
  );

  const displacedParent = join(root, 'displaced-parent');
  renameSync(originalParent, displacedParent);
  mkdirSync(originalParent, { mode: 0o700 });
  mkdirSync(join(originalParent, 'held'), { mode: 0o700 });
  assert.throws(
    () => assertHeldPathHasNoAcl({
      fd,
      helperWorkspaceParent: root,
      identity,
      kind: 'directory',
      path: target,
    }),
    (error) => error instanceof ExclusiveRenameError,
  );
});

test('tree ACL inspection starts from a fresh directory description after a shared offset was exhausted', {
  skip: process.platform !== 'darwin',
}, (t) => {
  const root = fixture(t);
  const target = join(root, 'prepared');
  const aclEntry = join(target, 'acl-entry.txt');
  mkdirSync(target, { mode: 0o700 });
  writeFileSync(aclEntry, 'acl\n', { mode: 0o600 });
  assert.equal(spawnSync('/bin/chmod', ['+a', 'everyone allow read', aclEntry]).status, 0);
  const fd = openSync(target, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  t.after(() => {
    spawnSync('/bin/chmod', ['-RN', target]);
    closeSync(fd);
  });
  const identity = fstatSync(fd, { bigint: true });

  assert.throws(
    () => assertHeldTreeHasNoAcl({
      fd,
      helperWorkspaceParent: root,
      identity,
      path: target,
      testOnlyAdvanceSharedOffset: true,
    }),
    (error) => error instanceof ExclusiveRenameError,
  );
});

test('held importer rewrite rejects stale equal-length file state', {
  skip: process.platform !== 'darwin',
}, (t) => {
  const root = fixture(t);
  const parent = join(root, 'prepared');
  const importer = join(parent, 'package.json');
  mkdirSync(parent, { mode: 0o700 });
  writeFileSync(importer, 'original\n', { mode: 0o600 });
  const parentFd = openSync(parent, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  const importerFd = openSync(importer, constants.O_RDONLY | constants.O_NOFOLLOW);
  t.after(() => {
    closeSync(importerFd);
    closeSync(parentFd);
  });
  const parentIdentity = fstatSync(parentFd, { bigint: true });
  const importerIdentity = fstatSync(importerFd, { bigint: true });
  writeFileSync(importer, 'attacker\n', { mode: 0o600 });

  assert.throws(
    () => rewriteHeldRegularFile({
      bytes: Buffer.from('accepted\n'),
      fileFd: importerFd,
      fileIdentity: importerIdentity,
      helperWorkspaceParent: root,
      name: 'package.json',
      parentFd,
      parentIdentity,
      parentPath: parent,
    }),
    (error) => error instanceof ExclusiveRenameError,
  );
  assert.equal(readFileSync(importer, 'utf8'), 'attacker\n');
});

test('mutable held parent tolerates concurrent sibling churn without weakening identity', {
  skip: process.platform !== 'darwin',
}, async (t) => {
  const root = fixture(t);
  const fd = openSync(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  t.after(() => closeSync(fd));
  const identity = fstatSync(fd, { bigint: true });
  const churn = spawn(process.execPath, ['-e', [
    "const { unlinkSync, writeFileSync } = require('node:fs');",
    "const { join } = require('node:path');",
    'const root = process.argv[1];',
    'for (let index = 0; index < 600; index += 1) {',
    "  const path = join(root, `ambient-${index % 7}`);",
    "  writeFileSync(path, 'ambient\\n', { mode: 0o600 });",
    '  unlinkSync(path);',
    '  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1);',
    '}',
  ].join('\n'), root], { stdio: 'ignore' });

  for (let attempt = 0; attempt < 2; attempt += 1) {
    assertHeldPathHasNoAcl({
      fd,
      helperWorkspaceParent: root,
      identity,
      kind: 'mutable-directory',
      path: root,
    });
  }
  const churnStatus = await new Promise((resolveStatus, rejectStatus) => {
    churn.once('error', rejectStatus);
    churn.once('exit', resolveStatus);
  });
  assert.equal(churnStatus, 0);
  const after = fstatSync(fd, { bigint: true });
  assert.equal(after.dev, identity.dev);
  assert.equal(after.ino, identity.ino);
  assert.equal(after.mode, identity.mode);
});
