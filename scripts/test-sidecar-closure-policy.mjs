import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdir, mkdtemp, open, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { isForbiddenDocumentationPath } from './sidecar-closure-policy.mjs';
import {
  assertSidecarCandidateLease,
  captureSidecarCandidateLease,
  prepareCandidateForRename,
  renamePreparedCandidate,
} from './sidecar-publication-policy.mjs';

const extensionlessDocumentationNames = [
  'README',
  'CHANGELOG-v2',
  'HISTORY_2024',
  'CONTRIBUTING notes',
  'CODE_OF_CONDUCT',
  'SECURITY',
];
const rejected = [
  'docs/guide.js',
  'node_modules/@scope/package/EXAMPLES/demo.js',
  'node_modules/proper-lockfile/node_modules/retry/example/README.md',
  'node_modules/outer/node_modules/@nested/package/Tests/canary.js',
  'node_modules/package/opslevel.yaml',
  'node_modules/package/runtime-notes.mdx',
  ...extensionlessDocumentationNames.flatMap((name) => [
    `node_modules/package/${name}`,
    `node_modules/package/${name}.md`,
  ]),
];
for (const path of rejected) {
  assert.equal(isForbiddenDocumentationPath(path), true, `expected policy rejection: ${path}`);
}

const runtimePrefixNames = [
  'README',
  'CHANGELOG',
  'HISTORY',
  'CONTRIBUTING',
  'CODE_OF_CONDUCT',
  'SECURITY',
];
const accepted = [
  'dist/pi/trust-loader-project-thread.js',
  'node_modules/proper-lockfile/node_modules/retry/index.js',
  'node_modules/@scope/package/dist/runtime.js',
  'node_modules/package/documentation/runtime.json',
  'node_modules/package/example-runtime.js',
  'node_modules/package/package.json',
  'node_modules/package/LICENSE.md',
  'node_modules/package/NOTICE.rst',
  'node_modules/package/CHANGELOG.txt',
  'node_modules/@earendil-works/pi-coding-agent/dist/utils/changelog.js',
  'node_modules/yaml/dist/doc/directives.js',
  'node_modules/yaml/dist/doc/Document.js',
  'node_modules/package/dist/test/runtime.js',
  'node_modules/@scope/package/lib/examples/runtime.json',
  'node_modules/@earendil-works/pi-coding-agent/dist/modes/interactive/theme/dark.json',
  ...runtimePrefixNames.flatMap((name) => [
    `node_modules/package/${name}.js`,
    `node_modules/package/${name}.json`,
  ]),
];
for (const path of accepted) {
  assert.equal(isForbiddenDocumentationPath(path), false, `expected runtime acceptance: ${path}`);
}

const stageSource = readFileSync(new URL('./stage-sidecar.mjs', import.meta.url), 'utf8');
const publicationSource = readFileSync(new URL('./sidecar-publication-policy.mjs', import.meta.url), 'utf8');
assert.match(stageSource, /manifestPath[\s\S]*await prepareCandidateForRename\(prepared, \{ heldRootFd: preparedLease\.handle\.fd \}\);/);
assert.match(stageSource, /mkdtemp\(resolve\(temporary, 'piui-sidecar-stage-'\)\)/);
assert.match(
  stageSource,
  /const temporary = await realpath\(resolve\(process\.env\.TMPDIR \|\| tmpdir\(\)\)\);[\s\S]*?const canonicalWorkspace = await realpath\(stagingWorkspace\);[\s\S]*?canonicalWorkspace !== stagingWorkspace \|\| dirname\(canonicalWorkspace\) !== temporary/u,
);
assert.doesNotMatch(stageSource, /temporary !== requestedTemporary/u);
assert.match(stageSource, /async function makeTreeOwnerWritable\(path, rootOnly = false, rootDirectoryMode\)[\s\S]*item\.nlink !== 1[\s\S]*O_NOFOLLOW[\s\S]*exact\.dev !== item\.dev[\s\S]*handle\.chmod/);
assert.match(stageSource, /async function cleanHeldWorkspaceMandatory\(workspaceLease, parentLease, setCleanupPhase\)[\s\S]*setCleanupPhase\('workspace-cleanup-temporary-lease'\)[\s\S]*setCleanupPhase\('workspace-cleanup-workspace-lease'\)[\s\S]*setCleanupPhase\('workspace-cleanup-tree-unlock'\)[\s\S]*makeTreeOwnerWritable\(workspaceLease\.path, false, 0o700\)[\s\S]*setCleanupPhase\('workspace-cleanup-post-unlock-lease-validation'\)[\s\S]*setCleanupPhase\('workspace-cleanup-inspector-capture'\)[\s\S]*setCleanupPhase\('workspace-cleanup-descriptor-bound-removal'\)[\s\S]*removeDescriptorBoundTree[\s\S]*setCleanupPhase\('workspace-cleanup-path-absence'\)/);
assert.match(stageSource, /workspaceCleanupAuthorised[\s\S]*assertHeldPathLease\(workspaceCleanupLease\)[\s\S]*cleanHeldWorkspaceMandatory/);
assert.doesNotMatch(stageSource, /cleanTreeBestEffort|Staging cleanup deferred|chmod', \['-R'/);
assert.match(stageSource, /failed-publish[\s\S]*moveHeldDirectory[\s\S]*sealHeldPublication/);
assert.match(stageSource, /rewriteHeldRegularFile[\s\S]*exclusiveDirectoryRename/);
assert.doesNotMatch(stageSource, /rename\((?:prepared|output|retired),/u);
assert.match(publicationSource, /handle\.chmod\(isRoot \? 0o700 : 0o555\)/);
assert.match(publicationSource, /renamePreparedCandidate[\s\S]*assertSidecarCandidateLease\(prepared, candidateLease[\s\S]*exclusiveDirectoryRename[\s\S]*sealPublishedOutput/);
assert.match(publicationSource, /fchmodSync\(heldRootFd, 0o555\)/);
assert.doesNotMatch(publicationSource, /removeFinderMetadataDefensively|verifyNoFinderMetadata/);
assert.doesNotMatch(stageSource, /chmod\(output, 0o755\)/);

const disposable = await realpath(await mkdtemp(join(tmpdir(), 'piui-closure-rename-')));
const canonicalTemporary = await realpath(resolve(tmpdir()));
assert.equal(dirname(disposable), canonicalTemporary, 'fixture must use the canonical temporary parent');
let preparedHandle;
try {
  const prepared = join(disposable, 'prepared');
  const output = join(disposable, 'output');
  const nested = join(prepared, 'node_modules', 'yaml', 'dist', 'doc');
  await mkdir(nested, { recursive: true });
  const directiveBytes = Buffer.from('export {};\n', 'utf8');
  await writeFile(join(nested, 'directives.js'), directiveBytes);
  await writeFile(join(prepared, 'manifest.json'), `${JSON.stringify({
    node: '22.23.1',
    piSdk: '0.82.0',
    closure: 'isolated-v1',
    files: [{
      path: 'node_modules/yaml/dist/doc/directives.js',
      bytes: directiveBytes.length,
      sha256: createHash('sha256').update(directiveBytes).digest('hex'),
    }],
  }, null, 2)}\n`);
  preparedHandle = await open(prepared, 'r');
  await prepareCandidateForRename(prepared, { heldRootFd: preparedHandle.fd });
  assert.equal((await stat(prepared)).mode & 0o777, 0o700, 'candidate root must remain private and renameable');
  assert.equal((await stat(nested)).mode & 0o777, 0o555, 'candidate descendants must be sealed');
  const lease = await captureSidecarCandidateLease(prepared, {
    heldRootFd: preparedHandle.fd,
    helperWorkspaceParent: disposable,
  });
  await assert.rejects(
    renamePreparedCandidate(prepared, output),
    /publication lease is unavailable/u,
  );
  await renamePreparedCandidate(prepared, output, {
    candidateLease: lease,
    heldRootFd: preparedHandle.fd,
    helperWorkspaceParent: disposable,
  });
  await assertSidecarCandidateLease(output, lease, {
    allowRootModeChange: true,
    heldRootFd: preparedHandle.fd,
    helperWorkspaceParent: disposable,
  });
  assert.equal((await stat(output)).mode & 0o777, 0o555, 'published root must be sealed');
  assert.equal((await stat(join(output, 'node_modules', 'yaml', 'dist', 'doc'))).mode & 0o777, 0o555);
  assert.equal(readFileSync(join(output, 'node_modules', 'yaml', 'dist', 'doc', 'directives.js'), 'utf8'), 'export {};\n');
  assert.equal(spawnSync('find', [output, '-name', '.DS_Store', '-print'], { encoding: 'utf8' }).stdout, '');
} finally {
  await preparedHandle?.close();
  spawnSync('chmod', ['-R', 'u+w', disposable], { stdio: 'ignore' });
  await rm(disposable, { recursive: true, force: true });
}

const hostile = await realpath(await mkdtemp(join(tmpdir(), 'piui-closure-hostile-')));
try {
  const linkedCandidate = join(hostile, 'linked');
  await mkdir(linkedCandidate, { mode: 0o700 });
  await writeFile(join(hostile, 'outside.js'), 'outside\n');
  await symlink(join(hostile, 'outside.js'), join(linkedCandidate, 'linked.js'));
  const linkedHandle = await open(linkedCandidate, 'r');
  try {
    await assert.rejects(
      prepareCandidateForRename(linkedCandidate, { heldRootFd: linkedHandle.fd }),
      /unsafe entry/u,
    );
  } finally {
    await linkedHandle.close();
  }

  const finderCandidate = join(hostile, 'finder');
  await mkdir(finderCandidate, { mode: 0o700 });
  await writeFile(join(finderCandidate, '.DS_Store'), 'untrusted metadata');
  const finderHandle = await open(finderCandidate, 'r');
  try {
    await assert.rejects(
      prepareCandidateForRename(finderCandidate, { heldRootFd: finderHandle.fd }),
      /contains Finder metadata/u,
    );
    assert.equal(readFileSync(join(finderCandidate, '.DS_Store'), 'utf8'), 'untrusted metadata');
  } finally {
    await finderHandle.close();
  }

  const mismatched = join(hostile, 'mismatched');
  await mkdir(mismatched, { mode: 0o700 });
  await writeFile(join(mismatched, 'runtime.js'), 'expected\n');
  await writeFile(join(mismatched, 'manifest.json'), `${JSON.stringify({
    node: '22.23.1',
    piSdk: '0.82.0',
    closure: 'isolated-v1',
    files: [{ path: 'runtime.js', bytes: 9, sha256: '0'.repeat(64) }],
  })}\n`);
  const mismatchedHandle = await open(mismatched, 'r');
  await prepareCandidateForRename(mismatched, { heldRootFd: mismatchedHandle.fd });
  await mismatchedHandle.close();
  await assert.rejects(
    captureSidecarCandidateLease(mismatched),
    /does not match its manifest/u,
  );

  if (process.platform === 'darwin') {
    const aclCandidate = join(hostile, 'acl-candidate');
    const aclBytes = Buffer.from('export const acl = false;\n', 'utf8');
    await mkdir(aclCandidate, { mode: 0o700 });
    await writeFile(join(aclCandidate, 'runtime.js'), aclBytes);
    await writeFile(join(aclCandidate, 'manifest.json'), `${JSON.stringify({
      node: '22.23.1',
      piSdk: '0.82.0',
      closure: 'isolated-v1',
      files: [{
        path: 'runtime.js',
        bytes: aclBytes.length,
        sha256: createHash('sha256').update(aclBytes).digest('hex'),
      }],
    })}\n`);
    const aclHandle = await open(aclCandidate, 'r');
    await prepareCandidateForRename(aclCandidate, { heldRootFd: aclHandle.fd });
    await aclHandle.close();
    const acl = spawnSync('/bin/chmod', ['+a', 'everyone allow read', join(aclCandidate, 'runtime.js')]);
    assert.equal(acl.status, 0, 'ACL fixture preparation must succeed');
    await assert.rejects(
      captureSidecarCandidateLease(aclCandidate),
      (error) => error?.code === 'exclusive-rename-rejected',
    );
  }
} finally {
  spawnSync('chmod', ['-RN', hostile], { stdio: 'ignore' });
  spawnSync('chmod', ['-R', 'u+w', hostile], { stdio: 'ignore' });
  await rm(hostile, { recursive: true, force: true });
}

console.log(`Sidecar closure policy accepted: ${rejected.length} rejected, ${accepted.length} runtime and real sealed-rename cases`);
