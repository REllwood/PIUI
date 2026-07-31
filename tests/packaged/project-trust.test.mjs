import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import {
  closeSync, constants, fstatSync, openSync,
} from 'node:fs';
import {
  chmod, lstat, mkdir, mkdtemp, open, readFile, realpath, rm, writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test, { after, before } from 'node:test';
import {
  assertDescriptorHasNoAcl,
  captureSystemDescriptorAclInspector,
  removeDescriptorBoundTree,
} from '../../scripts/descriptor-acl.mjs';
import {
  captureFixture,
  parsePackagedTrustEvidence,
  parseProjectTrustHarnessEvidence,
  projectTrustSandbox,
  waitForChildSpawn,
} from '../../scripts/run-packaged-trust-probe.mjs';

const root = resolve(import.meta.dirname, '../..');
let aclWorkspace;
let aclInspector;
let nativeAclHelper;

before(async () => {
  aclWorkspace = await mkdtemp(join(tmpdir(), 'piui-a24-acl-test-'));
  aclInspector = captureSystemDescriptorAclInspector();
  nativeAclHelper = resolve(aclWorkspace, 'native-acl-reference');
  const compiled = spawnSync('/usr/bin/clang', [
    '--no-default-config',
    '-std=c11',
    '-O2',
    '-Wall',
    '-Wextra',
    '-Werror',
    '-mmacosx-version-min=13.0',
    resolve(root, 'scripts/inspect-descriptor-acl.c'),
    '-o',
    nativeAclHelper,
  ], {
    encoding: 'utf8',
    env: { PATH: '/usr/bin:/bin' },
  });
  assert.equal(compiled.status, 0);
  assert.equal(compiled.signal, null);
  assert.equal(compiled.stdout, '');
  assert.equal(compiled.stderr, '');
  await chmod(nativeAclHelper, 0o500);
});

after(async () => {
  if (aclWorkspace) await rm(aclWorkspace, { recursive: true, force: true });
});
const expectedHarness = Object.freeze({
  schemaVersion: 1,
  packagedRuntimeValidated: true,
  metadataInspections: 1,
  untrustedLoadRejections: 1,
  projectTrustAuthorisations: 1,
  sentinelWorkspaceAuthorisations: 1,
  authoriseExecutions: 0,
  sidecarGenerationRestarted: true,
  sidecarGenerationRestarts: 2,
  trustedLoadExecutions: 1,
  markerBytes: 9,
  markerLines: 1,
  concurrentReplayRequests: 16,
  cachedReplayResults: 16,
  skillCanaryExecutions: 0,
  packageCanaryExecutions: 0,
  settingsCanaryLoads: 0,
  ancestorCanaryLoads: 0,
  projectTrustApprovalPolicyMutations: 0,
  approvalRecordsBeforeTrust: 0,
  approvalRecordsAfterTrust: 0,
  rememberedApprovalScopes: 0,
  groupApprovalScopes: 0,
  blanketApprovalScopes: 0,
  approvalSentinelUnchangedThroughTrustedLoad: true,
  revocations: 1,
  postRevokeLoadRejections: 1,
  staleGenerationRejections: 1,
  staleRevisionRejections: 1,
  staleLeaseRejections: 1,
  sourceMarkerExecutions: 0,
  fixtureInventoryUnchanged: true,
});

function line(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`);
}

function rejected(bytes, parser = parseProjectTrustHarnessEvidence) {
  assert.throws(() => parser(bytes), { message: 'A.24 packaged trust probe rejected' });
}

test('strictly accepts only the fixed path-free Rust trust evidence', () => {
  assert.deepEqual(parseProjectTrustHarnessEvidence(line(expectedHarness)), expectedHarness);
  assert.equal(JSON.stringify(expectedHarness).includes('appRestart'), false);
  assert.equal(JSON.stringify(expectedHarness).includes('/'), false);
  assert.equal(Object.values(expectedHarness).every((value) => ['boolean', 'number'].includes(typeof value)), true);
});

test('captures the hostile fixture through the bounded identity-checked path', async () => {
  const fixturePath = resolve(root, 'tests/fixtures/hostile-project');
  const inventory = await captureFixture(fixturePath, { retainBytes: true, aclInspector });
  assert.equal(inventory.root, fixturePath);
  assert.ok(inventory.entries.length > 1);
  assert.ok(inventory.bytesTotal > 0);
  assert.equal(inventory.entries.some((entry) => entry.path.endsWith('-marker.log')), false);
  assert.equal(
    inventory.entries.filter((entry) => entry.kind === 'file')
      .every((entry) => Buffer.isBuffer(entry.bytes) && entry.bytes.length === entry.size),
    true,
  );
});

test('descriptor-bound fixture capture rejects an extended ACL', async () => {
  const created = await mkdtemp(join(tmpdir(), 'piui-a24-acl-fixture-'));
  const fixture = await realpath(created);
  try {
    await chmod(fixture, 0o700);
    await mkdir(resolve(fixture, 'nested'), { mode: 0o700 });
    await writeFile(resolve(fixture, 'nested/value'), 'fixed fixture', { mode: 0o600 });
    const acl = spawnSync('/bin/chmod', ['+a', 'everyone allow read', resolve(fixture, 'nested')], {
      stdio: 'ignore',
    });
    assert.equal(acl.status, 0);
    await assert.rejects(
      captureFixture(fixture, { aclInspector }),
      { message: 'Descriptor ACL inspection rejected' },
    );
  } finally {
    spawnSync('/bin/chmod', ['-N', resolve(fixture, 'nested')], { stdio: 'ignore' });
    await rm(created, { recursive: true, force: true });
  }
});

test('system ACL bootstrap rejects a tampered generated-helper substitute', async () => {
  const original = await readFile(nativeAclHelper);
  const before = await lstat(nativeAclHelper);
  const targetFd = openSync(
    aclWorkspace,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    await chmod(nativeAclHelper, 0o700);
    const helper = await open(nativeAclHelper, constants.O_RDWR | constants.O_NOFOLLOW);
    try {
      const tampered = Buffer.from([original[0] ^ 0xff]);
      const result = await helper.write(tampered, 0, tampered.length, 0);
      assert.equal(result.bytesWritten, tampered.length);
      await helper.sync();
    } finally {
      await helper.close();
    }
    await chmod(nativeAclHelper, 0o500);
    const after = await lstat(nativeAclHelper);
    assert.equal(after.dev, before.dev);
    assert.equal(after.ino, before.ino);
    assert.equal(after.size, before.size);
    const tamperedBytes = await readFile(nativeAclHelper);
    const substitute = Object.freeze({
      path: nativeAclHelper,
      dev: after.dev,
      ino: after.ino,
      size: after.size,
      mode: after.mode,
      uid: after.uid,
      gid: after.gid,
      sha256: createHash('sha256').update(tamperedBytes).digest('hex'),
    });
    assert.throws(
      () => assertDescriptorHasNoAcl(targetFd, substitute),
      { message: 'Descriptor ACL inspection rejected' },
    );
  } finally {
    await chmod(nativeAclHelper, 0o700);
    const helper = await open(nativeAclHelper, constants.O_RDWR | constants.O_NOFOLLOW);
    try {
      await helper.truncate(0);
      await helper.writeFile(original);
      await helper.sync();
    } finally {
      await helper.close();
    }
    await chmod(nativeAclHelper, 0o500);
    closeSync(targetFd);
  }
});

test('descriptor-bound removal deletes only the witnessed tree', async () => {
  const created = await mkdtemp(join(tmpdir(), 'piui-a24-remove-test-'));
  const parent = await realpath(created);
  const isolate = resolve(parent, 'isolate');
  const sibling = resolve(parent, 'sibling');
  let rootFd;
  let parentFd;
  try {
    await chmod(parent, 0o700);
    await mkdir(resolve(isolate, 'nested'), { recursive: true, mode: 0o700 });
    await writeFile(resolve(isolate, 'nested/value'), 'private output', { mode: 0o600 });
    await writeFile(sibling, 'retain', { mode: 0o600 });
    rootFd = openSync(
      isolate,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    parentFd = openSync(
      parent,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    const rootItem = fstatSync(rootFd);
    const parentItem = fstatSync(parentFd);
    removeDescriptorBoundTree({
      fd: rootFd,
      parentFd,
      dev: rootItem.dev,
      ino: rootItem.ino,
      parentDev: parentItem.dev,
      parentIno: parentItem.ino,
    }, aclInspector);
    await assert.rejects(lstat(isolate), { code: 'ENOENT' });
    assert.equal(await readFile(sibling, 'utf8'), 'retain');
  } finally {
    if (Number.isSafeInteger(rootFd)) closeSync(rootFd);
    if (Number.isSafeInteger(parentFd)) closeSync(parentFd);
    await rm(created, { recursive: true, force: true });
  }
});

test('rejects malformed, non-exact, unsafe, and false-pass Rust evidence', () => {
  rejected(Buffer.from(''));
  rejected(Buffer.from(`${JSON.stringify(expectedHarness)}\r\n`));
  rejected(Buffer.from(`${JSON.stringify(expectedHarness)}\nextra\n`));
  rejected(Buffer.from([0xff, 0x0a]));
  rejected(Buffer.alloc(65_537, 0x61));
  rejected(line({ ...expectedHarness, workspacePath: '/private/project' }));
  rejected(line({ ...expectedHarness, sidecarGenerationRestarted: false }));
  rejected(line({ ...expectedHarness, sidecarGenerationRestarts: '2' }));
  rejected(line({ ...expectedHarness, authoriseExecutions: 1 }));
  rejected(line({ ...expectedHarness, approvalRecordsAfterTrust: 1 }));
  rejected(line({ ...expectedHarness, rememberedApprovalScopes: 1 }));
  const missing = { ...expectedHarness };
  delete missing.fixtureInventoryUnchanged;
  rejected(line(missing));
});

test('formal evidence requires both JS runner and package-generated cleanup observations', () => {
  const formal = { ...expectedHarness, runnerIsolateRemoved: true, generatedOutputsRemoved: true };
  assert.deepEqual(parsePackagedTrustEvidence(line(formal)), formal);
  rejected(line({ ...formal, runnerIsolateRemoved: false }), parsePackagedTrustEvidence);
  rejected(line({ ...formal, generatedOutputsRemoved: false }), parsePackagedTrustEvidence);
  rejected(line({ ...formal, cleanupClaim: true }), parsePackagedTrustEvidence);
});

test('runtime sandbox is deny-default and allows only the exact harness and packaged Node executables', () => {
  const profile = projectTrustSandbox({
    appPath: '/Users/runner/accepted/PIUI.app',
    harnessPath: '/private/isolate/project-trust-harness',
    isolatePath: '/private/isolate',
    nodePath: '/Users/runner/accepted/PIUI.app/Contents/MacOS/piui-node',
  });
  assert.match(profile, /\(deny default\)/);
  assert.match(profile, /\(deny network\*\)/);
  assert.match(profile, /com\.apple\.securityd/);
  assert.match(profile, /com\.apple\.SecurityServer/);
  assert.match(profile, /\(allow process-fork\)/);
  assert.match(profile, /\(allow signal \(target same-sandbox\)\)/);
  assert.doesNotMatch(profile, /\(allow signal\)(?:\n|$)/);
  assert.match(profile, /\(allow file-read-data \(literal "\/"\)\)/);
  assert.match(profile, /\(allow file-read-metadata \(literal "\/private"\)\)/);
  assert.match(profile, /\(allow file-read-metadata \(literal "\/Users"\)\)/);
  assert.match(profile, /\(allow file-read-metadata \(literal "\/Users\/runner"\)\)/);
  assert.match(profile, /\(allow file-read-metadata \(literal "\/System\/Volumes\/Data"\)\)/);
  assert.doesNotMatch(profile, /\(allow file-read\* \(literal "\/"\)\)/);
  const executableRules = profile.match(/\(allow process-exec\*/g) ?? [];
  assert.equal(executableRules.length, 2);
  assert.match(profile, /literal "\/private\/isolate\/project-trust-harness"/);
  assert.match(profile, /literal "\/Users\/runner\/accepted\/PIUI\.app\/Contents\/MacOS\/piui-node"/);
  assert.doesNotMatch(profile, /allow default/);
  assert.doesNotMatch(profile, /hostile-project/);
});

test('asynchronous sandbox spawn failures reject through the normal cleanup path', async () => {
  const child = new EventEmitter();
  const spawned = waitForChildSpawn(child);
  const error = new Error('sandbox spawn rejected');
  queueMicrotask(() => child.emit('error', error));
  await assert.rejects(spawned, error);
});

test('package gate wires an exact A.24 mode into the same lease and removes both harnesses before inspection', async () => {
  const [packageSource, runnerSource, supervisorSource, packageJson] = await Promise.all([
    readFile(resolve(root, 'scripts/package-spike.mjs'), 'utf8'),
    readFile(resolve(root, 'scripts/run-packaged-trust-probe.mjs'), 'utf8'),
    readFile(resolve(root, 'src-tauri/src/supervisor/process.rs'), 'utf8'),
    readFile(resolve(root, 'package.json'), 'utf8'),
  ]);
  assert.match(packageSource, /--authoritative-a24/);
  assert.match(packageSource, /captureProjectTrustHarness\(sourceRoot\)/);
  assert.match(packageSource, /removeKnownTestHarnesses\(appPath\)/);
  assert.match(packageSource, /\['stream-harness', 'project-trust-harness'\]/);
  assert.match(packageSource, /executeAuthoritativeProjectTrustProbe\(accepted, projectTrustHarness/);
  assert.match(packageSource, /generatedOutputsRemoved: true/);
  assert.match(runnerSource, /revalidateBundle\(bundle\)/);
  assert.match(runnerSource, /const HARNESS_DEADLINE_MS = 6 \* 60_000/);
  assert.match(runnerSource, /runnerIsolateRemoved: true/);
  assert.match(runnerSource, /args: \[resolve\(root, 'scripts\/package-spike\.mjs'\), '--authoritative-a24'\]/);
  assert.doesNotMatch(runnerSource, /a21-candidate|\.cache\/a21/);
  assert.match(
    supervisorSource,
    /\.env_clear\(\)[\s\S]*?\.env\("HOME", &paths\.resource_root\)[\s\S]*?\.env\("CFFIXED_USER_HOME", &paths\.resource_root\)/,
  );
  assert.doesNotMatch(
    supervisorSource,
    /\.env\("HOME", std::env::var|\.env\("HOME", std::env::var_os/,
  );
  const scripts = JSON.parse(packageJson).scripts;
  assert.equal(scripts['spike:packaged:trust'], 'node scripts/run-packaged-trust-probe.mjs');
});
