import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  appendFile,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import {
  assertA28EnrolmentAuthorityConfig,
  assertA28RootLaunchConfig,
  canonicalA28Line,
  parseCanonicalA28Line,
  sha256A28,
} from '../../scripts/a28-witness/contract.mjs';
import {
  createA28ProvisioningInputTemplate,
  materialiseA28ProvisioningStage,
  measureA28AcceptedApplicationTree,
  stageA28Provisioning,
  stageA28ProvisioningTemplate,
  validateA28ProvisioningStage,
} from '../../scripts/a28-witness/stage-provisioning.mjs';

const repositoryRoot = resolve(import.meta.dirname, '../..');
const toolPath = resolve(
  repositoryRoot,
  'scripts/a28-witness/stage-provisioning.mjs',
);

async function privateRoot(label) {
  const created = await mkdtemp(join(tmpdir(), `piui-a28-${label}-`));
  const canonical = await realpath(created);
  await chmod(canonical, 0o700);
  return canonical;
}

async function writeExclusiveFile(path, bytes, mode) {
  await writeFile(path, bytes, { flag: 'wx', mode });
  await chmod(path, mode);
}

function machOFixture(marker) {
  const bytes = Buffer.alloc(8192, marker);
  Buffer.from('cffaedfe', 'hex').copy(bytes, 0);
  return bytes;
}

async function acceptedFixture(label = 'staging') {
  const root = await privateRoot(label);
  const acceptedRoot = resolve(root, 'accepted');
  await mkdir(acceptedRoot, { mode: 0o700 });
  await chmod(acceptedRoot, 0o700);
  const paths = {
    processInspector: resolve(acceptedRoot, 'a28-process-identity'),
    rootLauncher: resolve(acceptedRoot, 'a28-root-launcher-signed'),
    rootLauncherUnsigned: resolve(acceptedRoot, 'a28-root-launcher-unsigned'),
    rootVerifierNode: resolve(acceptedRoot, 'node'),
    witnessExecutableUnsigned: resolve(acceptedRoot, 'A28Witness-unsigned'),
  };
  let marker = 1;
  for (const path of Object.values(paths)) {
    await writeExclusiveFile(path, machOFixture(marker), 0o500);
    marker += 1;
  }

  const application = resolve(acceptedRoot, 'PIUI A28 VoiceOver Witness.app');
  const contents = resolve(application, 'Contents');
  const macos = resolve(contents, 'MacOS');
  await mkdir(macos, { recursive: true, mode: 0o700 });
  for (const directory of [application, contents, macos]) {
    await chmod(directory, 0o700);
  }
  const infoPlist = Buffer.from(
    '<?xml version="1.0"?><plist version="1.0"><dict></dict></plist>\n',
    'utf8',
  );
  const profileBytes = Buffer.from('fixture-developer-id-profile\n', 'utf8');
  await writeExclusiveFile(resolve(contents, 'Info.plist'), infoPlist, 0o400);
  await writeExclusiveFile(
    resolve(contents, 'embedded.provisionprofile'),
    profileBytes,
    0o400,
  );
  await writeExclusiveFile(
    resolve(macos, 'A28Witness'),
    machOFixture(9),
    0o500,
  );
  const applicationMeasurement = await measureA28AcceptedApplicationTree(
    application,
  );
  const template = structuredClone(await createA28ProvisioningInputTemplate());
  template.acceptedFiles = {
    processInspector: {
      path: paths.processInspector,
      sha256: sha256A28(await readFile(paths.processInspector)),
    },
    rootLauncher: {
      path: paths.rootLauncher,
      sha256: sha256A28(await readFile(paths.rootLauncher)),
    },
    rootLauncherUnsigned: {
      path: paths.rootLauncherUnsigned,
      sha256: sha256A28(await readFile(paths.rootLauncherUnsigned)),
    },
    rootVerifierNode: {
      path: paths.rootVerifierNode,
      sha256: sha256A28(await readFile(paths.rootVerifierNode)),
    },
    witnessApplication: {
      path: application,
      treeSha256: applicationMeasurement.treeSha256,
    },
    witnessExecutableUnsigned: {
      path: paths.witnessExecutableUnsigned,
      sha256: sha256A28(await readFile(paths.witnessExecutableUnsigned)),
    },
  };
  template.externalPins = {
    ...template.externalPins,
    cdHash: 'a'.repeat(40),
    designatedRequirement:
      'identifier "au.com.piui.a28-witness" and anchor apple generic and certificate leaf[subject.OU] = AB12CD34EF',
    hostDesignatedRequirement:
      'anchor apple generic and identifier "au.com.piui.desktop.architecture-test" and certificate leaf[subject.OU] = "ZZZZ000002"',
    hostTeamIdentifier: 'ZZZZ000002',
    minimumMacOSVersion: '14.0',
    profileName: 'PIUI A28 VoiceOver Witness',
    profileSha256: sha256A28(profileBytes),
    profileUuid: '12345678-1234-1234-1234-123456789ABC',
    reviewerIdentity: 'Avery Reviewer',
    rootLauncherCdHash: 'd'.repeat(40),
    rootLauncherDesignatedRequirement:
      'identifier "au.com.piui.a28-root-launcher" and anchor apple generic and certificate leaf[subject.OU] = AB12CD34EF',
    runnerBundleIdentifier: 'node',
    runnerDesignatedRequirement:
      'identifier node and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "HX7739G8FX"',
    runnerTeamIdentifier: 'HX7739G8FX',
    signingCertificateSha256: '6'.repeat(64),
    signingIdentity: 'Developer ID Application: Avery Reviewer (AB12CD34EF)',
    teamIdentifier: 'AB12CD34EF',
    voiceOverDesignatedRequirement:
      'identifier "com.apple.VoiceOver" and anchor apple',
    witnessGid: 20,
    witnessHomeDirectory: '/Users/example',
    witnessTargetDev: 16777233,
    witnessTargetIno: 4101,
    witnessUid: 501,
    witnessUsername: 'example',
  };
  return {
    application,
    input: template,
    paths,
    root,
  };
}

test('template is one canonical non-authoritative value with explicit pins', async () => {
  const progress = [];
  const envelope = await stageA28ProvisioningTemplate({
    progress: (message) => progress.push(message),
  });
  assert.equal(envelope.kind, 'a28-provisioning-input-template');
  assert.equal(envelope.authoritative, false);
  assert.equal(envelope.credentialsAccessed, false);
  assert.equal(envelope.installationPerformed, false);
  assert.equal(envelope.acceptedInputPathsIncluded, false);
  assert.equal(
    envelope.disclosureClassification,
    'private-operator-material-never-publish',
  );
  assert.deepEqual(envelope.requirements.requiredOwner, { gid: 0, uid: 0 });
  assert.deepEqual(envelope.requirements.metadataPolicy, {
    bsdFlags: 0,
    extendedAclEntries: 0,
    xattrs: [],
  });
  assert.equal(envelope.requirements.requiredAncestors.length, 3);
  assert.match(envelope.template.externalPins.signingIdentity, /^REQUIRED_/u);
  assert.match(
    envelope.template.acceptedFiles.witnessApplication.path,
    /^REQUIRED_/u,
  );
  assert.match(envelope.template.externalPins.sourceSha256, /^[0-9a-f]{64}$/u);
  assert.match(
    envelope.template.externalPins.repositoryToolSha256.verifierContract,
    /^[0-9a-f]{64}$/u,
  );
  assert.deepEqual(
    parseCanonicalA28Line(canonicalA28Line(envelope)),
    envelope,
  );
  assert.ok(progress.some((message) => message.includes('hashing')));
  await assert.rejects(
    materialiseA28ProvisioningStage(envelope.template),
    /still contains required placeholders/u,
  );
});

test('completed pins produce a canonical private plan without accepted input paths', async () => {
  const fixture = await acceptedFixture('positive');
  const progress = [];
  const plan = await stageA28Provisioning({
    input: fixture.input,
    progress: (message) => progress.push(message),
  });
  assert.equal(plan.kind, 'a28-provisioning-plan');
  assert.equal(plan.receipt.authoritative, false);
  assert.equal(plan.receipt.credentialsAccessed, false);
  assert.equal(plan.receipt.enrolmentPerformed, false);
  assert.equal(plan.receipt.acceptedInputPathsIncluded, false);
  assert.equal(
    plan.disclosureClassification,
    'private-operator-material-never-publish',
  );
  const validation = await validateA28ProvisioningStage({
    plan,
    progress: (message) => progress.push(message),
  });
  assert.equal(validation.validated, true);
  assert.equal(validation.authoritative, false);

  const authority = assertA28EnrolmentAuthorityConfig(plan.authority);
  for (const mode of ['checkpoint', 'enrol', 'verify']) {
    assertA28RootLaunchConfig(plan.launchConfigs[mode], authority, mode);
  }
  const manifest = plan.installationManifest;
  assert.equal(manifest.authoritative, false);
  assert.equal(manifest.credentialsAccessed, false);
  assert.equal(manifest.policyFinalisationRequired, true);
  assert.equal(manifest.acceptedInputPathsIncluded, false);
  assert.deepEqual(manifest.metadataPolicy, {
    bsdFlags: 0,
    extendedAclEntries: 0,
    xattrs: [],
  });
  assert.deepEqual(manifest.requiredAncestors.map(({ path }) => path), [
    '/Library',
    '/Library/Application Support',
    '/Library/Application Support/PIUI',
  ]);
  const library = manifest.requiredAncestors[0];
  const applicationSupport = manifest.requiredAncestors[1];
  const piui = manifest.requiredAncestors[2];
  assert.equal(Object.hasOwn(library, 'gid'), false);
  assert.equal(Object.hasOwn(applicationSupport, 'gid'), false);
  assert.deepEqual(library.allowedBsdFlags, [0, 0x00100000]);
  assert.equal(applicationSupport.extendedAclPolicy, 'no-write-granting-entries');
  assert.equal(
    piui.state,
    'pre-existing-valid-or-create-exclusive-during-app-preinstall',
  );
  assert.deepEqual(piui.createExclusive, { gid: 0, mode: 0o755, uid: 0 });
  assert.ok(manifest.targets.every(({ gid, uid }) => gid === 0 && uid === 0));
  assert.ok(manifest.targets.some(({ mode, path }) =>
    path.endsWith('/bin/node') && mode === 0o500));
  assert.ok(manifest.targets.some(({ mode, path }) =>
    path.endsWith('/policy-pin.json') && mode === 0o444));
  assert.ok(manifest.targets.some(({ expectedDev, expectedIno, path }) =>
    path.endsWith('/Contents/MacOS/A28Witness')
      && expectedDev === 16777233
      && expectedIno === 4101));
  assert.deepEqual(
    manifest.installationSequence.map(({ availability, ordinal }) => ({
      availability,
      ordinal,
    })),
    [
      { availability: 'preinstalled-validation', ordinal: 1 },
      { availability: 'installation', ordinal: 2 },
      { availability: 'post-enrolment', ordinal: 3 },
      { availability: 'post-enrolment-policy-finalisation', ordinal: 4 },
    ],
  );
  const applicationTargets = manifest.targets.filter(({ path }) =>
    path.includes('/app/PIUI A28 VoiceOver Witness.app'));
  assert.ok(applicationTargets.length >= 6);
  assert.ok(applicationTargets.every(({ availability }) =>
    availability === 'preinstalled-validation'));
  assert.equal(
    manifest.targets.find(({ path }) =>
      path === '/Library/Application Support/PIUI/A28Witness').availability,
    'preinstalled-validation',
  );
  const sourceDescriptors = manifest.targets
    .map(({ source }) => source)
    .filter(Boolean);
  assert.ok(sourceDescriptors.length > 8);
  assert.ok(sourceDescriptors.every((source) =>
    Object.keys(source).every((key) => ['relativePath', 'role'].includes(key))
      && (source.relativePath === undefined || !isAbsolute(source.relativePath))));
  assert.doesNotMatch(plan.recipe, /\bsudo\b/u);
  assert.match(plan.recipe, /private operator material and must never be published/u);
  assert.match(plan.recipe, /must not run as root/u);
  assert.match(plan.recipe, /Never overwrite or remove/u);
  assert.match(plan.recipe, /zero extended ACL\s+entries/u);

  const canonicalPlan = canonicalA28Line(plan);
  assert.deepEqual(parseCanonicalA28Line(canonicalPlan), plan);
  assert.equal(canonicalPlan.includes(fixture.root), false);
  assert.equal(canonicalPlan.includes(fixture.application), false);
  for (const sourcePath of Object.values(fixture.paths)) {
    assert.equal(canonicalPlan.includes(sourcePath), false);
  }
  assert.equal(canonicalPlan.includes('/Users/example'), true);
  assert.ok(progress.some((message) => message.includes('materialising')));
  assert.ok(progress.some((message) => message.includes('rehashing')));
});

test('stale source, profile and accepted-file pins fail before a plan is emitted', async () => {
  const fixture = await acceptedFixture('negative-pins');
  const staleSource = structuredClone(fixture.input);
  staleSource.externalPins.sourceSha256 = 'f'.repeat(64);
  await assert.rejects(
    materialiseA28ProvisioningStage(staleSource),
    /reviewed source digest is stale/u,
  );

  const wrongProfile = structuredClone(fixture.input);
  wrongProfile.externalPins.profileSha256 = 'e'.repeat(64);
  await assert.rejects(
    materialiseA28ProvisioningStage(wrongProfile),
    /embedded profile hash rejected/u,
  );

  const wrongBinary = structuredClone(fixture.input);
  wrongBinary.acceptedFiles.rootLauncher.sha256 = 'd'.repeat(64);
  await assert.rejects(
    materialiseA28ProvisioningStage(wrongBinary),
    /input file hash rejected/u,
  );
});

test('saved-plan validation rechecks repository pins and embedded-profile equality', async () => {
  const fixture = await acceptedFixture('saved-plan-pins');
  const plan = await stageA28Provisioning({
    input: fixture.input,
    progress: () => {},
  });

  const staleSource = structuredClone(plan);
  staleSource.acceptedInstanceRecord.externalPins.sourceSha256 = 'f'.repeat(64);
  await assert.rejects(
    validateA28ProvisioningStage({ plan: staleSource, progress: () => {} }),
    /reviewed source digest is stale/u,
  );

  const staleTool = structuredClone(plan);
  staleTool.acceptedInstanceRecord.externalPins.repositoryToolSha256
    .verifierContract = 'e'.repeat(64);
  await assert.rejects(
    validateA28ProvisioningStage({ plan: staleTool, progress: () => {} }),
    /reviewed verifierContract digest is stale/u,
  );

  const wrongProfile = structuredClone(plan);
  const application = wrongProfile.acceptedInstanceRecord
    .acceptedFiles.witnessApplication;
  const profile = application.tree.records.find(({ path }) =>
    path === 'Contents/embedded.provisionprofile');
  profile.sha256 = 'd'.repeat(64);
  application.profileSha256 = profile.sha256;
  application.treeSha256 = sha256A28(canonicalA28Line(application.tree));
  await assert.rejects(
    validateA28ProvisioningStage({ plan: wrongProfile, progress: () => {} }),
    /embedded profile hash rejected/u,
  );
});

test('saved-plan validation rejects unsafe modes and case-fold target collisions', async () => {
  const fixture = await acceptedFixture('saved-plan-tree');
  const plan = await stageA28Provisioning({
    input: fixture.input,
    progress: () => {},
  });

  const unsafeMode = structuredClone(plan);
  const unsafeApplication = unsafeMode.acceptedInstanceRecord
    .acceptedFiles.witnessApplication;
  unsafeApplication.tree.rootMode = 0o7777;
  unsafeApplication.treeSha256 = sha256A28(
    canonicalA28Line(unsafeApplication.tree),
  );
  await assert.rejects(
    validateA28ProvisioningStage({ plan: unsafeMode, progress: () => {} }),
    /provisioning stage rejected/u,
  );

  const caseCollision = structuredClone(plan);
  const collisionApplication = caseCollision.acceptedInstanceRecord
    .acceptedFiles.witnessApplication;
  const info = collisionApplication.tree.records.find(({ path }) =>
    path === 'Contents/Info.plist');
  collisionApplication.tree.records.push({
    ...info,
    path: 'Contents/info.plist',
  });
  collisionApplication.tree.records.sort((left, right) =>
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  collisionApplication.treeSha256 = sha256A28(
    canonicalA28Line(collisionApplication.tree),
  );
  await assert.rejects(
    validateA28ProvisioningStage({ plan: caseCollision, progress: () => {} }),
    /provisioning stage rejected/u,
  );

  for (const [leftName, rightName] of [
    ['Σ.txt', 'ς.txt'],
    ['ß.txt', 'ss.txt'],
    ['ﬃ.txt', 'ffi.txt'],
  ]) {
    const unicodeCollision = structuredClone(plan);
    const unicodeApplication = unicodeCollision.acceptedInstanceRecord
      .acceptedFiles.witnessApplication;
    unicodeApplication.tree.records.push(
      {
        mode: 0o400,
        path: `Contents/${leftName}`,
        sha256: 'a'.repeat(64),
        size: 1,
        type: 'file',
      },
      {
        mode: 0o400,
        path: `Contents/${rightName}`,
        sha256: 'b'.repeat(64),
        size: 1,
        type: 'file',
      },
    );
    unicodeApplication.tree.records.sort((left, right) =>
      left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
    unicodeApplication.treeSha256 = sha256A28(
      canonicalA28Line(unicodeApplication.tree),
    );
    await assert.rejects(
      validateA28ProvisioningStage({
        plan: unicodeCollision,
        progress: () => {},
      }),
      /provisioning stage rejected/u,
    );
  }

  const overlongTarget = structuredClone(plan);
  const overlongApplication = overlongTarget.acceptedInstanceRecord
    .acceptedFiles.witnessApplication;
  let parentPath = 'Contents';
  for (const marker of ['a', 'b', 'c', 'd', 'e']) {
    parentPath += `/${marker.repeat(220)}`;
    overlongApplication.tree.records.push({
      mode: 0o700,
      path: parentPath,
      type: 'directory',
    });
  }
  overlongApplication.tree.records.sort((left, right) =>
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  overlongApplication.treeSha256 = sha256A28(
    canonicalA28Line(overlongApplication.tree),
  );
  await assert.rejects(
    validateA28ProvisioningStage({ plan: overlongTarget, progress: () => {} }),
    /installation path rejected/u,
  );
});

test('accepted symlinks and forged plan members fail closed', async () => {
  const fixture = await acceptedFixture('symlink');
  const launcherLink = resolve(fixture.root, 'linked-root-launcher');
  await symlink(fixture.paths.rootLauncher, launcherLink);
  const linkedInput = structuredClone(fixture.input);
  linkedInput.acceptedFiles.rootLauncher.path = launcherLink;
  await assert.rejects(
    materialiseA28ProvisioningStage(linkedInput),
    /must use its canonical path/u,
  );

  const plan = await stageA28Provisioning({
    input: fixture.input,
    progress: () => {},
  });
  const forged = structuredClone(plan);
  forged.unexpected = true;
  await assert.rejects(
    validateA28ProvisioningStage({ plan: forged, progress: () => {} }),
    /plan schema rejected/u,
  );
});

test('validated plans do not retain authority over mutable measurement paths', async () => {
  const fixture = await acceptedFixture('path-independence');
  const plan = await stageA28Provisioning({
    input: fixture.input,
    progress: () => {},
  });
  await chmod(fixture.paths.rootLauncher, 0o600);
  await appendFile(fixture.paths.rootLauncher, Buffer.from('changed', 'utf8'));
  await chmod(fixture.paths.rootLauncher, 0o500);
  const validation = await validateA28ProvisioningStage({
    plan,
    progress: () => {},
  });
  assert.equal(validation.validated, true);
  await assert.rejects(
    stageA28Provisioning({ input: fixture.input, progress: () => {} }),
    /input file hash rejected/u,
  );
});

test('CLI template reports a working state and one canonical result', async () => {
  const root = await privateRoot('cli');
  const result = spawnSync(process.execPath, [
    toolPath,
    'template',
  ], {
    encoding: null,
    env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr.toString('utf8'));
  assert.equal(result.signal, null);
  assert.match(result.stderr.toString('utf8'), /^\[working\] A\.28 provisioning /u);
  const parsed = parseCanonicalA28Line(result.stdout);
  assert.equal(parsed.kind, 'a28-provisioning-input-template');
  assert.equal(parsed.authoritative, false);
  assert.equal(parsed.credentialsAccessed, false);
  assert.deepEqual(result.stdout, canonicalA28Line(parsed));

  const relative = spawnSync(process.execPath, [
    toolPath,
    'stage',
    '--input',
    'relative-input.json',
  ], {
    cwd: root,
    encoding: null,
    env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
    timeout: 30_000,
  });
  assert.equal(relative.status, 1);
  assert.equal(relative.stdout.length, 0);
  assert.match(relative.stderr.toString('utf8'), /input path rejected/u);
});

test('CLI stage and validate preserve canonical output and visible working states', async () => {
  const fixture = await acceptedFixture('cli-stage');
  const inputPath = resolve(fixture.root, 'accepted-instance-input.json');
  const planPath = resolve(fixture.root, 'provisioning-plan.json');
  await writeExclusiveFile(inputPath, canonicalA28Line(fixture.input), 0o400);
  const staged = spawnSync(process.execPath, [
    toolPath,
    'stage',
    '--input',
    inputPath,
  ], {
    encoding: null,
    env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
    timeout: 30_000,
  });
  assert.equal(staged.status, 0, staged.stderr.toString('utf8'));
  const stagedPlan = parseCanonicalA28Line(staged.stdout);
  assert.equal(stagedPlan.kind, 'a28-provisioning-plan');
  assert.equal(stagedPlan.receipt.authoritative, false);
  assert.deepEqual(staged.stdout, canonicalA28Line(stagedPlan));
  assert.ok(staged.stderr.toString('utf8').split('\n').filter(Boolean)
    .every((line) => line.startsWith('[working] A.28 provisioning ')));
  await writeExclusiveFile(planPath, staged.stdout, 0o400);

  const validated = spawnSync(process.execPath, [
    toolPath,
    'validate',
    '--input',
    planPath,
  ], {
    encoding: null,
    env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
    timeout: 30_000,
  });
  assert.equal(validated.status, 0, validated.stderr.toString('utf8'));
  const validation = parseCanonicalA28Line(validated.stdout);
  assert.equal(validation.validated, true);
  assert.deepEqual(validated.stdout, canonicalA28Line(validation));
  assert.ok(validated.stderr.toString('utf8').split('\n').filter(Boolean)
    .every((line) => line.startsWith('[working] A.28 provisioning ')));
});

test('application-tree, metadata, source-role and receipt tampering fail closed', async () => {
  const fixture = await acceptedFixture('tampering');
  const plan = await stageA28Provisioning({
    input: fixture.input,
    progress: () => {},
  });

  const missingInfo = structuredClone(plan);
  const application = missingInfo.acceptedInstanceRecord
    .acceptedFiles.witnessApplication;
  application.tree.records = application.tree.records.filter(({ path }) =>
    path !== 'Contents/Info.plist');
  application.treeSha256 = sha256A28(canonicalA28Line(application.tree));
  await assert.rejects(
    validateA28ProvisioningStage({ plan: missingInfo, progress: () => {} }),
    /provisioning stage rejected/u,
  );

  const changedMetadata = structuredClone(plan);
  changedMetadata.installationManifest.metadataPolicy.xattrs = [
    'com.apple.provenance',
  ];
  await assert.rejects(
    validateA28ProvisioningStage({ plan: changedMetadata, progress: () => {} }),
    /bytes or semantics rejected/u,
  );

  const changedAncestor = structuredClone(plan);
  changedAncestor.installationManifest.requiredAncestors[2].mode = 0o777;
  await assert.rejects(
    validateA28ProvisioningStage({ plan: changedAncestor, progress: () => {} }),
    /bytes or semantics rejected/u,
  );

  const pathfulSource = structuredClone(plan);
  const sourceTarget = pathfulSource.installationManifest.targets.find(
    ({ source }) => source?.role === 'rootLauncher',
  );
  sourceTarget.source = { path: fixture.paths.rootLauncher, role: 'rootLauncher' };
  await assert.rejects(
    validateA28ProvisioningStage({ plan: pathfulSource, progress: () => {} }),
    /bytes or semantics rejected/u,
  );

  const changedReceipt = structuredClone(plan);
  changedReceipt.receipt.recipeSha256 = 'f'.repeat(64);
  await assert.rejects(
    validateA28ProvisioningStage({ plan: changedReceipt, progress: () => {} }),
    /bytes or semantics rejected/u,
  );
});

test('root execution is rejected before template materialisation', () => {
  const toolUrl = pathToFileURL(toolPath).href;
  const result = spawnSync(process.execPath, [
    '--input-type=module',
    '--eval',
    `Object.defineProperty(process, 'getuid', { value: () => 0 });\n`
      + `Object.defineProperty(process, 'geteuid', { value: () => 0 });\n`
      + `const owner = await import(${JSON.stringify(toolUrl)});\n`
      + 'await owner.stageA28ProvisioningTemplate();\n',
  ], {
    encoding: 'utf8',
    env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
    timeout: 30_000,
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /must run as one non-root user/u);
  assert.equal(result.stdout, '');
});

test('plan owner contains no writes, elevation, installation or credential subprocess', async () => {
  const source = await readFile(toolPath, 'utf8');
  assert.doesNotMatch(source, /node:child_process|\bexec(?:File|Sync)?\b|\bspawn(?:Sync)?\b/u);
  assert.doesNotMatch(source, /\bsudo\b|\btccutil\b|SecItem|find-identity|codesign/u);
  assert.doesNotMatch(
    source,
    /\b(?:appendFile|chmod|copyFile|mkdir|rename|rm|unlink|writeFile)\b/u,
  );
  assert.doesNotMatch(source, /--output-root|--stage-root/u);
});
