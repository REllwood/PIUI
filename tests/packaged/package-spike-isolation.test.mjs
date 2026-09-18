import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { closeSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { architectureVariantDefinition } from '../../scripts/architecture-artifact-evidence.mjs';
import {
  A23_ACCEPTED_HOST_MODE_PHASE_PREFIXES,
  A23_ACCEPTED_HOST_MODE_PHASE_SUFFIXES,
  A23_MAINTENANCE_EXECUTION_FAILURE_CLASSES,
  A23_MAINTENANCE_FAILURE_CODES,
  A23_NATIVE_SHEET_FAILURE_CODES,
  A23_PROBE_PHASES,
  classifyA23MaintenanceExecutionFailure,
  parseA23NativeSheetFailure,
} from '../../scripts/run-packaged-credential-probe.mjs';
import {
  CODE_SIGNATURE_VERIFICATION_TEST_HOOK,
  assertAutomationHostSigningEvidence,
  automationHostSigningPolicy,
  automationSigningAuthoritySandbox,
  automationSigningKeychainPath,
  automationSigningSandbox as exactAutomationSigningSandbox,
  inspectAppleDevelopmentHost,
  verifyCodeSignatureBytesWithLease,
} from '../../scripts/automation-host-signing.mjs';
import { inventoryBundle } from './bundle-inspection.mjs';
import {
  buildSandboxFor,
  copyBundleToPrivateControl,
  captureDependencyTree,
  captureToolInputTree,
  openHeldPackageChildContext,
  parseControlledSidecarFinalisationPhase,
  parsePackageChildDescriptor,
  parseIsolatedChildFailurePhase,
  preparePinnedNodeTool,
  privateBuildControlChangeClass,
  readHeldPackageChildContext,
  relocateAcceptedBundle,
  sealBundle,
  signAutomationHost,
} from '../../scripts/package-spike.mjs';
import {
  APPLE_TOOLCHAIN_PATHS,
  appleToolchainBuildEnvironment,
  captureAppleToolchainAuthority,
  releaseAppleToolchainAuthority,
  revalidateAppleToolchainAuthority,
} from '../../scripts/apple-toolchain-trust.mjs';

function compileTrustedNativeFixture(arguments_, input) {
  const authority = captureAppleToolchainAuthority();
  try {
    const result = spawnSync(APPLE_TOOLCHAIN_PATHS.clang, [
      '--no-default-config',
      '-isysroot',
      APPLE_TOOLCHAIN_PATHS.sdk,
      ...arguments_,
    ], {
      encoding: 'utf8',
      env: {
        ...appleToolchainBuildEnvironment(),
        LANG: 'C',
        LC_ALL: 'C',
        PATH: `${APPLE_TOOLCHAIN_PATHS.bin}:/usr/bin:/bin`,
      },
      input,
      maxBuffer: 256 * 1024,
      timeout: 30_000,
    });
    revalidateAppleToolchainAuthority(authority);
    return result;
  } finally {
    releaseAppleToolchainAuthority(authority);
  }
}

const packageSource = await readFile(
  new URL('../../scripts/package-spike.mjs', import.meta.url),
  'utf8',
);
const stageSidecarSource = await readFile(
  new URL('../../scripts/stage-sidecar.mjs', import.meta.url),
  'utf8',
);
const descriptorAclSource = await readFile(
  new URL('../../scripts/descriptor-acl.mjs', import.meta.url),
  'utf8',
);
const exclusiveRenameSource = await readFile(
  new URL('../../scripts/exclusive-rename.mjs', import.meta.url),
  'utf8',
);
const appleToolchainSource = await readFile(
  new URL('../../scripts/apple-toolchain-trust.mjs', import.meta.url),
  'utf8',
);
const variantSandboxBasePhases = [
  'variant-frontend-build',
  'variant-native-build',
  'variant-type-verification',
];
const frozenInputDiagnosticPrefixes = [
  'variant-inspection-frozen-input-recheck',
  ...variantSandboxBasePhases.flatMap((phase) => [
    `${phase}-frozen-input-before`,
    `${phase}-frozen-input-after`,
  ]),
];
const frozenInputDiagnosticClasses = [
  'apple-toolchain',
  'dependencies',
  'openssl-authentication',
  'openssl-lease',
  'private-controls-aggregate',
  'private-controls-capture',
  'source',
  'tool-inputs',
  'witnesses',
];
const privateBuildControlLabels = [
  'build-controls',
  'cargo-home-controls',
  'private-pnpm-tools',
];
const privateBuildControlChangeClasses = [
  'entry-identity',
  'entry-permissions',
  'entry-set',
  'entry-size',
  'entry-timestamps',
  'malformed',
  'other',
  'root-identity',
  'root-permissions',
  'root-size',
  'root-timestamps',
];
const frozenInputDiagnosticPhases = frozenInputDiagnosticPrefixes.flatMap((prefix) => [
  ...frozenInputDiagnosticClasses.map((diagnosticClass) => (
    `${prefix}-${diagnosticClass}`
  )),
  ...privateBuildControlLabels.flatMap((label) => (
    privateBuildControlChangeClasses.map((changeClass) => (
      `${prefix}-private-controls-${label}-${changeClass}`
    ))
  )),
]);
const variantInspectionPhases = [
  'variant-inspection-approval-harness-capture',
  'variant-inspection-bundle-copy',
  'variant-inspection-bundle-discovery',
  'variant-inspection-bundle-inventory',
  'variant-inspection-bundle-revalidation',
  'variant-inspection-credential-harness-capture',
  'variant-inspection-credential-helper-identity',
  'variant-inspection-frozen-input-recheck',
  'variant-inspection-harness-removal',
  'variant-inspection-host-capture',
  'variant-inspection-host-signing',
  'variant-inspection-project-trust-capture',
  'variant-inspection-sealing',
  ...frozenInputDiagnosticPhases,
];
const sandboxFailureClasses = [
  'disk-capacity',
  'sandbox-denial',
  'subprocess-failure',
];
const sandboxClassifiedBasePhases = [
  'sidecar-deployment-preparation',
  ...variantSandboxBasePhases,
];
const variantProbePhases = A23_PROBE_PHASES.map((phase) => `variant-probe-a23-${phase}`);

test('classifies only allow-listed single-line frozen-child phases', () => {
  for (const phase of [
    'node-provisioning',
    'node-provisioning-disk-capacity',
    'node-provisioning-sandbox-denial',
    'node-provisioning-subprocess-failure',
    'sidecar-finalisation-a25-fixture',
    ...variantInspectionPhases,
    ...variantProbePhases,
    ...sandboxClassifiedBasePhases.flatMap((basePhase) => (
      sandboxFailureClasses.map((failureClass) => `${basePhase}-${failureClass}`)
    )),
  ]) {
    assert.equal(
      parseIsolatedChildFailurePhase(Buffer.from(
        `A.21 package gate failed [phase=${phase}]: redacted fixed failure\n`,
        'utf8',
      )),
      phase,
    );
  }
  for (const bytes of [
    Buffer.from('A.21 package gate failed [phase=hostile-phase]: failure\n', 'utf8'),
    Buffer.from('A.21 package gate failed [phase=sidecar-finalisation-complete]: failure\n', 'utf8'),
    Buffer.from('A.21 package gate failed [phase=node-provisioning]: first\nsecond\n', 'utf8'),
    Buffer.from('A.21 package gate failed [phase=node-provisioning]: failure\r\n', 'utf8'),
    Buffer.from('A.21 package gate failed [phase=variant-frontend-build-timeout]: failure\n', 'utf8'),
    Buffer.from('A.21 package gate failed [phase=variant-native-build-SANDBOX-DENIAL]: failure\n', 'utf8'),
    Buffer.from('arbitrary child diagnostics\n', 'utf8'),
  ]) {
    assert.equal(parseIsolatedChildFailurePhase(bytes), 'unclassified');
  }
  assert.equal(parseIsolatedChildFailurePhase('not bytes'), 'unclassified');
});

test('maps every closed A.23 probe milestone through both formal package paths', () => {
  assert.deepEqual(A23_PROBE_PHASES, [
    'accepted-host-creator-cleanup-proof',
    'accepted-host-creator-injected-failure',
    'accepted-host-final-cleanup',
    'accessibility-capture',
    'boundary-validation',
    'canary-scan',
    'candidate-launch',
    'candidate-ledger',
    'candidate-termination',
    'cleanup',
    'cleanup-candidate-termination',
    'cleanup-keychain',
    'cleanup-workspace',
    'evidence-finalisation',
    'helper-precheck-cleanup',
    'helper-precheck-cleanup-boundary-before',
    'helper-precheck-cleanup-execution',
    ...A23_MAINTENANCE_EXECUTION_FAILURE_CLASSES.map((failureClass) => (
      `helper-precheck-cleanup-execution-failure-${failureClass}`
    )),
    'helper-precheck-cleanup-failure-process',
    'helper-precheck-cleanup-identity-after',
    'helper-precheck-cleanup-output-validation',
    ...A23_MAINTENANCE_FAILURE_CODES.map((code) => (
      `helper-precheck-cleanup-failure-${code}`
    )),
    'lifecycle-result',
    'native-boundary-validation',
    'native-sheet-automation',
    ...A23_MAINTENANCE_EXECUTION_FAILURE_CLASSES.map((failureClass) => (
      `native-sheet-automation-execution-failure-${failureClass}`
    )),
    'native-sheet-automation-failure-process',
    ...A23_NATIVE_SHEET_FAILURE_CODES.map((code) => (
      `native-sheet-automation-failure-${code}`
    )),
    'native-sheet-automation-identity-after',
    'native-sheet-automation-output-validation',
    'transcript-validation',
    'workspace-preparation',
    ...A23_ACCEPTED_HOST_MODE_PHASE_PREFIXES.flatMap((prefix) => (
      A23_ACCEPTED_HOST_MODE_PHASE_SUFFIXES.map((suffix) => `${prefix}-${suffix}`)
    )),
  ]);
  assert.deepEqual(A23_ACCEPTED_HOST_MODE_PHASE_PREFIXES, [
    'accepted-host-creator-cleanup',
    'accepted-host-creator-inspection',
    'accepted-host-creator-seed',
    'accepted-host-final-cleanup',
    'accepted-host-final-inspection',
  ]);
  assert.deepEqual(A23_ACCEPTED_HOST_MODE_PHASE_SUFFIXES, [
    'boundary-before',
    'execution',
    ...A23_MAINTENANCE_EXECUTION_FAILURE_CLASSES.map((failureClass) => (
      `execution-failure-${failureClass}`
    )),
    'identity-after',
    'output-validation',
    ...A23_MAINTENANCE_FAILURE_CODES.map((code) => `failure-${code}`),
  ]);
  assert.equal(
    (packageSource.match(/onPhase: \(phase\) => setIsolatedChildFailurePhase\(`variant-probe-a23-\$\{phase\}`\)/gu) ?? []).length,
    2,
  );
  assert.match(
    packageSource,
    /setIsolatedChildFailurePhase\('variant-launch'\);[\s\S]*?setIsolatedChildFailurePhase\('variant-post-build-revalidation'\);[\s\S]*?setIsolatedChildFailurePhase\('variant-probe'\);[\s\S]*?setIsolatedChildFailurePhase\('variant-post-probe-revalidation'\);/u,
  );
});

test('classifies maintenance execution failures without reflecting diagnostics', () => {
  const label = 'A.23 maintenance fixture';
  assert.deepEqual(A23_MAINTENANCE_EXECUTION_FAILURE_CLASSES, [
    'deadline',
    'descendant-survivor',
    'identity-observation',
    'output-bound',
    'parent-cutoff',
    'start',
    'unclassified',
  ]);
  for (const [message, expected] of [
    [`${label} exceeded its deadline`, 'deadline'],
    [`${label} left a recorded descendant survivor`, 'descendant-survivor'],
    [`${label} descendant identity observation failed`, 'identity-observation'],
    [`${label} exceeded its output bound`, 'output-bound'],
    [`${label} was cut off by its parent`, 'parent-cutoff'],
    [`${label} could not be started`, 'start'],
  ]) {
    assert.equal(classifyA23MaintenanceExecutionFailure(new Error(message), label), expected);
  }
  assert.equal(
    classifyA23MaintenanceExecutionFailure(new Error(`${label} /private/secret`), label),
    'unclassified',
  );
  assert.equal(classifyA23MaintenanceExecutionFailure('failure', label), 'unclassified');
  assert.equal(classifyA23MaintenanceExecutionFailure(new Error('failure'), 'bad\nlabel'), 'unclassified');
});

test('classifies only fixed native-sheet AppleScript failures', () => {
  assert.deepEqual(A23_NATIVE_SHEET_FAILURE_CODES, [
    'accessibility-denied',
    'apple-events-denied',
    'application-unavailable',
    'automation-failed',
    'automation-privilege-denied',
    'event-timeout',
    'probe-button-unavailable',
    'process-identity-ambiguous',
    'process-identity-mismatch',
    'save-button-unavailable',
    'script-error',
    'test-value-button-unavailable',
    'ui-object-unavailable',
    'window-unavailable',
  ]);
  for (const code of [
    'probe-button-unavailable',
    'process-identity-ambiguous',
    'process-identity-mismatch',
    'save-button-unavailable',
    'test-value-button-unavailable',
    'window-unavailable',
  ]) {
    assert.equal(
      parseA23NativeSheetFailure(Buffer.from(
        `execution error: a23-${code} (-2700)\n`,
        'utf8',
      )),
      code,
    );
  }
  for (const [numericCode, expected] of [
    [-25_211, 'accessibility-denied'],
    [-1_743, 'apple-events-denied'],
    [-600, 'application-unavailable'],
    [-10_000, 'automation-failed'],
    [-10_004, 'automation-privilege-denied'],
    [-1_712, 'event-timeout'],
    [-2_700, 'script-error'],
    [-1_719, 'ui-object-unavailable'],
    [-1_728, 'ui-object-unavailable'],
  ]) {
    assert.equal(
      parseA23NativeSheetFailure(Buffer.from(`execution error: fixed (${numericCode})\n`)),
      expected,
    );
  }
  assert.equal(
    parseA23NativeSheetFailure(Buffer.from('execution error: /private/secret (-2700)\n')),
    'script-error',
  );
  assert.equal(parseA23NativeSheetFailure(Buffer.from('a23-window-unavailable\0')), undefined);
  assert.equal(parseA23NativeSheetFailure('a23-window-unavailable'), undefined);
});

test('classifies private build-control lease changes without reflecting paths', () => {
  const root = {
    ctimeNs: '1',
    dev: '1',
    gid: '20',
    ino: '2',
    kind: 'directory',
    mode: '16704',
    mtimeNs: '1',
    nlink: '2',
    path: '.',
    size: '64',
    uid: '501',
  };
  const child = {
    ...root,
    ino: '3',
    kind: 'file',
    mode: '33024',
    nlink: '1',
    path: 'config.toml',
    size: '32',
  };
  const item = (lease, leaseSha256 = 'a'.repeat(64)) => ({
    label: 'cargo-home-controls',
    leaseBytes: Buffer.from(`${JSON.stringify(lease)}\n`, 'utf8'),
    leaseSha256,
    root: '/private/cargo-home',
  });
  const expected = item([root, child]);
  assert.equal(privateBuildControlChangeClass(expected, item([root, child])), undefined);
  assert.equal(
    privateBuildControlChangeClass(expected, item([{ ...root, mtimeNs: '2' }, child], 'b'.repeat(64))),
    'root-timestamps',
  );
  assert.equal(
    privateBuildControlChangeClass(expected, item([root, { ...child, size: '33' }], 'b'.repeat(64))),
    'entry-size',
  );
  assert.equal(
    privateBuildControlChangeClass(expected, item([root], 'b'.repeat(64))),
    'entry-set',
  );
  assert.equal(
    privateBuildControlChangeClass(expected, { ...expected, label: 'build-controls' }),
    'other',
  );
});

test('classifies sandbox failures without widening frozen dependency writes', () => {
  const helper = packageSource.slice(
    packageSource.indexOf('function setSandboxFailureClassPhase'),
    packageSource.indexOf('function readControlledSidecarFinalisationPhase'),
  );
  assert.match(
    helper,
    /error\.message\.match\(\/\\\(\(disk-capacity\|sandbox-denial\|subprocess-failure\)\\\)\$\/u\)/u,
  );
  assert.doesNotMatch(helper, /diagnostics|stderr|stdout|toString/u);

  const variantBuilder = packageSource.slice(
    packageSource.indexOf('async function buildAndInspectVariant'),
    packageSource.indexOf('function equalArtifact'),
  );
  assert.match(
    variantBuilder,
    /\[vite, 'build', '--configLoader', 'runner'\]/u,
  );
  for (const phase of variantSandboxBasePhases) {
    assert.match(
      variantBuilder,
      new RegExp(
        `setIsolatedChildFailurePhase\\('${phase}'\\);[\\s\\S]*?try \\{[\\s\\S]*?await runSandboxed\\([\\s\\S]*?\\} catch \\(error\\) \\{\\s*setSandboxFailureClassPhase\\('${phase}', error\\);\\s*throw error;\\s*\\}`,
        'u',
      ),
    );
  }
  const sidecarStaging = packageSource.slice(
    packageSource.indexOf('async function stageSidecarControlled'),
    packageSource.indexOf('async function prepareVariantOverlays'),
  );
  assert.match(
    sidecarStaging,
    /setIsolatedChildFailurePhase\('sidecar-deployment-preparation'\);[\s\S]*?try \{[\s\S]*?await runSandboxed\([\s\S]*?\} catch \(error\) \{\s*setSandboxFailureClassPhase\('sidecar-deployment-preparation', error\);\s*throw error;\s*\}/u,
  );

  const sandboxConfiguration = packageSource.slice(
    packageSource.indexOf('function buildSandboxConfiguration'),
    packageSource.indexOf('async function assertFrozenBuildInputs'),
  );
  const generatedOutputRegistry = packageSource.slice(
    packageSource.indexOf('function generatedOutputsFor'),
    packageSource.indexOf('async function prepareGeneratedOutputs'),
  );
  assert.match(
    generatedOutputRegistry,
    /\{ kind: 'directory', path: resolve\(root, 'src-tauri\/gen'\) \}/u,
    'Tauri capability schemas must use the exact declared generated source directory',
  );
  assert.doesNotMatch(
    generatedOutputRegistry,
    /src-tauri\/gen\/schemas/u,
    'the generated root must own and clean the Tauri-created schemas parent',
  );
  const writableRoots = sandboxConfiguration.slice(
    sandboxConfiguration.indexOf('const writableRoots'),
    sandboxConfiguration.indexOf('const systemRuntimeRoots'),
  );
  assert.match(sandboxConfiguration, /const generatedDirectories = generated/u);
  assert.match(writableRoots, /\.\.\.generatedDirectories/u);
  assert.doesNotMatch(writableRoots, /resolve\(source, 'src-tauri'\)/u);
  assert.doesNotMatch(writableRoots, /node_modules/u);
});

test('classifies only sealed allow-listed sidecar finalisation progress records', () => {
  const expectedPhases = [
    'entry',
    'transaction-validation',
    'resource-preparation',
    'workspace-validation',
    'receipt-read',
    'finalisation-authority-acquisition',
    'receipt-validate-before-copy',
    'deployment-copy',
    'receipt-validate-after-copy',
    'importer-read',
    'a25-fixture',
    'sidecar-copy',
    'fixture-copy',
    'protocol-copy',
    'protocol-target-create',
    'protocol-dist-copy',
    'protocol-schema-copy',
    'protocol-package-write',
    'importer-package-write',
    'closure-prune',
    'closure-validation',
    'manifest-build',
    'candidate-seal',
    'publication-preparation',
    'prior-output-retire',
    'candidate-publish',
    'workspace-cleanup-phase-write',
    'workspace-cleanup-authority-validation',
    'workspace-cleanup-temporary-lease',
    'workspace-cleanup-workspace-lease',
    'workspace-cleanup-tree-unlock',
    'workspace-cleanup-post-unlock-lease-validation',
    'workspace-cleanup-inspector-capture',
    'workspace-cleanup-descriptor-bound-removal',
    'workspace-cleanup-path-absence',
    'workspace-cleanup-compiler-authority-release',
    'workspace-cleanup-descriptor-releases',
    'workspace-cleanup-final-progress-write',
    'complete',
  ];
  const declaredPhases = (source, declaration) => {
    const start = source.indexOf(`const ${declaration}`);
    const end = source.indexOf(']));', start);
    assert.notEqual(start, -1);
    assert.notEqual(end, -1);
    return [...source.slice(start, end).matchAll(/'([a-z0-9-]+)'/gu)]
      .map((match) => match[1]);
  };
  assert.deepEqual(
    declaredPhases(packageSource, 'CONTROLLED_SIDECAR_FINALISATION_PHASES'),
    expectedPhases,
  );
  assert.deepEqual(
    declaredPhases(stageSidecarSource, 'CONTROLLED_FINALISATION_PHASES'),
    expectedPhases,
  );
  for (const phase of expectedPhases) {
    assert.equal(
      parseControlledSidecarFinalisationPhase(Buffer.from(
        `PIUI_SIDECAR_FINALISATION_PHASE=${phase}\n`,
        'utf8',
      )),
      phase,
    );
    const mapped = parseIsolatedChildFailurePhase(Buffer.from(
      `A.21 package gate failed [phase=sidecar-finalisation-${phase}]: fixed failure\n`,
      'utf8',
    ));
    assert.equal(mapped, phase === 'complete'
      ? 'unclassified'
      : `sidecar-finalisation-${phase}`);
  }
  for (const bytes of [
    Buffer.from('PIUI_SIDECAR_FINALISATION_PHASE=hostile-phase\n', 'utf8'),
    Buffer.from('PIUI_SIDECAR_FINALISATION_PHASE=workspace-cleanup\n', 'utf8'),
    Buffer.from('PIUI_SIDECAR_FINALISATION_PHASE=manifest-build\nsecond\n', 'utf8'),
    Buffer.from('PIUI_SIDECAR_FINALISATION_PHASE=manifest-build\r\n', 'utf8'),
    Buffer.from('PIUI_SIDECAR_FINALISATION_PHASE=manifest-build\0\n', 'utf8'),
    Buffer.alloc(129, 0x61),
  ]) {
    assert.equal(parseControlledSidecarFinalisationPhase(bytes), 'unclassified');
  }
  assert.equal(parseControlledSidecarFinalisationPhase('not bytes'), 'unclassified');
});

test('canonicalises temporary aliases while requiring the exact canonical finalisation parent', () => {
  const controlledWorkspaceOwner = stageSidecarSource.slice(
    stageSidecarSource.indexOf('async function controlledWorkspace'),
    stageSidecarSource.indexOf('function sidecarInstallArguments'),
  );
  const finalisationLeaseOwner = stageSidecarSource.slice(
    stageSidecarSource.indexOf('async function acquireFinalisationRootLeases'),
    stageSidecarSource.indexOf('async function assertPathMissing'),
  );
  for (const owner of [controlledWorkspaceOwner, finalisationLeaseOwner]) {
    assert.match(owner, /await realpath\(resolve\(process\.env\.TMPDIR \|\| tmpdir\(\)\)\)/u);
    assert.doesNotMatch(owner, /temporary !== requestedTemporary/u);
  }
  assert.match(
    finalisationLeaseOwner,
    /const canonicalWorkspace = await realpath\(stagingWorkspace\);[\s\S]*?canonicalWorkspace !== stagingWorkspace \|\| dirname\(canonicalWorkspace\) !== temporary/u,
  );
  assert.match(
    controlledWorkspaceOwner,
    /const canonical = await realpath\(path\);[\s\S]*?canonical !== path[\s\S]*?dirname\(canonical\) !== temporary/u,
  );
});

test('packages only from a byte-verified isolated source copy', () => {
  assert.match(
    packageSource,
    /const isolatedSource = await createIsolatedBuildSource\(\s*bootstrapIsolate,\s*bootstrapTools,\s*cutoffs\.signal,\s*\)/u,
  );
  assert.match(packageSource, /await copyFrozenSourceFile\(repositoryRoot, cloneRoot, entry\)/u);
  assert.match(packageSource, /const copied = await snapshotArchitectureSource\(cloneRoot\)/u);
  assert.match(packageSource, /const finalRepository = await snapshotArchitectureSource\(repositoryRoot\)/u);
  assert.match(packageSource, /materialiseFrozenDependencies\(/u);
  assert.match(packageSource, /'--frozen-lockfile'/u);
  assert.match(packageSource, /'--ignore-scripts'/u);
  assert.match(packageSource, /'--config\.package-import-method=copy'/u);
  assert.doesNotMatch(packageSource, /installTrustedNodeModules/u);
  assert.doesNotMatch(packageSource, /resolve\(repositoryRoot, 'node_modules'\)/u);
  assert.match(packageSource, /await installPinnedNodeArchive\(cloneRoot, tools\)/u);
  assert.match(packageSource, /function dependencyInstallRoots\(cloneRoot\)/u);
  assert.match(packageSource, /Private dependency link escaped the frozen source/u);
  assert.match(packageSource, /const destination = resolve\(cache, pin\.filename\)/u);
  assert.match(packageSource, /if \(!copied\.equals\(bytes\) \|\| sha256Bytes\(copied\) !== pin\.digest\)/u);
  assert.match(packageSource, /cacheEntries\[0\] !== pin\.filename/u);
  assert.doesNotMatch(packageSource, /resolve\(repositoryRoot, '\.cache\/a21-package\.lock'\)/u);
  assert.match(packageSource, /const temporaryRoot = await realpath\(tmpdir\(\)\)/u);
  assert.match(packageSource, /architecturePackageGlobalLockPath\(repositoryRoot, temporaryRoot\)/u);
  assert.match(packageSource, /PIUI_GUARDED_PRODUCTION_GLOBAL_LOCK_PATH/u);
  assert.match(packageSource, /assertGuardedGlobalLockAuthority/u);
  assert.match(packageSource, /guardedPackageIsolateAuthority\?\.path\s*\?\?/u);
  assert.match(packageSource, /mkdtemp\(resolve\(temporaryRoot, prefix\)\)/u);
  assert.match(packageSource, /await realpath\(path\) !== path/u);
  assert.match(
    packageSource,
    /TMPDIR: `\$\{guardedProductionContext \? resolve\(buildPath, 'tmp'\) : temporaryRoot\}\/`/u,
  );
  assert.match(packageSource, /generated = generatedOutputsFor\(sourceRoot\)/u);
  assert.match(
    packageSource,
    /const outputs = generatedOutputsFor\(cloneRoot\);\s*await prepareGeneratedOutputs\(outputs\);[\s\S]*?await sealFrozenSourceInputs\(cloneRoot, beforeSourceSeal\)/u,
  );
  assert.match(packageSource, /\(deny default\)/u);
  assert.doesNotMatch(packageSource, /\(allow default\)/u);
  assert.match(packageSource, /await sealFrozenSourceInputs\(cloneRoot, beforeSourceSeal\)/u);
  assert.match(packageSource, /await sealDependencyTree\(dependencyRoot\)/u);
  assert.match(packageSource, /await assertFrozenBuildInputs\(\)/u);
  assert.match(packageSource, /PIUI_PACKAGE_CHILD_CONTEXT_FD/u);
  assert.match(packageSource, /PIUI_PACKAGE_CHILD_CONTEXT_LEASE_SHA256/u);
  assert.match(packageSource, /inheritedFds: Object\.freeze\(\[\s*\.\.\.bootstrapChild\.inheritedFds,\s*bootstrapChildContextLease\.fd/u);
});

test('binds every initial and repeat Node provisioning to one held output descriptor', () => {
  assert.equal(
    (packageSource.match(/await provisionPinnedNodeOutput\(/gu) ?? []).length,
    2,
  );
  const helper = packageSource.slice(
    packageSource.indexOf('async function provisionPinnedNodeOutput'),
    packageSource.indexOf('async function runSandboxed'),
  );
  assert.match(
    helper,
    /constants\.O_RDWR \| constants\.O_NOFOLLOW[\s\S]*?'--held-output-fd',[\s\S]*?String\(handle\.fd\)[\s\S]*?inheritedFds: \[handle\.fd\]/u,
  );
  assert.match(
    helper,
    /const beforeRead = await handle\.stat[\s\S]*?sha256HeldDescriptor\(handle, Number\(beforeRead\.size\)\)[\s\S]*?const afterRead = await handle\.stat[\s\S]*?sameBigIntState\(beforeRead, afterRead\)[\s\S]*?sameBigIntState\(afterRead, pathAfterRead\)/u,
  );
  assert.match(
    packageSource,
    /spawnSync\('\/usr\/bin\/bsdtar', \['-xOf', '-', member\][\s\S]*?input: archiveBytes[\s\S]*?sha256Bytes\(extracted\.stdout\) !== architectureToolchainPins\.node\.executableSha256/u,
  );
  const runtimeInspection = packageSource.slice(
    packageSource.indexOf('async function trustedNodeRuntimeFiles'),
    packageSource.indexOf('export async function resolveTrustedTools'),
  );
  assert.match(
    runtimeInspection,
    /const authority = captureAppleToolchainAuthority\(\);[\s\S]*?spawnSync\(APPLE_TOOLCHAIN_PATHS\.otool[\s\S]*?revalidateAppleToolchainAuthority\(authority\)[\s\S]*?releaseAppleToolchainAuthority\(authority\)/u,
  );
  assert.doesNotMatch(runtimeInspection, /\/usr\/bin\/otool/u);
});

test('binds the exact authenticated system OpenSSL config across parent, child and build sandboxes', () => {
  assert.match(
    packageSource,
    /systemOpenSslConfig: bootstrapTools\.systemOpenSslConfig/u,
  );
  assert.match(
    packageSource,
    /systemOpenSslConfig = assertSystemOpenSslConfigRecord\(context\.systemOpenSslConfig\)/u,
  );
  assert.match(
    packageSource,
    /canonicalArchitectureJson\(resolvedTools\.systemOpenSslConfig\)[\s\S]*?canonicalArchitectureJson\(childContext\.systemOpenSslConfig\)[\s\S]*?systemOpenSslConfigBaseline = resolvedTools\.systemOpenSslConfig/u,
  );
  assert.match(packageSource, /tools\.systemOpenSslConfig\.path/u);
  const buildSandboxOwner = packageSource.slice(
    packageSource.indexOf('function buildSandboxConfiguration'),
    packageSource.indexOf('async function assertFrozenBuildInputs'),
  );
  assert.doesNotMatch(buildSandboxOwner, /readableRoots:[\s\S]*?['"]\/private\/etc/u);
  const frozenInputOwner = packageSource.slice(
    packageSource.indexOf('async function assertFrozenBuildInputs'),
    packageSource.indexOf('async function runSandboxed'),
  );
  assert.match(frozenInputOwner, /await authenticateSystemOpenSslConfig\(\)/u);
  assert.match(
    frozenInputOwner,
    /canonicalArchitectureJson\(systemOpenSslConfig\)[\s\S]*?canonicalArchitectureJson\(systemOpenSslConfigBaseline\)/u,
  );
  const sandboxRunner = packageSource.slice(
    packageSource.indexOf('async function runSandboxed'),
    packageSource.indexOf('function setSandboxFailureClassPhase'),
  );
  assert.match(
    sandboxRunner,
    /await assertFrozenBuildInputs\(frozenInputFailurePhasePrefix === undefined[\s\S]*?`\$\{frozenInputFailurePhasePrefix\}-before`\);[\s\S]*?await runOwnedCommand\([\s\S]*?await assertFrozenBuildInputs\(frozenInputFailurePhasePrefix === undefined[\s\S]*?`\$\{frozenInputFailurePhasePrefix\}-after`\);/u,
  );
  assert.match(
    packageSource,
    /const authority = appleToolchainAuthority;\s*appleToolchainAuthority = undefined;\s*await attemptCleanup\(\(\) => revalidateAppleToolchainAuthority\(authority\)\);\s*await attemptCleanup\(\(\) => releaseAppleToolchainAuthority\(authority\)\);/u,
  );
  assert.match(
    packageSource,
    /await noForkToolProbe\(paths\);[\s\S]*?captureToolInputSet[\s\S]*?await noForkToolProbe\(paths\);/u,
  );
});

test('holds one authenticated sidecar transaction through install and receipt-bound finalisation', () => {
  const buildEnvironmentOwner = packageSource.slice(
    packageSource.indexOf('function makeBuildEnvironment'),
    packageSource.indexOf('function buildSandboxConfiguration'),
  );
  const buildSandboxOwner = packageSource.slice(
    packageSource.indexOf('function buildSandboxConfiguration'),
    packageSource.indexOf('async function assertFrozenBuildInputs'),
  );
  assert.match(
    buildSandboxOwner,
    /const systemExecutables = \[[\s\S]*?'\/usr\/bin\/ruby'[\s\S]*?\];/u,
    'controlled sidecar staging imports a descriptor ACL inspector backed by /usr/bin/ruby',
  );
  assert.doesNotMatch(
    buildSandboxOwner,
    /systemWritableFiles|writableFiles: unique\(\[[\s\S]*?'\/dev\/null'/u,
    'the ACL inspector must not widen the build sandbox to write to /dev/null',
  );
  assert.equal(
    (descriptorAclSource.match(/stdio: \['ignore', 'pipe', 'pipe',[\s\S]*?\],[\s\S]*?maxBuffer: MAX_INSPECTOR_OUTPUT_BYTES/gu) ?? []).length,
    2,
    'both ACL helper launches must use bounded output pipes',
  );
  assert.match(
    descriptorAclSource,
    /const ACL_INSPECTOR_TIMEOUT_MS = 30_000;[\s\S]*?timeout: ACL_INSPECTOR_TIMEOUT_MS/u,
    'the Ruby ACL inspector must retain a finite load-tolerant deadline',
  );
  assert.match(
    descriptorAclSource,
    /const TREE_REMOVAL_TIMEOUT_MS = 180_000;[\s\S]*?timeout: TREE_REMOVAL_TIMEOUT_MS/u,
    'the descriptor-bound remover must retain its finite deadline',
  );
  assert.match(
    exclusiveRenameSource,
    /APPLE_TOOLCHAIN_PATHS[\s\S]*?captureAppleToolchainAuthority[\s\S]*?revalidateAppleToolchainAuthority/u,
    'the helper compiler must use the held Command Line Tools authority',
  );
  assert.match(
    appleToolchainSource,
    /const ROOT = '\/Library\/Developer\/CommandLineTools';[\s\S]*?const BIN = `\$\{ROOT\}\/usr\/bin`;[\s\S]*?const SDK = `\$\{ROOT\}\/SDKs\/MacOSX26\.5\.sdk`;/u,
    'the native package build must use the root-owned non-writable Command Line Tools family',
  );
  assert.match(
    appleToolchainSource,
    /const TREE_INSPECTION_TIMEOUT_MS = 300_000;[\s\S]*?timeout: TREE_INSPECTION_TIMEOUT_MS/u,
    'the complete CLT ACL walk must keep a finite deadline that tolerates formal-suite load',
  );
  assert.match(
    buildEnvironmentOwner,
    /\.\.\.appleToolchainBuildEnvironment\(\)/u,
    'Rust and native build scripts must receive the exact authenticated compiler environment',
  );
  assert.match(
    buildEnvironmentOwner,
    /PATH: `\$\{dirname\(tools\.pnpmNode\)\}:\$\{tools\.cargoBin\}:\$\{APPLE_TOOLCHAIN_PATHS\.bin\}:\/usr\/bin:/u,
    'by-name Apple developer tools must resolve inside the authenticated CLT bin first',
  );
  assert.doesNotMatch(
    buildSandboxOwner,
    /\/usr\/bin\/(?:ar|cc|clang(?:\+\+)?|dsymutil|install_name_tool|ld|libtool|lipo|nm|otool|ranlib|strip|xcode-select|xcrun)/u,
  );
  assert.doesNotMatch(
    buildSandboxOwner,
    /executableRoots:[\s\S]*?(?:Applications\/Xcode|Library\/Developer\/CommandLineTools)/u,
  );
  const executableRootPolicy = buildSandboxOwner.slice(
    buildSandboxOwner.indexOf('executableRoots:'),
    buildSandboxOwner.indexOf('readableFiles:'),
  );
  assert.doesNotMatch(
    executableRootPolicy,
    /rustToolchain|closureRoot/u,
    'the authenticated Rust closure must never become an executable root',
  );
  assert.match(
    packageSource,
    /rustObjcopy: paths\.rustObjcopy/u,
    'the authenticated toolchain must project its exact target objcopy helper',
  );
  assert.match(
    buildSandboxOwner,
    /resolve\(tools\.cargoBin, 'rustdoc'\),\s*tools\.rustObjcopy,/u,
    'the build sandbox must grant only the authenticated target objcopy helper',
  );
  assert.doesNotMatch(
    buildSandboxOwner,
    /rust-lld|wasm-component-ld|gcc-ld/u,
    'unused Rust linker and Wasm helpers must remain outside process-exec authority',
  );
  assert.match(
    packageSource,
    /async function stageSidecarControlled[\s\S]*?const transactionLock = await acquireOwnedLock[\s\S]*?Protocol compilation for sidecar staging[\s\S]*?--prepare-controlled[\s\S]*?Controlled production sidecar dependency installation[\s\S]*?captureSidecarDeploymentReceipt\(deployment\)[\s\S]*?--finalise-controlled[\s\S]*?releaseOwnedLock\(transactionLock\)/u,
  );
  assert.match(
    packageSource,
    /'Controlled sidecar closure finalisation',\s*buildEnv,\s*15 \* 60_000,/u,
    'the full controlled finaliser must retain a finite load-tolerant deadline',
  );
  assert.match(
    packageSource,
    /String\(finalisationProgressFd\)[\s\S]*?inheritedFds: \[[\s\S]*?transactionLock\.fd,[\s\S]*?deploymentReceiptFd,[\s\S]*?finalisationProgressFd,[\s\S]*?\]/u,
  );
  assert.match(
    packageSource,
    /catch \(error\) \{[\s\S]*?readControlledSidecarFinalisationPhase[\s\S]*?setIsolatedChildFailurePhase\(`sidecar-finalisation-\$\{finalisationPhase\}`\)/u,
  );
  assert.match(
    packageSource,
    /readControlledSidecarFinalisationPhase\(finalisationProgressFd\) !== 'complete'/u,
  );
  assert.match(packageSource, /'--config\.package-import-method=copy'/u);
  assert.match(stageSidecarSource, /assertControlledLockDescriptor\(controlledLockFd\)/u);
  assert.match(
    stageSidecarSource,
    /readHeldSidecarDeploymentReceipt\([\s\S]*?await finaliseDeployment\(workspace, receipt\)/u,
  );
  assert.match(
    stageSidecarSource,
    /async function finaliseDeployment[\s\S]*?setControlledFinalisationPhase\('finalisation-authority-acquisition'\);\s*await acquireFinalisationRootLeases\(stagingWorkspace\);/u,
  );
  assert.match(
    stageSidecarSource,
    /assertControlledProgressDescriptor\(controlledProgressFd\)[\s\S]*?setControlledFinalisationPhase\('entry'\)/u,
  );
  assert.match(stageSidecarSource, /process\.argv\.length !== 8/u);
  assert.match(
    stageSidecarSource,
    /const descriptor = Number\(value\);\s*return descriptor <= 255 \? descriptor : undefined;/u,
  );
  for (const pair of [
    'controlledReceiptFd === controlledLockFd',
    'controlledProgressFd === controlledLockFd',
    'controlledProgressFd === controlledReceiptFd',
  ]) assert.ok(stageSidecarSource.includes(pair));
  assert.match(
    stageSidecarSource,
    /ftruncateSync\(controlledProgressFd, 0\)[\s\S]*?while \(offset < bytes\.length\)[\s\S]*?writeSync\([\s\S]*?fsyncSync\(controlledProgressFd\)[\s\S]*?const after = fstatSync\(controlledProgressFd\)/u,
  );
  assert.match(
    stageSidecarSource,
    /setCleanupPhase\('workspace-cleanup-phase-write'\)[\s\S]*?setCleanupPhase\('workspace-cleanup-authority-validation'\)[\s\S]*?cleanHeldWorkspaceMandatory\([\s\S]*?setCleanupPhase\('workspace-cleanup-compiler-authority-release'\)[\s\S]*?endExclusiveRenameCompilerSession\(compilerSession\)[\s\S]*?setCleanupPhase\('workspace-cleanup-descriptor-releases'\)[\s\S]*?setControlledFinalisationPhase\('workspace-cleanup-final-progress-write'\)[\s\S]*?setControlledFinalisationPhase\('complete'\)/u,
  );
  assert.match(
    stageSidecarSource,
    /async function prepareHelperWorkspaceParent\(\)[\s\S]*?exclusiveRenameCompilerSession = beginExclusiveRenameCompilerSession\(\);[\s\S]*?helperRootLease = await acquireHeldPathLease/u,
  );
  assert.equal(
    (stageSidecarSource.match(/compilerSession: exclusiveRenameCompilerSession/gu) ?? []).length,
    6,
  );
  assert.match(
    stageSidecarSource,
    /setControlledFinalisationPhase\('resource-preparation'\)[\s\S]*?setControlledFinalisationPhase\('workspace-validation'\)[\s\S]*?setControlledFinalisationPhase\('receipt-read'\)[\s\S]*?async function finaliseDeployment[\s\S]*?setControlledFinalisationPhase\('finalisation-authority-acquisition'\)[\s\S]*?acquireFinalisationRootLeases/u,
  );
  assert.equal(
    (stageSidecarSource.match(/setControlledFinalisationPhase\('resource-preparation'\)/gu) ?? []).length,
    1,
  );
  assert.match(
    stageSidecarSource,
    /async function cleanHeldWorkspaceMandatory[\s\S]*?setCleanupPhase\('workspace-cleanup-temporary-lease'\)[\s\S]*?assertHeldPathLease\(parentLease\)[\s\S]*?setCleanupPhase\('workspace-cleanup-workspace-lease'\)[\s\S]*?assertHeldPathLease\(workspaceLease[\s\S]*?setCleanupPhase\('workspace-cleanup-tree-unlock'\)[\s\S]*?makeTreeOwnerWritable[\s\S]*?setCleanupPhase\('workspace-cleanup-post-unlock-lease-validation'\)[\s\S]*?setCleanupPhase\('workspace-cleanup-inspector-capture'\)[\s\S]*?captureSystemDescriptorAclInspector\(\)[\s\S]*?setCleanupPhase\('workspace-cleanup-descriptor-bound-removal'\)[\s\S]*?removeDescriptorBoundTree[\s\S]*?setCleanupPhase\('workspace-cleanup-path-absence'\)[\s\S]*?pathExists/u,
  );
  assert.match(
    packageSource,
    /setCleanupPhase\('parent-descriptor-releases'\)[\s\S]*?closeSync\(finalisationProgressFd\)[\s\S]*?workspaceLease\?\.handle\.close\(\)[\s\S]*?setCleanupPhase\('parent-transaction-lock-release'\)[\s\S]*?releaseOwnedLock\(transactionLock\)/u,
  );
  assert.match(
    packageSource,
    /finalisationPhase !== 'unclassified' && finalisationPhase !== 'complete'/u,
  );
  assert.match(
    stageSidecarSource,
    /if \(controlledMode\) \{\s*assertControlledLockDescriptor\(controlledLockFd\);\s*\} else \{[\s\S]*?acquireOwnedLock\(lockPath/u,
  );
});

test('held child context rejects pathname swaps, same-inode ABA and descriptor substitution', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'piui-held-child-context.'));
  t.after(async () => rm(root, { force: true, recursive: true }));
  const bytes = Buffer.from(`${JSON.stringify({ payload: 'x'.repeat(256), schemaVersion: 1 })}\n`);

  const swapPath = resolve(root, 'swap-context.json');
  await writeFile(swapPath, bytes, { flag: 'wx', mode: 0o600 });
  const swapLease = openHeldPackageChildContext(swapPath, bytes);
  try {
    await rename(swapPath, resolve(root, 'held-original.json'));
    await writeFile(swapPath, bytes, { flag: 'wx', mode: 0o400 });
    assert.throws(() => readHeldPackageChildContext({
      fd: swapLease.fd,
      leaseSha256: swapLease.leaseSha256,
      path: swapPath,
      sha256: swapLease.sha256,
    }), /descriptor lease is invalid/u);
  } finally {
    closeSync(swapLease.fd);
  }

  const abaPath = resolve(root, 'aba-context.json');
  await writeFile(abaPath, bytes, { flag: 'wx', mode: 0o600 });
  const abaLease = openHeldPackageChildContext(abaPath, bytes);
  try {
    await chmod(abaPath, 0o600);
    await writeFile(abaPath, Buffer.from(bytes.map((byte, index) => index === 128 ? byte ^ 1 : byte)));
    await writeFile(abaPath, bytes);
    await chmod(abaPath, 0o400);
    assert.throws(() => readHeldPackageChildContext({
      fd: abaLease.fd,
      leaseSha256: abaLease.leaseSha256,
      path: abaPath,
      sha256: abaLease.sha256,
    }), /descriptor lease is invalid/u);
  } finally {
    closeSync(abaLease.fd);
  }

  const firstPath = resolve(root, 'first-context.json');
  const secondPath = resolve(root, 'second-context.json');
  await writeFile(firstPath, bytes, { flag: 'wx', mode: 0o600 });
  await writeFile(secondPath, bytes, { flag: 'wx', mode: 0o600 });
  const firstLease = openHeldPackageChildContext(firstPath, bytes);
  const secondLease = openHeldPackageChildContext(secondPath, bytes);
  try {
    assert.throws(() => readHeldPackageChildContext({
      fd: secondLease.fd,
      leaseSha256: firstLease.leaseSha256,
      path: firstPath,
      sha256: firstLease.sha256,
    }), /descriptor lease is invalid/u);
  } finally {
    closeSync(secondLease.fd);
    closeSync(firstLease.fd);
  }
});

test('child descriptor parser accepts the complete canonical inherited-FD range', () => {
  for (const fd of ['3', '10', '29', '255']) {
    assert.equal(parsePackageChildDescriptor(fd), Number(fd));
  }
  for (const fd of ['2', '03', '256', '999', '-1', '']) {
    assert.throws(() => parsePackageChildDescriptor(fd), /descriptor number is invalid/u);
  }
});

test('never persists or passes raw ambient private values into the frozen child', () => {
  assert.doesNotMatch(packageSource, /private-values\.json/u);
  assert.doesNotMatch(packageSource, /privateValuesPath|privateValuesSha256/u);
  assert.match(packageSource, /boundedAmbientPrivateValues\(process\.env, repositoryRoot\)/u);
  assert.match(packageSource, /assertBuffersExcludeValues\(\s*\[child\.stdout, child\.stderr\]/u);
  assert.match(packageSource, /PIUI_PACKAGE_SYNTHETIC_CANARIES/u);
  assert.match(packageSource, /PIUI_BUILD_SECRET_CANARY_A/u);
  assert.match(packageSource, /delete process\.env\.PIUI_PACKAGE_SYNTHETIC_CANARIES/u);
});

test('forwards only the exact validated A.28 transcript from the automation child', () => {
  const bootstrap = packageSource.slice(
    packageSource.indexOf('async function runBootstrap()'),
    packageSource.indexOf('function seatbeltPath'),
  );
  assert.match(
    bootstrap,
    /gateAutomation\s*\? createA28ProgressTranscriptForwarder/u,
  );
  assert.match(
    bootstrap,
    /stderrObserver: \(bytes\) => childProgress\.push\(bytes\)/u,
  );
  assert.match(
    bootstrap,
    /childProgress\.finish\(\{ allowEmpty: true \}\)/u,
  );
  assert.match(
    bootstrap,
    /!child\.stderr\.equals\(forwardedChildStderr\)/u,
  );
  assert.match(
    bootstrap,
    /\[working\] A\.28 package proof failed closed\./u,
  );
});

async function removeFixture(path) {
  try {
    const state = await lstat(path);
    if (state.isDirectory() && !state.isSymbolicLink()) {
      await chmod(path, 0o700);
      for (const entry of await readdir(path)) {
        await removeFixture(resolve(path, entry));
      }
    }
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  await rm(path, { force: true, recursive: true });
}

test('deny-default build sandbox permits only declared build paths', async (t) => {
  if (process.platform !== 'darwin') {
    t.skip('macOS sandbox-exec is required');
    return;
  }
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-build-sandbox-test.'));
  t.after(async () => removeFixture(root));
  const isolate = resolve(root, 'isolate');
  const source = resolve(isolate, 'source');
  const generated = resolve(source, 'dist');
  const tools = resolve(isolate, 'tools');
  const working = resolve(isolate, 'work');
  const aclHelperRoot = resolve(working, 'acl-helper-root');
  const controls = resolve(isolate, 'build-controls');
  const credentialControls = resolve(isolate, 'credential-cleanup-control');
  const bundleControls = resolve(isolate, 'accepted-bundle-private-control');
  const forbiddenHome = resolve(root, 'forbidden-home');
  const forbiddenTemporary = resolve(root, 'forbidden-tmp');
  for (const path of [
    source,
    generated,
    tools,
    working,
    aclHelperRoot,
    controls,
    credentialControls,
    bundleControls,
    forbiddenHome,
    forbiddenTemporary,
  ]) {
    await mkdir(path, { recursive: true, mode: 0o700 });
  }
  const pinnedNode = await preparePinnedNodeTool(isolate);
  const privateNode = pinnedNode.node;
  const input = resolve(source, 'input.txt');
  const nativeInput = resolve(source, 'native-probe.c');
  const overlay = resolve(controls, 'automation-twin.json');
  const undeclaredControl = resolve(controls, 'undeclared.json');
  const credentialHelper = resolve(credentialControls, 'credential-cleanup-harness');
  const privateBundleFile = resolve(bundleControls, 'accepted.app/Contents/private.txt');
  const homeSecret = resolve(forbiddenHome, 'secret.txt');
  const otherSecret = resolve(forbiddenTemporary, 'secret.txt');
  const descriptorRemovalParent = resolve(working, 'descriptor-removal');
  const descriptorRemovalRoot = resolve(descriptorRemovalParent, 'root');
  const descriptorRemovalSibling = resolve(descriptorRemovalParent, 'sibling.txt');
  await writeFile(input, 'input\n', { mode: 0o400 });
  await writeFile(nativeInput, 'int main(void) { return 0; }\n', { mode: 0o400 });
  await writeFile(
    overlay,
    '{"identifier":"au.com.piui.desktop.architecture-test"}\n',
    { mode: 0o400 },
  );
  await writeFile(undeclaredControl, '{"hostile":true}\n', { mode: 0o400 });
  await copyFile('/usr/bin/true', credentialHelper);
  await chmod(credentialHelper, 0o500);
  await chmod(credentialControls, 0o500);
  await mkdir(resolve(privateBundleFile, '..'), { recursive: true, mode: 0o700 });
  await writeFile(privateBundleFile, 'private-bundle\n', { mode: 0o400 });
  await writeFile(homeSecret, 'home-secret\n', { mode: 0o600 });
  await writeFile(otherSecret, 'other-secret\n', { mode: 0o600 });
  await mkdir(resolve(descriptorRemovalRoot, 'nested'), { recursive: true, mode: 0o700 });
  await writeFile(resolve(descriptorRemovalRoot, 'nested/payload.txt'), 'remove-me\n', { mode: 0o600 });
  await writeFile(descriptorRemovalSibling, 'retain-me\n', { mode: 0o600 });
  const repositoryRoot = fileURLToPath(new URL('../..', import.meta.url));
  const pnpmEntries = await readdir(resolve(repositoryRoot, 'node_modules/.pnpm'));
  const esbuildPackages = pnpmEntries.filter((name) => (
    /^@esbuild\+darwin-arm64@[^/]+$/u.test(name)
  ));
  assert.equal(esbuildPackages.length, 1);
  const dependencyExecutable = resolve(
    source,
    'node_modules/@esbuild/darwin-arm64/bin/esbuild',
  );
  await mkdir(resolve(dependencyExecutable, '..'), { recursive: true, mode: 0o700 });
  await copyFile(
    resolve(
      repositoryRoot,
      'node_modules/.pnpm',
      esbuildPackages[0],
      'node_modules/@esbuild/darwin-arm64/bin/esbuild',
    ),
    dependencyExecutable,
  );
  await chmod(dependencyExecutable, 0o500);
  const probe = resolve(source, 'probe.mjs');
  await writeFile(probe, `
    import { spawnSync } from 'node:child_process';
    import {
      closeSync,
      constants,
      lstatSync,
      mkdirSync,
      openSync,
      readFileSync,
      writeFileSync,
    } from 'node:fs';
    import { pathToFileURL } from 'node:url';
    const denied = (operation) => {
      try { operation(); return false; }
      catch (error) { return error?.code === 'EPERM' || error?.code === 'EACCES'; }
    };
    const shell = spawnSync('/bin/sh', ['-c', 'printf shell > "$1"', 'probe', process.env.SHELL_OUTPUT]);
    const dependencyTool = spawnSync(
      process.env.DEPENDENCY_EXECUTABLE,
      ['--version'],
      { encoding: 'utf8' },
    );
    const ruby = spawnSync('/usr/bin/ruby', [
      '--disable=gems,rubyopt,did_you_mean',
      '-e',
      'exit 0',
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    const succeeded = (child) => child.status === 0 && child.signal === null && !child.error;
    const canonicalCompile = spawnSync(process.env.CANONICAL_CLANG, [
      '-isysroot',
      process.env.SDKROOT,
      '-g',
      '-x',
      'c',
      '-c',
      process.env.NATIVE_INPUT,
      '-o', process.env.NATIVE_OBJECT,
    ], { encoding: 'utf8' });
    const canonicalLink = spawnSync(process.env.CANONICAL_CLANG, [
      '-isysroot', process.env.SDKROOT,
      '-Wl,-headerpad_max_install_names',
      process.env.NATIVE_OBJECT,
      '-o', process.env.NATIVE_EXECUTABLE,
    ], { encoding: 'utf8' });
    const canonicalArchive = spawnSync(process.env.CANONICAL_AR, [
      'rcs', process.env.NATIVE_ARCHIVE, process.env.NATIVE_OBJECT,
    ], { encoding: 'utf8' });
    const canonicalRanlib = spawnSync(process.env.CANONICAL_RANLIB, [
      process.env.NATIVE_ARCHIVE,
    ], { encoding: 'utf8' });
    const canonicalLibtool = spawnSync(process.env.CANONICAL_LIBTOOL, [
      '-static', '-o', process.env.NATIVE_LIBTOOL_ARCHIVE, process.env.NATIVE_OBJECT,
    ], { encoding: 'utf8' });
    const canonicalNm = spawnSync(process.env.CANONICAL_NM, [
      '-g', process.env.NATIVE_OBJECT,
    ], { encoding: 'utf8' });
    const canonicalInstallNameTool = spawnSync(process.env.CANONICAL_INSTALL_NAME_TOOL, [
      '-add_rpath', '@executable_path/../Frameworks', process.env.NATIVE_EXECUTABLE,
    ], { encoding: 'utf8' });
    const canonicalStrip = spawnSync(process.env.CANONICAL_STRIP, [
      '-x', process.env.NATIVE_EXECUTABLE,
    ], { encoding: 'utf8' });
    const canonicalOtool = spawnSync(process.env.CANONICAL_OTOOL, [
      '-L', process.env.NATIVE_EXECUTABLE,
    ], { encoding: 'utf8' });
    const canonicalLipo = spawnSync('lipo', [
      '-info', process.env.NATIVE_EXECUTABLE,
    ], { encoding: 'utf8' });
    const canonicalDsymutil = spawnSync(process.env.CANONICAL_DSYMUTIL, [
      process.env.NATIVE_EXECUTABLE, '-o', process.env.NATIVE_DSYM,
    ], { encoding: 'utf8' });
    const canonicalDeveloperToolStatuses = Object.fromEntries([
      ['compile', canonicalCompile],
      ['link', canonicalLink],
      ['ar', canonicalArchive],
      ['ranlib', canonicalRanlib],
      ['libtool', canonicalLibtool],
      ['nm', canonicalNm],
      ['install-name-tool', canonicalInstallNameTool],
      ['strip', canonicalStrip],
      ['otool', canonicalOtool],
      ['lipo-by-name', canonicalLipo],
      ['dsymutil', canonicalDsymutil],
    ].map(([name, child]) => [
      name,
      child.error?.code ?? child.signal ?? child.status,
    ]));
    const systemDeveloperShimsDenied = [
      '/usr/bin/ar',
      '/usr/bin/cc',
      '/usr/bin/clang',
      '/usr/bin/clang++',
      '/usr/bin/dsymutil',
      '/usr/bin/install_name_tool',
      '/usr/bin/ld',
      '/usr/bin/libtool',
      '/usr/bin/lipo',
      '/usr/bin/nm',
      '/usr/bin/otool',
      '/usr/bin/ranlib',
      '/usr/bin/strip',
      '/usr/bin/xcode-select',
      '/usr/bin/xcrun',
    ].every((tool) => {
      const child = spawnSync(tool, ['--version'], { encoding: 'utf8' });
      return child.status === null
        && child.signal === null
        && (child.error?.code === 'EPERM' || child.error?.code === 'EACCES');
    });
    let nativeObjectWorked = false;
    try {
      const nativeObject = lstatSync(process.env.NATIVE_OBJECT);
      const nativeBytes = readFileSync(process.env.NATIVE_OBJECT);
      nativeObjectWorked = nativeObject.isFile()
        && !nativeObject.isSymbolicLink()
        && nativeObject.nlink === 1
        && nativeObject.size === nativeBytes.length
        && nativeBytes.length > 16
        && nativeBytes.readUInt32LE(0) === 0xfeedfacf
        && nativeBytes.readUInt32LE(4) === 0x0100000c
        && nativeBytes.readUInt32LE(12) === 1;
    } catch {}
    let canonicalDeveloperToolsWorked = false;
    try {
      const archive = readFileSync(process.env.NATIVE_ARCHIVE);
      const libtoolArchive = readFileSync(process.env.NATIVE_LIBTOOL_ARCHIVE);
      const executable = readFileSync(process.env.NATIVE_EXECUTABLE);
      canonicalDeveloperToolsWorked = [
        canonicalCompile,
        canonicalLink,
        canonicalArchive,
        canonicalRanlib,
        canonicalLibtool,
        canonicalNm,
        canonicalInstallNameTool,
        canonicalStrip,
        canonicalOtool,
        canonicalLipo,
        canonicalDsymutil,
      ].every(succeeded)
        && archive.subarray(0, 8).toString('ascii') === '!<arch>\\n'
        && libtoolArchive.subarray(0, 8).toString('ascii') === '!<arch>\\n'
        && executable.readUInt32LE(0) === 0xfeedfacf
        && /\\b_main\\b/u.test(canonicalNm.stdout)
        && canonicalOtool.stdout.includes(process.env.NATIVE_EXECUTABLE)
        && /architecture: arm64\\n$/u.test(canonicalLipo.stdout)
        && lstatSync(process.env.NATIVE_DSYM).isDirectory();
    } catch {}
    const exclusiveRename = await import(
      pathToFileURL(process.env.EXCLUSIVE_RENAME_MODULE).href
    );
    const descriptorAcl = await import(
      pathToFileURL(process.env.DESCRIPTOR_ACL_MODULE).href
    );
    const aclHelperFd = openSync(
      process.env.ACL_HELPER_ROOT,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY,
    );
    let descriptorAclHelperWorked = false;
    try {
      const identity = lstatSync(process.env.ACL_HELPER_ROOT, { bigint: true });
      exclusiveRename.assertHeldPathHasNoAcl({
        fd: aclHelperFd,
        helperWorkspaceParent: process.env.ACL_HELPER_ROOT,
        identity,
        kind: 'mutable-directory',
        path: process.env.ACL_HELPER_ROOT,
      });
      descriptorAclHelperWorked = true;
    } finally {
      closeSync(aclHelperFd);
    }
    const descriptorRemovalParentFd = openSync(
      process.env.DESCRIPTOR_REMOVAL_PARENT,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY,
    );
    const descriptorRemovalRootFd = openSync(
      process.env.DESCRIPTOR_REMOVAL_ROOT,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY,
    );
    let descriptorAclRemovalWorked = false;
    try {
      const parentIdentity = lstatSync(process.env.DESCRIPTOR_REMOVAL_PARENT);
      const rootIdentity = lstatSync(process.env.DESCRIPTOR_REMOVAL_ROOT);
      const inspector = descriptorAcl.captureSystemDescriptorAclInspector();
      descriptorAcl.removeDescriptorBoundTree({
        dev: rootIdentity.dev,
        fd: descriptorRemovalRootFd,
        ino: rootIdentity.ino,
        parentDev: parentIdentity.dev,
        parentFd: descriptorRemovalParentFd,
        parentIno: parentIdentity.ino,
      }, inspector);
      let rootMissing = false;
      try {
        lstatSync(process.env.DESCRIPTOR_REMOVAL_ROOT);
      } catch (error) {
        rootMissing = error?.code === 'ENOENT';
      }
      descriptorAclRemovalWorked = rootMissing
        && readFileSync(process.env.DESCRIPTOR_REMOVAL_SIBLING, 'utf8') === 'retain-me\\n';
    } finally {
      closeSync(descriptorRemovalRootFd);
      closeSync(descriptorRemovalParentFd);
    }
    const result = {
      allowedRead: readFileSync(process.env.ALLOWED_INPUT, 'utf8') === 'input\\n',
      allowedWrite: (() => { writeFileSync(process.env.ALLOWED_OUTPUT, 'allowed\\n'); return true; })(),
      bundleControlReadDenied: denied(() => readFileSync(process.env.BUNDLE_CONTROL)),
      bundleControlWriteDenied: denied(() => writeFileSync(process.env.BUNDLE_CONTROL, 'mutated')),
      canonicalClangWorked: succeeded(canonicalCompile)
        && canonicalCompile.stdout === ''
        && canonicalCompile.stderr === ''
        && nativeObjectWorked,
      canonicalDeveloperToolStatuses,
      canonicalDeveloperToolsWorked,
      dependencyExecutableWorked: dependencyTool.status === 0
        && /^\\d+\\.\\d+\\.\\d+\\n$/u.test(dependencyTool.stdout),
      descriptorAclInspectorLoaded: true,
      descriptorAclHelperWorked,
      descriptorAclRemovalWorked,
      dependencyTempCreateDenied: denied(() => mkdirSync(process.env.DEPENDENCY_TEMP)),
      credentialControlReadDenied: denied(() => readFileSync(process.env.CREDENTIAL_HELPER)),
      credentialControlWriteDenied: denied(() => writeFileSync(process.env.CREDENTIAL_HELPER, 'mutated')),
      homeReadDenied: denied(() => readFileSync(process.env.HOME_SECRET)),
      homeWriteDenied: denied(() => writeFileSync(process.env.HOME_WRITE, 'denied', { flag: 'wx' })),
      otherReadDenied: denied(() => readFileSync(process.env.OTHER_SECRET)),
      otherWriteDenied: denied(() => writeFileSync(process.env.OTHER_WRITE, 'denied', { flag: 'wx' })),
      overlayRead: JSON.parse(readFileSync(process.env.OVERLAY_INPUT, 'utf8')).identifier
        === 'au.com.piui.desktop.architecture-test',
      rubyWorked: ruby.status === 0
        && ruby.signal === null
        && ruby.stdout.length === 0
        && ruby.stderr.length === 0,
      sourceWriteDenied: denied(() => writeFileSync(process.env.ALLOWED_INPUT, 'mutated')),
      shellWorked: shell.status === 0,
      undeclaredControlReadDenied: denied(() => readFileSync(process.env.UNDECLARED_CONTROL)),
      pinnedDeveloperDirectory: process.env.DEVELOPER_DIR
        === '/Library/Developer/CommandLineTools',
      pinnedCompilerEnvironment: process.env.CC === process.env.CANONICAL_CLANG
        && process.env.CC_aarch64_apple_darwin === process.env.CANONICAL_CLANG
        && process.env['CC_aarch64-apple-darwin'] === process.env.CANONICAL_CLANG
        && process.env.CXX === process.env.CANONICAL_CLANGXX
        && process.env.CXX_aarch64_apple_darwin === process.env.CANONICAL_CLANGXX
        && process.env['CXX_aarch64-apple-darwin'] === process.env.CANONICAL_CLANGXX
        && process.env.CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER === process.env.CANONICAL_CLANG
        && process.env.MACOSX_DEPLOYMENT_TARGET === '13.0',
      pinnedSdkRoot: process.env.SDKROOT
        === '/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk',
      pinnedToolPath: process.env.PATH.startsWith(
        '/Library/Developer/CommandLineTools/usr/bin:',
      ),
      systemDeveloperShimsDenied,
    };
    process.stdout.write(JSON.stringify(result) + '\\n');
  `, { mode: 0o400 });
  const commandLineTools = '/Library/Developer/CommandLineTools';
  const commandLineClang = `${commandLineTools}/usr/bin/clang`;
  const commandLineClangxx = `${commandLineTools}/usr/bin/clang++`;
  const commandLineSdk = `${commandLineTools}/SDKs/MacOSX26.5.sdk`;
  const commandLineToolExecutables = [
    `${commandLineTools}/usr/bin/ar`,
    commandLineClang,
    commandLineClangxx,
    `${commandLineTools}/usr/bin/dsymutil`,
    `${commandLineTools}/usr/bin/install_name_tool`,
    `${commandLineTools}/usr/bin/ld`,
    `${commandLineTools}/usr/bin/libtool`,
    `${commandLineTools}/usr/bin/lipo`,
    `${commandLineTools}/usr/bin/llvm-nm`,
    `${commandLineTools}/usr/bin/llvm-otool`,
    `${commandLineTools}/usr/bin/nm`,
    `${commandLineTools}/usr/bin/otool`,
    `${commandLineTools}/usr/bin/otool-classic`,
    `${commandLineTools}/usr/bin/ranlib`,
    `${commandLineTools}/usr/bin/strip`,
  ];
  const profile = buildSandboxFor({
    authenticatedCommand: privateNode,
    executableFiles: [
      dependencyExecutable,
      privateNode,
      '/bin/bash',
      '/bin/sh',
      '/usr/bin/ruby',
      ...commandLineToolExecutables,
    ],
    executableRoots: [aclHelperRoot],
    readableFiles: [...new Set([
      '/',
      '/Library',
      '/Library/Developer',
      privateNode,
      dependencyExecutable,
      '/bin/bash',
      '/bin/sh',
      '/usr/bin/ruby',
      ...commandLineToolExecutables,
      '/private/var/select/sh',
      overlay,
      '/dev/null',
      '/dev/fd/9',
      '/dev/random',
      '/dev/urandom',
      ...pinnedNode.nodeRuntimeFiles,
    ])],
    readableRoots: [
      source,
      tools,
      working,
      resolve(repositoryRoot, 'scripts'),
      commandLineTools,
      '/Library/Apple/System/Library',
      '/System/Library',
      '/usr/lib',
    ],
    writableFiles: ['/dev/fd/3', generated, working],
    writableRoots: [generated, working],
  });
  assert.match(profile, /\(deny default\)/u);
  assert.doesNotMatch(profile, /\(allow default\)/u);
  const result = spawnSync('/usr/bin/sandbox-exec', [
    '-p', profile, privateNode, probe,
  ], {
    encoding: 'utf8',
    env: {
      ALLOWED_INPUT: input,
      ALLOWED_OUTPUT: resolve(generated, 'output.txt'),
      ACL_HELPER_ROOT: aclHelperRoot,
      BUNDLE_CONTROL: privateBundleFile,
      CANONICAL_AR: `${commandLineTools}/usr/bin/ar`,
      CANONICAL_CLANG: commandLineClang,
      CANONICAL_CLANGXX: commandLineClangxx,
      CANONICAL_DSYMUTIL: `${commandLineTools}/usr/bin/dsymutil`,
      CANONICAL_INSTALL_NAME_TOOL: `${commandLineTools}/usr/bin/install_name_tool`,
      CANONICAL_LIBTOOL: `${commandLineTools}/usr/bin/libtool`,
      CANONICAL_LIPO: `${commandLineTools}/usr/bin/lipo`,
      CANONICAL_NM: `${commandLineTools}/usr/bin/nm`,
      CANONICAL_OTOOL: `${commandLineTools}/usr/bin/otool`,
      CANONICAL_RANLIB: `${commandLineTools}/usr/bin/ranlib`,
      CANONICAL_STRIP: `${commandLineTools}/usr/bin/strip`,
      CREDENTIAL_HELPER: credentialHelper,
      DEPENDENCY_EXECUTABLE: dependencyExecutable,
      DEPENDENCY_TEMP: resolve(source, 'node_modules/.vite-temp'),
      EXCLUSIVE_RENAME_MODULE: resolve(repositoryRoot, 'scripts/exclusive-rename.mjs'),
      HOME: forbiddenHome,
      HOME_SECRET: homeSecret,
      HOME_WRITE: resolve(forbiddenHome, 'write.txt'),
      DEVELOPER_DIR: commandLineTools,
      SDKROOT: commandLineSdk,
      CC: commandLineClang,
      CC_aarch64_apple_darwin: commandLineClang,
      'CC_aarch64-apple-darwin': commandLineClang,
      CXX: commandLineClangxx,
      CXX_aarch64_apple_darwin: commandLineClangxx,
      'CXX_aarch64-apple-darwin': commandLineClangxx,
      CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER: commandLineClang,
      DESCRIPTOR_ACL_MODULE: resolve(repositoryRoot, 'scripts/descriptor-acl.mjs'),
      DESCRIPTOR_REMOVAL_PARENT: descriptorRemovalParent,
      DESCRIPTOR_REMOVAL_ROOT: descriptorRemovalRoot,
      DESCRIPTOR_REMOVAL_SIBLING: descriptorRemovalSibling,
      MACOSX_DEPLOYMENT_TARGET: '13.0',
      NATIVE_INPUT: nativeInput,
      NATIVE_ARCHIVE: resolve(generated, 'native-probe.a'),
      NATIVE_DSYM: resolve(generated, 'native-probe.dSYM'),
      NATIVE_EXECUTABLE: resolve(generated, 'native-probe'),
      NATIVE_LIBTOOL_ARCHIVE: resolve(generated, 'native-probe-libtool.a'),
      NATIVE_OBJECT: resolve(generated, 'native-probe.o'),
      OTHER_SECRET: otherSecret,
      OTHER_WRITE: resolve(forbiddenTemporary, 'write.txt'),
      OVERLAY_INPUT: overlay,
      SHELL_OUTPUT: resolve(generated, 'shell.txt'),
      UNDECLARED_CONTROL: undeclaredControl,
      TMPDIR: `${working}/`,
      PATH: `${commandLineTools}/usr/bin:/usr/bin:/bin`,
    },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  assert.deepEqual(JSON.parse(result.stdout), {
    allowedRead: true,
    allowedWrite: true,
    bundleControlReadDenied: true,
    bundleControlWriteDenied: true,
    canonicalClangWorked: true,
    canonicalDeveloperToolStatuses: {
      ar: 0,
      compile: 0,
      dsymutil: 0,
      'install-name-tool': 0,
      libtool: 0,
      link: 0,
      'lipo-by-name': 0,
      nm: 0,
      otool: 0,
      ranlib: 0,
      strip: 0,
    },
    canonicalDeveloperToolsWorked: true,
    credentialControlReadDenied: true,
    credentialControlWriteDenied: true,
    dependencyExecutableWorked: true,
    dependencyTempCreateDenied: true,
    descriptorAclInspectorLoaded: true,
    descriptorAclHelperWorked: true,
    descriptorAclRemovalWorked: true,
    homeReadDenied: true,
    homeWriteDenied: true,
    otherReadDenied: true,
    otherWriteDenied: true,
    overlayRead: true,
    rubyWorked: true,
    sourceWriteDenied: true,
    shellWorked: true,
    undeclaredControlReadDenied: true,
    pinnedDeveloperDirectory: true,
    pinnedCompilerEnvironment: true,
    pinnedSdkRoot: true,
    pinnedToolPath: true,
    systemDeveloperShimsDenied: true,
  });
  await assert.rejects(lstat(resolve(forbiddenHome, 'write.txt')), { code: 'ENOENT' });
  await assert.rejects(lstat(resolve(forbiddenTemporary, 'write.txt')), { code: 'ENOENT' });
  await assert.rejects(lstat(resolve(source, 'node_modules/.vite-temp')), { code: 'ENOENT' });
  await assert.rejects(lstat(descriptorRemovalRoot), { code: 'ENOENT' });
  assert.equal(await readFile(descriptorRemovalSibling, 'utf8'), 'retain-me\n');
});

test('bundle sealing rejects links and forbidden xattrs without mutating external metadata', async (t) => {
  if (process.platform !== 'darwin') {
    t.skip('macOS sandbox-exec and xattr are required');
    return;
  }
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-bundle-seal-test.'));
  t.after(async () => removeFixture(root));
  const app = resolve(root, 'PIUI.app');
  const contents = resolve(app, 'Contents');
  const payload = resolve(contents, 'payload.txt');
  const outside = resolve(root, 'outside.txt');
  await mkdir(contents, { recursive: true, mode: 0o755 });
  await writeFile(payload, 'payload\n', { mode: 0o644 });
  await writeFile(outside, 'outside\n', { mode: 0o600 });
  assert.equal(spawnSync('/usr/bin/xattr', ['-w', 'au.com.piui.test', 'inside', payload]).status, 0);
  assert.equal(spawnSync('/usr/bin/xattr', ['-w', 'au.com.piui.test', 'outside', outside]).status, 0);
  await symlink(outside, resolve(contents, 'escape'));

  await assert.rejects(sealBundle(app), /Symlink forbidden|unsafe bundle entry/u);
  assert.equal(
    spawnSync('/usr/bin/xattr', ['-p', 'au.com.piui.test', outside], { encoding: 'utf8' }).stdout,
    'outside\n',
  );
  await rm(resolve(contents, 'escape'));
  await assert.rejects(sealBundle(app), /Extended attributes/u);
  assert.equal(
    spawnSync('/usr/bin/xattr', ['-p', 'au.com.piui.test', outside], { encoding: 'utf8' }).stdout,
    'outside\n',
  );
  assert.equal(spawnSync('/usr/bin/xattr', ['-c', payload]).status, 0);
  await sealBundle(app);
  assert.equal((await lstat(app)).mode & 0o777, 0o555);
  assert.equal((await lstat(contents)).mode & 0o777, 0o555);
  assert.equal((await lstat(payload)).mode & 0o777, 0o444);
  assert.equal(
    spawnSync('/usr/bin/xattr', ['-p', 'au.com.piui.test', outside], { encoding: 'utf8' }).stdout,
    'outside\n',
  );
});

test('automation signing rejects same-byte host pathname replacement while held', async (t) => {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-sign-host-test.'));
  t.after(async () => removeFixture(root));
  const signedApp = resolve(root, 'Signed.app');
  const signedRoot = resolve(signedApp, 'Contents/MacOS');
  const signedHost = resolve(signedRoot, 'piui');
  await mkdir(signedRoot, { recursive: true, mode: 0o700 });
  const compilation = compileTrustedNativeFixture(
    ['-x', 'c', '-', '-o', signedHost],
    'int main(void) { return 0; }\n',
  );
  assert.equal(compilation.status, 0, compilation.stderr);
  await chmod(signedHost, 0o500);
  await signAutomationHost(signedApp, {});
  const verifiedSignature = spawnSync('/usr/bin/codesign', ['--verify', signedHost], {
    encoding: 'utf8',
  });
  assert.equal(verifiedSignature.status, 0, verifiedSignature.stderr);

  const app = resolve(root, 'PIUI.app');
  const executableRoot = resolve(app, 'Contents/MacOS');
  const host = resolve(executableRoot, 'piui');
  const replacement = resolve(executableRoot, 'replacement');
  const bytes = Buffer.from('#!/bin/sh\nexit 0\n');
  await mkdir(executableRoot, { recursive: true, mode: 0o700 });
  await writeFile(host, bytes, { mode: 0o500 });
  await writeFile(replacement, bytes, { mode: 0o500 });
  await assert.rejects(
    signAutomationHost(app, {}, async () => {
      await rename(replacement, host);
    }),
    /signed host transition is invalid/u,
  );
});

test('automation signing produces two strictly verified identities that differ only in CMS material', async (t) => {
  if (process.platform !== 'darwin') {
    t.skip('Apple Development codesign is required');
    return;
  }
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-two-sign-host-test.'));
  t.after(async () => removeFixture(root));
  const original = resolve(root, 'original');
  const compilation = compileTrustedNativeFixture([
    '-arch',
    'arm64',
    '-x',
    'c',
    '-',
    '-o',
    original,
  ], 'int main(void) { return 0; }\n');
  assert.equal(compilation.status, 0, compilation.stderr);

  const createApp = async (name) => {
    const app = resolve(root, `${name}.app`);
    const host = resolve(app, 'Contents/MacOS/piui');
    await mkdir(resolve(host, '..'), { recursive: true, mode: 0o700 });
    await copyFile(original, host);
    await chmod(host, 0o500);
    return { app, host };
  };
  const first = await createApp('First');
  const second = await createApp('Second');
  assert.deepEqual(await readFile(first.host), await readFile(second.host));

  const profile = exactAutomationSigningSandbox(
    first.host,
    automationSigningKeychainPath(),
  );
  assert.match(profile, /\(deny network\*\)/u);
  assert.match(
    profile,
    new RegExp(`\\(literal "${automationSigningKeychainPath()}"\\)`, 'u'),
  );
  assert.deepEqual(
    [...profile.matchAll(/\(global-name "([^"]+)"\)/gu)].map((match) => match[1]),
    ['com.apple.SecurityServer', 'com.apple.trustd.agent'],
  );
  assert.doesNotMatch(profile, /\(allow network/u);
  assert.doesNotMatch(profile, /\(subpath "\/Users\//u);
  const authorityProfile = automationSigningAuthoritySandbox(
    automationSigningKeychainPath(),
  );
  assert.match(authorityProfile, /\(deny network\*\)/u);
  assert.deepEqual(
    [...authorityProfile.matchAll(/\(global-name "([^"]+)"\)/gu)]
      .map((match) => match[1]),
    ['com.apple.SecurityServer', 'com.apple.trustd.agent'],
  );
  assert.doesNotMatch(authorityProfile, /\(allow network/u);
  assert.doesNotMatch(authorityProfile, /\(subpath "\/Users\//u);

  const firstEvidence = await signAutomationHost(first.app, {});
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 1_100));
  const secondEvidence = await signAutomationHost(second.app, {});
  for (const evidence of [firstEvidence, secondEvidence]) {
    assert.equal(evidence.bundleIdentifier, automationHostSigningPolicy.bundleIdentifier);
    assert.equal(evidence.certificateSha1, automationHostSigningPolicy.certificateSha1);
    assert.equal(evidence.certificateSha256, automationHostSigningPolicy.certificateSha256);
    assert.equal(evidence.codeDirectoryFlags, 0);
    assert.equal(evidence.designatedRequirement, automationHostSigningPolicy.designatedRequirement);
    assert.equal(evidence.entitlements, 'none');
    assert.equal(evidence.signature, 'apple-development');
    assert.equal(evidence.teamIdentifier, automationHostSigningPolicy.teamIdentifier);
    assert.deepEqual(evidence.signatureSlots.map(({ slot }) => slot), [0, 2, 0x10000]);
  }

  const deterministicEvidence = (evidence) => {
    const {
      cmsBytes: _cmsBytes,
      cmsSha256: _cmsSha256,
      executableBytes: _executableBytes,
      executableSha256: _executableSha256,
      signatureContainerBytes: _signatureContainerBytes,
      signatureSlots,
      ...deterministic
    } = evidence;
    return {
      ...deterministic,
      signatureSlots: signatureSlots.slice(0, 2),
    };
  };
  assert.deepEqual(
    deterministicEvidence(firstEvidence),
    deterministicEvidence(secondEvidence),
  );
  assert.notEqual(firstEvidence.cmsSha256, secondEvidence.cmsSha256);
  assert.notEqual(firstEvidence.executableSha256, secondEvidence.executableSha256);
  for (const mutate of [
    (evidence) => { evidence.certificateSha256 = '0'.repeat(64); },
    (evidence) => { evidence.codeDirectoryFlags = 0x2; },
    (evidence) => { evidence.signatureSlots[1].size += 1; },
  ]) {
    const hostile = structuredClone(firstEvidence);
    mutate(hostile);
    assert.throws(
      () => assertAutomationHostSigningEvidence(hostile),
      /signing evidence is invalid/u,
    );
  }
});

async function createSignedVerificationHost(root, name) {
  const app = resolve(root, `${name}.app`);
  const host = resolve(app, 'Contents/MacOS/piui');
  await mkdir(resolve(host, '..'), { recursive: true, mode: 0o700 });
  const compilation = compileTrustedNativeFixture([
    '-arch',
    'arm64',
    '-x',
    'c',
    '-',
    '-o',
    host,
  ], 'int main(void) { return 0; }\n');
  assert.equal(compilation.status, 0, compilation.stderr);
  await chmod(host, 0o500);
  await signAutomationHost(app, {});
  return host;
}

test('Apple host inspection verifies and describes one held private clone', async (t) => {
  if (process.platform !== 'darwin') {
    t.skip('Apple Development codesign is required');
    return;
  }
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-sign-lease-test.'));
  t.after(async () => removeFixture(root));
  const host = await createSignedVerificationHost(root, 'Stable');
  const observations = [];
  const evidence = await inspectAppleDevelopmentHost(host, {
    verificationParent: root,
    [CODE_SIGNATURE_VERIFICATION_TEST_HOOK]: async (event) => {
      observations.push(event);
    },
  });
  assert.equal(
    evidence.executableSha256,
    createHash('sha256').update(await readFile(host)).digest('hex'),
  );
  assert.deepEqual(
    observations.map(({ call, phase }) => `${call}:${phase}`),
    [
      'verify:after-lease-before-command',
      'verify:after-command-before-lease',
      'describe:after-lease-before-command',
      'describe:after-command-before-lease',
    ],
  );
  assert.equal(new Set(observations.map(({ clonePath }) => clonePath)).size, 1);
});

test('held signature bytes are verified through separate held source and clone files', async (t) => {
  if (process.platform !== 'darwin') {
    t.skip('Apple Development codesign is required');
    return;
  }
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-byte-sign-lease-test.'));
  t.after(async () => removeFixture(root));
  const host = await createSignedVerificationHost(root, 'HeldBytes');
  const bytes = await readFile(host);
  const observations = [];
  const leased = await verifyCodeSignatureBytesWithLease(
    bytes,
    root,
    'held-byte-test',
    {
      [CODE_SIGNATURE_VERIFICATION_TEST_HOOK]: async (event) => {
        observations.push(event);
      },
    },
  );
  const digest = createHash('sha256').update(bytes).digest('hex');
  assert.equal(leased.verified.status, 0, leased.verified.stderr);
  assert.equal(leased.sourceSha256, digest);
  assert.equal(leased.cloneSha256, digest);
  assert.deepEqual(
    observations.map(({ call, phase }) => `${call}:${phase}`),
    ['verify:after-lease-before-command', 'verify:after-command-before-lease'],
  );
});

test('Apple host inspection rejects a valid decoy ABA swap around either codesign call', async (t) => {
  if (process.platform !== 'darwin') {
    t.skip('Apple Development codesign is required');
    return;
  }
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-sign-aba-test.'));
  t.after(async () => removeFixture(root));
  const host = await createSignedVerificationHost(root, 'Aba');
  for (const targetCall of ['verify', 'describe']) {
    const decoy = resolve(root, `${targetCall}-valid-signed-decoy`);
    await copyFile(host, decoy);
    await chmod(decoy, 0o500);
    let displaced;
    await assert.rejects(
      inspectAppleDevelopmentHost(host, {
        verificationParent: root,
        [CODE_SIGNATURE_VERIFICATION_TEST_HOOK]: async ({ call, clonePath, phase }) => {
          if (call !== targetCall) return;
          displaced = `${clonePath}.held-original`;
          if (phase === 'after-lease-before-command') {
            await rename(clonePath, displaced);
            await rename(decoy, clonePath);
          } else if (phase === 'after-command-before-lease') {
            await rename(clonePath, decoy);
            await rename(displaced, clonePath);
          }
        },
      }),
      /Code-signature verification parent identity changed/u,
    );
    assert.deepEqual(await readFile(decoy), await readFile(host));
  }
});

test('Apple host inspection rejects a restored verification-parent ABA swap', async (t) => {
  if (process.platform !== 'darwin') {
    t.skip('Apple Development codesign is required');
    return;
  }
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-sign-parent-aba-test.'));
  t.after(async () => removeFixture(root));
  const host = await createSignedVerificationHost(root, 'ParentAba');
  const verificationParent = resolve(root, 'verification-parent');
  const heldParent = resolve(root, 'verification-parent-held-original');
  const decoyParent = resolve(root, 'verification-parent-valid-decoy');
  await mkdir(verificationParent, { mode: 0o700 });
  let restored = false;
  let swapped = false;

  await assert.rejects(
    inspectAppleDevelopmentHost(host, {
      verificationParent,
      [CODE_SIGNATURE_VERIFICATION_TEST_HOOK]: async ({
        call,
        clonePath,
        phase,
        verificationDirectory,
      }) => {
        if (call !== 'verify') return;
        const verificationDirectoryName = basename(verificationDirectory);
        if (phase === 'after-lease-before-command') {
          await rename(verificationParent, heldParent);
          await mkdir(verificationParent, { mode: 0o700 });
          const decoyVerificationDirectory = resolve(
            verificationParent,
            verificationDirectoryName,
          );
          await mkdir(decoyVerificationDirectory, { mode: 0o700 });
          const cloneName = basename(clonePath);
          await copyFile(
            resolve(heldParent, verificationDirectoryName, cloneName),
            resolve(decoyVerificationDirectory, cloneName),
          );
          await chmod(resolve(decoyVerificationDirectory, cloneName), 0o500);
          swapped = true;
        } else if (phase === 'after-command-before-lease') {
          await rename(verificationParent, decoyParent);
          await rename(heldParent, verificationParent);
          restored = true;
        }
      },
    }),
    /Code-signature verification parent identity changed/u,
  );
  assert.equal(swapped, true);
  assert.equal(restored, true);
});

test('Apple host inspection rejects a one-way verification-clone mutation', async (t) => {
  if (process.platform !== 'darwin') {
    t.skip('Apple Development codesign is required');
    return;
  }
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-sign-mutation-test.'));
  t.after(async () => removeFixture(root));
  const host = await createSignedVerificationHost(root, 'Mutation');
  let mutated = false;
  await assert.rejects(
    inspectAppleDevelopmentHost(host, {
      verificationParent: root,
      [CODE_SIGNATURE_VERIFICATION_TEST_HOOK]: async ({ call, clonePath, phase }) => {
        if (!mutated && call === 'verify' && phase === 'after-lease-before-command') {
          mutated = true;
          await chmod(clonePath, 0o700);
          await writeFile(clonePath, Buffer.from('mutated\n'), { flag: 'a' });
        }
      },
    }),
    /Private code-signature verification file is invalid|Code-signature verification file path identity changed/u,
  );
  assert.equal(mutated, true);
});

test('private bundle capture copies held bytes to fresh inodes and rejects target replacement', async (t) => {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-private-bundle-copy.'));
  t.after(async () => removeFixture(root));
  const createCandidate = async (name) => {
    const app = resolve(root, name);
    await mkdir(resolve(app, 'Contents/MacOS'), { recursive: true, mode: 0o755 });
    await writeFile(resolve(app, 'Contents/Info.plist'), '<plist/>\n', { mode: 0o644 });
    await writeFile(resolve(app, 'Contents/MacOS/piui'), 'host-bytes\n', { mode: 0o755 });
    await writeFile(resolve(app, 'Contents/MacOS/piui-node'), 'node-bytes\n', { mode: 0o755 });
    return app;
  };

  const candidate = await createCandidate('candidate.app');
  const candidateHost = resolve(candidate, 'Contents/MacOS/piui');
  const candidateHostBefore = await lstat(candidateHost);
  const privateApp = await copyBundleToPrivateControl(
    candidate,
    resolve(root, 'control-one'),
  );
  const privateHost = resolve(privateApp, 'Contents/MacOS/piui');
  const privateHostState = await lstat(privateHost);
  assert.notEqual(privateHostState.ino, candidateHostBefore.ino);
  assert.equal(privateHostState.mode & 0o777, 0o700);
  assert.equal(
    (await lstat(candidateHost)).mode & 0o777,
    candidateHostBefore.mode & 0o777,
  );
  await writeFile(candidateHost, 'candidate-mutated\n');
  assert.equal(await readFile(privateHost, 'utf8'), 'host-bytes\n');

  const replacementCandidate = await createCandidate('replacement-candidate.app');
  let replaced = false;
  await assert.rejects(
    copyBundleToPrivateControl(
      replacementCandidate,
      resolve(root, 'control-two'),
      async ({ destination, entry }) => {
        if (replaced || entry.kind !== 'file') return;
        replaced = true;
        const target = resolve(destination, entry.path);
        const replacement = `${target}.replacement`;
        await copyFile(target, replacement);
        await chmod(replacement, (await lstat(target)).mode & 0o777);
        await rename(replacement, target);
      },
    ),
    /exact held-byte copy/u,
  );
  assert.equal(replaced, true);
});

test('accepted bundle relocation preserves inode and rejects a source pathname replacement', async (t) => {
  const relocationStart = packageSource.indexOf('export async function relocateAcceptedBundle');
  const relocationEnd = packageSource.indexOf('\nfunction packageInspectionEvidence', relocationStart);
  const relocationSource = packageSource.slice(relocationStart, relocationEnd);
  assert.match(
    relocationSource,
    /let sourceParent;[\s\S]*?let destinationParent;[\s\S]*?let source;[\s\S]*?try \{[\s\S]*?sourceParent = await openHeldPath[\s\S]*?destinationParent = await openHeldPath[\s\S]*?source = await openHeldPath/u,
  );
  assert.match(
    relocationSource,
    /for \(const lease of \[source, destinationParent, sourceParent\]\)[\s\S]*?try \{ await lease\.handle\.close\(\); \} catch \(error\) \{ closeFailures\.push\(error\); \}/u,
  );
  assert.match(
    relocationSource,
    /if \(primaryFailure && closeFailures\.length > 0\)[\s\S]*?\[primaryFailure, \.\.\.closeFailures\][\s\S]*?if \(primaryFailure\) throw primaryFailure;[\s\S]*?if \(closeFailures\.length > 0\)/u,
  );
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-bundle-relocate.'));
  t.after(async () => removeFixture(root));
  const createAccepted = async (name) => {
    const parent = resolve(root, `${name}-source`);
    const app = resolve(parent, `${name}.app`);
    await mkdir(resolve(app, 'Contents/MacOS'), { recursive: true, mode: 0o700 });
    await writeFile(resolve(app, 'Contents/MacOS/piui'), 'host\n', { mode: 0o500 });
    await writeFile(resolve(app, 'Contents/MacOS/piui-node'), 'node\n', { mode: 0o500 });
    await chmod(app, 0o555);
    const inventory = await inventoryBundle(app);
    const host = inventory.entries.find((entry) => entry.path === 'Contents/MacOS/piui');
    const node = inventory.entries.find((entry) => entry.path === 'Contents/MacOS/piui-node');
    return {
      app,
      bundle: Object.freeze({
        appPath: app,
        fingerprint: inventory.fingerprint,
        hostIdentity: Object.freeze({ dev: host.dev, ino: host.ino, bytes: host.bytes, sha256: host.sha256 }),
        hostPath: resolve(app, 'Contents/MacOS/piui'),
        nodeIdentity: Object.freeze({ dev: node.dev, ino: node.ino, bytes: node.bytes, sha256: node.sha256 }),
        nodePath: resolve(app, 'Contents/MacOS/piui-node'),
      }),
    };
  };

  const destinationParent = resolve(root, 'published');
  await mkdir(destinationParent, { mode: 0o700 });
  const accepted = await createAccepted('first');
  const before = await lstat(accepted.app);
  const destination = resolve(destinationParent, 'first.app');
  const relocated = await relocateAcceptedBundle(accepted.bundle, destination);
  const after = await lstat(destination);
  assert.equal(after.dev, before.dev);
  assert.equal(after.ino, before.ino);
  assert.equal(after.mode & 0o777, 0o555);
  assert.equal(relocated.appPath, destination);

  const attacked = await createAccepted('attacked');
  const attackedBefore = await lstat(attacked.app);
  const attackedDestination = resolve(destinationParent, 'attacked.app');
  const displaced = `${attacked.app}.displaced`;
  await assert.rejects(
    relocateAcceptedBundle(attacked.bundle, attackedDestination, async ({ source }) => {
      await rename(source, displaced);
      await mkdir(source, { mode: 0o700 });
    }),
  );
  const displacedAfter = await lstat(displaced);
  assert.equal(displacedAfter.dev, attackedBefore.dev);
  assert.equal(displacedAfter.ino, attackedBefore.ino);
  await assert.rejects(lstat(attackedDestination), { code: 'ENOENT' });

  const cleanupFault = await createAccepted('cleanup-fault');
  const cleanupFaultBefore = await lstat(cleanupFault.app);
  const cleanupFaultDestination = resolve(destinationParent, 'cleanup-fault.app');
  const helperTemporaryRoot = resolve(root, 'exclusive-helper-temporary');
  await mkdir(helperTemporaryRoot, { mode: 0o700 });
  const helperPrefix = `piui-exclusive-rename-${process.pid}-`;
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
  ].join('\n'), helperTemporaryRoot, helperPrefix], { stdio: 'ignore' });
  const attackerClose = new Promise((resolveExit, rejectExit) => {
    attacker.once('error', rejectExit);
    attacker.once('exit', resolveExit);
  });
  const previousTemporary = process.env.TMPDIR;
  process.env.TMPDIR = helperTemporaryRoot;
  let completionError;
  try {
    await relocateAcceptedBundle(cleanupFault.bundle, cleanupFaultDestination);
  } catch (error) {
    completionError = error;
  } finally {
    if (previousTemporary === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = previousTemporary;
  }
  const attackerExit = await attackerClose;
  assert.equal(attackerExit, 0);
  assert.equal(completionError?.operationCompleted, true);
  assert.equal(completionError?.receipt?.destination, cleanupFaultDestination);
  await assert.rejects(lstat(cleanupFault.app), { code: 'ENOENT' });
  const completedDestination = await lstat(cleanupFaultDestination);
  assert.equal(completedDestination.dev, cleanupFaultBefore.dev);
  assert.equal(completedDestination.ino, cleanupFaultBefore.ino);
  assert.equal(completedDestination.mode & 0o777, 0o555);
});

test('dependency witness rejects external links and detects same-byte replacement', async (t) => {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-dependency-witness.'));
  t.after(async () => removeFixture(root));
  const dependencyRoot = resolve(root, 'node_modules');
  const packageRoot = resolve(dependencyRoot, 'package');
  await mkdir(packageRoot, { recursive: true, mode: 0o700 });
  const dependencyFile = resolve(packageRoot, 'index.js');
  await writeFile(dependencyFile, 'export {};\n', { mode: 0o400 });
  const dependencyExecutable = resolve(packageRoot, 'tool');
  await writeFile(dependencyExecutable, '#!/bin/sh\nexit 0\n', { mode: 0o500 });
  await chmod(packageRoot, 0o500);
  await chmod(dependencyRoot, 0o500);
  const initial = await captureDependencyTree(root, dependencyRoot, { includeHashes: true });
  assert.deepEqual(initial.executables, [dependencyExecutable]);
  await chmod(dependencyRoot, 0o700);
  await chmod(packageRoot, 0o700);
  const replacement = resolve(packageRoot, 'replacement.js');
  await writeFile(replacement, 'export {};\n', { mode: 0o400 });
  await rename(replacement, dependencyFile);
  await chmod(packageRoot, 0o500);
  await chmod(dependencyRoot, 0o500);
  const replaced = await captureDependencyTree(root, dependencyRoot, { includeHashes: false });
  assert.notEqual(replaced.leaseSha256, initial.leaseSha256);

  const externalRoot = `${root}-outside`;
  await mkdir(externalRoot, { recursive: true, mode: 0o700 });
  t.after(async () => removeFixture(externalRoot));
  await chmod(dependencyRoot, 0o700);
  await symlink(externalRoot, resolve(dependencyRoot, 'escape'));
  await chmod(dependencyRoot, 0o500);
  await assert.rejects(
    captureDependencyTree(root, dependencyRoot, { includeHashes: true }),
    /escaped the frozen source/u,
  );
});

test('tool input witness detects mutation and same-inode ABA restoration', async (t) => {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'piui-tool-input-witness.'));
  t.after(async () => removeFixture(root));
  const input = resolve(root, 'tool');
  await writeFile(input, 'trusted-input\n', { mode: 0o400 });
  const initial = await captureToolInputTree(root, { includeHashes: true });
  await chmod(input, 0o600);
  await writeFile(input, 'hostile-data!\n');
  await chmod(input, 0o400);
  const mutated = await captureToolInputTree(root, { includeHashes: true });
  assert.notEqual(mutated.inventorySha256, initial.inventorySha256);
  assert.notEqual(mutated.leaseSha256, initial.leaseSha256);

  await chmod(input, 0o600);
  await writeFile(input, 'trusted-input\n');
  await chmod(input, 0o400);
  const restored = await captureToolInputTree(root, { includeHashes: true });
  assert.equal(restored.inventorySha256, initial.inventorySha256);
  assert.notEqual(restored.leaseSha256, initial.leaseSha256);
});

test('executes the formal package runner from the authenticated frozen source clone', () => {
  assert.match(packageSource, /resolve\(isolatedSource\.root, 'scripts\/package-spike\.mjs'\),\s*'--isolated-child',\s*requestedMode/u);
  assert.match(packageSource, /cwd: isolatedSource\.root/u);
  assert.match(packageSource, /runnerRoot !== expectedSourceRoot/u);
  assert.match(packageSource, /throw new Error\('Package child is not executing from the frozen source root'\)/u);
  assert.match(packageSource, /const snapshot = await snapshotArchitectureSource\(runnerRoot\)/u);
  assert.match(packageSource, /snapshot\.source\.digest !== sourceDigest/u);
  assert.match(packageSource, /sourceRoot = childContext\.sourceRoot/u);
  assert.match(packageSource, /projectTrustModule = await import\(pathToFileURL\(\s*resolve\(sourceRoot, 'scripts\/run-packaged-trust-probe\.mjs'\)/u);
});

test('publishes proof output only after the owned build isolate is absent', () => {
  const childCleanup = packageSource.indexOf('await removeOwnedTree(buildIsolate);');
  const childAbsent = packageSource.indexOf("await assertPathAbsent(buildIsolate, 'Owned build isolate');", childCleanup);
  const finalise = packageSource.indexOf('resultDocument = finaliseResultAfterCleanup(resultDocument);', childAbsent);
  const childOutput = packageSource.indexOf('canonicalArchitectureJson(resultDocument)', finalise);
  const parentAbsent = packageSource.indexOf("await assertPathAbsent(bootstrapIsolate, 'Owned build isolate');");
  const parentOutput = packageSource.lastIndexOf('canonicalArchitectureJson(childResult)');
  assert.ok(
    childCleanup >= 0
      && childAbsent > childCleanup
      && finalise > childAbsent
      && childOutput > finalise
      && parentAbsent > childOutput
      && parentOutput > parentAbsent,
  );
  assert.match(packageSource, /generatedOutputsRemoved: true/u);
  assert.match(packageSource, /if \(id === 'A\.27'\)[\s\S]*?lifecycleModule\.finaliseLifecycleEvidence\(evidence\)/u);
  assert.match(packageSource, /\(item\.mode & 0o777\) !== 0o700/u);
  assert.match(packageSource, /item\.dev !== expectedIdentity\.dev \|\| item\.ino !== expectedIdentity\.ino/u);
  assert.match(packageSource, /ensurePrivateEvidenceDirectory\(forge, 'evidence', 'A\.28 evidence directory'\)/u);
  assert.match(packageSource, /'architecture-accessibility',\s*'A\.28 accessibility evidence root'/u);
  assert.match(
    packageSource,
    /evidenceRootIdentity = await optionalAccessibilityEvidenceRoot\(\);[\s\S]*?createIsolatedBuildSource\(\s*bootstrapIsolate,/u,
  );
  assert.match(packageSource, /if \(evidenceRoot\) environment\.PIUI_A28_HUMAN_EVIDENCE_ROOT = evidenceRoot/u);
});

test('builds the exact controlled twins and removes every packaged harness before inspection', () => {
  assert.match(packageSource, /const definition = architectureVariantDefinition\(kind\)/u);
  assert.match(packageSource, /definition\.cargoFeatures\.join\(','\)/u);
  assert.match(packageSource, /variant: definition/u);
  assert.doesNotMatch(packageSource, /function variantDefinition/u);
  assert.deepEqual(
    architectureVariantDefinition('credential-twin').cargoFeatures,
    ['a23-credential-test'],
  );
  assert.deepEqual(
    architectureVariantDefinition('approval-twin').cargoFeatures,
    ['a25-approval-test'],
  );
  assert.deepEqual(
    architectureVariantDefinition('automation-twin').cargoFeatures,
    ['a27-lifecycle-test', 'architecture-test'],
  );
  assert.deepEqual(
    architectureVariantDefinition('automation-twin').frontend,
    {
      VITE_PIUI_A26_MARKDOWN_TEST: '1',
      VITE_PIUI_A27_LIFECYCLE_TEST: '1',
      VITE_PIUI_A28_ACCESSIBILITY_TEST: '1',
    },
  );
  assert.equal(
    architectureVariantDefinition('automation-twin').overlay.identifier,
    'au.com.piui.desktop.architecture-test',
  );

  const removeKnown = packageSource.indexOf('await removeKnownTestHarnesses(appPath);');
  const removeApproval = packageSource.indexOf("definition.postBuild.externalHarness === 'approval-matrix-harness'");
  const seal = packageSource.indexOf('await sealBundle(appPath);', removeKnown);
  const inspect = packageSource.indexOf('const accepted = await inspectBundle({', seal);
  assert.ok(removeKnown >= 0 && removeApproval > removeKnown && seal > removeApproval && inspect > seal);
  assert.match(packageSource, /resolve\(appPath, 'Contents\/MacOS', 'approval-matrix-harness'\)/u);
  assert.match(packageSource, /await unlink\(path\)/u);
});

test('binds the A.23 cleanup helper to frozen source, exact invocation and authenticated tools', () => {
  assert.match(packageSource, /createA23CleanupHelperIdentity\(\{/u);
  assert.match(
    packageSource,
    /buildArguments: tauriArguments,[\s\S]*?frozenSourceDigest: sourceDigest,[\s\S]*?helperSourceSha256: requiredFrozenSourceSha256\(\s*'src-tauri\/src\/bin\/credential-cleanup-harness\.rs'/u,
  );
  assert.match(
    packageSource,
    /formalBuildOverlayPath,[\s\S]*?tauriEntry,[\s\S]*?toolchainContextSha256: tools\.authenticatedToolchainContextSha256,[\s\S]*?toolchainReceiptSha256: tools\.authenticatedToolchainReceiptSha256/u,
  );
  assert.match(
    packageSource,
    /variantDefinitionSha256:\s*ARCHITECTURE_VARIANT_DEFINITION_SHA256\['credential-twin'\],[\s\S]*?variantOverlayPath: overlay/u,
  );
  assert.equal(
    (packageSource.match(/cleanupHelperIdentity: (?:twinBuild|build)\.credentialCleanupHelperIdentity/gu) ?? []).length,
    2,
  );
});

test('measures every gate twin against clean production and exact repeat builds', () => {
  assert.match(packageSource, /import \{ measureTwinDelta \} from '\.\/measured-twin-delta\.mjs'/u);
  assert.doesNotMatch(packageSource, /controlledTwinDeltaSha256/u);
  assert.match(
    packageSource,
    /async function rebuildFreshStageAnchors[\s\S]*?await resetGeneratedOutputs\(\);[\s\S]*?Fresh pinned Node provisioning[\s\S]*?await stageSidecarControlled\(tools, buildEnv\);[\s\S]*?equalStageAnchors\(referenceAnchors, fresh\)/u,
  );
  assert.match(packageSource, /const repeatAutomationBuild = await buildAndInspectVariant\(/u);
  assert.match(packageSource, /const repeatTwinBuild = await buildAndInspectVariant\(/u);
  assert.match(packageSource, /captureProbeHarness: false/u);
  assert.match(
    packageSource,
    /const preSignHostBytes = await readTrustedRegularFile\([\s\S]*?definition\.postBuild\.hostSigning === 'apple-development'[\s\S]*?await signAutomationHost/u,
  );
  assert.match(
    packageSource,
    /measureTwinDelta\(\{[\s\S]*?productionPreSignHostBytes: productionBuild\.preSignHostBytes,[\s\S]*?twinPreSignHostBytes: automationBuild\.preSignHostBytes,[\s\S]*?twinRepeatPreSignHostBytes: repeatAutomationBuild\.preSignHostBytes/u,
  );
  assert.match(
    packageSource,
    /measureTwinDelta\(\{[\s\S]*?twinPreSignHostBytes: twinBuild\.preSignHostBytes,[\s\S]*?twinRepeatPreSignHostBytes: repeatTwinBuild\.preSignHostBytes/u,
  );
  assert.match(packageSource, /const deltaSha256 = measuredDelta\.sha256/u);
  assert.ok((packageSource.match(/\n\s*measuredDelta,\n/gu) ?? []).length >= 2);
  assert.match(
    packageSource,
    /else if \(gateCredential \|\| gateApproval\)[\s\S]*?assertExactProductionArtifact\(localProductionArtifact, receivedProductionArtifact\)/u,
  );
});

test('wires individual and append-only architecture proof modes without skipping A.27', () => {
  for (const argument of [
    '--authoritative-a26',
    '--authoritative-a27',
    '--authoritative-a28',
    '--architecture-gate-production',
    '--architecture-gate-credential',
    '--architecture-gate-approval',
    '--architecture-gate-automation',
  ]) assert.match(packageSource, new RegExp(argument, 'u'));
  assert.match(packageSource, /executeAuthoritativeMarkdownProbe/u);
  assert.match(packageSource, /executeAuthoritativeAccessibilityProbe/u);
  assert.match(packageSource, /executeRequiredLifecycleProbe/u);
  assert.match(packageSource, /resolve\(sourceRoot, 'scripts\/run-packaged-lifecycle-probe\.mjs'\)/u);
  assert.match(packageSource, /typeof lifecycleModule\.executeAuthoritativeLifecycleProbe !== 'function'/u);
  assert.match(packageSource, /typeof lifecycleModule\.finaliseLifecycleEvidence !== 'function'/u);
  assert.match(packageSource, /throw new Error\('A\.27 packaged lifecycle executor is unavailable'\)/u);
  assert.match(packageSource, /canonicalArchitectureJson\(resultDocument\)/u);
});
