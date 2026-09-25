import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, closeSync, constants, fchmodSync, fstatSync, lstatSync, mkdirSync, openSync, readSync, writeFileSync } from 'node:fs';
import { chmod, lstat, mkdtemp, open as openFile, readFile, readdir, readlink, realpath, rm, unlink } from 'node:fs/promises';
import { arch, homedir, platform, tmpdir } from 'node:os';
import { basename, dirname, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  captureStageAnchors,
  inspectBundle,
  inventoryBundle,
  revalidateBundle,
} from '../tests/packaged/bundle-inspection.mjs';
import {
  architectureArtifactFromBundle,
  architectureVariantDefinition,
} from './architecture-artifact-evidence.mjs';
import { measureTwinDelta } from './measured-twin-delta.mjs';
import {
  assertAutomationSigningAuthorityUnchanged,
  authenticateAutomationSigningAuthority,
  automationSigningArguments,
  automationSigningKeychainPath,
  automationSigningSandbox as authenticatedAutomationSigningSandbox,
  inspectAppleDevelopmentHost,
} from './automation-host-signing.mjs';
import {
  ARCHITECTURE_VARIANT_DEFINITION_SHA256,
  assertArchitectureArtifact,
  canonicalArchitectureJson,
  sha256Bytes,
} from './architecture-gate-schema.mjs';
import {
  assertArchitectureProofBatch,
  createArchitectureProofEnvelope,
} from './architecture-proof-batch.mjs';
import {
  equalArchitectureSourceLease,
  snapshotArchitectureSource,
} from './architecture-source-snapshot.mjs';
import {
  preparePrivateTauriBuildTools,
} from './tauri-build-authorisation.mjs';
import { validateLatestArchitectureGate } from './check-architecture-gate.mjs';
import {
  createGuardedProductionResult,
  parseGuardedProductionResult,
} from './guarded-production-contract.mjs';
import { exclusiveDirectoryRename } from './exclusive-rename.mjs';
import {
  ProcessLedger,
  acquireOwnedLock,
  authoriseAuthenticatedNodeSandboxProfile,
  configureAuthenticatedNodeSpawn,
  installParentCutoffs,
  isProcessObservationFailure,
  releaseOwnedLock,
  runOwnedCommand,
  terminateRecordedProcessGroupsWithoutObservation,
  waitForChildSpawn,
} from './a21-gate-support.mjs';
import { createAuthenticatedNodeSpawnConfiguration } from './authenticated-node-spawn.mjs';
import { executeAuthoritativePackagedProbe } from './run-packaged-probe.mjs';
import {
  A23_PROBE_PHASES,
  assertSafeCredentialEvidence,
  captureCredentialCleanupHarness,
  createA23CleanupHelperIdentity,
  credentialProbeSandbox,
  executeAuthoritativeCredentialProbe,
} from './run-packaged-credential-probe.mjs';
import {
  captureApprovalMatrixHarness,
  executeAuthoritativeApprovalProbe,
  parsePackagedApprovalMatrixEvidence,
} from './run-packaged-approval-probe.mjs';
import {
  deriveA26FrontendInventory as deriveA26FrontendInventoryFromProvenance,
  executeAuthoritativeMarkdownProbe,
  parsePackagedMarkdownEvidence,
} from './run-packaged-markdown-probe.mjs';
import { executeAuthoritativeAccessibilityProbe } from './run-packaged-accessibility-probe.mjs';
import {
  A28_OFFICIAL_NODE_SIGNING_IDENTITY,
  createA28ProgressTranscriptForwarder,
} from './a28-installed-witness-ceremony.mjs';
import {
  architectureBootstrapChildOptions,
  assertArchitectureBootstrap,
  releaseArchitectureBootstrap,
} from './architecture-bootstrap-contract.mjs';
import {
  authenticateSystemOpenSslConfig,
  authenticatedToolchainIdentity,
  assertSystemOpenSslConfigRecord,
  noForkToolProbe,
  prepareAuthenticatedToolchain,
  registerAuthenticatedToolchainNode,
  validateAuthenticatedToolchain,
} from './architecture-toolchain-prepare.mjs';
import {
  architectureCacheEntryPath,
  architectureToolchainPins,
} from './architecture-toolchain-trust.mjs';
import { captureSidecarDeploymentReceipt } from './sidecar-deployment-witness.mjs';
import {
  APPLE_TOOLCHAIN_PATHS,
  appleToolchainBuildEnvironment,
  captureAppleToolchainAuthority,
  releaseAppleToolchainAuthority,
  revalidateAppleToolchainAuthority,
} from './apple-toolchain-trust.mjs';

process.umask(0o077);
const MODES = Object.freeze({
  '--architecture-gate-approval': 'gate-approval',
  '--architecture-gate-automation': 'gate-automation',
  '--architecture-gate-credential': 'gate-credential',
  '--architecture-gate-production': 'gate-production',
  '--guarded-production-build': 'guarded-production',
  '--authoritative-a22': 'a22',
  '--authoritative-a23': 'a23',
  '--authoritative-a24': 'a24',
  '--authoritative-a25': 'a25',
  '--authoritative-a26': 'a26',
  '--authoritative-a27': 'a27',
  '--authoritative-a28': 'a28',
});
const CONTROLLED_SIDECAR_FINALISATION_PHASES = Object.freeze(new Set([
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
]));
const PRIVATE_BUILD_CONTROL_LABELS = Object.freeze([
  'build-controls',
  'cargo-home-controls',
  'private-pnpm-tools',
]);
const PRIVATE_BUILD_CONTROL_CHANGE_CLASSES = Object.freeze([
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
]);
const FROZEN_INPUT_DIAGNOSTIC_PREFIXES = Object.freeze([
  'variant-inspection-frozen-input-recheck',
  ...[
    'variant-frontend-build',
    'variant-native-build',
    'variant-type-verification',
  ].flatMap((phase) => [
    `${phase}-frozen-input-before`,
    `${phase}-frozen-input-after`,
  ]),
]);
const FROZEN_INPUT_DIAGNOSTIC_CLASSES = Object.freeze([
  'apple-toolchain',
  'dependencies',
  'openssl-authentication',
  'openssl-lease',
  'private-controls-aggregate',
  'private-controls-capture',
  'source',
  'tool-inputs',
  'witnesses',
]);
const ISOLATED_CHILD_FAILURE_PHASES = Object.freeze(new Set([
  'cleanup',
  'context-validation',
  'initial-output-reset',
  'node-provisioning',
  'node-provisioning-disk-capacity',
  'node-provisioning-sandbox-denial',
  'node-provisioning-subprocess-failure',
  'private-build-tools',
  'result-finalisation',
  'sandbox-configuration',
  'sidecar-closure-finalisation',
  'sidecar-dependency-installation',
  'sidecar-deployment-preparation',
  'sidecar-deployment-preparation-disk-capacity',
  'sidecar-deployment-preparation-sandbox-denial',
  'sidecar-deployment-preparation-subprocess-failure',
  'sidecar-finalisation-parent-descriptor-releases',
  'sidecar-finalisation-parent-transaction-lock-release',
  'sidecar-protocol-compilation',
  'sidecar-typescript-compilation',
  'toolchain-resolution',
  'toolchain-verification',
  'variant-frontend-build',
  'variant-frontend-build-disk-capacity',
  'variant-frontend-build-sandbox-denial',
  'variant-frontend-build-subprocess-failure',
  'variant-inspection',
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
  'variant-native-build',
  'variant-native-build-disk-capacity',
  'variant-native-build-sandbox-denial',
  'variant-native-build-subprocess-failure',
  'variant-launch',
  'variant-post-build-revalidation',
  'variant-post-probe-revalidation',
  'variant-probe',
  'variant-type-verification',
  'variant-type-verification-disk-capacity',
  'variant-type-verification-sandbox-denial',
  'variant-type-verification-subprocess-failure',
  ...FROZEN_INPUT_DIAGNOSTIC_PREFIXES.flatMap((prefix) => [
    ...FROZEN_INPUT_DIAGNOSTIC_CLASSES.map((diagnosticClass) => (
      `${prefix}-${diagnosticClass}`
    )),
    ...PRIVATE_BUILD_CONTROL_LABELS.flatMap((label) => (
      PRIVATE_BUILD_CONTROL_CHANGE_CLASSES.map((changeClass) => (
        `${prefix}-private-controls-${label}-${changeClass}`
      ))
    )),
  ]),
  ...A23_PROBE_PHASES.map((phase) => `variant-probe-a23-${phase}`),
  ...[...CONTROLLED_SIDECAR_FINALISATION_PHASES]
    .filter((phase) => phase !== 'complete')
    .map((phase) => `sidecar-finalisation-${phase}`),
]));
let isolatedChildFailurePhase = 'context-validation';
let isolatedChildFailurePhaseAtCatch;

function setIsolatedChildFailurePhase(phase) {
  if (!ISOLATED_CHILD_FAILURE_PHASES.has(phase)) {
    throw new Error('Isolated child failure phase is invalid');
  }
  isolatedChildFailurePhase = phase;
}

export function parseIsolatedChildFailurePhase(bytes) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 1
    || bytes.length > 1_024
    || bytes.at(-1) !== 0x0a
    || bytes.includes(0x00)
    || bytes.includes(0x0d)
    || bytes.subarray(0, -1).includes(0x0a)) {
    return 'unclassified';
  }
  const match = bytes.toString('utf8').match(
    /^A\.21 package gate failed \[phase=([a-z0-9-]+)\]: [^\n]{1,600}\n$/u,
  );
  return match && ISOLATED_CHILD_FAILURE_PHASES.has(match[1])
    ? match[1]
    : 'unclassified';
}

export function parseControlledSidecarFinalisationPhase(bytes) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 1
    || bytes.length > 128
    || bytes.at(-1) !== 0x0a
    || bytes.includes(0x00)
    || bytes.includes(0x0d)
    || bytes.subarray(0, -1).includes(0x0a)) {
    return 'unclassified';
  }
  const match = bytes.toString('utf8').match(
    /^PIUI_SIDECAR_FINALISATION_PHASE=([a-z0-9-]+)\n$/u,
  );
  return match && CONTROLLED_SIDECAR_FINALISATION_PHASES.has(match[1])
    ? match[1]
    : 'unclassified';
}
const packageRunnerPath = fileURLToPath(import.meta.url);
const directlyInvoked = process.argv[1]
  ? await realpath(process.argv[1]) === await realpath(packageRunnerPath)
  : false;
const architectureBootstrap = directlyInvoked
  ? assertArchitectureBootstrap()
  : undefined;
const ownsArchitectureBootstrap = architectureBootstrap?.receipt.rootPid === process.pid;
let architectureBootstrapReleaseAttempted = false;
function releaseOwnedArchitectureBootstrap() {
  if (!ownsArchitectureBootstrap || architectureBootstrapReleaseAttempted) return false;
  architectureBootstrapReleaseAttempted = true;
  return releaseArchitectureBootstrap();
}
if (ownsArchitectureBootstrap) {
  process.once('exit', () => {
    if (architectureBootstrapReleaseAttempted) return;
    try {
      releaseOwnedArchitectureBootstrap();
    } catch (error) {
      process.stderr.write(`Architecture bootstrap cleanup failed: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    }
  });
}
const publicInvocation = directlyInvoked && process.argv.length === 2
  ? { isolatedChild: false, mode: 'a21' }
  : directlyInvoked && process.argv.length === 3 && MODES[process.argv[2]]
    ? { isolatedChild: false, mode: MODES[process.argv[2]] }
    : undefined;
const childInvocation = directlyInvoked && process.argv.length === 4
  && process.argv[2] === '--isolated-child'
  && ['a21', ...Object.values(MODES)].includes(process.argv[3])
  ? { isolatedChild: true, mode: process.argv[3] }
  : undefined;
const invocation = publicInvocation ?? childInvocation;
if (directlyInvoked && !invocation) {
  throw new Error('Unsupported A.21 package-gate arguments');
}
const isolatedChild = invocation?.isolatedChild ?? false;
const requestedMode = invocation?.mode ?? 'library';
const authoritativeA22 = requestedMode === 'a22';
const authoritativeA23 = requestedMode === 'a23';
const authoritativeA24 = requestedMode === 'a24';
const authoritativeA25 = requestedMode === 'a25';
const authoritativeA26 = requestedMode === 'a26';
const authoritativeA27 = requestedMode === 'a27';
const authoritativeA28 = requestedMode === 'a28';
const gateProduction = requestedMode === 'gate-production';
const gateCredential = requestedMode === 'gate-credential';
const gateApproval = requestedMode === 'gate-approval';
const gateAutomation = requestedMode === 'gate-automation';
const guardedProduction = requestedMode === 'guarded-production';
const architectureBatch = gateProduction || gateCredential || gateApproval || gateAutomation;
const architectureSourceBound = architectureBatch || guardedProduction;
const architectureRunId = /^\d{8}T\d{9}Z-[0-9a-f]{32}$/u;
const sha256Pattern = /^[0-9a-f]{64}$/u;
const automationMode = authoritativeA26
  || authoritativeA27
  || authoritativeA28
  || gateAutomation;
const runnerRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const temporaryRoot = await realpath(tmpdir());
const repositoryRoot = isolatedChild
  && typeof process.env.PIUI_PACKAGE_REPOSITORY_ROOT === 'string'
  ? resolve(process.env.PIUI_PACKAGE_REPOSITORY_ROOT)
  : runnerRoot;
if (publicInvocation && architectureBootstrap.receipt.repositoryRoot !== runnerRoot) {
  throw new Error('Architecture bootstrap repository root does not match the package runner');
}
const gateRunIdEnvironment = process.env.PIUI_ARCHITECTURE_GATE_RUN_ID;
const gateRunContextSha256Environment = process.env.PIUI_ARCHITECTURE_GATE_RUN_CONTEXT_SHA256;
const architectureGateRun = architectureBatch
  ? (() => {
    if (!architectureRunId.test(gateRunIdEnvironment ?? '')
      || !sha256Pattern.test(gateRunContextSha256Environment ?? '')
      || architectureBootstrap.receipt.mode !== 'record') {
      throw new Error('Architecture gate run binding is unavailable');
    }
    return Object.freeze({
      contextSha256: gateRunContextSha256Environment,
      runId: gateRunIdEnvironment,
    });
  })()
  : null;
if (!architectureBatch
  && (gateRunIdEnvironment !== undefined
    || gateRunContextSha256Environment !== undefined)) {
  throw new Error('Unexpected architecture gate run binding');
}
if (guardedProduction && architectureBootstrap.receipt.mode !== 'build') {
  throw new Error('Guarded production package did not inherit its build bootstrap');
}
if (!architectureBatch
  && !guardedProduction
  && directlyInvoked
  && architectureBootstrap.receipt.mode !== 'package') {
  throw new Error('Standalone package proof did not inherit its package bootstrap');
}
let sourceRoot = runnerRoot;
const target = 'aarch64-apple-darwin';
export function architecturePackageGlobalLockPath(repositoryRootPath, globalTemporaryRoot) {
  if (typeof repositoryRootPath !== 'string'
    || resolve(repositoryRootPath) !== repositoryRootPath
    || typeof globalTemporaryRoot !== 'string'
    || resolve(globalTemporaryRoot) !== globalTemporaryRoot) {
    throw new Error('Architecture package global lock inputs are invalid');
  }
  return resolve(
    globalTemporaryRoot,
    'piui-architecture-gate-locks',
    `${createHash('sha256').update(repositoryRootPath).digest('hex')}.lock`,
  );
}
const lockPath = guardedProduction
  ? process.env.PIUI_GUARDED_PRODUCTION_GLOBAL_LOCK_PATH
  : architecturePackageGlobalLockPath(repositoryRoot, temporaryRoot);
let generated = [];
let frozenSource;
let buildSandbox;
export function buildSandboxFor(configuration) {
  const categories = [
    'authenticatedCommand',
    'executableFiles',
    'executableRoots',
    'readableFiles',
    'readableRoots',
    'writableFiles',
    'writableRoots',
  ];
  if (!configuration || typeof configuration !== 'object' || Array.isArray(configuration)
    || Object.keys(configuration).sort().join(',') !== [...categories].sort().join(',')) {
    throw new Error('Build sandbox configuration is not exact');
  }
  const escaped = (path) => path.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
  const normalise = (values, label) => {
    if (!Array.isArray(values)) throw new Error(`Build sandbox ${label} is invalid`);
    const unique = [...new Set(values)].sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
    if (unique.length !== values.length || unique.some((path) => (
      typeof path !== 'string'
      || !path.startsWith('/')
      || path.length > 4_096
      || /[\0\r\n]/u.test(path)
      || path.includes('/../')
      || path.includes('/./')
      || path.endsWith('/..')
      || path.endsWith('/.')
      || path.includes('//')
    ))) throw new Error(`Build sandbox ${label} is invalid`);
    return unique;
  };
  const listCategories = categories.filter((category) => category !== 'authenticatedCommand');
  if (typeof configuration.authenticatedCommand !== 'string'
    || !configuration.authenticatedCommand.startsWith('/')
    || resolve(configuration.authenticatedCommand) !== configuration.authenticatedCommand) {
    throw new Error('Build sandbox authenticated command is invalid');
  }
  const lists = Object.fromEntries(listCategories.map((category) => [
    category,
    normalise(configuration[category], category),
  ]));
  const ancestors = new Set(['/']);
  for (const path of Object.values(lists).flat()) {
    let current = path;
    while (current !== '/') {
      const separator = current.lastIndexOf('/');
      current = separator <= 0 ? '/' : current.slice(0, separator);
      ancestors.add(current);
    }
  }
  const filters = (files, roots) => [
    ...files.map((path) => `(literal "${escaped(path)}")`),
    ...roots.map((path) => `(subpath "${escaped(path)}")`),
  ].join(' ');
  const metadata = [...ancestors]
    .sort((left, right) => Buffer.from(left).compare(Buffer.from(right)))
    .map((path) => `  (allow file-read-metadata file-test-existence (literal "${escaped(path)}"))`)
    .join('\n');
  if (!lists.executableFiles.includes(configuration.authenticatedCommand)
    || lists.executableRoots.some((path) => (
      configuration.authenticatedCommand === path
      || configuration.authenticatedCommand.startsWith(`${path}/`)
    ))) {
    throw new Error('Build sandbox authenticated command permissions are invalid');
  }
  const ordinaryExecutableFiles = lists.executableFiles.filter(
    (path) => path !== configuration.authenticatedCommand,
  );
  const ordinaryProcessExec = ordinaryExecutableFiles.length > 0
    || lists.executableRoots.length > 0
    ? `\n  (allow process-exec ${filters(ordinaryExecutableFiles, lists.executableRoots)})`
    : '';
  const writes = lists.writableFiles.length > 0 || lists.writableRoots.length > 0
    ? `\n  (allow file-write* ${filters(lists.writableFiles, lists.writableRoots)})\n  (allow file-link ${filters(lists.writableFiles, lists.writableRoots)})`
    : '';
  return `(version 1)
  (deny default)
  (import "dyld-support.sb")
  (deny network*)
  (deny appleevent-send)
  (deny mach-lookup
    (global-name "com.apple.securityd")
    (global-name "com.apple.SecurityServer"))
  (allow process-fork)
  (allow signal (target same-sandbox))
  (allow process-info* (target same-sandbox))
  (allow dynamic-code-generation)
  (allow sysctl-read)
  (with-filter (process-path "/usr/bin/sandbox-exec")
    (allow process-exec (literal "${escaped(configuration.authenticatedCommand)}")))${ordinaryProcessExec}
${metadata}
  (allow file-read* file-test-existence file-map-executable ${filters(lists.readableFiles, lists.readableRoots)})${writes}`;
}

function authenticatedBuildSandboxPolicy(configuration) {
  const ancestors = new Set(['/']);
  for (const path of Object.entries(configuration)
    .filter(([key]) => key !== 'authenticatedCommand')
    .flatMap(([, values]) => values)) {
    let current = path;
    while (current !== '/') {
      const separator = current.lastIndexOf('/');
      current = separator <= 0 ? '/' : current.slice(0, separator);
      ancestors.add(current);
    }
  }
  return Object.freeze({
    executableFiles: Object.freeze([...configuration.executableFiles]),
    executableRoots: Object.freeze([...configuration.executableRoots]),
    kind: 'deny-network',
    metadataFiles: Object.freeze([...ancestors]),
    metadataRoots: Object.freeze([]),
    readableFiles: Object.freeze([...configuration.readableFiles]),
    readableRoots: Object.freeze([...configuration.readableRoots]),
    writableFiles: Object.freeze([...configuration.writableFiles]),
    writableRoots: Object.freeze([...configuration.writableRoots]),
  });
}
function runtimeSandbox(bundle, isolate) {
  return `${credentialProbeSandbox({
    artefacts: resolve(isolate, 'agent'),
    cache: resolve(isolate, 'cache'),
    config: resolve(isolate, 'config'),
    data: resolve(isolate, 'data'),
    home: resolve(isolate, 'home'),
    temporary: resolve(isolate, 'tmp'),
    working: isolate,
  }, bundle, { allowCredentialBrokers: false })}
  (deny file-write* (subpath "${seatbeltPath(bundle.appPath)}"))`;
}
const readinessLine = 'PIUI_A21_AUTHENTICATED_SIDECAR_READY protocol=1 node=22.23.1 pi=0.82.0';
let buildIsolate;
let childGuardedPackageIsolateAuthority;
let runtimeIsolate;
let runtimeLedger;
let runtimeLedgerInitialised = false;
let runtimeRootPid;
let resultDocument;
let failure;
let projectTrustModule;
let lifecycleModule;
let parentCutoffs;
let childBuildIsolateValidated = false;
let frozenInputBaseline;
let dependencyBaseline;
let toolInputBaseline;
let toolInputRoots = Object.freeze([]);
let systemOpenSslConfigBaseline;
let appleToolchainAuthority;
let privateBuildInputBaseline;
let privateBuildInputRoots = Object.freeze([]);
let privateBuildInputExclusions = Object.freeze([]);
let privateBuildLinkRoots = Object.freeze([]);
let variantOverlayPaths = Object.freeze([]);
let variantOverlayByKind = new Map();
let formalBuildOverlayPath;
let syntheticForbiddenValues = Object.freeze([]);

function generatedOutputsFor(root) {
  return Object.freeze([
    { kind: 'directory', path: resolve(root, 'dist') },
    { kind: 'directory', path: resolve(root, 'packages/protocol/dist') },
    { kind: 'directory', path: resolve(root, 'sidecar/dist') },
    { kind: 'directory', path: resolve(root, 'src-tauri/target') },
    { kind: 'directory', path: resolve(root, 'src-tauri/gen') },
    { kind: 'directory', path: resolve(root, 'src-tauri/resources/sidecar') },
    { kind: 'file', path: resolve(root, `src-tauri/binaries/piui-node-${target}`) },
    { kind: 'directory', path: resolve(root, 'test-results') },
    { kind: 'directory', path: resolve(root, 'playwright-report') },
  ]);
}

async function prepareGeneratedOutputs(outputs) {
  for (const output of outputs) {
    if (output.kind === 'directory') {
      mkdirSync(output.path, { recursive: true, mode: 0o700 });
      await chmod(output.path, 0o700);
      continue;
    }
    mkdirSync(dirname(output.path), { recursive: true, mode: 0o700 });
    try {
      writeFileSync(output.path, Buffer.alloc(0), { flag: 'wx', mode: 0o600 });
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }
    const state = await lstat(output.path);
    if (!state.isFile() || state.isSymbolicLink() || state.nlink !== 1) {
      throw new Error('Declared generated output is unsafe');
    }
    await chmod(output.path, 0o600);
  }
}

function sourceLeaseInputBytes(snapshot) {
  let parsed;
  try {
    parsed = JSON.parse(snapshot.leaseBytes.toString('utf8'));
  } catch {
    throw new Error('Frozen source lease is invalid');
  }
  if (parsed?.schemaVersion !== 1 || !Array.isArray(parsed.entries)) {
    throw new Error('Frozen source lease is invalid');
  }
  const entries = parsed.entries.filter((entry) => (
    entry.path !== 'src-tauri/resources/'
  ));
  return Buffer.from(`${canonicalArchitectureJson({ entries, schemaVersion: 1 })}\n`, 'utf8');
}

function sourceLeaseInputSha256(snapshot) {
  return sha256Bytes(sourceLeaseInputBytes(snapshot));
}

async function sealFrozenSourceInputs(root, snapshot) {
  for (const entry of snapshot.inventory) {
    const path = resolve(root, ...entry.path.split('/'));
    await chmod(path, entry.executable ? 0o500 : 0o400);
  }
  let lease;
  try {
    lease = JSON.parse(snapshot.leaseBytes.toString('utf8'));
  } catch {
    throw new Error('Frozen source lease is invalid');
  }
  const directories = lease.entries
    .filter((entry) => entry.kind === 'directory' && entry.path !== 'src-tauri/resources/')
    .sort((left, right) => right.path.split('/').length - left.path.split('/').length);
  for (const entry of directories) {
    const path = entry.path === '.'
      ? root
      : resolve(root, ...entry.path.replace(/\/$/u, '').split('/'));
    await chmod(path, 0o500);
  }
}

async function runIsolatedChild() {
parentCutoffs = installParentCutoffs();
try {
  assertHost();
  setIsolatedChildFailurePhase('context-validation');
  const childContext = await validateIsolatedChildContext();
  buildIsolate = childContext.buildIsolate;
  childGuardedPackageIsolateAuthority = childContext.guardedPackageIsolateAuthority;
  sourceRoot = childContext.sourceRoot;
  frozenSource = childContext.snapshot;
  frozenInputBaseline = childContext.snapshot;
  dependencyBaseline = childContext.dependency;
  childBuildIsolateValidated = true;
  projectTrustModule = await import(pathToFileURL(
    resolve(sourceRoot, 'scripts/run-packaged-trust-probe.mjs'),
  ).href);
  generated = generatedOutputsFor(sourceRoot);
  configureAuthenticatedNodeSpawn(await createAuthenticatedNodeSpawnConfiguration({
    nodePath: architectureBootstrap.receipt.nodePath,
    snapshot: childContext.snapshot,
    sourceRoot,
  }));
  setIsolatedChildFailurePhase('toolchain-resolution');
  const resolvedTools = await resolveTrustedTools(buildIsolate);
  if (resolvedTools.authenticatedToolchainContextSha256
      !== childContext.toolchainIdentity.authenticatedToolchainContextSha256
    || resolvedTools.authenticatedToolchainReceiptSha256
      !== childContext.toolchainIdentity.authenticatedToolchainReceiptSha256) {
    throw new Error('Authenticated toolchain identity does not match the parent witness');
  }
  if (resolvedTools.toolInput.entries !== childContext.toolInput.entries
    || resolvedTools.toolInput.inventorySha256 !== childContext.toolInput.inventorySha256
    || resolvedTools.toolInput.leaseSha256 !== childContext.toolInput.leaseSha256) {
    throw new Error('Build tool inputs do not match the parent witness');
  }
  if (canonicalArchitectureJson(resolvedTools.systemOpenSslConfig)
    !== canonicalArchitectureJson(childContext.systemOpenSslConfig)) {
    throw new Error('Authenticated system OpenSSL config does not match the parent witness');
  }
  systemOpenSslConfigBaseline = resolvedTools.systemOpenSslConfig;
  toolInputBaseline = resolvedTools.toolInput;
  toolInputRoots = resolvedTools.toolInputRoots;
  const authenticatedToolchainItems = resolvedTools.toolInput.items.filter((item) => (
    item.label === 'authenticated-toolchain'
  ));
  if (authenticatedToolchainItems.length !== 1) {
    throw new Error('Authenticated toolchain closure witness is unavailable');
  }
  const authenticatedToolchainItem = authenticatedToolchainItems[0];
  setIsolatedChildFailurePhase('private-build-tools');
  const privateBuildTools = await preparePrivateTauriBuildTools({
    authenticatedToolchainWitness: Object.freeze({
      entries: authenticatedToolchainItem.entries,
      inventoryBytes: authenticatedToolchainItem.inventoryBytes,
      inventorySha256: authenticatedToolchainItem.inventorySha256,
      root: authenticatedToolchainItem.root,
    }),
    buildIsolate,
    pnpmEntry: resolvedTools.pnpmEntry,
    pnpmNode: resolvedTools.pnpmNode,
  });
  configureAuthenticatedNodeSpawn(await createAuthenticatedNodeSpawnConfiguration({
    nodePath: privateBuildTools.pnpmNode,
    snapshot: childContext.snapshot,
    sourceRoot,
  }));
  const toolInputAfterPrivateCopy = await captureToolInputSet(
    toolInputRoots,
    { includeHashes: false },
  );
  if (!equalInputSetLease(toolInputBaseline, toolInputAfterPrivateCopy)) {
    throw new Error('Build tool inputs changed during private tool copying');
  }
  const tools = Object.freeze({
    ...resolvedTools,
    ...privateBuildTools,
  });
  appleToolchainAuthority = captureAppleToolchainAuthority();
  const sourceDigest = architectureSourceBound
    ? exactArchitectureSourceDigest(process.env.PIUI_ARCHITECTURE_SOURCE_DIGEST, frozenSource)
    : frozenSource.source.digest;
  const buildEnv = makeBuildEnvironment(
    buildIsolate,
    tools,
    syntheticForbiddenValues,
  );
  await prepareVariantOverlays();
  privateBuildInputRoots = Object.freeze([
    Object.freeze({ label: 'build-controls', root: resolve(buildIsolate, 'build-controls') }),
    Object.freeze({ label: 'cargo-home-controls', root: buildEnv.CARGO_HOME }),
    Object.freeze({ label: 'private-pnpm-tools', root: resolve(buildIsolate, 'tauri-build-tools') }),
  ]);
  privateBuildInputExclusions = Object.freeze([
    resolve(buildEnv.CARGO_HOME, '.package-cache'),
    resolve(buildEnv.CARGO_HOME, '.package-cache-mutate'),
  ]);
  privateBuildLinkRoots = Object.freeze([
    buildIsolate,
    ...toolInputRoots.map((item) => item.root),
  ]);
  privateBuildInputBaseline = await capturePrivateBuildInputSet(
    buildIsolate,
    privateBuildInputRoots,
    privateBuildLinkRoots,
    privateBuildInputExclusions,
    { includeHashes: true },
  );
  setIsolatedChildFailurePhase('sandbox-configuration');
  const buildSandboxInputs = buildSandboxConfiguration({
    buildEnv,
    buildIsolate,
    sourceRoot,
    tools,
  });
  buildSandbox = buildSandboxFor(buildSandboxInputs);
  authoriseAuthenticatedNodeSandboxProfile({
    command: tools.pnpmNode,
    policy: authenticatedBuildSandboxPolicy(buildSandboxInputs),
    profile: buildSandbox,
  });
  if (gateProduction && process.env.PIUI_ARCHITECTURE_PRODUCTION_ARTIFACT !== undefined) {
    throw new Error('Production batch received unexpected prior artefact metadata');
  }
  const receivedProductionArtifact = gateProduction
    ? undefined
    : architectureBatch
      ? parseReceivedProductionArtifact(process.env.PIUI_ARCHITECTURE_PRODUCTION_ARTIFACT)
      : undefined;
  setIsolatedChildFailurePhase('initial-output-reset');
  await resetGeneratedOutputs();
  await assertFrozenBuildInputs();
  await provisionPinnedNodeOutput(tools, buildEnv, 'Pinned Node provisioning');
  setIsolatedChildFailurePhase('toolchain-verification');
  await runSandboxed(tools.pnpmNode, ['scripts/verify-toolchain.mjs'], 'Toolchain verification', buildEnv, 120_000);
  setIsolatedChildFailurePhase('sidecar-protocol-compilation');
  await stageSidecarControlled(tools, buildEnv);

  const stagedSidecar = resolve(sourceRoot, 'src-tauri/resources/sidecar');
  const stagedNode = resolve(sourceRoot, `src-tauri/binaries/piui-node-${target}`);
  const anchors = await captureStageAnchors({ sidecarRoot: stagedSidecar, nodePath: stagedNode, expectedNode: '22.23.1', expectedPi: '0.82.0' });
  await assertAuthenticatedNodeAnchor(anchors, tools);
  const forbiddenValues = syntheticForbiddenValues;
  setIsolatedChildFailurePhase('variant-inspection');
  if (guardedProduction) {
    const build = await buildAndInspectVariant({
      anchors,
      buildEnv,
      forbiddenValues,
      kind: 'production',
      sourceDigest,
      tools,
    });
    const artifact = architectureArtifactFromBundle(build.accepted, {
      appliedVariant: build.variant,
      kind: 'production',
    });
    const guardedContext = childContext.guardedProduction;
    if (!guardedContext
      || artifact.fingerprint !== guardedContext.productionFingerprint) {
      throw new Error('Production build does not match the recorded architecture artefact');
    }
    await assertFrozenBuildInputs();
    const published = await relocateAcceptedBundle(
      build.accepted,
      resolve(guardedContext.outputRoot, 'PIUI.app'),
    );
    await revalidateBundle(published);
    await assertGuardedOutputRoot(
      guardedContext.outputRoot,
      { dev: guardedContext.outputDev, ino: guardedContext.outputIno },
      ['PIUI.app'],
      childContext.guardedPackageIsolateAuthority.parent,
    );
    resultDocument = createGuardedProductionResult({
      artifact,
      gateRunId: guardedContext.runId,
      generatedOutputsRemoved: false,
      sourceDigest,
    });
  } else if (automationMode) {
    const captureA26FrontendInventories = authoritativeA26 || gateAutomation;
    const productionBuild = await buildAndInspectVariant({
      anchors,
      buildEnv,
      forbiddenValues,
      kind: 'production',
      sourceDigest,
      tools,
    });
    const productionFrontend = captureA26FrontendInventories
      ? await inspectFrontendBuild(resolve(sourceRoot, 'dist'))
      : undefined;
    const productionBundle = await retainAcceptedBundle(
      productionBuild.accepted,
      resolve(buildIsolate, 'retained-production'),
    );
    const localProductionArtifact = architectureArtifactFromBundle(productionBundle, {
      appliedVariant: productionBuild.variant,
      kind: 'production',
    });
    if (gateAutomation) assertExactProductionArtifact(localProductionArtifact, receivedProductionArtifact);

    const automationAnchors = await rebuildFreshStageAnchors(
      anchors,
      tools,
      buildEnv,
    );
    const automationBuild = await buildAndInspectVariant({
      anchors: automationAnchors,
      buildEnv,
      forbiddenValues,
      kind: 'automation-twin',
      sourceDigest,
      tools,
    });
    const automationBundle = automationBuild.accepted;
    const automationFrontend = captureA26FrontendInventories
      ? await inspectFrontendBuild(resolve(sourceRoot, 'dist'))
      : undefined;
    const repeatAutomationAnchors = await rebuildFreshStageAnchors(
      anchors,
      tools,
      buildEnv,
    );
    const repeatAutomationBuild = await buildAndInspectVariant({
      anchors: repeatAutomationAnchors,
      buildEnv,
      captureProbeHarness: false,
      forbiddenValues,
      kind: 'automation-twin',
      sourceDigest,
      tools,
    });
    const repeatAutomationBundle = repeatAutomationBuild.accepted;
    const repeatAutomationFrontend = captureA26FrontendInventories
      ? await inspectFrontendBuild(resolve(sourceRoot, 'dist'))
      : undefined;
    const measuredDelta = await measureTwinDelta({
      appliedVariant: automationBuild.variant,
      kind: 'automation-twin',
      productionBundle,
      productionPreSignHostBytes: productionBuild.preSignHostBytes,
      twinBundle: automationBundle,
      twinPreSignHostBytes: automationBuild.preSignHostBytes,
      twinRepeatBundle: repeatAutomationBundle,
      twinRepeatPreSignHostBytes: repeatAutomationBuild.preSignHostBytes,
      verificationRoot: resolve(
        buildIsolate,
        `measured-automation-delta-${randomBytes(16).toString('hex')}`,
      ),
    });
    const deltaSha256 = measuredDelta.sha256;
    const markdownBundleDerivation = authoritativeA26 || gateAutomation
      ? await deriveA26BundleEvidence({
        automationBundle,
        automationFrontend,
        automationProvenance: automationBuild.frontendProvenance,
        productionBundle,
        productionFrontend,
        productionProvenance: productionBuild.frontendProvenance,
        repeatAutomationFrontend,
        repeatAutomationProvenance: repeatAutomationBuild.frontendProvenance,
      })
      : undefined;
    const markdownEvidence = authoritativeA26 || gateAutomation
      ? await executeAuthoritativeMarkdownProbe({
        automationBundle,
        bundleEvidence: markdownBundleDerivation.evidence,
        controlledDeltaSha256: deltaSha256,
        expectedResourcePaths: markdownBundleDerivation.expectedResourcePaths,
        productionBundle,
        signal: parentCutoffs.signal,
        sourceDigest,
      })
      : undefined;
    const lifecycleEvidence = authoritativeA27 || gateAutomation
      ? await executeRequiredLifecycleProbe({
        automationBundle,
        controlledDeltaSha256: deltaSha256,
        productionBundle,
        signal: parentCutoffs.signal,
        sourceDigest,
      })
      : undefined;
    const accessibilityEvidence = authoritativeA28 || gateAutomation
      ? await executeRequiredAccessibilityProbe({
        architectureGateRun,
        automationBundle,
        consumerAnchors: childContext.consumerAnchors,
        measuredDelta,
        productionBundle,
        repositoryRoot: childContext.repositoryRoot,
        runnerSigningIdentity: A28_OFFICIAL_NODE_SIGNING_IDENTITY,
        signal: parentCutoffs.signal,
        sourceDigest,
      }, childContext.evidenceRootIdentity)
      : undefined;
    await revalidateBundle(productionBundle);
    await revalidateBundle(automationBundle);
    await revalidateBundle(repeatAutomationBundle);

    if (gateAutomation) {
      const artifact = architectureArtifactFromBundle(automationBundle, {
        appliedVariant: automationBuild.variant,
        baseProductionFingerprint: receivedProductionArtifact.fingerprint,
        kind: 'automation-twin',
        measuredDelta,
      });
      assertTwinRuntimeHashes(artifact, receivedProductionArtifact);
      resultDocument = architectureProofBatch('automation', artifact, sourceDigest, {
        'A.26': markdownEvidence,
        'A.27': lifecycleEvidence,
        'A.28': accessibilityEvidence,
      });
    } else {
      resultDocument = authoritativeA26
        ? markdownEvidence
        : authoritativeA27
          ? lifecycleEvidence
          : accessibilityEvidence;
    }
  } else if (gateCredential || gateApproval) {
    const twinKind = gateCredential ? 'credential-twin' : 'approval-twin';
    const productionBuild = await buildAndInspectVariant({
      anchors,
      buildEnv,
      forbiddenValues,
      kind: 'production',
      sourceDigest,
      tools,
    });
    const productionBundle = await retainAcceptedBundle(
      productionBuild.accepted,
      resolve(buildIsolate, 'retained-production'),
    );
    const localProductionArtifact = architectureArtifactFromBundle(productionBundle, {
      appliedVariant: productionBuild.variant,
      kind: 'production',
    });
    assertExactProductionArtifact(localProductionArtifact, receivedProductionArtifact);

    const twinAnchors = await rebuildFreshStageAnchors(anchors, tools, buildEnv);
    const twinBuild = await buildAndInspectVariant({
      anchors: twinAnchors,
      buildEnv,
      forbiddenValues,
      kind: twinKind,
      sourceDigest,
      tools,
    });
    const repeatTwinAnchors = await rebuildFreshStageAnchors(anchors, tools, buildEnv);
    const repeatTwinBuild = await buildAndInspectVariant({
      anchors: repeatTwinAnchors,
      buildEnv,
      captureProbeHarness: false,
      forbiddenValues,
      kind: twinKind,
      sourceDigest,
      tools,
    });
    const accepted = twinBuild.accepted;
    const repeatTwinBundle = repeatTwinBuild.accepted;
    const measuredDelta = await measureTwinDelta({
      appliedVariant: twinBuild.variant,
      kind: twinKind,
      productionBundle,
      productionPreSignHostBytes: productionBuild.preSignHostBytes,
      twinBundle: accepted,
      twinPreSignHostBytes: twinBuild.preSignHostBytes,
      twinRepeatBundle: repeatTwinBundle,
      twinRepeatPreSignHostBytes: repeatTwinBuild.preSignHostBytes,
      verificationRoot: resolve(
        buildIsolate,
        `measured-${gateCredential ? 'credential' : 'approval'}-delta-${randomBytes(16).toString('hex')}`,
      ),
    });
    setIsolatedChildFailurePhase('variant-probe');
    const evidence = gateCredential
      ? await executeAuthoritativeCredentialProbe(accepted, twinBuild.credentialCleanupHarness, {
        cleanupHelperIdentity: twinBuild.credentialCleanupHelperIdentity,
        onPhase: (phase) => setIsolatedChildFailurePhase(`variant-probe-a23-${phase}`),
        signal: parentCutoffs.signal,
      })
      : await executeAuthoritativeApprovalProbe(accepted, twinBuild.approvalMatrixHarness, {
        signal: parentCutoffs.signal,
      });
    setIsolatedChildFailurePhase('variant-post-probe-revalidation');
    await revalidateBundle(productionBundle);
    await revalidateBundle(accepted);
    await revalidateBundle(repeatTwinBundle);
    const artifact = architectureArtifactFromBundle(accepted, {
      appliedVariant: twinBuild.variant,
      baseProductionFingerprint: receivedProductionArtifact.fingerprint,
      kind: twinKind,
      measuredDelta,
    });
    assertTwinRuntimeHashes(artifact, receivedProductionArtifact);
    resultDocument = architectureProofBatch(
      gateCredential ? 'credential' : 'approval',
      artifact,
      sourceDigest,
      gateCredential ? { 'A.23': evidence } : { 'A.25': evidence },
    );
  } else {
    const kind = authoritativeA23
      ? 'credential-twin'
      : authoritativeA25
        ? 'approval-twin'
        : 'production';
    const build = await buildAndInspectVariant({
      anchors,
      buildEnv,
      forbiddenValues,
      kind,
      sourceDigest,
      tools,
    });
    const accepted = build.accepted;
    const projectTrustHarness = build.projectTrustHarness;
    setIsolatedChildFailurePhase('variant-launch');
    const launch = kind === 'production' ? await launchAndInspect(accepted) : undefined;
    setIsolatedChildFailurePhase('variant-post-build-revalidation');
    await revalidateBundle(accepted);
    setIsolatedChildFailurePhase('variant-probe');
    const sdkEvidence = authoritativeA22 || gateProduction
      ? await executeAuthoritativePackagedProbe(accepted, { sourceRoot })
      : undefined;
    const trustEvidence = authoritativeA24 || gateProduction
      ? await projectTrustModule.executeAuthoritativeProjectTrustProbe(accepted, projectTrustHarness, {
        sourceRoot,
      })
      : undefined;
    const credentialEvidence = authoritativeA23
      ? await executeAuthoritativeCredentialProbe(accepted, build.credentialCleanupHarness, {
        cleanupHelperIdentity: build.credentialCleanupHelperIdentity,
        onPhase: (phase) => setIsolatedChildFailurePhase(`variant-probe-a23-${phase}`),
        signal: parentCutoffs.signal,
      })
      : undefined;
    const approvalEvidence = authoritativeA25
      ? await executeAuthoritativeApprovalProbe(accepted, build.approvalMatrixHarness, {
        signal: parentCutoffs.signal,
      })
      : undefined;
    setIsolatedChildFailurePhase('variant-post-probe-revalidation');
    await revalidateBundle(accepted);

    if (architectureBatch) {
      if (!gateProduction || kind !== 'production') {
        throw new Error('Twin architecture batches must use the measured repeat-build path');
      }
      const artifact = architectureArtifactFromBundle(accepted, {
        appliedVariant: build.variant,
        kind,
      });
      resultDocument = architectureProofBatch('production', artifact, sourceDigest, {
        'A.21': packageInspectionEvidence(accepted, launch, 'emitted-after-owned-temporary-cleanup'),
        'A.22': sdkEvidence,
        'A.24': trustEvidence,
      });
    } else {
      resultDocument = authoritativeA22 ? sdkEvidence
        : authoritativeA23 ? credentialEvidence
          : authoritativeA24 ? trustEvidence
            : authoritativeA25 ? approvalEvidence
              : packageInspectionEvidence(accepted, launch, 'pending');
    }
  }
} catch (error) {
  failure = error;
  isolatedChildFailurePhaseAtCatch = isolatedChildFailurePhase;
} finally {
  const cleanupFailures = [];
  const attemptCleanup = async (operation) => {
    try { await operation(); } catch (error) { cleanupFailures.push(error); }
  };
  if (runtimeLedger) {
    await attemptCleanup(async () => {
      if (!runtimeLedgerInitialised) {
        await terminateRecordedProcessGroupsWithoutObservation([
          runtimeRootPid,
          ...runtimeLedger.groups,
        ]);
        return;
      }
      try {
        await runtimeLedger.terminate();
      } catch (error) {
        if (isProcessObservationFailure(error)) {
          await terminateRecordedProcessGroupsWithoutObservation([
            runtimeRootPid,
            ...runtimeLedger.groups,
          ]);
        }
        throw error;
      }
    });
  }
  if (runtimeIsolate) await attemptCleanup(() => removeOwnedTree(runtimeIsolate));
  if (childBuildIsolateValidated) {
    await attemptCleanup(() => assertFrozenBuildInputs());
    await attemptCleanup(() => removeGeneratedOutputs());
    await attemptCleanup(() => assertGeneratedAbsent());
    await attemptCleanup(async () => {
      process.chdir(guardedProduction ? repositoryRoot : temporaryRoot);
      if (childGuardedPackageIsolateAuthority) {
        const held = fstatSync(childGuardedPackageIsolateAuthority.fd, { bigint: true });
        const pathname = lstatSync(buildIsolate, { bigint: true });
        if (!sameGuardedDirectoryIdentity(held, pathname)
          || held.dev !== childGuardedPackageIsolateAuthority.dev
          || held.ino !== childGuardedPackageIsolateAuthority.ino) {
          throw new Error('Guarded production package isolate changed before cleanup');
        }
      }
      await removeOwnedTree(buildIsolate);
      await assertPathAbsent(buildIsolate, 'Owned build isolate');
      if (childGuardedPackageIsolateAuthority) {
        assertGuardedPackageIsolateUnlinked(childGuardedPackageIsolateAuthority);
      }
    });
  }
  if (childGuardedPackageIsolateAuthority) {
    await attemptCleanup(async () => {
      closeSync(childGuardedPackageIsolateAuthority.fd);
      childGuardedPackageIsolateAuthority = undefined;
    });
  }
  if (appleToolchainAuthority) {
    const authority = appleToolchainAuthority;
    appleToolchainAuthority = undefined;
    await attemptCleanup(() => revalidateAppleToolchainAuthority(authority));
    await attemptCleanup(() => releaseAppleToolchainAuthority(authority));
  }
  if (cleanupFailures.length) {
    if (!failure) isolatedChildFailurePhaseAtCatch = 'cleanup';
    const cleanupError = new AggregateError(cleanupFailures, 'A.21 cleanup failed');
    failure = failure ? new AggregateError([failure, cleanupError], 'A.21 gate and cleanup failed') : cleanupError;
  }
}
parentCutoffs.dispose();
if (!failure) {
  try {
    setIsolatedChildFailurePhase('result-finalisation');
    resultDocument = finaliseResultAfterCleanup(resultDocument);
  } catch (error) {
    failure = error;
    isolatedChildFailurePhaseAtCatch = isolatedChildFailurePhase;
  }
}

if (failure) {
  console.error(
    `A.21 package gate failed [phase=${isolatedChildFailurePhaseAtCatch ?? isolatedChildFailurePhase}]: ${redactedMessage(failure)}`,
  );
  process.exitCode = failure?.code === 'PIUI_A28_ACCESSIBILITY_BLOCKED' ? 2 : 1;
} else {
  process.stdout.write(`${canonicalArchitectureJson(resultDocument)}\n`);
}
}

async function assertAccessibilityEvidenceRoot(path, expectedIdentity) {
  const expectedPath = resolve(
    repositoryRoot,
    '.forge/evidence/architecture-accessibility',
  );
  if (path !== expectedPath) {
    throw new Error('A.28 repository evidence root is not exact');
  }
  await assertControlledDirectory(repositoryRoot, 'A.28 repository root');
  await assertControlledDirectory(
    resolve(repositoryRoot, '.forge'),
    'A.28 .forge directory',
  );
  await assertControlledDirectory(
    resolve(repositoryRoot, '.forge/evidence'),
    'A.28 evidence directory',
    true,
  );
  const item = await lstat(path);
  if (!item.isDirectory()
    || item.isSymbolicLink()
    || (item.mode & 0o777) !== 0o700
    || (typeof process.getuid === 'function' && item.uid !== process.getuid())
    || await realpath(path) !== path
    || (expectedIdentity
      && (item.dev !== expectedIdentity.dev || item.ino !== expectedIdentity.ino))) {
    throw new Error('A.28 repository evidence root is unsafe');
  }
  return Object.freeze({ dev: item.dev, ino: item.ino, path });
}

async function assertControlledDirectory(path, label, exactPrivate = false) {
  const item = await lstat(path);
  if (!item.isDirectory()
    || item.isSymbolicLink()
    || (item.mode & 0o022) !== 0
    || (exactPrivate && (item.mode & 0o777) !== 0o700)
    || (typeof process.getuid === 'function' && item.uid !== process.getuid())
    || await realpath(path) !== path) {
    throw new Error(`${label} is unsafe`);
  }
  return Object.freeze({ dev: item.dev, ino: item.ino, path });
}

async function ensurePrivateEvidenceDirectory(parent, name, label) {
  const parentBefore = await assertControlledDirectory(parent.path, 'A.28 evidence parent');
  if (parentBefore.dev !== parent.dev || parentBefore.ino !== parent.ino) {
    throw new Error('A.28 evidence parent identity changed');
  }
  const path = resolve(parent.path, name);
  try {
    mkdirSync(path, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  const child = await assertControlledDirectory(path, label, true);
  const parentAfter = await assertControlledDirectory(parent.path, 'A.28 evidence parent');
  if (parentAfter.dev !== parent.dev || parentAfter.ino !== parent.ino) {
    throw new Error('A.28 evidence parent identity changed');
  }
  return child;
}

async function optionalAccessibilityEvidenceRoot() {
  if (!authoritativeA28 && !gateAutomation) return null;
  const repository = await assertControlledDirectory(
    repositoryRoot,
    'A.28 repository root',
  );
  const forge = await assertControlledDirectory(
    resolve(repositoryRoot, '.forge'),
    'A.28 .forge directory',
  );
  const repositoryAfterForge = await assertControlledDirectory(
    repositoryRoot,
    'A.28 repository root',
  );
  if (repositoryAfterForge.dev !== repository.dev
    || repositoryAfterForge.ino !== repository.ino) {
    throw new Error('A.28 repository root identity changed');
  }
  const evidence = await ensurePrivateEvidenceDirectory(forge, 'evidence', 'A.28 evidence directory');
  await ensurePrivateEvidenceDirectory(
    evidence,
    'architecture-accessibility',
    'A.28 accessibility evidence root',
  );
  return assertAccessibilityEvidenceRoot(
    resolve(repositoryRoot, '.forge/evidence/architecture-accessibility'),
  );
}

function parseIsolatedChildResult(bytes) {
  return parseCanonicalControlBytes(bytes, 4 * 1_048_576, 'Isolated package child result');
}

async function assertPathAbsent(path, label) {
  try {
    await lstat(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  throw new Error(`${label} remained after cleanup`);
}

function packageChildContextStateSha256(state) {
  return sha256Bytes(Buffer.from(`${canonicalArchitectureJson({
    ctimeNs: state.ctimeNs.toString(),
    dev: state.dev.toString(),
    gid: state.gid.toString(),
    ino: state.ino.toString(),
    mode: state.mode.toString(),
    mtimeNs: state.mtimeNs.toString(),
    nlink: state.nlink.toString(),
    size: state.size.toString(),
    uid: state.uid.toString(),
  })}\n`, 'utf8'));
}

export function readHeldPackageChildContext({ fd, leaseSha256, path, sha256 }) {
  if (!Number.isSafeInteger(fd)
    || fd < 3
    || fd > 255
    || typeof path !== 'string'
    || resolve(path) !== path
    || !sha256Pattern.test(leaseSha256 ?? '')
    || !sha256Pattern.test(sha256 ?? '')) {
    throw new Error('Package child context descriptor authority is invalid');
  }
  const before = fstatSync(fd, { bigint: true });
  const pathBefore = lstatSync(path, { bigint: true });
  if (!before.isFile()
    || before.isSymbolicLink()
    || before.uid !== BigInt(process.getuid())
    || before.nlink !== 1n
    || (before.mode & 0o777n) !== 0o400n
    || before.size < 128n
    || before.size > 16_384n
    || !sameBigIntState(before, pathBefore)
    || packageChildContextStateSha256(before) !== leaseSha256) {
    throw new Error('Package child context descriptor lease is invalid');
  }
  const bytes = Buffer.alloc(Number(before.size));
  let offset = 0;
  while (offset < bytes.length) {
    const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
    if (count < 1) throw new Error('Package child context descriptor ended early');
    offset += count;
  }
  const after = fstatSync(fd, { bigint: true });
  const pathAfter = lstatSync(path, { bigint: true });
  if (!sameBigIntState(before, after)
    || !sameBigIntState(after, pathAfter)
    || packageChildContextStateSha256(after) !== leaseSha256
    || sha256Bytes(bytes) !== sha256) {
    throw new Error('Package child context descriptor changed during its held read');
  }
  return bytes;
}

export function parsePackageChildDescriptor(value) {
  if (typeof value !== 'string' || !/^[0-9]+$/u.test(value)) {
    throw new Error('Package child context descriptor number is invalid');
  }
  const fd = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(fd) || fd < 3 || fd > 255 || String(fd) !== value) {
    throw new Error('Package child context descriptor number is invalid');
  }
  return fd;
}

function guardedProductionIdentity(value, label, { allowZero = false } = {}) {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
    throw new Error(`${label} is invalid`);
  }
  const identity = BigInt(value);
  if ((!allowZero && identity < 1n) || identity > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${label} is invalid`);
  }
  return identity;
}

function sameGuardedDirectoryIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid;
}

async function assertGuardedPackageIsolateAuthority({ dev, fd: fdText, ino, path }) {
  const fd = parsePackageChildDescriptor(fdText);
  const expectedDev = guardedProductionIdentity(dev, 'Guarded package isolate device', {
    allowZero: true,
  });
  const expectedIno = guardedProductionIdentity(ino, 'Guarded package isolate inode');
  if (typeof path !== 'string'
    || resolve(path) !== path
    || !basename(path).startsWith('piui-guarded-package-')
    || await realpath(dirname(path)) !== dirname(path)
    || process.env.HOME !== resolve(path, 'home')
    || temporaryRoot !== resolve(path, 'tmp')) {
    throw new Error('Guarded production package isolate authority is invalid');
  }
  const held = fstatSync(fd, { bigint: true });
  const pathname = lstatSync(path, { bigint: true });
  if (!held.isDirectory()
    || held.isSymbolicLink()
    || pathname.isSymbolicLink()
    || !sameGuardedDirectoryIdentity(held, pathname)
    || held.dev !== expectedDev
    || held.ino !== expectedIno
    || held.uid !== BigInt(process.getuid())
    || (held.mode & 0o777n) !== 0o700n
    || await realpath(path) !== path) {
    throw new Error('Guarded production package isolate descriptor identity is invalid');
  }
  await assertPrivateDirectory(resolve(path, 'home'), 'Guarded production package home');
  await assertPrivateDirectory(resolve(path, 'tmp'), 'Guarded production package temporary root');
  return Object.freeze({
    dev: held.dev,
    fd,
    ino: held.ino,
    parent: dirname(path),
    path,
  });
}

function assertGuardedGlobalLockAuthority(isolate) {
  const path = process.env.PIUI_GUARDED_PRODUCTION_GLOBAL_LOCK_PATH;
  const fd = parsePackageChildDescriptor(
    process.env.PIUI_GUARDED_PRODUCTION_GLOBAL_LOCK_FD,
  );
  const expectedDev = guardedProductionIdentity(
    process.env.PIUI_GUARDED_PRODUCTION_GLOBAL_LOCK_DEV,
    'Guarded global lock device',
    { allowZero: true },
  );
  const expectedIno = guardedProductionIdentity(
    process.env.PIUI_GUARDED_PRODUCTION_GLOBAL_LOCK_INO,
    'Guarded global lock inode',
  );
  if (path !== architecturePackageGlobalLockPath(repositoryRoot, isolate.parent)) {
    throw new Error('Guarded production global package lock path is invalid');
  }
  const parent = lstatSync(dirname(path), { bigint: true });
  const held = fstatSync(fd, { bigint: true });
  const pathname = lstatSync(path, { bigint: true });
  if (!parent.isDirectory()
    || parent.isSymbolicLink()
    || parent.uid !== BigInt(process.getuid())
    || (parent.mode & 0o022n) !== 0n
    || !held.isFile()
    || held.isSymbolicLink()
    || pathname.isSymbolicLink()
    || !sameBigIntState(held, pathname)
    || held.dev !== expectedDev
    || held.ino !== expectedIno
    || held.nlink !== 1n
    || held.uid !== BigInt(process.getuid())
    || (held.mode & 0o777n) !== 0o600n) {
    throw new Error('Guarded production global package lock descriptor is invalid');
  }
  return Object.freeze({
    dev: held.dev,
    fd,
    ino: held.ino,
    path,
    state: held,
  });
}

function assertGuardedGlobalLockUnchanged(authority) {
  const held = fstatSync(authority.fd, { bigint: true });
  const pathname = lstatSync(authority.path, { bigint: true });
  if (!sameBigIntState(authority.state, held)
    || !sameBigIntState(held, pathname)) {
    throw new Error('Guarded production global package lock identity changed');
  }
}

function assertGuardedPackageIsolateUnlinked(authority) {
  const held = fstatSync(authority.fd, { bigint: true });
  if (!held.isDirectory()
    || held.dev !== authority.dev
    || held.ino !== authority.ino
    || held.nlink !== 0n) {
    throw new Error('Guarded production package isolate was not consumed exactly');
  }
}

function rejectUnexpectedGuardedProductionAuthorities() {
  const keys = [
    'PIUI_GUARDED_PRODUCTION_GLOBAL_LOCK_DEV',
    'PIUI_GUARDED_PRODUCTION_GLOBAL_LOCK_FD',
    'PIUI_GUARDED_PRODUCTION_GLOBAL_LOCK_INO',
    'PIUI_GUARDED_PRODUCTION_GLOBAL_LOCK_PATH',
    'PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE',
    'PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE_DEV',
    'PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE_FD',
    'PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE_INO',
  ];
  if (keys.some((key) => process.env[key] !== undefined)) {
    throw new Error('Unexpected guarded production package authority');
  }
}

export function openHeldPackageChildContext(path, expectedBytes) {
  if (!Buffer.isBuffer(expectedBytes)
    || expectedBytes.length < 128
    || expectedBytes.length > 16_384) {
    throw new Error('Package child context bytes are invalid');
  }
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    fchmodSync(fd, 0o400);
    const state = fstatSync(fd, { bigint: true });
    const leaseSha256 = packageChildContextStateSha256(state);
    const digest = sha256Bytes(expectedBytes);
    const bytes = readHeldPackageChildContext({
      fd,
      leaseSha256,
      path,
      sha256: digest,
    });
    if (!bytes.equals(expectedBytes)) {
      throw new Error('Package child context descriptor bytes changed after publication');
    }
    return Object.freeze({ fd, leaseSha256, sha256: digest });
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function bootstrapChildEnvironment({
  bootstrapEnvironment,
  buildPath,
  contextLease,
  contextPath,
  contextSha256,
  evidenceRoot,
  guardedProductionContext,
  nonce,
  sourceDigest,
  syntheticCanaries,
}) {
  const environment = {
    ...bootstrapEnvironment,
    HOME: guardedProductionContext ? resolve(buildPath, 'home') : homedir(),
    LANG: 'en_AU.UTF-8',
    LC_ALL: 'en_AU.UTF-8',
    PATH: process.env.PATH ?? '/usr/bin:/bin:/usr/sbin:/sbin',
    TMPDIR: `${guardedProductionContext ? resolve(buildPath, 'tmp') : temporaryRoot}/`,
    PIUI_PACKAGE_BUILD_ISOLATE: buildPath,
    PIUI_PACKAGE_CHILD_CONTEXT: contextPath,
    PIUI_PACKAGE_CHILD_CONTEXT_FD: String(contextLease.fd),
    PIUI_PACKAGE_CHILD_CONTEXT_LEASE_SHA256: contextLease.leaseSha256,
    PIUI_PACKAGE_CHILD_CONTEXT_SHA256: contextSha256,
    PIUI_PACKAGE_CHILD_NONCE: nonce,
    PIUI_PACKAGE_FROZEN_SOURCE_DIGEST: sourceDigest,
    PIUI_PACKAGE_REPOSITORY_ROOT: repositoryRoot,
    PIUI_PACKAGE_SYNTHETIC_CANARIES: canonicalArchitectureJson(syntheticCanaries),
  };
  if (guardedProductionContext) {
    environment.PIUI_ARCHITECTURE_SOURCE_DIGEST = sourceDigest;
    environment.PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE = buildPath;
    environment.PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE_DEV =
      String(guardedProductionContext.packageIsolateDev);
    environment.PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE_FD =
      process.env.PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE_FD;
    environment.PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE_INO =
      String(guardedProductionContext.packageIsolateIno);
  } else if (typeof process.env.PIUI_ARCHITECTURE_SOURCE_DIGEST === 'string') {
    environment.PIUI_ARCHITECTURE_SOURCE_DIGEST = process.env.PIUI_ARCHITECTURE_SOURCE_DIGEST;
  }
  if (typeof process.env.PIUI_ARCHITECTURE_PRODUCTION_ARTIFACT === 'string') {
    environment.PIUI_ARCHITECTURE_PRODUCTION_ARTIFACT = process.env.PIUI_ARCHITECTURE_PRODUCTION_ARTIFACT;
  }
  if (evidenceRoot) environment.PIUI_A28_HUMAN_EVIDENCE_ROOT = evidenceRoot;
  if (guardedProductionContext) {
    environment.PIUI_GUARDED_PRODUCTION_OUTPUT_ROOT = guardedProductionContext.outputRoot;
  }
  if (architectureGateRun) {
    environment.PIUI_ARCHITECTURE_GATE_RUN_ID = architectureGateRun.runId;
    environment.PIUI_ARCHITECTURE_GATE_RUN_CONTEXT_SHA256 = architectureGateRun.contextSha256;
  }
  return environment;
}

async function runBootstrap() {
  const cutoffs = installParentCutoffs();
  let bootstrapLock;
  let bootstrapIsolate;
  let bootstrapSnapshot;
  let bootstrapTools;
  let bootstrapChildContextLease;
  let evidenceRootIdentity;
  let guardedBootstrap;
  let guardedGlobalLockAuthority;
  let guardedPackageIsolateAuthority;
  let childResult;
  let bootstrapFailure;
  let ambientPrivateValues;
  try {
    assertHost();
    const bootstrapChild = architectureBootstrapChildOptions(repositoryRoot);
    ambientPrivateValues = boundedAmbientPrivateValues(process.env, repositoryRoot);
    if (guardedProduction) {
      guardedPackageIsolateAuthority = await assertGuardedPackageIsolateAuthority({
        dev: process.env.PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE_DEV,
        fd: process.env.PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE_FD,
        ino: process.env.PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE_INO,
        path: process.env.PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE,
      });
      guardedGlobalLockAuthority = assertGuardedGlobalLockAuthority(
        guardedPackageIsolateAuthority,
      );
      if (guardedPackageIsolateAuthority.fd === architectureBootstrap.fd
        || guardedGlobalLockAuthority.fd === architectureBootstrap.fd
        || guardedGlobalLockAuthority.fd === guardedPackageIsolateAuthority.fd) {
        throw new Error('Guarded production authority descriptors alias');
      }
      const outputRootIdentity = await assertGuardedOutputRoot(
        process.env.PIUI_GUARDED_PRODUCTION_OUTPUT_ROOT,
        undefined,
        [],
        guardedPackageIsolateAuthority.parent,
      );
      const gate = assertGuardedGateSummary(
        await validateLatestArchitectureGate(repositoryRoot),
      );
      guardedBootstrap = Object.freeze({
        gate,
        outputRootIdentity,
        packageIsolate: guardedPackageIsolateAuthority,
      });
    } else if (process.env.PIUI_GUARDED_PRODUCTION_OUTPUT_ROOT !== undefined) {
      throw new Error('Unexpected guarded production output root');
    } else {
      rejectUnexpectedGuardedProductionAuthorities();
      bootstrapLock = await acquireOwnedLock(lockPath);
    }
    evidenceRootIdentity = await optionalAccessibilityEvidenceRoot();
    bootstrapIsolate = guardedPackageIsolateAuthority?.path
      ?? await privateTemporary('piui-a21-build-');
    buildIsolate = bootstrapIsolate;
    const bootstrapControlSnapshot = await snapshotArchitectureSource(repositoryRoot);
    configureAuthenticatedNodeSpawn(await createAuthenticatedNodeSpawnConfiguration({
      nodePath: architectureBootstrap.receipt.nodePath,
      snapshot: bootstrapControlSnapshot,
      sourceRoot: repositoryRoot,
    }));
    bootstrapTools = await resolveTrustedTools(bootstrapIsolate);
    const isolatedSource = await createIsolatedBuildSource(
      bootstrapIsolate,
      bootstrapTools,
      cutoffs.signal,
    );
    bootstrapSnapshot = isolatedSource.snapshot;
    if (!equalArchitectureSnapshot(bootstrapControlSnapshot, bootstrapSnapshot)) {
      throw new Error('Authenticated launch source changed before build-source freezing');
    }
    if (guardedBootstrap
      && guardedBootstrap.gate.sourceDigest !== bootstrapSnapshot.source.digest) {
      throw new Error('Guarded production gate source does not match the frozen build source');
    }
    const evidenceRoot = evidenceRootIdentity?.path ?? null;
    const syntheticCanaries = createSyntheticCanaries();
    const nonce = randomBytes(32).toString('hex');
    const contextPath = resolve(bootstrapIsolate, 'child-context.json');
    const guardedProductionContext = guardedBootstrap
      ? {
        outputDev: guardedBootstrap.outputRootIdentity.dev,
        outputIno: guardedBootstrap.outputRootIdentity.ino,
        outputRoot: guardedBootstrap.outputRootIdentity.path,
        packageIsolateDev: Number(guardedBootstrap.packageIsolate.dev),
        packageIsolateIno: Number(guardedBootstrap.packageIsolate.ino),
        productionFingerprint: guardedBootstrap.gate.productionFingerprint,
        runId: guardedBootstrap.gate.runId,
      }
      : null;
    const contextBytes = Buffer.from(`${canonicalArchitectureJson({
      architectureBootstrapPinsSha256: architectureBootstrap.receipt.pinsSha256,
      architectureBootstrapReceiptSha256: architectureBootstrap.receiptSha256,
      architectureGateRunContextSha256: architectureGateRun?.contextSha256 ?? null,
      architectureGateRunId: architectureGateRun?.runId ?? null,
      authenticatedToolchainContextSha256: bootstrapTools.authenticatedToolchainContextSha256,
      authenticatedToolchainReceiptSha256: bootstrapTools.authenticatedToolchainReceiptSha256,
      buildIsolate: bootstrapIsolate,
      dependencyEntries: isolatedSource.dependency.entries,
      dependencyInventorySha256: isolatedSource.dependency.inventorySha256,
      dependencyLeaseSha256: isolatedSource.dependency.leaseSha256,
      evidenceRoot,
      guardedProduction: guardedProductionContext,
      mode: requestedMode,
      nonce,
      repositoryRoot,
      schemaVersion: 1,
      sourceDigest: bootstrapSnapshot.source.digest,
      sourceInputLeaseSha256: sourceLeaseInputSha256(isolatedSource.frozenSnapshot),
      systemOpenSslConfig: bootstrapTools.systemOpenSslConfig,
      syntheticCanarySha256: syntheticCanaries.map((value) => sha256Bytes(Buffer.from(value))),
      toolInputEntries: isolatedSource.toolInput.entries,
      toolInputInventorySha256: isolatedSource.toolInput.inventorySha256,
      toolInputLeaseSha256: isolatedSource.toolInput.leaseSha256,
    })}\n`, 'utf8');
    writeFileSync(contextPath, contextBytes, { flag: 'wx', mode: 0o600 });
    bootstrapChildContextLease = openHeldPackageChildContext(contextPath, contextBytes);
    const childProgress = gateAutomation
      ? createA28ProgressTranscriptForwarder((bytes) => process.stderr.write(bytes))
      : undefined;
    const child = await runOwnedCommand({
      command: process.execPath,
      args: [
        resolve(isolatedSource.root, 'scripts/package-spike.mjs'),
        '--isolated-child',
        requestedMode,
      ],
      cwd: isolatedSource.root,
      env: bootstrapChildEnvironment({
        bootstrapEnvironment: bootstrapChild.environment,
        buildPath: bootstrapIsolate,
        contextLease: bootstrapChildContextLease,
        contextPath,
        contextSha256: bootstrapChildContextLease.sha256,
        evidenceRoot,
        guardedProductionContext,
        nonce,
        sourceDigest: bootstrapSnapshot.source.digest,
        syntheticCanaries,
      }),
      label: 'Frozen-source package proof child',
      inheritedFds: Object.freeze([
        ...bootstrapChild.inheritedFds,
        bootstrapChildContextLease.fd,
        ...(guardedPackageIsolateAuthority
          ? [guardedPackageIsolateAuthority.fd]
          : []),
      ]),
      maxOutputBytes: 4 * 1_048_576,
      signal: cutoffs.signal,
      ...(childProgress
        ? { stderrObserver: (bytes) => childProgress.push(bytes) }
        : {}),
      timeoutMs: gateAutomation ? 3 * 60 * 60_000 : 90 * 60_000,
    });
    const forwardedChildStderr = childProgress
      ? childProgress.finish({ allowEmpty: true })
      : Buffer.alloc(0);
    assertBuffersExcludeValues(
      [child.stdout, child.stderr],
      ambientPrivateValues,
      'Frozen-source package proof child output',
    );
    if (child.status !== 0
      || child.signal !== null
      || !child.stderr.equals(forwardedChildStderr)
      || child.forcedCleanup) {
      const failurePhase = parseIsolatedChildFailurePhase(child.stderr);
      const error = new Error(child.status === 2
        ? 'A.28 accessibility proof blocked'
        : `Frozen-source package proof child failed [phase=${failurePhase}]`);
      if (child.status === 2) error.code = 'PIUI_A28_ACCESSIBILITY_BLOCKED';
      throw error;
    }
    childResult = guardedBootstrap
      ? parseGuardedProductionResult(child.stdout, {
        expectedFingerprint: guardedBootstrap.gate.productionFingerprint,
        expectedRunId: guardedBootstrap.gate.runId,
        expectedSourceDigest: guardedBootstrap.gate.sourceDigest,
        requireCleanup: true,
      })
      : parseIsolatedChildResult(child.stdout);
    await assertPathAbsent(bootstrapIsolate, 'Owned build isolate');
    if (guardedPackageIsolateAuthority) {
      assertGuardedPackageIsolateUnlinked(guardedPackageIsolateAuthority);
      assertGuardedGlobalLockUnchanged(guardedGlobalLockAuthority);
    }
    const finalRepository = await snapshotArchitectureSource(repositoryRoot);
    if (!equalArchitectureSnapshot(bootstrapSnapshot, finalRepository)
      || !equalArchitectureSourceLease(bootstrapSnapshot, finalRepository)) {
      throw new Error('Architecture source changed during the frozen package proof');
    }
    if (guardedBootstrap) {
      await assertGuardedOutputRoot(
        guardedBootstrap.outputRootIdentity.path,
        guardedBootstrap.outputRootIdentity,
        ['PIUI.app'],
        guardedBootstrap.packageIsolate.parent,
      );
      const outputInventory = await inventoryBundle(resolve(
        guardedBootstrap.outputRootIdentity.path,
        'PIUI.app',
      ));
      if (outputInventory.fingerprint !== guardedBootstrap.gate.productionFingerprint) {
        throw new Error('Guarded production output fingerprint changed after isolation cleanup');
      }
      const finalGate = assertGuardedGateSummary(
        await validateLatestArchitectureGate(repositoryRoot),
      );
      if (canonicalArchitectureJson(finalGate)
        !== canonicalArchitectureJson(guardedBootstrap.gate)) {
        throw new Error('Architecture gate changed during the guarded production build');
      }
    }
  } catch (error) {
    bootstrapFailure = error;
  } finally {
    if (bootstrapChildContextLease) {
      try {
        closeSync(bootstrapChildContextLease.fd);
      } catch (error) {
        bootstrapFailure = bootstrapFailure
          ? new AggregateError([bootstrapFailure, error], 'Package bootstrap and context release failed')
          : error;
      }
    }
    if (evidenceRootIdentity) {
      try {
        await assertAccessibilityEvidenceRoot(
          evidenceRootIdentity.path,
          evidenceRootIdentity,
        );
      } catch (error) {
        bootstrapFailure = bootstrapFailure
          ? new AggregateError([bootstrapFailure, error], 'Package bootstrap and evidence recheck failed')
          : error;
      }
    }
    if (bootstrapIsolate) {
      try {
        await removeOwnedTree(bootstrapIsolate);
        await assertPathAbsent(bootstrapIsolate, 'Owned build isolate');
      } catch (error) {
        bootstrapFailure = bootstrapFailure
          ? new AggregateError([bootstrapFailure, error], 'Package bootstrap and cleanup failed')
          : error;
      }
    }
    if (bootstrapLock) {
      try {
        await releaseOwnedLock(bootstrapLock);
      } catch (error) {
        bootstrapFailure ??= error;
      }
    }
    if (guardedGlobalLockAuthority) {
      try {
        assertGuardedGlobalLockUnchanged(guardedGlobalLockAuthority);
      } catch (error) {
        bootstrapFailure = bootstrapFailure
          ? new AggregateError(
            [bootstrapFailure, error],
            'Package bootstrap and global lock recheck failed',
          )
          : error;
      } finally {
        closeSync(guardedGlobalLockAuthority.fd);
      }
    }
    if (guardedPackageIsolateAuthority) {
      try {
        assertGuardedPackageIsolateUnlinked(guardedPackageIsolateAuthority);
      } catch (error) {
        bootstrapFailure = bootstrapFailure
          ? new AggregateError(
            [bootstrapFailure, error],
            'Package bootstrap and isolate authority recheck failed',
          )
          : error;
      } finally {
        closeSync(guardedPackageIsolateAuthority.fd);
      }
    }
    cutoffs.dispose();
  }
  if (bootstrapFailure) {
    if (gateAutomation) {
      process.stderr.write('[working] A.28 package proof failed closed.\n');
    } else {
      console.error(`A.21 package gate failed: ${redactedMessage(bootstrapFailure)}`);
    }
    process.exitCode = bootstrapFailure?.code === 'PIUI_A28_ACCESSIBILITY_BLOCKED' ? 2 : 1;
    return;
  }
  const canonicalOutput = requestedMode !== 'a21';
  process.stdout.write(`${canonicalOutput
    ? canonicalArchitectureJson(childResult)
    : JSON.stringify(childResult, null, 2)}\n`);
}

function seatbeltPath(path) {
  return path.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
}

function assertHost() {
  if (platform() !== 'darwin' || arch() !== 'arm64') throw new Error('A.21 requires Apple Silicon macOS');
}

function equalArchitectureSnapshot(left, right) {
  return left.inventoryBytes.equals(right.inventoryBytes)
    && canonicalArchitectureJson(left.source) === canonicalArchitectureJson(right.source);
}

function requiredFrozenSourceSha256(path) {
  const matches = frozenSource?.inventory?.filter((entry) => entry.path === path);
  if (!Array.isArray(matches)
    || matches.length !== 1
    || typeof matches[0].sha256 !== 'string'
    || !sha256Pattern.test(matches[0].sha256)) {
    throw new Error(`Frozen source inventory is missing ${path}`);
  }
  return matches[0].sha256;
}

async function readTrustedRegularFile(path, expected, label) {
  let handle;
  try {
    handle = await openFile(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    if (!before.isFile()
      || before.nlink !== 1
      || (before.mode & 0o022) !== 0
      || (typeof process.getuid === 'function' && before.uid !== process.getuid())) {
      throw new Error(`${label} is not a trusted regular file`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const pathAfter = await lstat(path);
    if (after.dev !== before.dev
      || after.ino !== before.ino
      || after.size !== before.size
      || after.mode !== before.mode
      || after.mtimeMs !== before.mtimeMs
      || pathAfter.isSymbolicLink()
      || pathAfter.dev !== after.dev
      || pathAfter.ino !== after.ino
      || bytes.length !== before.size) {
      throw new Error(`${label} changed during verification`);
    }
    if (expected && (bytes.length !== expected.size
      || sha256Bytes(bytes) !== expected.sha256
      || ((before.mode & 0o111) !== 0) !== expected.executable)) {
      throw new Error(`${label} does not match the frozen source inventory`);
    }
    return bytes;
  } finally {
    await handle?.close();
  }
}

async function copyFrozenSourceFile(root, cloneRoot, entry) {
  const source = resolve(root, entry.path);
  const destination = resolve(cloneRoot, entry.path);
  if (relative(root, source).startsWith('..') || relative(cloneRoot, destination).startsWith('..')) {
    throw new Error('Frozen source path escaped its root');
  }
  const bytes = await readTrustedRegularFile(source, entry, 'Frozen source file');
  mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
  writeFileSync(destination, bytes, {
    flag: 'wx',
    mode: entry.executable ? 0o700 : 0o600,
  });
  const copied = await readTrustedRegularFile(destination, entry, 'Copied source file');
  if (!copied.equals(bytes)) throw new Error('Copied source bytes changed after publication');
}

function dependencyInstallRoots(cloneRoot) {
  return [
    resolve(cloneRoot, 'node_modules'),
    resolve(cloneRoot, 'packages/protocol/node_modules'),
    resolve(cloneRoot, 'sidecar/node_modules'),
  ];
}

async function materialiseFrozenDependencies(cloneRoot, isolateRoot, tools, signal) {
  const installRoots = dependencyInstallRoots(cloneRoot);
  for (const path of installRoots) mkdirSync(path, { recursive: true, mode: 0o700 });
  const working = resolve(isolateRoot, 'dependency-install');
  const home = resolve(working, 'home');
  const temporary = resolve(working, 'tmp');
  const cache = resolve(working, 'cache');
  for (const path of [working, home, temporary, cache]) {
    mkdirSync(path, { recursive: true, mode: 0o700 });
  }
  const sandboxInputs = {
    authenticatedCommand: tools.pnpmNode,
    executableFiles: [tools.pnpmNode],
    executableRoots: [],
    readableFiles: [tools.pnpmNode, ...tools.nodeRuntimeFiles],
    readableRoots: [
      cloneRoot,
      working,
      tools.pnpmRoot,
      tools.store,
      '/Library/Apple/System/Library',
      '/System/Library',
      '/usr/lib',
    ],
    writableFiles: [...installRoots],
    writableRoots: [...installRoots, working],
  };
  const profile = buildSandboxFor(sandboxInputs);
  authoriseAuthenticatedNodeSandboxProfile({
    command: tools.pnpmNode,
    policy: authenticatedBuildSandboxPolicy(sandboxInputs),
    profile,
  });
  const result = await runOwnedCommand({
    command: tools.pnpmNode,
    args: [
      tools.pnpmEntry,
      'install',
      '--offline',
      '--frozen-lockfile',
      '--ignore-scripts',
      '--config.node-linker=hoisted',
      '--config.package-import-method=copy',
      `--store-dir=${tools.store}`,
    ],
    cwd: cloneRoot,
    env: {
      HOME: home,
      CFFIXED_USER_HOME: home,
      TMPDIR: `${temporary}/`,
      XDG_CACHE_HOME: cache,
      npm_config_cache: cache,
      COREPACK_ENABLE_DOWNLOAD_PROMPT: '0',
      LANG: 'en_AU.UTF-8',
      LC_ALL: 'en_AU.UTF-8',
      PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    },
    label: 'Frozen-lock private dependency materialisation',
    maxOutputBytes: 4 * 1_048_576,
    sandboxProfile: profile,
    signal,
    timeoutMs: 10 * 60_000,
  });
  if (result.status !== 0
    || result.signal !== null
    || result.forcedCleanup
    || result.stderr.length > 256 * 1024) {
    throw new Error('Frozen-lock private dependency materialisation failed');
  }
  const after = await snapshotArchitectureSource(cloneRoot);
  return Object.freeze({ installRoots: Object.freeze(installRoots), source: after });
}

function sameBigIntState(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

async function captureInputTree(boundaryRoot, inputRoot, {
  allowedLinkRoots = [boundaryRoot],
  excludedPaths = [],
  includeHashes,
  label,
  maxFiles,
  maxTotalBytes,
}) {
  const canonicalBoundary = await realpath(boundaryRoot);
  const canonicalRoot = await realpath(inputRoot);
  if (canonicalBoundary !== boundaryRoot
    || canonicalRoot !== inputRoot
    || typeof includeHashes !== 'boolean'
    || typeof label !== 'string'
    || !Array.isArray(allowedLinkRoots)
    || allowedLinkRoots.length < 1
    || allowedLinkRoots.length > 32
    || allowedLinkRoots.some((root) => typeof root !== 'string')
    || !Array.isArray(excludedPaths)
    || excludedPaths.length > 32
    || excludedPaths.some((path) => typeof path !== 'string')
    || !Number.isSafeInteger(maxFiles)
    || maxFiles < 1
    || !Number.isSafeInteger(maxTotalBytes)
    || maxTotalBytes < 1) {
    throw new Error(`${label} root is not canonical`);
  }
  const canonicalAllowedLinkRoots = [];
  for (const root of allowedLinkRoots) {
    const canonical = await realpath(root);
    if (canonical !== root) throw new Error(`${label} link boundary is not canonical`);
    canonicalAllowedLinkRoots.push(canonical);
  }
  const excluded = new Set(excludedPaths);
  if ([...excluded].some((path) => (
    path !== resolve(path)
    || (path !== canonicalRoot && !path.startsWith(`${canonicalRoot}/`))
  ))) {
    throw new Error(`${label} exclusions are invalid`);
  }
  const expectedUid = typeof process.getuid === 'function' ? BigInt(process.getuid()) : null;
  if (expectedUid === null) throw new Error(`${label} owner is unavailable`);
  const inventory = [];
  const lease = [];
  const executables = [];
  let files = 0;
  let totalBytes = 0;
  async function visit(path, pathLabel) {
    const before = await lstat(path, { bigint: true });
    if (before.uid !== expectedUid
      || (!before.isSymbolicLink() && (before.mode & 0o022n) !== 0n)) {
      throw new Error(`${label} tree contains an unsafe entry`);
    }
    const record = {
      ctimeNs: before.ctimeNs.toString(10),
      dev: before.dev.toString(10),
      gid: before.gid.toString(10),
      ino: before.ino.toString(10),
      mode: before.mode.toString(10),
      mtimeNs: before.mtimeNs.toString(10),
      nlink: before.nlink.toString(10),
      path: pathLabel,
      size: before.size.toString(10),
      uid: before.uid.toString(10),
    };
    if (before.isSymbolicLink()) {
      const link = await readlink(path);
      const target = await realpath(path);
      if (!canonicalAllowedLinkRoots.some((root) => (
        target === root || target.startsWith(`${root}/`)
      ))) {
        throw new Error(`${label} link escaped its boundary`);
      }
      const targetState = await lstat(target, { bigint: true });
      const after = await lstat(path, { bigint: true });
      if (!sameBigIntState(before, after)) {
        throw new Error(`${label} link changed during inspection`);
      }
      if (targetState.isFile() && (targetState.mode & 0o111n) !== 0n) {
        executables.push(path);
      }
      lease.push({ ...record, kind: 'symlink', link });
      inventory.push({
        kind: 'symlink',
        link,
        path: pathLabel,
        target: target === canonicalBoundary || target.startsWith(`${canonicalBoundary}/`)
          ? relative(canonicalBoundary, target).split('/').join('/')
          : target,
      });
      return;
    }
    if (before.isDirectory()) {
      lease.push({ ...record, kind: 'directory' });
      inventory.push({ kind: 'directory', path: pathLabel });
      const entries = await readdir(path, { withFileTypes: true });
      entries.sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
      for (const entry of entries) {
        const child = resolve(path, entry.name);
        if (excluded.has(child)) continue;
        const childLabel = pathLabel === '.' ? entry.name : `${pathLabel}/${entry.name}`;
        await visit(child, childLabel);
      }
      const after = await lstat(path, { bigint: true });
      if (!sameBigIntState(before, after)) {
        throw new Error(`${label} directory changed during inspection`);
      }
      return;
    }
    if (!before.isFile() || before.nlink !== 1n || before.size < 0n) {
      throw new Error(`${label} tree contains an unsupported entry`);
    }
    files += 1;
    totalBytes += Number(before.size);
    if (!Number.isSafeInteger(totalBytes)
      || files > maxFiles
      || totalBytes > maxTotalBytes) {
      throw new Error(`${label} tree exceeds its inspection bounds`);
    }
    let sha256;
    if (includeHashes) {
      const bytes = await readTrustedRegularFile(path, undefined, `${label} file`);
      sha256 = sha256Bytes(bytes);
    }
    const after = await lstat(path, { bigint: true });
    if (!sameBigIntState(before, after)) {
      throw new Error(`${label} file changed during inspection`);
    }
    if ((before.mode & 0o111n) !== 0n) executables.push(path);
    lease.push({ ...record, kind: 'file' });
    if (includeHashes) {
      inventory.push({
        executable: (before.mode & 0o111n) !== 0n,
        path: pathLabel,
        sha256,
        size: Number(before.size),
      });
    }
  }
  await visit(canonicalRoot, '.');
  const leaseBytes = Buffer.from(`${canonicalArchitectureJson(lease)}\n`, 'utf8');
  const inventoryBytes = includeHashes
    ? Buffer.from(`${canonicalArchitectureJson(inventory)}\n`, 'utf8')
    : undefined;
  return Object.freeze({
    entries: lease.length,
    inventoryBytes,
    inventorySha256: inventoryBytes ? sha256Bytes(inventoryBytes) : undefined,
    leaseBytes,
    leaseSha256: sha256Bytes(leaseBytes),
    executables: Object.freeze(executables.sort((left, right) => (
      Buffer.from(left).compare(Buffer.from(right))
    ))),
    root: canonicalRoot,
  });
}

export async function captureDependencyTree(frozenRoot, dependencyRoot, { includeHashes }) {
  try {
    return await captureInputTree(frozenRoot, dependencyRoot, {
      includeHashes,
      label: 'Private dependency',
      maxFiles: 100_000,
      maxTotalBytes: 2 * 1_024 * 1_024 * 1_024,
    });
  } catch (error) {
    if (error?.message === 'Private dependency link escaped its boundary') {
      throw new Error('Private dependency link escaped the frozen source');
    }
    throw error;
  }
}

export async function captureToolInputTree(root, { includeHashes }) {
  return captureInputTree(root, root, {
    includeHashes,
    label: 'Build tool input',
    maxFiles: 200_000,
    maxTotalBytes: 4 * 1_024 * 1_024 * 1_024,
  });
}

async function sealDependencyTree(root) {
  async function seal(path) {
    const state = await lstat(path);
    if (state.isSymbolicLink()) return;
    if (state.isDirectory()) {
      for (const name of await readdir(path)) await seal(resolve(path, name));
      await chmod(path, 0o500);
      return;
    }
    if (!state.isFile() || state.nlink !== 1) {
      throw new Error('Private dependency tree cannot be sealed');
    }
    await chmod(path, (state.mode & 0o111) !== 0 ? 0o500 : 0o400);
  }
  await seal(root);
}

async function captureDependencySet(frozenRoot, roots, { includeHashes }) {
  const items = [];
  for (const root of roots) {
    const state = await lstat(root);
    if (!state.isDirectory() || state.isSymbolicLink()) {
      throw new Error('Private dependency install root is unsafe');
    }
    const witness = await captureDependencyTree(frozenRoot, root, { includeHashes });
    items.push(Object.freeze({
      ...witness,
      rootLabel: relative(frozenRoot, root).split('/').join('/'),
    }));
  }
  const inventoryBytes = includeHashes
    ? Buffer.from(`${canonicalArchitectureJson(items.map((item) => ({
      inventorySha256: item.inventorySha256,
      rootLabel: item.rootLabel,
    })))}\n`, 'utf8')
    : undefined;
  const leaseBytes = Buffer.from(`${canonicalArchitectureJson(items.map((item) => ({
    leaseSha256: item.leaseSha256,
    rootLabel: item.rootLabel,
  })))}\n`, 'utf8');
  return Object.freeze({
    entries: items.reduce((total, item) => total + item.entries, 0),
    executables: Object.freeze([...new Set(items.flatMap((item) => item.executables))]
      .sort((left, right) => Buffer.from(left).compare(Buffer.from(right)))),
    inventorySha256: inventoryBytes ? sha256Bytes(inventoryBytes) : undefined,
    items: Object.freeze(items),
    leaseSha256: sha256Bytes(leaseBytes),
  });
}

async function captureToolInputSet(roots, { includeHashes }) {
  if (!Array.isArray(roots)
    || roots.length < 1
    || roots.length > 16
    || roots.some((item) => (
      !item
      || typeof item !== 'object'
      || Array.isArray(item)
      || Object.keys(item).sort().join(',') !== 'label,root'
      || typeof item.label !== 'string'
      || !/^[a-z][a-z0-9-]{0,63}$/u.test(item.label)
      || typeof item.root !== 'string'
    ))
    || new Set(roots.map((item) => item.label)).size !== roots.length) {
    throw new Error('Build tool input roots are invalid');
  }
  const ordered = [...roots].sort((left, right) => (
    Buffer.from(left.label).compare(Buffer.from(right.label))
  ));
  const items = [];
  for (const input of ordered) {
    const witness = await captureToolInputTree(input.root, { includeHashes });
    items.push(Object.freeze({ ...witness, label: input.label }));
  }
  const inventoryBytes = includeHashes
    ? Buffer.from(`${canonicalArchitectureJson(items.map((item) => ({
      inventorySha256: item.inventorySha256,
      label: item.label,
      root: item.root,
    })))}\n`, 'utf8')
    : undefined;
  const leaseBytes = Buffer.from(`${canonicalArchitectureJson(items.map((item) => ({
    label: item.label,
    leaseSha256: item.leaseSha256,
    root: item.root,
  })))}\n`, 'utf8');
  return Object.freeze({
    entries: items.reduce((total, item) => total + item.entries, 0),
    inventorySha256: inventoryBytes ? sha256Bytes(inventoryBytes) : undefined,
    items: Object.freeze(items),
    leaseBytes,
    leaseSha256: sha256Bytes(leaseBytes),
  });
}

function equalInputSetLease(expected, actual) {
  return actual.entries === expected.entries
    && actual.leaseSha256 === expected.leaseSha256
    && actual.items.length === expected.items.length
    && actual.items.every((item, index) => (
      item.label === expected.items[index]?.label
      && item.root === expected.items[index]?.root
      && item.leaseBytes.equals(expected.items[index]?.leaseBytes)
    ));
}

export function privateBuildControlChangeClass(expected, actual) {
  if (!expected || !actual
    || expected.label !== actual.label
    || expected.root !== actual.root
    || !Buffer.isBuffer(expected.leaseBytes)
    || !Buffer.isBuffer(actual.leaseBytes)) {
    return 'other';
  }
  let expectedLease;
  let actualLease;
  try {
    expectedLease = JSON.parse(expected.leaseBytes.toString('utf8'));
    actualLease = JSON.parse(actual.leaseBytes.toString('utf8'));
  } catch {
    return 'malformed';
  }
  if (!Array.isArray(expectedLease)
    || !Array.isArray(actualLease)
    || expectedLease.length !== actualLease.length) {
    return 'entry-set';
  }
  for (let index = 0; index < expectedLease.length; index += 1) {
    const left = expectedLease[index];
    const right = actualLease[index];
    if (!left || !right || typeof left !== 'object' || typeof right !== 'object') {
      return 'malformed';
    }
    const root = left.path === '.' && right.path === '.';
    const prefix = root ? 'root' : 'entry';
    if (left.path !== right.path || left.kind !== right.kind || left.link !== right.link) {
      return 'entry-set';
    }
    if (left.dev !== right.dev || left.ino !== right.ino) return `${prefix}-identity`;
    if (left.mode !== right.mode
      || left.uid !== right.uid
      || left.gid !== right.gid
      || left.nlink !== right.nlink) {
      return `${prefix}-permissions`;
    }
    if (left.size !== right.size) return `${prefix}-size`;
    if (left.mtimeNs !== right.mtimeNs || left.ctimeNs !== right.ctimeNs) {
      return `${prefix}-timestamps`;
    }
    if (canonicalArchitectureJson(left) !== canonicalArchitectureJson(right)) return 'other';
  }
  return expected.leaseSha256 === actual.leaseSha256 ? undefined : 'other';
}

async function capturePrivateBuildInputSet(
  isolateRoot,
  roots,
  allowedLinkRoots,
  excludedPaths,
  { includeHashes },
) {
  const ordered = [...roots].sort((left, right) => (
    Buffer.from(left.label).compare(Buffer.from(right.label))
  ));
  const items = [];
  for (const input of ordered) {
    const inputExclusions = excludedPaths.filter((path) => (
      path === input.root || path.startsWith(`${input.root}/`)
    ));
    const witness = await captureInputTree(isolateRoot, input.root, {
      allowedLinkRoots,
      excludedPaths: inputExclusions,
      includeHashes,
      label: 'Private build control input',
      maxFiles: 10_000,
      maxTotalBytes: 512 * 1_024 * 1_024,
    });
    items.push(Object.freeze({ ...witness, label: input.label }));
  }
  const inventoryBytes = includeHashes
    ? Buffer.from(`${canonicalArchitectureJson(items.map((item) => ({
      inventorySha256: item.inventorySha256,
      label: item.label,
      root: item.root,
    })))}\n`, 'utf8')
    : undefined;
  const leaseBytes = Buffer.from(`${canonicalArchitectureJson(items.map((item) => ({
    label: item.label,
    leaseSha256: item.leaseSha256,
    root: item.root,
  })))}\n`, 'utf8');
  return Object.freeze({
    entries: items.reduce((total, item) => total + item.entries, 0),
    inventorySha256: inventoryBytes ? sha256Bytes(inventoryBytes) : undefined,
    items: Object.freeze(items),
    leaseBytes,
    leaseSha256: sha256Bytes(leaseBytes),
  });
}

async function readPinnedNodeArchive() {
  let manifest;
  try {
    manifest = JSON.parse(await readFile(resolve(repositoryRoot, 'scripts/node-checksums.json'), 'utf8'));
  } catch {
    throw new Error('Pinned Node checksum manifest is invalid');
  }
  const pin = manifest?.['22.23.1']?.['darwin-arm64'];
  if (!pin
    || typeof pin.archive !== 'string'
    || !/^node-v22\.23\.1-darwin-arm64\.tar\.gz$/u.test(pin.archive)
    || typeof pin.sha256 !== 'string'
    || !/^[0-9a-f]{64}$/u.test(pin.sha256)) {
    throw new Error('Pinned Node checksum manifest does not contain the exact architecture pin');
  }
  const source = architectureCacheEntryPath(architectureToolchainPins.node);
  const bytes = await readTrustedRegularFile(source, undefined, 'Pinned Node archive');
  if (sha256Bytes(bytes) !== pin.sha256) throw new Error('Pinned Node archive checksum mismatch');
  return Object.freeze({ bytes, pin });
}

async function installPinnedNodeArchive(cloneRoot, tools) {
  const pin = architectureToolchainPins.node;
  if (!tools
    || typeof tools.nodeArchive !== 'string'
    || !tools.nodeArchive.startsWith(`${tools.closureRoot}/`)) {
    throw new Error('Authenticated Node archive is unavailable');
  }
  const bytes = await readTrustedRegularFile(
    tools.nodeArchive,
    undefined,
    'Authenticated private Node archive',
  );
  if (bytes.length !== pin.minBytes
    || pin.minBytes !== pin.maxBytes
    || sha256Bytes(bytes) !== pin.digest) {
    throw new Error('Authenticated private Node archive does not match its exact pin');
  }
  const cache = resolve(cloneRoot, '.cache/node-runtime');
  mkdirSync(cache, { recursive: true, mode: 0o700 });
  const destination = resolve(cache, pin.filename);
  writeFileSync(destination, bytes, { flag: 'wx', mode: 0o600 });
  const copied = await readTrustedRegularFile(destination, undefined, 'Copied pinned Node archive');
  if (!copied.equals(bytes) || sha256Bytes(copied) !== pin.digest) {
    throw new Error('Copied pinned Node archive failed byte verification');
  }
  const cacheEntries = await readdir(cache);
  if (cacheEntries.length !== 1 || cacheEntries[0] !== pin.filename) {
    throw new Error('Isolated Node cache contains an unpinned entry');
  }
}

export async function preparePinnedNodeTool(isolateRoot) {
  if (typeof isolateRoot !== 'string' || resolve(isolateRoot) !== isolateRoot) {
    throw new Error('Pinned Node tool isolate is not canonical');
  }
  const toolRoot = resolve(isolateRoot, 'tools');
  try {
    mkdirSync(toolRoot, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  await assertPrivateDirectory(toolRoot, 'Pinned Node tool root');
  const { bytes: archiveBytes, pin } = await readPinnedNodeArchive();
  if (archiveBytes.length < 1_048_576 || archiveBytes.length > 64 * 1_048_576) {
    throw new Error('Pinned Node archive size is invalid');
  }
  const member = architectureToolchainPins.node.member;
  const extracted = spawnSync('/usr/bin/bsdtar', ['-xOf', '-', member], {
    encoding: null,
    env: { LANG: 'en_AU.UTF-8', LC_ALL: 'en_AU.UTF-8', PATH: '/usr/bin:/bin' },
    input: archiveBytes,
    maxBuffer: 256 * 1_048_576,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  if (extracted.status !== 0
    || extracted.signal !== null
    || !Buffer.isBuffer(extracted.stdout)
    || extracted.stdout.length < 10 * 1_048_576
    || extracted.stdout.length > 256 * 1_048_576
    || !Buffer.isBuffer(extracted.stderr)
    || extracted.stderr.length !== 0
    || sha256Bytes(extracted.stdout) !== architectureToolchainPins.node.executableSha256) {
    throw new Error('Pinned Node executable extraction failed');
  }
  const node = resolve(toolRoot, 'node');
  try {
    writeFileSync(node, extracted.stdout, { flag: 'wx', mode: 0o500 });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  const installed = await readTrustedRegularFile(node, undefined, 'Pinned Node executable');
  const state = await lstat(node);
  if (!installed.equals(extracted.stdout)
    || (state.mode & 0o777) !== 0o500
    || pin.archive !== architectureToolchainPins.node.filename
    || sha256Bytes(installed) !== architectureToolchainPins.node.executableSha256) {
    throw new Error('Pinned Node executable failed byte verification');
  }
  return Object.freeze({
    node,
    nodeRuntimeFiles: await trustedNodeRuntimeFiles(node),
  });
}

export async function createIsolatedBuildSource(isolateRoot, tools, signal) {
  const cloneRoot = resolve(isolateRoot, 'source');
  mkdirSync(cloneRoot, { mode: 0o700 });
  const initial = await snapshotArchitectureSource(repositoryRoot);
  for (const entry of initial.inventory) {
    await copyFrozenSourceFile(repositoryRoot, cloneRoot, entry);
  }
  const copied = await snapshotArchitectureSource(cloneRoot);
  const finalRepository = await snapshotArchitectureSource(repositoryRoot);
  if (!equalArchitectureSnapshot(initial, copied)
    || !equalArchitectureSnapshot(initial, finalRepository)
    || !equalArchitectureSourceLease(initial, finalRepository)) {
    throw new Error('Architecture source changed while the isolated build source was frozen');
  }
  await installPinnedNodeArchive(cloneRoot, tools);
  const dependencies = await materialiseFrozenDependencies(
    cloneRoot,
    isolateRoot,
    tools,
    signal,
  );
  if (!equalArchitectureSnapshot(initial, dependencies.source)) {
    throw new Error('Frozen-lock dependency materialisation changed source inputs');
  }
  const toolInputAfterMaterialisation = await captureToolInputSet(
    tools.toolInputRoots,
    { includeHashes: false },
  );
  if (!equalInputSetLease(tools.toolInput, toolInputAfterMaterialisation)) {
    throw new Error('Build tool inputs changed during private dependency materialisation');
  }
  const outputs = generatedOutputsFor(cloneRoot);
  await prepareGeneratedOutputs(outputs);
  for (const dependencyRoot of dependencies.installRoots) {
    await sealDependencyTree(dependencyRoot);
  }
  const beforeSourceSeal = await snapshotArchitectureSource(cloneRoot);
  await sealFrozenSourceInputs(cloneRoot, beforeSourceSeal);
  const frozenSnapshot = await snapshotArchitectureSource(cloneRoot);
  if (!equalArchitectureSnapshot(initial, frozenSnapshot)) {
    throw new Error('Sealed frozen source differs from its accepted source inputs');
  }
  const dependency = await captureDependencySet(
    cloneRoot,
    dependencies.installRoots,
    { includeHashes: true },
  );
  return Object.freeze({
    dependency,
    frozenSnapshot,
    outputs,
    root: cloneRoot,
    snapshot: initial,
    toolInput: tools.toolInput,
  });
}

function exactArchitectureSourceDigest(value, snapshot) {
  if (typeof value !== 'string'
    || !/^[0-9a-f]{64}$/u.test(value)
    || value !== snapshot.source.digest) {
    throw new Error('Architecture proof source digest does not match the frozen source');
  }
  return value;
}

function parseReceivedProductionArtifact(value) {
  if (typeof value !== 'string'
    || value.length < 3
    || value.length > 16_384
    || value.includes('\r')
    || value.includes('\n')
    || value.includes('\0')) {
    throw new Error('Architecture production artefact metadata is unavailable');
  }
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error('Architecture production artefact metadata is invalid');
  }
  if (canonicalArchitectureJson(parsed) !== value) {
    throw new Error('Architecture production artefact metadata is not canonical');
  }
  return Object.freeze({ ...assertArchitectureArtifact(parsed, 'production') });
}

function exactObjectKeys(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} is not an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} fields are not exact`);
  }
}

function parseCanonicalControlBytes(bytes, maximumBytes, label) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 3
    || bytes.length > maximumBytes
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
    || bytes.includes(0x00)) {
    throw new Error(`${label} is not a bounded canonical line`);
  }
  let value;
  try {
    value = JSON.parse(bytes.subarray(0, -1).toString('utf8'));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  if (`${canonicalArchitectureJson(value)}\n` !== bytes.toString('utf8')) {
    throw new Error(`${label} is not canonical`);
  }
  return value;
}

async function assertPrivateDirectory(path, label) {
  const item = await lstat(path);
  if (!item.isDirectory()
    || item.isSymbolicLink()
    || (item.mode & 0o777) !== 0o700
    || (typeof process.getuid === 'function' && item.uid !== process.getuid())
    || await realpath(path) !== path) {
    throw new Error(`${label} is not a private canonical directory`);
  }
}

function assertGuardedGateSummary(gate) {
  exactObjectKeys(gate, [
    'decision',
    'distributionAuthorised',
    'productionFingerprint',
    'runId',
    'sourceDigest',
    'target',
  ], 'Architecture gate summary');
  if (gate.decision !== 'pass'
    || gate.distributionAuthorised !== false
    || typeof gate.productionFingerprint !== 'string'
    || !sha256Pattern.test(gate.productionFingerprint)
    || typeof gate.runId !== 'string'
    || !architectureRunId.test(gate.runId)
    || typeof gate.sourceDigest !== 'string'
    || !sha256Pattern.test(gate.sourceDigest)
    || gate.target !== target) {
    throw new Error('Architecture gate did not authorise the guarded local production build');
  }
  return Object.freeze({ ...gate });
}

async function assertGuardedOutputRoot(
  path,
  expectedIdentity,
  expectedEntries,
  expectedTemporaryParent = temporaryRoot,
) {
  if (typeof path !== 'string'
    || resolve(path) !== path
    || dirname(path) !== expectedTemporaryParent
    || await realpath(expectedTemporaryParent) !== expectedTemporaryParent) {
    throw new Error('Guarded production output root is not an exact temporary child');
  }
  await assertPrivateDirectory(path, 'Guarded production output root');
  const state = await lstat(path);
  if (expectedIdentity
    && (state.dev !== expectedIdentity.dev || state.ino !== expectedIdentity.ino)) {
    throw new Error('Guarded production output root identity changed');
  }
  const entries = await readdir(path, { withFileTypes: true });
  entries.sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
  if (entries.length !== expectedEntries.length
    || entries.some((entry, index) => entry.name !== expectedEntries[index]
      || (entry.name === 'PIUI.app' && !entry.isDirectory()))) {
    throw new Error('Guarded production output inventory is not exact');
  }
  return Object.freeze({ dev: state.dev, ino: state.ino, path });
}

async function validateIsolatedChildContext() {
  const buildPath = process.env.PIUI_PACKAGE_BUILD_ISOLATE;
  const contextPath = process.env.PIUI_PACKAGE_CHILD_CONTEXT;
  const contextFdText = process.env.PIUI_PACKAGE_CHILD_CONTEXT_FD;
  const contextLeaseSha256 = process.env.PIUI_PACKAGE_CHILD_CONTEXT_LEASE_SHA256;
  const contextSha256 = process.env.PIUI_PACKAGE_CHILD_CONTEXT_SHA256;
  const childNonce = process.env.PIUI_PACKAGE_CHILD_NONCE;
  const sourceDigest = process.env.PIUI_PACKAGE_FROZEN_SOURCE_DIGEST;
  let contextFd;
  try {
    contextFd = parsePackageChildDescriptor(contextFdText);
  } catch {
    throw new Error('Isolated package child authentication is incomplete');
  }
  if (process.env.PIUI_PACKAGE_REPOSITORY_ROOT !== repositoryRoot
    || ![buildPath, contextPath, contextFdText, contextLeaseSha256,
      contextSha256, childNonce, sourceDigest]
    .every((value) => typeof value === 'string' && value.length > 0)
    || !/^[0-9a-f]{64}$/u.test(contextLeaseSha256)
    || !/^[0-9a-f]{64}$/u.test(contextSha256)
    || !/^[0-9a-f]{64}$/u.test(childNonce)
    || !/^[0-9a-f]{64}$/u.test(sourceDigest)) {
    throw new Error('Isolated package child authentication is incomplete');
  }
  const canonicalBuild = resolve(buildPath);
  if (canonicalBuild !== buildPath) throw new Error('Isolated build path is not canonical');
  await assertPrivateDirectory(canonicalBuild, 'Owned build isolate');
  const expectedSourceRoot = resolve(canonicalBuild, 'source');
  if (runnerRoot !== expectedSourceRoot || await realpath(runnerRoot) !== runnerRoot) {
    throw new Error('Package child is not executing from the frozen source root');
  }
  if (contextPath !== resolve(canonicalBuild, 'child-context.json')) {
    throw new Error('Package child context path is not exact');
  }
  if (contextFd === architectureBootstrap.fd) {
    throw new Error('Package child context descriptor aliases its bootstrap capability');
  }
  let contextBytes;
  try {
    contextBytes = readHeldPackageChildContext({
      fd: contextFd,
      leaseSha256: contextLeaseSha256,
      path: contextPath,
      sha256: contextSha256,
    });
  } finally {
    closeSync(contextFd);
  }
  const context = parseCanonicalControlBytes(contextBytes, 16_384, 'Package child context');
  exactObjectKeys(context, [
    'architectureBootstrapPinsSha256',
    'architectureBootstrapReceiptSha256',
    'architectureGateRunContextSha256',
    'architectureGateRunId',
    'authenticatedToolchainContextSha256',
    'authenticatedToolchainReceiptSha256',
    'buildIsolate',
    'dependencyEntries',
    'dependencyInventorySha256',
    'dependencyLeaseSha256',
    'evidenceRoot',
    'guardedProduction',
    'mode',
    'nonce',
    'repositoryRoot',
    'schemaVersion',
    'sourceDigest',
    'sourceInputLeaseSha256',
    'systemOpenSslConfig',
    'syntheticCanarySha256',
    'toolInputEntries',
    'toolInputInventorySha256',
    'toolInputLeaseSha256',
  ], 'Package child context');
  let systemOpenSslConfig;
  try {
    systemOpenSslConfig = assertSystemOpenSslConfigRecord(context.systemOpenSslConfig);
  } catch {
    throw new Error('Package child context values are invalid');
  }
  if (context.schemaVersion !== 1
    || context.mode !== requestedMode
    || context.nonce !== childNonce
    || context.buildIsolate !== canonicalBuild
    || context.repositoryRoot !== repositoryRoot
    || context.sourceDigest !== sourceDigest
    || context.architectureBootstrapReceiptSha256 !== architectureBootstrap.receiptSha256
    || context.architectureBootstrapPinsSha256 !== architectureBootstrap.receipt.pinsSha256
    || architectureBootstrap.receipt.repositoryRoot !== repositoryRoot
    || typeof context.authenticatedToolchainContextSha256 !== 'string'
    || !sha256Pattern.test(context.authenticatedToolchainContextSha256)
    || typeof context.authenticatedToolchainReceiptSha256 !== 'string'
    || !sha256Pattern.test(context.authenticatedToolchainReceiptSha256)
    || !Number.isSafeInteger(context.dependencyEntries)
    || context.dependencyEntries < 1
    || context.dependencyEntries > 200_000
    || typeof context.dependencyInventorySha256 !== 'string'
    || !/^[0-9a-f]{64}$/u.test(context.dependencyInventorySha256)
    || typeof context.dependencyLeaseSha256 !== 'string'
    || !/^[0-9a-f]{64}$/u.test(context.dependencyLeaseSha256)
    || typeof context.sourceInputLeaseSha256 !== 'string'
    || !/^[0-9a-f]{64}$/u.test(context.sourceInputLeaseSha256)
    || !Array.isArray(context.syntheticCanarySha256)
    || context.syntheticCanarySha256.length !== 4
    || context.syntheticCanarySha256.some((value) => (
      typeof value !== 'string' || !/^[0-9a-f]{64}$/u.test(value)
    ))
    || !Number.isSafeInteger(context.toolInputEntries)
    || context.toolInputEntries < 1
    || context.toolInputEntries > 500_000
    || typeof context.toolInputInventorySha256 !== 'string'
    || !/^[0-9a-f]{64}$/u.test(context.toolInputInventorySha256)
    || typeof context.toolInputLeaseSha256 !== 'string'
    || !/^[0-9a-f]{64}$/u.test(context.toolInputLeaseSha256)
    || (context.evidenceRoot !== null
      && context.evidenceRoot !== resolve(repositoryRoot, '.forge/evidence/architecture-accessibility'))) {
    throw new Error('Package child context values are invalid');
  }
  if (architectureBatch) {
    if (context.architectureGateRunId !== architectureGateRun.runId
      || context.architectureGateRunContextSha256 !== architectureGateRun.contextSha256) {
      throw new Error('Package child architecture run binding is invalid');
    }
  } else if (context.architectureGateRunId !== null
    || context.architectureGateRunContextSha256 !== null) {
    throw new Error('Package child received an unexpected architecture run binding');
  }
  const repositoryState = await lstat(repositoryRoot);
  if (!repositoryState.isDirectory()
    || repositoryState.isSymbolicLink()
    || (repositoryState.mode & 0o022) !== 0
    || (typeof process.getuid === 'function' && repositoryState.uid !== process.getuid())
    || await realpath(repositoryRoot) !== repositoryRoot) {
    throw new Error('Package child repository root is unsafe');
  }
  let evidenceRootIdentity = null;
  if (context.evidenceRoot === null) {
    if (process.env.PIUI_A28_HUMAN_EVIDENCE_ROOT !== undefined) {
      throw new Error('Unexpected A.28 evidence root');
    }
  } else if (process.env.PIUI_A28_HUMAN_EVIDENCE_ROOT !== context.evidenceRoot) {
    throw new Error('A.28 evidence root does not match the parent context');
  } else {
    evidenceRootIdentity = await assertAccessibilityEvidenceRoot(context.evidenceRoot);
  }
  let guardedProductionContext = null;
  let guardedPackageIsolateAuthority = null;
  if (guardedProduction) {
    exactObjectKeys(context.guardedProduction, [
      'outputDev',
      'outputIno',
      'outputRoot',
      'packageIsolateDev',
      'packageIsolateIno',
      'productionFingerprint',
      'runId',
    ], 'Guarded production child context');
    if (!Number.isSafeInteger(context.guardedProduction.outputDev)
      || context.guardedProduction.outputDev < 0
      || !Number.isSafeInteger(context.guardedProduction.outputIno)
      || context.guardedProduction.outputIno < 1
      || !Number.isSafeInteger(context.guardedProduction.packageIsolateDev)
      || context.guardedProduction.packageIsolateDev < 0
      || !Number.isSafeInteger(context.guardedProduction.packageIsolateIno)
      || context.guardedProduction.packageIsolateIno < 1
      || typeof context.guardedProduction.productionFingerprint !== 'string'
      || !sha256Pattern.test(context.guardedProduction.productionFingerprint)
      || typeof context.guardedProduction.runId !== 'string'
      || !architectureRunId.test(context.guardedProduction.runId)
      || process.env.PIUI_GUARDED_PRODUCTION_OUTPUT_ROOT
        !== context.guardedProduction.outputRoot) {
      throw new Error('Guarded production child context values are invalid');
    }
    guardedPackageIsolateAuthority = await assertGuardedPackageIsolateAuthority({
      dev: String(context.guardedProduction.packageIsolateDev),
      fd: process.env.PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE_FD,
      ino: String(context.guardedProduction.packageIsolateIno),
      path: process.env.PIUI_GUARDED_PRODUCTION_PACKAGE_ISOLATE,
    });
    if (guardedPackageIsolateAuthority.path !== canonicalBuild
      || guardedPackageIsolateAuthority.fd === architectureBootstrap.fd
      || guardedPackageIsolateAuthority.fd === contextFd) {
      throw new Error('Guarded production package isolate child authority is invalid');
    }
    const outputIdentity = await assertGuardedOutputRoot(
      context.guardedProduction.outputRoot,
      {
        dev: context.guardedProduction.outputDev,
        ino: context.guardedProduction.outputIno,
      },
      [],
      guardedPackageIsolateAuthority.parent,
    );
    guardedProductionContext = Object.freeze({
      ...context.guardedProduction,
      outputRoot: outputIdentity.path,
    });
  } else if (context.guardedProduction !== null
    || process.env.PIUI_GUARDED_PRODUCTION_OUTPUT_ROOT !== undefined) {
    throw new Error('Unexpected guarded production child context');
  }
  const syntheticCanaries = parseSyntheticCanaries(
    process.env.PIUI_PACKAGE_SYNTHETIC_CANARIES,
  );
  if (canonicalArchitectureJson(syntheticCanaries.map((value) => (
    sha256Bytes(Buffer.from(value))
  ))) !== canonicalArchitectureJson(context.syntheticCanarySha256)) {
    throw new Error('Synthetic build canary binding is invalid');
  }
  delete process.env.PIUI_PACKAGE_SYNTHETIC_CANARIES;
  const snapshot = await snapshotArchitectureSource(runnerRoot);
  if (snapshot.source.digest !== sourceDigest
    || sourceLeaseInputSha256(snapshot) !== context.sourceInputLeaseSha256) {
    throw new Error('Frozen child source digest mismatch');
  }
  const dependency = await captureDependencySet(
    runnerRoot,
    dependencyInstallRoots(runnerRoot),
    { includeHashes: true },
  );
  if (dependency.entries !== context.dependencyEntries
    || dependency.inventorySha256 !== context.dependencyInventorySha256
    || dependency.leaseSha256 !== context.dependencyLeaseSha256) {
    throw new Error('Frozen child dependency witness mismatch');
  }
  syntheticForbiddenValues = Object.freeze([...syntheticCanaries]);
  return Object.freeze({
    buildIsolate: canonicalBuild,
    consumerAnchors: Object.freeze({
      architectureBootstrapPinsSha256: context.architectureBootstrapPinsSha256,
      architectureBootstrapReceiptSha256: context.architectureBootstrapReceiptSha256,
      authenticatedToolchainContextSha256: context.authenticatedToolchainContextSha256,
      authenticatedToolchainReceiptSha256: context.authenticatedToolchainReceiptSha256,
      dependencyInventorySha256: context.dependencyInventorySha256,
      dependencyLeaseSha256: context.dependencyLeaseSha256,
      frozenSourceInventorySha256: snapshot.source.inventorySha256,
      frozenSourceLeaseSha256: snapshot.lease.sha256,
      packageChildContextLeaseSha256: contextLeaseSha256,
      packageChildContextSha256: contextSha256,
      sourceInputLeaseSha256: context.sourceInputLeaseSha256,
      toolInputInventorySha256: context.toolInputInventorySha256,
      toolInputLeaseSha256: context.toolInputLeaseSha256,
    }),
    dependency,
    evidenceRootIdentity,
    guardedProduction: guardedProductionContext,
    guardedPackageIsolateAuthority,
    nonce: context.nonce,
    repositoryRoot,
    snapshot,
    sourceRoot: runnerRoot,
    systemOpenSslConfig,
    toolchainIdentity: Object.freeze({
      authenticatedToolchainContextSha256: context.authenticatedToolchainContextSha256,
      authenticatedToolchainReceiptSha256: context.authenticatedToolchainReceiptSha256,
    }),
    toolInput: Object.freeze({
      entries: context.toolInputEntries,
      inventorySha256: context.toolInputInventorySha256,
      leaseSha256: context.toolInputLeaseSha256,
    }),
  });
}

async function trustedNodeRuntimeFiles(nodePath) {
  const authority = captureAppleToolchainAuthority();
  let inspection;
  try {
    inspection = spawnSync(APPLE_TOOLCHAIN_PATHS.otool, ['-L', nodePath], {
      encoding: 'utf8',
      env: {
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
        PATH: `${APPLE_TOOLCHAIN_PATHS.bin}:/usr/bin:/bin`,
      },
      maxBuffer: 256 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    revalidateAppleToolchainAuthority(authority);
  } finally {
    releaseAppleToolchainAuthority(authority);
  }
  if (inspection.status !== 0
    || inspection.signal !== null
    || inspection.stderr !== '') {
    throw new Error('Pinned Node runtime dependency inspection failed');
  }
  const paths = inspection.stdout.split('\n').slice(1).map((line) => {
    const match = /^\s+(\/[^\r\n]+?) \(compatibility version /u.exec(line);
    return match?.[1];
  }).filter(Boolean);
  if (paths.length < 2 || paths.length > 128 || new Set(paths).size !== paths.length) {
    throw new Error('Pinned Node runtime dependency set is invalid');
  }
  if (paths.some((path) => (
    !path.startsWith('/usr/lib/')
    && !path.startsWith('/System/Library/')
  ))) {
    throw new Error('Pinned Node runtime dependency escaped the system roots');
  }
  const allowedOwners = new Set([0, typeof process.getuid === 'function' ? process.getuid() : -1]);
  const verified = new Set();
  for (const path of paths) {
    let canonical;
    try {
      canonical = await realpath(path);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      verified.add(path);
      continue;
    }
    for (const candidate of new Set([path, canonical])) {
      const state = await lstat(candidate);
      if (!state.isFile()
        || state.isSymbolicLink()
        || !allowedOwners.has(state.uid)
        || (state.mode & 0o022) !== 0) {
        throw new Error('Pinned Node runtime dependency is unsafe');
      }
      verified.add(candidate);
    }
  }
  return Object.freeze([...verified].sort((left, right) => (
    Buffer.from(left).compare(Buffer.from(right))
  )));
}

export async function resolveTrustedTools(isolateRoot) {
  if (typeof isolateRoot !== 'string' || resolve(isolateRoot) !== isolateRoot) {
    throw new Error('Authenticated toolchain isolate is not canonical');
  }
  const toolSourceRoot = isolatedChild ? runnerRoot : repositoryRoot;
  const paths = isolatedChild
    ? await validateAuthenticatedToolchain(isolateRoot, toolSourceRoot)
    : await prepareAuthenticatedToolchain(isolateRoot, toolSourceRoot);
  await registerAuthenticatedToolchainNode(paths.node, toolSourceRoot);
  await noForkToolProbe(paths);
  const toolInputRoots = Object.freeze([
    Object.freeze({ label: 'authenticated-toolchain', root: paths.closureRoot }),
  ]);
  const toolInput = await captureToolInputSet(toolInputRoots, { includeHashes: true });
  await noForkToolProbe(paths);
  const identity = await authenticatedToolchainIdentity(isolateRoot, toolSourceRoot, {
    entries: toolInput.entries,
    inventorySha256: toolInput.inventorySha256,
    leaseSha256: toolInput.leaseSha256,
  });
  const toolInputAfterProbe = await captureToolInputSet(toolInputRoots, { includeHashes: false });
  if (!equalInputSetLease(toolInput, toolInputAfterProbe)) {
    throw new Error('Build tool inputs changed during version verification');
  }
  return Object.freeze({
    ...identity,
    authenticatedNode: paths.node,
    cargoBin: paths.cargoBin,
    cargoVendor: paths.cargoVendor,
    closureRoot: paths.closureRoot,
    nodeArchive: paths.nodeArchive,
    nodeRuntimeFiles: await trustedNodeRuntimeFiles(paths.node),
    pnpmEntry: paths.pnpmEntry,
    pnpmNode: paths.node,
    pnpmRoot: paths.pnpmRoot,
    rustObjcopy: paths.rustObjcopy,
    rustToolchain: paths.rustToolchain,
    store: paths.store,
    systemOpenSslConfig: paths.systemOpenSslConfig,
    toolInput,
    toolInputRoots,
  });
}

function makeBuildEnvironment(root, tools, syntheticCanaries) {
  const home = resolve(root, 'home');
  const temporary = resolve(root, 'tmp');
  const cache = resolve(root, 'cache');
  const cargoHome = resolve(root, 'cargo-home');
  for (const path of [
    home,
    temporary,
    cache,
    resolve(root, 'config'),
    resolve(root, 'data'),
    resolve(root, 'npm-cache'),
    cargoHome,
  ]) {
    mkdirSync(path, { recursive: true, mode: 0o700 });
  }
  if (typeof tools.cargoVendor !== 'string'
    || !tools.cargoVendor.startsWith(`${tools.closureRoot}/`)) {
    throw new Error('Authenticated Cargo vendor root is unavailable');
  }
  writeFileSync(
    resolve(cargoHome, 'config.toml'),
    `[net]\noffline = true\n\n[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = ${JSON.stringify(tools.cargoVendor)}\n`,
    { mode: 0o400, flag: 'wx' },
  );
  for (const name of ['.package-cache', '.package-cache-mutate']) {
    writeFileSync(resolve(cargoHome, name), '', { mode: 0o600, flag: 'wx' });
  }
  chmodSync(cargoHome, 0o500);
  if (!Array.isArray(syntheticCanaries) || syntheticCanaries.length !== 4) {
    throw new Error('Synthetic build canaries are unavailable');
  }
  return {
    HOME: home,
    CFFIXED_USER_HOME: home,
    TMPDIR: `${temporary}/`,
    XDG_CACHE_HOME: cache,
    XDG_CONFIG_HOME: resolve(root, 'config'),
    XDG_DATA_HOME: resolve(root, 'data'),
    npm_config_cache: resolve(root, 'npm-cache'),
    npm_config_ignore_scripts: 'true',
    PIUI_NODE_OFFLINE: '1',
    PIUI_PNPM_ENTRY: tools.pnpmEntry,
    PIUI_PNPM_NODE: tools.pnpmNode,
    PIUI_PNPM_STORE: tools.store,
    PIUI_PNPM_OFFLINE: '1',
    CARGO_HOME: cargoHome,
    CARGO_NET_OFFLINE: 'true',
    RUSTUP_TOOLCHAIN: '1.96.0-aarch64-apple-darwin',
    ...appleToolchainBuildEnvironment(),
    PATH: `${dirname(tools.pnpmNode)}:${tools.cargoBin}:${APPLE_TOOLCHAIN_PATHS.bin}:/usr/bin:/bin:/usr/sbin:/sbin`,
    LANG: 'en_AU.UTF-8',
    LC_ALL: 'en_AU.UTF-8',
    RUST_BACKTRACE: '0',
    PIUI_BUILD_SECRET_CANARY_A: syntheticCanaries[0],
    PIUI_BUILD_SECRET_CANARY_B: syntheticCanaries[1],
    PIUI_BUILD_SECRET_CANARY_C: syntheticCanaries[2],
    PIUI_BUILD_SECRET_CANARY_D: syntheticCanaries[3],
  };
}

function buildSandboxConfiguration({ buildEnv, buildIsolate: isolate, sourceRoot: source, tools }) {
  if (!dependencyBaseline || !Array.isArray(dependencyBaseline.executables)) {
    throw new Error('Frozen dependency executable witness is unavailable');
  }
  const unique = (values) => [...new Set(values)].sort((left, right) => (
    Buffer.from(left).compare(Buffer.from(right))
  ));
  const generatedDirectories = generated
    .filter((entry) => entry.kind === 'directory')
    .map((entry) => entry.path);
  const generatedFiles = generated
    .filter((entry) => entry.kind === 'file')
    .map((entry) => entry.path);
  const cargoRuntimeFiles = [
    resolve(buildEnv.CARGO_HOME, '.package-cache'),
    resolve(buildEnv.CARGO_HOME, '.package-cache-mutate'),
  ];
  const privateToolRoots = [
    resolve(isolate, 'tauri-build-tools'),
  ];
  const writableRoots = unique([
    ...generatedDirectories,
    resolve(source, '.cache/node-runtime'),
    buildEnv.HOME,
    buildEnv.TMPDIR.slice(0, -1),
    buildEnv.XDG_CACHE_HOME,
    buildEnv.XDG_CONFIG_HOME,
    buildEnv.XDG_DATA_HOME,
    buildEnv.npm_config_cache,
    resolve(isolate, '.tauri-build-authorisations'),
  ]);
  const systemRuntimeRoots = [
    '/Library/Apple/System/Library',
    APPLE_TOOLCHAIN_PATHS.root,
    '/System/Library',
    '/private/var/db/timezone',
    '/usr/lib',
    '/usr/share/zoneinfo',
  ];
  const systemRuntimeFiles = [
    '/private/etc/localtime',
    '/private/var/select/sh',
    '/dev/fd/9',
    '/dev/null',
    '/dev/random',
    '/dev/urandom',
    '/dev/zero',
  ];
  const appleToolchainAuthorityDirectories = [
    '/',
    '/Library',
    '/Library/Developer',
  ];
  const systemExecutables = [
    '/bin/bash',
    '/bin/sh',
    '/usr/bin/codesign',
    '/usr/bin/env',
    '/usr/bin/ruby',
    '/usr/bin/bsdtar',
  ];
  const appleToolchainExecutables = [
    APPLE_TOOLCHAIN_PATHS.ar,
    APPLE_TOOLCHAIN_PATHS.clang,
    APPLE_TOOLCHAIN_PATHS.clangxx,
    APPLE_TOOLCHAIN_PATHS.dsymutil,
    APPLE_TOOLCHAIN_PATHS.installNameTool,
    APPLE_TOOLCHAIN_PATHS.ld,
    APPLE_TOOLCHAIN_PATHS.libtool,
    APPLE_TOOLCHAIN_PATHS.lipo,
    APPLE_TOOLCHAIN_PATHS.llvmNm,
    APPLE_TOOLCHAIN_PATHS.llvmOtool,
    APPLE_TOOLCHAIN_PATHS.nm,
    APPLE_TOOLCHAIN_PATHS.otool,
    APPLE_TOOLCHAIN_PATHS.otoolClassic,
    APPLE_TOOLCHAIN_PATHS.ranlib,
    APPLE_TOOLCHAIN_PATHS.strip,
  ];
  return {
    authenticatedCommand: tools.pnpmNode,
    executableFiles: unique([
      ...dependencyBaseline.executables,
      ...generatedFiles,
      ...systemExecutables,
      ...appleToolchainExecutables,
      tools.pnpmNode,
      resolve(tools.cargoBin, 'cargo'),
      resolve(tools.cargoBin, 'rustc'),
      resolve(tools.cargoBin, 'rustdoc'),
      tools.rustObjcopy,
    ]),
    executableRoots: unique([
      resolve(source, 'src-tauri/target'),
    ]),
    readableFiles: unique([
      ...systemExecutables,
      ...appleToolchainExecutables,
      ...appleToolchainAuthorityDirectories,
      ...systemRuntimeFiles,
      ...tools.nodeRuntimeFiles,
      ...variantOverlayPaths,
      tools.systemOpenSslConfig.path,
    ]),
    readableRoots: unique([
      source,
      buildEnv.CARGO_HOME,
      ...privateToolRoots,
      tools.cargoBin,
      tools.closureRoot,
      tools.rustToolchain,
      tools.store,
      ...systemRuntimeRoots,
      ...writableRoots,
    ]),
    writableFiles: unique([
      '/dev/fd/3',
      ...cargoRuntimeFiles,
      ...generatedFiles,
      ...writableRoots,
    ]),
    writableRoots,
  };
}

async function assertFrozenBuildInputs(failurePhasePrefix) {
  const setFailurePhase = (suffix) => {
    if (failurePhasePrefix !== undefined) {
      setIsolatedChildFailurePhase(`${failurePhasePrefix}-${suffix}`);
    }
  };
  setFailurePhase('witnesses');
  if (!frozenInputBaseline
    || !dependencyBaseline
    || !toolInputBaseline
    || toolInputRoots.length < 1
    || !systemOpenSslConfigBaseline
    || !privateBuildInputBaseline
    || privateBuildInputRoots.length < 1) {
    throw new Error('Frozen build input witnesses are unavailable');
  }
  setFailurePhase('openssl-authentication');
  const systemOpenSslConfig = await authenticateSystemOpenSslConfig();
  setFailurePhase('apple-toolchain');
  revalidateAppleToolchainAuthority(appleToolchainAuthority);
  setFailurePhase('openssl-lease');
  if (canonicalArchitectureJson(systemOpenSslConfig)
    !== canonicalArchitectureJson(systemOpenSslConfigBaseline)) {
    throw new Error('Authenticated system OpenSSL config changed during the isolated build');
  }
  setFailurePhase('source');
  const source = await snapshotArchitectureSource(sourceRoot);
  if (!equalArchitectureSnapshot(frozenInputBaseline, source)
    || sourceLeaseInputSha256(source) !== sourceLeaseInputSha256(frozenInputBaseline)) {
    throw new Error('Frozen source inputs changed during the isolated build');
  }
  setFailurePhase('dependencies');
  const dependency = await captureDependencySet(
    sourceRoot,
    dependencyInstallRoots(sourceRoot),
    { includeHashes: false },
  );
  if (dependency.entries !== dependencyBaseline.entries
    || dependency.leaseSha256 !== dependencyBaseline.leaseSha256
    || dependency.items.length !== dependencyBaseline.items.length
    || dependency.items.some((item, index) => (
      item.rootLabel !== dependencyBaseline.items[index]?.rootLabel
      || !item.leaseBytes.equals(dependencyBaseline.items[index].leaseBytes)
    ))) {
    throw new Error('Private dependency tree changed during the isolated build');
  }
  setFailurePhase('tool-inputs');
  const toolInput = await captureToolInputSet(toolInputRoots, { includeHashes: false });
  if (!equalInputSetLease(toolInputBaseline, toolInput)) {
    throw new Error('External build tool inputs changed during the isolated build');
  }
  setFailurePhase('private-controls-capture');
  const privateInput = await capturePrivateBuildInputSet(
    buildIsolate,
    privateBuildInputRoots,
    privateBuildLinkRoots,
    privateBuildInputExclusions,
    { includeHashes: false },
  );
  for (const label of PRIVATE_BUILD_CONTROL_LABELS) {
    const expected = privateBuildInputBaseline.items.find((item) => item.label === label);
    const actual = privateInput.items.find((item) => item.label === label);
    const changeClass = privateBuildControlChangeClass(expected, actual);
    if (changeClass !== undefined) {
      setFailurePhase(`private-controls-${label}-${changeClass}`);
      throw new Error('Private build control inputs changed during the isolated build');
    }
  }
  setFailurePhase('private-controls-aggregate');
  if (!equalInputSetLease(privateBuildInputBaseline, privateInput)) {
    throw new Error('Private build control inputs changed during the isolated build');
  }
}

async function provisionPinnedNodeOutput(tools, buildEnv, label) {
  setIsolatedChildFailurePhase('node-provisioning');
  const output = resolve(sourceRoot, `src-tauri/binaries/piui-node-${target}`);
  const before = await lstat(output, { bigint: true });
  if (!before.isFile()
    || before.isSymbolicLink()
    || before.nlink !== 1n
    || (before.mode & 0o777n) !== 0o600n
    || (typeof process.getuid === 'function' && before.uid !== BigInt(process.getuid()))
    || await realpath(output) !== output) {
    throw new Error('Generated Node output authority is unsafe');
  }
  const handle = await openFile(output, constants.O_RDWR | constants.O_NOFOLLOW);
  try {
    const held = await handle.stat({ bigint: true });
    const pathname = await lstat(output, { bigint: true });
    if (!sameBigIntState(before, held)
      || !sameBigIntState(held, pathname)
      || handle.fd < 3
      || handle.fd > 255) {
      throw new Error('Generated Node output authority changed before provisioning');
    }
    try {
      await runSandboxed(
        tools.pnpmNode,
        [
          'scripts/fetch-node-runtime.mjs',
          '--held-output-fd',
          String(handle.fd),
        ],
        label,
        buildEnv,
        180_000,
        { inheritedFds: [handle.fd] },
      );
    } catch (error) {
      const failureClass = error instanceof Error
        ? error.message.match(/\((disk-capacity|sandbox-denial|subprocess-failure)\)$/u)?.[1]
        : undefined;
      if (failureClass) setIsolatedChildFailurePhase(`node-provisioning-${failureClass}`);
      throw error;
    }
    const beforeRead = await handle.stat({ bigint: true });
    const pathBeforeRead = await lstat(output, { bigint: true });
    if (beforeRead.dev !== held.dev
      || beforeRead.ino !== held.ino
      || beforeRead.nlink !== 1n
      || (beforeRead.mode & 0o777n) !== 0o755n
      || beforeRead.size < 1n
      || beforeRead.size > BigInt(Number.MAX_SAFE_INTEGER)
      || !sameBigIntState(beforeRead, pathBeforeRead)
      || await realpath(output) !== output) {
      throw new Error('Generated Node output changed after provisioning');
    }
    const digest = await sha256HeldDescriptor(handle, Number(beforeRead.size));
    const afterRead = await handle.stat({ bigint: true });
    const pathAfterRead = await lstat(output, { bigint: true });
    if (!sameBigIntState(beforeRead, afterRead)
      || !sameBigIntState(afterRead, pathAfterRead)
      || await realpath(output) !== output
      || digest !== architectureToolchainPins.node.executableSha256) {
      throw new Error('Generated Node output changed during held verification');
    }
  } finally {
    await handle.close();
  }
}

async function runSandboxed(
  command,
  args,
  label,
  env,
  timeoutMs,
  { frozenInputFailurePhasePrefix, inheritedFds = [] } = {},
) {
  await assertFrozenBuildInputs(frozenInputFailurePhasePrefix === undefined
    ? undefined
    : `${frozenInputFailurePhasePrefix}-before`);
  const result = await runOwnedCommand({
    command,
    args,
    cwd: sourceRoot,
    env,
    inheritedFds,
    timeoutMs,
    maxOutputBytes: 64 * 1024 * 1024,
    sandboxProfile: buildSandbox,
    signal: parentCutoffs.signal,
    label,
  });
  await assertFrozenBuildInputs(frozenInputFailurePhasePrefix === undefined
    ? undefined
    : `${frozenInputFailurePhasePrefix}-after`);
  if (result.status !== 0 || result.signal !== null) {
    // Child diagnostics are intentionally not reflected: build tools may echo
    // arbitrary source bytes. Only fixed non-sensitive failure classes are
    // derived for operational recovery.
    const diagnostics = `${result.stdout.toString('utf8')}\n${result.stderr.toString('utf8')}`;
    const failureClass = /(?:ENOSPC|no space left on device)/i.test(diagnostics)
      ? 'disk-capacity'
      : /operation not permitted|sandbox/i.test(diagnostics)
        ? 'sandbox-denial'
        : 'subprocess-failure';
    throw new Error(`${label} failed with exit ${result.status ?? 'signal'} (${failureClass})`);
  }
}

function setSandboxFailureClassPhase(phase, error) {
  const failureClass = error instanceof Error
    ? error.message.match(/\((disk-capacity|sandbox-denial|subprocess-failure)\)$/u)?.[1]
    : undefined;
  if (failureClass) setIsolatedChildFailurePhase(`${phase}-${failureClass}`);
}

function readControlledSidecarFinalisationPhase(descriptor) {
  const before = fstatSync(descriptor);
  if (!before.isFile()
    || before.isSymbolicLink()
    || before.nlink !== 1
    || before.uid !== process.getuid()
    || (before.mode & 0o777) !== 0o600
    || before.size < 1
    || before.size > 128) {
    return 'unclassified';
  }
  const bytes = Buffer.alloc(before.size);
  let offset = 0;
  try {
    while (offset < bytes.length) {
      const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count < 1) return 'unclassified';
      offset += count;
    }
    const after = fstatSync(descriptor);
    if (!sameHeldIdentity(before, after)
      || after.mode !== before.mode
      || after.size !== before.size) {
      return 'unclassified';
    }
    return parseControlledSidecarFinalisationPhase(bytes);
  } finally {
    bytes.fill(0);
  }
}

async function stageSidecarControlled(tools, buildEnv) {
  const transactionLock = await acquireOwnedLock(
    resolve(sourceRoot, '.cache/sidecar-stage.lock'),
    { timeoutMs: 120_000, label: 'Controlled sidecar staging transaction' },
  );
  let workspaceLease;
  let deploymentReceiptFd;
  let finalisationProgressFd;
  let primaryFailure;
  try {
    const typescript = resolve(sourceRoot, 'node_modules/typescript/bin/tsc');
    for (const [configuration, label] of [
      ['packages/protocol/tsconfig.build.json', 'Protocol compilation for sidecar staging'],
      ['sidecar/tsconfig.json', 'Sidecar compilation for closure staging'],
    ]) {
      setIsolatedChildFailurePhase(
        configuration.startsWith('packages/')
          ? 'sidecar-protocol-compilation'
          : 'sidecar-typescript-compilation',
      );
      await runSandboxed(
        tools.pnpmNode,
        [typescript, '-p', configuration, '--pretty', 'false'],
        label,
        buildEnv,
        5 * 60_000,
        { inheritedFds: [transactionLock.fd] },
      );
    }
    const workspace = await mkdtemp(resolve(
      buildEnv.TMPDIR,
      'piui-sidecar-stage-control-',
    ));
    workspaceLease = await openHeldPath(
      workspace,
      'directory',
      'Controlled sidecar staging workspace',
    );
    const deployment = resolve(workspace, 'deployment');
    setIsolatedChildFailurePhase('sidecar-deployment-preparation');
    try {
      await runSandboxed(
        tools.pnpmNode,
        [
          'scripts/stage-sidecar.mjs',
          '--prepare-controlled',
          workspace,
          String(transactionLock.fd),
        ],
        'Controlled sidecar deployment preparation',
        buildEnv,
        120_000,
        { inheritedFds: [transactionLock.fd] },
      );
    } catch (error) {
      setSandboxFailureClassPhase('sidecar-deployment-preparation', error);
      throw error;
    }
    await assertHeldPath(
      workspaceLease,
      workspace,
      'Controlled sidecar staging workspace',
    );
    setIsolatedChildFailurePhase('sidecar-dependency-installation');
    await runSandboxed(
      tools.pnpmNode,
      [
        tools.pnpmEntry,
        '--dir',
        deployment,
        '--config.node-linker=hoisted',
        '--config.package-import-method=copy',
        `--store-dir=${tools.store}`,
        'install',
        '--prod',
        '--ignore-workspace',
        '--frozen-lockfile',
        '--ignore-scripts',
        '--offline',
      ],
      'Controlled production sidecar dependency installation',
      buildEnv,
      10 * 60_000,
      { inheritedFds: [transactionLock.fd] },
    );
    await assertHeldPath(
      workspaceLease,
      workspace,
      'Controlled sidecar staging workspace',
    );
    const deploymentReceipt = await captureSidecarDeploymentReceipt(deployment);
    const deploymentReceiptPath = resolve(
      buildEnv.TMPDIR,
      `sidecar-deployment-${randomBytes(16).toString('hex')}.json`,
    );
    writeFileSync(deploymentReceiptPath, deploymentReceipt.bytes, {
      flag: 'wx',
      mode: 0o600,
    });
    chmodSync(deploymentReceiptPath, 0o400);
    deploymentReceiptFd = openSync(
      deploymentReceiptPath,
      constants.O_RDONLY | constants.O_NOFOLLOW,
    );
    const finalisationProgressPath = resolve(
      buildEnv.TMPDIR,
      `sidecar-finalisation-progress-${randomBytes(16).toString('hex')}.txt`,
    );
    finalisationProgressFd = openSync(
      finalisationProgressPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
      0o600,
    );
    fchmodSync(finalisationProgressFd, 0o600);
    const initialProgressState = fstatSync(finalisationProgressFd);
    if (!initialProgressState.isFile()
      || initialProgressState.isSymbolicLink()
      || initialProgressState.nlink !== 1
      || initialProgressState.uid !== process.getuid()
      || (initialProgressState.mode & 0o777) !== 0o600
      || initialProgressState.size !== 0) {
      throw new Error('Controlled sidecar finalisation progress descriptor is invalid');
    }
    setIsolatedChildFailurePhase('sidecar-closure-finalisation');
    try {
      await runSandboxed(
        tools.pnpmNode,
        [
          'scripts/stage-sidecar.mjs',
          '--finalise-controlled',
          workspace,
          String(transactionLock.fd),
          String(deploymentReceiptFd),
          deploymentReceipt.sha256,
          String(finalisationProgressFd),
        ],
        'Controlled sidecar closure finalisation',
        buildEnv,
        15 * 60_000,
        {
          inheritedFds: [
            transactionLock.fd,
            deploymentReceiptFd,
            finalisationProgressFd,
          ],
        },
      );
    } catch (error) {
      let finalisationPhase = 'unclassified';
      try {
        finalisationPhase = readControlledSidecarFinalisationPhase(
          finalisationProgressFd,
        );
      } catch {
        // Progress is a sealed recovery hint only. Never replace the primary
        // child failure when the hint itself cannot be read safely.
      }
      if (finalisationPhase !== 'unclassified' && finalisationPhase !== 'complete') {
        setIsolatedChildFailurePhase(`sidecar-finalisation-${finalisationPhase}`);
      }
      throw error;
    }
    if (readControlledSidecarFinalisationPhase(finalisationProgressFd) !== 'complete') {
      throw new Error('Controlled sidecar finalisation did not complete its sealed progress record');
    }
  } catch (error) {
    primaryFailure = error;
    throw error;
  } finally {
    const cleanupFailures = [];
    let cleanupPhaseLocked = primaryFailure !== undefined;
    const recordCleanupFailure = (error) => {
      cleanupFailures.push(error);
      cleanupPhaseLocked = true;
    };
    const setCleanupPhase = (phase) => {
      if (!cleanupPhaseLocked) {
        setIsolatedChildFailurePhase(`sidecar-finalisation-${phase}`);
      }
    };
    setCleanupPhase('parent-descriptor-releases');
    if (finalisationProgressFd !== undefined) {
      try { closeSync(finalisationProgressFd); } catch (error) { recordCleanupFailure(error); }
    }
    if (deploymentReceiptFd !== undefined) {
      try { closeSync(deploymentReceiptFd); } catch (error) { recordCleanupFailure(error); }
    }
    try { await workspaceLease?.handle.close(); } catch (error) { recordCleanupFailure(error); }
    setCleanupPhase('parent-transaction-lock-release');
    try { await releaseOwnedLock(transactionLock); } catch (error) { recordCleanupFailure(error); }
    if (cleanupFailures.length > 0) {
      throw new AggregateError(
        primaryFailure ? [primaryFailure, ...cleanupFailures] : cleanupFailures,
        'Controlled sidecar staging cleanup failed',
      );
    }
  }
}

async function prepareVariantOverlays() {
  const root = resolve(buildIsolate, 'build-controls');
  mkdirSync(root, { mode: 0o700 });
  const entries = [];
  const byKind = new Map();
  formalBuildOverlayPath = resolve(root, 'authenticated-build.json');
  const formalBuildBytes = Buffer.from(`${canonicalArchitectureJson({
    build: { beforeBuildCommand: '' },
  })}\n`, 'utf8');
  writeFileSync(formalBuildOverlayPath, formalBuildBytes, { flag: 'wx', mode: 0o600 });
  const verifiedFormalBuild = await readTrustedRegularFile(
    formalBuildOverlayPath,
    undefined,
    'Authenticated Tauri build overlay',
  );
  if (!verifiedFormalBuild.equals(formalBuildBytes)) {
    throw new Error('Authenticated Tauri build overlay changed after publication');
  }
  await chmod(formalBuildOverlayPath, 0o400);
  entries.push(formalBuildOverlayPath);
  for (const kind of ['approval-twin', 'automation-twin', 'credential-twin']) {
    const overlay = architectureVariantDefinition(kind).overlay;
    const path = resolve(root, `${kind}.json`);
    const bytes = Buffer.from(`${canonicalArchitectureJson(overlay)}\n`, 'utf8');
    writeFileSync(path, bytes, { flag: 'wx', mode: 0o600 });
    const verified = await readTrustedRegularFile(path, undefined, 'Variant overlay input');
    if (!verified.equals(bytes)) throw new Error('Variant overlay input changed after publication');
    await chmod(path, 0o400);
    entries.push(path);
    byKind.set(kind, path);
  }
  await chmod(root, 0o500);
  variantOverlayPaths = Object.freeze(entries.sort((left, right) => (
    Buffer.from(left).compare(Buffer.from(right))
  )));
  variantOverlayByKind = byKind;
}

function sameHeldIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.uid === right.uid
    && left.gid === right.gid
    && (left.isDirectory() || left.nlink === right.nlink)
    && left.isFile() === right.isFile()
    && left.isDirectory() === right.isDirectory();
}

async function openHeldPath(path, kind, label) {
  const requested = resolve(path);
  const before = await lstat(requested);
  const expectedKind = kind === 'file' ? before.isFile() : before.isDirectory();
  if (!expectedKind || before.isSymbolicLink()
    || (kind === 'file' && before.nlink !== 1)
    || (typeof process.getuid === 'function' && before.uid !== process.getuid())
    || await realpath(requested) !== requested) {
    throw new Error(`${label} is not a held owner-controlled ${kind}`);
  }
  const directoryFlag = kind === 'directory' ? constants.O_DIRECTORY : 0;
  const handle = await openFile(
    requested,
    constants.O_RDONLY | constants.O_NOFOLLOW | directoryFlag,
  );
  try {
    const opened = await handle.stat();
    const pathAfter = await lstat(requested);
    if (!sameHeldIdentity(before, opened)
      || !sameHeldIdentity(opened, pathAfter)
      || await realpath(requested) !== requested) {
      throw new Error(`${label} identity changed while it was held`);
    }
    return Object.freeze({ handle, identity: opened, path: requested });
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function assertHeldPath(held, path, label) {
  const requested = resolve(path);
  const descriptor = await held.handle.stat();
  const pathname = await lstat(requested);
  if (!sameHeldIdentity(held.identity, descriptor)
    || !sameHeldIdentity(descriptor, pathname)
    || await realpath(requested) !== requested) {
    throw new Error(`${label} identity changed while it was held`);
  }
  return descriptor;
}

function equalBundleInventoryLease(left, right) {
  if (left.rootIdentity.dev !== right.rootIdentity.dev
    || left.rootIdentity.ino !== right.rootIdentity.ino
    || left.fingerprint !== right.fingerprint
    || left.entries.length !== right.entries.length) return false;
  return left.entries.every((entry, index) => {
    const other = right.entries[index];
    return entry.path === other.path
      && entry.kind === other.kind
      && entry.dev === other.dev
      && entry.ino === other.ino
      && entry.mode === other.mode
      && entry.bytes === other.bytes
      && entry.sha256 === other.sha256;
  });
}

async function readHeldInventoryFile(root, entry) {
  const path = resolve(root, entry.path);
  const handle = await openFile(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    const pathBefore = await lstat(path);
    if (!before.isFile() || before.nlink !== 1
      || before.dev !== entry.dev || before.ino !== entry.ino
      || before.size !== entry.bytes || (before.mode & 0o777) !== entry.mode
      || !sameHeldIdentity(before, pathBefore)) {
      throw new Error(`Candidate bundle file changed before private capture: ${entry.path}`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const pathAfter = await lstat(path);
    if (!sameHeldIdentity(before, after) || !sameHeldIdentity(after, pathAfter)
      || after.size !== before.size || after.mode !== before.mode
      || bytes.length !== entry.bytes || sha256Bytes(bytes) !== entry.sha256) {
      throw new Error(`Candidate bundle file changed during private capture: ${entry.path}`);
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

export async function copyBundleToPrivateControl(candidatePath, controlRoot, testHook) {
  const source = await inventoryBundle(candidatePath);
  const canonicalControl = resolve(controlRoot);
  mkdirSync(canonicalControl, { mode: 0o700 });
  const control = await openHeldPath(canonicalControl, 'directory', 'Private bundle control root');
  const destination = resolve(canonicalControl, 'accepted.app');
  try {
    mkdirSync(destination, { mode: 0o700 });
    const privateRoot = await lstat(destination);
    const privateIdentities = new Map([['.', Object.freeze({
      dev: privateRoot.dev,
      ino: privateRoot.ino,
    })]]);
    const directories = source.entries
      .filter((entry) => entry.kind === 'directory')
      .sort((left, right) => (
        left.path.split('/').length - right.path.split('/').length
          || Buffer.from(left.path).compare(Buffer.from(right.path))
      ));
    for (const entry of directories) {
      const path = resolve(destination, entry.path.replace(/\/$/u, ''));
      if (relative(destination, path).startsWith('..')) {
        throw new Error('Private bundle directory escaped its control root');
      }
      mkdirSync(path, { mode: 0o700 });
      const copiedDirectory = await lstat(path);
      privateIdentities.set(entry.path, Object.freeze({
        dev: copiedDirectory.dev,
        ino: copiedDirectory.ino,
      }));
    }
    const files = source.entries.filter((entry) => entry.kind === 'file');
    for (const entry of files) {
      const bytes = await readHeldInventoryFile(source.root, entry);
      const path = resolve(destination, entry.path);
      if (relative(destination, path).startsWith('..')) {
        throw new Error('Private bundle file escaped its control root');
      }
      try {
        writeFileSync(path, bytes, {
          flag: 'wx',
          mode: (entry.mode & 0o111) !== 0 ? 0o700 : 0o600,
        });
      } finally {
        bytes.fill(0);
      }
      const copied = await readTrustedRegularFile(path, undefined, 'Private bundle file');
      if (copied.length !== entry.bytes || sha256Bytes(copied) !== entry.sha256) {
        throw new Error(`Private bundle file differs from held source: ${entry.path}`);
      }
      const copiedFile = await lstat(path);
      privateIdentities.set(entry.path, Object.freeze({
        dev: copiedFile.dev,
        ino: copiedFile.ino,
      }));
      if (testHook) await testHook(Object.freeze({ destination, entry, source: source.root }));
    }
    const sourceAfter = await inventoryBundle(source.root);
    if (!equalBundleInventoryLease(source, sourceAfter)) {
      throw new Error('Candidate bundle changed during private capture');
    }
    const privateInventory = await inventoryBundle(destination);
    const rootLease = privateIdentities.get('.');
    if (privateInventory.rootIdentity.dev !== rootLease.dev
      || privateInventory.rootIdentity.ino !== rootLease.ino
      || privateInventory.entries.length !== source.entries.length
      || privateInventory.entries.some((entry, index) => {
        const original = source.entries[index];
        const lease = privateIdentities.get(entry.path);
        return entry.path !== original.path
          || entry.kind !== original.kind
          || entry.dev !== lease?.dev
          || entry.ino !== lease?.ino
          || entry.bytes !== original.bytes
          || entry.sha256 !== original.sha256
          || ((entry.mode & 0o111) !== 0) !== ((original.mode & 0o111) !== 0)
          || (entry.provenance !== null && !/^[0-9a-f]+$/u.test(entry.provenance));
      })) {
      throw new Error('Private bundle capture is not an exact held-byte copy');
    }
    await assertHeldPath(control, canonicalControl, 'Private bundle control root');
    return destination;
  } finally {
    await control.handle.close();
  }
}

function writeVariantOverlay(kind, overlay) {
  if (!overlay) return undefined;
  const path = variantOverlayByKind.get(kind);
  if (!path
    || canonicalArchitectureJson(overlay)
      !== canonicalArchitectureJson(architectureVariantDefinition(kind).overlay)) {
    throw new Error('Variant overlay input is not predeclared');
  }
  return path;
}

export function automationSigningSandbox(
  hostPath,
  keychainPath = automationSigningKeychainPath(),
) {
  return authenticatedAutomationSigningSandbox(hostPath, keychainPath);
}

async function runExactAutomationSigner(
  _command,
  codesignArguments,
  label,
  _environment,
  timeoutMs,
  authority,
) {
  const hostPath = codesignArguments.at(-1);
  const result = await runOwnedCommand({
    command: '/usr/bin/sandbox-exec',
    args: [
      '-p',
      automationSigningSandbox(hostPath, authority.keychainPath),
      '/usr/bin/codesign',
      ...codesignArguments,
    ],
    cwd: '/',
    env: {
      HOME: homedir(),
      LANG: 'en_AU.UTF-8',
      LC_ALL: 'en_AU.UTF-8',
      PATH: '/usr/bin:/bin',
    },
    label,
    maxOutputBytes: 256 * 1024,
    timeoutMs,
  });
  const expectedReplacementNotice = Buffer.from(
    `${hostPath}: replacing existing signature\n`,
    'utf8',
  );
  const stderrAccepted = result.stderr.length === 0
    || result.stderr.equals(expectedReplacementNotice);
  if (result.status !== 0 || result.signal !== null || result.forcedCleanup
    || result.stdout.length !== 0 || !stderrAccepted) {
    throw new Error('Automation-twin exact-path signing failed');
  }
}

async function sha256HeldDescriptor(handle, size) {
  const hash = createHash('sha256');
  const chunk = Buffer.alloc(Math.min(64 * 1024, Math.max(1, size)));
  let offset = 0;
  try {
    while (offset < size) {
      const length = Math.min(chunk.length, size - offset);
      const { bytesRead } = await handle.read(chunk, 0, length, offset);
      if (bytesRead !== length) throw new Error('Held executable descriptor was truncated');
      hash.update(chunk.subarray(0, bytesRead));
      offset += bytesRead;
    }
    return hash.digest('hex');
  } finally {
    chunk.fill(0);
  }
}

export async function signAutomationHost(appPath, environment, signer = runExactAutomationSigner) {
  const hostPath = resolve(appPath, 'Contents/MacOS/piui');
  const held = await openHeldPath(hostPath, 'file', 'Automation-twin host');
  try {
    const authority = await authenticateAutomationSigningAuthority();
    const originalSha256 = await sha256HeldDescriptor(held.handle, held.identity.size);
    await held.handle.chmod(0o700);
    await assertHeldPath(held, hostPath, 'Automation-twin host');
    await signer(
      '/usr/bin/codesign',
      automationSigningArguments(hostPath, authority.keychainPath),
      'Automation-twin Apple Development signing',
      environment,
      60_000,
      authority,
    );
    await assertAutomationSigningAuthorityUnchanged(authority);
    const originalAfter = await held.handle.stat();
    if (originalAfter.dev !== held.identity.dev || originalAfter.ino !== held.identity.ino
      || originalAfter.size !== held.identity.size
      || await sha256HeldDescriptor(held.handle, held.identity.size) !== originalSha256) {
      throw new Error('Automation-twin original host changed while held');
    }
    const signed = await openHeldPath(hostPath, 'file', 'Automation-twin signed host');
    try {
      const sameInode = signed.identity.dev === held.identity.dev
        && signed.identity.ino === held.identity.ino;
      if ((!sameInode && originalAfter.nlink !== 0)
        || (signed.identity.mode & 0o777) !== 0o700 || signed.identity.size < 1) {
        throw new Error('Automation-twin signed host transition is invalid');
      }
      const signedBytes = await signed.handle.readFile();
      try {
        if (sha256Bytes(signedBytes) === originalSha256) {
          throw new Error('Automation-twin Apple Development signature was not applied');
        }
      } finally {
        signedBytes.fill(0);
      }
      const signingEvidence = await inspectAppleDevelopmentHost(hostPath);
      if (signingEvidence.executableBytes !== signed.identity.size) {
        throw new Error('Automation-twin signing evidence does not match the held host');
      }
      await assertHeldPath(signed, hostPath, 'Automation-twin signed host');
      await assertPathAbsent(`${hostPath}.cstemp`, 'Automation-twin codesign temporary');
      return signingEvidence;
    } finally {
      await signed.handle.close();
    }
  } finally {
    await held.handle.close();
  }
}

async function buildAndInspectVariant({
  anchors,
  buildEnv,
  captureProbeHarness = true,
  forbiddenValues,
  kind,
  sourceDigest,
  tools,
}) {
  if (typeof captureProbeHarness !== 'boolean') {
    throw new Error('Variant probe-harness capture flag is invalid');
  }
  const definition = architectureVariantDefinition(kind);
  const overlay = writeVariantOverlay(kind, definition.overlay);
  const frontendRoot = resolve(sourceRoot, 'dist');
  try {
    mkdirSync(frontendRoot, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  const frontendRootState = await lstat(frontendRoot);
  if (!frontendRootState.isDirectory()
    || frontendRootState.isSymbolicLink()
    || (frontendRootState.mode & 0o022) !== 0
    || (typeof process.getuid === 'function' && frontendRootState.uid !== process.getuid())) {
    throw new Error('Excluded frontend output root is unsafe');
  }
  const environment = {
    ...buildEnv,
    ...definition.frontend,
    PIUI_A26_MODULE_PROVENANCE_PATH: resolve(
      buildEnv.TMPDIR,
      `a26-module-provenance-${randomBytes(16).toString('hex')}.json`,
    ),
  };
  const typescript = resolve(sourceRoot, 'node_modules/typescript/bin/tsc');
  const vite = resolve(sourceRoot, 'node_modules/vite/bin/vite.js');
  setIsolatedChildFailurePhase('variant-type-verification');
  try {
    await runSandboxed(
      tools.pnpmNode,
      [typescript, '--noEmit', '--pretty', 'false'],
      `${definition.title} frontend type verification`,
      environment,
      5 * 60_000,
      { frozenInputFailurePhasePrefix: 'variant-type-verification-frozen-input' },
    );
  } catch (error) {
    setSandboxFailureClassPhase('variant-type-verification', error);
    throw error;
  }
  setIsolatedChildFailurePhase('variant-frontend-build');
  try {
    await runSandboxed(
      tools.pnpmNode,
      [vite, 'build', '--configLoader', 'runner'],
      `${definition.title} authenticated frontend build`,
      environment,
      10 * 60_000,
      { frozenInputFailurePhasePrefix: 'variant-frontend-build-frozen-input' },
    );
  } catch (error) {
    setSandboxFailureClassPhase('variant-frontend-build', error);
    throw error;
  }
  const frontendProvenance = await readTrustedRegularFile(
    environment.PIUI_A26_MODULE_PROVENANCE_PATH,
    undefined,
    `${definition.title} A.26 module provenance`,
  );
  const tauriEntry = resolve(sourceRoot, 'node_modules/@tauri-apps/cli/tauri.js');
  const tauriArguments = [
    tauriEntry,
    'build',
    '--target',
    target,
    '--bundles',
    'app',
    '--no-sign',
    '--config',
    formalBuildOverlayPath,
  ];
  if (definition.cargoFeatures.length > 0) {
    tauriArguments.push('--features', definition.cargoFeatures.join(','));
  }
  if (overlay) tauriArguments.push('--config', overlay);
  setIsolatedChildFailurePhase('variant-native-build');
  try {
    await runSandboxed(
      tools.pnpmNode,
      tauriArguments,
      `${definition.title} local package build`,
      environment,
      20 * 60_000,
      { frozenInputFailurePhasePrefix: 'variant-native-build-frozen-input' },
    );
  } catch (error) {
    setSandboxFailureClassPhase('variant-native-build', error);
    throw error;
  }

  setIsolatedChildFailurePhase('variant-inspection');
  setIsolatedChildFailurePhase('variant-inspection-bundle-discovery');
  const candidateAppPath = await findSingleApp(
    resolve(sourceRoot, `src-tauri/target/${target}/release/bundle/macos`),
  );
  setIsolatedChildFailurePhase('variant-inspection-bundle-copy');
  const appPath = await copyBundleToPrivateControl(
    candidateAppPath,
    resolve(buildIsolate, `accepted-bundle-${randomBytes(16).toString('hex')}`),
  );
  setIsolatedChildFailurePhase('variant-inspection-project-trust-capture');
  const projectTrustHarness = kind === 'production'
    && (authoritativeA24 || gateProduction)
    ? await projectTrustModule.captureProjectTrustHarness(sourceRoot)
    : undefined;
  setIsolatedChildFailurePhase('variant-inspection-credential-harness-capture');
  const credentialCleanupHarness = kind === 'credential-twin' && captureProbeHarness
    ? await captureCredentialCleanupHarness(
      sourceRoot,
      resolve(buildIsolate, 'credential-cleanup-control'),
    )
    : undefined;
  setIsolatedChildFailurePhase('variant-inspection-credential-helper-identity');
  const credentialCleanupHelperIdentity = credentialCleanupHarness
    ? createA23CleanupHelperIdentity({
      buildArguments: tauriArguments,
      formalBuildOverlayPath,
      frozenSourceDigest: sourceDigest,
      helper: credentialCleanupHarness,
      helperSourceSha256: requiredFrozenSourceSha256(
        'src-tauri/src/bin/credential-cleanup-harness.rs',
      ),
      tauriEntry,
      toolchainContextSha256: tools.authenticatedToolchainContextSha256,
      toolchainReceiptSha256: tools.authenticatedToolchainReceiptSha256,
      variantDefinitionSha256:
        ARCHITECTURE_VARIANT_DEFINITION_SHA256['credential-twin'],
      variantOverlayPath: overlay,
    })
    : undefined;
  setIsolatedChildFailurePhase('variant-inspection-approval-harness-capture');
  const approvalMatrixHarness = kind === 'approval-twin' && captureProbeHarness
    ? await captureApprovalMatrixHarness(sourceRoot)
    : undefined;
  setIsolatedChildFailurePhase('variant-inspection-harness-removal');
  await removeKnownTestHarnesses(appPath);
  if (definition.postBuild.externalHarness === 'credential-cleanup-harness') {
    await removeCredentialCleanupHarness(appPath);
  }
  if (definition.postBuild.externalHarness === 'approval-matrix-harness') {
    await removeApprovalMatrixHarness(appPath);
  }
  setIsolatedChildFailurePhase('variant-inspection-host-capture');
  const preSignHostBytes = await readTrustedRegularFile(
    resolve(appPath, 'Contents/MacOS/piui'),
    undefined,
    `${definition.title} pre-explicit-sign host`,
  );
  setIsolatedChildFailurePhase('variant-inspection-host-signing');
  const hostSigningIdentity = definition.postBuild.hostSigning === 'apple-development'
    ? await signAutomationHost(appPath, environment)
    : undefined;
  setIsolatedChildFailurePhase('variant-inspection-sealing');
  await sealBundle(appPath);
  setIsolatedChildFailurePhase('variant-inspection-bundle-inventory');
  const accepted = await inspectBundle({
    anchors,
    appPath,
    forbiddenValues,
    hostSigningIdentity,
    sourceRoot,
  });
  if (kind === 'automation-twin' && accepted.hostSignature !== 'apple-development') {
    throw new Error('Automation twin did not retain its required Apple Development host signature');
  }
  setIsolatedChildFailurePhase('variant-inspection-bundle-revalidation');
  await revalidateBundle(accepted);
  setIsolatedChildFailurePhase('variant-inspection-frozen-input-recheck');
  await assertFrozenBuildInputs('variant-inspection-frozen-input-recheck');
  return Object.freeze({
    accepted,
    approvalMatrixHarness,
    credentialCleanupHarness,
    credentialCleanupHelperIdentity,
    frontendProvenance,
    preSignHostBytes,
    projectTrustHarness,
    variant: definition,
  });
}

function equalStageAnchors(left, right) {
  return left?.manifestSha256 === right?.manifestSha256
    && left?.nodeSha256 === right?.nodeSha256
    && left?.nodeBytes === right?.nodeBytes
    && Buffer.isBuffer(left?.manifestBytes)
    && Buffer.isBuffer(right?.manifestBytes)
    && left.manifestBytes.equals(right.manifestBytes)
    && canonicalArchitectureJson(left.manifest)
      === canonicalArchitectureJson(right.manifest);
}

async function assertAuthenticatedNodeAnchor(anchors, tools) {
  if (typeof tools?.authenticatedNode !== 'string'
    || !tools.authenticatedNode.startsWith(`${tools.closureRoot}/`)) {
    throw new Error('Authenticated Node executable is unavailable');
  }
  const state = await lstat(tools.authenticatedNode);
  if (!state.isFile()
    || state.isSymbolicLink()
    || anchors?.nodeSha256 !== architectureToolchainPins.node.executableSha256
    || anchors?.nodeBytes !== state.size) {
    throw new Error('Staged Node anchor does not match the authenticated executable');
  }
}

async function rebuildFreshStageAnchors(referenceAnchors, tools, buildEnv) {
  await resetGeneratedOutputs();
  await assertFrozenBuildInputs();
  await provisionPinnedNodeOutput(tools, buildEnv, 'Fresh pinned Node provisioning');
  await runSandboxed(
    tools.pnpmNode,
    ['scripts/verify-toolchain.mjs'],
    'Fresh toolchain verification',
    buildEnv,
    120_000,
  );
  await stageSidecarControlled(tools, buildEnv);
  const fresh = await captureStageAnchors({
    expectedNode: '22.23.1',
    expectedPi: '0.82.0',
    nodePath: resolve(sourceRoot, `src-tauri/binaries/piui-node-${target}`),
    sidecarRoot: resolve(sourceRoot, 'src-tauri/resources/sidecar'),
  });
  if (!equalStageAnchors(referenceAnchors, fresh)) {
    throw new Error('Fresh generated build anchors differ from the initial held anchors');
  }
  return fresh;
}

async function retainAcceptedBundle(bundle, retentionRoot) {
  mkdirSync(retentionRoot, { mode: 0o700 });
  return relocateAcceptedBundle(bundle, resolve(retentionRoot, 'production.app'));
}

function bigintDirectoryIdentity(item) {
  return Object.freeze({
    dev: BigInt(item.dev),
    gid: BigInt(item.gid),
    ino: BigInt(item.ino),
    mode: BigInt(item.mode),
    uid: BigInt(item.uid),
  });
}

function assertExclusiveRenameReceipt(receipt, expected, destination) {
  if (!receipt || receipt.operationCompleted !== true || receipt.destination !== destination
    || receipt.destinationIdentity?.dev !== BigInt(expected.dev)
    || receipt.destinationIdentity?.ino !== BigInt(expected.ino)
    || receipt.destinationIdentity?.uid !== BigInt(expected.uid)
    || receipt.destinationIdentity?.gid !== BigInt(expected.gid)) {
    throw new Error('Accepted bundle exclusive-rename receipt is invalid');
  }
}

export async function relocateAcceptedBundle(bundle, destination, testHook) {
  await assertPathAbsent(destination, 'Accepted bundle destination');
  let sourceParent;
  let destinationParent;
  let source;
  let moved = false;
  let primaryFailure;
  try {
    sourceParent = await openHeldPath(
      dirname(bundle.appPath),
      'directory',
      'Accepted bundle source parent',
    );
    destinationParent = await openHeldPath(
      dirname(destination),
      'directory',
      'Accepted bundle destination parent',
    );
    source = await openHeldPath(bundle.appPath, 'directory', 'Accepted bundle');
    if ((sourceParent.identity.mode & 0o777) !== 0o700
      || (destinationParent.identity.mode & 0o777) !== 0o700) {
      throw new Error('Accepted bundle publication parents are not private');
    }
    await source.handle.chmod(0o700);
    const writableSource = await assertHeldPath(source, bundle.appPath, 'Accepted bundle');
    if ((writableSource.mode & 0o777) !== 0o700) {
      throw new Error('Accepted bundle descriptor could not be prepared for publication');
    }
    await assertHeldPath(sourceParent, dirname(bundle.appPath), 'Accepted bundle source parent');
    await assertHeldPath(destinationParent, dirname(destination), 'Accepted bundle destination parent');
    if (testHook) await testHook(Object.freeze({ destination, source: bundle.appPath }));
    let renameReceipt;
    let completedFinalisationError;
    try {
      renameReceipt = exclusiveDirectoryRename(bundle.appPath, destination, {
        expectedDestinationParentIdentity: bigintDirectoryIdentity(destinationParent.identity),
        expectedSourceIdentity: bigintDirectoryIdentity(writableSource),
        expectedSourceParentIdentity: bigintDirectoryIdentity(sourceParent.identity),
      });
    } catch (error) {
      if (error?.operationCompleted !== true) throw error;
      renameReceipt = error.receipt;
      completedFinalisationError = error;
    }
    assertExclusiveRenameReceipt(renameReceipt, writableSource, destination);
    moved = true;
    await assertHeldPath(source, destination, 'Relocated accepted bundle');
    await source.handle.chmod(0o555);
    const sealedDestination = await assertHeldPath(source, destination, 'Relocated accepted bundle');
    if ((sealedDestination.mode & 0o777) !== 0o555) {
      throw new Error('Relocated accepted bundle root did not reseal');
    }
    await assertHeldPath(sourceParent, dirname(bundle.appPath), 'Accepted bundle source parent');
    await assertHeldPath(destinationParent, dirname(destination), 'Accepted bundle destination parent');
    if (completedFinalisationError) throw completedFinalisationError;
  } catch (error) {
    primaryFailure = error;
    if (source) {
      try {
        await source.handle.chmod(0o555);
      } catch (restoreError) {
        primaryFailure = new AggregateError(
          [error, restoreError],
          'Accepted bundle relocation and reseal failed',
        );
      }
    }
  }
  const closeFailures = [];
  for (const lease of [source, destinationParent, sourceParent]) {
    if (!lease) continue;
    try { await lease.handle.close(); } catch (error) { closeFailures.push(error); }
  }
  if (primaryFailure && closeFailures.length > 0) {
    throw new AggregateError(
      [primaryFailure, ...closeFailures],
      'Accepted bundle relocation and descriptor cleanup failed',
    );
  }
  if (primaryFailure) throw primaryFailure;
  if (closeFailures.length > 0) {
    throw new AggregateError(closeFailures, 'Accepted bundle descriptor cleanup failed');
  }
  if (!moved) throw new Error('Accepted bundle was not relocated');
  const relocated = Object.freeze({
    ...bundle,
    appPath: destination,
    hostPath: resolve(destination, relative(bundle.appPath, bundle.hostPath)),
    nodePath: resolve(destination, relative(bundle.appPath, bundle.nodePath)),
  });
  await revalidateBundle(relocated);
  return relocated;
}

function packageInspectionEvidence(bundle, launch, cleanup) {
  if (!bundle || !launch || !Number.isSafeInteger(launch.observedIdentities)) {
    throw new Error('Package inspection evidence is incomplete');
  }
  return {
    status: 'pass',
    target,
    bundleFingerprint: bundle.fingerprint,
    fingerprintClaim: 'identity of this accepted sealed build; cross-build byte reproducibility is not claimed',
    bundleEntries: bundle.entries,
    bundleFiles: bundle.files,
    sidecarFiles: bundle.sidecarFiles,
    machoFiles: bundle.machoFiles,
    nodeVersion: bundle.nodeVersion,
    piVersion: bundle.piVersion,
    hostSignature: bundle.hostSignature,
    nodeSignature: bundle.nodeSignature,
    runtimeObservedIdentities: launch.observedIdentities,
    networkPolicy: 'inherited OS sandbox denial plus periodic descriptor defence-in-depth observation',
    cleanup,
    buildProcessBoundary: 'sampled PID/start/executable descendant ledger across observed reparenting and process-group changes; adversarial gapless containment is not claimed',
    candidateRetention: 'none; the inspected package is ephemeral and removed after the same-lease proof',
    signingAction: 'none; build used Tauri --no-sign and product signature states were parsed without codesign',
  };
}

function assertExactProductionArtifact(actual, expected) {
  if (!expected || canonicalArchitectureJson(actual) !== canonicalArchitectureJson(expected)) {
    throw new Error('Same-source production artefact does not match the architecture batch anchor');
  }
}

function assertTwinRuntimeHashes(twin, production) {
  if (!production
    || twin.baseProductionFingerprint !== production.fingerprint
    || twin.fingerprint === production.fingerprint
    || twin.nodeSha256 !== production.nodeSha256
    || twin.sidecarSha256 !== production.sidecarSha256) {
    throw new Error('Architecture twin does not retain the production runtime closure');
  }
}

function architectureProofBatch(
  batchId,
  artifact,
  sourceDigest,
  proofs,
  requireFinalProofs = false,
) {
  const envelopes = Object.fromEntries(Object.entries(proofs).map(([proofId, evidence]) => [
    proofId,
    createArchitectureProofEnvelope({
      artifact,
      evidence,
      proofId,
      sourceDigest,
    }),
  ]));
  return assertArchitectureProofBatch({
    artifact,
    batchId,
    proofs: envelopes,
    schemaVersion: 1,
    sourceDigest,
  }, batchId, { requireFinalProofs });
}

function evidenceLine(value) {
  return Buffer.from(`${canonicalArchitectureJson(value)}\n`, 'utf8');
}

function finaliseProofAfterCleanup(id, evidence) {
  if (id === 'A.23') {
    return assertSafeCredentialEvidence({
      ...evidence,
      generatedOutputsRemoved: true,
    }, true, evidence.bundleFingerprint);
  }
  if (id === 'A.24') {
    return projectTrustModule.parsePackagedTrustEvidence(evidenceLine({
      ...evidence,
      generatedOutputsRemoved: true,
    }));
  }
  if (id === 'A.25') {
    return parsePackagedApprovalMatrixEvidence(evidenceLine({
      ...evidence,
      generatedOutputsRemoved: true,
    }));
  }
  if (id === 'A.26') {
    return parsePackagedMarkdownEvidence(evidenceLine({
      ...evidence,
      generatedOutputsRemoved: true,
    }));
  }
  if (id === 'A.27') {
    if (!lifecycleModule || typeof lifecycleModule.finaliseLifecycleEvidence !== 'function') {
      throw new Error('A.27 lifecycle evidence finaliser is unavailable');
    }
    return lifecycleModule.finaliseLifecycleEvidence(evidence);
  }
  if (id === 'A.21') return Object.freeze({ ...evidence, cleanup: 'passed' });
  return evidence;
}

function finaliseResultAfterCleanup(result) {
  if (guardedProduction) {
    return createGuardedProductionResult({
      artifact: result.artifact,
      gateRunId: result.gateRunId,
      generatedOutputsRemoved: true,
      sourceDigest: result.sourceDigest,
    });
  }
  if (architectureBatch) {
    const proofs = Object.fromEntries(Object.entries(result.proofs).map(([id, envelope]) => [
      id,
      finaliseProofAfterCleanup(id, envelope.evidence),
    ]));
    return architectureProofBatch(
      result.batchId,
      result.artifact,
      result.sourceDigest,
      proofs,
      true,
    );
  }
  const proofId = {
    a23: 'A.23',
    a24: 'A.24',
    a25: 'A.25',
    a26: 'A.26',
    a27: 'A.27',
  }[requestedMode];
  if (proofId) return finaliseProofAfterCleanup(proofId, result);
  if (requestedMode === 'a21') return finaliseProofAfterCleanup('A.21', result);
  return result;
}

const EXACT_A26_CSP = "default-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self'; style-src-attr 'none'; img-src 'self' piui-raster:; font-src 'self'; connect-src ipc: http://ipc.localhost; object-src 'none'; frame-src 'none'; child-src 'none'; worker-src 'none'; media-src 'none'; manifest-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const EXACT_A26_CSP_WITHOUT_RASTER = "default-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self'; style-src-attr 'none'; img-src 'self'; font-src 'self'; connect-src ipc: http://ipc.localhost; object-src 'none'; frame-src 'none'; child-src 'none'; worker-src 'none'; media-src 'none'; manifest-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

async function inspectFrontendBuild(directory) {
  const files = [];
  let totalBytes = 0;
  async function visit(current) {
    const currentState = await lstat(current);
    if (!currentState.isDirectory()
      || currentState.isSymbolicLink()
      || (currentState.mode & 0o022) !== 0
      || (typeof process.getuid === 'function' && currentState.uid !== process.getuid())) {
      throw new Error('Bundled frontend input contains an unsafe directory');
    }
    const entries = await readdir(current, { withFileTypes: true });
    entries.sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
    for (const entry of entries) {
      const path = resolve(current, entry.name);
      if (entry.isDirectory()) {
        await visit(path);
        continue;
      }
      if (!entry.isFile()) throw new Error('Bundled frontend input contains an unsupported entry');
      const bytes = await readTrustedRegularFile(path, undefined, 'Bundled frontend input');
      totalBytes += bytes.length;
      if (files.length >= 4_096 || totalBytes > 128 * 1024 * 1024) {
        throw new Error('Bundled frontend input exceeds its inspection bounds');
      }
      files.push(Object.freeze({
        bytes,
        path: relative(directory, path).split('/').join('/'),
      }));
    }
  }
  await visit(directory);
  if (!files.some((file) => file.path === 'index.html')) {
    throw new Error('Bundled frontend input is missing its index');
  }
  return Object.freeze(files);
}

function containsAscii(bytes, value) {
  return bytes.includes(Buffer.from(value, 'utf8'));
}

// Production must carry no hostile fixture; the automation twin must carry the pinned one.
function deriveA26FrontendInventory(frontend, provenance, role) {
  return deriveA26FrontendInventoryFromProvenance(frontend, provenance, role);
}

async function deriveA26BundleEvidence({
  automationBundle,
  automationFrontend,
  automationProvenance,
  productionBundle,
  productionFrontend,
  productionProvenance,
  repeatAutomationFrontend,
  repeatAutomationProvenance,
}) {
  await revalidateBundle(productionBundle);
  await revalidateBundle(automationBundle);
  const [productionHost, automationHost, configBytes, cargoBytes] = await Promise.all([
    readTrustedRegularFile(productionBundle.hostPath, undefined, 'Production host'),
    readTrustedRegularFile(automationBundle.hostPath, undefined, 'Automation host'),
    readTrustedRegularFile(resolve(sourceRoot, 'src-tauri/tauri.conf.json'), undefined, 'Tauri configuration'),
    readTrustedRegularFile(resolve(sourceRoot, 'src-tauri/Cargo.toml'), undefined, 'Cargo manifest'),
  ]);
  await revalidateBundle(productionBundle);
  await revalidateBundle(automationBundle);

  const productionInventory = deriveA26FrontendInventory(
    productionFrontend,
    productionProvenance,
    'production',
  );
  const automationInventory = deriveA26FrontendInventory(
    automationFrontend,
    automationProvenance,
    'automation',
  );
  const repeatAutomationInventory = deriveA26FrontendInventory(
    repeatAutomationFrontend,
    repeatAutomationProvenance,
    'automation',
  );
  if (JSON.stringify(automationInventory)
    !== JSON.stringify(repeatAutomationInventory)) {
    throw new Error('A.26 automation frontend inventory is not reproducible');
  }

  let config;
  try {
    config = JSON.parse(configBytes.toString('utf8'));
  } catch {
    throw new Error('Tauri configuration is not valid JSON');
  }
  const csp = config?.app?.security?.csp;
  const cargo = cargoBytes.toString('utf8');
  const activationMarkers = [
    'PIUI_ARCHITECTURE_TEST_MODE',
    'PIUI_ARCHITECTURE_TEST_NONCE',
    'PIUI_ARCHITECTURE_TEST_PORT',
    'a26-markdown',
    'a28-accessibility',
  ];
  const productionContainsDriver = activationMarkers.some((marker) =>
    containsAscii(productionHost, marker));
  const automationContainsDriver = activationMarkers.every((marker) =>
    containsAscii(automationHost, marker))
    && /architecture-test\s*=\s*\[\s*"dep:tauri-plugin-wdio-webdriver"\s*\]/u.test(cargo)
    && /tauri-plugin-wdio-webdriver\s*=\s*\{[^}]*version\s*=\s*"=1\.2\.0"[^}]*optional\s*=\s*true[^}]*\}/su.test(cargo);
  const cspAnchored = sha256Bytes(configBytes) === productionBundle.sourceConfigSha256
    && sha256Bytes(configBytes) === automationBundle.sourceConfigSha256;
  const cspExact = cspAnchored && csp === EXACT_A26_CSP;
  const piuiRasterOnlyImageAddition = cspExact
    && csp.split('piui-raster:').length === 2
    && csp.replace(' piui-raster:', '') === EXACT_A26_CSP_WITHOUT_RASTER;

  const evidence = {
    automationFrontend: automationInventory.evidence,
    automationWebdriverIncluded: automationContainsDriver,
    cspExact,
    piuiRasterOnlyImageAddition,
    productionFrontend: productionInventory.evidence,
    productionWebdriverIncluded: productionContainsDriver,
    repeatAutomationFrontend: repeatAutomationInventory.evidence,
  };
  if (evidence.productionWebdriverIncluded !== false
    || evidence.automationWebdriverIncluded !== true
    || evidence.cspExact !== true
    || evidence.piuiRasterOnlyImageAddition !== true) {
    throw new Error('A.26 accepted-bundle evidence derivation failed');
  }
  return Object.freeze({
    evidence: Object.freeze(evidence),
    expectedResourcePaths: automationInventory.expectedResourcePaths,
  });
}

async function executeRequiredLifecycleProbe(input) {
  lifecycleModule = await import(pathToFileURL(
    resolve(sourceRoot, 'scripts/run-packaged-lifecycle-probe.mjs'),
  ).href);
  if (typeof lifecycleModule.executeAuthoritativeLifecycleProbe !== 'function'
    || typeof lifecycleModule.finaliseLifecycleEvidence !== 'function') {
    throw new Error('A.27 packaged lifecycle executor is unavailable');
  }
  return lifecycleModule.executeAuthoritativeLifecycleProbe(input);
}

async function executeRequiredAccessibilityProbe(input, evidenceRootIdentity) {
  try {
    return await executeAuthoritativeAccessibilityProbe(input);
  } finally {
    if (evidenceRootIdentity) {
      await assertAccessibilityEvidenceRoot(
        evidenceRootIdentity.path,
        evidenceRootIdentity,
      );
    }
  }
}

async function privateTemporary(prefix) {
  const path = await mkdtemp(resolve(temporaryRoot, prefix));
  await chmod(path, 0o700);
  if (await realpath(path) !== path) {
    throw new Error('Owned temporary directory is not canonical');
  }
  return path;
}

async function resetGeneratedOutputs() {
  for (const output of generated) {
    const state = await lstat(output.path);
    if (output.kind === 'directory') {
      if (!state.isDirectory() || state.isSymbolicLink()) {
        throw new Error('Declared generated directory is unsafe');
      }
      await chmod(output.path, 0o700);
      for (const name of await readdir(output.path)) {
        await removeOwnedTree(resolve(output.path, name));
      }
      continue;
    }
    if (!state.isFile() || state.isSymbolicLink() || state.nlink !== 1) {
      throw new Error('Declared generated file is unsafe');
    }
    await chmod(output.path, 0o600);
    const handle = await openFile(
      output.path,
      constants.O_WRONLY | constants.O_TRUNC | constants.O_NOFOLLOW,
    );
    try {
      const opened = await handle.stat();
      if (!opened.isFile()
        || opened.dev !== state.dev
        || opened.ino !== state.ino
        || opened.nlink !== 1) {
        throw new Error('Declared generated file identity changed');
      }
    } finally {
      await handle.close();
    }
  }
}

async function removeGeneratedOutputs() {
  for (const output of generated) {
    const parent = dirname(output.path);
    const parentBefore = await lstat(parent);
    if (!parentBefore.isDirectory()
      || parentBefore.isSymbolicLink()
      || (typeof process.getuid === 'function' && parentBefore.uid !== process.getuid())) {
      throw new Error('Declared generated output parent is unsafe');
    }
    await chmod(parent, 0o700);
    try {
      await removeOwnedTree(output.path);
    } finally {
      await chmod(parent, parentBefore.mode & 0o777);
    }
  }
}

async function removeOwnedTree(path) {
  let rootStat;
  try { rootStat = await lstat(path); } catch (error) { if (error?.code === 'ENOENT') return; throw error; }
  if (rootStat.isSymbolicLink()) throw new Error(`Refusing to clean generated-root symlink: ${relative(sourceRoot, path)}`);
  async function prepare(current) {
    const item = await lstat(current);
    if (item.isSymbolicLink()) return;
    if (item.isFile()) {
      if (item.nlink !== 1) throw new Error(`Refusing to clean hard-linked generated file: ${relative(sourceRoot, current)}`);
      return;
    }
    if (!item.isDirectory()) throw new Error(`Refusing to clean special generated entry: ${relative(sourceRoot, current)}`);
    const fd = openSync(current, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try {
      const exact = fstatSync(fd);
      if (!exact.isDirectory() || exact.dev !== item.dev || exact.ino !== item.ino) {
        throw new Error(`Generated directory identity changed during cleanup: ${relative(sourceRoot, current)}`);
      }
      fchmodSync(fd, 0o700);
    } finally {
      closeSync(fd);
    }
    for (const name of await readdir(current)) await prepare(resolve(current, name));
  }
  await prepare(path);
  await rm(path, { recursive: true, force: true, maxRetries: 6, retryDelay: 100 });
}

async function assertGeneratedAbsent() {
  for (const output of generated) {
    try { await lstat(output.path); throw new Error(`Generated path remained after cleanup: ${relative(sourceRoot, output.path)}`); }
    catch (error) { if (error?.code !== 'ENOENT') throw error; }
  }
}

async function findSingleApp(directory) {
  const entries = (await readdir(directory, { withFileTypes: true })).filter((entry) => entry.isDirectory() && entry.name.endsWith('.app'));
  if (entries.length !== 1) throw new Error(`Expected exactly one app bundle, found ${entries.length}`);
  return resolve(directory, entries[0].name);
}

async function removeKnownTestHarnesses(appPath) {
  for (const name of ['stream-harness', 'project-trust-harness']) {
    const path = resolve(appPath, 'Contents/MacOS', name);
    const item = await lstat(path);
    if (!item.isFile() || item.isSymbolicLink() || item.nlink !== 1) {
      throw new Error('Test harness bundle artefact was not a regular unique file');
    }
    await unlink(path);
  }
}

async function removeCredentialCleanupHarness(appPath) {
  const path = resolve(appPath, 'Contents/MacOS', 'credential-cleanup-harness');
  const item = await lstat(path);
  if (!item.isFile() || item.isSymbolicLink() || item.nlink !== 1) {
    throw new Error('Credential cleanup harness bundle artefact was not a regular unique file');
  }
  await unlink(path);
}

async function removeApprovalMatrixHarness(appPath) {
  const path = resolve(appPath, 'Contents/MacOS', 'approval-matrix-harness');
  const item = await lstat(path);
  if (!item.isFile() || item.isSymbolicLink() || item.nlink !== 1) {
    throw new Error('Approval-matrix harness bundle artefact was not a regular unique file');
  }
  await unlink(path);
}

async function captureBundleSealTree(appPath) {
  const root = resolve(appPath);
  const entries = [];
  async function visit(path) {
    const before = await lstat(path);
    const rel = path === root ? '.' : relative(root, path);
    if ((rel !== '.' && (rel === '..' || rel.startsWith('../') || resolve(root, rel) !== path))
      || before.isSymbolicLink()
      || (!before.isFile() && !before.isDirectory())
      || (before.isFile() && before.nlink !== 1)
      || (typeof process.getuid === 'function' && before.uid !== process.getuid())) {
      throw new Error(`Cannot seal unsafe bundle entry: ${rel}`);
    }
    entries.push(Object.freeze({
      dev: before.dev,
      executable: before.isFile() && (before.mode & 0o111) !== 0,
      ino: before.ino,
      kind: before.isDirectory() ? 'directory' : 'file',
      mode: before.mode & 0o777,
      nlink: before.nlink,
      path,
      rel,
      size: before.size,
    }));
    if (before.isDirectory()) {
      const names = await readdir(path);
      names.sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
      for (const name of names) await visit(resolve(path, name));
    }
    const after = await lstat(path);
    if (!sameHeldIdentity(before, after) || after.size !== before.size
      || after.mode !== before.mode) {
      throw new Error(`Bundle entry changed while preparing to seal: ${rel}`);
    }
  }
  await visit(root);
  entries.sort((left, right) => Buffer.from(left.rel).compare(Buffer.from(right.rel)));
  return Object.freeze(entries);
}

function sameSealTree(left, right) {
  return left.length === right.length && left.every((entry, index) => {
    const other = right[index];
    return entry.dev === other.dev
      && entry.ino === other.ino
      && entry.kind === other.kind
      && entry.nlink === other.nlink
      && entry.rel === other.rel
      && entry.size === other.size;
  });
}

export async function sealBundle(appPath) {
  const canonical = await realpath(resolve(appPath));
  if (canonical !== resolve(appPath)) throw new Error('Final bundle root is not canonical');
  await inventoryBundle(canonical);
  const beforeSeal = await captureBundleSealTree(canonical);

  const deepestFirst = [...beforeSeal].sort((left, right) => (
    right.rel.split('/').length - left.rel.split('/').length
      || Buffer.from(left.rel).compare(Buffer.from(right.rel))
  ));
  for (const entry of deepestFirst) {
    const held = await openHeldPath(entry.path, entry.kind, `Final bundle entry ${entry.rel}`);
    try {
      if (held.identity.dev !== entry.dev || held.identity.ino !== entry.ino
        || held.identity.size !== entry.size) {
        throw new Error(`Final bundle entry identity changed before sealing: ${entry.rel}`);
      }
      const mode = entry.kind === 'directory' || entry.executable ? 0o555 : 0o444;
      await held.handle.chmod(mode);
      const sealed = await assertHeldPath(held, entry.path, `Final bundle entry ${entry.rel}`);
      if ((sealed.mode & 0o777) !== mode) {
        throw new Error(`Final bundle entry mode did not seal: ${entry.rel}`);
      }
    } finally {
      await held.handle.close();
    }
  }
  const sealed = await captureBundleSealTree(canonical);
  if (!sameSealTree(beforeSeal, sealed)
    || sealed.some((entry, index) => entry.mode !== (
      beforeSeal[index].kind === 'directory' || beforeSeal[index].executable
        ? 0o555
        : 0o444
    ))) {
    throw new Error('Final bundle sealing witness changed');
  }
  await inventoryBundle(canonical);
}

function createSyntheticCanaries() {
  return Object.freeze(Array.from({ length: 4 }, () => (
    `PIUI_BUILD_CANARY_${randomBytes(32).toString('hex')}`
  )));
}

function parseSyntheticCanaries(value) {
  if (typeof value !== 'string' || value.length > 1_024 || value.includes('\0')) {
    throw new Error('Synthetic build canaries are invalid');
  }
  let canaries;
  try {
    canaries = JSON.parse(value);
  } catch {
    throw new Error('Synthetic build canaries are invalid');
  }
  if (!Array.isArray(canaries)
    || canaries.length !== 4
    || canaries.some((canary) => (
      typeof canary !== 'string'
      || !/^PIUI_BUILD_CANARY_[0-9a-f]{64}$/u.test(canary)
    ))
    || new Set(canaries).size !== canaries.length
    || canonicalArchitectureJson(canaries) !== value) {
    throw new Error('Synthetic build canaries are invalid');
  }
  return Object.freeze([...canaries]);
}

function boundedAmbientPrivateValues(environment, privateRepositoryRoot) {
  const publicKeys = /^(?:PATH|HOME|PWD|OLDPWD|SHELL|TERM|LANG|LC_|USER|LOGNAME|SHLVL|_|COLORTERM|TERM_PROGRAM|TERM_SESSION_ID|TMPDIR)$/u;
  const controlKeys = new Set([
    'PIUI_A28_HUMAN_EVIDENCE_ROOT',
    'PIUI_ARCHITECTURE_PRODUCTION_ARTIFACT',
    'PIUI_ARCHITECTURE_SOURCE_DIGEST',
    'PIUI_GUARDED_PRODUCTION_OUTPUT_ROOT',
  ]);
  const values = [privateRepositoryRoot];
  let totalBytes = Buffer.byteLength(privateRepositoryRoot);
  for (const [key, value] of Object.entries(environment)) {
    if (publicKeys.test(key)
      || controlKeys.has(key)
      || typeof value !== 'string'
      || value.length < 16
      || value.length > 4_096
      || values.includes(value)) continue;
    totalBytes += Buffer.byteLength(value);
    if (values.length >= 4_096 || totalBytes > 2 * 1_048_576) {
      throw new Error('Parent-only private-value inspection input exceeds its bound');
    }
    values.push(value);
  }
  return Object.freeze(values.sort((left, right) => Buffer.from(left).compare(Buffer.from(right))));
}

function assertBuffersExcludeValues(buffers, values, label) {
  if (!Array.isArray(buffers)
    || !buffers.every(Buffer.isBuffer)
    || !Array.isArray(values)
    || values.length > 4_096) {
    throw new Error(`${label} inspection is invalid`);
  }
  for (const buffer of buffers) {
    for (const value of values) {
      if (buffer.includes(Buffer.from(value))) {
        throw new Error(`${label} contained a parent-only private value`);
      }
    }
  }
}

function runtimeEnvironment(root) {
  const home = resolve(root, 'home');
  const temporary = resolve(root, 'tmp');
  const cache = resolve(root, 'cache');
  const data = resolve(root, 'data');
  const agent = resolve(root, 'agent');
  const sessions = resolve(root, 'sessions');
  for (const path of [home, temporary, cache, data, agent, sessions, resolve(root, 'config')]) mkdirSync(path, { recursive: true, mode: 0o700 });
  return { HOME: home, CFFIXED_USER_HOME: home, TMPDIR: `${temporary}/`, XDG_CACHE_HOME: cache, XDG_CONFIG_HOME: resolve(root, 'config'), XDG_DATA_HOME: data, PIUI_AGENT_ROOT: agent, PIUI_SESSION_ROOT: sessions, PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'en_AU.UTF-8', LC_ALL: 'en_AU.UTF-8' };
}

async function launchAndInspect(bundle) {
  runtimeIsolate = await privateTemporary('piui-a21-runtime-');
  const stdoutPath = resolve(runtimeIsolate, 'stdout.log');
  const stderrPath = resolve(runtimeIsolate, 'stderr.log');
  const stdoutFd = openSync(stdoutPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
  const stderrFd = openSync(stderrPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
  let child;
  try {
    child = spawn(
      '/usr/bin/sandbox-exec',
      ['-p', runtimeSandbox(bundle, runtimeIsolate), bundle.hostPath],
      {
        cwd: runtimeIsolate,
        env: runtimeEnvironment(runtimeIsolate),
        detached: true,
        stdio: ['ignore', stdoutFd, stderrFd],
      },
    );
    await waitForChildSpawn(child);
  } finally {
    closeSync(stdoutFd);
    closeSync(stderrFd);
  }
  runtimeRootPid = child.pid;
  runtimeLedger = new ProcessLedger({ bundleRoot: bundle.appPath, isolateRoot: runtimeIsolate, hostPath: bundle.hostPath, nodePath: bundle.nodePath });
  let initialised = false;
  for (let attempt = 0; attempt < 30 && !initialised; attempt += 1) {
    try { await runtimeLedger.initialise(child.pid); initialised = true; } catch { await sleep(25); }
  }
  if (!initialised) throw new Error('Could not bind packaged root process identity');
  runtimeLedgerInitialised = true;
  const deadline = Date.now() + 30_000;
  let ready = false;
  while (Date.now() < deadline) {
    const live = await runtimeLedger.sample();
    if (!live.some((entry) => entry.executable === bundle.hostPath)) {
      throw new Error('Packaged host exited before authenticated readiness');
    }
    const stderr = await readFile(stderrPath, 'utf8');
    if (stderr.split(/\r?\n/).includes(readinessLine) && runtimeLedger.hasLiveHostAndNode(live)) {
      ready = true;
      break;
    }
    await sleep(100);
  }
  if (!ready) throw new Error('Authenticated packaged sidecar readiness was not observed');
  for (let index = 0; index < 10; index += 1) {
    await sleep(100);
    const live = await runtimeLedger.sample();
    if (!runtimeLedger.hasLiveHostAndNode(live)) {
      throw new Error('Packaged host or sidecar exited during readiness stability window');
    }
  }
  const output = `${await readFile(stdoutPath, 'utf8')}\n${await readFile(stderrPath, 'utf8')}`;
  if (/127\.0\.0\.1:1420|localhost:1420|https?:\/\//i.test(output)) throw new Error('Runtime output disclosed a development or network endpoint');
  const observedIdentities = runtimeLedger.entries.size;
  const cleanup = await runtimeLedger.terminate();
  runtimeLedger = undefined;
  runtimeLedgerInitialised = false;
  runtimeRootPid = undefined;
  if (cleanup.forced) throw new Error('Packaged runtime required forced cleanup');
  await assertPrivateRuntimeModes(runtimeIsolate);
  await removeOwnedTree(runtimeIsolate);
  runtimeIsolate = undefined;
  return { observedIdentities };
}

async function assertPrivateRuntimeModes(root) {
  async function visit(path) {
    const item = await lstat(path);
    // WebKit explicitly creates some 0644 files, but every entry remains
    // unreachable through the 0700 isolate root. No descendant may grant
    // group/world write authority or set-id execution.
    if ((item.mode & 0o6022) !== 0) {
      throw new Error(`Isolated runtime created unsafe data mode: ${relative(root, path)} mode=${(item.mode & 0o7777).toString(8)}`);
    }
    if (item.isDirectory()) for (const name of await readdir(path)) await visit(resolve(path, name));
  }
  await visit(root);
}

function redactedMessage(error) {
  let message = error instanceof Error ? error.message : String(error);
  for (const value of [sourceRoot, homedir(), buildIsolate, runtimeIsolate].filter(Boolean)) message = message.split(value).join('<private>');
  return message.replace(/[\r\n]+/g, ' ').slice(0, 500);
}

if (directlyInvoked) {
  if (authoritativeA28) {
    process.stderr.write(
      'A.28 standalone accessibility proof is unavailable; run `pnpm gate:architecture:record`.\n',
    );
    process.exitCode = 2;
    releaseOwnedArchitectureBootstrap();
  } else {
    try {
      if (isolatedChild) await runIsolatedChild();
      else await runBootstrap();
    } finally {
      releaseOwnedArchitectureBootstrap();
    }
  }
}
