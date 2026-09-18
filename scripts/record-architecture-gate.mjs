import { randomBytes } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  lstat,
  mkdir,
  open,
  realpath,
} from 'node:fs/promises';
import { arch, homedir, platform, tmpdir } from 'node:os';
import {
  dirname,
  isAbsolute,
  join,
  resolve,
} from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ARCHITECTURE_GATE_SCHEMA_VERSION,
  ARCHITECTURE_GATE_TARGET,
  ARCHITECTURE_PROOF_CONTRACTS,
  ARCHITECTURE_PROOF_IDS,
  assertArchitectureGateResults,
  canonicalArchitectureJson,
  createArchitecturePassMarker,
  sha256Bytes,
} from './architecture-gate-schema.mjs';
import { parseArchitectureProofBatch } from './architecture-proof-batch.mjs';
import { snapshotArchitectureSource } from './architecture-source-snapshot.mjs';
import {
  configureAuthenticatedNodeSpawn,
  installParentCutoffs,
  runOwnedCommand,
} from './a21-gate-support.mjs';
import { createAuthenticatedNodeSpawnConfiguration } from './authenticated-node-spawn.mjs';
import { validateLatestArchitectureGate } from './check-architecture-gate.mjs';
import {
  architectureBootstrapChildOptions,
  assertArchitectureBootstrap,
  releaseArchitectureBootstrap,
} from './architecture-bootstrap-contract.mjs';
import { createA28ProgressTranscriptForwarder } from './a28-installed-witness-ceremony.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BATCH_ORDER = Object.freeze([...new Set(ARCHITECTURE_PROOF_IDS.map(
  (id) => ARCHITECTURE_PROOF_CONTRACTS[id].batchId,
))]);
const BATCH_ARGUMENTS = Object.freeze({
  approval: '--architecture-gate-approval',
  automation: '--architecture-gate-automation',
  credential: '--architecture-gate-credential',
  production: '--architecture-gate-production',
});
const RUN_NONCE = /^[0-9a-f]{32}$/u;

function reject(message = 'Architecture gate recording failed') {
  throw new Error(message);
}

function line(value) {
  return Buffer.from(`${canonicalArchitectureJson(value)}\n`, 'utf8');
}

function runTimestamp(date) {
  if (!(date instanceof Date) || Number.isNaN(date.valueOf())) reject();
  return date.toISOString().replace(/[-:.]/gu, '');
}

async function syncDirectory(path) {
  const handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY ?? 0));
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function writeExclusive(path, bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2) reject();
  const handle = await open(path, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await syncDirectory(dirname(path));
}

async function ensureDirectory(path, mode, allowExisting) {
  try {
    await mkdir(path, { mode });
  } catch (error) {
    if (!allowExisting || error?.code !== 'EEXIST') throw error;
  }
  const state = await lstat(path);
  if (!state.isDirectory()
    || state.isSymbolicLink()
    || (state.mode & 0o022) !== 0
    || (typeof process.getuid === 'function' && state.uid !== process.getuid())) reject();
}

async function createRun(repositoryRoot, sourceDigest, date, nonce) {
  const id = `${runTimestamp(date)}-${nonce}`;
  const forge = join(repositoryRoot, '.forge');
  const evidence = join(forge, 'evidence');
  const gate = join(evidence, 'architecture-gate');
  const runs = join(gate, 'runs');
  await ensureDirectory(forge, 0o700, true);
  await ensureDirectory(evidence, 0o700, true);
  await ensureDirectory(gate, 0o700, true);
  await ensureDirectory(runs, 0o700, true);
  const path = join(runs, id);
  await ensureDirectory(path, 0o700, false);
  const startedBytes = line({
    runId: id,
    schemaVersion: ARCHITECTURE_GATE_SCHEMA_VERSION,
    sourceDigest,
    startedAt: date.toISOString(),
    status: 'started',
    target: ARCHITECTURE_GATE_TARGET,
  });
  await writeExclusive(join(path, 'started.json'), startedBytes);
  return Object.freeze({
    contextSha256: sha256Bytes(startedBytes),
    id,
    path,
  });
}

function proofBytesFromBatches(batches) {
  return Object.freeze(Object.fromEntries(ARCHITECTURE_PROOF_IDS.map((id) => {
    const contract = ARCHITECTURE_PROOF_CONTRACTS[id];
    return [id, line(batches[contract.batchId].proofs[id])];
  })));
}

function assembleResults(source, batches, proofBytes) {
  const artifacts = Object.fromEntries(BATCH_ORDER.map((batchId) => [
    ARCHITECTURE_PROOF_CONTRACTS[ARCHITECTURE_PROOF_IDS.find(
      (id) => ARCHITECTURE_PROOF_CONTRACTS[id].batchId === batchId,
    )].artifactResultKey,
    batches[batchId].artifact,
  ]));
  const proofs = Object.fromEntries(ARCHITECTURE_PROOF_IDS.map((id) => {
    const contract = ARCHITECTURE_PROOF_CONTRACTS[id];
    const artifact = batches[contract.batchId].artifact;
    return [id, {
      artifactFingerprint: artifact.fingerprint,
      artifactKind: contract.artifactKind,
      commandId: contract.commandId,
      evidenceSha256: sha256Bytes(proofBytes[id]),
      sourceDigest: source.digest,
      status: 'pass',
    }];
  }));
  return assertArchitectureGateResults({
    artifacts,
    externalReleaseGates: {
      developerId: 'not-provided',
      distributionAuthorised: false,
      notarisation: 'not-provided',
      updaterHosting: 'not-provided',
      updaterSigning: 'not-provided',
    },
    limitations: {
      automationConformanceEquivalence: 'not-claimed',
      publicDistribution: 'not-authorised',
      trustedExtensionContainment: 'not-claimed',
    },
    proofs,
    schemaVersion: ARCHITECTURE_GATE_SCHEMA_VERSION,
    source,
    target: ARCHITECTURE_GATE_TARGET,
  });
}

async function completeRun(run, results, proofBytes) {
  const proofsPath = join(run.path, 'proofs');
  await mkdir(proofsPath, { mode: 0o700 });
  for (const id of Object.keys(proofBytes).sort()) {
    await writeExclusive(join(proofsPath, `${id}.json`), proofBytes[id]);
  }
  await writeExclusive(join(run.path, 'results.json'), line(results));
  await writeExclusive(join(run.path, 'pass-marker.json'), line(createArchitecturePassMarker(results)));
}

async function recordFailure(run, batchId) {
  if (!run) return;
  try {
    await writeExclusive(join(run.path, 'failure.json'), line({
      batchId: batchId ?? 'initialisation',
      reasonCode: 'architecture-proof-failed',
      runId: run.id,
      schemaVersion: ARCHITECTURE_GATE_SCHEMA_VERSION,
      status: 'failed',
    }));
  } catch {
    // The incomplete append-only run remains an authoritative blocker.
  }
}

async function executeDefaultBatch({
  architectureGateRunContextSha256,
  architectureGateRunId,
  batchId,
  productionArtifact,
  signal,
  sourceDigest,
}) {
  const bootstrap = architectureBootstrapChildOptions(root);
  const environment = {
    HOME: homedir(),
    LANG: 'en_AU.UTF-8',
    LC_ALL: 'en_AU.UTF-8',
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    TMPDIR: `${await realpath(tmpdir())}/`,
    PIUI_ARCHITECTURE_GATE_RUN_CONTEXT_SHA256: architectureGateRunContextSha256,
    PIUI_ARCHITECTURE_GATE_RUN_ID: architectureGateRunId,
    PIUI_ARCHITECTURE_SOURCE_DIGEST: sourceDigest,
    ...bootstrap.environment,
  };
  if (productionArtifact) {
    environment.PIUI_ARCHITECTURE_PRODUCTION_ARTIFACT = canonicalArchitectureJson(productionArtifact);
  }
  if (typeof process.env.PIUI_A28_HUMAN_EVIDENCE_ROOT === 'string') {
    environment.PIUI_A28_HUMAN_EVIDENCE_ROOT = process.env.PIUI_A28_HUMAN_EVIDENCE_ROOT;
  }
  const progress = batchId === 'automation'
    ? createA28ProgressTranscriptForwarder((bytes) => process.stderr.write(bytes))
    : undefined;
  const result = await runOwnedCommand({
    command: process.execPath,
    args: [join(root, 'scripts', 'package-spike.mjs'), BATCH_ARGUMENTS[batchId]],
    cwd: root,
    env: environment,
    inheritedFds: bootstrap.inheritedFds,
    timeoutMs: batchId === 'automation' ? 120 * 60_000 : 75 * 60_000,
    maxOutputBytes: 2 * 1_048_576,
    signal,
    ...(progress ? { stderrObserver: (bytes) => progress.push(bytes) } : {}),
    label: `Architecture ${batchId} proof batch`,
  });
  const forwardedStderr = progress
    ? progress.finish({ allowEmpty: true })
    : Buffer.alloc(0);
  if (result.status !== 0
    || result.signal !== null
    || !result.stderr.equals(forwardedStderr)) reject();
  return result.stdout;
}

export async function recordArchitectureGate(repositoryRoot, {
  executeBatch = executeDefaultBatch,
  now = () => new Date(),
  nonce = randomBytes(16).toString('hex'),
  signal,
} = {}) {
  if (typeof repositoryRoot !== 'string'
    || !repositoryRoot
    || !isAbsolute(repositoryRoot)
    || typeof executeBatch !== 'function'
    || typeof now !== 'function'
    || !RUN_NONCE.test(nonce)) reject();
  const canonicalRoot = await realpath(resolve(repositoryRoot));
  const initial = await snapshotArchitectureSource(canonicalRoot);
  let run;
  let activeBatch;
  try {
    run = await createRun(canonicalRoot, initial.source.digest, now(), nonce);
    const batches = {};
    for (const batchId of BATCH_ORDER) {
      activeBatch = batchId;
      const bytes = await executeBatch({
        architectureGateRunContextSha256: run.contextSha256,
        architectureGateRunId: run.id,
        batchId,
        productionArtifact: batches.production?.artifact,
        signal,
        sourceDigest: initial.source.digest,
      });
      const batch = parseArchitectureProofBatch(bytes, batchId);
      if (batch.sourceDigest !== initial.source.digest) reject();
      batches[batchId] = batch;
    }
    const final = await snapshotArchitectureSource(canonicalRoot);
    if (canonicalArchitectureJson(final.source) !== canonicalArchitectureJson(initial.source)) {
      reject('Architecture gate recording failed: source changed during proof execution');
    }
    const proofBytes = proofBytesFromBatches(batches);
    const results = assembleResults(initial.source, batches, proofBytes);
    await completeRun(run, results, proofBytes);
    return validateLatestArchitectureGate(canonicalRoot);
  } catch (error) {
    await recordFailure(run, activeBatch);
    throw error;
  }
}

function safeMessage(error) {
  const message = error instanceof Error ? error.message : 'Architecture gate recording failed';
  return message.replace(/[\r\n]+/gu, ' ').slice(0, 240);
}

const invokedPath = process.argv[1] ? await realpath(process.argv[1]) : undefined;
if (invokedPath === await realpath(fileURLToPath(import.meta.url))) {
  const cutoffs = installParentCutoffs();
  let bootstrapAccepted = false;
  try {
    const bootstrap = assertArchitectureBootstrap({ repositoryRoot: root });
    bootstrapAccepted = true;
    if (process.argv.length !== 2) reject('Architecture gate recording failed: unsupported arguments');
    if (platform() !== 'darwin' || arch() !== 'arm64') {
      reject('Architecture gate recording failed: Apple Silicon macOS is required');
    }
    const source = await snapshotArchitectureSource(root);
    configureAuthenticatedNodeSpawn(await createAuthenticatedNodeSpawnConfiguration({
      nodePath: bootstrap.receipt.nodePath,
      snapshot: source,
      sourceRoot: root,
    }));
    const result = await recordArchitectureGate(root, { signal: cutoffs.signal });
    process.stdout.write(`${canonicalArchitectureJson(result)}\n`);
  } catch (error) {
    process.stderr.write(`${safeMessage(error)}\n`);
    process.exitCode = 1;
  } finally {
    cutoffs.dispose();
    if (bootstrapAccepted) releaseArchitectureBootstrap();
  }
}
