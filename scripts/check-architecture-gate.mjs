import { constants as fsConstants } from 'node:fs';
import {
  lstat,
  open,
  readdir,
  realpath,
} from 'node:fs/promises';
import { arch, platform } from 'node:os';
import {
  dirname,
  isAbsolute,
  join,
  resolve,
  sep,
} from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ARCHITECTURE_GATE_SCHEMA_VERSION,
  ARCHITECTURE_GATE_TARGET,
  ARCHITECTURE_PROOF_CONTRACTS,
  ARCHITECTURE_PROOF_IDS,
  canonicalArchitectureJson,
  parseArchitectureGateResults,
  parseArchitecturePassMarker,
  sha256Bytes,
} from './architecture-gate-schema.mjs';
import {
  assertArchitectureProofEnvelope,
} from './architecture-proof-batch.mjs';
import { snapshotArchitectureSource } from './architecture-source-snapshot.mjs';

const RUN_ID = /^(\d{8}T\d{9}Z)-[0-9a-f]{32}$/u;
const MAX_CONTROL_BYTES = 1_048_576;
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function reject(message = 'Architecture gate blocked') {
  throw new Error(message);
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject();
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])) reject();
}

function canonicalSourceEqual(left, right) {
  return canonicalArchitectureJson(left) === canonicalArchitectureJson(right);
}

function expectedRunTimestamp(date) {
  return date.toISOString().replace(/[-:.]/gu, '');
}

function assertStarted(value, runId, sourceDigest) {
  exactKeys(value, [
    'runId',
    'schemaVersion',
    'sourceDigest',
    'startedAt',
    'status',
    'target',
  ]);
  const match = RUN_ID.exec(runId);
  const startedAt = typeof value.startedAt === 'string' ? new Date(value.startedAt) : undefined;
  if (!match
    || !startedAt
    || Number.isNaN(startedAt.valueOf())
    || expectedRunTimestamp(startedAt) !== match[1]
    || value.schemaVersion !== ARCHITECTURE_GATE_SCHEMA_VERSION
    || value.runId !== runId
    || value.sourceDigest !== sourceDigest
    || value.status !== 'started'
    || value.target !== ARCHITECTURE_GATE_TARGET) reject();
}

async function assertControlledDirectory(path) {
  const state = await lstat(path);
  if (!state.isDirectory()
    || state.isSymbolicLink()
    || (state.mode & 0o022) !== 0
    || (typeof process.getuid === 'function' && state.uid !== process.getuid())) reject();
  return state;
}

async function readControlledFile(path, maximumBytes = MAX_CONTROL_BYTES) {
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  const handle = await open(path, flags);
  try {
    const before = await handle.stat();
    if (!before.isFile()
      || before.nlink !== 1
      || (before.mode & 0o022) !== 0
      || (typeof process.getuid === 'function' && before.uid !== process.getuid())
      || before.size < 2
      || before.size > maximumBytes) reject();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (bytes.length !== before.size
      || before.dev !== after.dev
      || before.ino !== after.ino
      || before.mode !== after.mode
      || before.nlink !== after.nlink
      || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs) reject();
    return bytes;
  } finally {
    await handle.close();
  }
}

function parseCanonicalRecord(bytes) {
  if (!Buffer.isBuffer(bytes)
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
    || bytes.includes(0x00)) reject();
  let value;
  try {
    value = JSON.parse(bytes.subarray(0, -1).toString('utf8'));
  } catch {
    reject();
  }
  if (`${canonicalArchitectureJson(value)}\n` !== bytes.toString('utf8')) reject();
  return value;
}

async function listExactDirectory(path, expected) {
  const entries = await readdir(path, { withFileTypes: true });
  const actual = entries.map((entry) => entry.name).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length
    || actual.some((name, index) => name !== wanted[index])) reject();
  return entries;
}

async function resolveLatestRun(repositoryRoot) {
  const forge = join(repositoryRoot, '.forge');
  const evidence = join(forge, 'evidence');
  const gate = join(evidence, 'architecture-gate');
  const runs = join(gate, 'runs');
  for (const path of [forge, evidence, gate, runs]) {
    try {
      await assertControlledDirectory(path);
    } catch (error) {
      // A missing evidence tree fails closed without naming any filesystem path.
      if (error?.code === 'ENOENT') {
        reject('Architecture gate blocked: no recorded architecture-gate run exists');
      }
      throw error;
    }
  }
  const entries = await readdir(runs, { withFileTypes: true });
  if (!entries.length
    || entries.some((entry) => !entry.isDirectory() || !RUN_ID.test(entry.name))) {
    reject('Architecture gate blocked: run inventory is absent or invalid');
  }
  entries.sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
  const latest = entries.at(-1);
  if (!latest) reject();
  const latestTimestamp = RUN_ID.exec(latest.name)?.[1];
  if (!latestTimestamp
    || entries.filter((entry) => RUN_ID.exec(entry.name)?.[1] === latestTimestamp).length !== 1) {
    reject('Architecture gate blocked: latest run ordering is ambiguous');
  }
  const path = join(runs, latest.name);
  await assertControlledDirectory(path);
  return Object.freeze({ id: latest.name, path });
}

async function validateProofFiles(runPath, results) {
  const proofsPath = join(runPath, 'proofs');
  await assertControlledDirectory(proofsPath);
  await listExactDirectory(proofsPath, ARCHITECTURE_PROOF_IDS.map((id) => `${id}.json`));
  for (const id of ARCHITECTURE_PROOF_IDS) {
    const bytes = await readControlledFile(join(proofsPath, `${id}.json`));
    const proof = parseCanonicalRecord(bytes);
    const contract = ARCHITECTURE_PROOF_CONTRACTS[id];
    const artifact = results.artifacts[contract.artifactResultKey];
    if (!artifact) reject();
    try {
      assertArchitectureProofEnvelope(proof, id, {
        artifact,
        sourceDigest: results.source.digest,
      });
    } catch {
      reject();
    }
    if (sha256Bytes(bytes) !== results.proofs[id].evidenceSha256) reject();
  }
}

export async function validateLatestArchitectureGate(repositoryRoot) {
  if (typeof repositoryRoot !== 'string'
    || !repositoryRoot
    || !isAbsolute(repositoryRoot)) reject();
  const resolvedRoot = resolve(repositoryRoot);
  const requestedRoot = await lstat(resolvedRoot);
  if (!requestedRoot.isDirectory() || requestedRoot.isSymbolicLink()) reject();
  const canonicalRoot = await realpath(resolvedRoot);

  const run = await resolveLatestRun(canonicalRoot);
  await listExactDirectory(run.path, [
    'pass-marker.json',
    'proofs',
    'results.json',
    'started.json',
  ]);
  const resultsBytes = await readControlledFile(join(run.path, 'results.json'));
  const results = parseArchitectureGateResults(resultsBytes);
  const source = await snapshotArchitectureSource(canonicalRoot);
  if (!canonicalSourceEqual(results.source, source.source)) {
    reject('Architecture gate blocked: the latest proof source is stale');
  }

  const startedBytes = await readControlledFile(join(run.path, 'started.json'), 4_096);
  assertStarted(parseCanonicalRecord(startedBytes), run.id, source.source.digest);
  await validateProofFiles(run.path, results);

  const markerBytes = await readControlledFile(join(run.path, 'pass-marker.json'), 4_096);
  const marker = parseArchitecturePassMarker(markerBytes, results);
  return Object.freeze({
    decision: marker.decision,
    distributionAuthorised: marker.distributionAuthorised,
    productionFingerprint: marker.productionFingerprint,
    runId: run.id,
    sourceDigest: marker.sourceDigest,
    target: results.target,
  });
}

function safeMessage(error) {
  const message = error instanceof Error ? error.message : 'Architecture gate blocked';
  return message.replace(/[\r\n]+/gu, ' ').slice(0, 240);
}

const invokedPath = process.argv[1] ? await realpath(process.argv[1]) : undefined;
if (invokedPath === await realpath(fileURLToPath(import.meta.url))) {
  try {
    if (process.argv.length !== 2) reject('Architecture gate blocked: unsupported arguments');
    if (platform() !== 'darwin' || arch() !== 'arm64') {
      reject('Architecture gate blocked: Apple Silicon macOS is required');
    }
    const result = await validateLatestArchitectureGate(root);
    process.stdout.write(`${canonicalArchitectureJson(result)}\n`);
  } catch (error) {
    process.stderr.write(`${safeMessage(error)}\n`);
    process.exitCode = 1;
  }
}
