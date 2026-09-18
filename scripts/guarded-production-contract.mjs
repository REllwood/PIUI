import {
  assertArchitectureArtifact,
  canonicalArchitectureJson,
} from './architecture-gate-schema.mjs';

const MAX_RESULT_BYTES = 64 * 1024;
const RUN_ID = /^\d{8}T\d{9}Z-[0-9a-f]{32}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

function reject(message = 'Guarded production build result rejected') {
  throw new Error(message);
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject();
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])) reject();
}

export function assertGuardedProductionResult(value, {
  expectedFingerprint,
  expectedRunId,
  expectedSourceDigest,
  requireCleanup = true,
} = {}) {
  exactKeys(value, [
    'artifact',
    'bundleDirectory',
    'gateRunId',
    'generatedOutputsRemoved',
    'schemaVersion',
    'sourceDigest',
    'status',
  ]);
  const artifact = assertArchitectureArtifact(value.artifact, 'production');
  if (value.schemaVersion !== 1
    || value.bundleDirectory !== 'PIUI.app'
    || typeof value.gateRunId !== 'string'
    || !RUN_ID.test(value.gateRunId)
    || typeof value.sourceDigest !== 'string'
    || !SHA256.test(value.sourceDigest)
    || value.status !== 'pass'
    || typeof value.generatedOutputsRemoved !== 'boolean'
    || (requireCleanup && value.generatedOutputsRemoved !== true)
    || (expectedFingerprint !== undefined
      && artifact.fingerprint !== expectedFingerprint)
    || (expectedRunId !== undefined && value.gateRunId !== expectedRunId)
    || (expectedSourceDigest !== undefined
      && value.sourceDigest !== expectedSourceDigest)) reject();
  return Object.freeze({
    ...value,
    artifact: Object.freeze({ ...artifact }),
  });
}

export function createGuardedProductionResult({
  artifact,
  gateRunId,
  generatedOutputsRemoved,
  sourceDigest,
}) {
  return assertGuardedProductionResult({
    artifact,
    bundleDirectory: 'PIUI.app',
    gateRunId,
    generatedOutputsRemoved,
    schemaVersion: 1,
    sourceDigest,
    status: 'pass',
  }, { requireCleanup: generatedOutputsRemoved });
}

export function parseGuardedProductionResult(bytes, expected = {}) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 3
    || bytes.length > MAX_RESULT_BYTES
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
    || bytes.includes(0x00)) reject();
  let parsed;
  try {
    parsed = JSON.parse(bytes.subarray(0, -1).toString('utf8'));
  } catch {
    reject();
  }
  if (`${canonicalArchitectureJson(parsed)}\n` !== bytes.toString('utf8')) reject();
  return assertGuardedProductionResult(parsed, expected);
}
