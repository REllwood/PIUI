import {
  canonicalArchitectureJson,
  sha256Bytes,
} from './architecture-gate-schema.mjs';

const SHA256 = /^[0-9a-f]{64}$/u;
const MACOS_VERSION = /^\d{1,3}\.\d{1,3}(?:\.\d{1,3})?$/u;
const MAX_EVIDENCE_BYTES = 65_536;
const CHECK_APPEARANCES = Object.freeze(['dark', 'light']);
const CHECK_MODES = Object.freeze(['accessible', 'virtualised']);
const FORBIDDEN_HUMAN_NAME_WORDS = new Set([
  'agent',
  'anonymous',
  'automated',
  'automation',
  'bot',
  'codex',
  'human',
  'manual',
  'qa',
  'reviewer',
  'test',
  'tester',
  'unknown',
  'user',
  'witness',
]);
const HUMAN_NAME_JOINERS = /['’ʼ\-‐‑]/u;
const HUMAN_NAME_TOKEN = /^(?=(?:[^\p{L}]*\p{L}){2})(?:\p{L}\p{M}*)+(?:['’ʼ\-‐‑](?:\p{L}\p{M}*)+)*$/u;
const WITNESS_DIRECTORY =
  /^\.forge\/evidence\/architecture-accessibility\/([0-9a-f]{64})$/u;

function reject(message = 'A.28 accessibility evidence rejected') {
  throw new Error(message);
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject();
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])) reject();
}

function caseFoldHumanName(value) {
  return value
    .normalize('NFKC')
    .toLocaleLowerCase('und')
    .replaceAll('ß', 'ss')
    .replaceAll('ς', 'σ');
}

function parseCanonicalOneLine(bytes) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 3
    || bytes.length > MAX_EVIDENCE_BYTES
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

export function parseA28AccessibilityTreeEvidence(bytes, expectedPid) {
  if (!Number.isSafeInteger(expectedPid) || expectedPid < 2) reject();
  const value = parseCanonicalOneLine(bytes);
  exactKeys(value, [
    'applicationPidMatched',
    'bounded',
    'focusedRowOrdinal',
    'focusedTranscriptRows',
    'listItemRoles',
    'listRoles',
    'namedTranscriptRows',
    'nodesVisited',
    'orderedTranscriptRows',
    'pid',
    'schemaVersion',
    'trusted',
    'unexpectedRowIdentifiers',
  ]);
  if (value.schemaVersion !== 1
    || value.trusted !== true
    || value.pid !== expectedPid
    || value.applicationPidMatched !== true
    || value.bounded !== true
    || !Number.isSafeInteger(value.nodesVisited)
    || value.nodesVisited < 1
    || value.nodesVisited > 4_096
    || !Number.isSafeInteger(value.listRoles)
    || value.listRoles < 1
    || !Number.isSafeInteger(value.namedTranscriptRows)
    || value.namedTranscriptRows < 1
    || value.namedTranscriptRows > 100
    || value.listItemRoles !== value.namedTranscriptRows
    || value.orderedTranscriptRows !== true
    || value.unexpectedRowIdentifiers !== 0
    || value.focusedTranscriptRows !== 1
    || !Number.isSafeInteger(value.focusedRowOrdinal)
    || value.focusedRowOrdinal < 1
    || value.focusedRowOrdinal > 100) reject();
  return Object.freeze({ ...value });
}

export function parseA28VoiceOverEvidence(bytes, now = Date.now()) {
  if (!Number.isFinite(now)) reject();
  const value = parseCanonicalOneLine(bytes);
  // This is deliberately only a plausible-name syntax check. Code cannot
  // authenticate the witness's identity, and a live VoiceOver observation is
  // still required by the surrounding evidence protocol.
  const displayHumanName = typeof value.humanName === 'string'
    ? value.humanName.normalize('NFC')
    : '';
  const validationHumanName = caseFoldHumanName(displayHumanName);
  const humanNameTokens = validationHumanName
    ? validationHumanName.split(/\s+/u)
    : [];
  const humanNameComponents = humanNameTokens.flatMap((token) =>
    token.split(HUMAN_NAME_JOINERS));
  exactKeys(value, [
    'checks',
    'humanName',
    'macosVersion',
    'observedAt',
    'schemaVersion',
    'status',
  ]);
  if (value.schemaVersion !== 1
    || value.status !== 'pass'
    || typeof value.humanName !== 'string'
    || displayHumanName.length < 2
    || displayHumanName.length > 80
    || value.humanName !== value.humanName.trim()
    || humanNameTokens.length !== 2
    || humanNameTokens.some((token) => !HUMAN_NAME_TOKEN.test(token))
    || /[\0-\x1f\x7f/\\]/u.test(displayHumanName)
    || humanNameComponents.some((component) =>
      FORBIDDEN_HUMAN_NAME_WORDS.has(component))
    || typeof value.macosVersion !== 'string'
    || !MACOS_VERSION.test(value.macosVersion)
    || typeof value.observedAt !== 'string'
    || !Array.isArray(value.checks)
    || value.checks.length !== 4) reject();
  const observedAt = new Date(value.observedAt);
  if (Number.isNaN(observedAt.valueOf()) || observedAt.valueOf() > now + 5 * 60_000) reject();

  const combinations = new Set();
  for (const check of value.checks) {
    exactKeys(check, [
      'announcements',
      'appearance',
      'blockingDefects',
      'focusRetention',
      'keyboardOrder',
      'mode',
    ]);
    if (!CHECK_APPEARANCES.includes(check.appearance)
      || !CHECK_MODES.includes(check.mode)
      || check.announcements !== 'pass'
      || check.focusRetention !== 'pass'
      || check.keyboardOrder !== 'pass'
      || !Array.isArray(check.blockingDefects)
      || check.blockingDefects.length !== 0) reject();
    combinations.add(`${check.appearance}:${check.mode}`);
  }
  if (combinations.size !== 4) reject();
  return Object.freeze({
    ...value,
    humanName: displayHumanName,
    checks: Object.freeze(value.checks.map((check) => Object.freeze({
      ...check,
      blockingDefects: Object.freeze([]),
    }))),
  });
}

export function parseA28VoiceOverChecksums(bytes, {
  automationTwinFingerprint,
  productionFingerprint,
  sourceDigest,
  voiceOverBytes,
}) {
  for (const digest of [
    automationTwinFingerprint,
    productionFingerprint,
    sourceDigest,
  ]) {
    if (typeof digest !== 'string' || !SHA256.test(digest)) reject();
  }
  if (!Buffer.isBuffer(voiceOverBytes)) reject();
  const value = parseCanonicalOneLine(bytes);
  exactKeys(value, [
    'automationTwinFingerprint',
    'productionFingerprint',
    'schemaVersion',
    'sourceDigest',
    'voiceOverSha256',
  ]);
  if (value.schemaVersion !== 1
    || value.automationTwinFingerprint !== automationTwinFingerprint
    || value.productionFingerprint !== productionFingerprint
    || value.sourceDigest !== sourceDigest
    || value.voiceOverSha256 !== sha256Bytes(voiceOverBytes)) reject();
  return Object.freeze({ ...value });
}

export function assertA28HumanWitnessLease(value, now = Date.now()) {
  if (!Number.isFinite(now)) reject();
  exactKeys(value, [
    'applicationPid',
    'automationTwinFingerprint',
    'evidenceDirectory',
    'macosVersion',
    'productionFingerprint',
    'schemaVersion',
    'sourceDigest',
    'startedAt',
    'state',
    'witnessNonce',
  ]);
  const directoryMatch = typeof value.evidenceDirectory === 'string'
    ? WITNESS_DIRECTORY.exec(value.evidenceDirectory)
    : null;
  const startedAt = typeof value.startedAt === 'string'
    ? new Date(value.startedAt)
    : new Date(Number.NaN);
  if (value.schemaVersion !== 1
    || value.state !== 'waiting-for-human'
    || !Number.isSafeInteger(value.applicationPid)
    || value.applicationPid < 2
    || typeof value.automationTwinFingerprint !== 'string'
    || !SHA256.test(value.automationTwinFingerprint)
    || typeof value.productionFingerprint !== 'string'
    || !SHA256.test(value.productionFingerprint)
    || typeof value.sourceDigest !== 'string'
    || !SHA256.test(value.sourceDigest)
    || typeof value.witnessNonce !== 'string'
    || !SHA256.test(value.witnessNonce)
    || directoryMatch?.[1] !== value.witnessNonce
    || typeof value.macosVersion !== 'string'
    || !MACOS_VERSION.test(value.macosVersion)
    || Number.isNaN(startedAt.valueOf())
    || startedAt.valueOf() > now + 5 * 60_000) reject();
  return Object.freeze({ ...value });
}

export function parseA28VoiceOverCompletion(bytes, {
  applicationPid,
  witnessNonce,
}) {
  if (!Number.isSafeInteger(applicationPid)
    || applicationPid < 2
    || typeof witnessNonce !== 'string'
    || !SHA256.test(witnessNonce)) reject();
  const value = parseCanonicalOneLine(bytes);
  exactKeys(value, [
    'applicationPid',
    'schemaVersion',
    'state',
    'witnessNonce',
  ]);
  if (value.schemaVersion !== 1
    || value.state !== 'complete'
    || value.applicationPid !== applicationPid
    || value.witnessNonce !== witnessNonce) reject();
  return Object.freeze({ ...value });
}
