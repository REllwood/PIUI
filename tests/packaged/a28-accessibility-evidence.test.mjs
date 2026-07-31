import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  canonicalArchitectureJson,
  sha256Bytes,
} from '../../scripts/architecture-gate-schema.mjs';
import {
  assertA28HumanWitnessLease,
  parseA28AccessibilityTreeEvidence,
  parseA28VoiceOverChecksums,
  parseA28VoiceOverCompletion,
  parseA28VoiceOverEvidence,
} from '../../scripts/a28-accessibility-evidence.mjs';

const root = resolve(import.meta.dirname, '../..');
const sha = (character) => character.repeat(64);
const line = (value) => Buffer.from(`${canonicalArchitectureJson(value)}\n`);

test('accepts only bounded, exact-PID accessibility-tree evidence', () => {
  const evidence = {
    applicationPidMatched: true,
    bounded: true,
    focusedRowOrdinal: 51,
    focusedTranscriptRows: 1,
    listItemRoles: 13,
    listRoles: 1,
    namedTranscriptRows: 13,
    nodesVisited: 91,
    orderedTranscriptRows: true,
    pid: 1234,
    schemaVersion: 1,
    trusted: true,
    unexpectedRowIdentifiers: 0,
  };
  assert.deepEqual(parseA28AccessibilityTreeEvidence(line(evidence), 1234), evidence);
  for (const changed of [
    { ...evidence, pid: 1235 },
    { ...evidence, bounded: false },
    { ...evidence, focusedTranscriptRows: 0 },
    { ...evidence, listItemRoles: 12 },
    { ...evidence, nodesVisited: 4_097 },
    { ...evidence, privatePath: '/private/example' },
  ]) {
    assert.throws(() => parseA28AccessibilityTreeEvidence(line(changed), 1234));
  }
});

test('requires a plausible two-token personal name and every live VoiceOver check', () => {
  const checks = ['dark', 'light'].flatMap((appearance) =>
    ['accessible', 'virtualised'].map((mode) => ({
      announcements: 'pass',
      appearance,
      blockingDefects: [],
      focusRetention: 'pass',
      keyboardOrder: 'pass',
      mode,
    })));
  const evidence = {
    checks,
    humanName: 'Rhys Ellwood',
    macosVersion: '15.6.1',
    observedAt: '2026-07-31T12:00:00.000Z',
    schemaVersion: 1,
    status: 'pass',
  };
  const bytes = line(evidence);
  assert.deepEqual(
    parseA28VoiceOverEvidence(bytes, Date.parse('2026-07-31T12:01:00.000Z')),
    evidence,
  );
  for (const humanName of [
    'Rhys Ellwood',
    'María García',
    "Aoife O'Neill",
  ]) {
    assert.equal(
      parseA28VoiceOverEvidence(
        line({ ...evidence, humanName }),
        Date.parse('2026-07-31T12:01:00.000Z'),
      ).humanName,
      humanName,
    );
  }
  const decomposedName = 'Mari\u0301a Garci\u0301a';
  assert.equal(
    parseA28VoiceOverEvidence(
      line({ ...evidence, humanName: decomposedName }),
      Date.parse('2026-07-31T12:01:00.000Z'),
    ).humanName,
    'María García',
  );
  for (const forbiddenToken of [
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
    'witness',
    'agent',
    'user',
  ]) {
    assert.throws(() => parseA28VoiceOverEvidence(
      line({ ...evidence, humanName: `${forbiddenToken} Ellwood` }),
      Date.parse('2026-07-31T12:01:00.000Z'),
    ));
  }
  for (const changed of [
    { ...evidence, humanName: 'AA' },
    { ...evidence, humanName: 'A B' },
    { ...evidence, humanName: 'Rhys 7Ellwood' },
    { ...evidence, humanName: 'Manual Reviewer' },
    { ...evidence, humanName: 'QA Witness' },
    { ...evidence, humanName: 'Automated Tester' },
    { ...evidence, humanName: 'Anonymous User' },
    { ...evidence, humanName: 'Unknown Agent' },
    { ...evidence, humanName: 'Codex Bot' },
    { ...evidence, humanName: 'Human Automation' },
    { ...evidence, humanName: 'Automated-Tester Example' },
    { ...evidence, humanName: 'Manual-Reviewer Example' },
    { ...evidence, humanName: "Codex'Bot Example" },
    { ...evidence, humanName: 'Anonymous-User Example' },
    { ...evidence, humanName: 'Human-Witness Example' },
    { ...evidence, humanName: 'Ａｕｔｏｍａｔｅｄ Ｔｅｓｔｅｒ' },
    { ...evidence, humanName: 'Ｍａｎｕａｌ-Ｒｅｖｉｅｗｅｒ Example' },
    { ...evidence, humanName: 'Ｃｏｄｅｘ’Ｂｏｔ Example' },
    { ...evidence, humanName: 'Ｃｏｄｅｘ＇Ｂｏｔ Example' },
    { ...evidence, humanName: 'Ａｎｏｎｙｍｏｕｓ-Ｕｓｅｒ Example' },
    { ...evidence, humanName: 'Ｈｕｍａｎ-Ｗｉｔｎｅｓｓ Example' },
    { ...evidence, humanName: 'WITNEẞ Example' },
    { ...evidence, humanName: 'Codex' },
    { ...evidence, humanName: 'Codex Agent' },
    { ...evidence, humanName: '  ' },
    { ...evidence, humanName: ' Rhys Ellwood ' },
    { ...evidence, checks: checks.slice(0, 3) },
    { ...evidence, checks: checks.map((check) => ({ ...check, mode: 'accessible' })) },
    { ...evidence, checks: checks.map((check, index) => index === 0
      ? { ...check, announcements: 'blocked' }
      : check) },
  ]) {
    assert.throws(() => parseA28VoiceOverEvidence(
      line(changed),
      Date.parse('2026-07-31T12:01:00.000Z'),
    ));
  }

  const identities = {
    automationTwinFingerprint: sha('a'),
    productionFingerprint: sha('b'),
    sourceDigest: sha('c'),
    voiceOverBytes: bytes,
  };
  const checksums = {
    automationTwinFingerprint: identities.automationTwinFingerprint,
    productionFingerprint: identities.productionFingerprint,
    schemaVersion: 1,
    sourceDigest: identities.sourceDigest,
    voiceOverSha256: sha256Bytes(bytes),
  };
  assert.deepEqual(parseA28VoiceOverChecksums(line(checksums), identities), checksums);
  assert.throws(() => parseA28VoiceOverChecksums(
    line({ ...checksums, voiceOverSha256: sha('d') }),
    identities,
  ));

});

test('binds each append-only human witness lease and completion to one exact PID', () => {
  const lease = {
    applicationPid: 1234,
    automationTwinFingerprint: sha('a'),
    evidenceDirectory: `.forge/evidence/architecture-accessibility/${sha('d')}`,
    macosVersion: '15.6.1',
    productionFingerprint: sha('b'),
    schemaVersion: 1,
    sourceDigest: sha('c'),
    startedAt: '2026-07-31T12:00:00.000Z',
    state: 'waiting-for-human',
    witnessNonce: sha('d'),
  };
  assert.deepEqual(
    assertA28HumanWitnessLease(
      lease,
      Date.parse('2026-07-31T12:01:00.000Z'),
    ),
    lease,
  );
  for (const changed of [
    { ...lease, applicationPid: 1 },
    { ...lease, witnessNonce: sha('e') },
    { ...lease, evidenceDirectory: '/private/witness' },
    { ...lease, activationNonce: sha('f') },
  ]) {
    assert.throws(() => assertA28HumanWitnessLease(
      changed,
      Date.parse('2026-07-31T12:01:00.000Z'),
    ));
  }

  const completion = {
    applicationPid: lease.applicationPid,
    schemaVersion: 1,
    state: 'complete',
    witnessNonce: lease.witnessNonce,
  };
  assert.deepEqual(parseA28VoiceOverCompletion(line(completion), lease), completion);
  for (const changed of [
    { ...completion, applicationPid: 1235 },
    { ...completion, witnessNonce: sha('e') },
    { ...completion, automated: true },
  ]) {
    assert.throws(() => parseA28VoiceOverCompletion(line(changed), lease));
  }
});

test('the native helper compiles against the macOS accessibility frameworks', async (t) => {
  if (process.platform !== 'darwin') return t.skip('macOS-only helper');
  const source = resolve(root, 'scripts/inspect-a28-accessibility.c');
  const output = resolve(tmpdir(), `piui-a28-ax-helper-${process.pid}`);
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(output, { force: true });
  });
  const result = spawnSync('/usr/bin/clang', [
    '-std=c17',
    '-Wall',
    '-Wextra',
    '-Werror',
    '-framework',
    'ApplicationServices',
    '-framework',
    'CoreFoundation',
    source,
    '-o',
    output,
  ], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
  assert.equal(result.status, 0, result.stderr);
  const bytes = await readFile(output);
  assert.ok(bytes.length > 8_192);
});
