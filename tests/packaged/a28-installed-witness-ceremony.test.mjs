import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  A28_OFFICIAL_NODE_SIGNING_IDENTITY,
  assertA28ProgressTranscript,
  createA28ProgressTranscriptForwarder,
} from '../../scripts/a28-installed-witness-ceremony.mjs';

const root = resolve(import.meta.dirname, '../..');

test('pins the exact authenticated official Node identity required by A.28', () => {
  assert.deepEqual(A28_OFFICIAL_NODE_SIGNING_IDENTITY, {
    bundleIdentifier: 'node',
    cdHash: '59cdea89a982b05f23e756c08115bebc555ff092',
    designatedRequirement:
      'identifier node and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "HX7739G8FX"',
    executableSha256: '2e3f1286a7eb3736346ed1803e458a0ff909e2b2d5bc746144dcb76970e9b99d',
    teamIdentifier: 'HX7739G8FX',
  });
});

test('keeps privileged launch external and every operator wait visible', async () => {
  const source = await readFile(
    resolve(root, 'scripts/a28-installed-witness-ceremony.mjs'),
    'utf8',
  );
  assert.match(source, /A28_POLICY_PIN_PATH/);
  assert.match(source, /readHeldCanonicalA28File/);
  assert.match(source, /assertA28ChallengeRequest/);
  assert.match(source, /inspectPinnedA28WitnessApp/);
  assert.match(source, /\[working\] A\.28/);
  assert.match(source, /already privileged managed prepare command/);
  assert.match(source, /run root checkpoint reveal \$\{ordinal\} of 4/);
  assert.match(source, /already privileged managed verification command/);
  assert.doesNotMatch(source, /\bsudo\b/u);
  assert.doesNotMatch(source, /spawn(?:Sync)?\(policy\.rootLauncherPath/u);
});

test('accepts only bounded A.28 working-state output on the progress channel', () => {
  assert.equal(assertA28ProgressTranscript(Buffer.from(
    '[working] A.28 waiting for the root-owned receipt.\n',
    'utf8',
  )), true);
  for (const bytes of [
    Buffer.alloc(0),
    Buffer.from('waiting\n', 'utf8'),
    Buffer.from('[working] A.28 waiting\r\n', 'utf8'),
    Buffer.from('[working] A.28 token\0secret\n', 'utf8'),
    Buffer.alloc(256 * 1024 + 1, 0x61),
  ]) assert.throws(() => assertA28ProgressTranscript(bytes));
  assert.equal(assertA28ProgressTranscript(Buffer.alloc(0), { allowEmpty: true }), true);
});

test('forwards only complete validated A.28 progress lines across fragmented chunks', () => {
  const forwarded = [];
  const transcript = createA28ProgressTranscriptForwarder((line) => {
    forwarded.push(line);
  });
  transcript.push(Buffer.from('[work', 'utf8'));
  transcript.push(Buffer.from('ing] A.28 waiting for ', 'utf8'));
  assert.equal(forwarded.length, 0);
  transcript.push(Buffer.from('the root-owned receipt.\n', 'utf8'));
  const expected = Buffer.from(
    '[working] A.28 waiting for the root-owned receipt.\n',
    'utf8',
  );
  assert.equal(forwarded.length, 1);
  assert.ok(forwarded[0].equals(expected));
  assert.ok(transcript.finish().equals(expected));
});

test('frames and forwards each validated line from a multiline A.28 chunk', () => {
  const forwarded = [];
  const transcript = createA28ProgressTranscriptForwarder((line) => {
    forwarded.push(line);
  });
  const bytes = Buffer.from(
    '[working] A.28 first bounded wait.\n[working] A.28 second bounded wait.\n',
    'utf8',
  );
  transcript.push(bytes);
  assert.equal(forwarded.length, 2);
  assert.equal(forwarded[0].toString('utf8'), '[working] A.28 first bounded wait.\n');
  assert.equal(forwarded[1].toString('utf8'), '[working] A.28 second bounded wait.\n');
  assert.ok(transcript.finish().equals(bytes));
});

test('rejects invalid and unterminated A.28 progress without forwarding it', () => {
  const invalidForwarded = [];
  const invalid = createA28ProgressTranscriptForwarder((line) => {
    invalidForwarded.push(line);
  });
  assert.throws(() => invalid.push(Buffer.from('not A.28 progress\n', 'utf8')));
  assert.equal(invalidForwarded.length, 0);

  const malformedUtf8Forwarded = [];
  const malformedUtf8 = createA28ProgressTranscriptForwarder((line) => {
    malformedUtf8Forwarded.push(line);
  });
  assert.throws(() => malformedUtf8.push(Buffer.concat([
    Buffer.from('[working] A.28 invalid UTF-8 ', 'utf8'),
    Buffer.from([0xff, 0x0a]),
  ])));
  assert.equal(malformedUtf8Forwarded.length, 0);

  const partialForwarded = [];
  const partial = createA28ProgressTranscriptForwarder((line) => {
    partialForwarded.push(line);
  });
  partial.push(Buffer.from('[working] A.28 incomplete', 'utf8'));
  assert.throws(() => partial.finish({ allowEmpty: true }));
  assert.equal(partialForwarded.length, 0);
});

test('caps both an incomplete progress line and the complete transcript line count', () => {
  const oversized = createA28ProgressTranscriptForwarder(() => undefined);
  assert.throws(() => oversized.push(Buffer.from(
    `[working] A.28 ${'a'.repeat(5_000)}`,
    'utf8',
  )));

  const forwarded = [];
  const tooMany = createA28ProgressTranscriptForwarder((line) => {
    forwarded.push(line);
  });
  const line = Buffer.from('[working] A.28 bounded operator wait.\n', 'utf8');
  tooMany.push(Buffer.concat(Array.from({ length: 128 }, () => line)));
  assert.equal(forwarded.length, 128);
  assert.throws(() => tooMany.push(line));
});

test('waits for root-owned artefacts while continuously checking live identities', async () => {
  const source = await readFile(
    resolve(root, 'scripts/a28-installed-witness-ceremony.mjs'),
    'utf8',
  );
  assert.match(source, /verifyContinuity/);
  assert.match(source, /rootLauncherSha256/);
  assert.match(source, /checkpointCommitmentDirectoryPath/);
  assert.match(source, /checkpointDeliveryDirectoryPath/);
  assert.match(source, /resultDirectoryPath/);
  assert.match(source, /enterPhase\('initial', 'preparing'\)/);
  assert.match(source, /enterPhase\('revealed-4', 'authorising'\)/);
  assert.match(source, /enterPhase\('authorised', 'consuming'\)/);
  assert.match(source, /mode: 0o444/);
  assert.match(source, /uid: 0/);
});
