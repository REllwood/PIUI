import { readFileSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const envelopeSchema = JSON.parse(readFileSync(resolve(root, 'schema/envelope.schema.json'), 'utf8'));
const messagesSchema = JSON.parse(readFileSync(resolve(root, 'schema/messages.schema.json'), 'utf8'));
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
const envelopeValid = ajv.compile(envelopeSchema);
const messagesValid = ajv.compile(messagesSchema);
const maxLineBytes = 1_048_576;
const maxPayloadBytes = 524_288;
const maxDepth = 32;
const privateHostMaxDepth = maxDepth + 2;
// Mirrors validate.ts and Rust's is_secret_key: strip every `_` and `-`, then
// match a lowercase needle anywhere in the key.
const secretNeedles = ['secret', 'token', 'password', 'apikey', 'authorization', 'credential'];

function depth(value, limit) {
  let deepest = 0;
  const stack = [[value, 0]];
  while (stack.length) {
    const [current, level] = stack.pop();
    deepest = Math.max(deepest, level);
    if (deepest > limit) return limit + 1;
    if (!current || typeof current !== 'object') continue;
    for (const child of Object.values(current)) stack.push([child, level + 1]);
  }
  return deepest;
}

function isSecretKey(key) {
  const normalised = key.toLowerCase().replaceAll('_', '').replaceAll('-', '');
  return secretNeedles.some((needle) => normalised.includes(needle));
}

function hasSecretKey(value) {
  if (!value || typeof value !== 'object') return false;
  return Object.entries(value).some(([key, child]) => isSecretKey(key) || hasSecretKey(child));
}

function validateFile(path) {
  const seen = new Set();
  const raw = readFileSync(path);
  if (!raw.length || raw.at(-1) !== 0x0a || raw.includes(0x0d)) throw new Error('JSONL must use LF-delimited UTF-8');
  const text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  for (const sourceLine of text.slice(0, -1).split('\n')) {
    let line = sourceLine;
    const directive = JSON.parse(sourceLine);
    if (directive.fixture === 'oversized-line') line = JSON.stringify({ value: 'x'.repeat(directive.bytes) });
    if (Buffer.byteLength(line) > maxLineBytes) throw new Error('line limit exceeded');
    const envelope = JSON.parse(line);
    if (!envelopeValid(envelope) || !messagesValid(envelope)) throw new Error('schema rejected envelope');
    if (seen.has(envelope.id)) throw new Error('duplicate ID');
    seen.add(envelope.id);
    if (Buffer.byteLength(JSON.stringify(envelope.payload)) > maxPayloadBytes) throw new Error('payload limit exceeded');
    const depthLimit = envelope.kind === 'host-request' || envelope.kind === 'host-response' ? privateHostMaxDepth : maxDepth;
    if (depth(envelope, depthLimit) > depthLimit) throw new Error('depth limit exceeded');
    if (envelope.kind === 'event' && hasSecretKey(envelope.payload)) throw new Error('secret-shaped diagnostic field');
  }
}

const fixtures = readdirSync(resolve(root, 'fixtures')).filter((name) => name.endsWith('.jsonl')).sort();
let failures = 0;
for (const name of fixtures) {
  const expected = name.startsWith('valid-');
  let accepted = false;
  try { validateFile(resolve(root, 'fixtures', name)); accepted = true; } catch {}
  if (accepted !== expected) {
    failures += 1;
    console.error(`${name}: expected ${expected ? 'accept' : 'reject'}, got ${accepted ? 'accept' : 'reject'}`);
  } else {
    console.log(`${name}: ${accepted ? 'accepted' : 'rejected'} as expected`);
  }
}
if (failures) process.exit(1);
