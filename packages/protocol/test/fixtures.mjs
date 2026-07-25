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
const secretKey = /(secret|token|password|api[_-]?key|authorization|credential)/i;

function depth(value, level = 0) {
  if (level > maxDepth) return level;
  if (!value || typeof value !== 'object') return level;
  return Math.max(level, ...Object.values(value).map((child) => depth(child, level + 1)));
}

function hasSecretKey(value) {
  if (!value || typeof value !== 'object') return false;
  return Object.entries(value).some(([key, child]) => secretKey.test(key) || hasSecretKey(child));
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
    if (depth(envelope) > maxDepth) throw new Error('depth limit exceeded');
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
