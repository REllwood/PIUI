import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { relative, resolve, sep } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const stagedRoot = resolve(root, 'src-tauri/resources/sidecar');
const manifest = JSON.parse(await readFile(resolve(stagedRoot, 'manifest.json'), 'utf8'));

if (!Array.isArray(manifest.files)) {
  throw new Error('Staged sidecar manifest has no file inventory');
}

const entries = new Map();
for (const entry of manifest.files) {
  if (typeof entry?.path !== 'string'
    || typeof entry.bytes !== 'number'
    || typeof entry.sha256 !== 'string'
    || entries.has(entry.path)) {
    throw new Error('Staged sidecar manifest contains an invalid or duplicate entry');
  }
  entries.set(entry.path, entry);
}

async function listJavaScriptFiles(directory, base = directory) {
  const paths = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) {
      paths.push(...await listJavaScriptFiles(path, base));
    } else if (entry.isFile() && entry.name.endsWith('.js')) {
      paths.push(relative(base, path).split(sep).join('/'));
    } else if (entry.isSymbolicLink()) {
      throw new Error(`Current sidecar build contains a symbolic link: ${path}`);
    }
  }
  return paths.sort();
}

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

async function assertCurrentGroup({ sourceRoot, outputPrefix, omitted = new Set() }) {
  const current = (await listJavaScriptFiles(sourceRoot))
    .filter((path) => !omitted.has(path))
    .map((path) => `${outputPrefix}/${path}`);
  const staged = [...entries.keys()]
    .filter((path) => path.startsWith(`${outputPrefix}/`) && path.endsWith('.js'))
    .sort();
  if (current.length !== staged.length
    || current.some((path, index) => path !== staged[index])) {
    throw new Error(`Staged ${outputPrefix} JavaScript inventory is not current`);
  }
  for (const path of current) {
    const sourcePath = resolve(sourceRoot, path.slice(outputPrefix.length + 1));
    const bytes = await readFile(sourcePath);
    const entry = entries.get(path);
    if (entry.bytes !== bytes.length || entry.sha256 !== digest(bytes)) {
      throw new Error(`Staged sidecar file is stale: ${path}`);
    }
  }
}

await assertCurrentGroup({
  sourceRoot: resolve(root, 'sidecar/dist'),
  outputPrefix: 'dist',
  omitted: new Set([
    'spike/approval-entry.js',
    'spike/approval-matrix.js',
    'spike/approval-probes.js',
  ]),
});
await assertCurrentGroup({
  sourceRoot: resolve(root, 'packages/protocol/dist'),
  outputPrefix: 'node_modules/@piui/protocol/dist',
});

const schemaPath = 'node_modules/@piui/protocol/schema/envelope.schema.json';
const schemaBytes = await readFile(resolve(root, 'packages/protocol/schema/envelope.schema.json'));
const schemaEntry = entries.get(schemaPath);
if (!schemaEntry
  || schemaEntry.bytes !== schemaBytes.length
  || schemaEntry.sha256 !== digest(schemaBytes)) {
  throw new Error(`Staged sidecar file is stale: ${schemaPath}`);
}

console.log(`Staged sidecar matches the current production build: ${entries.size} files`);
