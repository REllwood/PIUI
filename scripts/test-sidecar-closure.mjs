import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const sidecar = resolve(root, 'src-tauri/resources/sidecar');
const manifest = JSON.parse(await readFile(resolve(sidecar, 'manifest.json'), 'utf8'));
const paths = new Set(manifest.files.map((entry) => entry.path));
const required = [
  'dist/index.js',
  'node_modules/@piui/protocol/dist/codec.js',
  'node_modules/@piui/protocol/schema/envelope.schema.json',
  'node_modules/@earendil-works/pi-coding-agent/dist/index.js',
  'node_modules/@earendil-works/pi-coding-agent/dist/modes/interactive/theme/theme-schema.json',
  'node_modules/@earendil-works/pi-coding-agent/dist/modes/interactive/theme/light.json',
  'node_modules/@earendil-works/pi-coding-agent/dist/modes/interactive/theme/dark.json',
];
for (const path of required) {
  if (!paths.has(path)) throw new Error(`Closure manifest omitted required runtime asset: ${path}`);
}
if (manifest.closure !== 'isolated-v1' || manifest.node !== '22.23.1' || manifest.piSdk !== '0.82.0') {
  throw new Error('Closure version metadata mismatch');
}
const forbidden = /^(?:docs?|examples?)(?:\/|$)|^node_modules\/(?:@[^/]+\/[^/]+|[^/]+)\/(?:docs?|examples?)(?:\/|$)|(^|\/)(?:tests?|\.github|\.history|\.DS_Store)(\/|$)|(^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock)$|^node_modules\/(?:@tauri-apps|@testing-library|@types|@vitejs|react(?:$|-)|tailwindcss|typescript|vite$|vitest$)|\.(?:d\.)?(?:m|c)?ts$|\.map$/;
const rejected = manifest.files.map((entry) => entry.path).filter((path) => forbidden.test(path));
if (rejected.length) throw new Error(`Forbidden closure entries: ${rejected.slice(0, 10).join(', ')}`);

const rootEntries = (await readdir(sidecar)).filter((name) => name !== '.DS_Store').sort();
if (rootEntries.join(',') !== 'dist,manifest.json,node_modules,package.json') {
  throw new Error(`Unexpected closure roots: ${rootEntries.join(', ')}`);
}
const packageJson = JSON.parse(await readFile(resolve(sidecar, 'package.json'), 'utf8'));
const dependencyNames = Object.keys(packageJson.dependencies ?? {}).sort();
if (dependencyNames.join(',') !== '@earendil-works/pi-coding-agent,@piui/protocol,ajv') {
  throw new Error(`Unexpected importer dependencies: ${dependencyNames.join(', ')}`);
}

const runtime = spawnSync(
  resolve(root, 'src-tauri/binaries/piui-node-aarch64-apple-darwin'),
  [resolve(sidecar, 'dist/index.js')],
  { cwd: sidecar, input: '', encoding: 'utf8', env: { NODE_ENV: 'production' } },
);
if (runtime.status !== 0 || runtime.stderr !== '') {
  throw new Error(`Staged sidecar importer failed: status=${runtime.status}, stderr=${runtime.stderr.slice(0, 300)}`);
}
const lines = runtime.stdout.trim().split('\n');
if (lines.length !== 1) throw new Error('Staged sidecar stdout was not protocol-only');
const handshake = JSON.parse(lines[0]);
if (handshake.kind !== 'handshake' || handshake.payload.piVersion !== '0.82.0' || handshake.payload.nodeVersion !== '22.23.1') {
  throw new Error('Staged sidecar handshake metadata mismatch');
}
console.log(`Sidecar closure accepted: ${manifest.files.length} files; runtime handshake passed`);
