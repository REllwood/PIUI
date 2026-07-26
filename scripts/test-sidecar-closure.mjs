import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const sidecar = resolve(root, 'src-tauri/resources/sidecar');
const manifest = JSON.parse(await readFile(resolve(sidecar, 'manifest.json'), 'utf8'));
const paths = new Set(manifest.files.map((entry) => entry.path));
const required = [
  'dist/index.js',
  'dist/pi/trust-gate.js',
  'dist/pi/trust-loader.js',
  'dist/pi/trust-loader-worker.js',
  'dist/pi/trust-loader-executor.js',
  'dist/pi/trust-loader-project-thread.js',
  'node_modules/@piui/protocol/dist/codec.js',
  'node_modules/@piui/protocol/schema/envelope.schema.json',
  'node_modules/@earendil-works/pi-coding-agent/dist/index.js',
  'node_modules/@earendil-works/pi-coding-agent/dist/utils/changelog.js',
  'node_modules/yaml/dist/doc/directives.js',
  'node_modules/yaml/dist/doc/Document.js',
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
const discardedDirectoryNames = new Set(['doc', 'docs', 'example', 'examples', 'test', 'tests']);
function independentlyRejectDocumentation(path) {
  const pieces = path.split('/').filter((piece) => piece.length > 0);
  const fileName = pieces.at(-1) ?? '';
  const directories = pieces.slice(0, -1);
  if (directories.length > 0 && discardedDirectoryNames.has(directories[0].toLowerCase())) return true;
  for (let index = 0; index < directories.length; index += 1) {
    if (directories[index].toLowerCase() !== 'node_modules') continue;
    const firstPackageSegment = index + 1;
    if (firstPackageSegment >= directories.length) continue;
    const childIndex = directories[firstPackageSegment].startsWith('@')
      ? firstPackageSegment + 2
      : firstPackageSegment + 1;
    if (
      childIndex < directories.length
      && discardedDirectoryNames.has(directories[childIndex].toLowerCase())
    ) return true;
  }
  if (/^(?:licen[cs]e|notice)(?:$|[._-])/i.test(fileName)) return false;
  const lowerFileName = fileName.toLowerCase();
  const maintenanceNames = ['readme', 'changelog', 'history', 'contributing', 'code_of_conduct', 'security'];
  const extensionlessMaintenance = !lowerFileName.includes('.')
    && maintenanceNames.some((prefix) => (
      lowerFileName === prefix
      || [`${prefix}-`, `${prefix}_`, `${prefix} `].some((start) => lowerFileName.startsWith(start))
    ));
  return extensionlessMaintenance
    || /\.(?:md|markdown|mdx|rst)$/i.test(fileName)
    || /^opslevel\.ya?ml$/i.test(fileName);
}
const forbidden = /(^|\/)(?:\.github|\.history|\.DS_Store)(\/|$)|(^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock)$|^node_modules\/(?:@tauri-apps|@testing-library|@types|@vitejs|react(?:$|-)|tailwindcss|typescript|vite$|vitest$)|\.(?:d\.)?(?:m|c)?ts$|\.map$/;
const rejected = manifest.files
  .map((entry) => entry.path)
  .filter((path) => independentlyRejectDocumentation(path) || forbidden.test(path));
if (rejected.length) throw new Error(`Forbidden closure entries: ${rejected.slice(0, 10).join(', ')}`);

async function assertNoFinderMetadata(path) {
  for (const entry of await readdir(path, { withFileTypes: true })) {
    if (entry.name === '.DS_Store') throw new Error(`Finder metadata entered closure: ${resolve(path, entry.name)}`);
    if (entry.isDirectory()) await assertNoFinderMetadata(resolve(path, entry.name));
  }
}
await assertNoFinderMetadata(sidecar);
const rootEntries = (await readdir(sidecar)).sort();
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
