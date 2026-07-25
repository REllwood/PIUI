import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const manifestPath = resolve(root, 'src-tauri/resources/sidecar/manifest.json');
function stage() {
  const result = spawnSync('pnpm', ['stage:sidecar'], { cwd: root, stdio: 'inherit' });
  if (result.status !== 0) throw new Error('Sidecar staging regression run failed');
}
async function digest() {
  return createHash('sha256').update(await readFile(manifestPath)).digest('hex');
}
stage();
const first = await digest();
stage();
const second = await digest();
if (first !== second) throw new Error(`Repeated sidecar manifests diverged: ${first} != ${second}`);
const closure = spawnSync(process.execPath, [resolve(root, 'scripts/test-sidecar-closure.mjs')], { cwd: root, stdio: 'inherit' });
if (closure.status !== 0) throw new Error('Sidecar closure regression test failed');
console.log(`Repeated sidecar manifest stable: ${second}`);
