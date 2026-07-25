import { createHash } from 'node:crypto';
import { chmod, cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { arch, platform } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const version = '22.23.1';
const target = 'aarch64-apple-darwin';
if (platform() !== 'darwin' || arch() !== 'arm64') throw new Error('The architecture gate requires arm64 macOS');
const checksums = JSON.parse(await readFile(resolve(root, 'scripts/node-checksums.json'), 'utf8'));
const pin = checksums[version]['darwin-arm64'];
const cache = resolve(root, '.cache/node-runtime');
const archive = resolve(cache, pin.archive);
const output = resolve(root, `src-tauri/binaries/piui-node-${target}`);
await mkdir(cache, { recursive: true });
let bytes;
try { bytes = await readFile(archive); } catch {
  const response = await fetch(`https://nodejs.org/dist/v${version}/${pin.archive}`, { redirect: 'error' });
  if (!response.ok) throw new Error(`Official Node download failed with ${response.status}`);
  bytes = Buffer.from(await response.arrayBuffer());
  await writeFile(archive, bytes, { mode: 0o600 });
}
const actual = createHash('sha256').update(bytes).digest('hex');
if (actual !== pin.sha256) throw new Error(`Node archive checksum mismatch: ${actual}`);
const extraction = await mkdtemp(resolve(cache, 'node-extract-'));
try {
  const unpack = spawnSync(
    'tar',
    [
      '-xzf',
      archive,
      '-C',
      extraction,
      '--strip-components=2',
      `node-v${version}-darwin-arm64/bin/node`,
    ],
    { stdio: 'inherit' },
  );
  if (unpack.status !== 0) throw new Error('Node archive extraction failed');
  await mkdir(dirname(output), { recursive: true });
  await cp(resolve(extraction, 'node'), output, { force: true });
  await chmod(output, 0o755);
} finally {
  await rm(extraction, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
}
const result = spawnSync(output, ['--version'], { encoding: 'utf8' });
if (result.status !== 0 || result.stdout.trim() !== `v${version}`) throw new Error('Bundled Node runtime did not execute at the pinned version');
console.log(`Bundled official Node ${result.stdout.trim()} (${actual})`);
