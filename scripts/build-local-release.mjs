import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { lstat, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { arch, platform } from 'node:os';
import { resolve } from 'node:path';
import { inventoryBundle, inspectMachOBytes } from '../tests/packaged/bundle-inspection.mjs';

const root = resolve(import.meta.dirname, '..');
const runId = `${new Date().toISOString().replaceAll(/[-:.]/gu, '')}-${randomBytes(8).toString('hex')}`;
const releasesRoot = resolve(root, '.forge/evidence/local-release-builds');
const releaseRoot = resolve(releasesRoot, runId);
const appPath = resolve(
  root,
  'src-tauri/target/aarch64-apple-darwin/release/bundle/macos/PIUI.app',
);

function run(command, args) {
  process.stdout.write(`${command} ${args.join(' ')}\n`);
  const result = spawnSync(command, args, {
    cwd: root,
    env: process.env,
    stdio: 'inherit',
  });
  if (result.status !== 0 || result.signal !== null || result.error) {
    throw new Error(`Local release command failed: ${command}`);
  }
}

if (platform() !== 'darwin' || arch() !== 'arm64') {
  throw new Error('The PIUI local release target requires Apple Silicon macOS');
}
await mkdir(releasesRoot, { recursive: true, mode: 0o700 });
await mkdir(releaseRoot, { recursive: false, mode: 0o700 });

let retainedCandidate = null;
try {
  await lstat(appPath);
  const retainedInventory = await inventoryBundle(appPath);
  const retainedParent = resolve(releaseRoot, 'retained-before-build');
  const retainedPath = resolve(retainedParent, 'PIUI.app');
  await mkdir(retainedParent, { recursive: false, mode: 0o700 });
  await rename(appPath, retainedPath);
  retainedCandidate = {
    path: retainedPath,
    fingerprint: retainedInventory.fingerprint,
    entries: retainedInventory.entries.length,
  };
  process.stdout.write(`Retained previous local bundle: ${retainedPath}\n`);
} catch (error) {
  if (error?.code !== 'ENOENT') throw error;
}

run('pnpm', ['verify:static']);
run('pnpm', ['security:supply-chain']);
run('node', ['scripts/check-staged-sidecar-current.mjs']);
run('node', ['scripts/test-sidecar-closure.mjs']);
run('pnpm', [
  'exec',
  'tauri',
  'build',
  '--target',
  'aarch64-apple-darwin',
  '--bundles',
  'app',
  '--config',
  'src-tauri/tauri.local-release.conf.json',
]);

let codesign = spawnSync('/usr/bin/codesign', ['--verify', '--deep', '--strict', appPath], {
  encoding: 'utf8',
});
if (codesign.status !== 0) {
  run('/usr/bin/codesign', ['--force', '--deep', '--sign', '-', '--timestamp=none', appPath]);
  codesign = spawnSync('/usr/bin/codesign', ['--verify', '--deep', '--strict', appPath], {
    encoding: 'utf8',
  });
}
if (codesign.status !== 0 || codesign.signal !== null || codesign.error) {
  throw new Error('Local ad-hoc code signature verification failed');
}

const inventory = await inventoryBundle(appPath);
const required = [
  'Contents/MacOS/piui',
  'Contents/MacOS/piui-node',
  'Contents/Resources/resources/THIRD-PARTY-NOTICES.txt',
  'Contents/Resources/resources/piui.cdx.json',
  'Contents/Resources/resources/sidecar/manifest.json',
];
for (const path of required) {
  if (!inventory.entries.some((entry) => entry.kind === 'file' && entry.path === path)) {
    throw new Error(`Local release bundle is missing ${path}`);
  }
}
for (const entry of inventory.entries.filter((candidate) => candidate.kind === 'file')) {
  if (/(?:^|\/)(?:\.env|auth\.json|credentials\.json|\.git-credentials)$/iu.test(entry.path)) {
    throw new Error(`Secret-bearing file entered the local bundle: ${entry.path}`);
  }
  const mustInspectExecutable = (entry.mode & 0o111) !== 0;
  if (mustInspectExecutable || entry.bytes <= 8 * 1_048_576) {
    const bytes = await readFile(resolve(appPath, entry.path));
    if (bytes.toString('latin1').includes('http://127.0.0.1:1420')) {
      throw new Error('Development endpoint entered the local release bundle');
    }
    const macho = inspectMachOBytes(bytes);
    if (macho && macho.architecture !== 'arm64') {
      throw new Error(`Non-arm64 Mach-O entered the local bundle: ${entry.path}`);
    }
  }
}

const runtimeRoot = resolve(releaseRoot, 'runtime');
await mkdir(runtimeRoot, { recursive: true, mode: 0o700 });
const child = spawn(resolve(appPath, 'Contents/MacOS/piui'), [], {
  cwd: runtimeRoot,
  detached: false,
  env: {
    ...process.env,
    PIUI_AGENT_ROOT: resolve(runtimeRoot, 'agent'),
    PIUI_SESSION_ROOT: resolve(runtimeRoot, 'sessions'),
    XDG_CACHE_HOME: resolve(runtimeRoot, 'cache'),
    XDG_CONFIG_HOME: resolve(runtimeRoot, 'config'),
    XDG_DATA_HOME: resolve(runtimeRoot, 'data'),
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let launchExit = null;
child.once('exit', (code, signal) => {
  launchExit = { code, signal };
});
await new Promise((resolveWait) => setTimeout(resolveWait, 2_000));
if (launchExit && launchExit.code !== 0) {
  throw new Error(`Local release exited during launch: ${JSON.stringify(launchExit)}`);
}
if (!launchExit) child.kill('SIGTERM');
await Promise.race([
  new Promise((resolveExit) => child.once('exit', resolveExit)),
  new Promise((_, reject) => setTimeout(() => reject(new Error('Local release did not quit')), 8_000)),
]);
const processCheck = spawnSync('/bin/ps', ['-axo', 'command='], { encoding: 'utf8' });
if (processCheck.status !== 0
  || processCheck.stdout.split('\n').some((line) => line.includes(`${appPath}/Contents/`))) {
  throw new Error('A PIUI local release process survived quit');
}

const evidence = {
  schemaVersion: 1,
  target: 'aarch64-apple-darwin',
  appPath,
  fingerprint: inventory.fingerprint,
  entries: inventory.entries.length,
  signing: 'ad-hoc-local-only',
  launch: 'pass',
  orphanProcess: false,
  retainedCandidate,
  distributionAuthorised: false,
};
await writeFile(
  resolve(runtimeRoot, 'release-evidence.json'),
  `${JSON.stringify(evidence, null, 2)}\n`,
  'utf8',
);
process.stdout.write(`Local release candidate: pass (${inventory.fingerprint})\n`);
process.stdout.write(`Local release bundle: ${appPath}\n`);
