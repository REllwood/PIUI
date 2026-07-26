import { createHash, randomUUID } from 'node:crypto';
import {
  chmod,
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  isForbiddenDocumentationDirectoryPath,
  isForbiddenDocumentationFile,
  isForbiddenDocumentationPath,
} from './sidecar-closure-policy.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cacheRoot = resolve(root, '.cache');
const output = resolve(root, 'src-tauri/resources/sidecar');
const lockPath = resolve(cacheRoot, 'sidecar-stage.lock');

await mkdir(cacheRoot, { recursive: true });
await acquireLock();
await unlockTauriResourceCopies();
await quarantineLegacyDeployment();
let workspace;
try {
  workspace = await mkdtemp(resolve(cacheRoot, 'sidecar-stage-'));
  const deployment = resolve(workspace, 'deployment');
  const prepared = resolve(workspace, 'prepared');

  let result = spawnSync('pnpm', ['--filter', '@piui/sidecar', 'build'], {
    cwd: root,
    stdio: 'inherit',
  });
  if (result.status !== 0) throw new Error('Sidecar build failed');

  await mkdir(deployment, { recursive: true });
  const productionImporter = resolve(root, 'sidecar/production');
  const importerPackage = JSON.parse(await readFile(resolve(productionImporter, 'package.json'), 'utf8'));
  await cp(resolve(productionImporter, 'package.json'), resolve(deployment, 'package.json'));
  await cp(resolve(productionImporter, 'pnpm-lock.yaml'), resolve(deployment, 'pnpm-lock.yaml')); 
  result = spawnSync(
    'pnpm',
    [
      '--dir',
      deployment,
      '--config.node-linker=hoisted',
      'install',
      '--prod',
      '--ignore-workspace',
      '--frozen-lockfile',
    ],
    { cwd: root, stdio: 'inherit' },
  );
  if (result.status !== 0) throw new Error('Isolated production dependency installation failed');

  await cp(resolve(root, 'sidecar/dist'), resolve(deployment, 'dist'), { recursive: true });
  const protocolTarget = resolve(deployment, 'node_modules/@piui/protocol');
  await mkdir(protocolTarget, { recursive: true });
  await cp(resolve(root, 'packages/protocol/dist'), resolve(protocolTarget, 'dist'), { recursive: true });
  await cp(resolve(root, 'packages/protocol/schema'), resolve(protocolTarget, 'schema'), { recursive: true });
  await writeFile(
    resolve(protocolTarget, 'package.json'),
    `${JSON.stringify({
      name: '@piui/protocol',
      version: '0.1.0',
      type: 'module',
      main: './dist/index.js',
      exports: {
        '.': './dist/index.js',
        './codec': './dist/codec.js',
      },
    }, null, 2)}\n`,
  );
  importerPackage.dependencies['@piui/protocol'] = '0.1.0';
  await writeFile(resolve(deployment, 'package.json'), `${JSON.stringify(importerPackage, null, 2)}\n`);

  await cp(deployment, prepared, { recursive: true, dereference: true });
  await prune(prepared);
  await validateProductionClosure(prepared);
  const all = await files(prepared, prepared);
  const manifest = [];
  for (const path of all) {
    const data = await readFile(path);
    manifest.push({
      path: relative(prepared, path),
      bytes: data.length,
      sha256: createHash('sha256').update(data).digest('hex'),
    });
    // Integrity is anchored by the manifest and later bundle signature, not by
    // read-only source modes. Normal writable owner modes keep repeated Tauri
    // resource copies atomic and prevent a prior build from poisoning the next.
    await chmod(path, 0o644);
  }
  const manifestPath = resolve(prepared, 'manifest.json');
  await writeFile(
    manifestPath,
    `${JSON.stringify({ node: '22.23.1', piSdk: '0.82.0', closure: 'isolated-v1', files: manifest }, null, 2)}\n`,
    { mode: 0o644 },
  );
  // Seal only after the manifest is complete: remove any Finder metadata that
  // raced the manifest walk, then make every directory non-writable so Finder
  // cannot recreate unlisted files in the published closure.
  await sealDirectories(prepared);

  await mkdir(dirname(output), { recursive: true });
  const retired = resolve(workspace, 'retired');
  if (await pathExists(output)) makeTreeOwnerWritable(output);
  try {
    await rename(output, retired);
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      if (await pathExists(output)) await sealDirectories(output);
      throw error;
    }
  }
  try {
    await rename(prepared, output);
  } catch (error) {
    if (await pathExists(retired)) {
      await rename(retired, output);
      await sealDirectories(output);
    }
    throw error;
  }

  console.log(
    `Staged ${manifest.length} production resources; manifest=${relative(root, resolve(output, 'manifest.json'))}`,
  );
} finally {
  if (workspace) await cleanTreeBestEffort(workspace);
  await rm(lockPath, { recursive: true, force: true });
}

async function acquireLock() {
  const deadline = Date.now() + 120_000;
  while (true) {
    try {
      await mkdir(lockPath);
      await writeFile(
        resolve(lockPath, 'owner.json'),
        `${JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() })}\n`,
        { mode: 0o600 },
      );
      return;
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      const owner = await readOwner();
      if (await lockIsStale(owner)) {
        const abandoned = resolve(cacheRoot, `sidecar-stage-abandoned-${randomUUID()}`);
        try {
          await rename(lockPath, abandoned);
          await cleanTreeBestEffort(abandoned);
          continue;
        } catch (renameError) {
          if (!['ENOENT', 'EEXIST'].includes(renameError?.code)) throw renameError;
        }
      }
      if (Date.now() >= deadline) throw new Error('Timed out waiting for the sidecar staging lock');
      await sleep(200);
    }
  }
}

async function readOwner() {
  try {
    return JSON.parse(await readFile(resolve(lockPath, 'owner.json'), 'utf8'));
  } catch {
    return null;
  }
}

async function lockIsStale(owner) {
  if (owner) return !processIsAlive(owner.pid);
  try {
    const stat = await lstat(lockPath);
    return Date.now() - stat.mtimeMs > 2_000;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

async function unlockTauriResourceCopies() {
  const target = resolve(root, 'src-tauri/target');
  for (const path of [
    resolve(target, 'debug/resources/sidecar'),
    resolve(target, 'release/resources/sidecar'),
    resolve(target, 'aarch64-apple-darwin/debug/resources/sidecar'),
    resolve(target, 'aarch64-apple-darwin/release/resources/sidecar'),
  ]) {
    if (await pathExists(path)) spawnSync('chmod', ['-R', 'u+w', path], { stdio: 'ignore' });
  }
}

async function quarantineLegacyDeployment() {
  const legacy = resolve(cacheRoot, 'sidecar-deploy');
  if (!(await pathExists(legacy))) return;
  const abandoned = resolve(cacheRoot, `sidecar-deploy-abandoned-${randomUUID()}`);
  await rename(legacy, abandoned);
  await cleanTreeBestEffort(abandoned);
}

function processIsAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code !== 'ESRCH';
  }
}

async function pathExists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

async function cleanTreeBestEffort(path) {
  spawnSync('chmod', ['-R', 'u+w', path], { stdio: 'ignore' });
  try {
    await rm(path, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch (error) {
    console.warn(`Staging cleanup deferred for ${relative(root, path)}: ${error.message}`);
  }
}

async function files(path, boundary) {
  const entries = [];
  for (const name of (await readdir(path)).sort()) {
    const absolute = resolve(path, name);
    // Finder may recreate metadata between the prune and manifest walks. Remove
    // it at the point of enumeration so repeated staging stays byte-for-byte
    // deterministic and the bundle never records Finder state.
    if (name === '.DS_Store') {
      await rm(absolute, { recursive: true, force: true });
      continue;
    }
    const stat = await lstat(absolute);
    if (stat.isSymbolicLink()) {
      throw new Error(`Staged resource contains symlink: ${relative(boundary, absolute)}`);
    }
    if (stat.isDirectory()) entries.push(...(await files(absolute, boundary)));
    else entries.push(absolute);
  }
  return entries;
}

async function validateProductionClosure(path) {
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
  for (const requiredPath of required) {
    if (!(await pathExists(resolve(path, requiredPath)))) {
      throw new Error(`Required sidecar runtime asset missing: ${requiredPath}`);
    }
  }
  const forbiddenPackages = [
    '@tauri-apps',
    '@testing-library',
    '@types',
    '@vitejs',
    'react',
    'react-aria',
    'react-aria-components',
    'react-dom',
    'tailwindcss',
    'typescript',
    'vite',
    'vitest',
  ];
  for (const packageName of forbiddenPackages) {
    if (await pathExists(resolve(path, 'node_modules', packageName))) {
      throw new Error(`Non-sidecar package entered production closure: ${packageName}`);
    }
  }
  const staged = await files(path, path);
  const forbiddenPath = /(^|\/)(?:\.github|\.history)(\/|$)|(^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock)$|\.(?:d\.)?(?:m|c)?ts$|\.map$/;
  const rejected = staged
    .map((entry) => relative(path, entry))
    .filter((entry) => isForbiddenDocumentationPath(entry) || forbiddenPath.test(entry));
  if (rejected.length) {
    throw new Error(`Rejected production resources remain: ${rejected.slice(0, 10).join(', ')}`);
  }
}

async function prune(path, boundary = path) {
  for (const name of await readdir(path)) {
    const child = resolve(path, name);
    const stat = await lstat(child);
    if (stat.isDirectory()) {
      const relativePath = relative(boundary, child);
      if (
        /^(?:@types|\.cache|\.git|\.github|\.history|\.bin|\.pnpm|\.pnpm-store)$/.test(name) ||
        isForbiddenDocumentationDirectoryPath(relativePath)
      ) {
        await rm(child, { recursive: true, force: true });
      } else {
        await prune(child, boundary);
      }
    } else if (
      name === '.DS_Store' ||
      name === '.modules.yaml' ||
      /^(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock)$/.test(name) ||
      /^(\.editorconfig|\.eslintignore|\.eslintrc.*|\.gitignore|\.jscs.*|\.npmignore|\.nvmrc|\.prettier.*|\.travis.*|\.yarnrc.*)$/.test(name) ||
      isForbiddenDocumentationFile(name) ||
      /\.(d\.)?(m|c)?ts$|\.map$/.test(name)
    ) {
      await rm(child, { force: true });
    }
  }
}

function makeTreeOwnerWritable(path) {
  const result = spawnSync('chmod', ['-R', 'u+w', path], { stdio: 'ignore' });
  if (result.status !== 0) throw new Error('Unable to unlock prior staged closure');
}

async function sealDirectories(path) {
  for (const name of await readdir(path)) {
    const child = resolve(path, name);
    if (name === '.DS_Store') {
      await rm(child, { recursive: true, force: true });
    } else if ((await lstat(child)).isDirectory()) {
      await sealDirectories(child);
    }
  }
  // Close the final Finder race in this directory immediately before sealing.
  await rm(resolve(path, '.DS_Store'), { recursive: true, force: true });
  await chmod(path, 0o555);
}
