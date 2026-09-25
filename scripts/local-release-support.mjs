import { chmod, lstat, mkdir, readdir, rm } from 'node:fs/promises';
import { resolve } from 'node:path';

/**
 * One fixed location per output. Each run overwrites the evidence, replaces
 * the single retained previous bundle and reuses Tauri's own bundle output,
 * so repeated local releases never accumulate per-run copies.
 */
export function localReleasePaths(root) {
  const evidenceRoot = resolve(root, '.build/evidence/release-local');
  const previousRoot = resolve(root, '.build/release-local-previous');
  return Object.freeze({
    appPath: resolve(
      root,
      'src-tauri/target/aarch64-apple-darwin/release/bundle/macos/PIUI.app',
    ),
    evidencePath: resolve(evidenceRoot, 'release-evidence.json'),
    evidenceRoot,
    previousAppPath: resolve(previousRoot, 'PIUI.app'),
    previousRoot,
    runtimeRoot: resolve(root, '.build/release-local-runtime'),
  });
}

async function unlockTree(path) {
  const state = await lstat(path);
  if (state.isSymbolicLink() || !state.isDirectory()) return;
  await chmod(path, 0o700);
  for (const name of await readdir(path)) await unlockTree(resolve(path, name));
}

/**
 * Empty a fixed output directory in place. Bundles can carry read-only
 * directories, so they are made owner-writable (without following links)
 * before removal.
 */
export async function replaceDirectory(path) {
  try {
    await unlockTree(path);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  await rm(path, { force: true, recursive: true });
  await mkdir(path, { recursive: true, mode: 0o700 });
  await chmod(path, 0o700);
}
