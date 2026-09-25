import { chmod, lstat, mkdir, readdir, rm } from 'node:fs/promises';
import { resolve } from 'node:path';

// Keys a local smoke launch may inherit. Everything else in the developer
// shell, including provider API keys and loader variables, stays behind.
const LAUNCH_ENVIRONMENT_KEYS = Object.freeze([
  'HOME',
  'LANG',
  'LC_ALL',
  'LOGNAME',
  'TMPDIR',
  'USER',
  '__CF_USER_TEXT_ENCODING',
]);

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

export function localReleaseLaunchEnvironment(environment, runtimeRoot) {
  const launch = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' };
  for (const key of LAUNCH_ENVIRONMENT_KEYS) {
    if (typeof environment[key] === 'string') launch[key] = environment[key];
  }
  return Object.freeze({
    ...launch,
    PIUI_AGENT_ROOT: resolve(runtimeRoot, 'agent'),
    PIUI_SESSION_ROOT: resolve(runtimeRoot, 'sessions'),
    XDG_CACHE_HOME: resolve(runtimeRoot, 'cache'),
    XDG_CONFIG_HOME: resolve(runtimeRoot, 'config'),
    XDG_DATA_HOME: resolve(runtimeRoot, 'data'),
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
