import { lstat, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

export const LOCAL_TRAIL_SKIPPED = 'skipped: local-only documentation trail not present';

async function pathExists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

/**
 * docs/ and the .forge/ planning record live only on the owner's machine
 * and are never committed. A checkout holding none of a check's markers is
 * a fresh clone, so the check skips; any marker present means the trail is
 * expected, and every file the check reads becomes mandatory so a partial
 * trail cannot pass silently.
 */
export async function localDocumentationTrailPresent(root, markers) {
  for (const marker of markers) {
    if (await pathExists(resolve(root, marker))) return true;
  }
  return false;
}

export async function readLocalTrailFile(root, path) {
  try {
    return await readFile(resolve(root, path), 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw new Error(`Local documentation trail is incomplete: ${path} is missing`);
    }
    throw error;
  }
}
