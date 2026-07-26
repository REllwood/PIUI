import { chmod, lstat, readdir, rename, rm } from 'node:fs/promises';
import { resolve } from 'node:path';

async function pathExists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

async function prepareDirectory(path, isRoot) {
  for (const entry of await readdir(path, { withFileTypes: true })) {
    const child = resolve(path, entry.name);
    if (entry.name === '.DS_Store') {
      await rm(child, { recursive: true, force: true });
    } else if (entry.isDirectory()) {
      await prepareDirectory(child, false);
    }
  }
  await rm(resolve(path, '.DS_Store'), { recursive: true, force: true });
  await chmod(path, isRoot ? 0o755 : 0o555);
}

/** Seal descendants while keeping the candidate root writable for macOS rename. */
export async function prepareCandidateForRename(path) {
  await prepareDirectory(path, true);
}

async function removeFinderMetadataDefensively(path, isRoot) {
  const entries = await readdir(path, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) {
      await removeFinderMetadataDefensively(resolve(path, entry.name), false);
    }
  }
  if (await pathExists(resolve(path, '.DS_Store'))) {
    // Nested candidates are already 0555. Open only the affected directory,
    // remove the unlisted file, and immediately reseal it.
    if (!isRoot) await chmod(path, 0o755);
    try {
      await rm(resolve(path, '.DS_Store'), { recursive: true, force: true });
    } finally {
      if (!isRoot) await chmod(path, 0o555);
    }
  }
}

async function verifyNoFinderMetadata(path) {
  for (const entry of await readdir(path, { withFileTypes: true })) {
    if (entry.name === '.DS_Store') throw new Error('Finder metadata entered staged closure');
    if (entry.isDirectory()) await verifyNoFinderMetadata(resolve(path, entry.name));
  }
}

/** Finish publication only after rename, then verify the sealed tree. */
export async function sealPublishedOutput(path) {
  await removeFinderMetadataDefensively(path, true);
  await rm(resolve(path, '.DS_Store'), { recursive: true, force: true });
  await chmod(path, 0o555);
  await verifyNoFinderMetadata(path);
}

/** Actual rename seam used by the disposable macOS regression. */
export async function renamePreparedCandidate(prepared, output) {
  await rename(prepared, output);
  await sealPublishedOutput(output);
}
