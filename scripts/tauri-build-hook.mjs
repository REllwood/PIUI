import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  equalArchitectureSourceLease,
  snapshotArchitectureSource,
} from './architecture-source-snapshot.mjs';
import {
  revalidateTauriBuildAuthorisation,
  validateTauriBuildAuthorisation,
} from './tauri-build-authorisation.mjs';

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const authorisation = await validateTauriBuildAuthorisation(sourceRoot);
const sourceBefore = await snapshotArchitectureSource(sourceRoot);
if (sourceBefore.source.digest !== authorisation.sourceDigest) {
  throw new Error('Tauri build source does not match its authenticated frozen snapshot');
}
await revalidateTauriBuildAuthorisation(authorisation);
const result = spawnSync(
  authorisation.pnpmNode.path,
  [authorisation.pnpmEntry.path, 'build'], {
  cwd: sourceRoot,
  env: process.env,
  stdio: 'inherit',
},
);
await revalidateTauriBuildAuthorisation(authorisation);
if (result.status !== 0 || result.signal !== null) {
  throw new Error('Tauri frontend build hook failed');
}
const sourceAfter = await snapshotArchitectureSource(sourceRoot);
if (!sourceBefore.inventoryBytes.equals(sourceAfter.inventoryBytes)
  || !equalArchitectureSourceLease(sourceBefore, sourceAfter)
  || sourceAfter.source.digest !== authorisation.sourceDigest) {
  throw new Error('Tauri build source changed while the frontend was built');
}
await revalidateTauriBuildAuthorisation(authorisation);
