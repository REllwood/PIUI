import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  LOCAL_TRAIL_SKIPPED,
  localDocumentationTrailPresent,
  readLocalTrailFile,
} from './local-documentation-trail.mjs';

const root = resolve(import.meta.dirname, '..');
const trailPresent = await localDocumentationTrailPresent(root, ['docs', '.forge/SECURITY.md']);
if (trailPresent) {
  const inventory = spawnSync(process.execPath, ['scripts/security-command-inventory.mjs', '--check'], {
    cwd: root,
    stdio: 'inherit',
  });
  if (inventory.status !== 0 || inventory.signal !== null || inventory.error) {
    throw new Error('Security command inventory check failed');
  }
}

// The shipped capability and CSP are tracked, so they are enforced on every
// checkout whether or not the local security record is present.
const [capabilityText, tauriText] = await Promise.all([
  readFile(resolve(root, 'src-tauri/capabilities/default.json'), 'utf8'),
  readFile(resolve(root, 'src-tauri/tauri.conf.json'), 'utf8'),
]);
const capability = JSON.parse(capabilityText);
if (JSON.stringify(capability.permissions) !== JSON.stringify(['core:default'])) {
  throw new Error('Main capability broadened');
}
const csp = JSON.parse(tauriText).app?.security?.csp;
for (const directive of [
  "default-src 'none'",
  "script-src 'self'",
  "worker-src 'none'",
  "frame-src 'none'",
  "object-src 'none'",
]) {
  if (typeof csp !== 'string' || !csp.includes(directive)) {
    throw new Error(`CSP is missing ${directive}`);
  }
}

if (!trailPresent) {
  process.stdout.write('Native capability and CSP: current\n');
  process.stdout.write(`Security threat model and data-flow inventory: ${LOCAL_TRAIL_SKIPPED}\n`);
} else {
  // Read in a fixed order so an incomplete trail names the same file each run.
  const trail = [];
  for (const path of [
    '.forge/SECURITY.md',
    'docs/SECURITY.md',
    'docs/architecture/data-flow.md',
    'docs/architecture/command-inventory.md',
  ]) trail.push(await readLocalTrailFile(root, path));
  const [forge, security, flow, inventoryText] = trail;
  for (const term of [
    'WebView',
    'Keychain',
    'OAuth',
    'workspace',
    'executable',
    'approval',
    'update',
    'process lifecycle',
  ]) {
    if (!`${forge}\n${security}\n${flow}`.toLowerCase().includes(term.toLowerCase())) {
      throw new Error(`Security record is missing ${term}`);
    }
  }
  for (const round of ['Round 1', 'Round 2', 'Round 3', 'Round 4']) {
    if (!forge.includes(round)) throw new Error(`Security record is missing ${round}`);
  }
  const count = Number(inventoryText.match(/Registered command count: (\d+)\./u)?.[1]);
  if (!Number.isSafeInteger(count) || count < 50) throw new Error('Command inventory count invalid');

  process.stdout.write('Security threat model and data-flow inventory: current\n');
}
