import { readFileSync, readdirSync, statSync } from 'node:fs';
import { extname, join, relative, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const failures = [];

function filesWithin(directory) {
  const result = [];
  for (const name of readdirSync(directory)) {
    const absolute = join(directory, name);
    const metadata = statSync(absolute);
    if (metadata.isDirectory()) result.push(...filesWithin(absolute));
    else if (['.ts', '.tsx', '.mts', '.cts'].includes(extname(name))) result.push(absolute);
  }
  return result;
}

function imports(source) {
  return [...source.matchAll(/(?:import|export)\s+(?:type\s+)?(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]/gu)].map((match) => match[1]);
}

function isDeepPiImport(specifier) {
  if (!specifier.startsWith('@earendil-works/pi-')) return false;
  return specifier.split('/').length > 2;
}

for (const file of [...filesWithin(join(root, 'src')), ...filesWithin(join(root, 'sidecar', 'src'))]) {
  const name = relative(root, file).replaceAll('\\', '/');
  const source = readFileSync(file, 'utf8');
  for (const specifier of imports(source)) {
    if (name.startsWith('src/features/') && specifier.startsWith('@tauri-apps/')) {
      failures.push(`${name}: feature code must use src/platform, not ${specifier}`);
    }
    if (name.startsWith('src/') && !name.startsWith('src/architecture-gate/') && /sidecar|credentials/u.test(specifier)) {
      failures.push(`${name}: WebView code cannot import sidecar or credential modules`);
    }
    if (name.startsWith('sidecar/src/') && isDeepPiImport(specifier)) {
      failures.push(`${name}: Pi imports must use a public package root (${specifier})`);
    }
    if (name.startsWith('sidecar/src/') && specifier.startsWith('@tauri-apps/')) {
      failures.push(`${name}: sidecar code cannot import Tauri`);
    }
  }
}

const negativeFixtures = [
  ['src/features/example.ts', "import { invoke } from '@tauri-apps/api/core'"],
  ['sidecar/src/example.ts', "import x from '@earendil-works/pi-coding-agent/dist/private.js'"],
];
for (const [name, source] of negativeFixtures) {
  const rejected = imports(source).some((specifier) =>
    (name.startsWith('src/features/') && specifier.startsWith('@tauri-apps/'))
    || (name.startsWith('sidecar/src/') && isDeepPiImport(specifier)));
  if (!rejected) failures.push(`boundary checker failed to reject negative fixture ${name}`);
}

if (failures.length > 0) {
  process.stderr.write(`${failures.join('\n')}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write('Application layer boundaries verified.\n');
}
