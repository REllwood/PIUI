import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const commands = Object.freeze([
  ['pnpm', ['exec', 'vitest', 'run', 'tests/security']],
  [
    'cargo',
    [
      'test',
      '--manifest-path',
      'src-tauri/Cargo.toml',
      'credentials::import::tests',
      '--quiet',
    ],
  ],
  [
    'cargo',
    [
      'test',
      '--manifest-path',
      'src-tauri/Cargo.toml',
      'diagnostics::redact::tests',
      '--quiet',
    ],
  ],
  ['node', ['--test', 'tests/packaged/secret-canary-scanner.test.mjs']],
  [
    'pnpm',
    ['exec', 'playwright', 'test', 'tests/e2e/hostile-markdown.spec.ts'],
  ],
]);

for (const [command, args] of commands) {
  const result = spawnSync(command, args, {
    cwd: root,
    env: process.env,
    stdio: 'inherit',
  });
  if (result.error || result.signal || result.status !== 0) {
    process.exitCode = result.status ?? 1;
    break;
  }
}
