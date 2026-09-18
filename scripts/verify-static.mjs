import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const commands = [
  ['node', ['scripts/check-format.mjs']],
  ['node', ['scripts/check-boundaries.mjs']],
  ['pnpm', ['exec', 'tsc', '--noEmit']],
  ['pnpm', ['--filter', '@piui/sidecar', 'build']],
  ['cargo', ['fmt', '--manifest-path', 'src-tauri/Cargo.toml', '--', '--check']],
  ['cargo', ['clippy', '--manifest-path', 'src-tauri/Cargo.toml', '--all-targets', '--', '-D', 'warnings']],
];

for (const [command, args] of commands) {
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit', env: process.env });
  if (result.status !== 0) process.exit(result.status ?? 1);
}
process.stdout.write('Static verification passed.\n');
