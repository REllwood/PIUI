import { spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const argumentsAfterScript = process.argv.slice(2);

if (argumentsAfterScript.length !== 1 || argumentsAfterScript[0] !== 'dev') {
  process.stderr.write([
    'The Tauri package script accepts only: pnpm tauri dev.',
    'Use pnpm tauri:build:production for a guarded production build.',
    'Direct pnpm exec tauri invocations and Tauri config overrides are unsupported.',
    '',
  ].join('\n'));
  process.exitCode = 1;
} else {
  const cliEntry = resolve(repositoryRoot, 'node_modules/@tauri-apps/cli/tauri.js');
  const child = spawn(process.execPath, [cliEntry, 'dev'], {
    cwd: repositoryRoot,
    env: process.env,
    stdio: 'inherit',
  });
  const outcome = await new Promise((resolveOutcome, rejectOutcome) => {
    child.once('error', rejectOutcome);
    child.once('exit', (status, signal) => resolveOutcome({ signal, status }));
  });
  if (outcome.signal !== null) {
    process.stderr.write(`Tauri development process ended via ${outcome.signal}.\n`);
    process.exitCode = 1;
  } else {
    process.exitCode = outcome.status ?? 1;
  }
}
