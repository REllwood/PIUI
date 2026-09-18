import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
for (const [command, args] of [
  ['node', ['scripts/check-docs.mjs']],
  ['node', ['scripts/check-security-record.mjs']],
  ['pnpm', ['gate:architecture']],
]) {
  const result = spawnSync(command, args, { cwd: root, env: process.env, stdio: 'inherit' });
  if (result.status !== 0 || result.signal !== null || result.error) {
    throw new Error(`Forge closure prerequisite failed: ${command}`);
  }
}

const [plan, forge, manual, review, release] = await Promise.all([
  readFile(resolve(root, '.forge/PLAN.md'), 'utf8'),
  readFile(resolve(root, '.forge/FORGE.md'), 'utf8'),
  readFile(resolve(root, '.forge/MANUAL-TEST-RESULTS.md'), 'utf8'),
  readFile(resolve(root, '.forge/REVIEW.md'), 'utf8'),
  readFile(resolve(root, '.forge/RELEASE-CANDIDATE.md'), 'utf8'),
]);
if (/^- \[ \] done$/mu.test(plan)) throw new Error('Forge plan still contains unfinished steps');
if (!/\*\*Status:\*\* done-local/u.test(forge)) throw new Error('Forge status is not done-local');
if (/\bNot run\b/u.test(manual)) throw new Error('Manual release checklist is not complete');
if (!review.includes('Final automated review: Pass')) throw new Error('Final review evidence is absent');
if (!release.includes('Local candidate status: Pass')) throw new Error('Local release evidence is absent');

const staged = spawnSync('git', ['diff', '--cached', '--quiet'], { cwd: root });
if (staged.status !== 0 || staged.signal !== null || staged.error) {
  throw new Error('Git index contains staged changes');
}
const remote = spawnSync('git', ['remote', '-v'], { cwd: root, encoding: 'utf8' });
if (remote.status !== 0 || !remote.stdout.trim()) throw new Error('Pre-existing Git remote unavailable');
process.stdout.write('Forge trail: closed without source-control mutation\n');
