import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const fixture = readFileSync(resolve(root, 'src/domain/fixtures.ts'), 'utf8');
for (const required of ['connection: \'ready\'', "turnStatus: 'tool-running'", "state: 'awaiting'", "undo: 'revoked'", "status: 'offline'"]) {
  if (!fixture.includes(required)) throw new Error(`Fixture state missing: ${required}`);
}
const build = spawnSync('pnpm', ['build'], { cwd: root, stdio: 'inherit', env: process.env });
if (build.status !== 0) process.exit(build.status ?? 1);
const bundle = readFileSync(resolve(root, 'dist/index.html'), 'utf8');
if (/VITE_PIUI_FIXTURE|__PIUI_PRODUCT_FIXTURE__/u.test(bundle)) throw new Error('Release bundle exposes fixture activation');
process.stdout.write('Deterministic product fixtures and release-mode rejection verified.\n');
