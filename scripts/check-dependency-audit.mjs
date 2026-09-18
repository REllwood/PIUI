import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

function reject() {
  throw new Error('Dependency audit evidence rejected');
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject();
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])) reject();
}

export function assertDependencyAuditReport(report) {
  exactKeys(report, ['actions', 'advisories', 'metadata', 'muted']);
  if (Object.keys(report.advisories).length !== 0
    || !Array.isArray(report.muted)
    || report.muted.length !== 0
    || !Array.isArray(report.actions)
    || report.actions.length !== 0) reject();
  exactKeys(report.metadata, [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'totalDependencies',
    'vulnerabilities',
  ]);
  exactKeys(report.metadata.vulnerabilities, [
    'critical',
    'high',
    'info',
    'low',
    'moderate',
  ]);
  const vulnerabilities = report.metadata.vulnerabilities;
  if (vulnerabilities.critical !== 0
    || vulnerabilities.info !== 0
    || vulnerabilities.low !== 0
    || vulnerabilities.moderate !== 0
    || vulnerabilities.high !== 0) reject();
  return report;
}

async function assertNoException() {
  const manifest = JSON.parse(await readFile(
    new URL('../package.json', import.meta.url),
    'utf8',
  ));
  if (manifest.pnpm?.auditConfig !== undefined) reject();
  const workspace = await readFile(new URL('../pnpm-workspace.yaml', import.meta.url), 'utf8');
  if (/ignoreGhsas|GHSA-/u.test(workspace)) reject();
}

async function main() {
  await assertNoException();
  const pnpmEntry = resolve(
    homedir(),
    '.cache/node/corepack/v1/pnpm/9.15.0/bin/pnpm.cjs',
  );
  const result = spawnSync(process.execPath, [
    pnpmEntry,
    'audit',
    '--audit-level',
    'low',
    '--json',
  ], {
    cwd: resolve(new URL('..', import.meta.url).pathname),
    encoding: 'utf8',
    env: {
      HOME: homedir(),
      LANG: 'en_AU.UTF-8',
      PATH: '/usr/bin:/bin',
    },
    maxBuffer: 8 * 1_048_576,
    timeout: 120_000,
  });
  if (![0, 1].includes(result.status) || result.signal !== null || result.error) reject();
  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    reject();
  }
  assertDependencyAuditReport(parsed);
  process.stdout.write('Dependency audit: pass (zero advisories and no exceptions)\n');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
