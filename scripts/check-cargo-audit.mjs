import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const TARGET = 'aarch64-apple-darwin';

function reject(message) {
  throw new Error(`Cargo audit evidence rejected: ${message}`);
}

function run(command, arguments_, maximumBytes = 32 * 1_048_576) {
  const result = spawnSync(command, arguments_, {
    cwd: new URL('..', import.meta.url),
    encoding: 'utf8',
    maxBuffer: maximumBytes,
    timeout: 120_000,
  });
  if (result.signal !== null || result.error) reject(`${command} did not complete`);
  return result;
}

function parseJson(value, label) {
  try {
    return JSON.parse(value);
  } catch {
    reject(`${label} was not JSON`);
  }
}

function packageKey(package_) {
  return `${package_.name}\u0000${package_.version}`;
}

export function assertCargoAuditReport(report, activePackages) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    reject('report shape changed');
  }
  if (report.vulnerabilities?.found !== false
    || report.vulnerabilities?.count !== 0
    || !Array.isArray(report.vulnerabilities?.list)
    || report.vulnerabilities.list.length !== 0) {
    reject('a vulnerability is present');
  }
  const warnings = report.warnings;
  if (!warnings || typeof warnings !== 'object' || Array.isArray(warnings)) {
    reject('warning shape changed');
  }
  const warningClasses = Object.keys(warnings).sort();
  if (warningClasses.some((kind) => !['unmaintained', 'unsound'].includes(kind))) {
    reject(`unexpected warning class: ${warningClasses.join(', ')}`);
  }
  const targetActive = [];
  const targetInactive = [];
  for (const [kind, entries] of Object.entries(warnings)) {
    if (!Array.isArray(entries)) reject(`${kind} warnings changed shape`);
    for (const entry of entries) {
      const advisoryId = entry?.advisory?.id;
      const package_ = entry?.package;
      if (typeof advisoryId !== 'string'
        || typeof package_?.name !== 'string'
        || typeof package_?.version !== 'string') {
        reject(`${kind} warning changed shape`);
      }
      const finding = { advisoryId, kind, package: packageKey(package_) };
      if (activePackages.has(finding.package)) targetActive.push(finding);
      else targetInactive.push(finding);
    }
  }
  const activeUnsound = targetActive.filter(({ kind }) => kind === 'unsound');
  if (activeUnsound.length > 0) {
    reject(`target-active unsound advisory: ${activeUnsound.map(({ advisoryId }) => advisoryId).join(', ')}`);
  }
  return { targetActive, targetInactive };
}

async function main() {
  const metadataResult = run('cargo', [
    'metadata',
    '--manifest-path',
    'src-tauri/Cargo.toml',
    '--format-version',
    '1',
    '--filter-platform',
    TARGET,
  ], 64 * 1_048_576);
  if (metadataResult.status !== 0) reject('cargo metadata failed');
  const metadata = parseJson(metadataResult.stdout, 'cargo metadata');
  const resolvedIds = new Set(metadata.resolve?.nodes?.map(({ id }) => id));
  if (resolvedIds.size === 0) reject('target dependency graph is empty');
  const activePackages = new Set(
    metadata.packages
      .filter(({ id }) => resolvedIds.has(id))
      .map(packageKey),
  );

  const auditResult = run('cargo', [
    'audit',
    '--file',
    'src-tauri/Cargo.lock',
    '--json',
  ]);
  if (![0, 1].includes(auditResult.status)) reject('cargo audit failed to report');
  const audit = parseJson(auditResult.stdout, 'cargo audit');
  const { targetActive, targetInactive } = assertCargoAuditReport(audit, activePackages);
  const activeAdvisories = targetActive.map(({ advisoryId }) => advisoryId).sort();
  process.stdout.write(
    `Cargo audit: pass (0 vulnerabilities; ${targetActive.length} target-active unmaintained warnings recorded${
      activeAdvisories.length > 0 ? `: ${activeAdvisories.join(', ')}` : ''
    }; ${targetInactive.length} target-inactive warnings excluded)\n`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
