import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');

export function collectReleaseDependencies() {
  return [...nodeDependencies(), ...rustDependencies()].sort((left, right) =>
    `${left.ecosystem}:${left.name}@${left.version}`.localeCompare(
      `${right.ecosystem}:${right.name}@${right.version}`,
      'en-AU',
    ),
  );
}

export function assertReviewedLicences(components) {
  const failures = components.filter(
    (component) =>
      !component.license || /(?:^|\W)(?:AGPL|GPL)(?:\W|$)/iu.test(component.license),
  );
  if (failures.length > 0) {
    throw new Error(
      `Unreviewed or incompatible release licences: ${failures
        .map((component) => `${component.name}@${component.version} (${component.license || 'missing'})`)
        .join(', ')}`,
    );
  }
}

function nodeDependencies() {
  const result = JSON.parse(
    execFileSync('pnpm', ['licenses', 'list', '--json', '--prod'], {
      cwd: root,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    }),
  );
  const dependencies = [];
  for (const [license, entries] of Object.entries(result)) {
    for (const entry of entries) {
      for (const version of entry.versions) {
        dependencies.push(
          Object.freeze({
            ecosystem: 'npm',
            name: entry.name,
            version,
            license,
            homepage: typeof entry.homepage === 'string' ? entry.homepage : '',
          }),
        );
      }
    }
  }
  return dependencies;
}

function rustDependencies() {
  const metadata = JSON.parse(
    execFileSync(
      'cargo',
      ['metadata', '--format-version', '1', '--locked', '--manifest-path', 'src-tauri/Cargo.toml'],
      { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
    ),
  );
  return metadata.packages
    .filter((entry) => entry.source !== null)
    .map((entry) =>
      Object.freeze({
        ecosystem: 'cargo',
        name: entry.name,
        version: entry.version,
        license: entry.license ?? '',
        homepage: entry.homepage ?? entry.repository ?? '',
      }),
    );
}
