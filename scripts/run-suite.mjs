import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const step = (command, ...args) => Object.freeze({ command, args: Object.freeze(args) });

const suites = Object.freeze({
  'web-build': [
    step('pnpm', 'exec', 'tsc', '--noEmit'),
    step('pnpm', 'exec', 'vite', 'build'),
  ],
  format: [
    step('node', 'scripts/check-format.mjs'),
    step('cargo', 'fmt', '--manifest-path', 'src-tauri/Cargo.toml', '--', '--check'),
  ],
  types: [
    step('pnpm', 'exec', 'tsc', '--noEmit'),
    step('pnpm', '--filter', '@piui/sidecar', 'build'),
  ],
  'stage-sidecar': [
    step('node', 'scripts/fetch-node-runtime.mjs'),
    step('node', 'scripts/stage-sidecar.mjs'),
  ],
  e2e: [
    step('node', 'scripts/run-suite.mjs', 'stage-sidecar'),
    step('pnpm', 'exec', 'playwright', 'test', 'tests/e2e'),
  ],
  streaming: [
    step('node', 'scripts/run-suite.mjs', 'stage-sidecar'),
    step('pnpm', 'exec', 'playwright', 'test', 'tests/e2e/spike-stream.spec.ts'),
  ],
  'protocol-all': [
    step('pnpm', '--filter', '@piui/protocol', 'test:fixtures'),
    step('pnpm', '--filter', '@piui/protocol', 'test'),
    step(
      'cargo',
      'test',
      '--manifest-path',
      'src-tauri/Cargo.toml',
      '--test',
      'protocol_fixtures',
      '--test',
      'protocol_limits',
      '--test',
      'stdout_contamination',
      '--test',
      'sequencing_resync',
    ),
  ],
  onboarding: [
    step('pnpm', 'exec', 'vitest', 'run', 'src/domain/onboardingMachine.test.ts'),
    step('pnpm', 'exec', 'playwright', 'test', 'tests/e2e/onboarding.spec.ts'),
    step(
      'pnpm',
      'exec',
      'playwright',
      'test',
      '--config',
      'playwright.visual.config.ts',
      'tests/visual/onboarding.spec.ts',
    ),
  ],
  'simple-workspace': [
    step(
      'pnpm',
      'exec',
      'playwright',
      'test',
      '--config',
      'playwright.visual.config.ts',
      '--grep',
      'Simple workspace|Minimum window',
    ),
    step(
      'pnpm',
      'exec',
      'playwright',
      'test',
      '--config',
      'playwright.accessibility.config.ts',
      '--grep',
      'Simple conversation|Minimum window',
    ),
  ],
  advanced: [
    step(
      'pnpm',
      'exec',
      'playwright',
      'test',
      '--config',
      'playwright.visual.config.ts',
      '--grep',
      'Advanced settings',
    ),
    step(
      'pnpm',
      'exec',
      'playwright',
      'test',
      '--config',
      'playwright.accessibility.config.ts',
      '--grep',
      'Advanced routes',
    ),
  ],
  updates: [
    step('cargo', 'test', '--manifest-path', 'src-tauri/Cargo.toml', '--test', 'update_activation'),
    step('cargo', 'test', '--manifest-path', 'src-tauri/Cargo.toml', 'updates::tests'),
  ],
  lifecycle: [
    step('cargo', 'test', '--manifest-path', 'src-tauri/Cargo.toml', '--test', 'lifecycle_matrix'),
    step('cargo', 'test', '--manifest-path', 'src-tauri/Cargo.toml', 'lifecycle'),
    step('node', 'scripts/test-sidecar-closure.mjs'),
    step('node', 'scripts/test-sidecar-closure-policy.mjs'),
    step('node', 'scripts/test-sidecar-routing.mjs'),
    step('node', 'scripts/test-sidecar-auth-routing.mjs'),
  ],
  packaged: [
    step('pnpm', 'test:packaged:inspection'),
    step('pnpm', 'exec', 'vitest', 'run', 'tests/packaged/credential-lifecycle.spec.ts'),
    step('pnpm', 'exec', 'vitest', 'run', 'tests/packaged/approval-matrix.spec.ts'),
  ],
  'release-metadata': [
    step('node', 'scripts/generate-notices.mjs'),
    step('node', 'scripts/generate-sbom.mjs'),
  ],
  'supply-chain': [
    step('node', 'scripts/run-suite.mjs', 'release-metadata'),
    step('node', '--test', 'tests/packaged/dependency-security.test.mjs'),
    step('node', 'scripts/check-dependency-audit.mjs'),
    step('node', 'scripts/check-cargo-audit.mjs'),
  ],
  'security-full': [
    step('node', 'scripts/check-security-record.mjs'),
    step('node', 'scripts/run-suite.mjs', 'supply-chain'),
    step('node', 'scripts/run-security-tests.mjs'),
  ],
  'review-correctness': [
    step('pnpm', 'test:unit'),
    step('pnpm', 'test:contract'),
    step('pnpm', 'test:protocol:all'),
    step('pnpm', 'test:updates'),
    step('pnpm', 'test:lifecycle'),
  ],
  'review-ui': [
    step('pnpm', 'test:onboarding'),
    step('pnpm', 'test:visual'),
    step('pnpm', 'test:a11y'),
  ],
  'release-verify': [
    step('pnpm', 'install', '--frozen-lockfile'),
    step('pnpm', 'verify:static'),
    step('pnpm', 'test:unit'),
    step('pnpm', 'test:components'),
    step('pnpm', 'test:contract'),
    step('pnpm', 'test:protocol:all'),
    step('pnpm', 'security:full'),
    step('pnpm', 'test:e2e'),
    step('pnpm', 'test:visual'),
    step('pnpm', 'test:a11y'),
    step('pnpm', 'test:performance'),
    step('pnpm', 'test:updates'),
    step('pnpm', 'test:lifecycle'),
    step('cargo', 'test', '--manifest-path', 'src-tauri/Cargo.toml', '--all-targets', '--', '--test-threads=1'),
    step('pnpm', 'test:packaged'),
    step('pnpm', 'gate:architecture'),
    step('pnpm', 'docs:check'),
  ],
});

const suiteName = process.argv[2];
const suite = suites[suiteName];
if (!suite) {
  throw new Error(`Unknown suite: ${suiteName ?? '(missing)'}`);
}

for (const [index, command] of suite.entries()) {
  process.stdout.write(`[${index + 1}/${suite.length}] ${command.command} ${command.args.join(' ')}\n`);
  const result = spawnSync(command.command, command.args, {
    cwd: root,
    stdio: 'inherit',
    env: process.env,
  });
  if (result.status !== 0 || result.signal !== null || result.error) {
    throw new Error(`${suiteName} failed at step ${index + 1}`);
  }
}

process.stdout.write(`${suiteName}: pass\n`);
