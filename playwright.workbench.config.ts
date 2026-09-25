import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  testMatch: ['workbench.spec.ts', 'product-golden.spec.ts', 'onboarding.spec.ts'],
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  // One fixed output directory, replaced by each run, so local evidence
  // never accumulates per-run copies.
  outputDir: './test-results/workbench',
  use: {
    baseURL: 'http://127.0.0.1:1420',
    browserName: 'chromium',
    channel: 'chrome',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'pnpm dev',
    url: 'http://127.0.0.1:1420',
    reuseExistingServer: true,
    timeout: 30_000,
  },
});
