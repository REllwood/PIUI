import { defineConfig } from '@playwright/test';

const runId = process.env.PIUI_WORKBENCH_RUN ?? String(Date.now());
process.env.PIUI_WORKBENCH_RUN = runId;

export default defineConfig({
  testDir: './tests/e2e',
  testMatch: ['workbench.spec.ts', 'product-golden.spec.ts', 'onboarding.spec.ts'],
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  // Each local run retains its evidence without clearing an earlier run.
  outputDir: `./test-results/workbench-${runId}`,
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
