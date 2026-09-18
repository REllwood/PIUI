import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/accessibility',
  fullyParallel: false,
  workers: 1,
  // Browser and first-page start-up can legitimately exceed 30 seconds on a
  // cold or resource-constrained Mac. Keep the assertion timeouts strict, but
  // give the complete accessibility scenario enough room to reach them.
  timeout: 60_000,
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
  // Browser and first-page start-up can legitimately exceed 30 seconds on a
  // cold or resource-constrained Mac. Keep the assertion timeouts strict, but
  // give the complete accessibility scenario enough room to reach them.
  timeout: 60_000,
  },
});
