import { expect, test, type Page } from '@playwright/test';

const FIXTURE_LOAD_TIMEOUT_MS = 15_000;

async function openOnboarding(
  page: Page,
  viewport: Readonly<{ width: number; height: number }>,
  theme: 'dark' | 'light',
) {
  await page.setViewportSize(viewport);
  await page.goto(`/?fixture=onboarding&theme=${theme}`);
  await expect(page.locator('[data-test-fixture="onboarding"]')).toBeVisible({
    timeout: FIXTURE_LOAD_TIMEOUT_MS,
  });
  await page.evaluate(() => document.fonts.ready);
}

test('Onboarding welcome dark reference', async ({ page }) => {
  await openOnboarding(page, { width: 1577, height: 877 }, 'dark');
  await expect(page).toHaveScreenshot('onboarding-welcome-dark-1577x877.png', {
    animations: 'disabled',
    caret: 'hide',
    scale: 'css',
  });
});

test('Onboarding welcome light reference', async ({ page }) => {
  await openOnboarding(page, { width: 1100, height: 720 }, 'light');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page).toHaveScreenshot('onboarding-welcome-light-1100x720.png', {
    animations: 'disabled',
    caret: 'hide',
    scale: 'css',
  });
});

test('Onboarding compact reflow reference', async ({ page }) => {
  await openOnboarding(page, { width: 480, height: 720 }, 'dark');
  await expect(page).toHaveScreenshot('onboarding-welcome-dark-480x720.png', {
    animations: 'disabled',
    caret: 'hide',
    scale: 'css',
  });
});
