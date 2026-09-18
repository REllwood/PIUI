import { expect, test, type Page } from '@playwright/test';

const FIXTURE_LOAD_TIMEOUT_MS = 15_000;

async function openProduct(page: Page, width: number, height: number) {
  await page.setViewportSize({ width, height });
  await page.goto('/?fixture=product');
  await expect(page.locator('[data-test-fixture="product"]')).toBeVisible({
    timeout: FIXTURE_LOAD_TIMEOUT_MS,
  });
  await page.evaluate(() => document.fonts.ready);
}

test('Simple workspace dark reference', async ({ page }) => {
  await openProduct(page, 1577, 877);
  await expect(page).toHaveScreenshot('simple-dark-1577x877.png', {
    animations: 'disabled',
    caret: 'hide',
    scale: 'css',
  });
});

test('Advanced settings light reference', async ({ page }) => {
  await openProduct(page, 1280, 800);
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByText('Simple enabled', { exact: true }).click();
  await page.getByRole('button', { name: /Appearance/ }).click();
  await page.getByRole('radio', { name: 'Light' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page).toHaveScreenshot('advanced-light-1280x800.png', {
    animations: 'disabled',
    caret: 'hide',
    scale: 'css',
  });
});

test('Minimum window reflow reference', async ({ page }) => {
  await openProduct(page, 680, 560);
  await expect(page.getByRole('button', { name: 'Open navigation' })).toBeVisible();
  await expect(page).toHaveScreenshot('simple-dark-680x560.png', {
    animations: 'disabled',
    caret: 'hide',
    scale: 'css',
  });
});
