import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const FIXTURE_LOAD_TIMEOUT_MS = 15_000;

async function openProduct(page: Page, width: number, height: number) {
  await page.setViewportSize({ width, height });
  await page.goto('/?fixture=product');
  await expect(page.locator('[data-test-fixture="product"]')).toBeVisible({
    timeout: FIXTURE_LOAD_TIMEOUT_MS,
  });
}

async function expectAccessible(page: Page) {
  const result = await new AxeBuilder({ page }).analyze();
  expect(
    result.violations.filter((violation) =>
      ['serious', 'critical'].includes(violation.impact ?? ''),
    ),
  ).toEqual([]);
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
  const undersized = await page.locator('button:visible, [role="button"]:visible').evaluateAll(
    (elements) =>
      elements
        .map((element) => {
          const rect = element.getBoundingClientRect();
          return {
            label: element.getAttribute('aria-label') ?? element.textContent?.trim() ?? '',
            width: rect.width,
            height: rect.height,
          };
        })
        .filter((item) => item.width < 44 || item.height < 44),
  );
  expect(undersized).toEqual([]);
}

test('Simple conversation is keyboard and screen-reader ready in both themes', async ({ page }) => {
  await openProduct(page, 1577, 877);
  await expectAccessible(page);
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByRole('button', { name: /Appearance/ }).click();
  await page.getByRole('radio', { name: 'Light' }).click();
  await expectAccessible(page);
});

test('Advanced routes remain accessible with contrast and reduced motion preferences', async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: 'dark' });
  await openProduct(page, 1280, 800);
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByText('Simple enabled', { exact: true }).click();
  await page.getByRole('button', { name: /Appearance/ }).click();
  await page.getByText('Increase contrast', { exact: true }).click();
  await page.getByRole('button', { name: /Resources/ }).click();
  await expectAccessible(page);
  await page.getByRole('button', { name: /^Activity/ }).click();
  await expectAccessible(page);
});

test('Minimum window at 200 percent zoom preserves actions and reflow', async ({ page }) => {
  await openProduct(page, 680, 560);
  await page.evaluate(() => {
    document.documentElement.style.zoom = '2';
  });
  await expect(page.getByRole('button', { name: 'Open navigation' })).toBeVisible();
  await expect(page.getByRole('textbox', { name: 'Message Pi' })).toBeVisible();
  await expectAccessible(page);
});

test('Toolbar search and workspace actions are operable', async ({ page }) => {
  await openProduct(page, 1280, 800);
  await page.getByRole('button', { name: 'Stop' }).click();
  await expect(page.getByRole('button', { name: 'Send' })).toBeVisible();
  const navigation = page.getByRole('complementary', { name: 'Workspace navigation' });
  await navigation.getByRole('button', { name: /Architecture gate/ }).click();
  await expect(page.getByRole('heading', { name: 'Architecture gate' })).toBeVisible();
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await expect(page.getByPlaceholder('Search sessions, projects or branches')).toBeFocused();
  await page.getByRole('button', { name: 'More workspace actions' }).click();
  await expect(page.getByRole('dialog', { name: 'Search commands' })).toBeVisible();
  await page.getByRole('button', { name: 'Close command menu' }).click();
  await navigation.getByRole('button', { name: 'New conversation' }).click();
  await expect(page.getByRole('heading', { name: 'What would you like to make possible?' })).toBeVisible();
});
