import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

async function openFixture(page: Page, viewport = { width: 1577, height: 877 }) {
  await page.setViewportSize(viewport);
  await page.goto('/?fixture=product');
  await expect(page.locator('[data-test-fixture="product"]')).toBeVisible();
}

// Resolves a theme token to the computed colour string the browser reports for text.
async function tokenColour(page: Page, token: string): Promise<string> {
  return page.evaluate((name) => {
    const probe = document.createElement('span');
    probe.style.color = `var(${name})`;
    document.body.append(probe);
    const colour = getComputedStyle(probe).color;
    probe.remove();
    return colour;
  }, token);
}

async function expectNoHorizontalOverflow(page: Page) {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
}

test('conversation, approval and acknowledged message journey', async ({ page }) => {
  await openFixture(page);
  await expect(page.getByRole('region', { name: 'Conversation', exact: true })).toBeVisible();
  await expect(
    page.getByRole('heading', { name: 'Run the local verification suite' }),
  ).toBeVisible();

  await page.getByRole('button', { name: 'Approve once' }).click();
  await expect(page.getByRole('button', { name: 'Recording decision…' }).first()).toBeVisible();
  await expect(
    page.getByRole('heading', { name: 'Run the local verification suite' }),
  ).toBeHidden();

  await page.getByRole('button', { name: 'Stop' }).click();
  await page.getByRole('textbox', { name: 'Message Pi' }).fill('Check the local release evidence.');
  await expect(page.getByRole('button', { name: 'Send' })).toBeEnabled();
  await page.getByRole('button', { name: 'Send' }).click();
  await expect(page.getByText('Sending…')).toBeVisible();
  await expect(page.getByText('The deterministic fixture accepted this message.')).toBeVisible();
});

test('sessions, activity, settings and diagnostics are integrated', async ({ page }) => {
  await openFixture(page);

  await page.getByRole('button', { name: 'Sessions', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Sessions' })).toBeVisible();
  await page.getByPlaceholder('Search sessions, projects or branches').fill('architecture');
  await expect(page.getByRole('heading', { name: 'Architecture gate' })).toBeVisible();

  await page.getByRole('button', { name: /^Activity/ }).click();
  await expect(page.getByRole('heading', { name: 'Activity' })).toBeVisible();
  await page.getByRole('button', { name: 'Redacted event details' }).click();
  await expect(page.locator('.raw-event pre')).toContainText('product requirements');

  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();
  await page.getByPlaceholder('Search Settings').fill('diagnostics');
  await page.getByRole('button', { name: /Diagnostics/ }).click();
  await page.getByRole('button', { name: 'Run checks' }).click();
  await expect(page.getByText('Running checks…')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Run checks' })).toBeEnabled();
});

test('keyboard discovery, themes and accessibility remain usable', async ({ page }) => {
  await openFixture(page, { width: 960, height: 720 });
  const composer = page.getByRole('textbox', { name: 'Message Pi' });
  await composer.fill('@App');
  await expect(page.getByRole('listbox', { name: 'Composer suggestions' })).toBeVisible();
  await composer.press('ArrowDown');
  await composer.press('Enter');
  await expect(composer).toHaveValue(/@src\/app\/ProductContext\.tsx /);

  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByRole('button', { name: /Appearance/ }).click();
  await page.getByRole('radio', { name: 'Light' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');

  const result = await new AxeBuilder({ page }).disableRules(['color-contrast']).analyze();
  expect(
    result.violations.filter((violation) =>
      ['serious', 'critical'].includes(violation.impact ?? ''),
    ),
  ).toEqual([]);
  await expectNoHorizontalOverflow(page);
});

test('Markdown colours follow the app theme rather than the macOS appearance', async ({ page }) => {
  // Measures the shared Markdown code surface inside the themed product root.
  const codeSurface = () =>
    page.evaluate(() => {
      const probe = document.createElement('pre');
      probe.className = 'markdown__code-block';
      document.querySelector('.piui')?.append(probe);
      const colour = getComputedStyle(probe).backgroundColor;
      probe.remove();
      return colour;
    });
  await page.emulateMedia({ colorScheme: 'dark' });
  await openFixture(page);
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByRole('button', { name: /Appearance/ }).click();

  await page.getByRole('radio', { name: 'Light' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  expect(await codeSurface()).toBe('rgb(241, 244, 239)');

  await page.emulateMedia({ colorScheme: 'light' });
  await page.getByRole('radio', { name: 'Dark' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await codeSurface()).toBe('rgb(9, 11, 9)');
});

test('replaying the product tour shows only the tour, in place', async ({ page }) => {
  await openFixture(page);
  const url = page.url();
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  const replay = page.getByRole('button', { name: 'Replay product tour' });
  await replay.click();
  const tour = page.getByRole('dialog', { name: 'Ask in plain language' });
  await expect(tour).toBeVisible();
  expect(page.url()).toBe(url);
  await tour.getByRole('button', { name: 'Next' }).click();
  await tour.getByRole('button', { name: 'Next' }).click();
  await tour.getByRole('button', { name: 'Tour complete' }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();
  await expect(replay).toBeFocused();

  await replay.click();
  await expect(page.getByRole('dialog', { name: 'Ask in plain language' })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);
});

test('minimum window and 200 percent zoom reflow without page overflow', async ({ page }) => {
  await openFixture(page, { width: 680, height: 560 });
  await page.evaluate(() => {
    document.documentElement.style.zoom = '2';
  });
  await expect(page.getByRole('button', { name: 'Open navigation' })).toBeVisible();
  await expect(page.getByRole('textbox', { name: 'Message Pi' })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

test('advanced package lifecycle is explicit, acknowledged and visibly pending', async ({ page }) => {
  await openFixture(page);
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByText('Simple enabled', { exact: true }).click();
  await expect(page.getByRole('checkbox', { name: /Advanced enabled/ })).toBeChecked();
  await page.getByRole('button', { name: /Resources/ }).click();

  await page.getByRole('textbox', { name: 'Package source' }).fill('@piui/fixture-package');
  await page.getByRole('button', { name: 'Review and install' }).click();
  // Confirmation is an in-app dialog: WKWebView may not present window.confirm at all.
  const confirmation = page.getByRole('alertdialog');
  await expect(confirmation).toHaveAccessibleName('Install “@piui/fixture-package” from npm?');
  await expect(confirmation.getByRole('button', { name: 'Cancel' })).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(confirmation).toHaveCount(0);
  await expect(page.getByText('Installing package…')).toHaveCount(0);
  await page.getByRole('button', { name: 'Review and install' }).click();
  await confirmation.getByRole('button', { name: 'Install' }).click();
  await expect(page.getByText('Installing package…')).toBeVisible();
  await expect(page.getByText('@piui/fixture-package installed but left disabled.')).toBeVisible();

  const card = page.locator('.resource-card').filter({ hasText: '@piui/fixture-package' });
  await expect(card.getByText('Disabled', { exact: true })).toBeVisible();
  // The executable-code warning keeps its warning tone rather than the muted card copy.
  await expect(card.getByText(/This code runs with your permissions/)).toHaveCSS(
    'color',
    await tokenColour(page, '--warning'),
  );
  await card.getByRole('button', { name: 'Update' }).click();
  await confirmation.getByRole('button', { name: 'Update' }).click();
  await expect(page.getByText('Updating…')).toBeVisible();
  await expect(page.getByText('@piui/fixture-package updated.')).toBeVisible();

  await card.getByRole('button', { name: 'Remove' }).click();
  await confirmation.getByRole('button', { name: 'Remove' }).click();
  await expect(page.getByText('Removing…')).toBeVisible();
  await expect(page.getByText('@piui/fixture-package removed.')).toBeVisible();
  await expect(card).toHaveCount(0);
});
