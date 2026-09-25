import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Locator, type Page } from '@playwright/test';

async function openOnboarding(page: Page, width = 1100, height = 720) {
  await page.setViewportSize({ width, height });
  await page.goto('/?fixture=onboarding');
  await expect(page.locator('[data-test-fixture="onboarding"]')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'A clear, local place to work with Pi.' })).toBeVisible();
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

async function expectNoOverflow(page: Page) {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
}

test('welcome reflows without clipping at reference, medium and compact sizes', async ({ page }) => {
  for (const viewport of [
    { width: 1577, height: 877 },
    { width: 1100, height: 720 },
    { width: 480, height: 720 },
  ]) {
    await openOnboarding(page, viewport.width, viewport.height);
    await expect(page.getByText('Local by default', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Continue' })).toBeVisible();
    await expectNoOverflow(page);
  }
});

test('golden onboarding journey preserves loading, consent and trust boundaries', async ({ page }) => {
  await openOnboarding(page);

  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: 'Let’s make sure the local foundations are ready.' })).toBeVisible();
  const continueButton = page.getByRole('button', { name: 'Continue', exact: true });
  await expect(continueButton).toBeDisabled();

  await page.getByRole('button', { name: 'Run checks' }).click();
  await expect(page.getByText('Checking this Mac…')).toBeVisible();
  await expect(page.getByText('Supported arm64 macOS host.')).toBeVisible();
  await expect(continueButton).toBeEnabled();
  await continueButton.click();

  await expect(page.getByRole('heading', { name: 'Bring across existing provider access, if you want to.' })).toBeVisible();
  await expect(page.locator('input[type="password"]')).toHaveCount(0);
  await page.getByText('Import selected provider credentials', { exact: true }).click();
  await page.getByRole('button', { name: 'Import to Keychain' }).click();
  await expect(page.getByText('Importing securely…')).toBeVisible();
  await expect(page.getByText('Import completed. The source was not changed.')).toBeVisible();
  await continueButton.click();

  await expect(page.getByRole('heading', { name: 'Use a subscription you already have.' })).toBeVisible();
  await page.getByRole('button', { name: /Continue with ChatGPT \/ Codex/ }).click();
  await expect(page.getByText('Checking provider confirmation…')).toBeVisible();
  await expect(page.getByText('ChatGPT / Codex connected and validated.')).toBeVisible();
  await expect(page.locator('input[type="password"]')).toHaveCount(0);
  await continueButton.click();

  await expect(page.getByRole('heading', { name: 'Select the folder where Pi will work.' })).toBeVisible();
  await page.getByRole('button', { name: 'Choose project folder' }).click();
  await expect(page.getByText('Waiting for folder selection…')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'PIUI Fixture Project' })).toBeVisible();
  await expect(page.getByText(/Choosing a folder does not run its extensions/)).toBeVisible();
  await page.getByRole('button', { name: 'Trust and open' }).click();
  await expect(page.getByText('Applying trust…')).toBeVisible();
  await expect(page.getByText('Trusted and ready')).toBeVisible();
  const disclaimer = page.getByText(/Trust does not change the approval policy/);
  await expect(disclaimer).toBeVisible();
  // The disclaimer keeps its warning tone and spacing inside the project preview.
  await expect(disclaimer).toHaveCSS('color', await tokenColour(page, '--warning'));
  await expect(disclaimer).toHaveCSS('margin-top', '16px');
  await continueButton.click();

  await expect(page.getByRole('heading', { name: 'Your local workspace is ready.' })).toBeVisible();
  await expect(page.getByText('Local test account', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Skip tour' }).click();
  await page.getByRole('button', { name: 'Replay tour' }).click();
  await page.getByRole('button', { name: 'Next' }).click();
  await page.getByRole('button', { name: 'Next' }).click();
  await page.getByRole('button', { name: 'Tour complete' }).click();

  await page.getByRole('button', { name: 'Finish and open PIUI' }).click();
  await expect(page.getByText('Saving setup…')).toBeVisible();
  await expect(page.locator('[data-test-fixture="product"]')).toBeVisible();
  await expect(page.getByRole('textbox', { name: 'Message Pi' })).toBeVisible();
  await expectNoOverflow(page);
});

test('onboarding has no serious accessibility violation or undersized visible action', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
  await openOnboarding(page, 1100, 720);
  const result = await new AxeBuilder({ page }).analyze();
  expect(
    result.violations.filter((violation) =>
      ['serious', 'critical'].includes(violation.impact ?? ''),
    ),
  ).toEqual([]);
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
  await expectNoOverflow(page);
});

// Walks the deterministic fixture to the Project step with the folder chosen but untrusted.
async function openProjectStep(page: Page, width: number, height: number) {
  await openOnboarding(page, width, height);
  const continueButton = page.getByRole('button', { name: 'Continue', exact: true });
  await continueButton.click();
  await page.getByRole('button', { name: 'Run checks' }).click();
  await expect(continueButton).toBeEnabled();
  await continueButton.click();
  await continueButton.click();
  await page.getByRole('button', { name: /Continue with ChatGPT \/ Codex/ }).click();
  await expect(page.getByText('ChatGPT / Codex connected and validated.')).toBeVisible();
  await continueButton.click();
  await page.getByRole('button', { name: 'Choose project folder' }).click();
  await expect(page.getByRole('button', { name: 'Trust and open' })).toBeVisible();
}

// How many lines of text an element's content occupies, measured from its line boxes.
async function lineCount(locator: Locator) {
  return locator.evaluate((element) => {
    const style = getComputedStyle(element);
    const lineHeight = Number.parseFloat(style.lineHeight) || Number.parseFloat(style.fontSize) * 1.4;
    const range = document.createRange();
    range.selectNodeContents(element);
    const rects = Array.from(range.getClientRects()).filter((rect) => rect.width > 0);
    const top = Math.min(...rects.map((rect) => rect.top));
    const bottom = Math.max(...rects.map((rect) => rect.bottom));
    return Math.round((bottom - top) / lineHeight);
  });
}

for (const viewport of [
  { width: 680, height: 720 },
  { width: 1100, height: 720 },
  { width: 1577, height: 877 },
]) {
  test(`project trust choices and tour points read cleanly at ${viewport.width}px`, async ({ page }) => {
    await openProjectStep(page, viewport.width, viewport.height);
    await expect(page.locator('.trust-choices article')).toHaveCount(2);
    for (const name of ['Open untrusted', 'Trust and open']) {
      expect(await lineCount(page.getByRole('heading', { name, level: 3 }))).toBe(1);
    }
    const trust = page.getByRole('button', { name: 'Trust and open' });
    expect(await lineCount(trust)).toBe(1);
    await trust.click();
    const trusted = page.getByRole('button', { name: 'Trusted and ready' });
    await expect(trusted).toBeVisible();
    expect(await lineCount(trusted)).toBe(1);
    // The card names the folder, never its internal capability.
    await expect(page.locator('.project-preview')).not.toContainText('capability');
    await expectNoOverflow(page);

    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Your local workspace is ready.' })).toBeVisible();
    const points = page.locator('.tour-points span');
    await expect(points).toHaveCount(3);
    // Each tour point label stays on one or two lines rather than a narrow stacked column.
    for (const point of await points.all()) {
      expect(await lineCount(point)).toBeLessThanOrEqual(2);
    }
    await expectNoOverflow(page);
  });
}
