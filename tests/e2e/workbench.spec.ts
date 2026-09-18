import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

async function welcome(page: Page, width = 1440, height = 900) {
  await page.setViewportSize({ width, height });
  await page.goto('/?fixture=product&welcome=true');
  await expect(
    page.getByRole('heading', { name: 'What would you like to make possible?' }),
  ).toBeVisible();
}

async function accessible(page: Page) {
  const result = await new AxeBuilder({ page }).analyze();
  expect(
    result.violations.filter((item) => ['serious', 'critical'].includes(item.impact ?? '')),
  ).toEqual([]);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    ),
  ).toBeLessThanOrEqual(1);
}

test('starter drafts survive navigation and remain separate between conversations', async ({
  page,
}) => {
  await welcome(page);
  const composer = page.getByRole('textbox', { name: 'Message Pi' });
  await page.getByRole('button', { name: /^Get to know this project/ }).click();
  await expect(composer).toBeFocused();
  await expect(composer).toHaveValue(/Help me understand this project/);
  await composer.fill('Keep this unsent idea.');
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByRole('button', { name: 'Conversation', exact: true }).click();
  await expect(composer).toHaveValue('Keep this unsent idea.');
  await page.getByRole('button', { name: /^New conversation/ }).click();
  await expect(composer).toHaveValue('');
  await composer.fill('A different conversation.');
  await page
    .getByRole('complementary', { name: 'Workspace navigation' })
    .getByRole('button', { name: /Finish the desktop experience/ })
    .click();
  await expect(composer).toHaveValue('Keep this unsent idea.');
  await page.getByRole('button', { name: /^Review and refine/ }).click();
  await expect(composer).toHaveValue(/^Keep this unsent idea\.\n\nReview this project/);
});

test('models and thinking are available in Simple mode without submitting the draft', async ({
  page,
}) => {
  await welcome(page);
  const composer = page.getByRole('textbox', { name: 'Message Pi' });
  await composer.fill('A draft to keep.');
  await page.getByRole('button', { name: /Choose model:/ }).click();
  const dialog = page.getByRole('dialog', { name: 'Choose your model' });
  const search = dialog.getByRole('searchbox', { name: 'Search models' });
  await expect(search).toBeFocused();
  await search.fill('mini');
  await search.press('Enter');
  await search.press('Meta+Enter');
  await expect(composer).toHaveValue('A draft to keep.');
  await expect(dialog).toBeVisible();
  await dialog.getByRole('radio', { name: /GPT-5.4 mini/ }).check();
  await dialog.getByLabel('Thinking', { exact: true }).selectOption('low');
  await accessible(page);
  await dialog.getByRole('button', { name: 'Save choice' }).click();
  await expect(dialog).toBeHidden();
  await expect(
    page.getByRole('button', { name: 'Choose model: GPT-5.4 mini, Quick thinking' }),
  ).toBeFocused();
  await expect(composer).toHaveValue('A draft to keep.');
  await page.getByRole('button', { name: /^New conversation/ }).click();
  await expect(
    page.getByRole('button', { name: 'Choose model: GPT-5.4 mini, Quick thinking' }),
  ).toBeVisible();
});

test('command search works while composing and restores focus on Escape', async ({ page }) => {
  await welcome(page);
  const composer = page.getByRole('textbox', { name: 'Message Pi' });
  await composer.fill('Do not lose this.');
  await composer.press('Meta+k');
  const dialog = page.getByRole('dialog', { name: 'Search commands' });
  const search = dialog.getByRole('textbox', { name: 'Search commands' });
  await expect(search).toBeFocused();
  await accessible(page);
  await search.fill('unmatched action');
  await expect(dialog.getByRole('status')).toContainText('No actions found');
  await search.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(composer).toBeFocused();
  await composer.press('Meta+k');
  await search.fill('previous conversation');
  await search.press('ArrowDown');
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Sessions', exact: true })).toBeVisible();
});

test('approval and change reviews can be reopened on a wide window', async ({ page }) => {
  await page.setViewportSize({ width: 1577, height: 877 });
  await page.goto('/?fixture=product');
  await page.getByRole('button', { name: 'Close approval' }).click();
  await expect(page.getByRole('button', { name: 'Approve once' })).toBeHidden();
  await page.getByRole('button', { name: /Open 1 pending approval/ }).click();
  await expect(page.getByRole('button', { name: 'Approve once' })).toBeVisible();
  await page.getByRole('button', { name: 'Close approval' }).click();
  await page
    .getByRole('group', { name: 'Context views' })
    .getByRole('button', { name: 'Approval needed' })
    .click();
  await expect(page.getByRole('button', { name: 'Approve once' })).toBeVisible();
  await page
    .getByRole('group', { name: 'Context views' })
    .getByRole('button', { name: /Changes/ })
    .click();
  await expect(page.getByRole('complementary', { name: 'Context review' })).toContainText('Undo');
});

test('compact navigation hides its controls and keeps keyboard focus in the drawer', async ({
  page,
}) => {
  await welcome(page, 680, 700);
  const navigation = page.locator('.navigation-plane');
  await expect(navigation).toHaveAttribute('inert', '');
  const trigger = page.getByRole('button', { name: 'Open navigation' });
  await trigger.click();
  await expect(navigation).not.toHaveAttribute('inert', '');
  await expect(navigation.getByRole('button', { name: 'Close navigation' })).toBeFocused();
  for (let i = 0; i < 14; i += 1) {
    await page.keyboard.press('Tab');
    expect(await navigation.evaluate((element) => element.contains(document.activeElement))).toBe(
      true,
    );
  }
  await page.keyboard.press('Escape');
  await expect(trigger).toBeFocused();
  await expect(navigation).toHaveAttribute('inert', '');
  await page.evaluate(() => {
    document.documentElement.style.zoom = '2';
  });
  await accessible(page);
});

test('welcome and interaction motion honour both app and system preferences', async ({ page }) => {
  await page.goto('/?fixture=product&welcome=true&motion=standard');
  const content = page.locator('.conversation-welcome__content');
  await expect(content).toBeVisible();
  await expect(content).toHaveCSS('animation-name', 'piui-surface-enter');
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await expect(content).toHaveCSS('animation-name', 'none');
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.goto('/?fixture=product&welcome=true');
  await expect(content).toHaveCSS('animation-name', 'none');
  await accessible(page);
});

test('silent copy and external-open failures surface a dismissible notice', async ({ page }) => {
  await welcome(page);
  const notice = page.getByRole('alert');
  await page.evaluate(() => {
    window.dispatchEvent(new CustomEvent('piui:copy-unavailable'));
  });
  await expect(notice).toContainText(
    'Copying to the clipboard is not available right now. Select the text and copy it manually.',
  );
  await notice.getByRole('button', { name: 'Dismiss' }).click();
  await expect(notice).toBeHidden();
  await page.evaluate(() => {
    window.dispatchEvent(new CustomEvent('piui:external-open-failed'));
  });
  await expect(notice).toContainText('That link could not be opened in your browser.');
  await notice.getByRole('button', { name: 'Dismiss' }).click();
  await expect(notice).toBeHidden();
});
