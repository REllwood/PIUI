import { expect, test } from '@playwright/test';

function percentile(samples: readonly number[], rank: number): number {
  const ordered = [...samples].sort((left, right) => left - right);
  return ordered[Math.min(ordered.length - 1, Math.ceil(ordered.length * rank) - 1)] ?? Infinity;
}

test('warm launch, long transcript, interaction, cancellation and resize budgets', async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/?fixture=product');
  await expect(page.locator('[data-test-fixture="product"]')).toBeVisible();

  const warmLaunches: number[] = [];
  for (let sample = 0; sample < 5; sample += 1) {
    await page.reload();
    await expect(page.locator('[data-test-fixture="product"]')).toBeVisible();
    warmLaunches.push(
      await page.evaluate(() => {
        const navigation = performance.getEntriesByType('navigation')[0] as
          | PerformanceNavigationTiming
          | undefined;
        return navigation?.duration ?? Infinity;
      }),
    );
  }
  const warmP50 = percentile(warmLaunches, 0.5);
  const warmP95 = percentile(warmLaunches, 0.95);
  expect(warmP50).toBeLessThanOrEqual(2_000);
  expect(warmP95).toBeLessThanOrEqual(3_000);

  await page.goto('/?fixture=product&long=10000&payload=5000');
  await expect(page.locator('[data-test-fixture="product"]')).toBeVisible();
  await expect(page.locator('.transcript-list .message').first()).toBeVisible();

  const visibleRows = await page.locator('.transcript-list .message').count();
  expect(visibleRows).toBeLessThanOrEqual(500);
  const scrollDurations = await page.locator('.transcript-viewport').evaluate(async (element) => {
    const values: number[] = [];
    for (let sample = 0; sample < 24; sample += 1) {
      const started = performance.now();
      element.scrollTop = (element.scrollHeight * sample) / 23;
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      values.push(performance.now() - started);
    }
    return values;
  });
  const scrollP95 = percentile(scrollDurations, 0.95);
  expect(scrollP95).toBeLessThan(50);

  const heapBytes = await page.evaluate(() => {
    const memory = performance as Performance & { memory?: { usedJSHeapSize: number } };
    return memory.memory?.usedJSHeapSize ?? 0;
  });
  if (heapBytes > 0) expect(heapBytes).toBeLessThan(500 * 1024 * 1024);

  await page.goto('/?fixture=product');
  await expect(page.locator('[data-test-fixture="product"]')).toBeVisible();
  const stopStarted = Date.now();
  await page.getByRole('button', { name: 'Stop' }).evaluate((button) => button.click());
  await expect(page.getByRole('button', { name: 'Send' })).toBeVisible();
  const cancellationMs = Date.now() - stopStarted;
  expect(cancellationMs).toBeLessThanOrEqual(200);

  await page.setViewportSize({ width: 680, height: 560 });
  const layout = await page.evaluate(() => ({
    overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    clippedPrimaryActions: [...document.querySelectorAll<HTMLElement>('button.button--primary')]
      .filter((element) => {
        const rect = element.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
      })
      .flatMap((element) => {
        const rect = element.getBoundingClientRect();
        return rect.left >= 0 && rect.right <= innerWidth && rect.width >= 44 && rect.height >= 44
          ? []
          : [
              {
                label: element.innerText,
                left: rect.left,
                right: rect.right,
                width: rect.width,
                height: rect.height,
                minHeight: getComputedStyle(element).minHeight,
                rootZoom: getComputedStyle(document.documentElement).zoom,
                target: getComputedStyle(document.documentElement).getPropertyValue('--target'),
                devicePixelRatio,
              },
            ];
      }),
  }));
  expect(layout.overflow).toBeLessThanOrEqual(1);
  expect(layout.clippedPrimaryActions).toEqual([]);
  console.log(
    `PIUI_PERFORMANCE:${JSON.stringify({
      warmP50,
      warmP95,
      scrollP95,
      visibleRows,
      heapBytes,
      cancellationMs,
      resizeOverflowPx: layout.overflow,
    })}`,
  );
});
