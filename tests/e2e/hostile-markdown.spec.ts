import {
  expect,
  test,
  type APIRequestContext,
  type Browser,
  type Page,
  type Request,
} from '@playwright/test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  MARKDOWN_ASSET_REGISTER_PATH,
  MARKDOWN_ASSET_SCOPE,
} from '../support/markdownAssetRegistry';

const projectRoot = resolve(import.meta.dirname, '../..');
const applicationOrigin = 'http://127.0.0.1:1420';

type HarnessAsset = {
  capability: string;
  url: string;
  mime: unknown;
  byteLength: number;
  expiresAt: number;
};

type RegisteredAsset = {
  capability: string;
  descriptor: {
    url: string;
    mime: 'image/png' | 'image/jpeg' | 'image/webp';
    byteLength: number;
    expiresAt: number;
  };
};

type BrowserEvidence = {
  fetches: string[];
  xhr: string[];
  webSockets: string[];
  eventSources: string[];
  beacons: string[];
  popups: string[];
  history: string[];
  navigationEvents: string[];
  tauriInvokes: string[];
  cspViolations: string[];
};

type PageOptions = {
  markdown?: string;
  assets?: HarnessAsset[];
  complete?: boolean;
};

type RequestObservation = ReturnType<typeof observeRequests>;
type RequestInventory = ReadonlyMap<string, number>;
type BootstrapInventories = Readonly<{
  core: RequestInventory;
  highlighted: RequestInventory;
}>;

let bootstrapInventories: BootstrapInventories = {
  core: new Map(),
  highlighted: new Map(),
};

const AUDITED_SOURCE_MODULE_PATHS = new Set([
  '/src/main.tsx',
  '/src/App.tsx',
  '/src/architecture-gate/CredentialProbe.tsx',
  '/src/architecture-gate/StreamProbe.tsx',
  '/src/architecture-gate/a26MarkdownPrelude.ts',
  '/src/architecture-gate/routeActivation.ts',
  '/src/bridge/client.ts',
  '/src/components/primitives/LoadingLabel.tsx',
  '/src/security/SafeMarkdownSpike.tsx',
  '/src/security/SafeMarkdownSpikeRoute.tsx',
  '/src/security/markdownPolicy.ts',
  '/src/security/shikiHighlighter.ts',
]);
const AUDITED_STYLESHEET_PATHS = new Set([
  '/src/app.css',
  '/src/styles/tokens.css',
  '/src/styles/theme-dark.css',
  '/src/styles/theme-light.css',
  '/src/styles/typography.css',
  '/src/styles/base.css',
  '/src/app/shell.css',
  '/src/components/work-trace/work-trace.css',
  '/src/features/conversation/conversation.css',
  '/src/features/composer/model-picker.css',
  '/src/features/composer/resource-picker.css',
  '/src/features/onboarding/onboarding.css',
  '/src/features/sessions/supporting-routes.css',
  '/src/features/settings/settings.css',
]);
const AUDITED_VITE_DEPENDENCY_PATH = /^\/node_modules\/\.vite\/deps\/(?:chunk-[A-Z0-9]+|rolldown-runtime-[A-Za-z0-9_-]+|core-[A-Za-z0-9_-]+|lib-[A-Za-z0-9_-]+|space-separated-tokens-[A-Za-z0-9_-]+|ccount-[A-Za-z0-9_-]+|css-[A-Za-z0-9_-]+|javascript-[A-Za-z0-9_-]+|react|react-dom|react_jsx-runtime|react_jsx-dev-runtime|react-dom_client|@tauri-apps_api_core|react-markdown|remark-gfm|shiki_core|shiki_engine_javascript|shiki_themes_github-dark-default__mjs|shiki_langs_(?:bash|css|html|javascript|json|markdown|rust|tsx|typescript)__mjs|@shikijs_engine-javascript|@shikijs_themes_github-dark-default|@shikijs_langs_(?:bash|css|html|javascript|json|markdown|rust|tsx|typescript))\.js$/;

function requestKey(request: Request): string {
  return `${request.method()} ${request.resourceType()} ${request.url()}`;
}

async function installBeforePageJavaScript(page: Page, options: PageOptions = {}) {
  const opened: string[] = [];
  await page.exposeFunction('__piuiRecordExternalOpen', (canonicalUrl: string) => {
    opened.push(canonicalUrl);
  });
  await page.addInitScript(
    ({ markdown, assets, complete }) => {
      const browser = window as typeof window & {
        __PIUI_MARKDOWN_SCRIPT_EXECUTED__?: boolean;
        __PIUI_MARKDOWN_EVENT_EXECUTED__?: boolean;
        __PIUI_MARKDOWN_EVIDENCE__: BrowserEvidence;
        __PIUI_MARKDOWN_HARNESS__: {
          markdown?: string;
          assets?: HarnessAsset[];
          complete?: boolean;
          openExternal: (canonicalUrl: string) => void;
        };
        __TAURI_INTERNALS__: { invoke: (command: string) => Promise<never> };
        __piuiRecordExternalOpen: (canonicalUrl: string) => void;
      };
      const evidence: BrowserEvidence = {
        fetches: [],
        xhr: [],
        webSockets: [],
        eventSources: [],
        beacons: [],
        popups: [],
        history: [],
        navigationEvents: [],
        tauriInvokes: [],
        cspViolations: [],
      };
      browser.__PIUI_MARKDOWN_EVIDENCE__ = evidence;
      browser.__PIUI_MARKDOWN_SCRIPT_EXECUTED__ = false;
      browser.__PIUI_MARKDOWN_EVENT_EXECUTED__ = false;
      browser.__PIUI_MARKDOWN_HARNESS__ = {
        markdown: markdown ?? undefined,
        assets: assets ?? undefined,
        complete: complete ?? undefined,
        openExternal: (canonicalUrl) => browser.__piuiRecordExternalOpen(canonicalUrl),
      };
      browser.__TAURI_INTERNALS__ = {
        invoke: async (command: string) => {
          evidence.tauriInvokes.push(String(command));
          throw new Error('Tauri invoke is unavailable in the Markdown browser proof');
        },
      };

      const nativeFetch = window.fetch.bind(window);
      window.fetch = (input, init) => {
        evidence.fetches.push(String(input));
        return nativeFetch(input, init);
      };
      const nativeXhrOpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function instrumentedOpen(
        method: string,
        url: string | URL,
        async = true,
        username?: string | null,
        password?: string | null,
      ) {
        evidence.xhr.push(String(url));
        return nativeXhrOpen.call(this, method, url, async, username, password);
      };
      window.WebSocket = new Proxy(window.WebSocket, {
        construct(_target, argumentsList) {
          evidence.webSockets.push(String(argumentsList[0]));
          throw new Error('WebSocket blocked by Markdown test instrumentation');
        },
      });
      window.EventSource = new Proxy(window.EventSource, {
        construct(_target, argumentsList) {
          evidence.eventSources.push(String(argumentsList[0]));
          throw new Error('EventSource blocked by Markdown test instrumentation');
        },
      });
      Object.defineProperty(navigator, 'sendBeacon', {
        configurable: true,
        value: (url: string | URL) => {
          evidence.beacons.push(String(url));
          return false;
        },
      });
      window.open = (url) => {
        evidence.popups.push(String(url));
        return null;
      };
      const nativePushState = history.pushState.bind(history);
      const nativeReplaceState = history.replaceState.bind(history);
      history.pushState = (data, unused, url) => {
        evidence.history.push(`push:${String(url)}`);
        nativePushState(data, unused, url);
      };
      history.replaceState = (data, unused, url) => {
        evidence.history.push(`replace:${String(url)}`);
        nativeReplaceState(data, unused, url);
      };
      for (const eventName of ['beforeunload', 'hashchange', 'popstate']) {
        window.addEventListener(eventName, () => evidence.navigationEvents.push(eventName));
      }
      document.addEventListener('securitypolicyviolation', (event) => {
        evidence.cspViolations.push(`${event.effectiveDirective}:${event.blockedURI}`);
      });
    },
    {
      markdown: options.markdown ?? null,
      assets: options.assets ?? null,
      complete: options.complete ?? null,
    },
  );
  return opened;
}

function observeRequests(page: Page) {
  const attempts: string[] = [];
  const requests: Request[] = [];
  const outboundAttempts: string[] = [];
  page.on('request', (request) => {
    requests.push(request);
    attempts.push(requestKey(request));
  });
  return {
    attempts,
    requests,
    outboundAttempts,
    async route() {
      await page.route('**/*', async (route) => {
        const requestUrl = new URL(route.request().url());
        if (requestUrl.origin === applicationOrigin) {
          await route.continue();
        } else {
          outboundAttempts.push(requestKey(route.request()));
          await route.abort('blockedbyclient');
        }
      });
    },
  };
}

function requestInventory(attempts: readonly string[]): Map<string, number> {
  const inventory = new Map<string, number>();
  for (const attempt of attempts) inventory.set(attempt, (inventory.get(attempt) ?? 0) + 1);
  return inventory;
}

function sortedInventory(inventory: RequestInventory): [string, number][] {
  return [...inventory.entries()].sort(([left], [right]) => left.localeCompare(right));
}

function isAuditedBootstrapRequest(request: Request): boolean {
  if (request.method() !== 'GET') return false;
  const url = new URL(request.url());
  if (url.origin !== applicationOrigin || url.username || url.password || url.hash) return false;

  if (request.resourceType() === 'document') {
    return url.href === `${applicationOrigin}/?spike=markdown`;
  }
  if (request.resourceType() === 'stylesheet') {
    return AUDITED_STYLESHEET_PATHS.has(url.pathname) && url.search === '';
  }
  if (request.resourceType() !== 'script') return false;

  if (AUDITED_SOURCE_MODULE_PATHS.has(url.pathname)) {
    return url.search === '';
  }
  if (url.pathname === '/tests/fixtures/markdown/hostile.md') {
    return url.search === '?import&raw' || url.search === '?raw';
  }
  if (AUDITED_VITE_DEPENDENCY_PATH.test(url.pathname)) {
    return /^\?v=[a-f0-9]+$/.test(url.search);
  }
  return false;
}

function expectExactRequestInventory(
  observed: RequestObservation,
  highlighted = false,
  additionalAllowedUrls: readonly string[] = [],
) {
  const expected = new Map(highlighted ? bootstrapInventories.highlighted : bootstrapInventories.core);
  const allowedAssets = new Set(additionalAllowedUrls);
  for (const url of additionalAllowedUrls) {
    const key = `GET image ${url}`;
    expected.set(key, (expected.get(key) ?? 0) + 1);
  }

  expect(observed.outboundAttempts).toEqual([]);
  expect(
    observed.attempts.filter((attempt) => {
      if (expected.has(attempt)) return false;
      const [, resourceType, ...urlParts] = attempt.split(' ');
      return resourceType !== 'image' || !allowedAssets.has(urlParts.join(' '));
    }),
    'every request must be independently policy-constrained before count comparison',
  ).toEqual([]);
  expect(sortedInventory(requestInventory(observed.attempts))).toEqual(sortedInventory(expected));
}

async function browserEvidence(page: Page): Promise<BrowserEvidence> {
  return page.evaluate(() => {
    return (window as typeof window & { __PIUI_MARKDOWN_EVIDENCE__: BrowserEvidence })
      .__PIUI_MARKDOWN_EVIDENCE__;
  });
}

async function observeAuditedBootstrap(
  browser: Browser,
  markdown: string,
  expectHighlight: boolean,
): Promise<RequestInventory> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await installBeforePageJavaScript(page, { markdown });
  const observed = observeRequests(page);
  await observed.route();
  await page.goto('/?spike=markdown');
  if (expectHighlight) await expect(page.locator('[data-highlight-status="tokens"]')).toBeVisible();
  await page.waitForLoadState('networkidle');
  expect(observed.outboundAttempts).toEqual([]);
  expect(
    observed.requests.filter((request) => !isAuditedBootstrapRequest(request)).map(requestKey),
    'bootstrap observations may only populate the independently constrained local module policy',
  ).toEqual([]);
  const evidence = await browserEvidence(page);
  expect({
    fetches: evidence.fetches,
    xhr: evidence.xhr,
    webSockets: evidence.webSockets,
    eventSources: evidence.eventSources,
    beacons: evidence.beacons,
  }).toEqual({ fetches: [], xhr: [], webSockets: [], eventSources: [], beacons: [] });
  const inventory = requestInventory(observed.attempts);
  expect(inventory.get(`GET document ${applicationOrigin}/?spike=markdown`)).toBe(1);
  await context.close();
  return inventory;
}

async function createBootstrapInventories(browser: Browser): Promise<BootstrapInventories> {
  const core = await observeAuditedBootstrap(browser, 'Bootstrap prose.', false);
  const highlighted = await observeAuditedBootstrap(
    browser,
    '```typescript\nconst bootstrap: number = 1\n```',
    true,
  );
  expect([...highlighted.keys()].some((attempt) => /shiki|@shikijs/.test(attempt))).toBe(true);
  for (const [attempt, count] of core) expect(highlighted.get(attempt)).toBe(count);
  return Object.freeze({ core, highlighted });
}

async function registerAsset(
  request: APIRequestContext,
  body: Record<string, unknown> = {},
) {
  return request.post(MARKDOWN_ASSET_REGISTER_PATH, {
    headers: {
      'Content-Type': 'application/json',
      'X-PIUI-Markdown-Proof': 'register',
    },
    data: {
      fixture: 'safe-local',
      mime: 'image/png',
      scope: MARKDOWN_ASSET_SCOPE,
      ttlMs: 10_000,
      ...body,
    },
  });
}

test.describe('hostile Markdown containment', () => {
  test.beforeAll(async ({ browser }) => {
    bootstrapInventories = await createBootstrapInventories(browser);
  });

  test('ships exact narrow Vite and Tauri CSP plus unchanged capabilities', async ({ page }) => {
    await installBeforePageJavaScript(page);
    const response = await page.goto('/?spike=markdown');
    const common = [
      "default-src 'none'",
      "script-src 'self'",
      "script-src-attr 'none'",
      "style-src 'self'",
      "style-src-attr 'none'",
      "img-src 'self'",
      "font-src 'self'",
    ];
    const tail = [
      "object-src 'none'",
      "frame-src 'none'",
      "child-src 'none'",
      "worker-src 'none'",
      "media-src 'none'",
      "manifest-src 'none'",
      "base-uri 'none'",
      "form-action 'none'",
      "frame-ancestors 'none'",
    ];
    expect(response?.headers()['content-security-policy']).toBe(
      [...common, "connect-src 'none'", ...tail].join('; '),
    );

    const tauriConfig = JSON.parse(
      readFileSync(resolve(projectRoot, 'src-tauri/tauri.conf.json'), 'utf8'),
    ) as { app: { withGlobalTauri: boolean; security: { csp: string } } };
    const capability = JSON.parse(
      readFileSync(resolve(projectRoot, 'src-tauri/capabilities/default.json'), 'utf8'),
    ) as { permissions: string[] };
    expect(tauriConfig.app.withGlobalTauri).toBe(false);
    const tauriCommon = common.map((directive) =>
      directive === "img-src 'self'" ? "img-src 'self' piui-raster:" : directive,
    );
    expect(tauriConfig.app.security.csp).toBe(
      [...tauriCommon, 'connect-src ipc: http://ipc.localhost', ...tail].join('; '),
    );
    expect(capability.permissions).toEqual(['core:default']);
    expect(JSON.stringify(capability)).not.toMatch(/shell|opener|filesystem|fs:|http:/i);
  });

  test('renders hostile HTML as visible inert evidence with no extra request attempt or authority', async ({ page }) => {
    const opened = await installBeforePageJavaScript(page);
    const observed = observeRequests(page);
    await observed.route();
    const mainNavigations: string[] = [];
    const pageErrors: string[] = [];
    const popups: Page[] = [];
    const downloads: string[] = [];
    page.on('framenavigated', (frame) => {
      if (frame === page.mainFrame()) mainNavigations.push(frame.url());
    });
    page.on('pageerror', (error) => pageErrors.push(error.message));
    page.on('popup', (popup) => popups.push(popup));
    page.on('download', (download) => downloads.push(download.suggestedFilename()));

    await page.setViewportSize({ width: 680, height: 560 });
    await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
    await page.goto('/?spike=markdown');
    await page.waitForLoadState('networkidle');
    const message = page.getByRole('region', { name: 'Contained Markdown message' });
    const audit = message.getByRole('region', { name: 'Inert raw Markdown source' });
    await expect(audit).toBeVisible();
    await expect(audit).toContainText('<script>window.__PIUI_MARKDOWN_SCRIPT_EXECUTED__');
    await expect(audit).toContainText('rel="preload"');
    await expect(message.getByText('JavaScript blocked', { exact: true })).toBeVisible();
    await expect(message.getByText('Unknown opaque image', { exact: true })).toBeVisible();
    await expect(message.locator('table')).toBeVisible();
    await expect(message.locator('.markdown__table-scroll')).not.toHaveAttribute('tabindex');
    await expect(message.locator('del')).toContainText('Strikethrough');
    await expect(message.getByRole('checkbox')).toHaveCount(2);
    for (const checkbox of await message.getByRole('checkbox').all()) {
      await expect(checkbox).toBeDisabled();
    }

    expect(
      await message.locator('script, iframe, object, embed, base, meta, form, style, link, svg, math, picture').count(),
    ).toBe(0);
    expect(await message.locator('img, source, video, audio').count()).toBe(0);
    const activeAttributes = await message.evaluate((root) => {
      const blocked = new Set(['href', 'src', 'srcset', 'style', 'download', 'formaction', 'poster', 'ping']);
      return Array.from(root.querySelectorAll('*')).flatMap((element) =>
        element
          .getAttributeNames()
          .filter((name) => blocked.has(name.toLowerCase()) || name.toLowerCase().startsWith('on'))
          .map((name) => `${element.tagName.toLowerCase()}:${name}`),
      );
    });
    expect(activeAttributes).toEqual([]);

    const safeButton = message.getByRole('button', { name: 'Safe documentation' });
    const descriptionId = await safeButton.getAttribute('aria-describedby');
    expect(descriptionId).toMatch(/^external-destination-/);
    await expect(message.locator(`#${descriptionId}`)).toContainText(
      'HTTPS destination: https://safe.example.invalid/guide?q=visible · opens in your browser',
    );
    await safeButton.focus();
    await expect(safeButton).toBeFocused();
    expect(opened).toEqual([]);

    await expect(message.locator('[data-highlight-status="tokens"]').first()).toBeVisible();
    expect(await message.locator('pre script, pre img').count()).toBe(0);
    expect(await message.locator('[class^="tok-"]').count()).toBeGreaterThan(0);

    const darkBackground = await message.evaluate((element) => getComputedStyle(element).backgroundColor);
    await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' });
    const lightBackground = await message.evaluate((element) => getComputedStyle(element).backgroundColor);
    expect(darkBackground).not.toBe(lightBackground);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

    expect(await browserEvidence(page)).toEqual({
      fetches: [], xhr: [], webSockets: [], eventSources: [], beacons: [], popups: [], history: [],
      navigationEvents: [], tauriInvokes: [], cspViolations: [],
    });
    expect(
      await page.evaluate(() => ({
        script: (window as typeof window & { __PIUI_MARKDOWN_SCRIPT_EXECUTED__?: boolean })
          .__PIUI_MARKDOWN_SCRIPT_EXECUTED__,
        event: (window as typeof window & { __PIUI_MARKDOWN_EVENT_EXECUTED__?: boolean })
          .__PIUI_MARKDOWN_EVENT_EXECUTED__,
      })),
    ).toEqual({ script: false, event: false });
    expectExactRequestInventory(observed, true);
    expect(mainNavigations).toEqual([`${applicationOrigin}/?spike=markdown`]);
    expect(pageErrors).toEqual([]);
    expect(popups).toEqual([]);
    expect(downloads).toEqual([]);
  });

  test('audits isolated ordinary, custom, CDATA and late raw input without mounting a sink', async ({ page }) => {
    const markdown = [
      '<a href="/synthetic/private/raw-anchor-canary">isolated anchor</a>',
      '<div onclick="window.hostile=true">isolated division</div>',
      '<picture><source srcset="/synthetic/private/source-canary.png"></picture>',
      '<custom-element data-canary="/synthetic/private/custom-canary">custom</custom-element>',
      '<![CDATA[<img src="/synthetic/private/early-cdata-canary.png">]]>',
      `${'late audit filler '.repeat(600)}<late-element onclick="window.hostile=true">late marker</late-element>`,
      `${'late CDATA filler '.repeat(600)}<![CDATA[<img src="/synthetic/private/late-cdata-canary.png">]]>`,
    ].join('\n\n');
    await installBeforePageJavaScript(page, { markdown });
    const observed = observeRequests(page);
    await observed.route();
    await page.goto('/?spike=markdown');

    const audit = page.getByRole('region', { name: 'Inert raw Markdown source' });
    await expect(audit).toBeVisible();
    for (const excerpt of [
      '<a href=',
      '<div onclick=',
      '<picture>',
      '<source srcset=',
      '<custom-element',
      '<![CDATA[<img src="/synthetic/private/early-cdata-canary.png">]]>',
      '<late-element',
      '<![CDATA[<img src="/synthetic/private/late-cdata-canary.png">]]>',
    ]) {
      await expect(audit).toContainText(excerpt);
    }
    expect(await page.locator('.markdown__prose a, .markdown__prose div, .markdown__prose picture, .markdown__prose source, .markdown__prose custom-element, .markdown__prose late-element, .markdown__prose img').count()).toBe(0);
    expectExactRequestInventory(observed);
  });

  test('routes only a trusted explicit gesture and exposes a stable canonical description', async ({ page }) => {
    const opened = await installBeforePageJavaScript(page, {
      markdown: [
        '[**Approved** guide](https://SAFE.example.invalid:443/guide?q=visible)',
        '[JavaScript attempt](javascript:alert(1))',
        '[HTTP attempt](http://cleartext.example.invalid/)',
        '[Relative attempt](/synthetic/private/canary)',
      ].join('\n\n'),
    });
    const observed = observeRequests(page);
    await observed.route();
    await page.goto('/?spike=markdown');

    const approved = page.getByRole('button', { name: 'Approved guide' });
    const descriptionId = await approved.getAttribute('aria-describedby');
    await expect(page.locator(`#${descriptionId}`)).toContainText(
      'https://safe.example.invalid/guide?q=visible',
    );
    await approved.evaluate((element) => (element as HTMLButtonElement).click());
    expect(opened).toEqual([]);
    await approved.click();
    await approved.focus();
    await page.keyboard.press('Enter');
    expect(opened).toEqual([
      'https://safe.example.invalid/guide?q=visible',
      'https://safe.example.invalid/guide?q=visible',
    ]);
    expect((await browserEvidence(page)).tauriInvokes).toEqual([]);
    expectExactRequestInventory(observed);
    expect(page.url()).toBe(`${applicationOrigin}/?spike=markdown`);
  });

  test('serves exactly one host-registered raster, then rejects replay and hostile registry inputs', async ({ page, request }) => {
    const registrationResponse = await registerAsset(request);
    expect(registrationResponse.status()).toBe(201);
    const registered = await registrationResponse.json() as RegisteredAsset;
    expect(registered.capability).toMatch(/^piui-asset-[0-9a-f]{32}$/);
    expect(registered.descriptor.byteLength).toBe(68);
    expect((await request.get(`${registered.descriptor.url}?substituted=1`)).status()).toBe(404);

    await installBeforePageJavaScript(page, {
      markdown: [
        `![Registered local preview](${registered.capability})`,
        '![Unknown capability](piui-asset-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)',
        '![Direct private path](/synthetic/private/image-canary.png)',
        `![Substituted raw URL](${registered.descriptor.url})`,
      ].join('\n\n'),
      assets: [{ capability: registered.capability, ...registered.descriptor }],
    });
    const observed = observeRequests(page);
    await observed.route();
    const assetResponse = page.waitForResponse(registered.descriptor.url);
    await page.goto('/?spike=markdown');
    const response = await assetResponse;
    expect(response.status()).toBe(200);
    expect(response.headers()['content-type']).toBe('image/png');
    expect(response.headers()['cache-control']).toBe('no-store, max-age=0');
    expect(response.headers()['x-content-type-options']).toBe('nosniff');
    await expect(page.getByRole('img', { name: 'Registered local preview' })).toBeVisible();
    expect(await page.locator('.markdown__prose img').count()).toBe(1);
    expect(observed.attempts.filter((attempt) => attempt.endsWith(registered.descriptor.url))).toEqual([
      `GET image ${registered.descriptor.url}`,
    ]);
    expectExactRequestInventory(observed, false, [registered.descriptor.url]);

    expect((await request.get(registered.descriptor.url)).status()).toBe(404);
    expect((await request.get(`${registered.descriptor.url}.substituted`)).status()).toBe(404);
    expect(
      (await request.get(`${applicationOrigin}/__piui_markdown_asset__/ffffffffffffffffffffffffffffffff.png`)).status(),
    ).toBe(404);
    expect((await registerAsset(request, { mime: 'image/svg+xml' })).status()).toBe(400);
    expect((await registerAsset(request, { fixture: 'oversized' })).status()).toBe(400);
  });

  test('rejects expired, invalid-MIME, oversized and substituted descriptors before lazy fetch', async ({ page, request }) => {
    const registrationResponse = await registerAsset(request, { ttlMs: 1 });
    const registered = await registrationResponse.json() as RegisteredAsset;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 10));
    const invalidMimeCapability = 'piui-asset-11111111111111111111111111111111';
    const oversizedCapability = 'piui-asset-22222222222222222222222222222222';
    const substitutedCapability = 'piui-asset-33333333333333333333333333333333';
    await installBeforePageJavaScript(page, {
      markdown: [
        `![Expired local preview](${registered.capability})`,
        `![Invalid MIME preview](${invalidMimeCapability})`,
        `![Oversized preview](${oversizedCapability})`,
        `![Substituted preview](${substitutedCapability})`,
      ].join('\n\n'),
      assets: [
        { capability: registered.capability, ...registered.descriptor },
        {
          capability: invalidMimeCapability,
          url: `${applicationOrigin}/__piui_markdown_asset__/11111111111111111111111111111111.webp`,
          mime: 'image/svg+xml',
          byteLength: 68,
          expiresAt: Date.now() + 10_000,
        },
        {
          capability: oversizedCapability,
          url: `${applicationOrigin}/__piui_markdown_asset__/22222222222222222222222222222222.png`,
          mime: 'image/png',
          byteLength: 10 * 1_048_576 + 1,
          expiresAt: Date.now() + 10_000,
        },
        {
          capability: substitutedCapability,
          url: `${applicationOrigin}/synthetic/private/substituted.png`,
          mime: 'image/png',
          byteLength: 68,
          expiresAt: Date.now() + 10_000,
        },
      ],
    });
    const observed = observeRequests(page);
    await observed.route();
    await page.goto('/?spike=markdown');
    await expect(page.getByText('Expired local preview')).toBeVisible();
    await expect(page.getByText('Invalid MIME preview')).toBeVisible();
    await expect(page.getByText('Oversized preview')).toBeVisible();
    await expect(page.getByText('Substituted preview')).toBeVisible();
    expect(await page.locator('.markdown__prose img').count()).toBe(0);
    expect(observed.attempts.some((attempt) => attempt.includes(registered.descriptor.url))).toBe(false);
    expectExactRequestInventory(observed);
    expect((await request.get(registered.descriptor.url)).status()).toBe(404);
  });

  test('loads Shiki only after a completed allow-listed block mounts and keeps token text inert', async ({ page }) => {
    await installBeforePageJavaScript(page, {
      markdown: [
        'Inline `const inline = true`.',
        '```unknown\nconst unknown = true\n```',
        '```tsx\nconst payload = "</span><script>window.hostile=true</script>"\n```',
      ].join('\n\n'),
      complete: true,
    });
    const observed = observeRequests(page);
    await observed.route();
    await page.goto('/?spike=markdown');
    const highlighted = page.locator('[data-highlight-status="tokens"]');
    await expect(highlighted).toBeVisible();
    await expect(highlighted).toContainText('</span><script>window.hostile=true</script>');
    expect(await page.locator('.markdown__prose script').count()).toBe(0);
    await expect(page.locator('[data-language="plain"]')).toHaveAttribute('data-highlight-status', 'plain');
    expectExactRequestInventory(observed, true);
  });

  test('falls back to plain code when the lazy Shiki import fails', async ({ page }) => {
    await installBeforePageJavaScript(page, {
      markdown: '```typescript\nconst safe = true\n```',
    });
    await page.route('**/*', async (route) => {
      if (/shiki_core/.test(route.request().url())) await route.abort('failed');
      else await route.continue();
    });
    await page.goto('/?spike=markdown');
    await expect(page.getByText('Plain code: syntax highlighting was unavailable.')).toBeVisible();
    await expect(page.locator('[data-highlight-status="plain"]')).toContainText('const safe = true');
    expect(await page.locator('[data-highlight-status="tokens"]').count()).toBe(0);
  });

  test('does no Shiki module work for inline, unknown or incomplete code', async ({ page }) => {
    await installBeforePageJavaScript(page, {
      markdown: 'Inline `const inline = true`.\n\n```unknown\nplain\n```\n\n```ts\nincomplete\n```',
      complete: false,
    });
    const observed = observeRequests(page);
    await observed.route();
    await page.goto('/?spike=markdown');
    await page.waitForLoadState('networkidle');
    expect(await page.locator('[data-highlight-status="tokens"]').count()).toBe(0);
    expect(observed.attempts.some((attempt) => /shiki\/dist|@shikijs|shiki_core/.test(attempt))).toBe(false);
    expectExactRequestInventory(observed);
  });

  test('remeasures conditional code focus when delayed highlighting changes overflow', async ({ page }) => {
    await page.setViewportSize({ width: 1_400, height: 560 });
    await installBeforePageJavaScript(page, {
      markdown: `\`\`\`typescript\n${'const '.repeat(15)}\n\`\`\``,
    });
    const observed = observeRequests(page);
    await observed.route();
    let releaseHighlight = () => {};
    const highlightGate = new Promise<void>((resolveGate) => {
      releaseHighlight = resolveGate;
    });
    await page.route(/shiki_core/, async (route) => {
      await highlightGate;
      await route.continue();
    });
    await page.goto('/?spike=markdown');

    const codeBlock = page.locator('.markdown__code-block');
    await expect(page.locator('[data-highlight-status="plain"]')).toBeVisible();
    let plainDimensions = await codeBlock.evaluate((element) => ({
      clientWidth: element.clientWidth,
      scrollWidth: element.scrollWidth,
    }));
    expect(plainDimensions.scrollWidth).toBeLessThanOrEqual(plainDimensions.clientWidth);
    let currentViewport = page.viewportSize();
    if (!currentViewport) throw new Error('Markdown overflow proof requires a viewport');
    for (let attempt = 0; attempt < 60 && plainDimensions.scrollWidth <= plainDimensions.clientWidth; attempt += 1) {
      currentViewport = { width: currentViewport.width - 20, height: currentViewport.height };
      await page.setViewportSize(currentViewport);
      plainDimensions = await codeBlock.evaluate((element) => ({
        clientWidth: element.clientWidth,
        scrollWidth: element.scrollWidth,
      }));
    }
    expect(plainDimensions.scrollWidth).toBeGreaterThan(plainDimensions.clientWidth);
    await page.setViewportSize({
      width: currentViewport.width + plainDimensions.scrollWidth + 1 - plainDimensions.clientWidth,
      height: currentViewport.height,
    });
    await expect.poll(() => codeBlock.evaluate((element) => element.clientWidth))
      .toBe(plainDimensions.scrollWidth + 1);
    expect(await codeBlock.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
    await expect(codeBlock).not.toHaveAttribute('tabindex');

    releaseHighlight();
    await expect(page.locator('[data-highlight-status="tokens"]')).toBeVisible();
    await page.locator('.markdown__token-line').evaluate((line) => {
      line.append(document.createTextNode(' highlighted-overflow-transition'));
    });
    await expect.poll(() => codeBlock.evaluate((element) => element.scrollWidth > element.clientWidth))
      .toBe(true);
    await expect(codeBlock).toHaveAttribute('tabindex', '0');
    await expect(codeBlock).toHaveAttribute('role', 'region');
    expectExactRequestInventory(observed, true);
  });

  test('focuses only actual code/table overflow and supports fallback keyboard scrolling', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 560 });
    await installBeforePageJavaScript(page, {
      markdown: [
        '```text\nshort\n```',
        '| Short | Table |\n| - | - |\n| A | B |',
        `\`\`\`text\n${'long-code-'.repeat(200)}\n\`\`\``,
        `| Long | Table |\n| - | - |\n| ${'wide'.repeat(200)} | value |`,
      ].join('\n\n'),
    });
    await page.goto('/?spike=markdown');
    const codeBlocks = page.locator('.markdown__code-block');
    await expect(codeBlocks).toHaveCount(2);
    await expect(codeBlocks.nth(0)).not.toHaveAttribute('tabindex');
    await expect(codeBlocks.nth(1)).toHaveAttribute('tabindex', '0');
    const tables = page.locator('.markdown__table-scroll');
    await expect(tables).toHaveCount(2);
    await expect(tables.nth(0)).toHaveAttribute('tabindex', '0');
    await expect(tables.nth(1)).toHaveAttribute('tabindex', '0');

    const fallbackPage = await page.context().newPage();
    await installBeforePageJavaScript(fallbackPage, { markdown: '*'.repeat(100_000) });
    await fallbackPage.goto('/?spike=markdown');
    const fallback = fallbackPage.getByRole('region', { name: 'Plain text safety preview' });
    await expect(fallback).toHaveAttribute('tabindex', '0');
    await fallback.focus();
    expect(await fallback.evaluate((element) => element.scrollWidth > element.clientWidth)).toBe(true);
    for (let index = 0; index < 8; index += 1) await fallbackPage.keyboard.press('ArrowRight');
    expect(await fallback.evaluate((element) => element.scrollLeft)).toBeGreaterThan(0);
    await fallbackPage.close();
  });
});
