import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import {
  A26_EXPECTED_NATIVE_EVIDENCE,
  A26_HOSTILE_FIXTURE_CANARIES,
  A26_HOSTILE_FIXTURE_SHA256,
  A26_MODULE_KINDS,
  A26_NATIVE_EVIDENCE_KEYS,
  A26_RASTER_FIXTURE_SHA256,
  a26ResourceAllowlistSha256,
  assertA26BrowserEvidence,
  assertA26BundleEvidence,
  assertA26DomEvidence,
  assertA26FrontendInventory,
  assertA26ResourceAllowlist,
  assertAuthoritativeMarkdownEvidence,
  classifyA26ResourceEntries,
  createA26ObserveScript,
  deriveA26FrontendInventory,
  parseA26ModuleProvenance,
  parseAuthoritativeMarkdownEvidence,
  parseNativeMarkdownEvidence,
  parsePackagedMarkdownEvidence,
} from '../../scripts/run-packaged-markdown-probe.mjs';

const sha = (character: string) => character.repeat(64);

function line(value: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
}

function browserEvidence() {
  return {
    schemaVersion: 1,
    networkApiAttempts: 0,
    navigationApiAttempts: 0,
    popupAttempts: 0,
    cspViolations: 0,
    wasmApiAttempts: 0,
    runtimeErrors: 0,
    unhandledRejections: 0,
    disclosedExternalOpens: 0,
    duplicateResourceEntries: 0,
    missingResourceEntries: 0,
    unexpectedResourceEntries: 0,
    hostileSameOriginResourceEntries: 0,
    rasterResourceEntries: 1,
    resourceAllowlistEntries: 17,
    observedResourceEntries: 17,
    observedResourceSha256: sha('c'),
    locationUnchanged: true,
    scriptCanaryExecuted: false,
    eventCanaryExecuted: false,
    loadingIndicatorPresented: true,
    codeLoadingIndicatorPresented: true,
  };
}

function domEvidence() {
  return {
    schemaVersion: 1,
    probeReady: true,
    rawAuditRegions: 1,
    unsafeActiveElements: 0,
    unsafeActiveAttributes: 0,
    rasterImages: 1,
    loadedRasterImages: 1,
    rasterSourcesExact: true,
    highlightedBlocks: 2,
    highlightTokenNodes: 12,
    plainCodeBlocks: 3,
    languageFallbacks: 1,
    renderBudgetFallbacks: 1,
    workBudgetFallbacks: 1,
    fallbackSourceTextExact: true,
    omittedAssets: 19,
    blockedLinks: 31,
    externalLinkButtons: 3,
    engine: 'javascript-regex',
    wasmModules: 0,
    hostileFixtureSha256: A26_HOSTILE_FIXTURE_SHA256,
    rasterFixtureSha256: A26_RASTER_FIXTURE_SHA256,
  };
}

function frontendInventory(
  inventoryCharacter: string,
  allowlistCharacter: string,
  provenanceCharacter: string,
  role: 'automation' | 'production',
) {
  return {
    fileCount: 18,
    // Only the flagged probe build carries the pinned hostile fixture.
    hostileFixtureChunks: role === 'automation' ? 1 : 0,
    hostileFixtureSha256: role === 'automation' ? A26_HOSTILE_FIXTURE_SHA256 : null,
    inventorySha256: sha(inventoryCharacter),
    javascriptRegexEngineChunks: 1,
    moduleProvenanceSha256: sha(provenanceCharacter),
    onigurumaEngineChunks: 0,
    resourceAllowlistEntries: 17,
    resourceAllowlistSha256: sha(allowlistCharacter),
    wasmFiles: 0,
    wasmMagicFrontendFiles: 0,
    wasmPayloadReferences: 0,
  };
}

function bundleEvidence() {
  const automationFrontend = frontendInventory('b', 'c', 'f', 'automation');
  return {
    productionWebdriverIncluded: false,
    automationWebdriverIncluded: true,
    cspExact: true,
    piuiRasterOnlyImageAddition: true,
    productionFrontend: frontendInventory('a', 'd', 'e', 'production'),
    automationFrontend,
    repeatAutomationFrontend: { ...automationFrontend },
  };
}

function canonicalReceiptJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'number'
    || typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalReceiptJson).join(',')}]`;
  if (!value || typeof value !== 'object') throw new Error('invalid receipt test value');
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => (
    `${JSON.stringify(key)}:${canonicalReceiptJson(record[key])}`
  )).join(',')}}`;
}

type ReceiptChunk = Readonly<{
  assets: readonly string[];
  css: readonly string[];
  dynamicImports: readonly string[];
  fileName: string;
  imports: readonly string[];
  isEntry: boolean;
  moduleKinds: readonly string[];
}>;

function moduleProvenanceBytes(
  chunks: readonly ReceiptChunk[],
  hostileFixtureSha256: string | null = chunks.some((chunk) => (
    chunk.moduleKinds.includes('a26-hostile-fixture')
  )) ? A26_HOSTILE_FIXTURE_SHA256 : null,
): Buffer {
  return Buffer.from(
    `${canonicalReceiptJson({ chunks, hostileFixtureSha256, schemaVersion: 1 })}\n`,
    'utf8',
  );
}

// A small flagged probe build by default; the production variant drops the fixture
// module and its bytes but keeps the shared highlighter.
function provenanceFixture(role: 'automation' | 'production' = 'automation') {
  const requiredKinds = A26_MODULE_KINDS.filter((kind) => (
    kind !== 'a26-engine-oniguruma'
    && kind !== 'a26-wasm-module'
    && (role === 'automation' || kind !== 'a26-hostile-fixture')
  ));
  const engineSource = role === 'automation'
    ? `export const regexEngine = true; export const fixture = "${A26_HOSTILE_FIXTURE_CANARIES.join(' ')}";`
    : 'export const regexEngine = true;';
  const frontend = [
    { path: 'assets/dormant.js', bytes: Buffer.from('export const dormant = true;') },
    { path: 'assets/engine.js', bytes: Buffer.from(engineSource) },
    { path: 'assets/main.js', bytes: Buffer.from('export const entry = true;') },
    {
      path: 'index.html',
      bytes: Buffer.from(
        '<!doctype html><script type="module" src="/assets/main.js"></script>',
      ),
    },
  ];
  const chunks: ReceiptChunk[] = [
    {
      assets: [],
      css: [],
      dynamicImports: [],
      fileName: 'assets/dormant.js',
      imports: [],
      isEntry: false,
      moduleKinds: [],
    },
    {
      assets: [],
      css: [],
      dynamicImports: [],
      fileName: 'assets/engine.js',
      imports: [],
      isEntry: false,
      moduleKinds: requiredKinds,
    },
    {
      assets: [],
      css: [],
      dynamicImports: ['assets/dormant.js', 'assets/engine.js'],
      fileName: 'assets/main.js',
      imports: [],
      isEntry: true,
      moduleKinds: [],
    },
  ];
  return { chunks, frontend, provenance: moduleProvenanceBytes(chunks) };
}

function authoritativeEvidence() {
  return {
    schemaVersion: 1,
    status: 'pass',
    identity: {
      sourceDigest: sha('1'),
      productionFingerprint: sha('2'),
      automationFingerprint: sha('3'),
      controlledDeltaSha256: sha('4'),
      sameFrozenSource: true,
    },
    driver: {
      productionHostileActivationListeners: 0,
      dormantTwinListeners: 0,
      activatedTwinIpv4LoopbackListeners: 1,
      activatedTwinOtherListeners: 0,
      legacyEnvPortListeners: 0,
      legacyWebdriverPortIgnored: true,
      randomHighPort: true,
      activationNonceValidated: true,
      webdriverSessions: 1,
    },
    bundle: bundleEvidence(),
    dom: domEvidence(),
    browser: browserEvidence(),
    native: A26_EXPECTED_NATIVE_EVIDENCE,
    cleanup: {
      webdriverSessionDeleted: true,
      listenerRemoved: true,
      runnerIsolatesRemoved: true,
      bundlesRevalidated: true,
    },
  };
}

describe('A.26 packaged hostile-Markdown contract', () => {
  it('accepts only the exact path-free native, browser, DOM and bundle evidence', () => {
    expect(A26_NATIVE_EVIDENCE_KEYS).toHaveLength(15);
    expect(parseNativeMarkdownEvidence(line(A26_EXPECTED_NATIVE_EVIDENCE)))
      .toEqual(A26_EXPECTED_NATIVE_EVIDENCE);
    expect(assertA26BrowserEvidence(browserEvidence())).toEqual(browserEvidence());
    expect(assertA26BrowserEvidence({ ...browserEvidence(), rasterResourceEntries: 0 }))
      .toEqual({ ...browserEvidence(), rasterResourceEntries: 0 });
    expect(assertA26DomEvidence(domEvidence())).toEqual(domEvidence());
    expect(assertA26FrontendInventory(bundleEvidence().productionFrontend, 'production'))
      .toEqual(bundleEvidence().productionFrontend);
    expect(assertA26FrontendInventory(bundleEvidence().automationFrontend, 'automation'))
      .toEqual(bundleEvidence().automationFrontend);
    expect(assertA26BundleEvidence(bundleEvidence())).toEqual(bundleEvidence());
    expect(JSON.stringify({
      native: A26_EXPECTED_NATIVE_EVIDENCE,
      browser: browserEvidence(),
      dom: domEvidence(),
      bundle: bundleEvidence(),
    })).not.toContain('/');
  });

  it('requires a clean engine inventory for production and both automation builds', () => {
    const valid = bundleEvidence();
    for (const candidate of [
      {
        ...valid,
        productionFrontend: { ...valid.productionFrontend, wasmFiles: 1 },
      },
      {
        ...valid,
        automationFrontend: { ...valid.automationFrontend, onigurumaEngineChunks: 1 },
      },
      {
        ...valid,
        repeatAutomationFrontend: {
          ...valid.repeatAutomationFrontend,
          javascriptRegexEngineChunks: 0,
        },
      },
      {
        ...valid,
        repeatAutomationFrontend: {
          ...valid.repeatAutomationFrontend,
          inventorySha256: sha('e'),
        },
      },
    ]) {
      expect(() => assertA26BundleEvidence(candidate))
        .toThrow('A.26 packaged Markdown probe rejected');
    }
  });

  it('requires production to carry no hostile fixture and the probe build the pinned one', () => {
    const valid = bundleEvidence();
    for (const candidate of [
      {
        ...valid,
        productionFrontend: { ...valid.productionFrontend, hostileFixtureChunks: 1 },
      },
      {
        ...valid,
        productionFrontend: {
          ...valid.productionFrontend,
          hostileFixtureSha256: A26_HOSTILE_FIXTURE_SHA256,
        },
      },
      {
        ...valid,
        automationFrontend: { ...valid.automationFrontend, hostileFixtureChunks: 0 },
      },
      {
        ...valid,
        automationFrontend: { ...valid.automationFrontend, hostileFixtureSha256: sha('9') },
        repeatAutomationFrontend: {
          ...valid.repeatAutomationFrontend,
          hostileFixtureSha256: sha('9'),
        },
      },
      {
        ...valid,
        repeatAutomationFrontend: {
          ...valid.repeatAutomationFrontend,
          hostileFixtureSha256: null,
        },
      },
    ]) {
      expect(() => assertA26BundleEvidence(candidate))
        .toThrow('A.26 packaged Markdown probe rejected');
    }
  });

  it('uses a package-derived exact resource allow-list and catches the hostile same-origin image', () => {
    const expectedResourcePaths = [
      '/assets/engine-javascript-a1.js',
      '/assets/index-b2.js',
    ];
    const expectedRasterUrl =
      'piui-raster://localhost/__piui_markdown_asset__/0123456789abcdef0123456789abcdef.png';
    const currentLocation = 'tauri://localhost/markdown-packaged';
    const allowedResources = expectedResourcePaths.map((path) => `tauri://localhost${path}`);
    expect(assertA26ResourceAllowlist(expectedResourcePaths)).toEqual(expectedResourcePaths);
    expect(a26ResourceAllowlistSha256(expectedResourcePaths)).toBe(
      createHash('sha256')
        .update(Buffer.from(`${JSON.stringify(expectedResourcePaths)}\n`, 'utf8'))
        .digest('hex'),
    );
    expect(classifyA26ResourceEntries({
      currentLocation,
      expectedRasterUrl,
      expectedResourcePaths,
      resourceNames: [
        ...allowedResources,
        expectedRasterUrl,
        'tauri://localhost/synthetic/private/image-canary.png',
      ],
    })).toEqual({
      duplicateResourceEntries: 0,
      hostileSameOriginResourceEntries: 1,
      missingResourceEntries: 0,
      observedResourcePaths: expectedResourcePaths,
      rasterResourceEntries: 1,
      resourceAllowlistEntries: 2,
      unexpectedResourceEntries: 1,
    });
    expect(classifyA26ResourceEntries({
      currentLocation,
      expectedRasterUrl,
      expectedResourcePaths,
      resourceNames: [...allowedResources, expectedRasterUrl],
    })).toEqual({
      duplicateResourceEntries: 0,
      hostileSameOriginResourceEntries: 0,
      missingResourceEntries: 0,
      observedResourcePaths: expectedResourcePaths,
      rasterResourceEntries: 1,
      resourceAllowlistEntries: 2,
      unexpectedResourceEntries: 0,
    });
    expect(classifyA26ResourceEntries({
      currentLocation,
      expectedRasterUrl,
      expectedResourcePaths,
      resourceNames: [allowedResources[1], expectedRasterUrl],
    })).toMatchObject({
      duplicateResourceEntries: 0,
      missingResourceEntries: 1,
      observedResourcePaths: [expectedResourcePaths[1]],
      unexpectedResourceEntries: 0,
    });
    expect(classifyA26ResourceEntries({
      currentLocation,
      expectedRasterUrl,
      expectedResourcePaths,
      resourceNames: [...allowedResources, allowedResources[1], expectedRasterUrl],
    })).toMatchObject({
      duplicateResourceEntries: 1,
      missingResourceEntries: 0,
      observedResourcePaths: expectedResourcePaths,
      unexpectedResourceEntries: 0,
    });
    expect(classifyA26ResourceEntries({
      currentLocation,
      expectedRasterUrl,
      expectedResourcePaths,
      resourceNames: [...allowedResources, 'tauri://localhost/assets/dormant.js'],
    })).toMatchObject({
      missingResourceEntries: 0,
      unexpectedResourceEntries: 1,
    });
    for (const malformed of [
      ['/index.html'],
      ['/assets/index-b2.js?cache=1'],
      [...expectedResourcePaths].reverse(),
    ]) {
      expect(() => assertA26ResourceAllowlist(malformed))
        .toThrow('A.26 packaged Markdown probe rejected');
    }
    const observeScript = createA26ObserveScript(expectedResourcePaths);
    expect(observeScript).toContain(JSON.stringify(expectedResourcePaths));
    expect(observeScript).toContain("performance.getEntriesByType('resource')");
    expect(observeScript).toContain("crypto.subtle.digest('SHA-256'");
    expect(observeScript).toContain('resourceObservation.observedResourcePaths');
    expect(observeScript).toContain('/synthetic/private/image-canary.png');
    expect(() => new Function(`return async function a26Observation() {${observeScript}}`))
      .not.toThrow();
  });

  it('derives the exact route closure from path-free provenance and rejects hidden engines or payloads', () => {
    const fixture = provenanceFixture();
    expect(parseA26ModuleProvenance(fixture.provenance).chunks).toHaveLength(3);
    const derived = deriveA26FrontendInventory(fixture.frontend, fixture.provenance, 'automation');
    expect(derived.expectedResourcePaths).toEqual([
      '/assets/engine.js',
      '/assets/main.js',
    ]);
    expect(derived.evidence.resourceAllowlistEntries).toBe(2);
    expect(derived.evidence.resourceAllowlistEntries).toBeLessThan(
      derived.evidence.fileCount - 1,
    );
    expect(derived.evidence.resourceAllowlistSha256).toBe(
      a26ResourceAllowlistSha256(derived.expectedResourcePaths),
    );

    const hiddenOniguruma = fixture.chunks.map((chunk) => (
      chunk.fileName === 'assets/dormant.js'
        ? { ...chunk, moduleKinds: ['a26-engine-oniguruma'] }
        : chunk
    ));
    expect(() => deriveA26FrontendInventory(
      fixture.frontend,
      moduleProvenanceBytes(hiddenOniguruma),
      'automation',
    )).toThrow('A.26 packaged Markdown probe rejected');

    for (const bytes of [
      Buffer.concat([Buffer.from('renamed payload: '), Buffer.from([0x00, 0x61, 0x73, 0x6d])]),
      Buffer.from('export const renamedPayload = "AGFzbQEAAAA";'),
      Buffer.from('export const renamedPayload = [0, 97, 115, 109];'),
    ]) {
      const frontend = fixture.frontend.map((file) => (
        file.path === 'assets/dormant.js' ? { ...file, bytes } : file
      ));
      expect(() => deriveA26FrontendInventory(frontend, fixture.provenance, 'automation'))
        .toThrow('A.26 packaged Markdown probe rejected');
    }

    const missingLanguage = fixture.chunks.map((chunk) => (
      chunk.fileName === 'assets/engine.js'
        ? { ...chunk, moduleKinds: chunk.moduleKinds.filter((kind) => kind !== 'a26-lang-rust') }
        : chunk
    ));
    expect(() => deriveA26FrontendInventory(
      fixture.frontend,
      moduleProvenanceBytes(missingLanguage),
      'automation',
    )).toThrow('A.26 packaged Markdown probe rejected');

    const nonCanonical = Buffer.from(
      fixture.provenance.toString('utf8').replace('{"chunks"', '{ "chunks"'),
      'utf8',
    );
    expect(() => parseA26ModuleProvenance(nonCanonical))
      .toThrow('A.26 packaged Markdown probe rejected');
    expect(() => deriveA26FrontendInventory(fixture.frontend, fixture.provenance, 'twin'))
      .toThrow('A.26 packaged Markdown probe rejected');
  });

  it('asserts the production bundle carries no hostile fixture module, digest or bytes', () => {
    const production = provenanceFixture('production');
    const derived = deriveA26FrontendInventory(
      production.frontend,
      production.provenance,
      'production',
    );
    expect(derived.evidence.hostileFixtureChunks).toBe(0);
    expect(derived.evidence.hostileFixtureSha256).toBeNull();
    expect(() => deriveA26FrontendInventory(
      production.frontend,
      production.provenance,
      'automation',
    )).toThrow('A.26 packaged Markdown probe rejected');

    const probe = provenanceFixture('automation');
    expect(() => deriveA26FrontendInventory(probe.frontend, probe.provenance, 'production'))
      .toThrow('A.26 packaged Markdown probe rejected');

    for (const canary of A26_HOSTILE_FIXTURE_CANARIES) {
      const leaked = production.frontend.map((file) => (
        file.path === 'assets/dormant.js'
          ? { ...file, bytes: Buffer.from(`export const leaked = "${canary}";`) }
          : file
      ));
      expect(() => deriveA26FrontendInventory(leaked, production.provenance, 'production'))
        .toThrow('A.26 packaged Markdown probe rejected');
    }

    // A receipt may not claim a digest without a fixture chunk, or hide one without it.
    expect(() => parseA26ModuleProvenance(
      moduleProvenanceBytes(production.chunks, A26_HOSTILE_FIXTURE_SHA256),
    )).toThrow('A.26 packaged Markdown probe rejected');
    expect(() => parseA26ModuleProvenance(moduleProvenanceBytes(probe.chunks, null)))
      .toThrow('A.26 packaged Markdown probe rejected');
  });

  it('binds the probe build to the pinned hostile fixture and keeps its bytes in fixture chunks', () => {
    const probe = provenanceFixture('automation');
    const derived = deriveA26FrontendInventory(probe.frontend, probe.provenance, 'automation');
    expect(derived.evidence.hostileFixtureChunks).toBe(1);
    expect(derived.evidence.hostileFixtureSha256).toBe(A26_HOSTILE_FIXTURE_SHA256);

    expect(() => deriveA26FrontendInventory(
      probe.frontend,
      moduleProvenanceBytes(probe.chunks, sha('9')),
      'automation',
    )).toThrow('A.26 packaged Markdown probe rejected');

    const withoutBytes = probe.frontend.map((file) => (
      file.path === 'assets/engine.js'
        ? { ...file, bytes: Buffer.from('export const regexEngine = true;') }
        : file
    ));
    expect(() => deriveA26FrontendInventory(withoutBytes, probe.provenance, 'automation'))
      .toThrow('A.26 packaged Markdown probe rejected');

    const strayBytes = probe.frontend.map((file) => (
      file.path === 'assets/dormant.js'
        ? { ...file, bytes: Buffer.from(`export const stray = "${A26_HOSTILE_FIXTURE_CANARIES[0]}";`) }
        : file
    ));
    expect(() => deriveA26FrontendInventory(strayBytes, probe.provenance, 'automation'))
      .toThrow('A.26 packaged Markdown probe rejected');
  });

  it('accepts statically imported module preloads but not a preloaded lazy route', () => {
    const probe = provenanceFixture('automation');
    const shared = { path: 'assets/shared.js', bytes: Buffer.from('export const shared = 1;') };
    const chunks: ReceiptChunk[] = [
      ...probe.chunks.map((chunk) => (
        chunk.fileName === 'assets/main.js' ? { ...chunk, imports: ['assets/shared.js'] } : chunk
      )),
      {
        assets: [],
        css: [],
        dynamicImports: [],
        fileName: 'assets/shared.js',
        imports: [],
        isEntry: false,
        moduleKinds: [],
      },
    ].sort((left, right) => (left.fileName < right.fileName ? -1 : 1));
    const index = (preload: string) => ({
      path: 'index.html',
      bytes: Buffer.from(
        '<!doctype html><script type="module" src="/assets/main.js"></script>'
          + `<link rel="modulepreload" href="/${preload}">`,
      ),
    });
    const frontend = (preload: string) => [
      ...probe.frontend.filter((file) => file.path !== 'index.html'),
      shared,
      index(preload),
    ].sort((left, right) => (left.path < right.path ? -1 : 1));

    const derived = deriveA26FrontendInventory(
      frontend('assets/shared.js'),
      moduleProvenanceBytes(chunks),
      'automation',
    );
    expect(derived.expectedResourcePaths).toContain('/assets/shared.js');
    expect(() => deriveA26FrontendInventory(
      frontend('assets/dormant.js'),
      moduleProvenanceBytes(chunks),
      'automation',
    )).toThrow('A.26 packaged Markdown probe rejected');
  });

  it('uses fixture-only canaries that never appear in application source', async () => {
    const fixture = await readFile(new URL('../fixtures/markdown/hostile.md', import.meta.url), 'utf8');
    for (const canary of A26_HOSTILE_FIXTURE_CANARIES) expect(fixture).toContain(canary);
    const sourceRoot = new URL('../../src/', import.meta.url);
    const entries = await readdir(sourceRoot, { recursive: true, withFileTypes: true });
    const sources = entries.filter((entry) => (
      entry.isFile()
      && /\.(?:tsx?|css)$/u.test(entry.name)
      && !/\.test\.tsx?$/u.test(entry.name)
    ));
    expect(sources.length).toBeGreaterThan(0);
    for (const entry of sources) {
      const source = await readFile(`${entry.parentPath}/${entry.name}`, 'utf8');
      for (const canary of A26_HOSTILE_FIXTURE_CANARIES) {
        expect(source, `${entry.name} must not contain ${canary}`).not.toContain(canary);
      }
    }
  });

  it('accepts the closed authoritative and post-cleanup reports and rejects substitutions', () => {
    const authoritative = authoritativeEvidence();
    expect(assertAuthoritativeMarkdownEvidence(authoritative)).toEqual(authoritative);
    expect(parseAuthoritativeMarkdownEvidence(line(authoritative))).toEqual(authoritative);
    const formal = { ...authoritative, generatedOutputsRemoved: true };
    expect(parsePackagedMarkdownEvidence(line(formal))).toEqual(formal);

    const malformed = [
      Buffer.alloc(0),
      Buffer.from([0xff, 0x0a]),
      Buffer.from(`${JSON.stringify(authoritative)}\r\n`, 'utf8'),
      Buffer.from(`${JSON.stringify(authoritative)}\n{}\n`, 'utf8'),
      line({ ...authoritative, workspacePath: '/private/project' }),
      line({ ...authoritative, status: 'partial' }),
      line({ ...authoritative, browser: { ...browserEvidence(), wasmApiAttempts: 1 } }),
      line({ ...authoritative, dom: { ...domEvidence(), rasterImages: 2 } }),
      line({ ...authoritative, native: { ...A26_EXPECTED_NATIVE_EVIDENCE, assetSuccessfulReads: 0 } }),
      line({ ...authoritative, driver: { ...authoritative.driver, dormantTwinListeners: 1 } }),
      line({
        ...authoritative,
        bundle: {
          ...bundleEvidence(),
          automationFrontend: {
            ...bundleEvidence().automationFrontend,
            wasmFiles: 1,
          },
        },
      }),
      Buffer.alloc(262_145, 0x20),
    ];
    for (const candidate of malformed) {
      expect(() => parseAuthoritativeMarkdownEvidence(candidate))
        .toThrow('A.26 packaged Markdown probe rejected');
    }
    expect(() => parsePackagedMarkdownEvidence(line({
      ...formal,
      generatedOutputsRemoved: false,
    }))).toThrow('A.26 packaged Markdown probe rejected');
  });

  it('binds the hard-coded native fixture digests to the audited source bytes', async () => {
    const [hostile, raster] = await Promise.all([
      readFile(new URL('../fixtures/markdown/hostile.md', import.meta.url)),
      readFile(new URL('../fixtures/markdown/safe-local.png', import.meta.url)),
    ]);
    expect(createHash('sha256').update(hostile).digest('hex')).toBe(A26_HOSTILE_FIXTURE_SHA256);
    expect(createHash('sha256').update(raster).digest('hex')).toBe(A26_RASTER_FIXTURE_SHA256);
    expect(A26_EXPECTED_NATIVE_EVIDENCE.hostileFixtureSha256).toBe(A26_HOSTILE_FIXTURE_SHA256);
    expect(A26_EXPECTED_NATIVE_EVIDENCE.rasterFixtureSha256).toBe(A26_RASTER_FIXTURE_SHA256);
  });

  it('keeps the browser observer bounded, payload-free and independent of direct-eval endpoints', async () => {
    const source = await readFile(
      new URL('../../scripts/run-packaged-markdown-probe.mjs', import.meta.url),
      'utf8',
    );
    expect(source).toContain("capabilities: { alwaysMatch: {}, firstMatch: [{}] }");
    expect(source).toContain("internals.invoke('a26_markdown_evidence')");
    expect(source).toContain("document.querySelector('[data-a26-probe-state]')");
    expect(source).toContain("raster.scrollIntoView({ block: 'center', inline: 'nearest' })");
    expect(source).not.toContain('/wdio/eval');
    expect(source).not.toContain('wdio:');
    expect(source).not.toContain('markdown:');
    expect(source).not.toContain('assetBytes');
    expect(source).not.toContain('response.arrayBuffer()');
    expect(source).toContain('total > HTTP_RESPONSE_LIMIT');
    expect(source).toContain('await reader.cancel()');
  });

  it('keeps the architecture route and native command surface fixed and visibly busy', async () => {
    const [index, route, prelude, command] = await Promise.all([
      readFile(new URL('../../index.html', import.meta.url), 'utf8'),
      readFile(new URL('../../src/architecture-gate/MarkdownProbe.tsx', import.meta.url), 'utf8'),
      readFile(new URL('../../src/architecture-gate/a26MarkdownPrelude.ts', import.meta.url), 'utf8'),
      readFile(new URL('../../src-tauri/src/commands/a26_markdown.rs', import.meta.url), 'utf8'),
    ]);
    const preludeIndex = index.indexOf('/src/architecture-gate/a26MarkdownPrelude.ts');
    const applicationIndex = index.indexOf('/src/main.tsx');
    expect(preludeIndex).toBeGreaterThan(-1);
    expect(applicationIndex).toBeGreaterThan(preludeIndex);
    expect(route).toContain("invoke<unknown>('a26_markdown_prepare')");
    expect(route).toContain("import('../../tests/fixtures/markdown/hostile.md?raw')");
    expect(route).toContain('aria-busy={state.phase !== \'ready\'}');
    expect(route).toContain('markdown-probe__spinner');
    expect(prelude).toContain("import.meta.env.VITE_PIUI_A26_MARKDOWN_TEST === '1'");
    expect(prelude).toContain('let begun = false;');
    expect(prelude).toContain('const preBeginCounters = blankCounters();');
    expect(prelude).toContain('else if (!begun) preBeginCounters[key] += 1;');
    expect(prelude).toContain('counters = { ...preBeginCounters };');
    const beginSource = prelude.slice(
      prelude.indexOf('begin(rasterUrl: string)'),
      prelude.indexOf('recordDisclosedExternalOpen()'),
    );
    expect(beginSource).not.toContain('loadingIndicatorPresented = false;');
    expect(prelude).toContain('WebAssembly.Module = new Proxy');
    expect(prelude).toContain('WebAssembly.Instance = new Proxy');
    expect(prelude).toContain('WebAssembly.Memory = new Proxy');
    expect(prelude).toContain('WebAssembly.Table = new Proxy');
    expect(prelude).toContain('WebAssembly.Global = new Proxy');
    expect(command).toContain('pub fn a26_markdown_prepare(');
    expect(command).toContain('pub fn a26_markdown_evidence(');
    expect(command).toContain('pub fn record_invoke_entry(');
    expect(command).toContain('tauri::ipc::InvokeBody::Json(serde_json::Value::Object(arguments))');
    expect(command).toContain('if arguments.is_empty()');
    expect(command).toContain('tauri::ipc::InvokeBody::Raw(Vec::new())');
    expect(command).toContain('include_str!("../../../tests/fixtures/markdown/hostile.md")');
    expect(command).toContain('include_bytes!("../../../tests/fixtures/markdown/safe-local.png")');
    expect(command).not.toContain('markdown: String');
    expect(command).not.toContain('bytes: Vec');
  });

  it('integrates the feature-only driver, exact custom protocol and packaged command', async () => {
    const [cargo, commands, native, app, config, packageJson, packageRunner, viteConfig]
      = await Promise.all([
      readFile(new URL('../../src-tauri/Cargo.toml', import.meta.url), 'utf8'),
      readFile(new URL('../../src-tauri/src/commands/mod.rs', import.meta.url), 'utf8'),
      readFile(new URL('../../src-tauri/src/lib.rs', import.meta.url), 'utf8'),
      readFile(new URL('../../src/App.tsx', import.meta.url), 'utf8'),
      readFile(new URL('../../src-tauri/tauri.conf.json', import.meta.url), 'utf8'),
      readFile(new URL('../../package.json', import.meta.url), 'utf8'),
      readFile(new URL('../../scripts/package-spike.mjs', import.meta.url), 'utf8'),
      readFile(new URL('../../vite.config.ts', import.meta.url), 'utf8'),
    ]);
    expect(cargo).toMatch(/architecture-test\s*=\s*\["dep:tauri-plugin-wdio-webdriver"\]/);
    expect(cargo).toContain('tauri-plugin-wdio-webdriver');
    expect(commands).toContain('#[cfg(feature = "architecture-test")]');
    expect(commands).toContain('pub mod a26_markdown;');
    expect(native).toContain('PIUI_ARCHITECTURE_TEST_MODE');
    expect(native).toContain('PIUI_ARCHITECTURE_TEST_NONCE');
    expect(native).toContain('PIUI_ARCHITECTURE_TEST_PORT');
    expect(native).toContain('tauri_plugin_wdio_webdriver::init_with_port(port)');
    expect(native).not.toContain('tauri_plugin_wdio_webdriver::init()');
    expect(native).toContain('register_uri_scheme_protocol("piui-raster"');
    expect(app).toContain('MarkdownProbe');
    expect(app).toContain('spike === A26_MARKDOWN_ROUTE');
    expect(JSON.parse(config).app.security.csp).toContain("img-src 'self' piui-raster:");
    expect(JSON.parse(packageJson).scripts['spike:packaged:markdown'])
      .toBe('/usr/bin/env -i PATH=/usr/bin:/bin LANG=en_AU.UTF-8 LC_ALL=en_AU.UTF-8 /usr/bin/ruby --disable-gems scripts/architecture-bootstrap.rb package --authoritative-a26');
    expect(packageRunner).toContain('--authoritative-a26');
    expect(packageRunner).toContain('executeAuthoritativeMarkdownProbe');
    expect(packageRunner).toContain("productionFrontend = captureA26FrontendInventories");
    expect(packageRunner).toContain("automationFrontend = captureA26FrontendInventories");
    expect(packageRunner).toContain("repeatAutomationFrontend = captureA26FrontendInventories");
    expect(packageRunner).toContain('PIUI_A26_MODULE_PROVENANCE_PATH: resolve(');
    expect(packageRunner).toContain('const frontendProvenance = await readTrustedRegularFile(');
    expect(packageRunner).toContain('productionProvenance,');
    expect(packageRunner).toContain('automationProvenance,');
    expect(packageRunner).toContain('repeatAutomationProvenance,');
    expect(packageRunner).toContain('deriveA26FrontendInventoryFromProvenance(frontend, provenance, role)');
    expect(packageRunner).toMatch(/productionFrontend,\s*productionProvenance,\s*'production',/u);
    expect(packageRunner).toMatch(/automationFrontend,\s*automationProvenance,\s*'automation',/u);
    expect(packageRunner).toContain(
      'expectedResourcePaths: markdownBundleDerivation.expectedResourcePaths',
    );
    expect(viteConfig).toContain("name: 'piui-a26-module-provenance'");
    expect(viteConfig).toContain('hostileFixtureSha256: [...hostileFixtureDigests][0] ?? null');
    expect(viteConfig).toContain("flag: 'wx'");
    expect(viteConfig).toContain('mode: 0o600');
    expect(viteConfig).toContain('moduleKinds: sorted(moduleKinds)');
  });
});
