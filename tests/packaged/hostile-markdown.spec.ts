import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import {
  A26_EXPECTED_NATIVE_EVIDENCE,
  A26_HOSTILE_FIXTURE_SHA256,
  A26_NATIVE_EVIDENCE_KEYS,
  A26_RASTER_FIXTURE_SHA256,
  assertA26BrowserEvidence,
  assertA26BundleEvidence,
  assertA26DomEvidence,
  assertAuthoritativeMarkdownEvidence,
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
    unexpectedResourceEntries: 0,
    rasterResourceEntries: 1,
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
    highlightedBlocks: 1,
    highlightTokenNodes: 12,
    plainCodeBlocks: 1,
    omittedAssets: 19,
    blockedLinks: 31,
    externalLinkButtons: 3,
    engine: 'javascript-regex',
    wasmModules: 0,
    hostileFixtureSha256: A26_HOSTILE_FIXTURE_SHA256,
    rasterFixtureSha256: A26_RASTER_FIXTURE_SHA256,
  };
}

function bundleEvidence() {
  return {
    productionWebdriverIncluded: false,
    automationWebdriverIncluded: true,
    cspExact: true,
    piuiRasterOnlyImageAddition: true,
    wasmFiles: 0,
    wasmMagicFrontendFiles: 0,
    onigurumaEngineChunks: 0,
    javascriptRegexEngineChunks: 1,
  };
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
    expect(assertA26BundleEvidence(bundleEvidence())).toEqual(bundleEvidence());
    expect(JSON.stringify({
      native: A26_EXPECTED_NATIVE_EVIDENCE,
      browser: browserEvidence(),
      dom: domEvidence(),
      bundle: bundleEvidence(),
    })).not.toContain('/');
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
      line({ ...authoritative, bundle: { ...bundleEvidence(), wasmFiles: 1 } }),
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
    const [route, prelude, command] = await Promise.all([
      readFile(new URL('../../src/architecture-gate/MarkdownProbe.tsx', import.meta.url), 'utf8'),
      readFile(new URL('../../src/architecture-gate/a26MarkdownPrelude.ts', import.meta.url), 'utf8'),
      readFile(new URL('../../src-tauri/src/commands/a26_markdown.rs', import.meta.url), 'utf8'),
    ]);
    expect(route).toContain("invoke<unknown>('a26_markdown_prepare')");
    expect(route).toContain("import('../../tests/fixtures/markdown/hostile.md?raw')");
    expect(route).toContain('aria-busy={state.phase !== \'ready\'}');
    expect(route).toContain('markdown-probe__spinner');
    expect(prelude).toContain("import.meta.env.VITE_PIUI_A26_MARKDOWN_TEST === '1'");
    expect(prelude).toContain('let begun = false;');
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
    const [cargo, commands, native, app, config, packageJson, packageRunner] = await Promise.all([
      readFile(new URL('../../src-tauri/Cargo.toml', import.meta.url), 'utf8'),
      readFile(new URL('../../src-tauri/src/commands/mod.rs', import.meta.url), 'utf8'),
      readFile(new URL('../../src-tauri/src/lib.rs', import.meta.url), 'utf8'),
      readFile(new URL('../../src/App.tsx', import.meta.url), 'utf8'),
      readFile(new URL('../../src-tauri/tauri.conf.json', import.meta.url), 'utf8'),
      readFile(new URL('../../package.json', import.meta.url), 'utf8'),
      readFile(new URL('../../scripts/package-spike.mjs', import.meta.url), 'utf8'),
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
      .toBe('node scripts/run-packaged-markdown-probe.mjs');
    expect(packageRunner).toContain('--authoritative-a26');
    expect(packageRunner).toContain('executeAuthoritativeMarkdownProbe');
  });
});
