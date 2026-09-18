import { createHash, randomBytes, randomInt } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { closeSync, constants, openSync } from 'node:fs';
import { chmod, lstat, mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { revalidateBundle } from '../tests/packaged/bundle-inspection.mjs';
import {
  ProcessLedger,
  installParentCutoffs,
  isProcessObservationFailure,
  runOwnedCommand,
  terminateRecordedProcessGroupsWithoutObservation,
  waitForChildSpawn,
} from './a21-gate-support.mjs';
import { credentialProbeSandbox } from './run-packaged-credential-probe.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const MAX_EVIDENCE_BYTES = 262_144;
const HTTP_RESPONSE_LIMIT = 262_144;
const ACTIVATION_MODE = 'a26-markdown';
const ACTIVATION_PORT_MIN = 49_152;
const ACTIVATION_PORT_MAX = 65_535;
const SHA256 = /^[0-9a-f]{64}$/;
const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function seatbeltPath(path) {
  return path.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
}

export function a26RuntimeSandbox({ activation, bundle, isolate }) {
  const profile = credentialProbeSandbox({
    artefacts: resolve(isolate, 'agent'),
    cache: resolve(isolate, 'cache'),
    config: resolve(isolate, 'config'),
    data: resolve(isolate, 'data'),
    home: resolve(isolate, 'home'),
    temporary: resolve(isolate, 'tmp'),
    working: isolate,
  }, bundle, { allowCredentialBrokers: false });
  if (activation !== undefined
    && (!isRecord(activation)
      || !Number.isSafeInteger(activation.port)
      || activation.port < ACTIVATION_PORT_MIN
      || activation.port > ACTIVATION_PORT_MAX)) fail();
  const loopback = activation === undefined
    ? ''
    : `
  (allow network-inbound (local tcp "localhost:${activation.port}"))
  (allow network-outbound (remote tcp "localhost:${activation.port}"))`;
  return `${profile}
  (deny file-write* (subpath "${seatbeltPath(bundle.appPath)}"))${loopback}`;
}

export const A26_HOSTILE_FIXTURE_SHA256 = '9c08397fe195119adb5abf548e5df287c82174918c35b758e150750da26b5ac9';
export const A26_RASTER_FIXTURE_SHA256 = '431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460';

export const A26_NATIVE_EVIDENCE_KEYS = Object.freeze([
  'assetActiveBytes',
  'assetActiveEntries',
  'assetRegistrations',
  'assetRejectedReads',
  'assetSuccessfulReads',
  'engine',
  'evidenceInvocations',
  'hostileFixtureSha256',
  'prepareInvocations',
  'rasterFixtureSha256',
  'schemaVersion',
  'testMode',
  'unexpectedTauriInvocations',
  'wasmModules',
  'wrongWebviewInvocations',
]);

export const A26_EXPECTED_NATIVE_EVIDENCE = Object.freeze({
  schemaVersion: 1,
  testMode: true,
  engine: 'javascript-regex',
  wasmModules: 0,
  hostileFixtureSha256: A26_HOSTILE_FIXTURE_SHA256,
  rasterFixtureSha256: A26_RASTER_FIXTURE_SHA256,
  prepareInvocations: 1,
  evidenceInvocations: 1,
  unexpectedTauriInvocations: 0,
  wrongWebviewInvocations: 0,
  assetRegistrations: 1,
  assetSuccessfulReads: 1,
  assetRejectedReads: 0,
  assetActiveEntries: 0,
  assetActiveBytes: 0,
});

const BROWSER_KEYS = Object.freeze([
  'codeLoadingIndicatorPresented',
  'cspViolations',
  'disclosedExternalOpens',
  'eventCanaryExecuted',
  'hostileSameOriginResourceEntries',
  'loadingIndicatorPresented',
  'locationUnchanged',
  'missingResourceEntries',
  'navigationApiAttempts',
  'networkApiAttempts',
  'observedResourceEntries',
  'observedResourceSha256',
  'popupAttempts',
  'rasterResourceEntries',
  'resourceAllowlistEntries',
  'runtimeErrors',
  'schemaVersion',
  'scriptCanaryExecuted',
  'duplicateResourceEntries',
  'unexpectedResourceEntries',
  'unhandledRejections',
  'wasmApiAttempts',
]);

const DOM_KEYS = Object.freeze([
  'blockedLinks',
  'engine',
  'externalLinkButtons',
  'fallbackSourceTextExact',
  'highlightTokenNodes',
  'highlightedBlocks',
  'hostileFixtureSha256',
  'loadedRasterImages',
  'languageFallbacks',
  'omittedAssets',
  'plainCodeBlocks',
  'probeReady',
  'rasterFixtureSha256',
  'rasterImages',
  'rasterSourcesExact',
  'rawAuditRegions',
  'renderBudgetFallbacks',
  'schemaVersion',
  'unsafeActiveAttributes',
  'unsafeActiveElements',
  'wasmModules',
  'workBudgetFallbacks',
]);

const IDENTITY_KEYS = Object.freeze([
  'automationFingerprint',
  'controlledDeltaSha256',
  'productionFingerprint',
  'sameFrozenSource',
  'sourceDigest',
]);

const DRIVER_KEYS = Object.freeze([
  'activatedTwinIpv4LoopbackListeners',
  'activatedTwinOtherListeners',
  'activationNonceValidated',
  'dormantTwinListeners',
  'legacyEnvPortListeners',
  'legacyWebdriverPortIgnored',
  'productionHostileActivationListeners',
  'randomHighPort',
  'webdriverSessions',
]);

const BUNDLE_KEYS = Object.freeze([
  'automationFrontend',
  'automationWebdriverIncluded',
  'cspExact',
  'piuiRasterOnlyImageAddition',
  'productionFrontend',
  'productionWebdriverIncluded',
  'repeatAutomationFrontend',
]);

const FRONTEND_INVENTORY_KEYS = Object.freeze([
  'fileCount',
  'inventorySha256',
  'javascriptRegexEngineChunks',
  'moduleProvenanceSha256',
  'onigurumaEngineChunks',
  'resourceAllowlistEntries',
  'resourceAllowlistSha256',
  'wasmFiles',
  'wasmMagicFrontendFiles',
  'wasmPayloadReferences',
]);

const CLEANUP_KEYS = Object.freeze([
  'bundlesRevalidated',
  'listenerRemoved',
  'runnerIsolatesRemoved',
  'webdriverSessionDeleted',
]);

const EVIDENCE_KEYS = Object.freeze([
  'browser',
  'bundle',
  'cleanup',
  'dom',
  'driver',
  'identity',
  'native',
  'schemaVersion',
  'status',
]);

function fail() {
  throw new Error('A.26 packaged Markdown probe rejected');
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, expected) {
  if (!isRecord(value)
    || !isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort())) fail();
}

function exactSha(value) {
  if (typeof value !== 'string' || !SHA256.test(value)) fail();
}

const A26_OUTPUT_PATH = /^(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/u;
export const A26_MODULE_KINDS = Object.freeze([
  'a26-engine-javascript',
  'a26-engine-oniguruma',
  'a26-hostile-fixture',
  'a26-lang-bash',
  'a26-lang-css',
  'a26-lang-html',
  'a26-lang-javascript',
  'a26-lang-json',
  'a26-lang-markdown',
  'a26-lang-rust',
  'a26-lang-tsx',
  'a26-lang-typescript',
  'a26-shiki-core',
  'a26-theme-github-dark-default',
  'a26-wasm-module',
]);
const A26_REQUIRED_ROUTE_MODULE_KINDS = Object.freeze(
  A26_MODULE_KINDS.filter((kind) => (
    kind !== 'a26-engine-oniguruma' && kind !== 'a26-wasm-module'
  )),
);
const A26_PROVENANCE_KEYS = Object.freeze(['chunks', 'schemaVersion']);
const A26_PROVENANCE_CHUNK_KEYS = Object.freeze([
  'assets',
  'css',
  'dynamicImports',
  'fileName',
  'imports',
  'isEntry',
  'moduleKinds',
]);

function canonicalA26Json(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'number'
    || typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalA26Json).join(',')}]`;
  if (!isRecord(value)) fail();
  return `{${Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${canonicalA26Json(value[key])}`
  )).join(',')}}`;
}

function assertSortedUniqueStrings(value, {
  maximum = 4_096,
  predicate = () => true,
} = {}) {
  if (!Array.isArray(value) || value.length > maximum) fail();
  let previous;
  for (const entry of value) {
    if (typeof entry !== 'string'
      || entry.length < 1
      || entry.length > 512
      || !predicate(entry)
      || (previous !== undefined && entry <= previous)) fail();
    previous = entry;
  }
  return Object.freeze([...value]);
}

export function parseA26ModuleProvenance(bytes) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 3
    || bytes.length > MAX_EVIDENCE_BYTES
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
    || bytes.includes(0x00)) fail();
  const text = bytes.subarray(0, -1).toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes.subarray(0, -1))) fail();
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail();
  }
  if (canonicalA26Json(value) !== text) fail();
  exactKeys(value, A26_PROVENANCE_KEYS);
  if (value.schemaVersion !== 1
    || !Array.isArray(value.chunks)
    || value.chunks.length < 1
    || value.chunks.length > 4_096) fail();
  const chunks = [];
  let previousFileName;
  for (const chunk of value.chunks) {
    exactKeys(chunk, A26_PROVENANCE_CHUNK_KEYS);
    if (typeof chunk.fileName !== 'string'
      || !A26_OUTPUT_PATH.test(chunk.fileName)
      || !/\.m?js$/u.test(chunk.fileName)
      || (previousFileName !== undefined && chunk.fileName <= previousFileName)
      || typeof chunk.isEntry !== 'boolean') fail();
    previousFileName = chunk.fileName;
    const outputPath = (entry) => A26_OUTPUT_PATH.test(entry);
    const javascriptPath = (entry) => outputPath(entry) && /\.m?js$/u.test(entry);
    const moduleKind = (entry) => A26_MODULE_KINDS.includes(entry);
    chunks.push(Object.freeze({
      assets: assertSortedUniqueStrings(chunk.assets, { predicate: outputPath }),
      css: assertSortedUniqueStrings(chunk.css, { predicate: outputPath }),
      dynamicImports: assertSortedUniqueStrings(
        chunk.dynamicImports,
        { predicate: javascriptPath },
      ),
      fileName: chunk.fileName,
      imports: assertSortedUniqueStrings(chunk.imports, { predicate: javascriptPath }),
      isEntry: chunk.isEntry,
      moduleKinds: assertSortedUniqueStrings(chunk.moduleKinds, {
        maximum: A26_MODULE_KINDS.length,
        predicate: moduleKind,
      }),
    }));
  }
  const chunkNames = new Set(chunks.map((chunk) => chunk.fileName));
  if (chunks.filter((chunk) => chunk.isEntry).length < 1
    || chunks.some((chunk) => (
      [...chunk.imports, ...chunk.dynamicImports].some((path) => !chunkNames.has(path))
    ))) fail();
  return Object.freeze({ schemaVersion: 1, chunks: Object.freeze(chunks) });
}

function indexResourcePaths(indexBytes) {
  if (!Buffer.isBuffer(indexBytes) || indexBytes.length < 16 || indexBytes.length > 1_048_576) fail();
  const html = indexBytes.toString('utf8');
  if (!Buffer.from(html, 'utf8').equals(indexBytes)) fail();
  const resources = new Set();
  for (const tag of html.matchAll(/<(?:script|link)\b[^>]*>/giu)) {
    for (const attribute of tag[0].matchAll(/\b(?:src|href)="([^"]+)"/gu)) {
      const path = attribute[1];
      if (!path.startsWith('/')) continue;
      const relativePath = path.slice(1);
      if (!A26_OUTPUT_PATH.test(relativePath)) fail();
      resources.add(relativePath);
    }
  }
  if (resources.size < 1 || resources.size > 4_095) fail();
  return Object.freeze([...resources].sort());
}

function containsRawWasmMagic(bytes) {
  return bytes.indexOf(Buffer.from([0x00, 0x61, 0x73, 0x6d])) !== -1;
}

function containsEncodedWasmPayload(bytes) {
  const text = bytes.toString('latin1');
  return text.includes('AGFzbQ')
    || /(?:\\x00|\\u0000)asm/u.test(text)
    || /0x00\s*,\s*0x61\s*,\s*0x73\s*,\s*0x6d/iu.test(text)
    || /(?:^|[^0-9])0\s*,\s*97\s*,\s*115\s*,\s*109(?:[^0-9]|$)/u.test(text)
    || /(?:^|[^A-Za-z0-9_.-])(?:[A-Za-z0-9_./-]+\.wasm)(?:[^A-Za-z0-9_.-]|$)/iu.test(text);
}

export function deriveA26FrontendInventory(frontend, provenanceBytes) {
  if (!Array.isArray(frontend)
    || frontend.length < 2
    || frontend.length > 4_096
    || frontend.filter((file) => file?.path === 'index.html').length !== 1) fail();
  const provenance = parseA26ModuleProvenance(provenanceBytes);
  const canonicalFiles = [];
  const frontendByPath = new Map();
  let previousPath;
  for (const file of frontend) {
    if (!file
      || !Buffer.isBuffer(file.bytes)
      || typeof file.path !== 'string'
      || file.path.length < 1
      || file.path.length > 511
      || !A26_OUTPUT_PATH.test(file.path)
      || (previousPath !== undefined && file.path <= previousPath)) fail();
    previousPath = file.path;
    frontendByPath.set(file.path, file);
    canonicalFiles.push(Object.freeze({
      byteLength: file.bytes.length,
      path: file.path,
      sha256: createHash('sha256').update(file.bytes).digest('hex'),
    }));
  }
  const frontendChunkPaths = [...frontendByPath.keys()].filter((path) => /\.m?js$/u.test(path));
  if (!isDeepStrictEqual(frontendChunkPaths, provenance.chunks.map((chunk) => chunk.fileName))) fail();
  const chunkByName = new Map(provenance.chunks.map((chunk) => [chunk.fileName, chunk]));
  const indexFile = frontendByPath.get('index.html');
  if (!indexFile) fail();
  const indexResources = indexResourcePaths(indexFile.bytes);
  if (indexResources.some((path) => !frontendByPath.has(path))) fail();

  const entryChunks = indexResources.filter((path) => chunkByName.has(path));
  if (entryChunks.length < 1 || entryChunks.some((path) => !chunkByName.get(path).isEntry)) fail();
  const dynamicallyReachable = new Set();
  const allQueue = [...entryChunks];
  while (allQueue.length > 0) {
    const name = allQueue.shift();
    if (dynamicallyReachable.has(name)) continue;
    dynamicallyReachable.add(name);
    const chunk = chunkByName.get(name);
    if (!chunk) fail();
    allQueue.push(...chunk.imports, ...chunk.dynamicImports);
  }

  const routeRootChunks = provenance.chunks.filter((chunk) => (
    chunk.moduleKinds.some((kind) => A26_REQUIRED_ROUTE_MODULE_KINDS.includes(kind))
  ));
  const observedKinds = new Set(routeRootChunks.flatMap((chunk) => chunk.moduleKinds));
  if (A26_REQUIRED_ROUTE_MODULE_KINDS.some((kind) => !observedKinds.has(kind))
    || routeRootChunks.some((chunk) => !dynamicallyReachable.has(chunk.fileName))) fail();

  const selectedResources = new Set(indexResources);
  const staticQueue = [...entryChunks, ...routeRootChunks.map((chunk) => chunk.fileName)];
  const selectedChunks = new Set();
  while (staticQueue.length > 0) {
    const name = staticQueue.shift();
    if (selectedChunks.has(name)) continue;
    selectedChunks.add(name);
    selectedResources.add(name);
    const chunk = chunkByName.get(name);
    if (!chunk) fail();
    for (const path of [...chunk.css, ...chunk.assets]) {
      if (!frontendByPath.has(path)) fail();
      selectedResources.add(path);
    }
    staticQueue.push(...chunk.imports);
  }
  const expectedResourcePaths = [...selectedResources]
    .map((path) => `/${path}`)
    .sort();
  if (expectedResourcePaths.length < 1
    || expectedResourcePaths.length > frontend.length - 1) fail();

  const rawWasmFiles = frontend.filter((file) => containsRawWasmMagic(file.bytes));
  const wasmPayloadPaths = new Set(
    frontend.filter((file) => containsEncodedWasmPayload(file.bytes)).map((file) => file.path),
  );
  for (const chunk of provenance.chunks) {
    if (chunk.moduleKinds.includes('a26-wasm-module')) wasmPayloadPaths.add(chunk.fileName);
  }
  const evidence = Object.freeze({
    fileCount: frontend.length,
    inventorySha256: createHash('sha256')
      .update(Buffer.from(`${JSON.stringify(canonicalFiles)}\n`, 'utf8'))
      .digest('hex'),
    javascriptRegexEngineChunks: provenance.chunks.filter((chunk) =>
      chunk.moduleKinds.includes('a26-engine-javascript')).length,
    moduleProvenanceSha256: createHash('sha256').update(provenanceBytes).digest('hex'),
    onigurumaEngineChunks: provenance.chunks.filter((chunk) =>
      chunk.moduleKinds.includes('a26-engine-oniguruma')).length,
    resourceAllowlistEntries: expectedResourcePaths.length,
    resourceAllowlistSha256: createHash('sha256')
      .update(Buffer.from(`${JSON.stringify(expectedResourcePaths)}\n`, 'utf8'))
      .digest('hex'),
    wasmFiles: frontend.filter((file) => file.path.toLowerCase().endsWith('.wasm')).length,
    wasmMagicFrontendFiles: rawWasmFiles.length,
    wasmPayloadReferences: wasmPayloadPaths.size,
  });
  if (evidence.wasmFiles !== 0
    || evidence.wasmMagicFrontendFiles !== 0
    || evidence.wasmPayloadReferences !== 0
    || evidence.onigurumaEngineChunks !== 0
    || evidence.javascriptRegexEngineChunks < 1) fail();
  return Object.freeze({
    evidence,
    expectedResourcePaths: Object.freeze(expectedResourcePaths),
  });
}

async function readBoundedResponseBytes(response) {
  if (!response.body) fail();
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) fail();
      total += value.byteLength;
      if (total > HTTP_RESPONSE_LIMIT) {
        try {
          await reader.cancel();
        } catch {
          // The fixed rejection below remains authoritative.
        }
        fail();
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  if (total < 2) fail();
  return Buffer.concat(chunks, total);
}

function parseOneLine(bytes) {
  if (!Buffer.isBuffer(bytes)
    || bytes.length < 3
    || bytes.length > MAX_EVIDENCE_BYTES
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
    || bytes.includes(0x00)) fail();
  const text = bytes.subarray(0, -1).toString('utf8');
  if (Buffer.byteLength(text, 'utf8') !== bytes.length - 1) fail();
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail();
  }
  if (JSON.stringify(value) !== text) fail();
  return value;
}

export function assertNativeMarkdownEvidence(value) {
  exactKeys(value, A26_NATIVE_EVIDENCE_KEYS);
  if (!isDeepStrictEqual(value, A26_EXPECTED_NATIVE_EVIDENCE)) fail();
  return Object.freeze({ ...A26_EXPECTED_NATIVE_EVIDENCE });
}

export function parseNativeMarkdownEvidence(bytes) {
  return assertNativeMarkdownEvidence(parseOneLine(bytes));
}

export function assertA26BrowserEvidence(value) {
  exactKeys(value, BROWSER_KEYS);
  const exact = {
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
    locationUnchanged: true,
    scriptCanaryExecuted: false,
    eventCanaryExecuted: false,
    loadingIndicatorPresented: true,
    codeLoadingIndicatorPresented: true,
  };
  for (const [key, expected] of Object.entries(exact)) {
    if (value[key] !== expected || typeof value[key] !== typeof expected) fail();
  }
  if (!Number.isSafeInteger(value.rasterResourceEntries)
    || value.rasterResourceEntries < 0
    || value.rasterResourceEntries > 1
    || !Number.isSafeInteger(value.resourceAllowlistEntries)
    || value.resourceAllowlistEntries < 1
    || value.resourceAllowlistEntries > 4_095
    || !Number.isSafeInteger(value.observedResourceEntries)
    || value.observedResourceEntries !== value.resourceAllowlistEntries) fail();
  exactSha(value.observedResourceSha256);
  return Object.freeze({ ...value });
}

export function assertA26DomEvidence(value) {
  exactKeys(value, DOM_KEYS);
  if (value.schemaVersion !== 1
    || value.probeReady !== true
    || value.rawAuditRegions !== 1
    || value.unsafeActiveElements !== 0
    || value.unsafeActiveAttributes !== 0
    || value.rasterImages !== 1
    || value.loadedRasterImages !== 1
    || value.rasterSourcesExact !== true
    || !Number.isSafeInteger(value.highlightTokenNodes)
    || value.highlightTokenNodes < 1
    || value.highlightedBlocks !== 2
    || value.plainCodeBlocks !== 3
    || value.languageFallbacks !== 1
    || value.renderBudgetFallbacks !== 1
    || value.workBudgetFallbacks !== 1
    || value.fallbackSourceTextExact !== true
    || !Number.isSafeInteger(value.omittedAssets)
    || value.omittedAssets < 1
    || !Number.isSafeInteger(value.blockedLinks)
    || value.blockedLinks < 1
    || value.externalLinkButtons !== 3
    || value.engine !== 'javascript-regex'
    || value.wasmModules !== 0
    || value.hostileFixtureSha256 !== A26_HOSTILE_FIXTURE_SHA256
    || value.rasterFixtureSha256 !== A26_RASTER_FIXTURE_SHA256) fail();
  return Object.freeze({ ...value });
}

function assertIdentity(value) {
  exactKeys(value, IDENTITY_KEYS);
  exactSha(value.sourceDigest);
  exactSha(value.productionFingerprint);
  exactSha(value.automationFingerprint);
  exactSha(value.controlledDeltaSha256);
  if (value.sameFrozenSource !== true
    || value.productionFingerprint === value.automationFingerprint) fail();
  return Object.freeze({ ...value });
}

function assertDriver(value) {
  exactKeys(value, DRIVER_KEYS);
  if (!isDeepStrictEqual(value, {
    productionHostileActivationListeners: 0,
    dormantTwinListeners: 0,
    activatedTwinIpv4LoopbackListeners: 1,
    activatedTwinOtherListeners: 0,
    legacyEnvPortListeners: 0,
    legacyWebdriverPortIgnored: true,
    randomHighPort: true,
    activationNonceValidated: true,
    webdriverSessions: 1,
  })) fail();
  return Object.freeze({ ...value });
}

export function assertA26FrontendInventory(value) {
  exactKeys(value, FRONTEND_INVENTORY_KEYS);
  exactSha(value.inventorySha256);
  exactSha(value.moduleProvenanceSha256);
  exactSha(value.resourceAllowlistSha256);
  if (!Number.isSafeInteger(value.fileCount)
    || value.fileCount < 2
    || value.fileCount > 4_096
    || !Number.isSafeInteger(value.resourceAllowlistEntries)
    || value.resourceAllowlistEntries < 1
    || value.resourceAllowlistEntries > value.fileCount - 1
    || value.wasmFiles !== 0
    || value.wasmMagicFrontendFiles !== 0
    || value.wasmPayloadReferences !== 0
    || value.onigurumaEngineChunks !== 0
    || !Number.isSafeInteger(value.javascriptRegexEngineChunks)
    || value.javascriptRegexEngineChunks < 1
    || value.javascriptRegexEngineChunks > value.resourceAllowlistEntries) fail();
  return Object.freeze({ ...value });
}

export function assertA26BundleEvidence(value) {
  exactKeys(value, BUNDLE_KEYS);
  if (value.productionWebdriverIncluded !== false
    || value.automationWebdriverIncluded !== true
    || value.cspExact !== true
    || value.piuiRasterOnlyImageAddition !== true) fail();
  const productionFrontend = assertA26FrontendInventory(value.productionFrontend);
  const automationFrontend = assertA26FrontendInventory(value.automationFrontend);
  const repeatAutomationFrontend = assertA26FrontendInventory(
    value.repeatAutomationFrontend,
  );
  if (!isDeepStrictEqual(automationFrontend, repeatAutomationFrontend)) fail();
  return Object.freeze({
    productionWebdriverIncluded: false,
    automationWebdriverIncluded: true,
    cspExact: true,
    piuiRasterOnlyImageAddition: true,
    productionFrontend,
    automationFrontend,
    repeatAutomationFrontend,
  });
}

function assertCleanup(value) {
  exactKeys(value, CLEANUP_KEYS);
  if (!isDeepStrictEqual(value, {
    webdriverSessionDeleted: true,
    listenerRemoved: true,
    runnerIsolatesRemoved: true,
    bundlesRevalidated: true,
  })) fail();
  return Object.freeze({ ...value });
}

export function assertAuthoritativeMarkdownEvidence(value) {
  exactKeys(value, EVIDENCE_KEYS);
  if (value.schemaVersion !== 1 || value.status !== 'pass') fail();
  const identity = assertIdentity(value.identity);
  const driver = assertDriver(value.driver);
  const bundle = assertA26BundleEvidence(value.bundle);
  const dom = assertA26DomEvidence(value.dom);
  const browser = assertA26BrowserEvidence(value.browser);
  const native = assertNativeMarkdownEvidence(value.native);
  const cleanup = assertCleanup(value.cleanup);
  if (browser.resourceAllowlistEntries
      !== bundle.automationFrontend.resourceAllowlistEntries
    || browser.observedResourceEntries
      !== bundle.automationFrontend.resourceAllowlistEntries
    || browser.observedResourceSha256
      !== bundle.automationFrontend.resourceAllowlistSha256) fail();
  return Object.freeze({
    schemaVersion: 1,
    status: 'pass',
    identity,
    driver,
    bundle,
    dom,
    browser,
    native,
    cleanup,
  });
}

export function parseAuthoritativeMarkdownEvidence(bytes) {
  return assertAuthoritativeMarkdownEvidence(parseOneLine(bytes));
}

export function parsePackagedMarkdownEvidence(bytes) {
  const value = parseOneLine(bytes);
  exactKeys(value, [...EVIDENCE_KEYS, 'generatedOutputsRemoved']);
  if (value.generatedOutputsRemoved !== true) fail();
  const authoritative = Object.fromEntries(EVIDENCE_KEYS.map((key) => [key, value[key]]));
  return Object.freeze({
    ...assertAuthoritativeMarkdownEvidence(authoritative),
    generatedOutputsRemoved: true,
  });
}

export function classifyA26ResourceEntries(input) {
  const reject = () => {
    throw new Error('A.26 resource observation rejected');
  };
  if (input === null || typeof input !== 'object' || Array.isArray(input)) reject();
  const {
    currentLocation,
    expectedRasterUrl,
    expectedResourcePaths,
    resourceNames,
  } = input;
  if (typeof currentLocation !== 'string'
    || currentLocation.length < 1
    || currentLocation.length > 2_048
    || typeof expectedRasterUrl !== 'string'
    || !/^piui-raster:\/\/localhost\/__piui_markdown_asset__\/[0-9a-f]{32}\.(?:png|jpg|webp)$/u
      .test(expectedRasterUrl)
    || !Array.isArray(expectedResourcePaths)
    || expectedResourcePaths.length < 1
    || expectedResourcePaths.length > 4_095
    || !Array.isArray(resourceNames)
    || resourceNames.length > 8_192) reject();

  let current;
  try {
    current = new URL(currentLocation);
  } catch {
    reject();
  }
  if (!current
    || current.username !== ''
    || current.password !== ''
    || current.host === '') reject();

  const allowlist = new Set();
  let previousPath;
  for (const path of expectedResourcePaths) {
    if (typeof path !== 'string'
      || path.length < 2
      || path.length > 512
      || path === '/index.html'
      || !/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/u.test(path)
      || path.split('/').some((segment) => segment === '.' || segment === '..')
      || (previousPath !== undefined && path <= previousPath)) reject();
    previousPath = path;
    allowlist.add(path);
  }
  if (allowlist.size !== expectedResourcePaths.length) reject();

  let rasterResourceEntries = 0;
  let hostileSameOriginResourceEntries = 0;
  let unexpectedResourceEntries = 0;
  let duplicateResourceEntries = 0;
  const observedPaths = new Set();
  for (const name of resourceNames) {
    if (typeof name !== 'string' || name.length < 1 || name.length > 2_048) reject();
    if (name === expectedRasterUrl) {
      rasterResourceEntries += 1;
      continue;
    }
    let candidate;
    try {
      candidate = new URL(name);
    } catch {
      unexpectedResourceEntries += 1;
      continue;
    }
    const sameOrigin = candidate.protocol === current.protocol
      && candidate.host === current.host
      && candidate.username === ''
      && candidate.password === '';
    if (sameOrigin && candidate.pathname === '/synthetic/private/image-canary.png') {
      hostileSameOriginResourceEntries += 1;
    }
    const accepted = sameOrigin
      && candidate.search === ''
      && candidate.hash === ''
      && allowlist.has(candidate.pathname);
    if (!accepted) {
      unexpectedResourceEntries += 1;
      continue;
    }
    if (observedPaths.has(candidate.pathname)) {
      duplicateResourceEntries += 1;
    } else {
      observedPaths.add(candidate.pathname);
    }
  }
  const observedResourcePaths = [...observedPaths].sort();
  return Object.freeze({
    duplicateResourceEntries,
    hostileSameOriginResourceEntries,
    missingResourceEntries: expectedResourcePaths.filter((path) => !observedPaths.has(path)).length,
    observedResourcePaths: Object.freeze(observedResourcePaths),
    rasterResourceEntries,
    resourceAllowlistEntries: expectedResourcePaths.length,
    unexpectedResourceEntries,
  });
}

export function assertA26ResourceAllowlist(value) {
  try {
    classifyA26ResourceEntries({
      currentLocation: 'tauri://localhost/',
      expectedRasterUrl:
        'piui-raster://localhost/__piui_markdown_asset__/00000000000000000000000000000000.png',
      expectedResourcePaths: value,
      resourceNames: value.map((path) => `tauri://localhost${path}`),
    });
  } catch {
    fail();
  }
  return Object.freeze([...value]);
}

export function a26ResourceAllowlistSha256(value) {
  const accepted = assertA26ResourceAllowlist(value);
  return createHash('sha256')
    .update(Buffer.from(`${JSON.stringify(accepted)}\n`, 'utf8'))
    .digest('hex');
}

export const A26_OBSERVE_SCRIPT = String.raw`
const deadline = Date.now() + 30000;
let probe = null;
while (Date.now() < deadline) {
  probe = document.querySelector('[data-a26-probe-state]');
  const raster = document.querySelector('.markdown__asset-image');
  if (raster instanceof HTMLElement) raster.scrollIntoView({ block: 'center', inline: 'nearest' });
  if (probe && probe.getAttribute('data-a26-probe-state') === 'ready') break;
  if (probe && probe.getAttribute('data-a26-probe-state') === 'failed') {
    throw new Error('a26-probe-failed');
  }
  await new Promise((resolveWait) => setTimeout(resolveWait, 50));
}
if (!probe || probe.getAttribute('data-a26-probe-state') !== 'ready') {
  throw new Error('a26-probe-timeout');
}
const expectedRaster = /^piui-raster:\/\/localhost\/__piui_markdown_asset__\/[0-9a-f]{32}\.(?:png|jpg|webp)$/;
const rasters = Array.from(document.querySelectorAll('.markdown__asset-image'));
const expectedRasterUrl = rasters.length === 1 ? rasters[0].getAttribute('src') || '' : '';
const blockedAttributes = new Set([
  'href', 'srcset', 'style', 'download', 'formaction', 'poster', 'ping', 'srcdoc', 'action',
]);
let unsafeActiveAttributes = 0;
for (const element of document.querySelectorAll('.markdown__prose *')) {
  for (const name of element.getAttributeNames()) {
    const lowered = name.toLowerCase();
    if (lowered.startsWith('on') || blockedAttributes.has(lowered)) unsafeActiveAttributes += 1;
    if (lowered === 'src' && !(element instanceof HTMLImageElement && expectedRaster.test(element.getAttribute(name) || ''))) {
      unsafeActiveAttributes += 1;
    }
  }
}
const prelude = window.__PIUI_A26_MARKDOWN_PRELUDE__;
if (!prelude || typeof prelude.stopAndSnapshot !== 'function') throw new Error('a26-prelude-missing');
const preludeBrowser = prelude.stopAndSnapshot();
const resourceObservation = classifyResourceEntries({
  currentLocation: window.location.href,
  expectedRasterUrl,
  expectedResourcePaths,
  resourceNames: performance.getEntriesByType('resource').map((entry) => entry.name),
});
const observedResourceBytes = new TextEncoder().encode(
  JSON.stringify(resourceObservation.observedResourcePaths) + '\n',
);
const observedResourceDigest = new Uint8Array(
  await crypto.subtle.digest('SHA-256', observedResourceBytes),
);
const observedResourceSha256 = Array.from(observedResourceDigest)
  .map((byte) => byte.toString(16).padStart(2, '0'))
  .join('');
const { observedResourcePaths, ...closedResourceObservation } = resourceObservation;
const browser = {
  ...preludeBrowser,
  ...closedResourceObservation,
  observedResourceEntries: observedResourcePaths.length,
  observedResourceSha256,
};
const codeBlocks = Array.from(
  document.querySelectorAll('.markdown__code-block > code[data-highlight-status]'),
);
const plainSource = (code) => Array.from(code.childNodes)
  .filter((node) => node.nodeType === Node.TEXT_NODE)
  .map((node) => node.textContent || '')
  .join('');
const fallbackFor = (reason) => codeBlocks.filter((code) => (
  code.getAttribute('data-highlight-status') === 'plain'
  && code.querySelector('.markdown__code-reason')?.textContent === reason
));
const languageFallbacks = fallbackFor('Plain code: language is not enabled.');
const renderBudgetFallbacks = fallbackFor(
  'Plain code: per-block highlight rendering budget reached.',
);
const workBudgetFallbacks = fallbackFor('Plain code: message highlight work budget reached.');
const languageSource = languageFallbacks.length === 1 ? plainSource(languageFallbacks[0]) : '';
const renderSource = renderBudgetFallbacks.length === 1 ? plainSource(renderBudgetFallbacks[0]) : '';
const workSource = workBudgetFallbacks.length === 1 ? plainSource(workBudgetFallbacks[0]) : '';
const fallbackSourceTextExact = languageSource
  === '<script>window.__PIUI_MARKDOWN_SCRIPT_EXECUTED__=true</script>'
  && renderSource.startsWith('const A26_RENDER_BUDGET_START: number = 0;')
  && renderSource.endsWith('const A26_RENDER_BUDGET_END: number = 351;')
  && workSource.startsWith('// A26_WORK_BUDGET_START ')
  && workSource.endsWith(' A26_WORK_BUDGET_END')
  && workSource.length > 27000
  && [...languageFallbacks, ...renderBudgetFallbacks, ...workBudgetFallbacks]
    .every((code) => code.children.length === 1);
return {
  browser,
  dom: {
    schemaVersion: 1,
    probeReady: true,
    rawAuditRegions: document.querySelectorAll('.markdown__raw-audit pre[aria-label="Inert raw Markdown source"]').length,
    unsafeActiveElements: document.querySelectorAll('.markdown__prose script, .markdown__prose iframe, .markdown__prose object, .markdown__prose embed, .markdown__prose base, .markdown__prose meta, .markdown__prose form, .markdown__prose style, .markdown__prose link, .markdown__prose svg, .markdown__prose math, .markdown__prose picture, .markdown__prose source, .markdown__prose template, .markdown__prose a, .markdown__prose custom-fetch-probe').length,
    unsafeActiveAttributes,
    rasterImages: rasters.length,
    loadedRasterImages: rasters.filter((image) => image.complete && image.naturalWidth > 0 && image.naturalHeight > 0).length,
    rasterSourcesExact: rasters.length === 1 && expectedRaster.test(rasters[0].getAttribute('src') || ''),
    highlightedBlocks: document.querySelectorAll('[data-highlight-status="tokens"]').length,
    highlightTokenNodes: document.querySelectorAll('[data-highlight-status="tokens"] [class^="tok-"]').length,
    plainCodeBlocks: document.querySelectorAll('.markdown__code-block > code:not([data-highlight-status="tokens"])').length,
    languageFallbacks: languageFallbacks.length,
    renderBudgetFallbacks: renderBudgetFallbacks.length,
    workBudgetFallbacks: workBudgetFallbacks.length,
    fallbackSourceTextExact,
    omittedAssets: document.querySelectorAll('.markdown__asset-omitted').length,
    blockedLinks: document.querySelectorAll('.markdown__blocked-link').length,
    externalLinkButtons: document.querySelectorAll('.markdown__link-button').length,
    engine: probe.getAttribute('data-a26-engine'),
    wasmModules: Number(probe.getAttribute('data-a26-wasm-modules')),
    hostileFixtureSha256: probe.getAttribute('data-a26-hostile-fixture-sha256'),
    rasterFixtureSha256: probe.getAttribute('data-a26-raster-fixture-sha256'),
  },
};`;

export function createA26ObserveScript(expectedResourcePaths) {
  const accepted = assertA26ResourceAllowlist(expectedResourcePaths);
  return `const classifyResourceEntries = (${classifyA26ResourceEntries.toString()});\nconst expectedResourcePaths = ${JSON.stringify(accepted)};\n${A26_OBSERVE_SCRIPT}`;
}

export const A26_NATIVE_EVIDENCE_SCRIPT = String.raw`
const internals = window.__TAURI_INTERNALS__;
if (!internals || typeof internals.invoke !== 'function') throw new Error('a26-native-bridge-missing');
return await internals.invoke('a26_markdown_evidence');`;

/**
 * Executes the bounded A.26 observations through either this module's raw W3C
 * client or an already-created official WebdriverIO browser session.
 */
export async function observeA26WithExecutor(executeScript, expectedResourcePaths) {
  if (typeof executeScript !== 'function') fail();
  const rendered = await executeScript(createA26ObserveScript(expectedResourcePaths));
  exactKeys(rendered, ['browser', 'dom']);
  const dom = assertA26DomEvidence(rendered.dom);
  const browser = assertA26BrowserEvidence(rendered.browser);
  const native = assertNativeMarkdownEvidence(
    await executeScript(A26_NATIVE_EVIDENCE_SCRIPT),
  );
  return Object.freeze({ dom, browser, native });
}

class A26WebDriverClient {
  constructor(port, signal) {
    if (!Number.isSafeInteger(port) || port < ACTIVATION_PORT_MIN || port > ACTIVATION_PORT_MAX) fail();
    this.baseUrl = `http://127.0.0.1:${port}`;
    this.signal = signal;
    this.sessionId = undefined;
    this.sessionDeleted = false;
  }

  async request(method, path, body, timeoutMs = 35_000) {
    const timeout = AbortSignal.timeout(timeoutMs);
    const signal = this.signal ? AbortSignal.any([this.signal, timeout]) : timeout;
    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      redirect: 'error',
      headers: {
        accept: 'application/json',
        connection: 'close',
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    });
    const length = response.headers.get('content-length');
    if ((length !== null && (!/^(?:0|[1-9][0-9]{0,6})$/.test(length)
      || Number(length) > HTTP_RESPONSE_LIMIT))
      || !response.headers.get('content-type')?.toLowerCase().startsWith('application/json')) fail();
    const bytes = await readBoundedResponseBytes(response);
    const text = bytes.toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(bytes)) fail();
    let payload;
    try {
      payload = JSON.parse(text);
    } catch {
      fail();
    }
    exactKeys(payload, ['value']);
    if (!response.ok) fail();
    return payload.value;
  }

  async waitUntilReady() {
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
      if (this.signal?.aborted) fail();
      try {
        const status = await this.request('GET', '/status', undefined, 2_000);
        exactKeys(status, ['message', 'ready']);
        if (status.ready === true && typeof status.message === 'string') return;
      } catch {
        // A connection refusal is expected until the feature-only listener is bound.
      }
      await sleep(50, undefined, this.signal ? { signal: this.signal } : undefined);
    }
    fail();
  }

  async createSession() {
    if (this.sessionId !== undefined) fail();
    const value = await this.request('POST', '/session', {
      capabilities: { alwaysMatch: {}, firstMatch: [{}] },
    });
    exactKeys(value, ['capabilities', 'sessionId']);
    if (typeof value.sessionId !== 'string' || !SESSION_ID.test(value.sessionId)
      || !isRecord(value.capabilities)) fail();
    this.sessionId = value.sessionId;
  }

  async execute(script) {
    if (!this.sessionId || typeof script !== 'string' || script.length < 1 || script.length > 65_536) fail();
    return this.request(
      'POST',
      `/session/${this.sessionId}/execute/sync`,
      { script, args: [] },
      40_000,
    );
  }

  async deleteSession() {
    if (!this.sessionId || this.sessionDeleted) fail();
    const value = await this.request('DELETE', `/session/${this.sessionId}`);
    if (value !== null) fail();
    this.sessionDeleted = true;
    this.sessionId = undefined;
  }
}

export async function observePackagedMarkdown({ expectedResourcePaths, port, signal } = {}) {
  const client = new A26WebDriverClient(port, signal);
  let evidence;
  let failure;
  try {
    await client.waitUntilReady();
    await client.createSession();
    evidence = await observeA26WithExecutor(
      (script) => client.execute(script),
      expectedResourcePaths,
    );
  } catch (error) {
    failure = error;
  } finally {
    if (client.sessionId && !client.sessionDeleted) {
      try {
        await client.deleteSession();
      } catch (error) {
        failure ??= error;
      }
    }
  }
  if (failure || !evidence || !client.sessionDeleted) fail();
  return Object.freeze({ ...evidence, webdriverSessionDeleted: true });
}

function assertNoNetwork(pid) {
  const result = spawnSync(
    '/usr/sbin/lsof',
    ['-nP', '-a', '-p', String(pid), '-i'],
    { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } },
  );
  if (result.stdout.trim() || ![0, 1].includes(result.status)) fail();
}

function networkNames(pid) {
  const result = spawnSync(
    '/usr/sbin/lsof',
    ['-nP', '-a', '-p', String(pid), '-i', '-Fn'],
    { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } },
  );
  if (![0, 1].includes(result.status)) fail();
  return result.stdout
    .split('\n')
    .filter((line) => line.startsWith('n'))
    .map((line) => line.slice(1));
}

function assertOnlyA26LoopbackNetwork(pid, port) {
  const exactListener = `127.0.0.1:${port}`;
  const accepted = new RegExp(`^127\\.0\\.0\\.1:${port}->127\\.0\\.0\\.1:[1-9][0-9]{0,4}$`);
  if (networkNames(pid).some((name) => name !== exactListener && !accepted.test(name))) fail();
}

function listenerNames(pid) {
  const result = spawnSync(
    '/usr/sbin/lsof',
    ['-nP', '-a', '-p', String(pid), '-iTCP', '-sTCP:LISTEN', '-Fn'],
    { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } },
  );
  if (![0, 1].includes(result.status)) fail();
  return result.stdout
    .split('\n')
    .filter((line) => line.startsWith('n'))
    .map((line) => line.slice(1));
}

function listenerInventory(live, expectedPort) {
  const names = live.flatMap((entry) => listenerNames(entry.pid));
  const exactName = expectedPort === undefined ? undefined : `127.0.0.1:${expectedPort}`;
  return Object.freeze({
    exact: exactName === undefined ? 0 : names.filter((name) => name === exactName).length,
    other: names.filter((name) => name !== exactName).length,
  });
}

function runtimeEnvironment(isolate, activation) {
  const home = resolve(isolate, 'home');
  const temporary = resolve(isolate, 'tmp');
  const cache = resolve(isolate, 'cache');
  const config = resolve(isolate, 'config');
  const data = resolve(isolate, 'data');
  const agent = resolve(isolate, 'agent');
  const sessions = resolve(isolate, 'sessions');
  return {
    HOME: home,
    CFFIXED_USER_HOME: home,
    TMPDIR: `${temporary}/`,
    XDG_CACHE_HOME: cache,
    XDG_CONFIG_HOME: config,
    XDG_DATA_HOME: data,
    PIUI_AGENT_ROOT: agent,
    PIUI_SESSION_ROOT: sessions,
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    LANG: 'en_AU.UTF-8',
    LC_ALL: 'en_AU.UTF-8',
    RUST_BACKTRACE: '0',
    ...(activation ? {
      PIUI_ARCHITECTURE_TEST_MODE: ACTIVATION_MODE,
      PIUI_ARCHITECTURE_TEST_NONCE: activation.nonce,
      PIUI_ARCHITECTURE_TEST_PORT: String(activation.port),
      ...(activation.legacyPort === undefined
        ? {}
        : { TAURI_WEBDRIVER_PORT: String(activation.legacyPort) }),
    } : {}),
  };
}

async function createRuntimeIsolate(prefix) {
  const requested = await mkdtemp(resolve(tmpdir(), prefix));
  await chmod(requested, 0o700);
  const isolate = await realpath(requested);
  for (const name of ['home', 'tmp', 'cache', 'config', 'data', 'agent', 'sessions']) {
    await mkdir(resolve(isolate, name), { mode: 0o700 });
  }
  return isolate;
}

async function launchRuntime(bundle, activation, signal) {
  if (!bundle
    || typeof bundle.appPath !== 'string'
    || typeof bundle.hostPath !== 'string'
    || typeof bundle.nodePath !== 'string') fail();
  if (signal?.aborted) fail();
  const isolate = await createRuntimeIsolate('piui-a26-runtime-');
  const stdoutPath = resolve(isolate, 'stdout.log');
  const stderrPath = resolve(isolate, 'stderr.log');
  let stdoutFd;
  let stderrFd;
  let child;
  let ledger;
  try {
    stdoutFd = openSync(
      stdoutPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
      0o600,
    );
    stderrFd = openSync(
      stderrPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
      0o600,
    );
    child = spawn('/usr/bin/sandbox-exec', [
      '-p',
      a26RuntimeSandbox({ activation, bundle, isolate }),
      bundle.hostPath,
    ], {
      cwd: isolate,
      env: runtimeEnvironment(isolate, activation),
      detached: true,
      stdio: ['ignore', stdoutFd, stderrFd],
    });
    await waitForChildSpawn(child);
    const networkChecker = activation
      ? (pid) => assertOnlyA26LoopbackNetwork(pid, activation.port)
      : assertNoNetwork;
    ledger = new ProcessLedger({
      hostPath: bundle.hostPath,
      nodePath: bundle.nodePath,
      networkChecker,
    });
    let initialised = false;
    for (let attempt = 0; attempt < 120 && !initialised; attempt += 1) {
      try {
        await ledger.initialise(child.pid);
        initialised = true;
      } catch {
        await sleep(25);
      }
    }
    if (!initialised) fail();
  } catch {
    const groups = [child?.pid, ...(ledger?.groups ?? [])]
      .filter((group) => Number.isSafeInteger(group) && group > 1);
    if (groups.length) {
      try {
        await terminateRecordedProcessGroupsWithoutObservation(groups);
      } catch {
        // The fixed rejection below remains authoritative.
      }
    }
    try {
      await rm(isolate, { recursive: true, force: false });
    } catch {
      // The fixed rejection below remains authoritative.
    }
    fail();
  } finally {
    if (stdoutFd !== undefined) closeSync(stdoutFd);
    if (stderrFd !== undefined) closeSync(stderrFd);
  }
  return { isolate, stdoutPath, stderrPath, childPid: child.pid, ledger, removed: false };
}

async function assertNoListenerStability(runtime, signal) {
  for (let index = 0; index < 15; index += 1) {
    if (signal?.aborted) fail();
    const live = await runtime.ledger.sample();
    if (!runtime.ledger.hasLiveHost(live)) fail();
    const inventory = listenerInventory(live);
    if (inventory.exact !== 0 || inventory.other !== 0) fail();
    await sleep(100);
  }
  return 0;
}

async function waitForExactListener(runtime, port, signal) {
  const deadline = Date.now() + 30_000;
  let stable = 0;
  while (Date.now() < deadline) {
    if (signal?.aborted) fail();
    const live = await runtime.ledger.sample();
    if (!runtime.ledger.hasLiveHost(live)
      || live.some((entry) => entry.executable !== runtime.ledger.hostPath)) fail();
    const inventory = listenerInventory(live, port);
    if (inventory.exact === 1 && inventory.other === 0) {
      stable += 1;
      if (stable === 5) return inventory;
    } else if (inventory.exact > 1 || inventory.other > 0) {
      fail();
    } else {
      stable = 0;
    }
    await sleep(50);
  }
  fail();
}

async function terminateRuntime(runtime) {
  let failure;
  let safeToRemove = false;
  try {
    const cleanup = await runtime.ledger.terminate();
    if (cleanup.forced) fail();
    safeToRemove = true;
  } catch (error) {
    if (isProcessObservationFailure(error)) {
      try {
        await terminateRecordedProcessGroupsWithoutObservation([
          runtime.childPid,
          ...runtime.ledger.groups,
        ]);
        safeToRemove = true;
      } catch {
        // The fixed rejection below remains authoritative.
      }
    }
    failure = error;
  }
  try {
    if (!safeToRemove) fail();
    for (const path of [runtime.stdoutPath, runtime.stderrPath]) {
      const item = await lstat(path);
      if (!item.isFile() || item.isSymbolicLink() || item.nlink !== 1 || item.size > 65_536) fail();
    }
    await rm(runtime.isolate, { recursive: true, force: false });
    runtime.removed = true;
  } catch (error) {
    failure ??= error;
  }
  if (failure) fail();
}

async function canBind(port) {
  return new Promise((resolveBind) => {
    const server = createServer();
    server.unref();
    server.once('error', () => resolveBind(false));
    server.listen({ host: '127.0.0.1', port, exclusive: true }, () => {
      server.close((error) => resolveBind(error === undefined));
    });
  });
}

async function randomFreeHighPort(excluded = new Set()) {
  for (let attempt = 0; attempt < 128; attempt += 1) {
    const port = randomInt(ACTIVATION_PORT_MIN, ACTIVATION_PORT_MAX + 1);
    if (!excluded.has(port) && await canBind(port)) return port;
  }
  fail();
}

async function runListenerNegative(bundle, activation, signal) {
  const runtime = await launchRuntime(bundle, activation, signal);
  let listeners;
  let failure;
  try {
    listeners = await assertNoListenerStability(runtime, signal);
  } catch (error) {
    failure = error;
  } finally {
    try {
      await terminateRuntime(runtime);
    } catch (error) {
      failure ??= error;
    }
  }
  if (failure || listeners !== 0 || !runtime.removed) fail();
  return listeners;
}

function validateExecutionInput(input) {
  exactKeys(input, [
    'automationBundle',
    'bundleEvidence',
    'controlledDeltaSha256',
    'expectedResourcePaths',
    'productionBundle',
    'signal',
    'sourceDigest',
  ]);
  exactSha(input.sourceDigest);
  exactSha(input.controlledDeltaSha256);
  if (!input.productionBundle || !input.automationBundle) fail();
  exactSha(input.productionBundle.fingerprint);
  exactSha(input.automationBundle.fingerprint);
  if (input.productionBundle.fingerprint === input.automationBundle.fingerprint
    || (input.signal !== undefined && !(input.signal instanceof AbortSignal))) fail();
  const bundleEvidence = assertA26BundleEvidence(input.bundleEvidence);
  const expectedResourcePaths = assertA26ResourceAllowlist(input.expectedResourcePaths);
  if (expectedResourcePaths.length
      !== bundleEvidence.automationFrontend.resourceAllowlistEntries
    || a26ResourceAllowlistSha256(expectedResourcePaths)
      !== bundleEvidence.automationFrontend.resourceAllowlistSha256) fail();
}

export async function executeAuthoritativeMarkdownProbe(input) {
  validateExecutionInput(input);
  const {
    productionBundle,
    automationBundle,
    sourceDigest,
    controlledDeltaSha256,
    bundleEvidence,
    expectedResourcePaths,
    signal,
  } = input;
  let activeRuntime;
  let activePort;
  let activeNonce;
  let observed;
  let productionListeners;
  let dormantListeners;
  let activeInventory;
  let listenerRemoved = false;
  let activeIsolateRemoved = false;
  let failure;
  try {
    await revalidateBundle(productionBundle);
    await revalidateBundle(automationBundle);

    const hostilePort = await randomFreeHighPort();
    const hostileLegacyPort = await randomFreeHighPort(new Set([hostilePort]));
    productionListeners = await runListenerNegative(productionBundle, {
      port: hostilePort,
      nonce: randomBytes(32).toString('hex'),
      legacyPort: hostileLegacyPort,
    }, signal);
    if (!(await canBind(hostilePort)) || !(await canBind(hostileLegacyPort))) fail();

    dormantListeners = await runListenerNegative(automationBundle, undefined, signal);

    activePort = await randomFreeHighPort();
    const activeLegacyPort = await randomFreeHighPort(new Set([activePort]));
    activeNonce = randomBytes(32).toString('hex');
    if (!SHA256.test(activeNonce)) fail();
    activeRuntime = await launchRuntime(
      automationBundle,
      { port: activePort, nonce: activeNonce, legacyPort: activeLegacyPort },
      signal,
    );
    activeInventory = await waitForExactListener(activeRuntime, activePort, signal);
    if (!isDeepStrictEqual(listenerInventory(
      await activeRuntime.ledger.sample(),
      activeLegacyPort,
    ), { exact: 0, other: 1 })) fail();
    observed = await observePackagedMarkdown({
      expectedResourcePaths,
      port: activePort,
      signal,
    });
    const liveAfter = await activeRuntime.ledger.sample();
    if (liveAfter.length !== 1
      || liveAfter[0].executable !== automationBundle.hostPath
      || !isDeepStrictEqual(listenerInventory(liveAfter, activePort), { exact: 1, other: 0 })) fail();
  } catch (error) {
    failure = error;
  } finally {
    if (activeRuntime) {
      try {
        await terminateRuntime(activeRuntime);
        activeIsolateRemoved = activeRuntime.removed;
        listenerRemoved = activePort !== undefined && await canBind(activePort);
      } catch (error) {
        failure ??= error;
      }
    }
  }
  if (failure || productionListeners !== 0 || dormantListeners !== 0
    || !activeInventory || !observed || !activeIsolateRemoved || !listenerRemoved
    || activePort === undefined || activeNonce === undefined) fail();
  await revalidateBundle(productionBundle);
  await revalidateBundle(automationBundle);

  return assertAuthoritativeMarkdownEvidence({
    schemaVersion: 1,
    status: 'pass',
    identity: {
      sourceDigest,
      productionFingerprint: productionBundle.fingerprint,
      automationFingerprint: automationBundle.fingerprint,
      controlledDeltaSha256,
      sameFrozenSource: true,
    },
    driver: {
      productionHostileActivationListeners: productionListeners,
      dormantTwinListeners: dormantListeners,
      activatedTwinIpv4LoopbackListeners: activeInventory.exact,
      activatedTwinOtherListeners: activeInventory.other,
      randomHighPort: activePort >= ACTIVATION_PORT_MIN && activePort <= ACTIVATION_PORT_MAX,
      activationNonceValidated: SHA256.test(activeNonce),
      legacyEnvPortListeners: 0,
      legacyWebdriverPortIgnored: true,
      webdriverSessions: 1,
    },
    bundle: bundleEvidence,
    dom: observed.dom,
    browser: observed.browser,
    native: observed.native,
    cleanup: {
      webdriverSessionDeleted: observed.webdriverSessionDeleted,
      listenerRemoved,
      runnerIsolatesRemoved: true,
      bundlesRevalidated: true,
    },
  });
}

export async function runAuthoritativeA26Command() {
  const cutoffs = installParentCutoffs();
  try {
    const result = await runOwnedCommand({
      command: process.execPath,
      args: [resolve(root, 'scripts/package-spike.mjs'), '--authoritative-a26'],
      cwd: root,
      env: {
        HOME: process.env.HOME,
        PATH: process.env.PATH,
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
      },
      timeoutMs: 40 * 60_000,
      maxOutputBytes: MAX_EVIDENCE_BYTES,
      signal: cutoffs.signal,
      label: 'A.26 packaged Markdown command',
    });
    if (result.status !== 0 || result.signal !== null || result.stderr.length !== 0) fail();
    return parsePackagedMarkdownEvidence(result.stdout);
  } finally {
    cutoffs.dispose();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const evidence = await runAuthoritativeA26Command();
    process.stdout.write(`${JSON.stringify(evidence)}\n`);
  } catch {
    process.stderr.write('A.26 packaged Markdown probe rejected\n');
    process.exitCode = 1;
  }
}
