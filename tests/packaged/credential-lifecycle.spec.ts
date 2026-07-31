import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { link, lstat, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { createServer } from 'node:net';
import { describe, expect, it } from 'vitest';
import { PiCredentialStore } from '../../sidecar/src/credentials/store-proxy';
import { A23CredentialLifecycle } from '../../sidecar/src/spike/credential-lifecycle';
import type { HostRequestClient } from '../../sidecar/src/bridge/host-requests';
import type {
  CredentialHostGeneration,
  CredentialHostTransport,
} from '../../sidecar/src/bridge/host-requests';
import type {
  PublicCredential,
  PublicCredentialInfo,
} from '../../sidecar/src/pi/public-sdk';
import {
  ARCHITECTURE_VARIANT_DEFINITION_SHA256,
} from '../../scripts/architecture-gate-schema.mjs';
import {
  A23_CLEANUP_HELPER_BUILD_ARGUMENT_TAIL,
  A23_CLEANUP_HELPER_BUILD_RECIPE_SHA256,
  A23_PROCESS_TOPOLOGY,
  assertA23CleanupHelperIdentity,
  assertAcceptedCandidateProcess,
  credentialProbeSandbox,
  createA23CleanupHelperIdentity,
  parseAccessibilityControlState,
  parseNativeBoundaryEvidence,
  parsePackagedCredentialEvidence,
  parsePrivateChannelTranscript,
  readPublishedLifecycleResult,
  readStablePrivateFile,
  terminateUnledgeredRoot,
  waitForFinalAccessibilityState,
} from '../../scripts/run-packaged-credential-probe.mjs';

const repositoryRoot = resolve(import.meta.dirname, '../..');
const PRODUCTION_SERVICE = 'au.com.piui.desktop.credentials';
const SEALED_CANDIDATE_FINGERPRINT = '0123456789abcdef'.repeat(4);
const CREDENTIAL_VARIANT_SHA256 =
  ARCHITECTURE_VARIANT_DEFINITION_SHA256['credential-twin'];
const SAFE_TOP_LEVEL_KEYS = [
  'cleanup',
  'execution',
  'keychain',
  'lifecycle',
  'nativeSheet',
  'namespaceIsolation',
  'privateChannel',
  'publicSurfaces',
  'realPackagedLifecycle',
  'schemaVersion',
  'status',
] as const;

function runtimeCanary(): string {
  return `PIUI_A23_${randomBytes(24).toString('hex')}`;
}

function isolatedNamespace(): string {
  return `a23-${randomBytes(16).toString('hex')}`;
}

function exactKeys(value: unknown, expected: readonly string[]): asserts value is Record<string, unknown> {
  expect(value).not.toBeNull();
  expect(typeof value).toBe('object');
  expect(Array.isArray(value)).toBe(false);
  expect(Object.keys(value as object).sort()).toEqual([...expected].sort());
}

function containsExactCanary(value: unknown, canary: string): boolean {
  if (typeof value === 'string') return value === canary;
  if (Array.isArray(value)) return value.some((entry) => containsExactCanary(entry, canary));
  if (value && typeof value === 'object') {
    return Object.values(value).some((entry) => containsExactCanary(entry, canary));
  }
  return false;
}

function clearCredentialFieldsLogically(credential: PublicCredential | undefined): void {
  if (!credential || typeof credential !== 'object') return;
  if ('access' in credential) credential.access = '';
  if ('refresh' in credential) credential.refresh = '';
  if ('expires' in credential) credential.expires = 0;
}

type Method = 'credential.get' | 'credential.set' | 'credential.remove';

class InMemoryPrivateCredentialHost implements CredentialHostTransport {
  readonly credentialGeneration: CredentialHostGeneration = Object.freeze({
    signal: new AbortController().signal,
  });
  readonly trace: Method[] = [];
  private credential: PublicCredential | undefined;
  private lastLogicallyClearedCredential: PublicCredential | undefined;
  private logicalCredentialClears = 0;
  privateCanaryObservations = 0;

  constructor(
    namespace: string,
    credential: PublicCredential,
    private readonly canary: string,
  ) {
    if (!/^a23-[0-9a-f]{32}$/.test(namespace) || namespace === PRODUCTION_SERVICE) {
      throw new Error('isolated-test-namespace-required');
    }
    this.credential = structuredClone(credential);
  }

  private clearStoredCredentialLogically(): void {
    if (!this.credential) return;
    clearCredentialFieldsLogically(this.credential);
    this.lastLogicallyClearedCredential = structuredClone(this.credential);
    this.logicalCredentialClears += 1;
  }

  async get(_providerId: string): Promise<PublicCredential | undefined> {
    this.trace.push('credential.get');
    const credential = this.credential ? structuredClone(this.credential) : undefined;
    if (containsExactCanary(credential, this.canary)) this.privateCanaryObservations += 1;
    return credential;
  }

  async list(): Promise<readonly PublicCredentialInfo[]> {
    throw new Error('credential-lifecycle-list-not-permitted');
  }

  async set(_providerId: string, credential: PublicCredential): Promise<void> {
    this.trace.push('credential.set');
    if (containsExactCanary(credential, this.canary)) this.privateCanaryObservations += 1;
    this.clearStoredCredentialLogically();
    this.credential = structuredClone(credential);
  }

  async remove(_providerId: string): Promise<void> {
    this.trace.push('credential.remove');
    this.clearStoredCredentialLogically();
    this.credential = undefined;
  }

  hasCredential(): boolean {
    return this.credential !== undefined;
  }

  lastLogicallyClearedCredentialSnapshot(): Readonly<PublicCredential> | undefined {
    return this.lastLogicallyClearedCredential
      ? structuredClone(this.lastLogicallyClearedCredential)
      : undefined;
  }

  logicalCleanupCount(): number {
    return this.logicalCredentialClears;
  }
}

type SafeCredentialEvidence = Readonly<{
  schemaVersion: 1;
  status: 'groundwork-pass';
  execution: 'in-memory-only';
  namespaceIsolation: 'test-only-required';
  nativeSheet: 'not-run';
  keychain: 'not-run';
  realPackagedLifecycle: 'not-run-in-focused-test';
  lifecycle: Readonly<{
    get: 1;
    refresh: 1;
    logoutDelete: 1;
    postDeleteMiss: 1;
  }>;
  privateChannel: Readonly<{
    authorisedPathCount: 'not-observed';
    canaryObservations: 'not-observed';
  }>;
  publicSurfaces: Readonly<{
    webViewState: 'not-observed';
    webViewEvents: 'not-observed';
    logs: 'not-observed';
    crashArtefacts: 'not-observed';
    ordinaryAppData: 'not-observed';
  }>;
  cleanup: Readonly<{
    attempted: true;
    succeeded: true;
    postDeleteMissing: true;
    logicalCredentialFieldsCleared: true;
    memoryZeroisation: 'not-claimed';
  }>;
}>;

function assertSafeCredentialEvidence(value: unknown): asserts value is SafeCredentialEvidence {
  exactKeys(value, SAFE_TOP_LEVEL_KEYS);
  exactKeys(value.lifecycle, ['get', 'logoutDelete', 'postDeleteMiss', 'refresh']);
  exactKeys(value.privateChannel, ['authorisedPathCount', 'canaryObservations']);
  exactKeys(value.publicSurfaces, [
    'crashArtefacts',
    'logs',
    'ordinaryAppData',
    'webViewEvents',
    'webViewState',
  ]);
  exactKeys(value.cleanup, [
    'attempted',
    'logicalCredentialFieldsCleared',
    'memoryZeroisation',
    'postDeleteMissing',
    'succeeded',
  ]);
  expect(value).toEqual({
    schemaVersion: 1,
    status: 'groundwork-pass',
    execution: 'in-memory-only',
    namespaceIsolation: 'test-only-required',
    nativeSheet: 'not-run',
    keychain: 'not-run',
    realPackagedLifecycle: 'not-run-in-focused-test',
    lifecycle: { get: 1, refresh: 1, logoutDelete: 1, postDeleteMiss: 1 },
    privateChannel: { authorisedPathCount: 'not-observed', canaryObservations: 'not-observed' },
    publicSurfaces: {
      webViewState: 'not-observed',
      webViewEvents: 'not-observed',
      logs: 'not-observed',
      crashArtefacts: 'not-observed',
      ordinaryAppData: 'not-observed',
    },
    cleanup: {
      attempted: true,
      succeeded: true,
      postDeleteMissing: true,
      logicalCredentialFieldsCleared: true,
      memoryZeroisation: 'not-claimed',
    },
  });
}

async function runInMemoryLifecycle(canary: string): Promise<{
  evidence: SafeCredentialEvidence;
  trace: readonly Method[];
}> {
  const providerId = 'a23.fixture-provider';
  const host = new InMemoryPrivateCredentialHost(
    isolatedNamespace(),
    { type: 'oauth', access: canary, refresh: 'fixture-refresh', expires: 0 },
    canary,
  );
  const store = new PiCredentialStore(host);
  let logoutDeleteCompleted = false;
  let cleanupAttempted = false;
  let cleanupSucceeded = false;

  try {
    let initial = await store.read(providerId);
    if (!containsExactCanary(initial, canary)) throw new Error('credential-lifecycle-read-failed');
    clearCredentialFieldsLogically(initial);
    initial = undefined;

    let refreshed = await store.modify(providerId, async (current) => {
      if (!current || current.type !== 'oauth' || !containsExactCanary(current, canary)) {
        throw new Error('credential-lifecycle-refresh-failed');
      }
      return { ...current, expires: 1_800_000_000_000 };
    });
    if (!containsExactCanary(refreshed, canary)) throw new Error('credential-lifecycle-refresh-failed');
    clearCredentialFieldsLogically(refreshed);
    refreshed = undefined;

    cleanupAttempted = true;
    await store.delete(providerId);
    logoutDeleteCompleted = true;
    cleanupSucceeded = !host.hasCredential();
    if (await store.read(providerId) !== undefined) throw new Error('credential-lifecycle-delete-failed');
  } finally {
    if (!logoutDeleteCompleted) {
      cleanupAttempted = true;
      try {
        await store.delete(providerId);
        cleanupSucceeded = !host.hasCredential();
      } catch {
        cleanupSucceeded = false;
      }
    }
  }

  const logicallyClearedCredential = host.lastLogicallyClearedCredentialSnapshot();
  if (!cleanupAttempted || !cleanupSucceeded || host.privateCanaryObservations !== 3
    || host.logicalCleanupCount() < 2 || !logicallyClearedCredential
    || logicallyClearedCredential.access !== '' || logicallyClearedCredential.refresh !== ''
    || logicallyClearedCredential.expires !== 0) {
    throw new Error('credential-lifecycle-evidence-rejected');
  }
  const evidence: SafeCredentialEvidence = Object.freeze({
    schemaVersion: 1,
    status: 'groundwork-pass',
    execution: 'in-memory-only',
    namespaceIsolation: 'test-only-required',
    nativeSheet: 'not-run',
    keychain: 'not-run',
    realPackagedLifecycle: 'not-run-in-focused-test',
    lifecycle: Object.freeze({ get: 1, refresh: 1, logoutDelete: 1, postDeleteMiss: 1 }),
    privateChannel: Object.freeze({
      authorisedPathCount: 'not-observed',
      canaryObservations: 'not-observed',
    }),
    publicSurfaces: Object.freeze({
      webViewState: 'not-observed',
      webViewEvents: 'not-observed',
      logs: 'not-observed',
      crashArtefacts: 'not-observed',
      ordinaryAppData: 'not-observed',
    }),
    cleanup: Object.freeze({
      attempted: true,
      succeeded: true,
      postDeleteMissing: true,
      logicalCredentialFieldsCleared: true,
      memoryZeroisation: 'not-claimed',
    }),
  });
  return { evidence, trace: Object.freeze([...host.trace]) };
}

function rawFrame(direction: 'S' | 'H', envelope: object): Buffer {
  const body = Buffer.from(`${JSON.stringify(envelope)}\n`, 'utf8');
  return Buffer.concat([Buffer.from(`${direction} ${body.length}\n`, 'ascii'), body]);
}

function privateTranscriptFrames(canary: string): Buffer[] {
  const requests = [
    { method: 'credential.get', providerId: 'a23.fixture-provider' },
    { method: 'credential.get', providerId: 'a23.fixture-provider' },
    {
      method: 'credential.set',
      providerId: 'a23.fixture-provider',
      credential: { type: 'api_key', key: canary, env: { PIUI_A23_REFRESHED: '1' } },
    },
    { method: 'credential.get', providerId: 'a23.fixture-provider' },
    { method: 'credential.remove', providerId: 'a23.fixture-provider' },
    { method: 'credential.get', providerId: 'a23.fixture-provider' },
  ];
  const responses = [
    { found: true, credential: { type: 'api_key', key: canary } },
    { found: true, credential: { type: 'api_key', key: canary } },
    { stored: true },
    {
      found: true,
      credential: { type: 'api_key', key: canary, env: { PIUI_A23_REFRESHED: '1' } },
    },
    { removed: true },
    { found: false },
  ];
  const frames: Buffer[] = [];
  for (let index = 0; index < requests.length; index += 1) {
    frames.push(rawFrame('S', {
      version: 1,
      kind: 'host-request',
      id: `request-${index}`,
      sequence: 10 + index,
      payload: requests[index],
    }));
    frames.push(rawFrame('H', {
      version: 1,
      kind: 'host-response',
      id: `response-${index}`,
      correlationId: `request-${index}`,
      sequence: 20 + index,
      payload: responses[index],
    }));
  }
  return frames;
}

function framedTranscript(frames: readonly Buffer[]): Buffer {
  const header = Buffer.from('PIUI-A23-RAW-V1\n', 'ascii');
  try {
    return Buffer.concat([header, ...frames]);
  } finally {
    header.fill(0);
  }
}

function privateTranscript(canary: string): Buffer {
  const frames = privateTranscriptFrames(canary);
  try {
    return framedTranscript(frames);
  } finally {
    for (const frame of frames) frame.fill(0);
  }
}

function nativeBoundaryFixture(runNonce: string, candidatePid: number, hostIdentity: {
  dev: number;
  ino: number;
  bytes: number;
}): Buffer {
  const records = [
    {
      schemaVersion: 1,
      record: 'header',
      runNonce,
      processId: candidatePid,
      executable: {
        device: hostIdentity.dev,
        inode: hostIdentity.ino,
        bytes: hostIdentity.bytes,
      },
      coverage: {
        invokeInputs: 'all-native-handler-entries',
        invokeResults: 'closed-a23-command-set',
        rustEvents: 'webview-queue-admission',
        documentDom: 'not-claimed',
        webStorage: 'not-claimed',
        arbitraryJavascriptHeap: 'not-claimed',
      },
    },
    { schemaVersion: 1, record: 'invoke-entry', command: 'sidecar_start', input: {} },
    {
      schemaVersion: 1,
      record: 'invoke-result',
      command: 'sidecar_start',
      result: { running: true, failed: false },
    },
    {
      schemaVersion: 1,
      record: 'invoke-entry',
      command: 'present_credential_sheet',
      input: {
        request: {
          providerId: 'a23.fixture-provider',
          providerLabel: 'Example provider',
          accountLabel: 'Architecture gate account',
        },
      },
    },
    {
      schemaVersion: 1,
      record: 'invoke-result',
      command: 'present_credential_sheet',
      result: {
        accountLabel: 'Architecture gate account',
        credentialReference: 'credential-fixture',
        savedState: 'saved',
        validationState: 'saved-not-validated',
      },
    },
    {
      schemaVersion: 1,
      record: 'invoke-entry',
      command: 'credential_lifecycle_status',
      input: {},
    },
    {
      schemaVersion: 1,
      record: 'invoke-result',
      command: 'credential_lifecycle_status',
      result: { state: 'passed' },
    },
  ].map((record, index) => ({ ...record, sequence: index + 1 }));
  return Buffer.from(`${records.map((record) => JSON.stringify(record)).join('\n')}\n`, 'utf8');
}

describe.sequential('A.23 credential lifecycle focused contracts', () => {
  it('specifies get → refresh → logout/delete using only the private in-memory host', async () => {
    const canary = runtimeCanary();
    const { evidence, trace } = await runInMemoryLifecycle(canary);
    expect(trace).toEqual([
      'credential.get',
      'credential.get',
      'credential.set',
      'credential.remove',
      'credential.get',
    ]);
    assertSafeCredentialEvidence(evidence);
    const serialised = JSON.stringify(evidence);
    expect(containsExactCanary(serialised, canary)).toBe(false);
    expect(serialised.includes(providerIdForLeakGuard())).toBe(false);
    expect(serialised).not.toMatch(/[/\\](?:Users|home|private|tmp)[/\\]/);
  });

  it('strictly parses the exact ordered raw native transcript and rejects malformed sequences', () => {
    const canaryText = runtimeCanary();
    const canary = Buffer.from(canaryText, 'utf8');
    const transcript = privateTranscript(canaryText);
    try {
      expect(parsePrivateChannelTranscript(transcript, canary)).toEqual({
        frames: 12,
        canaryOccurrences: 4,
      });
      const extra = rawFrame('S', {
        version: 1,
        kind: 'host-request',
        id: 'request-extra',
        sequence: 99,
        payload: { method: 'credential.get', providerId: 'a23.fixture-provider' },
      });
      const invalid = Buffer.concat([transcript, extra]);
      try {
        expect(() => parsePrivateChannelTranscript(invalid, canary)).toThrow();
      } finally {
        invalid.fill(0);
        extra.fill(0);
      }

      const reorderedFrames = privateTranscriptFrames(canaryText);
      const reordered = framedTranscript([
        reorderedFrames[2], reorderedFrames[3],
        reorderedFrames[0], reorderedFrames[1],
        ...reorderedFrames.slice(4),
      ]);
      try {
        expect(() => parsePrivateChannelTranscript(reordered, canary)).toThrow();
      } finally {
        reordered.fill(0);
        for (const frame of reorderedFrames) frame.fill(0);
      }

      const missingFrames = privateTranscriptFrames(canaryText);
      const missing = framedTranscript(missingFrames.slice(0, -1));
      try {
        expect(() => parsePrivateChannelTranscript(missing, canary)).toThrow();
      } finally {
        missing.fill(0);
        for (const frame of missingFrames) frame.fill(0);
      }

      const wrongCanaryFrames = privateTranscriptFrames(canaryText);
      wrongCanaryFrames[1].fill(0);
      wrongCanaryFrames[1] = rawFrame('H', {
        version: 1,
        kind: 'host-response',
        id: canaryText,
        correlationId: 'request-0',
        sequence: 20,
        payload: {
          found: true,
          credential: { type: 'api_key', key: 'not-the-canary' },
        },
      });
      const wrongCanaryField = framedTranscript(wrongCanaryFrames);
      try {
        expect(() => parsePrivateChannelTranscript(wrongCanaryField, canary)).toThrow();
      } finally {
        wrongCanaryField.fill(0);
        for (const frame of wrongCanaryFrames) frame.fill(0);
      }

      const replayedFrames = privateTranscriptFrames(canaryText);
      replayedFrames[10].fill(0);
      replayedFrames[10] = Buffer.from(replayedFrames[0]);
      const replayed = framedTranscript(replayedFrames);
      try {
        expect(() => parsePrivateChannelTranscript(replayed, canary)).toThrow();
      } finally {
        replayed.fill(0);
        for (const frame of replayedFrames) frame.fill(0);
      }
    } finally {
      canary.fill(0);
      transcript.fill(0);
    }
  });

  it('binds native invoke evidence to the run nonce, PID and accepted executable identity', () => {
    const runNonce = '0123456789abcdef'.repeat(2);
    const candidatePid = 4242;
    const hostIdentity = { dev: 7, ino: 11, bytes: 16_384 };
    const evidence = nativeBoundaryFixture(runNonce, candidatePid, hostIdentity);
    try {
      expect(parseNativeBoundaryEvidence(
        evidence,
        runNonce,
        candidatePid,
        hostIdentity,
      )).toEqual({ records: 7, events: 0 });
      expect(() => parseNativeBoundaryEvidence(
        evidence,
        'f'.repeat(32),
        candidatePid,
        hostIdentity,
      )).toThrow();
      expect(() => parseNativeBoundaryEvidence(
        evidence,
        runNonce,
        candidatePid + 1,
        hostIdentity,
      )).toThrow();
    } finally {
      evidence.fill(0);
    }
  });

  it('accepts only a closed sheet with one disabled visible Finalising control and status', () => {
    const fixture = Buffer.from([
      'AXHeading\tTest native API-key entry\tunknown',
      'AXButton\tFinalising…\tfalse',
      'AXStaticText\tFinalising external cleanup and credential leak checks.\tunknown',
      '',
    ].join('\n'), 'utf8');
    expect(parseAccessibilityControlState(fixture)).toEqual({
      state: 'final',
      controls: 3,
      finalisingButtons: 1,
      finalisingStatuses: 1,
    });
    expect(() => parseAccessibilityControlState(Buffer.from(
      fixture.toString('utf8').replace('Finalising…\tfalse', 'Finalising…\ttrue'),
    ))).toThrow();
    expect(() => parseAccessibilityControlState(Buffer.from(
      `${fixture.toString('utf8')}AXButton\tInsert test value\ttrue\n`,
    ))).toThrow();
    expect(() => parseAccessibilityControlState(Buffer.from(
      'AXButton\tFinalising…\tfalse\n',
    ))).toThrow();
  });

  it('boundedly transitions from exact Verifying accessibility state to Finalising', async () => {
    const verifying = Buffer.from([
      'AXButton\tVerifying credential lifecycle…\tfalse',
      'AXStaticText\tVerifying the packaged credential lifecycle.\tunknown',
      '',
    ].join('\n'));
    const finalising = Buffer.from([
      'AXButton\tFinalising…\tfalse',
      'AXStaticText\tFinalising external cleanup and credential leak checks.\tunknown',
      '',
    ].join('\n'));
    expect(parseAccessibilityControlState(verifying)).toEqual({ state: 'pending', controls: 2 });
    const snapshots = [Buffer.from(verifying), Buffer.from(finalising)];
    let identityChecks = 0;
    const accepted = await waitForFinalAccessibilityState({
      capture: async () => snapshots.shift() ?? Buffer.from('invalid'),
      assertIdentity: async () => { identityChecks += 1; },
      pause: async () => undefined,
    });
    try {
      expect(accepted.equals(finalising)).toBe(true);
      expect(identityChecks).toBe(3);
    } finally {
      accepted.fill(0);
      verifying.fill(0);
      finalising.fill(0);
      for (const snapshot of snapshots) snapshot.fill(0);
    }
  });

  it('treats only the exact two-link lifecycle publication transition as pending', async () => {
    const root = await mkdtemp(resolve(tmpdir(), 'piui-a23-result-reader-'));
    const resultPath = resolve(root, 'lifecycle-result.json');
    const pendingPath = resolve(root, 'lifecycle-result.json.pending');
    const result = {
      schemaVersion: 1,
      status: 'pass',
      initialGet: 1,
      refreshReads: 1,
      refreshWrites: 1,
      postRefreshGet: 1,
      logoutDelete: 1,
      postDeleteMiss: 1,
      privateChannelQuiesced: true,
    } as const;
    try {
      await writeFile(pendingPath, `${JSON.stringify(result)}\n`, { mode: 0o600 });
      await link(pendingPath, resultPath);
      await expect(readStablePrivateFile(resultPath, 512)).rejects.toThrow();
      await expect(readPublishedLifecycleResult(resultPath)).resolves.toBeUndefined();
      await rm(pendingPath);
      await expect(readPublishedLifecycleResult(resultPath)).resolves.toEqual(result);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('bounds fallback deletion when failure publication and the private host both stall', async () => {
    const root = await mkdtemp(resolve(tmpdir(), 'piui-a23-lifecycle-failure-'));
    const triggerPath = resolve(root, 'credential-saved.trigger');
    const resultPath = resolve(root, 'lifecycle-result.json');
    const generation = new AbortController();
    try {
      await writeFile(triggerPath, 'ready\n', { mode: 0o600 });
      await writeFile(resultPath, 'occupied\n', { mode: 0o600 });
      const stalledHost = {
        credentialGeneration: Object.freeze({ signal: generation.signal }),
        get: async () => undefined,
        list: async () => [],
        set: async () => undefined,
        remove: () => new Promise<void>(() => undefined),
      } as unknown as HostRequestClient;
      const started = Date.now();
      await expect(new A23CredentialLifecycle(resultPath, triggerPath).run(stalledHost))
        .rejects.toThrow('credential-lifecycle-rejected');
      expect(Date.now() - started).toBeLessThan(2_500);
    } finally {
      generation.abort();
      await rm(root, { recursive: true, force: true });
    }
  });

  it('cleans the in-memory credential in finally when refresh fails', async () => {
    const canary = runtimeCanary();
    const host = new InMemoryPrivateCredentialHost(
      isolatedNamespace(),
      { type: 'oauth', access: canary, refresh: 'fixture-refresh', expires: 0 },
      canary,
    );
    const store = new PiCredentialStore(host);
    let cleanupAttempted = false;
    let cleanupSucceeded = false;
    await expect((async () => {
      try {
        await store.modify('a23.failure-provider', async () => {
          throw new Error('injected-refresh-failure');
        });
      } finally {
        cleanupAttempted = true;
        await store.delete('a23.failure-provider');
        cleanupSucceeded = !host.hasCredential();
      }
    })()).rejects.toThrow('injected-refresh-failure');
    expect({ cleanupAttempted, cleanupSucceeded }).toEqual({
      cleanupAttempted: true,
      cleanupSucceeded: true,
    });
    expect(host.trace).toEqual(['credential.get', 'credential.remove']);
    expect(host.hasCredential()).toBe(false);
  });

  it('requires a unique test namespace and cannot select the production service', () => {
    const canary = runtimeCanary();
    const credential: PublicCredential = {
      type: 'oauth', access: canary, refresh: 'fixture-refresh', expires: 0,
    };
    expect(() => new InMemoryPrivateCredentialHost(PRODUCTION_SERVICE, credential, canary))
      .toThrow('isolated-test-namespace-required');
    expect(() => new InMemoryPrivateCredentialHost('shared-test', credential, canary))
      .toThrow('isolated-test-namespace-required');
    expect(() => new InMemoryPrivateCredentialHost(isolatedNamespace(), credential, canary))
      .not.toThrow();
  });

  it('accepts only the exact path-free, secret-free evidence schema', async () => {
    const canary = runtimeCanary();
    const { evidence } = await runInMemoryLifecycle(canary);
    assertSafeCredentialEvidence(evidence);
    expect(containsExactCanary(evidence, canary)).toBe(false);
    expect(() => assertSafeCredentialEvidence({ ...evidence, privatePath: '/private/fixture' })).toThrow();
    expect(() => assertSafeCredentialEvidence({
      ...evidence,
      keychain: 'pass',
      nativeSheet: 'pass',
    })).toThrow();
  });

  it('guards the existing Rust in-memory seam and ignored real-Keychain gates', () => {
    const proxy = readFileSync(resolve(repositoryRoot, 'src-tauri/src/credentials/proxy.rs'), 'utf8');
    const keychain = readFileSync(resolve(repositoryRoot, 'src-tauri/src/credentials/keychain.rs'), 'utf8');
    const proxyTests = readFileSync(resolve(repositoryRoot, 'src-tauri/src/credentials/proxy_tests.rs'), 'utf8');
    const keychainTests = readFileSync(resolve(repositoryRoot, 'src-tauri/tests/keychain.rs'), 'utf8');
    const sheetTests = readFileSync(resolve(repositoryRoot, 'src-tauri/tests/credential_sheet.rs'), 'utf8');

    expect(proxy).toMatch(/#\[cfg\(test\)\]\s*#\[derive\(Default\)\]\s*struct DispatcherMemoryRepository/);
    expect(proxy).toMatch(/#\[cfg\(test\)\][\s\S]{0,160}in_memory_for_dispatcher_test/);
    expect(proxy).toContain('pub(crate) struct PrivateHostResponse');
    expect(proxy).not.toMatch(/pub struct PrivateHostResponse/);
    expect(keychain).toContain('pub fn for_tests(namespace: &str)');
    expect(keychain.match(/\.test\.\{namespace\}/g)).toHaveLength(3);
    expect(keychain).toContain('service: SERVICE_NAMESPACE.into()');
    expect(proxyTests).toContain('credential_proxy_in_memory_get_refresh_logout_delete_lifecycle');
    expect(proxyTests).toContain('credential_proxy_real_macos_keychain_restart_lifecycle');
    expect(proxyTests).toMatch(/#\[ignore = "requires an interactive macOS login Keychain; run serially"\]/);
    expect(keychainTests).toMatch(/#\[ignore = "requires an interactive macOS login Keychain"\]/);
    expect(sheetTests).toMatch(/#\[ignore = "requires an interactive macOS login Keychain"\]/);
  });

  it('maps the formal command to the isolated packaged runner and retains a separate refusal utility', () => {
    const packageDocument = JSON.parse(readFileSync(resolve(repositoryRoot, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(packageDocument.scripts['spike:packaged:credentials'])
      .toBe('node scripts/package-spike.mjs --authoritative-a23');
    const cargo = readFileSync(resolve(repositoryRoot, 'src-tauri/Cargo.toml'), 'utf8');
    const runner = readFileSync(
      resolve(repositoryRoot, 'scripts/run-packaged-credential-probe.mjs'),
      'utf8',
    );
    const nativeCommand = readFileSync(
      resolve(repositoryRoot, 'src-tauri/src/commands/credentials.rs'),
      'utf8',
    );
    const appHost = readFileSync(resolve(repositoryRoot, 'src-tauri/src/lib.rs'), 'utf8');
    const bridge = readFileSync(
      resolve(repositoryRoot, 'src-tauri/src/commands/bridge.rs'),
      'utf8',
    );
    const platformSheet = readFileSync(
      resolve(repositoryRoot, 'src-tauri/src/platform/macos/credential_sheet.rs'),
      'utf8',
    );
    const lifecycle = readFileSync(
      resolve(repositoryRoot, 'sidecar/src/spike/credential-lifecycle.ts'),
      'utf8',
    );
    const sidecarEntry = readFileSync(resolve(repositoryRoot, 'sidecar/src/index.ts'), 'utf8');
    const sidecarRuntime = readFileSync(resolve(repositoryRoot, 'sidecar/src/runtime.ts'), 'utf8');
    expect(cargo).toContain('a23-credential-test = []');
    expect(cargo).toContain('required-features = ["a23-credential-test"]');
    expect(runner).toContain("stdio: ['ignore', stdout, stderr, 'ignore', 'ignore', 'ignore', 'pipe']");
    expect(runner).toContain("name of candidate is \"Insert test value\"");
    expect(runner.match(/await assertPrivateExecutableLease\(helper\);/g)).toHaveLength(4);
    expect(runner).toContain('private-held-copy-rechecked-and-keychain-sandboxed');
    expect(runner).not.toContain("command: '/dev/fd/3'");
    expect(runner).not.toMatch(/\/usr\/bin\/(?:pbcopy|pbpaste)|pasteboardInput/);
    expect(runner).toContain('(deny mach-lookup\n');
    expect(runner).toContain('(global-name "com.apple.pasteboard.1")');
    expect(runner).toContain('canary?.fill(0)');
    expect(runner).toContain('scanSecretCanary({');
    expect(runner).not.toMatch(/PIUI_A23_CANARY|\.env\([^\n]*canary/i);
    expect(platformSheet).toMatch(
      /#\[cfg\(not\(feature = "a23-credential-test"\)\)\][\s\S]{0,240}fn paste_api_key/,
    );
    expect(platformSheet).toContain('Paste API key');
    expect(platformSheet).toContain('#[cfg(feature = "a23-credential-test")]');
    expect(platformSheet).toContain('Insert test value');
    expect(appHost).toContain('const A23_CANARY_FD: i32 = 6;');
    expect(appHost).toMatch(/is_fifo\(\)[\s\S]{0,80}is_socket\(\)/);
    expect(appHost).toContain('a23_canary_descriptor_rejects_regular_files');
    expect(nativeCommand).toContain('store_native_api_key(&provider_id, &account_label, secret)');
    expect(nativeCommand).toContain('signal_a23_credential_saved()?');
    expect(nativeCommand).toContain('publish_a23_native_failure()');
    expect(nativeCommand).toContain('make_a23_native_failure_observable(&_app)');
    expect(nativeCommand).toContain('super::bridge::bridge_stop_transport(state.inner())');
    expect(nativeCommand).not.toContain('let _ = publish_a23_native_failure()');
    expect(nativeCommand).toContain('lifecycle-result.json.native-pending');
    expect(appHost).toContain('credential_proxy.clone()');
    expect(appHost).toContain('CredentialSheetState::new_with_a23_secret');
    expect(bridge).toContain('new_with_credentials(paths, CredentialProxy::default())');
    expect(lifecycle).toContain('linkSync(pendingPath, resultPath)');
    expect(lifecycle).toContain('fdatasyncSync(descriptor)');
    expect(lifecycle).toContain('fsyncSync(directory)');
    expect(lifecycle).toContain("status: 'fail'");
    expect(sidecarEntry).toContain("import { runSidecar } from './runtime.js'");
    expect(sidecarEntry).toContain('runSidecar()');
    expect(sidecarRuntime).toContain('process.exit(terminalExitCode)');
    const privateRoot = runner.indexOf('const root = await privateWorkspace();');
    const cleanupTry = runner.indexOf('try {', privateRoot);
    const setupNonce = runner.indexOf('namespace = `a23-${randomBytes(16)', privateRoot);
    const workspaceCleanup = runner.indexOf('await removeWorkspace(root)', setupNonce);
    expect(privateRoot).toBeGreaterThan(-1);
    expect(cleanupTry).toBeGreaterThan(privateRoot);
    expect(setupNonce).toBeGreaterThan(cleanupTry);
    expect(workspaceCleanup).toBeGreaterThan(setupNonce);

    const refusal = spawnSync(process.execPath, [
      resolve(repositoryRoot, 'scripts/refuse-packaged-credential-lifecycle.mjs'),
    ], { encoding: 'utf8', env: {} });
    expect(refusal.status).toBe(1);
    expect(refusal.stderr).toBe('');
    expect(JSON.parse(refusal.stdout)).toEqual({
      schemaVersion: 1,
      status: 'refused',
      reasonCode: 'explicit-isolated-keychain-authorisation-required',
      keychainMutated: false,
      nativeSheetLaunched: false,
    });
  });

  it('statically binds Accessibility and every writable app surface to the accepted isolate', () => {
    const runner = readFileSync(
      resolve(repositoryRoot, 'scripts/run-packaged-credential-probe.mjs'),
      'utf8',
    );
    expect(runner).not.toContain('application process "${APP_PROCESS_NAME}"');
    expect(runner).not.toContain('exists application process');
    expect(runner.match(/whose unix id is candidatePID/g)).toHaveLength(2);
    expect(runner).toContain('if name of exactProcess is not "${APP_PROCESS_NAME}"');
    expect(runner).toContain('const candidatePid = child.pid;');
    const preClickIdentity = runner.indexOf(
      'A23_PROCESS_TOPOLOGY.HOST_ONLY,',
    );
    const automation = runner.indexOf("'A.23 native credential sheet automation'");
    const postClickIdentity = runner.indexOf(
      'A23_PROCESS_TOPOLOGY.HOST_AND_NODE,',
      automation,
    );
    expect(preClickIdentity).toBeGreaterThan(-1);
    expect(automation).toBeGreaterThan(preClickIdentity);
    expect(postClickIdentity).toBeGreaterThan(automation);
    expect(runner).toContain('cwd: runtime.working');
    expect(runner).toContain('TMPDIR: `${runtime.temporary}/`');
    expect(runner).toContain('(deny default)');
    expect(runner).not.toContain('(allow default)');
    expect(runner).toContain('(import "dyld-support.sb")');
    expect(runner).not.toContain('(import "system.sb")');
    expect(runner).not.toContain('(import "com.apple.corefoundation.sb")');
    expect(runner).not.toContain('(target same-sandbox)');
    expect(runner).not.toContain('(local-name-prefix "")');
    expect(runner).toContain(
      '(allow file-read* file-test-existence file-map-executable',
    );
    expect(runner).toContain('(deny appleevent-send)');
    expect(runner).toContain('(with-filter (process-path "/usr/bin/sandbox-exec")');
    expect(runner).toContain('(with-filter (process-path "${seatbeltPath(bundle.hostPath)}")');
    expect(runner).toContain('(with-filter (process-path "${seatbeltPath(bundle.nodePath)}")');
    expect(runner).toContain('(literal "/System/Library/OpenSSL/openssl.cnf")');
    expect(runner).toContain('credentialProbeSandbox(runtime, bundle)');
    expect(runner).toContain("'com.apple.securityd.xpc'");
    for (const key of ['artefacts', 'cache', 'config', 'data', 'home', 'temporary', 'working']) {
      expect(runner).toContain(`  '${key}',`);
    }
    expect(runner).toContain('roots: writableRuntimeRoots(runtime)');
    expect(runner).toContain('PIUI_A23_NATIVE_EVIDENCE_PATH: paths.nativeBoundary');
    expect(runner).toContain('const MAX_NATIVE_EVIDENCE_BYTES = 262_144;');
    expect(runner).toContain('parsePrivateChannelTranscript(transcriptBytes, canary)');
    expect(runner).toContain('parseNativeBoundaryEvidence(');
    expect(runner).toContain('await chmod(paths.capture, 0o400)');
    expect(runner).toContain('await chmod(paths.nativeBoundary, 0o400)');
    expect(runner).toContain(
      'authorised: [{ path: paths.capture, count: PRIVATE_CHANNEL_OCCURRENCES }]',
    );
    expect(runner).not.toMatch(/authorised:[^\n]*nativeBoundary/);
    const profile = credentialProbeSandbox({
      artefacts: '/tmp/a23/artefacts',
      cache: '/tmp/a23/cache',
      config: '/tmp/a23/config',
      data: '/tmp/a23/data',
      home: '/tmp/a23/home',
      temporary: '/tmp/a23/tmp',
      working: '/tmp/a23/cwd',
    }, {
      appPath: '/Applications/PIUI A23 Architecture Test.app',
      hostPath: '/Applications/PIUI A23 Architecture Test.app/Contents/MacOS/PIUI',
      nodePath: '/Applications/PIUI A23 Architecture Test.app/Contents/Resources/node',
    });
    expect(profile).toContain('(deny default)');
    expect(profile).not.toContain('(allow default)');
    expect(profile).toContain('(deny appleevent-send)');
    expect(profile).toContain('(deny mach-lookup\n');
    expect(profile).toContain('(global-name "com.apple.coreservices.appleevents")');
    expect(profile).toContain('(global-name "com.apple.pasteboard.1")');
    expect(profile).toContain('(global-name "com.apple.pbs.fetch_services")');
    expect(profile).not.toMatch(/com\.apple\.logd|com\.apple\.analyticsd/);
  });

  it('behaviourally fences sandbox reads, execution, Mach lookup and local network access', async () => {
    const runtime = {
      artefacts: '/tmp/a23/artefacts',
      cache: '/tmp/a23/cache',
      config: '/tmp/a23/config',
      data: '/tmp/a23/data',
      home: '/tmp/a23/home',
      temporary: '/tmp/a23/tmp',
      working: '/tmp/a23/cwd',
    };
    const behaviouralProfile = credentialProbeSandbox({
      ...runtime,
    }, {
      appPath: '/bin',
      hostPath: '/bin/cat',
      nodePath: '/bin/cat',
    });
    const allowedRead = spawnSync('/usr/bin/sandbox-exec', [
      '-p', behaviouralProfile, '/bin/cat', resolve(repositoryRoot, 'package.json'),
    ], { encoding: 'utf8' });
    expect(allowedRead.status).not.toBe(0);
    const acceptedBundleReadProfile = credentialProbeSandbox(runtime, {
      appPath: repositoryRoot,
      hostPath: '/bin/cat',
      nodePath: '/bin/cat',
    });
    const acceptedBundleRead = spawnSync('/usr/bin/sandbox-exec', [
      '-p', acceptedBundleReadProfile, '/bin/cat', resolve(repositoryRoot, 'package.json'),
    ], { encoding: 'utf8' });
    expect(acceptedBundleRead.status).toBe(0);
    const deniedHomeRead = spawnSync('/usr/bin/sandbox-exec', [
      '-p', behaviouralProfile, '/bin/cat', resolve(homedir(), '.zshrc'),
    ], { encoding: 'utf8' });
    expect(deniedHomeRead.status).not.toBe(0);
    expect(deniedHomeRead.stdout).toBe('');
    const deniedSystemConfigurationRead = spawnSync('/usr/bin/sandbox-exec', [
      '-p', behaviouralProfile, '/bin/cat', '/etc/hosts',
    ], { encoding: 'utf8' });
    expect(deniedSystemConfigurationRead.status).not.toBe(0);
    expect(deniedSystemConfigurationRead.stdout).toBe('');
    const deniedExecutable = spawnSync('/usr/bin/sandbox-exec', [
      '-p', behaviouralProfile, '/usr/bin/head', '-c', '1', '/usr/bin/cat',
    ], { encoding: 'utf8' });
    expect(deniedExecutable.status).not.toBe(0);
    expect(deniedExecutable.stdout).toBe('');

    const childExecutionProfile = credentialProbeSandbox(runtime, {
      appPath: repositoryRoot,
      hostPath: '/usr/bin/env',
      nodePath: '/bin/cat',
    });
    const exactChildExecution = spawnSync('/usr/bin/sandbox-exec', [
      '-p', childExecutionProfile, '/usr/bin/env', '-i', '/bin/cat',
      resolve(repositoryRoot, 'package.json'),
    ], { encoding: 'utf8' });
    expect(exactChildExecution.status).toBe(0);
    const unrelatedChildExecution = spawnSync('/usr/bin/sandbox-exec', [
      '-p', childExecutionProfile, '/usr/bin/env', '-i', '/usr/bin/head', '-c', '1',
      resolve(repositoryRoot, 'package.json'),
    ], { encoding: 'utf8' });
    expect(unrelatedChildExecution.status).not.toBe(0);
    expect(unrelatedChildExecution.stdout).toBe('');

    const stagedNode = resolve(
      repositoryRoot,
      'src-tauri/binaries/piui-node-aarch64-apple-darwin',
    );
    const nodeProbePath = existsSync(stagedNode) ? stagedNode : process.execPath;
    const nodeExecutionProfile = credentialProbeSandbox(runtime, {
      appPath: repositoryRoot,
      hostPath: '/usr/bin/env',
      nodePath: nodeProbePath,
    });
    const exactNodeExecution = spawnSync('/usr/bin/sandbox-exec', [
      '-p', nodeExecutionProfile, '/usr/bin/env', '-i', nodeProbePath, '-e',
      "process.stdout.write('node-ready\\n')",
    ], { encoding: 'utf8' });
    expect(exactNodeExecution.status).toBe(0);
    expect(exactNodeExecution.stdout).toBe('node-ready\n');
    const deniedNodeToHostReexec = spawnSync('/usr/bin/sandbox-exec', [
      '-p', nodeExecutionProfile, '/usr/bin/env', '-i', nodeProbePath, '-e',
      "process.execve('/usr/bin/env', ['env'], {})",
    ], { encoding: 'utf8' });
    expect(deniedNodeToHostReexec.status).toBeNull();
    expect(deniedNodeToHostReexec.signal).toBe('SIGABRT');
    expect(deniedNodeToHostReexec.stdout).toBe('');
    expect(deniedNodeToHostReexec.stderr).toContain('error code EPERM');

    const machProbeProfile = credentialProbeSandbox(runtime, {
      appPath: '/usr/bin',
      hostPath: '/usr/bin/notifyutil',
      nodePath: '/usr/bin/notifyutil',
    });
    const machLookupControl = spawnSync('/usr/bin/notifyutil', [
      '-g', 'au.com.piui.a23.sandbox.probe',
    ], { encoding: 'utf8' });
    expect(machLookupControl.status).toBe(0);
    expect(machLookupControl.stdout).toMatch(/au\.com\.piui\.a23\.sandbox\.probe 0/);
    const deniedMachLookup = spawnSync('/usr/bin/sandbox-exec', [
      '-p', machProbeProfile, '/usr/bin/notifyutil', '-g', 'au.com.piui.a23.sandbox.probe',
    ], { encoding: 'utf8' });
    expect(deniedMachLookup.status).toBe(0);
    expect(deniedMachLookup.stdout).toMatch(/Failed with code 9/);
    expect(deniedMachLookup.stderr).toBe('');

    const pasteboardProfile = credentialProbeSandbox(runtime, {
      appPath: '/usr/bin',
      hostPath: '/usr/bin/pbpaste',
      nodePath: '/usr/bin/pbpaste',
    });
    const deniedPasteboard = spawnSync('/usr/bin/sandbox-exec', [
      '-p', pasteboardProfile, '/usr/bin/pbpaste',
    ], { stdio: ['ignore', 'ignore', 'pipe'], encoding: 'utf8' });
    expect(deniedPasteboard.status).not.toBe(0);

    const server = createServer();
    await new Promise<void>((resolveListen, rejectListen) => {
      server.once('error', rejectListen);
      server.listen(0, '127.0.0.1', resolveListen);
    });
    try {
      const address = server.address();
      if (!address || typeof address === 'string') throw new Error('local-listener-unavailable');
      const unsandboxedConnection = spawnSync(
        '/usr/bin/nc',
        ['-z', '127.0.0.1', String(address.port)],
        { encoding: 'utf8', timeout: 5_000 },
      );
      expect(unsandboxedConnection.status).toBe(0);
      const networkProfile = credentialProbeSandbox(runtime, {
        appPath: '/usr/bin',
        hostPath: '/usr/bin/nc',
        nodePath: '/usr/bin/nc',
      });
      const deniedNetwork = spawnSync('/usr/bin/sandbox-exec', [
        '-p', networkProfile, '/usr/bin/nc', '-z', '127.0.0.1', String(address.port),
      ], { encoding: 'utf8', timeout: 5_000 });
      expect(deniedNetwork.status).not.toBe(0);
    } finally {
      await new Promise<void>((resolveClose, rejectClose) => {
        server.close((error) => (error ? rejectClose(error) : resolveClose()));
      });
    }
  });

  it('terminates an exact unreaped root without a naked process-group fallback', async () => {
    const child = spawn('/bin/sleep', ['30'], { detached: true, stdio: 'ignore' });
    await new Promise<void>((resolveSpawn, rejectSpawn) => {
      child.once('spawn', resolveSpawn);
      child.once('error', rejectSpawn);
    });
    await terminateUnledgeredRoot(child);
    expect(child.signalCode).toMatch(/SIGTERM|SIGKILL/);
    expect(() => process.kill(child.pid ?? 0, 0)).toThrow();

    const runner = readFileSync(
      resolve(repositoryRoot, 'scripts/run-packaged-credential-probe.mjs'),
      'utf8',
    );
    const terminationCatch = runner.indexOf('cleanupErrors.push(error);', runner.indexOf('if (ledger)'));
    const exactRootFallback = runner.indexOf('await terminateUnledgeredRoot(child);', terminationCatch);
    const identityRetry = runner.indexOf('await ledger.terminate();', exactRootFallback);
    expect(terminationCatch).toBeGreaterThan(-1);
    expect(exactRootFallback).toBeGreaterThan(terminationCatch);
    expect(identityRetry).toBeGreaterThan(exactRootFallback);
    expect(runner).not.toContain('terminateRecordedProcessGroupsWithoutObservation');
  });

  it('rejects eager or duplicate sidecars instead of weakening the accepted process topology', async () => {
    const topologyRoot = await mkdtemp(resolve(tmpdir(), 'piui-a23-topology-'));
    const hostPath = resolve(topologyRoot, 'PIUI-host');
    const nodePath = resolve(topologyRoot, 'PIUI-node');
    const hostBytes = Buffer.from('sealed-a23-host-fixture', 'utf8');
    try {
      await writeFile(hostPath, hostBytes, { mode: 0o700 });
      const host = await lstat(hostPath);
      const bundle = Object.freeze({
        fingerprint: SEALED_CANDIDATE_FINGERPRINT,
        hostPath,
        nodePath,
        hostIdentity: Object.freeze({
          dev: host.dev,
          ino: host.ino,
          bytes: host.size,
          sha256: createHash('sha256').update(hostBytes).digest('hex'),
        }),
      });
      const candidatePid = 41_001;
      const hostProcess = Object.freeze({ pid: candidatePid, executable: hostPath });
      const firstNode = Object.freeze({ pid: 41_002, executable: nodePath });
      const secondNode = Object.freeze({ pid: 41_003, executable: nodePath });
      const fakeLedger = (live: readonly object[]) => Object.freeze({
        rootPid: candidatePid,
        sample: async () => Object.freeze([...live]),
      });

      await expect(assertAcceptedCandidateProcess(
        fakeLedger([hostProcess]),
        candidatePid,
        bundle,
        A23_PROCESS_TOPOLOGY.HOST_ONLY,
      )).resolves.toBeUndefined();
      await expect(assertAcceptedCandidateProcess(
        fakeLedger([hostProcess, firstNode]),
        candidatePid,
        bundle,
        A23_PROCESS_TOPOLOGY.HOST_ONLY,
      )).rejects.toThrow('A.23 packaged credential probe rejected');
      await expect(assertAcceptedCandidateProcess(
        fakeLedger([hostProcess, firstNode]),
        candidatePid,
        bundle,
        A23_PROCESS_TOPOLOGY.HOST_AND_NODE,
      )).resolves.toBeUndefined();
      await expect(assertAcceptedCandidateProcess(
        fakeLedger([hostProcess, firstNode, secondNode]),
        candidatePid,
        bundle,
        A23_PROCESS_TOPOLOGY.HOST_AND_NODE,
      )).rejects.toThrow('A.23 packaged credential probe rejected');
    } finally {
      hostBytes.fill(0);
      await rm(topologyRoot, { recursive: true, force: true });
    }
  });

  it('uses native-owned bounded WebView boundary evidence and remains visibly finalising', () => {
    const recorder = readFileSync(
      resolve(repositoryRoot, 'src/architecture-gate/a23WebViewEvidence.ts'),
      'utf8',
    );
    const probe = readFileSync(
      resolve(repositoryRoot, 'src/architecture-gate/CredentialProbe.tsx'),
      'utf8',
    );
    const nativeEvidence = readFileSync(
      resolve(repositoryRoot, 'src-tauri/src/commands/a23_native_evidence.rs'),
      'utf8',
    );
    const commandModules = readFileSync(
      resolve(repositoryRoot, 'src-tauri/src/commands/mod.rs'),
      'utf8',
    );
    const appHost = readFileSync(resolve(repositoryRoot, 'src-tauri/src/lib.rs'), 'utf8');
    const process = readFileSync(
      resolve(repositoryRoot, 'src-tauri/src/supervisor/process.rs'),
      'utf8',
    );
    const dispatcher = readFileSync(
      resolve(repositoryRoot, 'src-tauri/src/supervisor/dispatcher.rs'),
      'utf8',
    );

    expect(recorder).toContain('not acceptance evidence');
    expect(probe).not.toMatch(/A23WebViewEvidenceRecorder|credential_webview_snapshot|\.capture\(\)/);
    expect(commandModules).toMatch(
      /#\[cfg\(feature = "a23-credential-test"\)\]\s*pub mod a23_native_evidence;/,
    );
    expect(commandModules).not.toContain('pub mod a23_webview;');
    expect(nativeEvidence).toContain('const MAX_EVIDENCE_BYTES: usize = 262_144;');
    expect(nativeEvidence).toContain('PIUI_A23_NATIVE_EVIDENCE_PATH');
    expect(nativeEvidence).toContain('.create_new(true)');
    expect(nativeEvidence).toContain('.custom_flags(libc::O_NOFOLLOW)');
    expect(nativeEvidence).toContain('"documentDom": "not-claimed"');
    expect(nativeEvidence).toContain('"webStorage": "not-claimed"');
    expect(nativeEvidence).toContain('"arbitraryJavascriptHeap": "not-claimed"');
    expect(appHost).toContain('state.record_invoke_entry(invoke.message.command()');
    expect(appHost).not.toContain('credential_webview_snapshot');
    expect(process).toMatch(/self\.write_bytes\(bytes\)\?;[\s\S]{0,240}record_host_response/);
    expect(process).not.toContain('.env("PIUI_A23_CAPTURE_PATH"');
    expect(dispatcher).toContain('writer.capture_a23_inbound_frame(&line)');
    expect(process).toContain('fn record_sidecar_frame(&self, raw: &[u8])');
    expect(process).not.toContain('record_if_credential_request');

    expect(probe).toContain("setBusyLabel('Finalising…')");
    expect(probe).toContain('await waitForExternalTermination(controller.signal)');
    expect(probe).toContain('activeProbe.current?.abort()');
    expect(probe).toContain('if (mounted.current && !runPackagedLifecycle)');
    expect(probe).not.toContain('Packaged credential lifecycle verified');
  });

  it('accepts only the exact path-free formal packaged evidence line', () => {
    const evidence = {
      schemaVersion: 1,
      status: 'pass',
      bundleFingerprint: SEALED_CANDIDATE_FINGERPRINT,
      execution: 'genuine-packaged-app',
      namespaceIsolation: 'isolated-test-keychain',
      nativeSheet: 'appkit-accessibility-driven',
      keychain: 'stored-refreshed-deleted',
      lifecycle: {
        initialGet: 1,
        refreshReads: 1,
        refreshWrites: 1,
        postRefreshGet: 1,
        logoutDelete: 1,
        postDeleteMiss: 1,
      },
      privateChannel: {
        authorisedFiles: 1,
        authorisedOccurrences: 4,
        unauthorisedOccurrences: 0,
        quiescedBeforeScan: true,
        rawFrames: 12,
      },
      publicSurfaces: {
        accessibilityControls: 'runner-owned-after-quiescence-scanned',
        nativeInvokeBoundary: 'all-entries-and-expected-results-scanned',
        rustEventBoundary: 'no-events-observed',
        documentDom: 'not-claimed',
        webStorage: 'not-claimed',
        arbitraryJavascriptHeap: 'not-claimed',
        logsAndCrashArtefacts: 'isolated-runtime-and-owned-stdio-only',
        ordinaryAppData: 'isolated-runtime-only',
      },
      cleanup: {
        credentialInputDescriptorClosed: true,
        helperExecutionResidual: 'private-held-copy-rechecked-and-keychain-sandboxed',
        keychainEntriesRemoved: true,
        keychainIndexRemoved: true,
        ownedProcessesRemoved: true,
        privateCapturesRemoved: true,
        runnerIsolateRemoved: true,
      },
      credentialCleanupHelper: {
        buildRecipeSha256: A23_CLEANUP_HELPER_BUILD_RECIPE_SHA256,
        executableSha256: '1'.repeat(64),
        executableSize: 1_048_576,
        helperSourceSha256: '3'.repeat(64),
        schemaVersion: 1,
        sourceDigest: '2'.repeat(64),
        toolchainContextSha256: '4'.repeat(64),
        toolchainReceiptSha256: '5'.repeat(64),
        variantDefinitionSha256: '6'.repeat(64),
      },
      generatedOutputsRemoved: true,
    } as const;
    const line = Buffer.from(`${JSON.stringify(evidence)}\n`);
    expect(parsePackagedCredentialEvidence(line, SEALED_CANDIDATE_FINGERPRINT))
      .toEqual(evidence);
    expect(() => parsePackagedCredentialEvidence(line)).toThrow();
    expect(() => parsePackagedCredentialEvidence(line, 'f'.repeat(64))).toThrow();
    expect(() => parsePackagedCredentialEvidence(Buffer.from(
      `${JSON.stringify({ ...evidence, privatePath: '/private/a23' })}\n`,
    ), SEALED_CANDIDATE_FINGERPRINT)).toThrow();
    expect(() => parsePackagedCredentialEvidence(Buffer.from(
      `${JSON.stringify({ ...evidence, bundleFingerprint: 'F'.repeat(64) })}\n`,
    ), SEALED_CANDIDATE_FINGERPRINT)).toThrow();
    expect(() => parsePackagedCredentialEvidence(Buffer.from(
      `${JSON.stringify({
        ...evidence,
        credentialCleanupHelper: {
          ...evidence.credentialCleanupHelper,
          buildRecipeSha256: '7'.repeat(64),
        },
      })}\n`,
    ), SEALED_CANDIDATE_FINGERPRINT)).toThrow();
    expect(() => parsePackagedCredentialEvidence(Buffer.from(
      `${JSON.stringify({
        ...evidence,
        credentialCleanupHelper: {
          ...evidence.credentialCleanupHelper,
          binaryPath: '/private/helper',
        },
      })}\n`,
    ), SEALED_CANDIDATE_FINGERPRINT)).toThrow();
    const { bundleFingerprint: _omittedFingerprint, ...missingFingerprint } = evidence;
    expect(() => parsePackagedCredentialEvidence(Buffer.from(
      `${JSON.stringify(missingFingerprint)}\n`,
    ), SEALED_CANDIDATE_FINGERPRINT)).toThrow();
    expect(() => parsePackagedCredentialEvidence(
      Buffer.from(JSON.stringify(evidence)),
      SEALED_CANDIDATE_FINGERPRINT,
    ))
      .toThrow();
  });

  it('binds the private cleanup executable to the exact source, recipe and toolchain', () => {
    expect(A23_CLEANUP_HELPER_BUILD_RECIPE_SHA256)
      .toBe('fbf5b1f2e49932477247528ccf2ae8df4aefd747c7d44be72e0ca5ee5ddb21c3');
    const helper = {
      sha256: '1'.repeat(64),
      size: 1_048_576,
    };
    const pnpmEntry = '/private/toolchain/pnpm.cjs';
    const variantOverlayPath = '/private/build/credential-overlay.json';
    const identity = createA23CleanupHelperIdentity({
      buildArguments: [
        pnpmEntry,
        ...A23_CLEANUP_HELPER_BUILD_ARGUMENT_TAIL,
        variantOverlayPath,
      ],
      frozenSourceDigest: '2'.repeat(64),
      helper,
      helperSourceSha256: '3'.repeat(64),
      pnpmEntry,
      toolchainContextSha256: '4'.repeat(64),
      toolchainReceiptSha256: '5'.repeat(64),
      variantOverlayPath,
      variantDefinitionSha256: CREDENTIAL_VARIANT_SHA256,
    });
    expect(identity).toEqual({
      buildRecipeSha256: A23_CLEANUP_HELPER_BUILD_RECIPE_SHA256,
      executableSha256: helper.sha256,
      executableSize: helper.size,
      helperSourceSha256: '3'.repeat(64),
      schemaVersion: 1,
      sourceDigest: '2'.repeat(64),
      toolchainContextSha256: '4'.repeat(64),
      toolchainReceiptSha256: '5'.repeat(64),
      variantDefinitionSha256: CREDENTIAL_VARIANT_SHA256,
    });
    expect(() => createA23CleanupHelperIdentity({
      buildArguments: [
        pnpmEntry,
        ...A23_CLEANUP_HELPER_BUILD_ARGUMENT_TAIL,
        variantOverlayPath,
        '--unexpected',
      ],
      frozenSourceDigest: '2'.repeat(64),
      helper,
      helperSourceSha256: '3'.repeat(64),
      pnpmEntry,
      toolchainContextSha256: '4'.repeat(64),
      toolchainReceiptSha256: '5'.repeat(64),
      variantOverlayPath,
      variantDefinitionSha256: CREDENTIAL_VARIANT_SHA256,
    })).toThrow();
    expect(() => assertA23CleanupHelperIdentity(identity, {
      ...helper,
      size: helper.size + 1,
    })).toThrow();
  });
});

function providerIdForLeakGuard(): string {
  return 'a23.fixture-provider';
}
