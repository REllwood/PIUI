import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { SessionManager, type SessionEntry } from '@earendil-works/pi-coding-agent';
import { afterEach, describe, expect, it } from 'vitest';
import {
  SESSION_ACKNOWLEDGEMENT_TYPE,
  SESSION_SPIKE_LIMITS,
  SESSION_SPIKE_TEST_OBSERVER,
  SessionSpikeError,
  proveSessionResumeAndFork,
  type SessionSpikeLease,
  type SessionSpikeTestFault,
} from '../../sidecar/src/pi/session-spike.js';

const fixture = resolve(
  import.meta.dirname,
  '../fixtures/pi-sessions/active-branch-v3.jsonl',
);
const provenance = resolve(import.meta.dirname, '../../scripts/generate-pi-session-fixture.mjs');
const repositoryRoot = resolve(import.meta.dirname, '../..');
const operationId = `operation-${'1'.repeat(32)}`;
const temporaryRoots: string[] = [];

function hash(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function testRoot(prefix = 'piui-a19-contract-'): string {
  const created = mkdtempSync(join(tmpdir(), prefix));
  chmodSync(created, 0o700);
  const root = realpathSync(created);
  temporaryRoots.push(root);
  return root;
}

function privateFile(bytes: Uint8Array, name = 'fixture.jsonl'): string {
  const root = testRoot();
  const path = join(root, name);
  writeFileSync(path, bytes, { flag: 'wx', mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

const usage = Object.freeze({
  input: 1,
  output: 1,
  cacheRead: 0,
  cacheWrite: 0,
  totalTokens: 2,
  cost: Object.freeze({ input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 }),
});

function generatedFixture(entryCount: number, activeBranchHasAssistant = true): string {
  const root = testRoot();
  const workspace = join(root, 'workspace');
  const sessions = join(root, 'sessions');
  mkdirSync(workspace, { mode: 0o700 });
  mkdirSync(sessions, { mode: 0o700 });
  const manager = SessionManager.create(workspace, sessions, {
    id: `a19-generated-${entryCount}-${activeBranchHasAssistant ? 'active' : 'inactive'}`,
  });
  manager.appendThinkingLevelChange('off');
  const rootId = manager.appendMessage({
    role: 'user', content: 'generated root', timestamp: 1_700_100_000_000,
  });
  manager.appendMessage({
    role: 'assistant',
    content: [{ type: 'text', text: 'generated selected assistant' }],
    api: 'fixture-api',
    provider: 'fixture-provider',
    model: 'fixture-model',
    usage,
    stopReason: 'stop',
    timestamp: 1_700_100_001_000,
  });
  if (!activeBranchHasAssistant) {
    manager.branch(rootId);
    manager.appendCustomEntry('fixture.active-without-assistant', { state: 'active' });
  } else {
    for (let index = 3; index < entryCount; index += 1) {
      manager.appendCustomEntry('fixture.bounded-entry', { index });
    }
  }
  const path = manager.getSessionFile();
  if (!path || !existsSync(path)) throw new Error('public SessionManager did not persist fixture');
  return path;
}

function corruptPublicFixture(
  mutate: (text: string, manager: SessionManager) => string,
): string {
  const path = privateFile(readFileSync(fixture));
  const workspace = dirname(path);
  const manager = SessionManager.open(path, workspace, workspace);
  const changed = mutate(readFileSync(path, 'utf8'), manager);
  if (changed === readFileSync(path, 'utf8')) throw new Error('adversarial mutation did not apply');
  writeFileSync(path, changed, { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

function replaceOnce(text: string, before: string, after: string): string {
  const index = text.indexOf(before);
  if (index < 0) throw new Error('adversarial token absent');
  return `${text.slice(0, index)}${after}${text.slice(index + before.length)}`;
}

function disposableSpikeRoots(): Set<string> {
  return new Set(readdirSync(tmpdir()).filter((name) => name.startsWith('piui-a19-')));
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
    throw new Error('expected rejection');
  } catch (error) {
    expect(error).toBeInstanceOf(SessionSpikeError);
    expect(error).toMatchObject({ code, message: code });
    expect(String(error)).not.toContain(fixture);
  }
}

function expectSyncCode(run: () => unknown, code: string): void {
  try {
    run();
    throw new Error('expected rejection');
  } catch (error) {
    expect(error).toBeInstanceOf(SessionSpikeError);
    expect(error).toMatchObject({ code, message: code });
  }
}

function semanticEntry(
  entry: SessionEntry,
  ordinalById: ReadonlyMap<string, number>,
): Readonly<Record<string, unknown>> {
  const { id: _id, parentId, timestamp: _timestamp, ...payload } = entry;
  return Object.freeze({
    parentOrdinal: parentId === null ? null : ordinalById.get(parentId),
    payload: structuredClone(payload),
  });
}

function semanticSession(manager: SessionManager): Readonly<Record<string, unknown>> {
  const header = manager.getHeader();
  if (!header) throw new Error('missing public SessionManager header');
  const entries = manager.getEntries();
  const ordinalById = new Map(entries.map((entry, index) => [entry.id, index]));
  return Object.freeze({
    header: Object.freeze({
      type: header.type,
      version: header.version,
      id: header.id,
      cwd: header.cwd,
      parentSessionPresent: header.parentSession !== undefined,
    }),
    entries: Object.freeze(entries.map((entry) => semanticEntry(entry, ordinalById))),
    activeBranchOrdinals: Object.freeze(manager.getBranch().map((entry) => ordinalById.get(entry.id))),
    leafOrdinal: ordinalById.get(manager.getLeafId() ?? ''),
  });
}

async function dispose(lease: SessionSpikeLease | undefined): Promise<void> {
  if (lease) await lease.dispose();
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe('A.19 public Pi session runtime resume and fork proof', () => {
  it('uses live switch/fork callbacks, independently reopens state and retires both capabilities', async () => {
    const repositoryZero = hash(fixture);
    let lease: SessionSpikeLease | undefined;
    try {
      lease = await proveSessionResumeAndFork({ fixturePath: fixture, operationId });
      const repositoryOne = hash(fixture);
      expect(repositoryOne).toBe(repositoryZero);

      expect(lease.references.source).toMatch(/^session-[0-9a-f]{32}$/);
      expect(lease.references.fork).toMatch(/^session-[0-9a-f]{32}$/);
      expect(lease.references.source).not.toBe(lease.references.fork);
      expect(new Set(Object.values(lease.references))).toHaveProperty('size', 2);
      expect(lease.counts).toEqual({
        sourceEntriesBeforeAcknowledgement: 8,
        sourceEntriesAfterAcknowledgement: 9,
        selectedBranchEntries: 4,
        forkEntries: 4,
        acknowledgementMarkers: 1,
        liveSessionReferences: 2,
        forks: 1,
      });

      const sourceView = lease.inspect(lease.references.source);
      const forkView = lease.inspect(lease.references.fork);
      expect(sourceView).toEqual({
        reference: lease.references.source,
        role: 'source',
        active: false,
        writable: false,
        entries: 9,
        activeBranchEntries: 7,
        acknowledgementMarkers: 1,
        availableTools: 0,
        toolExecutionAvailable: false,
      });
      expect(forkView).toEqual({
        reference: lease.references.fork,
        role: 'fork',
        active: true,
        writable: true,
        entries: 4,
        activeBranchEntries: 4,
        acknowledgementMarkers: 0,
        availableTools: 0,
        toolExecutionAvailable: false,
      });
      expectSyncCode(
        () => lease!.inspect(`session-${'f'.repeat(32)}`),
        'session-reference-rejected',
      );

      // This symbol-keyed seam reopens both private files through the public
      // SessionManager. These assertions do not trust production true flags.
      const observed = lease[SESSION_SPIKE_TEST_OBSERVER]();
      const checkedFixture = SessionManager.open(fixture);
      const fixtureActiveIds = checkedFixture.getBranch().map((entry) => entry.id);
      expect(observed.callbacks.switchSessionId).toBe(observed.source.sessionId);
      expect(observed.callbacks.switchBranchIds).toEqual(fixtureActiveIds);
      expect(observed.source.branchIds.slice(0, -1)).toEqual(fixtureActiveIds);
      expect(observed.acknowledgement.count).toBe(1);
      expect(observed.acknowledgement.id).toBe(observed.source.leafId);
      expect(observed.acknowledgement.leafId).toBe(observed.source.leafId);
      expect(observed.acknowledgement.parentId).toBe(observed.source.branchIds.at(-2));
      expect(observed.source.branchIds.at(-1)).toBe(observed.acknowledgement.id);

      expect(observed.fork.sessionId).not.toBe(observed.source.sessionId);
      expect(observed.fork.parentMatchesSource).toBe(true);
      expect(observed.fork.branchIds).toEqual(observed.selectedPrefixIds);
      expect(observed.fork.leafId).toBe(observed.selectedEntryId);
      expect(observed.fork.branchIds).not.toContain(observed.acknowledgement.id);
      expect(observed.callbacks.forkSessionId).toBe(observed.fork.sessionId);
      expect(observed.callbacks.forkBranchIds).toEqual(observed.fork.branchIds);
      expect(observed.callbacks.reboundSessionIds).toEqual([
        observed.source.sessionId,
        observed.fork.sessionId,
      ]);
      expect(observed.callbacks.activeRuntimeSessionId).toBe(observed.fork.sessionId);
      expect(observed.callbacks.activeRuntimeBranchIds).toEqual(observed.fork.branchIds);

      expect(observed.hashes.repositoryCurrent).toBe(observed.hashes.repositoryBefore);
      expect(observed.hashes.workingZero).toBe(observed.hashes.repositoryBefore);
      expect(observed.hashes.workingOne).not.toBe(observed.hashes.workingZero);
      expect(observed.hashes.workingTwo).toBe(observed.hashes.workingOne);
      expect(observed.fileIdentities.sourceCurrent).toBe(observed.fileIdentities.sourceZero);
      expect(observed.fileIdentities.forkCurrent).not.toBe(observed.fileIdentities.sourceCurrent);

      expect(observed.constructions.map((record) => record.reason)).toEqual([
        'initial', 'resume', 'fork',
      ]);
      for (const record of observed.constructions) {
        expect(record.decorateSequence).toBeLessThan(record.createSequence);
        expect(record.createSequence).toBeLessThan(record.bindSequence);
        expect(record.boundExactFactorySession).toBe(true);
        expect(record.allToolNames).toEqual([]);
        expect(record.activeToolNames).toEqual([]);
        expect(record.modelAvailable).toBe(false);
      }
      expect(observed.isolatedCredentialWrites).toBe(0);
      expect(observed.approvalHostCalls).toBe(0);

      const safeOutput = JSON.stringify(lease);
      for (const forbidden of [
        fixture,
        '.jsonl',
        'cwd',
        'parentSession',
        'piui-a19-active-branch-v3',
        'root request',
        'selected earlier assistant response',
        observed.source.sessionId,
        observed.fork.sessionId,
        observed.selectedEntryId,
        observed.acknowledgement.id!,
      ]) {
        expect(safeOutput).not.toContain(forbidden);
      }
    } finally {
      await dispose(lease);
    }

    expectSyncCode(() => lease!.inspect(lease!.references.source), 'session-reference-rejected');
    expectSyncCode(
      () => lease![SESSION_SPIKE_TEST_OBSERVER](),
      'session-reference-rejected',
    );
  });

  it('regenerates provenance in temp and compares public-SDK semantics without changing the fixture', () => {
    const repositoryZero = hash(fixture);
    const root = testRoot('piui-a19-provenance-');
    const generated = join(root, 'generated.jsonl');

    execFileSync(process.execPath, [provenance, generated], {
      cwd: repositoryRoot,
      env: { ...process.env, PI_OFFLINE: '1' },
      stdio: 'pipe',
    });

    expect(existsSync(generated)).toBe(true);
    const checkedManager = SessionManager.open(fixture);
    const generatedManager = SessionManager.open(generated);
    expect(semanticSession(generatedManager)).toEqual(semanticSession(checkedManager));
    expect(generatedManager.getEntries().some((entry) => entry.type === 'custom')).toBe(true);
    expect(generatedManager.getEntries().length).toBeGreaterThan(generatedManager.getBranch().length);
    expect(hash(fixture)).toBe(repositoryZero);
  });

  it('pre-checks an existing operation ID and rejects replay without mutation', async () => {
    const replay = privateFile(readFileSync(fixture), 'replay.jsonl');
    const manager = SessionManager.open(replay, dirname(replay), '/tmp');
    manager.appendCustomEntry(SESSION_ACKNOWLEDGEMENT_TYPE, {
      operationId,
      state: 'hostile-replay-shape',
    });
    const replayZero = hash(replay);
    const rootsZero = disposableSpikeRoots();

    await expectCode(
      proveSessionResumeAndFork({ fixturePath: replay, operationId }),
      'session-operation-rejected',
    );
    expect(hash(replay)).toBe(replayZero);
    expect(disposableSpikeRoots()).toEqual(rootsZero);
  });

  it('rejects path, operation, partial-LF, oversized, symlink and hardlink inputs before mutation', async () => {
    const repositoryZero = hash(fixture);
    const partial = privateFile(readFileSync(fixture).subarray(0, -1), 'partial.jsonl');
    const oversizedBytes = Buffer.alloc(SESSION_SPIKE_LIMITS.maxFileBytes + 1, 0x61);
    oversizedBytes[oversizedBytes.length - 1] = 0x0a;
    const oversized = privateFile(oversizedBytes, 'oversized.jsonl');
    const overlongLineBytes = Buffer.alloc(SESSION_SPIKE_LIMITS.maxJsonlLineBytes + 2, 0x61);
    overlongLineBytes[overlongLineBytes.length - 1] = 0x0a;
    const overlongLine = privateFile(overlongLineBytes, 'overlong-line.jsonl');

    const symlinkRoot = testRoot();
    const symlink = join(symlinkRoot, 'linked.jsonl');
    symlinkSync(fixture, symlink);
    const realAncestor = join(symlinkRoot, 'real-ancestor');
    const linkedAncestor = join(symlinkRoot, 'linked-ancestor');
    mkdirSync(realAncestor, { mode: 0o700 });
    copyFileSync(fixture, join(realAncestor, 'ancestor.jsonl'));
    symlinkSync(realAncestor, linkedAncestor);
    const ancestorSymlinkFixture = join(linkedAncestor, 'ancestor.jsonl');

    const hardlinkRoot = testRoot();
    const firstLink = join(hardlinkRoot, 'first.jsonl');
    const secondLink = join(hardlinkRoot, 'second.jsonl');
    copyFileSync(fixture, firstLink);
    chmodSync(firstLink, 0o600);
    linkSync(firstLink, secondLink);
    expect(lstatSync(firstLink).nlink).toBe(2);

    await expectCode(proveSessionResumeAndFork({ fixturePath: partial, operationId }), 'session-partial-write');
    await expectCode(proveSessionResumeAndFork({ fixturePath: oversized, operationId }), 'session-source-rejected');
    await expectCode(proveSessionResumeAndFork({ fixturePath: overlongLine, operationId }), 'session-source-rejected');
    await expectCode(proveSessionResumeAndFork({ fixturePath: symlink, operationId }), 'session-filesystem-rejected');
    await expectCode(proveSessionResumeAndFork({ fixturePath: ancestorSymlinkFixture, operationId }), 'session-filesystem-rejected');
    await expectCode(proveSessionResumeAndFork({ fixturePath: firstLink, operationId }), 'session-filesystem-rejected');
    await expectCode(proveSessionResumeAndFork({ fixturePath: fixture, operationId: 'operation-short' }), 'session-input-rejected');
    await expectCode(proveSessionResumeAndFork({ fixturePath: 'relative.jsonl', operationId }), 'session-input-rejected');
    await expectCode(proveSessionResumeAndFork({
      fixturePath: `/${'a'.repeat(SESSION_SPIKE_LIMITS.maxPathBytes)}.jsonl`,
      operationId,
    }), 'session-input-rejected');
    expect(hash(fixture)).toBe(repositoryZero);
  });

  it('rejects absent selection, duplicate or overlong IDs and malformed parent/type data before append', async () => {
    const repositoryZero = hash(fixture);
    await expectCode(proveSessionResumeAndFork({
      fixturePath: fixture,
      operationId,
      selectedAssistantOrdinal: 9,
    }), 'session-selection-rejected');
    await expectCode(proveSessionResumeAndFork({
      fixturePath: generatedFixture(4, false),
      operationId,
    }), 'session-selection-rejected');

    const duplicateId = corruptPublicFixture((text, manager) => {
      const entries = manager.getEntries();
      return replaceOnce(text, `"id":"${entries[1].id}"`, `"id":"${entries[0].id}"`);
    });
    await expectCode(proveSessionResumeAndFork({ fixturePath: duplicateId, operationId }), 'session-malformed');

    const overlongId = corruptPublicFixture((text, manager) => {
      const id = manager.getEntries()[1].id;
      return replaceOnce(text, `"id":"${id}"`, `"id":"${'a'.repeat(129)}"`);
    });
    await expectCode(proveSessionResumeAndFork({ fixturePath: overlongId, operationId }), 'session-malformed');

    const brokenParent = corruptPublicFixture((text, manager) => {
      const entry = manager.getEntries().at(-1)!;
      return replaceOnce(
        text,
        `"id":"${entry.id}","parentId":"${entry.parentId}"`,
        `"id":"${entry.id}","parentId":"missing-parent"`,
      );
    });
    await expectCode(proveSessionResumeAndFork({ fixturePath: brokenParent, operationId }), 'session-malformed');

    const unknownType = corruptPublicFixture((text) => replaceOnce(
      text,
      '"type":"message"',
      '"type":"unknown"',
    ));
    await expectCode(proveSessionResumeAndFork({ fixturePath: unknownType, operationId }), 'session-malformed');
    expect(hash(fixture)).toBe(repositoryZero);
  });

  it('allows a final 2,048-entry post-append branch and rejects one entry beyond the bound', async () => {
    const exact = generatedFixture(SESSION_SPIKE_LIMITS.maxBranchEntries - 1);
    let lease: SessionSpikeLease | undefined;
    try {
      lease = await proveSessionResumeAndFork({ fixturePath: exact, operationId });
      expect(lease.counts.sourceEntriesAfterAcknowledgement).toBe(SESSION_SPIKE_LIMITS.maxBranchEntries);
      expect(lease.counts.acknowledgementMarkers).toBe(1);
    } finally {
      await dispose(lease);
    }

    const plusOne = generatedFixture(SESSION_SPIKE_LIMITS.maxBranchEntries);
    const plusOneHash = hash(plusOne);
    await expectCode(proveSessionResumeAndFork({ fixturePath: plusOne, operationId }), 'session-malformed');
    expect(hash(plusOne)).toBe(plusOneHash);
  });

  it('reserves synchronously and keeps the one-operation gate until lease disposal', async () => {
    let release!: () => void;
    const barrier = new Promise<void>((resolveBarrier) => { release = resolveBarrier; });
    const first = proveSessionResumeAndFork({ fixturePath: fixture, operationId, testBarrier: barrier });
    await expectCode(proveSessionResumeAndFork({
      fixturePath: fixture,
      operationId: `operation-${'2'.repeat(32)}`,
    }), 'session-busy');
    release();
    const lease = await first;
    await expectCode(proveSessionResumeAndFork({
      fixturePath: fixture,
      operationId: `operation-${'3'.repeat(32)}`,
    }), 'session-busy');
    await lease.dispose();
  });

  it('fails ambiguous append/fork, identity substitution and output collision closed without retry', async () => {
    const repositoryZero = hash(fixture);
    const rootsZero = disposableSpikeRoots();
    await expectCode(proveSessionResumeAndFork({
      fixturePath: fixture,
      operationId,
      testFault: 'replace-before-append',
    }), 'session-filesystem-rejected');
    expect(hash(fixture)).toBe(repositoryZero);

    const recoveryFaults: readonly SessionSpikeTestFault[] = [
      'throw-after-append',
      'replace-before-fork',
      'fork-output-collision',
      'replace-after-fork',
      'throw-after-fork',
    ];
    for (let index = 0; index < recoveryFaults.length; index += 1) {
      await expectCode(proveSessionResumeAndFork({
        fixturePath: fixture,
        operationId: `operation-${(index + 10).toString(16).padStart(32, '0')}`,
        testFault: recoveryFaults[index],
      }), 'session-recovery-required');
      expect(hash(fixture)).toBe(repositoryZero);
    }
    expect(disposableSpikeRoots()).toEqual(rootsZero);
  });

  it('uses package-root runtime factories and contains no deep import, competing parser or unsafe path output', () => {
    const sidecarRoot = resolve(import.meta.dirname, '../../sidecar/src');
    const sources: string[] = [];
    const visit = (directory: string): void => {
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const path = join(directory, entry.name);
        if (entry.isDirectory()) visit(path);
        else if (entry.name.endsWith('.ts')) sources.push(readFileSync(path, 'utf8'));
      }
    };
    visit(sidecarRoot);
    const allSidecarSource = sources.join('\n');
    expect(allSidecarSource).not.toMatch(/@earendil-works\/pi-coding-agent\//);
    expect(allSidecarSource.match(/from ['"]@earendil-works\/pi-coding-agent['"]/g)).toHaveLength(1);

    const spike = readFileSync(resolve(sidecarRoot, 'pi/session-spike.ts'), 'utf8');
    const sdk = readFileSync(resolve(sidecarRoot, 'pi/public-sdk.ts'), 'utf8');
    expect(spike).toContain('await runtime.switchSession(');
    expect(spike).toContain('await runtime.fork(');
    expect(spike).toContain("position: 'at'");
    expect(spike).not.toContain('createBranchedSession');
    expect(spike).not.toContain('parseSessionEntries');
    expect(spike).not.toContain('loadEntriesFromFile');
    expect(spike).not.toContain('migrateSessionEntries');
    expect(spike).not.toContain('JSON.parse');
    expect(spike).not.toContain('JSON.stringify');
    expect(spike).not.toContain('as unknown as');
    expect(spike.match(/\.appendCustomEntry\(/g)).toHaveLength(1);
    expect(spike.indexOf('assertPublicSdk();')).toBeLessThan(spike.indexOf('root = mkdtempSync('));
    expect(sdk).toContain('createAgentSessionRuntime,');
    expect(sdk).toContain('createAgentSessionServices,');
    expect(sdk).toContain('createAgentSessionFromServices,');
    for (const forbidden of [
      'fetch(',
      '.prompt(',
      'loadTrustedProjectSnapshot',
      'host-request',
      'host-response',
      'Keychain',
    ]) {
      expect(spike).not.toContain(forbidden);
    }
    expect(readFileSync(fixture).at(-1)).toBe(0x0a);
    expect(readFileSync(fixture).length).toBeLessThanOrEqual(SESSION_SPIKE_LIMITS.maxFileBytes);
  });
});
