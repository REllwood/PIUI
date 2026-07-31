import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runPackagedSdkProbe } from '../../sidecar/src/pi/packaged-sdk-probe';
import { proveSessionResumeAndFork } from '../../sidecar/src/pi/session-spike';
import {
  assertSafeEvidence,
  packagedProbeSandbox,
  parsePackagedEvidence,
} from '../../scripts/run-packaged-probe.mjs';

const repositoryRoot = resolve(import.meta.dirname, '../..');
const repositoryFixture = resolve(repositoryRoot, 'tests/fixtures/pi-sessions/active-branch-v3.jsonl');
const originalCwd = process.cwd();
let temporaryRoot: string | undefined;

function sha256(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function prepareFixture(): string {
  temporaryRoot = mkdtempSync(join(tmpdir(), 'piui-a22-test-'));
  mkdirSync(join(temporaryRoot, 'fixture'), { mode: 0o700 });
  cpSync(repositoryFixture, join(temporaryRoot, 'fixture', 'active-branch-v3.jsonl'));
  process.chdir(temporaryRoot);
  return temporaryRoot;
}

afterEach(() => {
  process.chdir(originalCwd);
  if (temporaryRoot) rmSync(temporaryRoot, { recursive: true, force: true });
  temporaryRoot = undefined;
});

describe.sequential('A.22 public SDK session turn', () => {
  it('resumes, forks, streams and cancels through the real public SDK', async () => {
    const before = sha256(repositoryFixture);
    prepareFixture();
    const evidence = await runPackagedSdkProbe();
    expect(evidence).toMatchObject({
      schemaVersion: 1,
      publicSdkImported: true,
      resumed: true,
      forkedAtSelection: true,
      sourceUnchanged: true,
      repositoryFixtureUnchanged: true,
      zeroTools: true,
      selectedBranchEntries: 4,
      forkEntriesBeforeTurn: 4,
    });
    expect(evidence).toMatchObject({
      fixtureSha256: before,
      sourceBeforeTurnSha256: evidence.sourceAfterTurnSha256,
      sourceEntries: 9,
      forkEntriesAfterTurn: 7,
    });
    expect(evidence.turn).toEqual(expect.objectContaining({
      providerCalls: 1,
      providerAbortObserved: true,
      messageStarts: 1,
      textDeltas: 1,
      abortedTerminals: 1,
      completeTerminals: 0,
      postAbortRequestUpdates: 0,
      postTerminalEvents: 0,
      forbiddenFinalChunkAbsent: true,
      partialBytes: 4,
      partialSha256: '668e1c03090afbe4491469529c26b0f21aac187f63f0187bef8f17906abc783c',
      credentialAccess: {
        reads: 1_400,
        lists: 8,
        modifies: 0,
        deletes: 0,
        providerIds: 39,
        unexpectedProviderIds: 0,
      },
      approvalHostCalls: 0,
    }));
    expect(assertSafeEvidence(evidence)).toEqual(evidence);
    expect(sha256(repositoryFixture)).toBe(before);
  });

  it('permits exactly one real turn and never retries an ambiguous mutation', async () => {
    prepareFixture();
    const lease = await proveSessionResumeAndFork({
      fixturePath: resolve(process.cwd(), 'fixture', 'active-branch-v3.jsonl'),
      operationId: 'operation-a2211111111111111111111111111111',
    });
    try {
      await expect(lease.runDeterministicTurn()).resolves.toMatchObject({ abortedTerminals: 1 });
      await expect(lease.runDeterministicTurn()).rejects.toThrow('session-operation-rejected');
    } finally {
      await lease.dispose();
    }
  });

  it('fails closed when the fixed fixture is absent without falling back to source', async () => {
    temporaryRoot = mkdtempSync(join(tmpdir(), 'piui-a22-missing-'));
    process.chdir(temporaryRoot);
    await expect(runPackagedSdkProbe()).rejects.toThrow(/session-source-rejected/);
  });

  it('rejects forged, non-exact or multi-value packaged evidence', () => {
    const valid = {
      schemaVersion: 1,
      publicSdkImported: true,
      resumed: true,
      forkedAtSelection: true,
      sourceUnchanged: true,
      repositoryFixtureUnchanged: true,
      zeroTools: true,
      fixtureSha256: 'ea8814148eccb23250f92af2bf9f42a89e38f3f137d3fb380f42f830ac47a742',
      sourceBeforeTurnSha256: 'a'.repeat(64),
      sourceAfterTurnSha256: 'a'.repeat(64),
      selectedBranchEntries: 4,
      sourceEntries: 9,
      forkEntriesBeforeTurn: 4,
      forkEntriesAfterTurn: 7,
      turn: {
        providerCalls: 1,
        providerAbortObserved: true,
        messageStarts: 1,
        textDeltas: 1,
        abortedTerminals: 1,
        completeTerminals: 0,
        postAbortRequestUpdates: 0,
        postTerminalEvents: 0,
        forbiddenFinalChunkAbsent: true,
        partialBytes: 4,
        partialSha256: '668e1c03090afbe4491469529c26b0f21aac187f63f0187bef8f17906abc783c',
        cancellationLatencyMilliseconds: 5,
        credentialAccess: { reads: 1_400, lists: 8, modifies: 0, deletes: 0, providerIds: 39, unexpectedProviderIds: 0 },
        approvalHostCalls: 0,
      },
    };
    expect(assertSafeEvidence(valid)).toEqual(valid);
    expect(() => assertSafeEvidence({ ...valid, leakedPrivatePath: '/private/path' })).toThrow();
    expect(() => assertSafeEvidence({ ...valid, turn: { ...valid.turn, partialSha256: '0'.repeat(64) } })).toThrow();
    expect(() => parsePackagedEvidence(Buffer.from(`${JSON.stringify(valid)}\n{}\n`))).toThrow();
    expect(() => parsePackagedEvidence(Buffer.from(`${JSON.stringify(valid)} trailing\n`))).toThrow();
  });

  it('uses exact package-root imports and no competing session parser', () => {
    const piAdapter = readFileSync(resolve(repositoryRoot, 'sidecar/src/pi/public-sdk.ts'), 'utf8');
    const aiAdapter = readFileSync(resolve(repositoryRoot, 'sidecar/src/pi/ai-public-sdk.ts'), 'utf8');
    const probe = readFileSync(resolve(repositoryRoot, 'sidecar/src/pi/packaged-sdk-probe.ts'), 'utf8');
    expect(piAdapter.match(/from ['"]@earendil-works\/pi-coding-agent['"]/g)).toHaveLength(1);
    expect(aiAdapter.match(/from ['"]@earendil-works\/pi-ai['"]/g)).toHaveLength(1);
    expect(`${piAdapter}\n${aiAdapter}\n${probe}`).not.toMatch(/@earendil-works\/pi-(?:coding-agent|ai)\//);
    expect(probe).not.toContain('JSON.parse');
    expect(probe).not.toContain('fetch(');
    const profile = packagedProbeSandbox(
      resolve(repositoryRoot, '.cache/a21/accepted/PIUI.app'),
      resolve(tmpdir(), 'piui-a22-packaged-static'),
    );
    expect(profile).toContain('(deny default)');
    expect(profile).not.toContain('(allow default)');
    expect(profile).toContain('(deny network*)');
    expect(profile).toContain('(deny process-fork)');
    expect(profile).toContain(`(deny file-write* (subpath "${resolve(repositoryRoot, '.cache/a21/accepted/PIUI.app')}"))`);
    expect(profile).toContain('com.apple.securityd');
    expect(profile).toContain('com.apple.SecurityServer');
    expect(profile).not.toContain(`(allow file-read* (subpath "${repositoryRoot}"))`);
    expect(profile).not.toContain(`(allow file-write* (subpath "${repositoryRoot}"))`);
    const formalRunner = readFileSync(resolve(repositoryRoot, 'scripts/run-packaged-probe.mjs'), 'utf8');
    expect(formalRunner).toContain("'--authoritative-a22'");
    expect(formalRunner).toContain("'-cRP'");
    expect(formalRunner).toContain("command: '/bin/cp'");
    expect(formalRunner).not.toContain('loadAcceptedCandidate');
  });
});
