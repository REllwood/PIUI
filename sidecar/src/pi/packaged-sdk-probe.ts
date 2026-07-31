import { resolve } from 'node:path';
import {
  SESSION_SPIKE_TEST_OBSERVER,
  proveSessionResumeAndFork,
  type DeterministicTurnEvidence,
} from './session-spike.js';

export const PACKAGED_SDK_FIXTURE = 'fixture/active-branch-v3.jsonl';

export type PackagedSdkProbeEvidence = Readonly<{
  schemaVersion: 1;
  publicSdkImported: true;
  resumed: true;
  forkedAtSelection: true;
  sourceUnchanged: true;
  repositoryFixtureUnchanged: true;
  zeroTools: true;
  fixtureSha256: string;
  sourceBeforeTurnSha256: string;
  sourceAfterTurnSha256: string;
  selectedBranchEntries: 4;
  sourceEntries: 9;
  forkEntriesBeforeTurn: 4;
  forkEntriesAfterTurn: 7;
  turn: DeterministicTurnEvidence;
}>;

/**
 * Runs only the fixed A.22 fixture beneath the caller's isolated cwd. The
 * packaged driver owns that cwd and supplies no path, prompt, model or tool
 * authority to this function.
 */
export async function runPackagedSdkProbe(): Promise<PackagedSdkProbeEvidence> {
  const priorOffline = process.env.PI_OFFLINE;
  process.env.PI_OFFLINE = '1';
  try {
    const lease = await proveSessionResumeAndFork({
      fixturePath: resolve(process.cwd(), PACKAGED_SDK_FIXTURE),
      operationId: 'operation-a2200000000000000000000000000000',
      selectedAssistantOrdinal: 0,
    });
    try {
      const beforeTurn = lease[SESSION_SPIKE_TEST_OBSERVER]();
      const turn = await lease.runDeterministicTurn();
      const afterTurn = lease[SESSION_SPIKE_TEST_OBSERVER]();
      const source = lease.inspect(lease.references.source);
      const fork = lease.inspect(lease.references.fork);
      if (source.availableTools !== 0
        || fork.availableTools !== 0
        || source.toolExecutionAvailable
        || fork.toolExecutionAvailable
        || !fork.active
        || !fork.writable
        || lease.counts.selectedBranchEntries !== 4
        || lease.counts.forkEntries !== 4
        || source.entries !== 9
        || source.entries !== lease.counts.sourceEntriesAfterAcknowledgement
        // Public setModel appends one model-change entry, then the cancelled
        // prompt appends exactly one user and one aborted assistant message.
        || fork.entries !== 7
        || fork.entries !== lease.counts.forkEntries + 3
        || beforeTurn.hashes.repositoryBefore !== beforeTurn.hashes.repositoryCurrent
        || afterTurn.hashes.repositoryBefore !== afterTurn.hashes.repositoryCurrent
        || beforeTurn.hashes.repositoryBefore !== afterTurn.hashes.repositoryBefore
        || beforeTurn.hashes.workingTwo !== afterTurn.hashes.workingTwo) {
        throw new Error('packaged-sdk-probe-rejected');
      }
      return Object.freeze({
        schemaVersion: 1 as const,
        publicSdkImported: true as const,
        resumed: true as const,
        forkedAtSelection: true as const,
        sourceUnchanged: true as const,
        repositoryFixtureUnchanged: true as const,
        zeroTools: true as const,
        fixtureSha256: beforeTurn.hashes.repositoryBefore,
        sourceBeforeTurnSha256: beforeTurn.hashes.workingTwo,
        sourceAfterTurnSha256: afterTurn.hashes.workingTwo,
        selectedBranchEntries: 4 as const,
        sourceEntries: 9 as const,
        forkEntriesBeforeTurn: 4 as const,
        forkEntriesAfterTurn: 7 as const,
        turn,
      });
    } finally {
      await lease.dispose();
    }
  } finally {
    if (priorOffline === undefined) delete process.env.PI_OFFLINE;
    else process.env.PI_OFFLINE = priorOffline;
  }
}
