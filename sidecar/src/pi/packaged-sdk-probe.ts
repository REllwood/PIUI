import { resolve } from 'node:path';
import { proveSessionResumeAndFork, type DeterministicTurnEvidence } from './session-spike.js';

export const PACKAGED_SDK_FIXTURE = 'fixture/active-branch-v3.jsonl';

export type PackagedSdkProbeEvidence = Readonly<{
  schemaVersion: 1;
  publicSdkImported: true;
  resumed: true;
  forkedAtSelection: true;
  sourceUnchanged: true;
  repositoryFixtureUnchanged: true;
  zeroTools: true;
  selectedBranchEntries: number;
  sourceEntries: number;
  forkEntriesBeforeTurn: number;
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
      const turn = await lease.runDeterministicTurn();
    const source = lease.inspect(lease.references.source);
    const fork = lease.inspect(lease.references.fork);
    if (source.availableTools !== 0
      || fork.availableTools !== 0
      || source.toolExecutionAvailable
      || fork.toolExecutionAvailable
      || !fork.active
      || !fork.writable
      || source.entries !== lease.counts.sourceEntriesAfterAcknowledgement
      // Public setModel appends one model-change entry, then the cancelled
      // prompt appends exactly one user and one aborted assistant message.
      || fork.entries !== lease.counts.forkEntries + 3) {
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
        selectedBranchEntries: lease.counts.selectedBranchEntries,
        sourceEntries: source.entries,
        forkEntriesBeforeTurn: lease.counts.forkEntries,
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
