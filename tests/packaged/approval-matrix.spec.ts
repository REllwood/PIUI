import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import {
  A25_APPROVAL_CASES,
  A25_EXPECTED_MATRIX_COUNTS,
  APPROVAL_PROBE_MANIFEST,
  approvalCasesForGeneration,
} from '../fixtures/tools/approval-probes.js';
import {
  APPROVAL_MATRIX_EXPECTED_EVIDENCE,
  parseApprovalMatrixHarnessEvidence,
  parsePackagedApprovalMatrixEvidence,
} from '../../scripts/run-packaged-approval-probe.mjs';

const expectedCaseIds = [
  'routine-individual',
  'routine-group',
  'routine-deny',
  'destructive-individual',
  'destructive-repeat',
  'external-individual',
  'external-repeat',
  'routine-timeout',
  'host-disconnect',
  'transport-cutoff',
  'sidecar-death',
  'stale-replay',
] as const;

function line(value: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(value)}\n`);
}

describe('A.25 fixed packaged approval matrix', () => {
  it('pins five generations, twelve three-call public SDK turns and the exact risk cases', () => {
    expect(APPROVAL_PROBE_MANIFEST).toEqual({
      schemaVersion: 1,
      matrixVersion: 'a25-v1',
      generations: 5,
      turns: 12,
      requests: 36,
    });
    expect(A25_APPROVAL_CASES.map(({ id }) => id)).toEqual(expectedCaseIds);
    expect(A25_APPROVAL_CASES).toHaveLength(12);
    expect(A25_APPROVAL_CASES.every(({ tools }) => tools.length === 3)).toBe(true);
    expect(new Set(A25_APPROVAL_CASES.map(({ generation }) => generation))).toEqual(new Set([1, 2, 3, 4, 5]));
    expect(approvalCasesForGeneration(1)).toHaveLength(8);
    expect(approvalCasesForGeneration(2)).toHaveLength(1);
    expect(approvalCasesForGeneration(3)).toHaveLength(1);
    expect(approvalCasesForGeneration(4)).toHaveLength(1);
    expect(approvalCasesForGeneration(5)).toHaveLength(1);
    expect(A25_EXPECTED_MATRIX_COUNTS).toEqual({
      generations: 5,
      turns: 12,
      requests: 36,
      approvedRecords: 6,
      deniedRecords: 18,
      expiredRecords: 3,
      cancelledRecords: 9,
      delegateExecutions: 6,
    });
  });

  it('keeps destructive and external repeats explicit and never group-eligible', () => {
    const destructive = A25_APPROVAL_CASES.filter(({ risk }) => risk === 'destructive');
    const external = A25_APPROVAL_CASES.filter(({ risk }) => risk === 'external');
    expect(destructive.map(({ action }) => action)).toEqual(['approve-one', 'deny']);
    expect(external.map(({ action }) => action)).toEqual(['approve-one', 'deny']);
    expect([...destructive, ...external].every(({ groupEligible }) => groupEligible === false)).toBe(true);
  });

  it('strictly accepts only the exact path-free native and formal evidence contracts', () => {
    expect(parseApprovalMatrixHarnessEvidence(line(APPROVAL_MATRIX_EXPECTED_EVIDENCE)))
      .toEqual(APPROVAL_MATRIX_EXPECTED_EVIDENCE);
    expect(JSON.stringify(APPROVAL_MATRIX_EXPECTED_EVIDENCE)).not.toContain('/');
    expect(Object.values(APPROVAL_MATRIX_EXPECTED_EVIDENCE)
      .every((value) => typeof value === 'number' || typeof value === 'boolean')).toBe(true);

    const formal = {
      ...APPROVAL_MATRIX_EXPECTED_EVIDENCE,
      runnerIsolateRemoved: true,
      generatedOutputsRemoved: true,
    };
    expect(parsePackagedApprovalMatrixEvidence(line(formal))).toEqual(formal);

    for (const malformed of [
      Buffer.from(''),
      Buffer.from(`${JSON.stringify(APPROVAL_MATRIX_EXPECTED_EVIDENCE)}\r\n`),
      Buffer.from(`${JSON.stringify(APPROVAL_MATRIX_EXPECTED_EVIDENCE)}\nextra\n`),
      line({ ...APPROVAL_MATRIX_EXPECTED_EVIDENCE, approvedRecords: 7 }),
      line({ ...APPROVAL_MATRIX_EXPECTED_EVIDENCE, workspacePath: '/private/project' }),
    ]) {
      expect(() => parseApprovalMatrixHarnessEvidence(malformed)).toThrow('A.25 packaged approval probe rejected');
    }
    const missing = { ...APPROVAL_MATRIX_EXPECTED_EVIDENCE } as Record<string, unknown>;
    delete missing.witnessInventoryExact;
    expect(() => parseApprovalMatrixHarnessEvidence(line(missing))).toThrow('A.25 packaged approval probe rejected');
    expect(() => parsePackagedApprovalMatrixEvidence(line({ ...formal, runnerIsolateRemoved: false })))
      .toThrow('A.25 packaged approval probe rejected');
  });

  it('keeps A.25 activation in the external fixed fixture and rejects A.23/A.25 overlap', async () => {
    const [
      cargo,
      processSource,
      indexSource,
      runtimeSource,
      fixtureEntrySource,
      stageSource,
      runnerSource,
      packageSource,
    ] = await Promise.all([
      readFile(new URL('../../src-tauri/Cargo.toml', import.meta.url), 'utf8'),
      readFile(new URL('../../src-tauri/src/supervisor/process.rs', import.meta.url), 'utf8'),
      readFile(new URL('../../sidecar/src/index.ts', import.meta.url), 'utf8'),
      readFile(new URL('../../sidecar/src/runtime.ts', import.meta.url), 'utf8'),
      readFile(new URL('../../sidecar/src/spike/approval-entry.ts', import.meta.url), 'utf8'),
      readFile(new URL('../../scripts/stage-sidecar.mjs', import.meta.url), 'utf8'),
      readFile(new URL('../../scripts/run-packaged-approval-probe.mjs', import.meta.url), 'utf8'),
      readFile(new URL('../../scripts/package-spike.mjs', import.meta.url), 'utf8'),
    ]);
    expect(cargo).toContain('a25-approval-test = []');
    expect(processSource).toContain('PIUI_A25_CONTROL_ROOT');
    expect(processSource).toContain('A.23 and A.25 architecture test features cannot overlap');
    expect(indexSource).toBe("import { runSidecar } from './runtime.js';\n\nrunSidecar();\n");
    for (const productionSource of [indexSource, runtimeSource]) {
      expect(productionSource).not.toContain('PIUI_A25_');
      expect(productionSource).not.toContain('createA25Approval');
      expect(productionSource).not.toContain('approval-matrix.complete');
    }
    expect(fixtureEntrySource).toContain('createA25ApprovalFixtureFromEnvironment');
    expect(stageSource).toContain('A25_FIXTURE_FILES');
    expect(stageSource).toContain("'@piui/a25-approval-fixture'");
    expect(stageSource).toContain('A.25 fixture entered production closure');
    expect(stageSource).toContain('A.25 activation entered production closure');
    expect(runnerSource).toContain('FIXTURE_FILES');
    expect(runnerSource).toContain("'@piui/a25-approval-fixture'");
    expect(runnerSource).toContain('assertApprovalFixtureAbsentFromBundle');
    expect(runnerSource).toContain('PIUI_A25_FIXTURE_ENTRY');
    expect(packageSource).toContain('--authoritative-a25');
  });
});
