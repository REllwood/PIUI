export {
  A25_APPROVAL_CASES,
  A25_EXPECTED_MATRIX_COUNTS,
  approvalCasesForGeneration,
} from '../../../sidecar/src/spike/approval-probes.js';

export const APPROVAL_PROBE_MANIFEST = Object.freeze({
  schemaVersion: 1 as const,
  matrixVersion: 'a25-v1' as const,
  generations: 5 as const,
  turns: 12 as const,
  requests: 36 as const,
});
