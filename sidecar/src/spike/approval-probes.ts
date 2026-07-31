import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  writeSync,
} from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { resolve } from 'node:path';
import type { ProtocolEnvelope } from '@piui/protocol';
import type { PublicToolDefinition } from '../pi/public-sdk.js';

export type A25ApprovalAction =
  | 'approve-one'
  | 'approve-group'
  | 'deny'
  | 'timeout'
  | 'disconnect'
  | 'transport-cutoff'
  | 'sidecar-death'
  | 'stale-replay';

export type A25ApprovalCase = Readonly<{
  id: string;
  generation: 1 | 2 | 3 | 4 | 5;
  turn: number;
  tools: readonly [string, string, string];
  action: A25ApprovalAction;
  risk: 'routine' | 'destructive' | 'external';
  groupEligible: boolean;
  approvedMember?: number;
}>;

function approvalCase(value: A25ApprovalCase): A25ApprovalCase {
  return Object.freeze({ ...value, tools: Object.freeze([...value.tools]) }) as A25ApprovalCase;
}

export const A25_APPROVAL_CASES: readonly A25ApprovalCase[] = Object.freeze([
  approvalCase({ id: 'routine-individual', generation: 1, turn: 1, tools: ['read', 'grep', 'find'], action: 'approve-one', risk: 'routine', groupEligible: true, approvedMember: 0 }),
  approvalCase({ id: 'routine-group', generation: 1, turn: 2, tools: ['read', 'grep', 'find'], action: 'approve-group', risk: 'routine', groupEligible: true }),
  approvalCase({ id: 'routine-deny', generation: 1, turn: 3, tools: ['read', 'grep', 'find'], action: 'deny', risk: 'routine', groupEligible: true }),
  approvalCase({ id: 'destructive-individual', generation: 1, turn: 4, tools: ['read', 'bash', 'find'], action: 'approve-one', risk: 'destructive', groupEligible: false, approvedMember: 1 }),
  approvalCase({ id: 'destructive-repeat', generation: 1, turn: 5, tools: ['read', 'bash', 'find'], action: 'deny', risk: 'destructive', groupEligible: false }),
  approvalCase({ id: 'external-individual', generation: 1, turn: 6, tools: ['read', 'web_fetch', 'find'], action: 'approve-one', risk: 'external', groupEligible: false, approvedMember: 1 }),
  approvalCase({ id: 'external-repeat', generation: 1, turn: 7, tools: ['read', 'web_fetch', 'find'], action: 'deny', risk: 'external', groupEligible: false }),
  approvalCase({ id: 'routine-timeout', generation: 1, turn: 8, tools: ['read', 'grep', 'find'], action: 'timeout', risk: 'routine', groupEligible: true }),
  approvalCase({ id: 'host-disconnect', generation: 2, turn: 9, tools: ['read', 'grep', 'find'], action: 'disconnect', risk: 'routine', groupEligible: true }),
  approvalCase({ id: 'transport-cutoff', generation: 3, turn: 10, tools: ['read', 'grep', 'find'], action: 'transport-cutoff', risk: 'routine', groupEligible: true }),
  approvalCase({ id: 'sidecar-death', generation: 4, turn: 11, tools: ['read', 'grep', 'find'], action: 'sidecar-death', risk: 'routine', groupEligible: true }),
  approvalCase({ id: 'stale-replay', generation: 5, turn: 12, tools: ['read', 'grep', 'find'], action: 'stale-replay', risk: 'routine', groupEligible: true }),
]);

export const A25_EXPECTED_MATRIX_COUNTS = Object.freeze({
  generations: 5 as const,
  turns: 12 as const,
  requests: 36 as const,
  approvedRecords: 6 as const,
  deniedRecords: 18 as const,
  expiredRecords: 3 as const,
  cancelledRecords: 9 as const,
  delegateExecutions: 6 as const,
});

export function approvalCasesForGeneration(generation: number): readonly A25ApprovalCase[] {
  if (!Number.isSafeInteger(generation) || generation < 1 || generation > 5) {
    throw new Error('approval-matrix-generation-rejected');
  }
  return Object.freeze(A25_APPROVAL_CASES.filter((candidate) => candidate.generation === generation));
}

const EXPECTED_PLAN = Object.freeze({
  schemaVersion: 1,
  matrixVersion: 'a25-v1',
  generations: 5,
  turns: 12,
  requests: 36,
});
const MARKER_ID = /^[a-z][a-z0-9-]{0,63}$/;
const TOOL_CALL_ID = /^a25-g([1-5])-t(1[0-2]|[1-9])-m([0-2])$/;

function assertOwnerPrivateDirectory(path: string): string {
  const requested = resolve(path);
  const item = lstatSync(requested);
  const canonical = realpathSync(requested);
  const opened = lstatSync(canonical);
  const expectedUid = typeof process.getuid === 'function' ? process.getuid() : opened.uid;
  if (requested !== canonical || item.isSymbolicLink() || !opened.isDirectory()
    || item.dev !== opened.dev || item.ino !== opened.ino || opened.uid !== expectedUid
    || (opened.mode & 0o777) !== 0o700) {
    throw new Error('approval-matrix-control-rejected');
  }
  return canonical;
}

function validatePlan(controlRoot: string): void {
  const planPath = resolve(controlRoot, 'plan.json');
  const descriptor = openSync(planPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const item = fstatSync(descriptor);
    const expectedUid = typeof process.getuid === 'function' ? process.getuid() : item.uid;
    if (!item.isFile() || item.nlink !== 1 || item.uid !== expectedUid
      || (item.mode & 0o777) !== 0o400 || item.size < 2 || item.size > 512) {
      throw new Error('approval-matrix-control-rejected');
    }
    const bytes = readFileSync(descriptor);
    const parsed = JSON.parse(bytes.toString('utf8')) as unknown;
    bytes.fill(0);
    if (!isDeepStrictEqual(parsed, EXPECTED_PLAN)) {
      throw new Error('approval-matrix-control-rejected');
    }
  } finally {
    closeSync(descriptor);
  }
}

function createMarker(path: string, body: string): void {
  const descriptor = openSync(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL
      | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    const bytes = Buffer.from(body, 'utf8');
    const written = writeSync(descriptor, bytes);
    bytes.fill(0);
    if (written !== Buffer.byteLength(body, 'utf8')) {
      throw new Error('approval-matrix-witness-rejected');
    }
  } finally {
    closeSync(descriptor);
  }
}

function privateFileExists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

function readPrivateFile(path: string, maximumBytes: number): Buffer {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const item = fstatSync(descriptor);
    const expectedUid = typeof process.getuid === 'function' ? process.getuid() : item.uid;
    if (!item.isFile() || item.nlink !== 1 || item.uid !== expectedUid
      || (item.mode & 0o777) !== 0o600 || item.size < 2 || item.size > maximumBytes) {
      throw new Error('approval-matrix-witness-rejected');
    }
    const bytes = readFileSync(descriptor);
    if (bytes.length !== item.size) {
      bytes.fill(0);
      throw new Error('approval-matrix-witness-rejected');
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

function assertMarker(path: string, body: string): boolean {
  if (!privateFileExists(path)) return false;
  const bytes = readPrivateFile(path, 128);
  try {
    if (!bytes.equals(Buffer.from(body, 'utf8'))) {
      throw new Error('approval-matrix-witness-rejected');
    }
    return true;
  } finally {
    bytes.fill(0);
  }
}

function nativeFrameName(kind: 'individual' | 'group'): string {
  return `native-old-${kind}.frame`;
}

export class A25ApprovalWitness {
  readonly #witnessRoot: string;
  readonly #calls = new Set<string>();
  #delegateCalls = 0;
  #fiveArgumentViolations = 0;
  readonly #capturedNativeFrames = new Set<'individual' | 'group'>();

  private constructor(witnessRoot: string) {
    this.#witnessRoot = witnessRoot;
  }

  static fromControlRoot(controlRoot: string): A25ApprovalWitness {
    const root = assertOwnerPrivateDirectory(controlRoot);
    validatePlan(root);
    const witnessRoot = assertOwnerPrivateDirectory(resolve(root, 'witness'));
    const witness = new A25ApprovalWitness(witnessRoot);
    for (const kind of ['individual', 'group'] as const) {
      const path = resolve(witnessRoot, nativeFrameName(kind));
      if (privateFileExists(path)) {
        const frame = witness.loadNativeFrame(kind);
        if (frame.payload.method !== (kind === 'individual'
          ? 'approval.resolve'
          : 'approval.group-commit')) {
          throw new Error('approval-matrix-witness-rejected');
        }
        witness.#capturedNativeFrames.add(kind);
      }
    }
    return witness;
  }

  nextMatrixGeneration(): 1 | 2 | 3 | 4 | 5 {
    let completed = 0;
    let gap = false;
    for (let generation = 1; generation <= 5; generation += 1) {
      const exists = assertMarker(
        resolve(this.#witnessRoot, `session-generation-${generation}.created`),
        'created\n',
      );
      if (exists && gap) throw new Error('approval-matrix-witness-rejected');
      if (exists) completed = generation;
      else gap = true;
    }
    const next = completed + 1;
    if (next < 1 || next > 5) throw new Error('approval-matrix-witness-rejected');
    return next as 1 | 2 | 3 | 4 | 5;
  }

  caseStarted(candidate: A25ApprovalCase): void {
    if (!MARKER_ID.test(candidate.id)) throw new Error('approval-matrix-witness-rejected');
    createMarker(resolve(this.#witnessRoot, `case-${candidate.id}.started`), 'started\n');
  }

  sessionCreated(generation: number): void {
    if (!Number.isSafeInteger(generation) || generation < 1 || generation > 5) {
      throw new Error('approval-matrix-witness-rejected');
    }
    createMarker(resolve(this.#witnessRoot, `session-generation-${generation}.created`), 'created\n');
  }

  caseReady(candidate: A25ApprovalCase): void {
    if (!MARKER_ID.test(candidate.id)) throw new Error('approval-matrix-witness-rejected');
    createMarker(resolve(this.#witnessRoot, `case-${candidate.id}.ready`), 'ready\n');
  }

  replayReady(candidate: A25ApprovalCase): void {
    if (candidate.id !== 'stale-replay') throw new Error('approval-matrix-witness-rejected');
    createMarker(resolve(this.#witnessRoot, `case-${candidate.id}.replay-ready`), 'replay-ready\n');
  }

  async waitForReplayRelease(candidate: A25ApprovalCase): Promise<void> {
    if (candidate.id !== 'stale-replay') throw new Error('approval-matrix-witness-rejected');
    const path = resolve(this.#witnessRoot, `case-${candidate.id}.replay-release`);
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
      if (assertMarker(path, 'replay-release\n')) return;
      await new Promise<void>((resolvePromise) => setTimeout(resolvePromise, 10));
    }
    throw new Error('approval-matrix-witness-rejected');
  }

  replayComplete(candidate: A25ApprovalCase): void {
    if (candidate.id !== 'stale-replay') throw new Error('approval-matrix-witness-rejected');
    createMarker(resolve(this.#witnessRoot, `case-${candidate.id}.replay-complete`), 'replay-complete\n');
  }

  captureNativeFrame(envelope: ProtocolEnvelope, rawFrame: Uint8Array): void {
    if (envelope.kind !== 'host-response') return;
    const method = envelope.payload.method;
    const kind = method === 'approval.group-commit'
      ? 'group'
      : method === 'approval.resolve' && envelope.payload.decision === 'approved'
        ? 'individual'
        : undefined;
    if (!kind || this.#capturedNativeFrames.has(kind)) return;
    const bytes = Buffer.from(rawFrame);
    try {
      if (bytes.length < 3 || bytes.length > 65_536
        || bytes.at(-1) !== 0x0a || bytes.includes(0x0d)) {
        throw new Error('approval-matrix-witness-rejected');
      }
      const parsed = JSON.parse(bytes.subarray(0, -1).toString('utf8')) as unknown;
      if (!isDeepStrictEqual(parsed, envelope)) {
        throw new Error('approval-matrix-witness-rejected');
      }
      const path = resolve(this.#witnessRoot, nativeFrameName(kind));
      const descriptor = openSync(
        path,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
      try {
        if (writeSync(descriptor, bytes) !== bytes.length) {
          throw new Error('approval-matrix-witness-rejected');
        }
        fsyncSync(descriptor);
      } finally {
        closeSync(descriptor);
      }
      this.#capturedNativeFrames.add(kind);
    } finally {
      bytes.fill(0);
    }
  }

  loadNativeFrame(kind: 'individual' | 'group'): ProtocolEnvelope {
    const bytes = readPrivateFile(resolve(this.#witnessRoot, nativeFrameName(kind)), 65_536);
    try {
      if (bytes.at(-1) !== 0x0a || bytes.includes(0x0d)) {
        throw new Error('approval-matrix-witness-rejected');
      }
      const parsed = JSON.parse(bytes.subarray(0, -1).toString('utf8')) as ProtocolEnvelope;
      if (parsed.kind !== 'host-response'
        || parsed.payload.method !== (kind === 'individual'
          ? 'approval.resolve'
          : 'approval.group-commit')) {
        throw new Error('approval-matrix-witness-rejected');
      }
      return parsed;
    } finally {
      bytes.fill(0);
    }
  }

  recordDelegate(
    toolCallId: string,
    params: unknown,
    argumentCount: number,
    signal: AbortSignal | undefined,
    onUpdate: unknown,
    context: unknown,
  ): void {
    const match = TOOL_CALL_ID.exec(toolCallId);
    const caseId = params !== null && typeof params === 'object'
      ? Object.getOwnPropertyDescriptor(params, 'caseId')?.value
      : undefined;
    const value = params !== null && typeof params === 'object'
      ? Object.getOwnPropertyDescriptor(params, 'value')?.value
      : undefined;
    const exact = Boolean(match && typeof caseId === 'string' && MARKER_ID.test(caseId)
      && value === 'fixed' && argumentCount === 5
      && (signal === undefined || signal instanceof AbortSignal)
      && (onUpdate === undefined || typeof onUpdate === 'function')
      && context !== null && typeof context === 'object');
    if (!exact || !match) {
      this.#fiveArgumentViolations += 1;
      throw new Error('approval-matrix-delegate-rejected');
    }
    const member = Number(match[3]);
    const key = `${caseId}-${member}`;
    if (this.#calls.has(key)) throw new Error('approval-matrix-delegate-rejected');
    this.#calls.add(key);
    createMarker(resolve(this.#witnessRoot, `delegate-${caseId}-${member}.called`), 'called\n');
    this.#delegateCalls += 1;
  }

  get delegateCalls(): number {
    return this.#delegateCalls;
  }

  get fiveArgumentViolations(): number {
    return this.#fiveArgumentViolations;
  }
}

export function createApprovalProbeDefinitions(
  witness: A25ApprovalWitness,
): readonly PublicToolDefinition[] {
  const parameters = Object.freeze({
    type: 'object',
    properties: Object.freeze({
      caseId: Object.freeze({ type: 'string' }),
      value: Object.freeze({ type: 'string' }),
    }),
    required: Object.freeze(['caseId', 'value']),
    additionalProperties: false,
  }) as never;
  const names = ['read', 'grep', 'find', 'bash', 'web_fetch'] as const;
  return Object.freeze(names.map((name): PublicToolDefinition => {
    const execute: PublicToolDefinition['execute'] = async function (
      toolCallId,
      params,
      signal,
      onUpdate,
      context,
    ) {
      witness.recordDelegate(toolCallId, params, arguments.length, signal, onUpdate, context);
      return {
        content: [{ type: 'text' as const, text: 'approved fixture result' }],
        details: {},
      };
    };
    return {
      name,
      label: `A.25 ${name}`,
      description: 'Fixed non-production approval architecture probe.',
      parameters,
      executionMode: 'parallel' as const,
      execute,
    } as PublicToolDefinition;
  }));
}
