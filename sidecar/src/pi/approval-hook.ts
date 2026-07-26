import { createHash, randomUUID } from 'node:crypto';
import type { ApprovalGrant, ApprovalRequestPayload } from '../bridge/host-requests.js';
import type { PublicInlineExtension } from './public-sdk.js';

const MAX_BYTES = 65_536;
const MAX_DEPTH = 16;
const MAX_NODES = 256;
const MAX_STRING_BYTES = 16_384;
const FIXED_BLOCK_REASON = 'This action was not approved.';

export type ApprovalHost = Readonly<{
  requestApproval(payload: ApprovalRequestPayload): Promise<ApprovalGrant>;
}>;
export type ApprovalContext = Readonly<{
  generation: number;
  sessionId: string;
  workspaceId: string;
  workspaceRevision: number;
}>;
export type ApprovalExecution<T> = (input: Readonly<Record<string, unknown>>, signal?: AbortSignal) => Promise<T>;

type Canonical = Readonly<{ bytes: Buffer; digest: string; value: Readonly<Record<string, unknown>> }>;
type StoredGrant = Readonly<{ invocationId: string; digest: string; bytes: Buffer; decisionId: string }>;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function cloneCanonical(value: unknown, depth: number, state: { nodes: number; ancestors: Set<object> }): unknown {
  if (depth > MAX_DEPTH || state.nodes >= MAX_NODES) throw new Error('approval-input-rejected');
  state.nodes += 1;
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    if (Buffer.byteLength(value, 'utf8') > MAX_STRING_BYTES || value.includes('\0')) throw new Error('approval-input-rejected');
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) throw new Error('approval-input-rejected');
    return value;
  }
  if (typeof value !== 'object' || state.ancestors.has(value)) throw new Error('approval-input-rejected');
  state.ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (value.length > MAX_NODES) throw new Error('approval-input-rejected');
      const descriptors = Object.getOwnPropertyDescriptors(value);
      const keys = Object.keys(descriptors).filter((key) => key !== 'length');
      if (keys.length !== value.length || keys.some((key, index) => key !== String(index) || !('value' in descriptors[key]))) throw new Error('approval-input-rejected');
      return value.map((entry) => cloneCanonical(entry, depth + 1, state));
    }
    if (!isPlainObject(value)) throw new Error('approval-input-rejected');
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Object.keys(descriptors).sort();
    if (keys.length > 128 || keys.some((key) => key.length < 1 || key.length > 128 || /\p{Cc}/u.test(key) || !('value' in descriptors[key]))) throw new Error('approval-input-rejected');
    const output: Record<string, unknown> = Object.create(null);
    for (const key of keys) output[key] = cloneCanonical(descriptors[key].value, depth + 1, state);
    return output;
  } finally {
    state.ancestors.delete(value);
  }
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object') {
    for (const entry of Object.values(value as Record<string, unknown>)) deepFreeze(entry);
    Object.freeze(value);
  }
  return value;
}

export function canonicaliseApprovalInput(input: unknown): Canonical {
  if (!isPlainObject(input)) throw new Error('approval-input-rejected');
  const value = cloneCanonical(input, 0, { nodes: 0, ancestors: new Set() }) as Record<string, unknown>;
  const encoded = JSON.stringify(value);
  const bytes = Buffer.from(encoded, 'utf8');
  if (bytes.length > MAX_BYTES) { bytes.fill(0); throw new Error('approval-input-rejected'); }
  const digest = createHash('sha256').update(bytes).digest('hex');
  return Object.freeze({ bytes, digest, value: deepFreeze(value) });
}

function opaque(prefix: string): string { return `${prefix}-${randomUUID().replaceAll('-', '')}`; }

/**
 * Public Pi's awaited tool_call hook is the universal pre-execution observation
 * seam. Exact execution authority additionally requires `wrapExecution`: later
 * third-party hooks may replace `event.input`, so unwrapped tools fail closed.
 */
export function createApprovalGate(host: ApprovalHost, context: ApprovalContext) {
  const grants = new WeakMap<object, StoredGrant>();
  const wrappedNames = new Set<string>();

  const extension: PublicInlineExtension = Object.freeze({
    name: 'piui-approval-gate',
    hidden: true,
    factory(pi) {
      pi.on('tool_call', async (event) => {
        if (!wrappedNames.has(event.toolName) || !isPlainObject(event.input)) return { block: true, reason: FIXED_BLOCK_REASON };
        let canonical: Canonical | undefined;
        try {
          canonical = canonicaliseApprovalInput(event.input);
          const invocationId = opaque('invocation');
          const response = await host.requestApproval({
            method: 'approval.request', schemaVersion: 1, generation: context.generation,
            sessionId: context.sessionId, workspaceId: context.workspaceId,
            workspaceRevision: context.workspaceRevision, invocationId, toolName: event.toolName,
            input: canonical.value,
          });
          if (response.decision !== 'approved' || response.invocationId !== invocationId || response.inputDigest !== canonical.digest || response.scopeIds.length !== 1) return { block: true, reason: FIXED_BLOCK_REASON };
          const executionInput = deepFreeze(JSON.parse(canonical.bytes.toString('utf8')) as Record<string, unknown>);
          const storedBytes = Buffer.from(canonical.bytes);
          grants.set(executionInput, Object.freeze({ invocationId, digest: canonical.digest, bytes: storedBytes, decisionId: response.decisionId }));
          event.input = executionInput;
          return undefined;
        } catch {
          return { block: true, reason: FIXED_BLOCK_REASON };
        } finally {
          canonical?.bytes.fill(0);
        }
      });
    },
  });

  function wrapExecution<T>(toolName: string, execute: ApprovalExecution<T>): ApprovalExecution<T> {
    if (!toolName || wrappedNames.has(toolName)) throw new Error('approval-wrapper-rejected');
    wrappedNames.add(toolName);
    return async (input, signal) => {
      const grant = input && typeof input === 'object' ? grants.get(input as object) : undefined;
      if (!grant) throw new Error(FIXED_BLOCK_REASON);
      grants.delete(input as object);
      if (signal?.aborted) { grant.bytes.fill(0); throw new Error(FIXED_BLOCK_REASON); }
      let verified: Canonical | undefined;
      try {
        verified = canonicaliseApprovalInput(input);
        if (verified.digest !== grant.digest) throw new Error(FIXED_BLOCK_REASON);
        const fresh = deepFreeze(JSON.parse(grant.bytes.toString('utf8')) as Record<string, unknown>);
        if (signal?.aborted) throw new Error(FIXED_BLOCK_REASON);
        return await execute(fresh, signal);
      } finally {
        verified?.bytes.fill(0);
        grant.bytes.fill(0);
      }
    };
  }

  return Object.freeze({ extension, wrapExecution });
}

export const APPROVAL_GATE_LIMITS = Object.freeze({ maxBytes: MAX_BYTES, maxDepth: MAX_DEPTH, maxNodes: MAX_NODES, maxStringBytes: MAX_STRING_BYTES });
