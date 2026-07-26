import type { ProtocolEnvelope, ProtocolErrorCategory } from '@piui/protocol';
import type {
  PublicCredential,
  PublicCredentialInfo,
} from '../pi/public-sdk.js';
import type { SidecarRouter } from './router.js';
import type { ProtocolEnvelopeWriter } from './protocol-writer.js';
import { canonicaliseApprovalInput } from '../pi/approval-canonical.js';

const DEFAULT_MAX_CREDENTIAL_PENDING = 128;
const DEFAULT_MAX_APPROVAL_PENDING = 128;
const DEFAULT_MAX_APPROVAL_READY_PENDING = 128;
const DEFAULT_CREDENTIAL_TIMEOUT_MS = 30_000;
const APPROVAL_TIMEOUT_MS = 125_000;
const MAX_CREDENTIAL_BYTES = 65_536;
const MAX_LIST_ENTRIES = 256;
const MAX_PROVIDER_QUEUES = 256;
const MAX_QUEUED_OPERATIONS_PER_PROVIDER = 32;
const MAX_QUEUED_OPERATIONS_TOTAL = 256;
const MAX_RETIRED_CORRELATIONS = 512;
const MAX_JSON_DEPTH = 32;
const MAX_OBJECT_PROPERTIES = 128;
const MAX_ARRAY_ITEMS = 256;
const ENVELOPE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CONTROL_CHARACTER = /\p{Cc}/u;
const APPROVAL_TOOL_NAME = /^[A-Za-z][A-Za-z0-9_-]{0,95}$/;

const HOST_ERROR_DETAILS = Object.freeze({
  'credential-request-rejected': {
    category: 'invalid-request',
    message: 'Credential request rejected',
    retryable: false,
  },
  'credential-store-unavailable': {
    category: 'unavailable',
    message: 'Credential store unavailable',
    retryable: true,
  },
  'credential-request-cancelled': {
    category: 'cancelled',
    message: 'Credential request cancelled',
    retryable: true,
  },
  'credential-operation-failed': {
    category: 'internal',
    message: 'Credential operation failed',
    retryable: false,
  },
  'credential-request-timeout': {
    category: 'timeout',
    message: 'Credential request timed out',
    retryable: true,
  },
  'credential-host-disconnected': {
    category: 'unavailable',
    message: 'Credential host disconnected',
    retryable: true,
  },
  'credential-host-capacity': {
    category: 'unavailable',
    message: 'Credential host capacity exceeded',
    retryable: true,
  },
  'credential-response-rejected': {
    category: 'invalid-request',
    message: 'Credential response rejected',
    retryable: false,
  },
  'approval-request-rejected': {
    category: 'invalid-request',
    message: 'Approval request rejected',
    retryable: false,
  },
  'approval-unavailable': {
    category: 'unavailable',
    message: 'Approval unavailable',
    retryable: false,
  },
  'approval-cancelled': {
    category: 'cancelled',
    message: 'Approval cancelled',
    retryable: false,
  },
  'approval-timeout': {
    category: 'timeout',
    message: 'Approval timed out',
    retryable: false,
  },
  'approval-response-rejected': {
    category: 'invalid-request',
    message: 'Approval response rejected',
    retryable: false,
  },
} as const satisfies Record<
  string,
  { category: ProtocolErrorCategory; message: string; retryable: boolean }
>);

export type HostRequestErrorCode = keyof typeof HOST_ERROR_DETAILS;

export class HostRequestError extends Error {
  readonly category: ProtocolErrorCategory;
  readonly retryable: boolean;

  constructor(readonly code: HostRequestErrorCode) {
    const details = HOST_ERROR_DETAILS[code];
    super(details.message);
    this.name = 'HostRequestError';
    this.stack = `${this.name}: ${this.message}`;
    this.category = details.category;
    this.retryable = details.retryable;
  }
}

/** @internal Private lifecycle contract between the sidecar host client and store proxy. */
export type CredentialHostGeneration = Readonly<{
  signal: AbortSignal;
}>;

export interface CredentialHostTransport {
  readonly credentialGeneration: CredentialHostGeneration;
  get(providerId: string): Promise<PublicCredential | undefined>;
  list(): Promise<readonly PublicCredentialInfo[]>;
  set(providerId: string, credential: PublicCredential): Promise<void>;
  remove(providerId: string): Promise<void>;
}

type CredentialMethod =
  | 'credential.get'
  | 'credential.list'
  | 'credential.set'
  | 'credential.remove';
export type ApprovalCohortMember = Readonly<{
  ordinal: number;
  toolCallId: string;
  toolName: string;
}>;

export type ApprovalCohortDescriptor = Readonly<{
  assistantEntryId: string;
  cohortDigest: string;
  orderedMembers: readonly ApprovalCohortMember[];
}>;

type LegacyApprovalRequestPayload = Readonly<{
  method: 'approval.request';
  schemaVersion: 1;
  generation: number;
  sessionId: string;
  workspaceId: string;
  workspaceRevision: number;
  invocationId: string;
  toolName: string;
  inputDigest: string;
  input: unknown;
  groupId?: string;
}>;

export type CohortApprovalRequestPayload = Readonly<{
  method: 'approval.request';
  schemaVersion: 2;
  generation: number;
  sessionId: string;
  workspaceId: string;
  workspaceRevision: number;
  invocationId: string;
  toolCallId: string;
  toolName: string;
  inputDigest: string;
  input: unknown;
  cohort: ApprovalCohortDescriptor;
}>;

export type ApprovalRequestPayload = LegacyApprovalRequestPayload | CohortApprovalRequestPayload;
export type ApprovalReadyPayload = Readonly<{
  method: 'approval.ready';
  schemaVersion: 2;
  generation: number;
  invocationId: string;
  toolCallId: string;
  inputDigest: string;
  cohortDigest: string;
}>;
export type ApprovalAbandonPayload = Readonly<{
  method: 'approval.abandon';
  schemaVersion: 2;
  generation: number;
  sessionId: string;
  workspaceId: string;
  workspaceRevision: number;
  assistantEntryId: string;
  cohortDigest: string;
  reason: 'pi-abort' | 'definition-change' | 'digest-change' | 'extension-error' | 'session-shutdown';
}>;

type ApprovalControlPayload = ApprovalReadyPayload | ApprovalAbandonPayload;
type HostMethod = CredentialMethod | 'approval.request' | 'approval.ready' | 'approval.abandon';

export type ApprovalGrant = Readonly<{
  approvalId: string;
  decisionId: string;
  invocationId: string;
  inputDigest: string;
  decision: 'approved' | 'denied' | 'expired' | 'cancelled';
  scopeIds: readonly string[];
  toolCallId?: string;
  cohortDigest?: string;
  transactionId?: string;
  groupCommit?: Readonly<{
    groupId: string;
    groupDecisionId: string;
    transactionId: string;
    cohortDigest: string;
    memberCount: number;
  }>;
}>;

type PendingRequest = {
  method: HostMethod;
  timer: ReturnType<typeof setTimeout>;
  payload?: ApprovalRequestPayload | ApprovalControlPayload;
  resolve(value: unknown): void;
  reject(error: HostRequestError): void;
};

export type HostRequestClientOptions = {
  router: Pick<SidecarRouter, 'next'>;
  write: ProtocolEnvelopeWriter;
  /** Credential capacity retained for API compatibility. */
  maxPending?: number;
  maxApprovalPending?: number;
  maxApprovalReadyPending?: number;
  /** Credential timeout retained for API compatibility. */
  timeoutMs?: number;
};

function failProtocol(code: HostRequestErrorCode = 'credential-response-rejected'): never {
  throw new HostRequestError(code);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => actual.includes(key));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validateJsonValue(value: unknown, depth: number, ancestors: Set<object>): boolean {
  if (depth > MAX_JSON_DEPTH) return false;
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isSafeInteger(value);
  if (typeof value !== 'object') return false;
  if (ancestors.has(value)) return false;

  ancestors.add(value);
  let valid: boolean;
  if (Array.isArray(value)) {
    valid = value.length <= MAX_ARRAY_ITEMS
      && value.every((entry) => validateJsonValue(entry, depth + 1, ancestors));
  } else if (isRecord(value)) {
    const entries = Object.entries(value);
    valid = entries.length <= MAX_OBJECT_PROPERTIES
      && entries.every(([key, entry]) => (
        key.length <= 128
        && !CONTROL_CHARACTER.test(key)
        && validateJsonValue(entry, depth + 1, ancestors)
      ));
  } else {
    valid = false;
  }
  ancestors.delete(value);
  return valid;
}

function validOpaque(value: unknown, prefix: string): value is string {
  return typeof value === 'string' && new RegExp(`^${prefix}[0-9a-f]{32}$`).test(value);
}

export function isApprovalToolName(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const match = APPROVAL_TOOL_NAME.exec(value);
  return match?.[0] === value;
}

function validWireCoordinate(value: unknown): value is string {
  return typeof value === 'string' && ENVELOPE_ID.test(value);
}

function assertCohortDescriptor(value: unknown): asserts value is ApprovalCohortDescriptor {
  if (!isRecord(value) || !hasExactKeys(value, ['assistantEntryId', 'cohortDigest', 'orderedMembers'])
    || !validWireCoordinate(value.assistantEntryId)
    || typeof value.cohortDigest !== 'string' || !/^[0-9a-f]{64}$/.test(value.cohortDigest)
    || !Array.isArray(value.orderedMembers) || value.orderedMembers.length < 1 || value.orderedMembers.length > 32) {
    throw new HostRequestError('approval-request-rejected');
  }
  const ids = new Set<string>();
  for (let index = 0; index < value.orderedMembers.length; index += 1) {
    const member = value.orderedMembers[index];
    if (!isRecord(member) || !hasExactKeys(member, ['ordinal', 'toolCallId', 'toolName'])
      || member.ordinal !== index || !validWireCoordinate(member.toolCallId)
      || !isApprovalToolName(member.toolName) || ids.has(member.toolCallId)) {
      throw new HostRequestError('approval-request-rejected');
    }
    ids.add(member.toolCallId);
  }
  let canonical: ReturnType<typeof canonicaliseApprovalInput> | undefined;
  try {
    canonical = canonicaliseApprovalInput({
      assistantEntryId: value.assistantEntryId,
      orderedMembers: value.orderedMembers,
    });
    if (canonical.digest !== value.cohortDigest) throw new HostRequestError('approval-request-rejected');
  } catch {
    throw new HostRequestError('approval-request-rejected');
  } finally {
    canonical?.bytes.fill(0);
  }
}

export function assertApprovalRequestPayload(value: unknown): asserts value is ApprovalRequestPayload {
  if (!isRecord(value)) throw new HostRequestError('approval-request-rejected');
  const legacy = value.schemaVersion === 1;
  const hasGroup = legacy && 'groupId' in value;
  const keys = legacy
    ? ['method', 'schemaVersion', 'generation', 'sessionId', 'workspaceId', 'workspaceRevision', 'invocationId', 'toolName', 'inputDigest', 'input', ...(hasGroup ? ['groupId'] : [])]
    : ['method', 'schemaVersion', 'generation', 'sessionId', 'workspaceId', 'workspaceRevision', 'invocationId', 'toolCallId', 'toolName', 'inputDigest', 'input', 'cohort'];
  if (!hasExactKeys(value, keys) || value.method !== 'approval.request' || ![1, 2].includes(value.schemaVersion as number)
    || !Number.isSafeInteger(value.generation) || (value.generation as number) < 1
    || !Number.isSafeInteger(value.workspaceRevision) || (value.workspaceRevision as number) < 0
    || !validOpaque(value.sessionId, 'session-') || !validOpaque(value.workspaceId, 'workspace-')
    || !validOpaque(value.invocationId, 'invocation-') || (hasGroup && !validOpaque(value.groupId, 'group-'))
    || !isApprovalToolName(value.toolName)
    || typeof value.inputDigest !== 'string' || !/^[0-9a-f]{64}$/.test(value.inputDigest)) throw new HostRequestError('approval-request-rejected');
  if (!legacy) {
    if (!validWireCoordinate(value.toolCallId)) throw new HostRequestError('approval-request-rejected');
    assertCohortDescriptor(value.cohort);
    const matches = value.cohort.orderedMembers.filter((member) => member.toolCallId === value.toolCallId && member.toolName === value.toolName);
    if (matches.length !== 1) throw new HostRequestError('approval-request-rejected');
  }
  let canonical: ReturnType<typeof canonicaliseApprovalInput> | undefined;
  try {
    canonical = canonicaliseApprovalInput(value.input);
    if (canonical.digest !== value.inputDigest) throw new HostRequestError('approval-request-rejected');
  } catch {
    throw new HostRequestError('approval-request-rejected');
  } finally {
    canonical?.bytes.fill(0);
  }
}

function assertApprovalControlPayload(value: unknown): asserts value is ApprovalControlPayload {
  if (!isRecord(value) || value.schemaVersion !== 2 || !Number.isSafeInteger(value.generation) || (value.generation as number) < 1) {
    throw new HostRequestError('approval-request-rejected');
  }
  if (value.method === 'approval.ready') {
    if (!hasExactKeys(value, ['method', 'schemaVersion', 'generation', 'invocationId', 'toolCallId', 'inputDigest', 'cohortDigest'])
      || !validOpaque(value.invocationId, 'invocation-') || !validWireCoordinate(value.toolCallId)
      || typeof value.inputDigest !== 'string' || !/^[0-9a-f]{64}$/.test(value.inputDigest)
      || typeof value.cohortDigest !== 'string' || !/^[0-9a-f]{64}$/.test(value.cohortDigest)) {
      throw new HostRequestError('approval-request-rejected');
    }
    return;
  }
  if (value.method === 'approval.abandon') {
    if (!hasExactKeys(value, [
      'method', 'schemaVersion', 'generation', 'sessionId', 'workspaceId',
      'workspaceRevision', 'assistantEntryId', 'cohortDigest', 'reason',
    ])
      || !validOpaque(value.sessionId, 'session-') || !validOpaque(value.workspaceId, 'workspace-')
      || !Number.isSafeInteger(value.workspaceRevision) || (value.workspaceRevision as number) < 0
      || !validWireCoordinate(value.assistantEntryId)
      || typeof value.cohortDigest !== 'string' || !/^[0-9a-f]{64}$/.test(value.cohortDigest)
      || !['pi-abort', 'definition-change', 'digest-change', 'extension-error', 'session-shutdown'].includes(value.reason as string)) {
      throw new HostRequestError('approval-request-rejected');
    }
    return;
  }
  throw new HostRequestError('approval-request-rejected');
}

export function assertApprovalHostRequestEnvelope(value: unknown): asserts value is ProtocolEnvelope {
  if (!isRecord(value) || !hasExactKeys(value, ['version', 'kind', 'id', 'sequence', 'payload'])
    || value.version !== 1 || value.kind !== 'host-request' || typeof value.id !== 'string' || !ENVELOPE_ID.test(value.id)
    || !Number.isSafeInteger(value.sequence) || (value.sequence as number) < 0 || !isRecord(value.payload)) {
    throw new HostRequestError('approval-request-rejected');
  }
  if (value.payload.method === 'approval.request') assertApprovalRequestPayload(value.payload);
  else assertApprovalControlPayload(value.payload);
}

export function assertApprovalResponsePayload(value: unknown): asserts value is Readonly<{ decisionId: string; payload: Record<string, unknown> }> {
  if (!isRecord(value) || !hasExactKeys(value, ['decisionId', 'payload']) || !validOpaque(value.decisionId, 'decision-') || !isRecord(value.payload)) throw new HostRequestError('approval-response-rejected');
  parseSuccess('approval.request', value.payload, value.decisionId);
}

export function assertCredentialProviderId(providerId: string): void {
  if (
    typeof providerId !== 'string'
    || providerId.length === 0
    || CONTROL_CHARACTER.test(providerId)
  ) {
    throw new HostRequestError('credential-request-rejected');
  }
  let codePoints = 0;
  for (const _codePoint of providerId) {
    codePoints += 1;
    if (codePoints > 128) {
      throw new HostRequestError('credential-request-rejected');
    }
  }
}

export function assertPublicCredential(
  credential: unknown,
): asserts credential is PublicCredential {
  if (!isRecord(credential) || !validateJsonValue(credential, 0, new Set())) {
    throw new HostRequestError('credential-request-rejected');
  }

  if (credential.type === 'api_key') {
    if (!Object.keys(credential).every((key) => ['type', 'key', 'env'].includes(key))) {
      throw new HostRequestError('credential-request-rejected');
    }
    if ('key' in credential && typeof credential.key !== 'string') {
      throw new HostRequestError('credential-request-rejected');
    }
    if ('env' in credential) {
      if (!isRecord(credential.env)) {
        throw new HostRequestError('credential-request-rejected');
      }
      if (!Object.values(credential.env).every((value) => typeof value === 'string')) {
        throw new HostRequestError('credential-request-rejected');
      }
    }
  } else if (credential.type === 'oauth') {
    if (
      typeof credential.access !== 'string'
      || typeof credential.refresh !== 'string'
      || !Number.isSafeInteger(credential.expires)
    ) {
      throw new HostRequestError('credential-request-rejected');
    }
  } else {
    throw new HostRequestError('credential-request-rejected');
  }

  let encoded: string;
  try {
    encoded = JSON.stringify(credential);
  } catch {
    throw new HostRequestError('credential-request-rejected');
  }
  if (Buffer.byteLength(encoded, 'utf8') > MAX_CREDENTIAL_BYTES) {
    throw new HostRequestError('credential-request-rejected');
  }
}

/**
 * Strict A.15a boundary for private credential requests. The shared protocol
 * codec intentionally remains method-agnostic; Rust A.15b must mirror this
 * method-specific validator before activating the host route.
 */
export function assertCredentialHostRequestEnvelope(
  value: unknown,
): asserts value is ProtocolEnvelope {
  if (!isRecord(value)) throw new HostRequestError('credential-request-rejected');
  if (
    !hasExactKeys(value, ['version', 'kind', 'id', 'sequence', 'payload'])
    || value.version !== 1
    || value.kind !== 'host-request'
    || typeof value.id !== 'string'
    || !ENVELOPE_ID.test(value.id)
    || !Number.isSafeInteger(value.sequence)
    || (value.sequence as number) < 0
    || !isRecord(value.payload)
  ) {
    throw new HostRequestError('credential-request-rejected');
  }

  const payload = value.payload;
  if (payload.method === 'credential.list') {
    if (!hasExactKeys(payload, ['method'])) {
      throw new HostRequestError('credential-request-rejected');
    }
    return;
  }
  if (payload.method === 'credential.get' || payload.method === 'credential.remove') {
    if (!hasExactKeys(payload, ['method', 'providerId'])) {
      throw new HostRequestError('credential-request-rejected');
    }
    assertCredentialProviderId(payload.providerId as string);
    return;
  }
  if (payload.method === 'credential.set') {
    if (!hasExactKeys(payload, ['method', 'providerId', 'credential'])) {
      throw new HostRequestError('credential-request-rejected');
    }
    assertCredentialProviderId(payload.providerId as string);
    assertPublicCredential(payload.credential);
    return;
  }
  throw new HostRequestError('credential-request-rejected');
}

function validateCredentialInfo(value: unknown): value is PublicCredentialInfo {
  if (!isRecord(value) || !hasExactKeys(value, ['providerId', 'type'])) return false;
  try {
    assertCredentialProviderId(value.providerId as string);
  } catch {
    return false;
  }
  return value.type === 'api_key' || value.type === 'oauth';
}

function validateHostResponseEnvelope(envelope: ProtocolEnvelope): void {
  if (
    envelope.version !== 1
    || envelope.kind !== 'host-response'
    || !ENVELOPE_ID.test(envelope.id)
    || !envelope.correlationId
    || !ENVELOPE_ID.test(envelope.correlationId)
    || !Number.isSafeInteger(envelope.sequence)
    || envelope.sequence < 0
  ) {
    failProtocol();
  }
  if (envelope.decisionId !== undefined && !/^decision-[0-9a-f]{32}$/.test(envelope.decisionId)) failProtocol();
  const allowed = envelope.error
    ? ['version', 'kind', 'id', 'correlationId', 'sequence', 'payload', 'error']
    : ['version', 'kind', 'id', 'correlationId', 'sequence', 'payload', ...(envelope.decisionId ? ['decisionId'] : [])];
  if (!hasExactKeys(envelope as unknown as Record<string, unknown>, allowed)) failProtocol();
  if (!isRecord(envelope.payload)) failProtocol();
}

function parseSuccess(method: HostMethod, payload: Record<string, unknown>, decisionId?: string): unknown {
  if (method === 'approval.request') {
    if (!decisionId || !/^decision-[0-9a-f]{32}$/.test(decisionId)) failProtocol('approval-response-rejected');
    const legacy = payload.schemaVersion === 1;
    const keys = legacy
      ? ['schemaVersion', 'approvalId', 'invocationId', 'inputDigest', 'decision', 'scopeIds']
      : ['schemaVersion', 'method', 'approvalId', 'transactionId', 'invocationId', 'toolCallId', 'inputDigest', 'cohortDigest', 'decision', 'scopeIds'];
    if (!hasExactKeys(payload, keys) || ![1, 2].includes(payload.schemaVersion as number)
      || (!legacy && payload.method !== 'approval.resolve')
      || typeof payload.approvalId !== 'string' || !/^approval-[0-9a-f]{32}$/.test(payload.approvalId)
      || typeof payload.invocationId !== 'string' || !/^invocation-[0-9a-f]{32}$/.test(payload.invocationId)
      || typeof payload.inputDigest !== 'string' || !/^[0-9a-f]{64}$/.test(payload.inputDigest)
      || !['approved', 'denied', 'expired', 'cancelled'].includes(payload.decision as string)
      || !Array.isArray(payload.scopeIds) || payload.scopeIds.length > 1
      || !payload.scopeIds.every((scope) => typeof scope === 'string' && /^scope-[0-9a-f]{32}$/.test(scope))
      || new Set(payload.scopeIds).size !== payload.scopeIds.length
      || (payload.decision === 'approved') !== (payload.scopeIds.length === 1)
      || (!legacy && (!validOpaque(payload.transactionId, 'transaction-')
        || !validWireCoordinate(payload.toolCallId)
        || typeof payload.cohortDigest !== 'string' || !/^[0-9a-f]{64}$/.test(payload.cohortDigest)))) {
      failProtocol('approval-response-rejected');
    }
    return Object.freeze({
      approvalId: payload.approvalId,
      decisionId,
      invocationId: payload.invocationId,
      inputDigest: payload.inputDigest,
      decision: payload.decision,
      scopeIds: Object.freeze([...payload.scopeIds]),
      ...(!legacy ? {
        transactionId: payload.transactionId as string,
        toolCallId: payload.toolCallId as string,
        cohortDigest: payload.cohortDigest as string,
      } : {}),
    }) as ApprovalGrant;
  }
  if (method === 'approval.ready') {
    if (decisionId || !hasExactKeys(payload, ['schemaVersion', 'method', 'invocationId', 'accepted'])
      || payload.schemaVersion !== 2 || payload.method !== 'approval.ready-ack'
      || !validOpaque(payload.invocationId, 'invocation-') || payload.accepted !== true) {
      failProtocol('approval-response-rejected');
    }
    return undefined;
  }
  if (method === 'approval.abandon') {
    if (decisionId || !hasExactKeys(payload, ['schemaVersion', 'method', 'cohortDigest', 'cancelled'])
      || payload.schemaVersion !== 2 || payload.method !== 'approval.abandon-ack'
      || typeof payload.cohortDigest !== 'string' || !/^[0-9a-f]{64}$/.test(payload.cohortDigest)
      || payload.cancelled !== true) {
      failProtocol('approval-response-rejected');
    }
    return undefined;
  }
  if (decisionId) failProtocol('credential-response-rejected');
  if (method === 'credential.get') {
    if (hasExactKeys(payload, ['found']) && payload.found === false) return undefined;
    if (!hasExactKeys(payload, ['found', 'credential']) || payload.found !== true) failProtocol();
    try {
      assertPublicCredential(payload.credential);
    } catch {
      failProtocol();
    }
    return payload.credential;
  }
  if (method === 'credential.list') {
    if (!hasExactKeys(payload, ['entries']) || !Array.isArray(payload.entries)) failProtocol();
    if (payload.entries.length > MAX_LIST_ENTRIES || !payload.entries.every(validateCredentialInfo)) {
      failProtocol();
    }
    const providerIds = new Set(payload.entries.map((entry) => entry.providerId));
    if (providerIds.size !== payload.entries.length) failProtocol();
    return payload.entries;
  }
  if (method === 'credential.set') {
    if (!hasExactKeys(payload, ['stored']) || payload.stored !== true) failProtocol();
    return undefined;
  }
  if (!hasExactKeys(payload, ['removed']) || payload.removed !== true) failProtocol();
  return undefined;
}

function parseHostError(envelope: ProtocolEnvelope, method: HostMethod): HostRequestError {
  if (!envelope.error || !hasExactKeys(envelope.payload, []) || envelope.decisionId) failProtocol(method.startsWith('approval.') ? 'approval-response-rejected' : 'credential-response-rejected');
  const error = envelope.error as unknown as Record<string, unknown>;
  if (!hasExactKeys(error, ['category', 'message', 'retryable'])) failProtocol();

  const codes: readonly HostRequestErrorCode[] = method.startsWith('approval.')
    ? ['approval-request-rejected', 'approval-unavailable', 'approval-cancelled', 'approval-timeout']
    : ['credential-request-rejected', 'credential-store-unavailable', 'credential-request-cancelled', 'credential-operation-failed'];
  for (const code of codes) {
    const expected = HOST_ERROR_DETAILS[code];
    if (
      error.category === expected.category
      && error.message === expected.message
      && error.retryable === expected.retryable
    ) {
      return new HostRequestError(code);
    }
  }
  failProtocol(method.startsWith('approval.') ? 'approval-response-rejected' : 'credential-response-rejected');
}

export class HostRequestClient implements CredentialHostTransport {
  readonly #router: Pick<SidecarRouter, 'next'>;
  readonly #write: ProtocolEnvelopeWriter;
  readonly #maxCredentialPending: number;
  readonly #maxApprovalPending: number;
  readonly #maxApprovalReadyPending: number;
  readonly #credentialTimeoutMs: number;
  readonly #pending = new Map<string, PendingRequest>();
  readonly #retired = new Map<string, HostMethod>();
  #generationController = new AbortController();
  #currentGeneration: CredentialHostGeneration = Object.freeze({
    signal: this.#generationController.signal,
  });
  #disconnected = false;

  constructor(options: HostRequestClientOptions) {
    if (
      !Number.isSafeInteger(options.maxPending ?? DEFAULT_MAX_CREDENTIAL_PENDING)
      || (options.maxPending ?? DEFAULT_MAX_CREDENTIAL_PENDING) < 1
      || (options.maxPending ?? DEFAULT_MAX_CREDENTIAL_PENDING) > DEFAULT_MAX_CREDENTIAL_PENDING
      || !Number.isSafeInteger(options.maxApprovalPending ?? DEFAULT_MAX_APPROVAL_PENDING)
      || (options.maxApprovalPending ?? DEFAULT_MAX_APPROVAL_PENDING) < 1
      || (options.maxApprovalPending ?? DEFAULT_MAX_APPROVAL_PENDING) > DEFAULT_MAX_APPROVAL_PENDING
      || !Number.isSafeInteger(options.maxApprovalReadyPending ?? DEFAULT_MAX_APPROVAL_READY_PENDING)
      || (options.maxApprovalReadyPending ?? DEFAULT_MAX_APPROVAL_READY_PENDING) < 1
      || (options.maxApprovalReadyPending ?? DEFAULT_MAX_APPROVAL_READY_PENDING) > DEFAULT_MAX_APPROVAL_READY_PENDING
      || !Number.isSafeInteger(options.timeoutMs ?? DEFAULT_CREDENTIAL_TIMEOUT_MS)
      || (options.timeoutMs ?? DEFAULT_CREDENTIAL_TIMEOUT_MS) < 1
      || (options.timeoutMs ?? DEFAULT_CREDENTIAL_TIMEOUT_MS) > 120_000
    ) {
      throw new HostRequestError('credential-request-rejected');
    }
    this.#router = options.router;
    this.#write = options.write;
    this.#maxCredentialPending = options.maxPending ?? DEFAULT_MAX_CREDENTIAL_PENDING;
    this.#maxApprovalPending = options.maxApprovalPending ?? DEFAULT_MAX_APPROVAL_PENDING;
    this.#maxApprovalReadyPending = options.maxApprovalReadyPending ?? DEFAULT_MAX_APPROVAL_READY_PENDING;
    this.#credentialTimeoutMs = options.timeoutMs ?? DEFAULT_CREDENTIAL_TIMEOUT_MS;
  }

  get credentialGeneration(): CredentialHostGeneration {
    return this.#currentGeneration;
  }

  /** @internal Test observability only. */
  get pendingCount(): number {
    return this.#pending.size;
  }

  /** @internal Test observability only. */
  get pendingApprovalCount(): number {
    return this.#pendingCount('approval.request');
  }

  /** @internal Test observability only. */
  get pendingApprovalReadyCount(): number {
    return this.#pendingCount('approval.ready');
  }

  /** @internal Test observability only. */
  get pendingCredentialCount(): number {
    return this.#pending.size - this.pendingApprovalCount - this.pendingApprovalReadyCount - this.#pendingCount('approval.abandon');
  }

  /** @internal Test observability only. */
  get retiredCorrelationCount(): number {
    return this.#retired.size;
  }

  get(providerId: string): Promise<PublicCredential | undefined> {
    assertCredentialProviderId(providerId);
    return this.#request('credential.get', { method: 'credential.get', providerId }) as Promise<PublicCredential | undefined>;
  }

  list(): Promise<readonly PublicCredentialInfo[]> {
    return this.#request('credential.list', { method: 'credential.list' }) as Promise<readonly PublicCredentialInfo[]>;
  }

  set(providerId: string, credential: PublicCredential): Promise<void> {
    assertCredentialProviderId(providerId);
    assertPublicCredential(credential);
    return this.#request('credential.set', {
      method: 'credential.set',
      providerId,
      credential,
    }) as Promise<void>;
  }

  remove(providerId: string): Promise<void> {
    assertCredentialProviderId(providerId);
    return this.#request('credential.remove', { method: 'credential.remove', providerId }) as Promise<void>;
  }

  /**
   * Consumes private responses before ordinary routing. A correlated envelope
   * of any other kind is a protocol violation rather than an ordinary reply.
   */
  consume(envelope: ProtocolEnvelope): boolean {
    try {
      return this.#consumeEnvelope(envelope);
    } catch (error) {
      if (error instanceof HostRequestError
        && (error.code === 'approval-response-rejected'
          || error.code === 'credential-response-rejected')) {
        // A private response violation means the two authorities no longer
        // agree. Cut off every lane immediately; no waiter may survive it.
        this.disconnect();
      }
      throw error;
    }
  }

  #consumeEnvelope(envelope: ProtocolEnvelope): boolean {
    const correlation = envelope.correlationId;
    const owner = correlation ? this.#pending.get(correlation) : undefined;
    const retiredMethod = correlation ? this.#retired.get(correlation) : undefined;
    const method = owner?.method ?? retiredMethod;
    const rejectionCode: HostRequestErrorCode = method?.startsWith('approval.')
      ? 'approval-response-rejected'
      : 'credential-response-rejected';

    if (envelope.kind !== 'host-response') {
      if (correlation && method) {
        this.#take(correlation)?.reject(new HostRequestError(rejectionCode));
        failProtocol(rejectionCode);
      }
      return false;
    }

    try {
      validateHostResponseEnvelope(envelope);
    } catch {
      if (correlation) this.#take(correlation)?.reject(new HostRequestError(rejectionCode));
      failProtocol(rejectionCode);
    }
    if (!correlation || !method) failProtocol(rejectionCode);

    if (owner?.method === 'approval.request' && envelope.payload.method === 'approval.group-commit') {
      return this.#consumeGroupCommit(envelope);
    }

    // Rust's ordinary expiry arrives before the longer local guard while the
    // owner is still pending. Any response after local retirement is replayed
    // private authority and is generation-fatal, even if well formed.
    const pending = this.#take(correlation);
    if (!pending) failProtocol(rejectionCode);
    try {
      if (envelope.error) {
        pending.reject(parseHostError(envelope, pending.method));
      } else {
        const parsed = parseSuccess(pending.method, envelope.payload, envelope.decisionId);
        this.#validateExactResponse(pending, envelope.payload, parsed);
        pending.resolve(parsed);
      }
    } catch {
      pending.reject(new HostRequestError(rejectionCode));
      failProtocol(rejectionCode);
    }
    return true;
  }

  abortAll(): void {
    if (this.#disconnected) return;
    this.#generationController.abort(new HostRequestError('credential-request-cancelled'));
    this.#settleAll('credential-request-cancelled', 'approval-cancelled');
    this.#generationController = new AbortController();
    this.#currentGeneration = Object.freeze({ signal: this.#generationController.signal });
  }

  disconnect(): void {
    if (this.#disconnected) return;
    this.#disconnected = true;
    this.#generationController.abort(new HostRequestError('credential-host-disconnected'));
    this.#settleAll('credential-host-disconnected', 'approval-unavailable');
  }

  requestApproval(payload: ApprovalRequestPayload): Promise<ApprovalGrant> {
    assertApprovalRequestPayload(payload);
    return this.#request('approval.request', payload as unknown as Record<string, unknown>) as Promise<ApprovalGrant>;
  }

  notifyApprovalReady(payload: ApprovalReadyPayload): Promise<void> {
    assertApprovalControlPayload(payload);
    return this.#request('approval.ready', payload as unknown as Record<string, unknown>) as Promise<void>;
  }

  abandonApproval(payload: ApprovalAbandonPayload): Promise<void> {
    assertApprovalControlPayload(payload);
    return this.#request('approval.abandon', payload as unknown as Record<string, unknown>) as Promise<void>;
  }

  #request(method: HostMethod, payload: Record<string, unknown>): Promise<unknown> {
    const approval = method.startsWith('approval.');
    if (this.#disconnected) {
      return Promise.reject(new HostRequestError(approval ? 'approval-unavailable' : 'credential-host-disconnected'));
    }
    let methodCount: number;
    let capacity: number;
    if (method === 'approval.request') {
      methodCount = this.#pendingCount(method);
      capacity = this.#maxApprovalPending;
    } else if (method === 'approval.ready' || method === 'approval.abandon') {
      methodCount = this.#pendingCount('approval.ready') + this.#pendingCount('approval.abandon');
      capacity = this.#maxApprovalReadyPending;
    } else {
      methodCount = this.pendingCredentialCount;
      capacity = this.#maxCredentialPending;
    }
    if (methodCount >= capacity) {
      return Promise.reject(new HostRequestError(approval ? 'approval-unavailable' : 'credential-host-capacity'));
    }

    let envelope: ProtocolEnvelope | undefined = this.#router.next('host-request', method, payload);
    const requestId = envelope.id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const pending = this.#take(requestId);
        pending?.reject(new HostRequestError(approval ? 'approval-timeout' : 'credential-request-timeout'));
      }, approval ? APPROVAL_TIMEOUT_MS : this.#credentialTimeoutMs);
      timer.unref?.();
      this.#pending.set(requestId, {
        method,
        timer,
        ...(approval ? { payload: payload as unknown as ApprovalRequestPayload | ApprovalControlPayload } : {}),
        resolve,
        reject,
      });

      const outbound = envelope;
      try {
        if (approval) assertApprovalHostRequestEnvelope(outbound);
        else assertCredentialHostRequestEnvelope(outbound);
        this.#write(outbound);
      } catch {
        const pending = this.#take(requestId);
        pending?.reject(new HostRequestError(approval ? 'approval-unavailable' : 'credential-operation-failed'));
      } finally {
        // Do not retain a secret-bearing set envelope in pending/timer closures.
        envelope = undefined;
      }
    });
  }

  #validateExactResponse(
    pending: PendingRequest,
    payload: Record<string, unknown>,
    parsed: unknown,
  ): void {
    if (pending.method === 'approval.request' && pending.payload?.method === 'approval.request') {
      const request = pending.payload;
      const grant = parsed as ApprovalGrant;
      if (grant.invocationId !== request.invocationId || grant.inputDigest !== request.inputDigest) {
        failProtocol('approval-response-rejected');
      }
      if (request.schemaVersion === 2 && (
        grant.toolCallId !== request.toolCallId
        || grant.cohortDigest !== request.cohort.cohortDigest
        || !grant.transactionId
      )) failProtocol('approval-response-rejected');
      return;
    }
    if (pending.method === 'approval.ready' && pending.payload?.method === 'approval.ready') {
      if (payload.invocationId !== pending.payload.invocationId) failProtocol('approval-response-rejected');
      return;
    }
    if (pending.method === 'approval.abandon' && pending.payload?.method === 'approval.abandon') {
      if (payload.cohortDigest !== pending.payload.cohortDigest) failProtocol('approval-response-rejected');
    }
  }

  #consumeGroupCommit(envelope: ProtocolEnvelope): true {
    if (envelope.error || !envelope.decisionId || !validOpaque(envelope.decisionId, 'decision-')) {
      failProtocol('approval-response-rejected');
    }
    const payload = envelope.payload;
    if (!hasExactKeys(payload, [
      'schemaVersion', 'method', 'generation', 'sessionId', 'workspaceId',
      'workspaceRevision', 'assistantEntryId', 'groupId', 'transactionId',
      'cohortDigest', 'decision', 'members',
    ])
      || payload.schemaVersion !== 2 || payload.method !== 'approval.group-commit'
      || !Number.isSafeInteger(payload.generation) || (payload.generation as number) < 1
      || !validOpaque(payload.sessionId, 'session-') || !validOpaque(payload.workspaceId, 'workspace-')
      || !Number.isSafeInteger(payload.workspaceRevision) || (payload.workspaceRevision as number) < 0
      || !validWireCoordinate(payload.assistantEntryId)
      || !validOpaque(payload.groupId, 'group-') || !validOpaque(payload.transactionId, 'transaction-')
      || typeof payload.cohortDigest !== 'string' || !/^[0-9a-f]{64}$/.test(payload.cohortDigest)
      || payload.decision !== 'approved' || !Array.isArray(payload.members)
      || payload.members.length < 2 || payload.members.length > 32) {
      failProtocol('approval-response-rejected');
    }

    const expectedRequests = [...this.#pending.entries()].filter((entry): entry is [string, PendingRequest & { payload: CohortApprovalRequestPayload }] => {
      const request = entry[1];
      return request.method === 'approval.request'
        && request.payload?.method === 'approval.request'
        && request.payload.schemaVersion === 2
        && request.payload.generation === payload.generation
        && request.payload.sessionId === payload.sessionId
        && request.payload.workspaceId === payload.workspaceId
        && request.payload.workspaceRevision === payload.workspaceRevision
        && request.payload.cohort.assistantEntryId === payload.assistantEntryId
        && request.payload.cohort.cohortDigest === payload.cohortDigest;
    });
    if (expectedRequests.length === 0) failProtocol('approval-response-rejected');
    const descriptor = expectedRequests[0][1].payload.cohort;
    if (expectedRequests.length !== descriptor.orderedMembers.length || payload.members.length !== descriptor.orderedMembers.length) {
      failProtocol('approval-response-rejected');
    }

    const byToolCall = new Map(expectedRequests.map(([correlation, pending]) => [pending.payload.toolCallId, { correlation, pending }]));
    if (byToolCall.size !== descriptor.orderedMembers.length) failProtocol('approval-response-rejected');
    const seenCorrelations = new Set<string>();
    const seenApprovals = new Set<string>();
    const seenDecisions = new Set<string>();
    const seenScopes = new Set<string>();
    const grants: Array<{ correlation: string; pending: PendingRequest; grant: ApprovalGrant }> = [];

    for (let memberIndex = 0; memberIndex < payload.members.length; memberIndex += 1) {
      const raw = payload.members[memberIndex];
      if (!isRecord(raw) || !hasExactKeys(raw, ['correlationId', 'approvalId', 'decisionId', 'invocationId', 'toolCallId', 'inputDigest', 'scopeId'])
        || !validWireCoordinate(raw.correlationId) || !validOpaque(raw.approvalId, 'approval-')
        || !validOpaque(raw.decisionId, 'decision-') || !validOpaque(raw.invocationId, 'invocation-')
        || !validWireCoordinate(raw.toolCallId) || typeof raw.inputDigest !== 'string' || !/^[0-9a-f]{64}$/.test(raw.inputDigest)
        || !validOpaque(raw.scopeId, 'scope-')
        || seenCorrelations.has(raw.correlationId) || seenApprovals.has(raw.approvalId)
        || seenDecisions.has(raw.decisionId) || seenScopes.has(raw.scopeId)) {
        failProtocol('approval-response-rejected');
      }
      const expectedMember = descriptor.orderedMembers[memberIndex];
      const expected = byToolCall.get(raw.toolCallId);
      const request = expected?.pending.payload;
      if (!expectedMember || raw.toolCallId !== expectedMember.toolCallId
        || !expected || expected.correlation !== raw.correlationId || request?.method !== 'approval.request'
        || request.schemaVersion !== 2 || request.invocationId !== raw.invocationId
        || request.inputDigest !== raw.inputDigest) {
        failProtocol('approval-response-rejected');
      }
      seenCorrelations.add(raw.correlationId);
      seenApprovals.add(raw.approvalId);
      seenDecisions.add(raw.decisionId);
      seenScopes.add(raw.scopeId);
      grants.push({
        correlation: raw.correlationId,
        pending: expected.pending,
        grant: Object.freeze({
          approvalId: raw.approvalId,
          decisionId: raw.decisionId,
          invocationId: raw.invocationId,
          toolCallId: raw.toolCallId,
          inputDigest: raw.inputDigest,
          cohortDigest: payload.cohortDigest,
          transactionId: payload.transactionId,
          decision: 'approved',
          scopeIds: Object.freeze([raw.scopeId]),
          groupCommit: Object.freeze({
            groupId: payload.groupId,
            groupDecisionId: envelope.decisionId,
            transactionId: payload.transactionId,
            cohortDigest: payload.cohortDigest,
            memberCount: payload.members.length,
          }),
        }),
      });
    }
    if (grants.length !== expectedRequests.length
      || !grants.some((entry) => entry.correlation === envelope.correlationId)) {
      failProtocol('approval-response-rejected');
    }

    const owned: Array<{ pending: PendingRequest; grant: ApprovalGrant }> = [];
    for (const { correlation, grant } of grants) {
      const pending = this.#take(correlation);
      if (!pending || pending.method !== 'approval.request') failProtocol('approval-response-rejected');
      owned.push({ pending, grant });
    }
    // Promise continuations cannot run until this complete LF frame and exact
    // set have been synchronously validated and every member has been removed.
    for (const { pending, grant } of owned) pending.resolve(grant);
    return true;
  }

  #pendingCount(method: HostMethod): number {
    let count = 0;
    for (const pending of this.#pending.values()) if (pending.method === method) count += 1;
    return count;
  }

  #take(id: string): PendingRequest | undefined {
    const pending = this.#pending.get(id);
    if (!pending) return undefined;
    this.#pending.delete(id);
    clearTimeout(pending.timer);
    this.#retire(id, pending.method);
    return pending;
  }

  #retire(id: string, method: HostMethod): void {
    this.#retired.delete(id);
    this.#retired.set(id, method);
    if (this.#retired.size > MAX_RETIRED_CORRELATIONS) {
      this.#retired.delete(this.#retired.keys().next().value!);
    }
  }

  #settleAll(credentialCode: HostRequestErrorCode, approvalCode: HostRequestErrorCode): void {
    const pending = [...this.#pending];
    this.#pending.clear();
    for (const [id, request] of pending) {
      clearTimeout(request.timer);
      this.#retire(id, request.method);
      request.reject(new HostRequestError(request.method.startsWith('approval.') ? approvalCode : credentialCode));
    }
  }
}

export const CREDENTIAL_PROXY_LIMITS = Object.freeze({
  maxCredentialBytes: MAX_CREDENTIAL_BYTES,
  maxListEntries: MAX_LIST_ENTRIES,
  maxProviderQueues: MAX_PROVIDER_QUEUES,
  maxQueuedOperationsPerProvider: MAX_QUEUED_OPERATIONS_PER_PROVIDER,
  maxQueuedOperationsTotal: MAX_QUEUED_OPERATIONS_TOTAL,
  maxPending: DEFAULT_MAX_CREDENTIAL_PENDING,
  maxApprovalPending: DEFAULT_MAX_APPROVAL_PENDING,
  maxApprovalReadyPending: DEFAULT_MAX_APPROVAL_READY_PENDING,
  credentialTimeoutMs: DEFAULT_CREDENTIAL_TIMEOUT_MS,
  approvalTimeoutMs: APPROVAL_TIMEOUT_MS,
  maxRetiredCorrelations: MAX_RETIRED_CORRELATIONS,
});
