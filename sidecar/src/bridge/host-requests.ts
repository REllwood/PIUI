import type { ProtocolEnvelope, ProtocolErrorCategory } from '@piui/protocol';
import type {
  PublicCredential,
  PublicCredentialInfo,
} from '../pi/public-sdk.js';
import type { SidecarRouter } from './router.js';
import type { ProtocolEnvelopeWriter } from './protocol-writer.js';

const DEFAULT_MAX_PENDING = 128;
const DEFAULT_TIMEOUT_MS = 30_000;
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
type HostMethod = CredentialMethod | 'approval.request';

export type ApprovalRequestPayload = Readonly<{
  method: 'approval.request';
  schemaVersion: 1;
  generation: number;
  sessionId: string;
  workspaceId: string;
  workspaceRevision: number;
  invocationId: string;
  toolName: string;
  input: unknown;
  groupId?: string;
}>;
export type ApprovalGrant = Readonly<{
  approvalId: string;
  decisionId: string;
  invocationId: string;
  inputDigest: string;
  decision: 'approved' | 'denied' | 'expired' | 'cancelled';
  scopeIds: readonly string[];
}>;

type PendingRequest = {
  method: HostMethod;
  timer: ReturnType<typeof setTimeout>;
  resolve(value: unknown): void;
  reject(error: HostRequestError): void;
};

export type HostRequestClientOptions = {
  router: Pick<SidecarRouter, 'next'>;
  write: ProtocolEnvelopeWriter;
  maxPending?: number;
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

export function assertApprovalRequestPayload(value: unknown): asserts value is ApprovalRequestPayload {
  if (!isRecord(value)) throw new HostRequestError('approval-request-rejected');
  const hasGroup = 'groupId' in value;
  const keys = ['method', 'schemaVersion', 'generation', 'sessionId', 'workspaceId', 'workspaceRevision', 'invocationId', 'toolName', 'input', ...(hasGroup ? ['groupId'] : [])];
  if (!hasExactKeys(value, keys) || value.method !== 'approval.request' || value.schemaVersion !== 1
    || !Number.isSafeInteger(value.generation) || (value.generation as number) < 1
    || !Number.isSafeInteger(value.workspaceRevision) || (value.workspaceRevision as number) < 0
    || !validOpaque(value.sessionId, 'session-') || !validOpaque(value.workspaceId, 'workspace-')
    || !validOpaque(value.invocationId, 'invocation-') || (hasGroup && !validOpaque(value.groupId, 'group-'))
    || typeof value.toolName !== 'string' || value.toolName.length < 1 || value.toolName.length > 96 || CONTROL_CHARACTER.test(value.toolName)
    || !validateJsonValue(value.input, 0, new Set())) throw new HostRequestError('approval-request-rejected');
  let encoded: string;
  try { encoded = JSON.stringify(value.input); } catch { throw new HostRequestError('approval-request-rejected'); }
  if (Buffer.byteLength(encoded, 'utf8') > 65_536) throw new HostRequestError('approval-request-rejected');
}

export function assertApprovalHostRequestEnvelope(value: unknown): asserts value is ProtocolEnvelope {
  if (!isRecord(value) || !hasExactKeys(value, ['version', 'kind', 'id', 'sequence', 'payload'])
    || value.version !== 1 || value.kind !== 'host-request' || typeof value.id !== 'string' || !ENVELOPE_ID.test(value.id)
    || !Number.isSafeInteger(value.sequence) || (value.sequence as number) < 0) throw new HostRequestError('approval-request-rejected');
  assertApprovalRequestPayload(value.payload);
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
    if (!hasExactKeys(payload, ['schemaVersion', 'approvalId', 'invocationId', 'inputDigest', 'decision', 'scopeIds'])
      || payload.schemaVersion !== 1
      || typeof payload.approvalId !== 'string' || !/^approval-[0-9a-f]{32}$/.test(payload.approvalId)
      || typeof payload.invocationId !== 'string' || !/^invocation-[0-9a-f]{32}$/.test(payload.invocationId)
      || typeof payload.inputDigest !== 'string' || !/^[0-9a-f]{64}$/.test(payload.inputDigest)
      || !['approved', 'denied', 'expired', 'cancelled'].includes(payload.decision as string)
      || !Array.isArray(payload.scopeIds) || payload.scopeIds.length > 1
      || !payload.scopeIds.every((scope) => typeof scope === 'string' && /^scope-[0-9a-f]{32}$/.test(scope))
      || new Set(payload.scopeIds).size !== payload.scopeIds.length
      || (payload.decision === 'approved') !== (payload.scopeIds.length === 1)) failProtocol('approval-response-rejected');
    return Object.freeze({ approvalId: payload.approvalId, decisionId, invocationId: payload.invocationId, inputDigest: payload.inputDigest, decision: payload.decision, scopeIds: Object.freeze([...payload.scopeIds]) }) as ApprovalGrant;
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
  if (!envelope.error || !hasExactKeys(envelope.payload, []) || envelope.decisionId) failProtocol(method === 'approval.request' ? 'approval-response-rejected' : 'credential-response-rejected');
  const error = envelope.error as unknown as Record<string, unknown>;
  if (!hasExactKeys(error, ['category', 'message', 'retryable'])) failProtocol();

  const codes: readonly HostRequestErrorCode[] = method === 'approval.request'
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
  failProtocol(method === 'approval.request' ? 'approval-response-rejected' : 'credential-response-rejected');
}

export class HostRequestClient implements CredentialHostTransport {
  readonly #router: Pick<SidecarRouter, 'next'>;
  readonly #write: ProtocolEnvelopeWriter;
  readonly #maxPending: number;
  readonly #timeoutMs: number;
  readonly #pending = new Map<string, PendingRequest>();
  readonly #retired = new Set<string>();
  #generationController = new AbortController();
  #currentGeneration: CredentialHostGeneration = Object.freeze({
    signal: this.#generationController.signal,
  });
  #disconnected = false;

  constructor(options: HostRequestClientOptions) {
    if (
      !Number.isSafeInteger(options.maxPending ?? DEFAULT_MAX_PENDING)
      || (options.maxPending ?? DEFAULT_MAX_PENDING) < 1
      || (options.maxPending ?? DEFAULT_MAX_PENDING) > DEFAULT_MAX_PENDING
      || !Number.isSafeInteger(options.timeoutMs ?? DEFAULT_TIMEOUT_MS)
      || (options.timeoutMs ?? DEFAULT_TIMEOUT_MS) < 1
      || (options.timeoutMs ?? DEFAULT_TIMEOUT_MS) > 120_000
    ) {
      throw new HostRequestError('credential-request-rejected');
    }
    this.#router = options.router;
    this.#write = options.write;
    this.#maxPending = options.maxPending ?? DEFAULT_MAX_PENDING;
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  get credentialGeneration(): CredentialHostGeneration {
    return this.#currentGeneration;
  }

  /** @internal Test observability only. */
  get pendingCount(): number {
    return this.#pending.size;
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
    if (envelope.kind !== 'host-response') {
      if (
        envelope.correlationId
        && (
          this.#pending.has(envelope.correlationId)
          || this.#retired.has(envelope.correlationId)
        )
      ) {
        const pending = this.#take(envelope.correlationId);
        pending?.reject(new HostRequestError('credential-response-rejected'));
        failProtocol();
      }
      return false;
    }

    try {
      validateHostResponseEnvelope(envelope);
    } catch {
      if (envelope.correlationId) {
        this.#take(envelope.correlationId)?.reject(
          new HostRequestError('credential-response-rejected'),
        );
      }
      failProtocol();
    }
    const pending = this.#take(envelope.correlationId!);
    if (!pending) failProtocol();

    try {
      if (envelope.error) {
        pending.reject(parseHostError(envelope, pending.method));
      } else {
        pending.resolve(parseSuccess(pending.method, envelope.payload, envelope.decisionId));
      }
    } catch {
      pending.reject(new HostRequestError('credential-response-rejected'));
      failProtocol();
    }
    return true;
  }

  abortAll(): void {
    if (this.#disconnected) return;
    this.#generationController.abort(
      new HostRequestError('credential-request-cancelled'),
    );
    this.#settleAll('credential-request-cancelled');
    this.#generationController = new AbortController();
    this.#currentGeneration = Object.freeze({
      signal: this.#generationController.signal,
    });
  }

  disconnect(): void {
    if (this.#disconnected) return;
    this.#disconnected = true;
    this.#generationController.abort(
      new HostRequestError('credential-host-disconnected'),
    );
    this.#settleAll('credential-host-disconnected');
  }

  requestApproval(payload: ApprovalRequestPayload): Promise<ApprovalGrant> {
    assertApprovalRequestPayload(payload);
    return this.#request('approval.request', payload as unknown as Record<string, unknown>) as Promise<ApprovalGrant>;
  }

  #request(method: HostMethod, payload: Record<string, unknown>): Promise<unknown> {
    if (this.#disconnected) {
      return Promise.reject(new HostRequestError('credential-host-disconnected'));
    }
    if (this.#pending.size >= this.#maxPending) {
      return Promise.reject(new HostRequestError('credential-host-capacity'));
    }

    let envelope: ProtocolEnvelope | undefined = this.#router.next(
      'host-request',
      method,
      payload,
    );
    const requestId = envelope.id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const pending = this.#take(requestId);
        pending?.reject(new HostRequestError('credential-request-timeout'));
      }, this.#timeoutMs);
      timer.unref?.();
      this.#pending.set(requestId, { method, timer, resolve, reject });

      const outbound = envelope;
      try {
        if (method === 'approval.request') assertApprovalHostRequestEnvelope(outbound);
        else assertCredentialHostRequestEnvelope(outbound);
        this.#write(outbound);
      } catch {
        const pending = this.#take(requestId);
        pending?.reject(new HostRequestError('credential-operation-failed'));
      } finally {
        // Do not retain a secret-bearing set envelope in pending/timer closures.
        envelope = undefined;
      }
    });
  }

  #take(id: string): PendingRequest | undefined {
    const pending = this.#pending.get(id);
    if (!pending) return undefined;
    this.#pending.delete(id);
    clearTimeout(pending.timer);
    this.#retire(id);
    return pending;
  }

  #retire(id: string): void {
    this.#retired.delete(id);
    this.#retired.add(id);
    if (this.#retired.size > MAX_RETIRED_CORRELATIONS) {
      this.#retired.delete(this.#retired.values().next().value!);
    }
  }

  #settleAll(code: HostRequestErrorCode): void {
    const pending = [...this.#pending];
    this.#pending.clear();
    for (const [id, request] of pending) {
      clearTimeout(request.timer);
      this.#retire(id);
      request.reject(new HostRequestError(code));
    }
  }
}

export const CREDENTIAL_PROXY_LIMITS = Object.freeze({
  maxCredentialBytes: MAX_CREDENTIAL_BYTES,
  maxListEntries: MAX_LIST_ENTRIES,
  maxProviderQueues: MAX_PROVIDER_QUEUES,
  maxQueuedOperationsPerProvider: MAX_QUEUED_OPERATIONS_PER_PROVIDER,
  maxQueuedOperationsTotal: MAX_QUEUED_OPERATIONS_TOTAL,
  maxPending: DEFAULT_MAX_PENDING,
  maxRetiredCorrelations: MAX_RETIRED_CORRELATIONS,
});
