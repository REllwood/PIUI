import {
  lstat,
  readdir,
  realpath,
} from 'node:fs/promises';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import type { ProtocolEnvelope } from '@piui/protocol';
import type { TrustedResourceCounts } from './public-sdk.js';
import {
  TrustLoaderError,
  TrustLoaderSupervisor,
} from './trust-loader.js';

const SCHEMA_VERSION = 1;
const MAX_WORKSPACES = 32;
const MAX_PENDING = 64;
const MAX_PENDING_PER_WORKSPACE = 32;
const MAX_SNAPSHOT_ENTRIES = 256;
const MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024;
const MAX_PATH_BYTES = 4_096;
const MAX_JS_SAFE_INTEGER = 9_007_199_254_740_991;
const WORKSPACE_ID = /^workspace-[a-f0-9]{32}$/;
const LEASE_ID = /^trust-[a-f0-9]{32}$/;
const INTERNAL_REQUEST_ID = /^rust-workspace-[A-Za-z0-9._:-]{1,111}$/;
const CONTROL_CHARACTER = /\p{Cc}/u;

export type WorkspaceMethod =
  | 'workspace.sync'
  | 'workspace.openUntrusted'
  | 'workspace.authorise'
  | 'workspace.loadTrusted'
  | 'workspace.revoke';

export type WorkspaceRequest = Readonly<{
  method: WorkspaceMethod;
  schemaVersion: 1;
  workspaceId: string;
  generation: number;
  revision: number;
  expectedRevision?: number;
  trustState?: 'untrusted' | 'trusted' | 'revoked';
  leaseId?: string;
  snapshotRoot?: string;
  agentRoot?: string;
}>;

export type WorkspaceGateReply = Readonly<Record<string, unknown>>;

type WorkspacePhase = 'open' | 'trusted' | 'loading' | 'loaded' | 'failed' | 'revoked';

type WorkspaceMirror = {
  generation: number;
  revision: number;
  phase: WorkspacePhase;
  leaseId?: string;
  result?: TrustedResourceCounts;
  failure?: WorkspaceGateErrorCode;
  loadAttempted: boolean;
};

const ERROR_DETAILS = Object.freeze({
  'workspace-request-rejected': ['invalid-request', 'Workspace request rejected'],
  'workspace-capacity': ['unavailable', 'Workspace capacity unavailable'],
  'workspace-not-found': ['invalid-request', 'Workspace unavailable'],
  'workspace-conflict': ['conflict', 'Workspace state conflict'],
  'workspace-not-trusted': ['permission-denied', 'Workspace is not trusted'],
  'workspace-containment': ['permission-denied', 'Workspace resources were rejected'],
  'workspace-load-failed': ['internal', 'Workspace resource load failed'],
  'workspace-disconnected': ['unavailable', 'Workspace generation unavailable'],
  'workspace-execution-uncertain': ['unavailable', 'Workspace execution is uncertain'],
} as const);

export type WorkspaceGateErrorCode = keyof typeof ERROR_DETAILS;

export class WorkspaceGateError extends Error {
  readonly category: (typeof ERROR_DETAILS)[WorkspaceGateErrorCode][0];
  readonly retryable = false;

  constructor(readonly code: WorkspaceGateErrorCode) {
    const [category, message] = ERROR_DETAILS[code];
    super(message);
    this.name = 'WorkspaceGateError';
    this.stack = `${this.name}: ${this.message}`;
    this.category = category;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => actual.includes(key));
}

function isBoundedInteger(value: unknown): value is number {
  return Number.isSafeInteger(value)
    && (value as number) >= 0
    && (value as number) <= MAX_JS_SAFE_INTEGER;
}

function isPrivatePath(value: unknown): value is string {
  return typeof value === 'string'
    && isAbsolute(value)
    && value.length > 0
    && Buffer.byteLength(value, 'utf8') <= MAX_PATH_BYTES
    && !CONTROL_CHARACTER.test(value);
}

export function assertWorkspaceRequestEnvelope(
  value: unknown,
): asserts value is ProtocolEnvelope {
  if (!isRecord(value)) throw new WorkspaceGateError('workspace-request-rejected');
  if (
    !hasExactKeys(value, ['version', 'kind', 'id', 'sequence', 'payload'])
    || value.version !== 1
    || value.kind !== 'request'
    || typeof value.id !== 'string'
    || !INTERNAL_REQUEST_ID.test(value.id)
    || !isBoundedInteger(value.sequence)
    || !isRecord(value.payload)
  ) {
    throw new WorkspaceGateError('workspace-request-rejected');
  }
  assertWorkspaceRequest(value.payload);
}

export function assertWorkspaceRequest(value: unknown): asserts value is WorkspaceRequest {
  if (!isRecord(value)) throw new WorkspaceGateError('workspace-request-rejected');
  const common = value.schemaVersion === SCHEMA_VERSION
    && typeof value.workspaceId === 'string'
    && WORKSPACE_ID.test(value.workspaceId)
    && isBoundedInteger(value.generation)
    && isBoundedInteger(value.revision);
  if (!common) throw new WorkspaceGateError('workspace-request-rejected');

  switch (value.method) {
    case 'workspace.sync': {
      const state = value.trustState;
      const keys = state === 'trusted'
        ? ['method', 'schemaVersion', 'workspaceId', 'generation', 'revision', 'trustState', 'leaseId']
        : ['method', 'schemaVersion', 'workspaceId', 'generation', 'revision', 'trustState'];
      if (
        !hasExactKeys(value, keys)
        || !['untrusted', 'trusted', 'revoked'].includes(state as string)
        || (state === 'trusted' && (typeof value.leaseId !== 'string' || !LEASE_ID.test(value.leaseId)))
      ) {
        throw new WorkspaceGateError('workspace-request-rejected');
      }
      return;
    }
    case 'workspace.openUntrusted':
      if (!hasExactKeys(value, ['method', 'schemaVersion', 'workspaceId', 'generation', 'revision'])) {
        throw new WorkspaceGateError('workspace-request-rejected');
      }
      return;
    case 'workspace.authorise':
      if (
        !hasExactKeys(value, [
          'method', 'schemaVersion', 'workspaceId', 'generation', 'expectedRevision',
          'revision', 'leaseId',
        ])
        || !isBoundedInteger(value.expectedRevision)
        || value.revision !== (value.expectedRevision as number) + 1
        || typeof value.leaseId !== 'string'
        || !LEASE_ID.test(value.leaseId)
      ) {
        throw new WorkspaceGateError('workspace-request-rejected');
      }
      return;
    case 'workspace.loadTrusted':
      if (
        !hasExactKeys(value, [
          'method', 'schemaVersion', 'workspaceId', 'generation', 'revision',
          'leaseId', 'snapshotRoot', 'agentRoot',
        ])
        || typeof value.leaseId !== 'string'
        || !LEASE_ID.test(value.leaseId)
        || !isPrivatePath(value.snapshotRoot)
        || !isPrivatePath(value.agentRoot)
      ) {
        throw new WorkspaceGateError('workspace-request-rejected');
      }
      return;
    case 'workspace.revoke':
      if (
        !hasExactKeys(value, [
          'method', 'schemaVersion', 'workspaceId', 'generation', 'expectedRevision',
          'revision', 'leaseId',
        ])
        || !isBoundedInteger(value.expectedRevision)
        || value.revision !== (value.expectedRevision as number) + 1
        || typeof value.leaseId !== 'string'
        || !LEASE_ID.test(value.leaseId)
      ) {
        throw new WorkspaceGateError('workspace-request-rejected');
      }
      return;
    default:
      throw new WorkspaceGateError('workspace-request-rejected');
  }
}

export function assertWorkspaceReply(value: unknown): asserts value is WorkspaceGateReply {
  if (!isRecord(value) || value.schemaVersion !== SCHEMA_VERSION || !isBoundedInteger(value.revision)) {
    throw new WorkspaceGateError('workspace-request-rejected');
  }
  if ('synced' in value) {
    if (!hasExactKeys(value, [
      'schemaVersion', 'revision', 'trustState', 'resourceState', 'synced',
    ]) || value.synced !== true) {
      throw new WorkspaceGateError('workspace-request-rejected');
    }
    const compatible = value.trustState === 'untrusted'
      ? value.resourceState === 'open'
      : value.trustState === 'revoked'
        ? value.resourceState === 'revoked'
        : value.trustState === 'trusted'
          && ['trusted', 'loading', 'loaded', 'failed'].includes(value.resourceState as string);
    if (!compatible) throw new WorkspaceGateError('workspace-request-rejected');
    return;
  }
  if ('counts' in value || 'cached' in value) {
    const counts = value.counts;
    if (!hasExactKeys(value, [
      'schemaVersion', 'revision', 'resourceState', 'counts', 'cached',
    ]) || value.resourceState !== 'loaded' || typeof value.cached !== 'boolean' || !isRecord(counts)
      || !hasExactKeys(counts, [
        'extensions', 'skills', 'prompts', 'themes', 'packages', 'truncated',
      ]) || !['extensions', 'skills', 'prompts', 'themes', 'packages'].every((key) => (
        isBoundedInteger(counts[key]) && (counts[key] as number) <= 64
      )) || typeof counts.truncated !== 'boolean') {
      throw new WorkspaceGateError('workspace-request-rejected');
    }
    return;
  }
  if ('requiresGenerationStop' in value) {
    if (!hasExactKeys(value, [
      'schemaVersion', 'revision', 'resourceState', 'requiresGenerationStop',
    ]) || value.resourceState !== 'revoked' || typeof value.requiresGenerationStop !== 'boolean') {
      throw new WorkspaceGateError('workspace-request-rejected');
    }
    return;
  }
  if (!hasExactKeys(value, ['schemaVersion', 'revision', 'resourceState'])
    || !['open', 'trusted'].includes(value.resourceState as string)) {
    throw new WorkspaceGateError('workspace-request-rejected');
  }
}

function safeReply(
  workspace: WorkspaceMirror,
  extra: Readonly<Record<string, unknown>> = {},
): WorkspaceGateReply {
  return Object.freeze({
    schemaVersion: SCHEMA_VERSION,
    revision: workspace.revision,
    resourceState: workspace.phase,
    ...extra,
  });
}

function syncReply(
  workspace: WorkspaceMirror,
  trustState: 'untrusted' | 'trusted' | 'revoked',
): WorkspaceGateReply {
  return Object.freeze({
    schemaVersion: SCHEMA_VERSION,
    revision: workspace.revision,
    trustState,
    resourceState: workspace.phase,
    synced: true,
  });
}

function contained(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === '' || (!path.startsWith(`..${sep}`) && path !== '..' && !isAbsolute(path));
}

async function validateSnapshotTree(snapshotRoot: string, agentRoot: string): Promise<void> {
  const rootStat = await lstat(snapshotRoot).catch(() => undefined);
  const agentStat = await lstat(agentRoot).catch(() => undefined);
  if (!rootStat?.isDirectory() || rootStat.isSymbolicLink() || !agentStat?.isDirectory() || agentStat.isSymbolicLink()) {
    throw new WorkspaceGateError('workspace-containment');
  }
  const canonicalRoot = await realpath(snapshotRoot).catch(() => '');
  const canonicalAgent = await realpath(agentRoot).catch(() => '');
  if (!canonicalRoot || !canonicalAgent || canonicalRoot === canonicalAgent || contained(canonicalRoot, canonicalAgent)) {
    throw new WorkspaceGateError('workspace-containment');
  }
  if ((await readdir(canonicalAgent)).length !== 0) {
    throw new WorkspaceGateError('workspace-containment');
  }

  let entries = 0;
  let bytes = 0;
  const visit = async (path: string): Promise<void> => {
    const stat = await lstat(path).catch(() => undefined);
    if (!stat || stat.isSymbolicLink()) throw new WorkspaceGateError('workspace-containment');
    const canonical = await realpath(path).catch(() => '');
    if (!canonical || !contained(canonicalRoot, canonical)) {
      throw new WorkspaceGateError('workspace-containment');
    }
    entries += 1;
    if (entries > MAX_SNAPSHOT_ENTRIES) throw new WorkspaceGateError('workspace-containment');
    if (stat.isDirectory()) {
      const names = await readdir(path);
      for (const name of names) {
        if (
          name === '.'
          || name === '..'
          || Buffer.byteLength(name, 'utf8') > 255
          || CONTROL_CHARACTER.test(name)
        ) {
          throw new WorkspaceGateError('workspace-containment');
        }
        await visit(join(path, name));
      }
      return;
    }
    if (!stat.isFile()) throw new WorkspaceGateError('workspace-containment');
    bytes += stat.size;
    if (bytes > MAX_SNAPSHOT_BYTES) throw new WorkspaceGateError('workspace-containment');
  };

  // Fixed-entry roots only. Parent context and arbitrary root names are never
  // enumerated or passed to Pi.
  for (const relativePath of [
    '.pi/extensions',
    '.pi/skills',
    '.pi/prompts',
    '.pi/themes',
  ]) {
    const path = resolve(canonicalRoot, relativePath);
    const stat = await lstat(path).catch(() => undefined);
    if (stat) await visit(path);
  }

}

export class TrustGate {
  readonly #generation: number;
  readonly #workspaces = new Map<string, WorkspaceMirror>();
  readonly #tails = new Map<string, Promise<void>>();
  readonly #queuedByWorkspace = new Map<string, number>();
  readonly #loader: TrustLoaderSupervisor;
  #pending = 0;
  #disconnected = false;

  constructor(
    generation: number,
    loader: TrustLoaderSupervisor = new TrustLoaderSupervisor(),
  ) {
    if (!isBoundedInteger(generation) || generation === 0) {
      throw new WorkspaceGateError('workspace-request-rejected');
    }
    this.#generation = generation;
    this.#loader = loader;
  }

  handle(payload: unknown): Promise<WorkspaceGateReply> {
    assertWorkspaceRequest(payload);
    const request = payload;
    if (this.#disconnected) {
      return Promise.reject(new WorkspaceGateError('workspace-disconnected'));
    }
    if (request.generation !== this.#generation) {
      return Promise.reject(new WorkspaceGateError('workspace-conflict'));
    }
    const queued = this.#queuedByWorkspace.get(request.workspaceId) ?? 0;
    if (this.#pending >= MAX_PENDING || queued >= MAX_PENDING_PER_WORKSPACE) {
      return Promise.reject(new WorkspaceGateError('workspace-capacity'));
    }

    this.#pending += 1;
    this.#queuedByWorkspace.set(request.workspaceId, queued + 1);
    const prior = this.#tails.get(request.workspaceId) ?? Promise.resolve();
    const operation = prior.catch(() => undefined).then(() => this.#execute(request));
    const tail = operation.then(() => undefined, () => undefined);
    this.#tails.set(request.workspaceId, tail);
    return operation.finally(() => {
      this.#pending -= 1;
      const remaining = (this.#queuedByWorkspace.get(request.workspaceId) ?? 1) - 1;
      if (remaining === 0) this.#queuedByWorkspace.delete(request.workspaceId);
      else this.#queuedByWorkspace.set(request.workspaceId, remaining);
      if (this.#tails.get(request.workspaceId) === tail) this.#tails.delete(request.workspaceId);
    });
  }

  disconnect(): void {
    if (this.#disconnected) return;
    this.#disconnected = true;
    this.#loader.disconnect();
    for (const workspace of this.#workspaces.values()) {
      if (workspace.phase === 'loading' || workspace.phase === 'loaded') {
        workspace.phase = 'failed';
        workspace.failure = 'workspace-execution-uncertain';
      }
      delete workspace.result;
      delete workspace.leaseId;
    }
    this.#workspaces.clear();
  }

  async #execute(request: WorkspaceRequest): Promise<WorkspaceGateReply> {
    if (this.#disconnected) throw new WorkspaceGateError('workspace-disconnected');
    switch (request.method) {
      case 'workspace.sync':
        return this.#sync(request);
      case 'workspace.openUntrusted':
        return this.#open(request);
      case 'workspace.authorise':
        return this.#authorise(request);
      case 'workspace.loadTrusted':
        return this.#load(request);
      case 'workspace.revoke':
        return this.#revoke(request);
    }
  }

  #sync(request: WorkspaceRequest): WorkspaceGateReply {
    if (!request.trustState) throw new WorkspaceGateError('workspace-request-rejected');
    const existing = this.#workspaces.get(request.workspaceId);
    if (existing && request.revision < existing.revision) {
      throw new WorkspaceGateError('workspace-conflict');
    }
    if (!existing && this.#workspaces.size >= MAX_WORKSPACES) {
      throw new WorkspaceGateError('workspace-capacity');
    }
    const phase = request.trustState === 'trusted'
      ? 'trusted'
      : request.trustState === 'revoked' ? 'revoked' : 'open';
    if (existing && request.revision === existing.revision) {
      const compatible = existing.phase === phase
        || (phase === 'trusted' && ['loading', 'loaded', 'failed'].includes(existing.phase));
      if (!compatible || (phase === 'trusted' && existing.leaseId !== request.leaseId)) {
        throw new WorkspaceGateError('workspace-conflict');
      }
      return syncReply(existing, request.trustState);
    }
    const workspace: WorkspaceMirror = {
      generation: request.generation,
      revision: request.revision,
      phase,
      ...(phase === 'trusted' ? { leaseId: request.leaseId } : {}),
      loadAttempted: false,
    };
    this.#workspaces.set(request.workspaceId, workspace);
    return syncReply(workspace, request.trustState);
  }

  #open(request: WorkspaceRequest): WorkspaceGateReply {
    const existing = this.#workspaces.get(request.workspaceId);
    if (existing) {
      if (
        existing.generation === request.generation
        && existing.revision === request.revision
        && existing.phase === 'open'
      ) return safeReply(existing);
      throw new WorkspaceGateError('workspace-conflict');
    }
    if (this.#workspaces.size >= MAX_WORKSPACES) {
      throw new WorkspaceGateError('workspace-capacity');
    }
    const workspace: WorkspaceMirror = {
      generation: request.generation,
      revision: request.revision,
      phase: 'open',
      loadAttempted: false,
    };
    this.#workspaces.set(request.workspaceId, workspace);
    return safeReply(workspace);
  }

  #authorise(request: WorkspaceRequest): WorkspaceGateReply {
    const workspace = this.#require(request.workspaceId);
    if (
      !['open', 'revoked'].includes(workspace.phase)
      || workspace.revision !== request.expectedRevision
      || request.revision !== workspace.revision + 1
      || !request.leaseId
    ) {
      throw new WorkspaceGateError('workspace-conflict');
    }
    workspace.revision = request.revision;
    workspace.phase = 'trusted';
    workspace.leaseId = request.leaseId;
    workspace.loadAttempted = false;
    delete workspace.result;
    delete workspace.failure;
    return safeReply(workspace);
  }

  async #load(request: WorkspaceRequest): Promise<WorkspaceGateReply> {
    const workspace = this.#require(request.workspaceId);
    if (workspace.phase === 'open' || workspace.phase === 'revoked') {
      throw new WorkspaceGateError('workspace-not-trusted');
    }
    if (
      workspace.generation !== request.generation
      || workspace.revision !== request.revision
      || workspace.leaseId !== request.leaseId
    ) {
      throw new WorkspaceGateError('workspace-conflict');
    }
    if (workspace.phase === 'loaded' && workspace.result) {
      return safeReply(workspace, { counts: workspace.result, cached: true });
    }
    if (workspace.phase === 'failed' && workspace.failure) {
      throw new WorkspaceGateError(workspace.failure);
    }
    if (workspace.phase !== 'trusted' || workspace.loadAttempted) {
      throw new WorkspaceGateError('workspace-not-trusted');
    }
    if (!request.snapshotRoot || !request.agentRoot) {
      throw new WorkspaceGateError('workspace-request-rejected');
    }

    workspace.loadAttempted = true;
    workspace.phase = 'loading';
    try {
      await validateSnapshotTree(request.snapshotRoot, request.agentRoot);
      if (this.#disconnected) throw new WorkspaceGateError('workspace-execution-uncertain');
      const result = await this.#loader.run(request.snapshotRoot, request.agentRoot);
      if (this.#disconnected) throw new WorkspaceGateError('workspace-execution-uncertain');
      workspace.result = result;
      workspace.phase = 'loaded';
      return safeReply(workspace, { counts: result, cached: false });
    } catch (error) {
      workspace.phase = 'failed';
      workspace.failure = error instanceof WorkspaceGateError
        ? error.code
        : error instanceof TrustLoaderError && error.launched
          ? 'workspace-execution-uncertain'
          : 'workspace-load-failed';
      delete workspace.result;
      throw new WorkspaceGateError(workspace.failure);
    }
  }

  #revoke(request: WorkspaceRequest): WorkspaceGateReply {
    const workspace = this.#require(request.workspaceId);
    if (
      workspace.revision !== request.expectedRevision
      || request.revision !== workspace.revision + 1
      || workspace.leaseId !== request.leaseId
      || workspace.phase === 'revoked'
    ) {
      throw new WorkspaceGateError('workspace-conflict');
    }
    const requiresGenerationStop = workspace.phase === 'loaded'
      || workspace.phase === 'loading'
      || workspace.phase === 'failed';
    workspace.revision = request.revision;
    workspace.phase = 'revoked';
    workspace.loadAttempted = true;
    delete workspace.result;
    delete workspace.failure;
    delete workspace.leaseId;
    return safeReply(workspace, { requiresGenerationStop });
  }

  #require(workspaceId: string): WorkspaceMirror {
    const workspace = this.#workspaces.get(workspaceId);
    if (!workspace) throw new WorkspaceGateError('workspace-not-found');
    return workspace;
  }
}

export const WORKSPACE_TRUST_LIMITS = Object.freeze({
  maxWorkspaces: MAX_WORKSPACES,
  maxPending: MAX_PENDING,
  maxPendingPerWorkspace: MAX_PENDING_PER_WORKSPACE,
  maxSnapshotEntries: MAX_SNAPSHOT_ENTRIES,
  maxSnapshotBytes: MAX_SNAPSHOT_BYTES,
  maxPathBytes: MAX_PATH_BYTES,
});
