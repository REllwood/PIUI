import { randomUUID } from 'node:crypto';
import { isApprovalToolName } from '../bridge/host-requests.js';
import type {
  ApprovalAbandonPayload,
  ApprovalCohortDescriptor,
  ApprovalGrant,
  ApprovalReadyPayload,
  CohortApprovalRequestPayload,
} from '../bridge/host-requests.js';
import {
  APPROVAL_CANONICAL_LIMITS,
  canonicaliseApprovalInput,
  deepFreezeApprovalValue,
  isApprovalInputTooLarge,
} from './approval-canonical.js';
import type {
  PublicAgentSession,
  PublicExtensionContext,
  PublicInlineExtension,
  PublicToolDefinition,
} from './public-sdk.js';

const FIXED_BLOCK_REASON = 'This action was not approved.';
// Seen by the model when only the C4 review bound was exceeded, so it can
// retry the same change as several smaller tool calls.
const TOO_LARGE_BLOCK_REASON =
  'This action was too large to review, so it was not approved. Split the change into several smaller tool calls.';
const MAX_COHORT_MEMBERS = 32;
const MAX_ACTIVE_COHORTS = 64;
const MAX_ACTIVE_MEMBERS = 128;
const MAX_FAILED_COHORTS = 128;
const MAX_COMPLETED_COHORTS = 128;
const DEFAULT_COHORT_TIMEOUT_MS = 125_000;
// Entries walked back from the leaf to find the latest message. Branch length
// itself is unbounded: long sessions keep their tools.
const MAX_LEAF_SCAN = 2_048;
const MAX_MESSAGE_CONTENT = 256;
const WIRE_COORDINATE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export type ApprovalHost = Readonly<{
  requestApproval(payload: CohortApprovalRequestPayload): Promise<ApprovalGrant>;
  notifyApprovalReady(payload: ApprovalReadyPayload): Promise<void>;
  abandonApproval(payload: ApprovalAbandonPayload): Promise<void>;
}>;
export type ApprovalContext = Readonly<{
  generation: number;
  sessionId: string;
  workspaceId: string;
  workspaceRevision: number;
}>;
export type ApprovalGateOptions = Readonly<{
  /** Test fixtures may shorten this bounded guard; production uses the host guard. */
  cohortTimeoutMs?: number;
  beforeExecute?: (toolName: string, params: unknown) => Promise<unknown>;
  afterExecute?: (token: unknown, result: unknown, error: unknown | undefined) => Promise<void>;
}>;

type DefinitionLookup = (name: string) => PublicToolDefinition | undefined;
type ApprovalOutcome = Readonly<{ grant?: ApprovalGrant; failed: boolean }>;
type ReadyOutcome = Readonly<{ failed: boolean }>;

type PendingInvocation = {
  readonly invocationId: string;
  readonly toolCallId: string;
  readonly toolName: string;
  readonly definition: PublicToolDefinition;
  readonly digest: string;
  readonly cohort: CohortState;
  originalInput?: object;
  approval?: Promise<ApprovalOutcome>;
  wrapperStarted: boolean;
  readySent: boolean;
  readyAcknowledged: boolean;
  params?: object;
  signal?: AbortSignal;
  abortListener?: () => void;
  settled: boolean;
};

type CohortState = {
  readonly key: string;
  readonly descriptor: ApprovalCohortDescriptor;
  readonly members: Map<string, PendingInvocation>;
  readonly groupGrants: Map<string, ApprovalGrant>;
  readonly registered: Promise<boolean>;
  releaseRegistered(value: boolean): void;
  readonly allReady: Promise<boolean>;
  releaseAllReady(value: boolean): void;
  readonly groupRelease: Promise<boolean>;
  releaseGroup(value: boolean): void;
  /** Members Pi finalised as errors without ever offering them to the gate. */
  readonly prefailed: Set<string>;
  /** Every member that ever registered, so a late event cannot re-classify it. */
  readonly registeredIds: Set<string>;
  timer: ReturnType<typeof setTimeout>;
  failed: boolean;
  abandonSent: boolean;
  /** True once any member's approval.request has been written to the host. */
  hostRegistered: boolean;
  completed: number;
};

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function opaque(prefix: string): string {
  return `${prefix}-${randomUUID().replaceAll('-', '')}`;
}

function copyDefinition<T extends PublicToolDefinition>(
  original: T,
  execute: PublicToolDefinition['execute'],
): T {
  if (!isPlainObject(original)) throw new Error('approval-wrapper-rejected');
  const descriptors = Object.getOwnPropertyDescriptors(original);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.some(
      (key) => typeof key === 'symbol' || !Object.hasOwn(descriptors[key as string], 'value'),
    ) ||
    typeof descriptors.name?.value !== 'string' ||
    typeof descriptors.execute?.value !== 'function'
  )
    throw new Error('approval-wrapper-rejected');
  const decorated = Object.create(Object.getPrototypeOf(original), descriptors) as T;
  Object.defineProperty(decorated, 'execute', {
    configurable: false,
    enumerable: descriptors.execute.enumerable,
    writable: false,
    value: execute,
  });
  return Object.freeze(decorated);
}

function ownValue(value: unknown, key: string): unknown {
  if (value === null || typeof value !== 'object') throw new Error('approval-cohort-rejected');
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !Object.hasOwn(descriptor, 'value'))
    throw new Error('approval-cohort-rejected');
  return descriptor.value;
}

/**
 * Walks parent links back from the leaf to the latest message entry. Only the
 * newest assistant entry matters, so the cost is bounded by MAX_LEAF_SCAN
 * rather than by the length of the session.
 */
function latestMessageEntry(ctx: PublicExtensionContext): unknown {
  const manager = ctx.sessionManager;
  let entry: unknown = manager.getLeafEntry();
  for (let steps = 0; entry !== undefined && steps < MAX_LEAF_SCAN; steps += 1) {
    if (ownValue(entry, 'type') === 'message') return entry;
    const parentId = ownValue(entry, 'parentId');
    if (parentId === null) return undefined;
    if (typeof parentId !== 'string') throw new Error('approval-cohort-rejected');
    const parent: unknown = manager.getEntry(parentId);
    if (parent === undefined || ownValue(parent, 'id') !== parentId) {
      throw new Error('approval-cohort-rejected');
    }
    entry = parent;
  }
  return undefined;
}

function deriveCohort(
  ctx: PublicExtensionContext,
  toolCallId: string,
  toolName: string,
): ApprovalCohortDescriptor {
  const latestMessage = latestMessageEntry(ctx);
  if (!latestMessage) throw new Error('approval-cohort-rejected');
  const assistantEntryId = ownValue(latestMessage, 'id');
  const message = ownValue(latestMessage, 'message');
  if (
    typeof assistantEntryId !== 'string' ||
    !WIRE_COORDINATE.test(assistantEntryId) ||
    ownValue(message, 'role') !== 'assistant'
  ) {
    throw new Error('approval-cohort-rejected');
  }
  const content = ownValue(message, 'content');
  if (!Array.isArray(content) || content.length < 1 || content.length > MAX_MESSAGE_CONTENT) {
    throw new Error('approval-cohort-rejected');
  }

  const orderedMembers: Array<{ ordinal: number; toolCallId: string; toolName: string }> = [];
  const seen = new Set<string>();
  for (const block of content) {
    if (ownValue(block, 'type') !== 'toolCall') continue;
    const id = ownValue(block, 'id');
    const name = ownValue(block, 'name');
    if (
      typeof id !== 'string' ||
      !WIRE_COORDINATE.test(id) ||
      !isApprovalToolName(name) ||
      seen.has(id) ||
      orderedMembers.length >= MAX_COHORT_MEMBERS
    ) {
      throw new Error('approval-cohort-rejected');
    }
    seen.add(id);
    orderedMembers.push(
      Object.freeze({
        ordinal: orderedMembers.length,
        toolCallId: id,
        toolName: name,
      }),
    );
  }
  if (
    orderedMembers.length < 1 ||
    orderedMembers.filter(
      (member) => member.toolCallId === toolCallId && member.toolName === toolName,
    ).length !== 1 ||
    orderedMembers.some(
      (member) => member.toolCallId === toolCallId && member.toolName !== toolName,
    )
  ) {
    throw new Error('approval-cohort-rejected');
  }

  let canonical: ReturnType<typeof canonicaliseApprovalInput> | undefined;
  try {
    canonical = canonicaliseApprovalInput({ assistantEntryId, orderedMembers });
    return Object.freeze({
      assistantEntryId,
      cohortDigest: canonical.digest,
      orderedMembers: Object.freeze(orderedMembers),
    });
  } finally {
    canonical?.bytes.fill(0);
  }
}

function sameDescriptor(left: ApprovalCohortDescriptor, right: ApprovalCohortDescriptor): boolean {
  return (
    left.assistantEntryId === right.assistantEntryId &&
    left.cohortDigest === right.cohortDigest &&
    left.orderedMembers.length === right.orderedMembers.length &&
    left.orderedMembers.every((member, index) => {
      const other = right.orderedMembers[index];
      return (
        member.ordinal === other.ordinal &&
        member.toolCallId === other.toolCallId &&
        member.toolName === other.toolName
      );
    })
  );
}

function privateCohortKey(context: ApprovalContext, descriptor: ApprovalCohortDescriptor): string {
  return [
    context.generation,
    context.sessionId,
    context.workspaceId,
    context.workspaceRevision,
    descriptor.assistantEntryId,
    descriptor.cohortDigest,
  ].join('|');
}

function createCohort(
  key: string,
  descriptor: ApprovalCohortDescriptor,
  timeoutMs: number,
  onTimeout: () => void,
): CohortState {
  let releaseRegistered!: (value: boolean) => void;
  let releaseAllReady!: (value: boolean) => void;
  let releaseGroup!: (value: boolean) => void;
  const registered = new Promise<boolean>((resolve) => {
    releaseRegistered = resolve;
  });
  const allReady = new Promise<boolean>((resolve) => {
    releaseAllReady = resolve;
  });
  const groupRelease = new Promise<boolean>((resolve) => {
    releaseGroup = resolve;
  });
  const timer = setTimeout(onTimeout, timeoutMs);
  timer.unref?.();
  return {
    key,
    descriptor,
    members: new Map(),
    groupGrants: new Map(),
    registered,
    releaseRegistered,
    allReady,
    releaseAllReady,
    groupRelease,
    releaseGroup,
    prefailed: new Set(),
    registeredIds: new Set(),
    timer,
    failed: false,
    abandonSent: false,
    hostRegistered: false,
    completed: 0,
  };
}

/** Members the gate still expects to register: Pi-failed ones never will. */
function expectedMembers(cohort: CohortState): ApprovalCohortDescriptor['orderedMembers'] {
  return cohort.descriptor.orderedMembers.filter(
    (member) => !cohort.prefailed.has(member.toolCallId),
  );
}

/**
 * Builds the A.18 Pi gate. Preflight establishes a bounded registration only;
 * the exact decorated delegate remains the sole execution boundary.
 */
export function createApprovalGate(
  host: ApprovalHost,
  context: ApprovalContext,
  options: ApprovalGateOptions = {},
) {
  const cohortTimeoutMs = options.cohortTimeoutMs ?? DEFAULT_COHORT_TIMEOUT_MS;
  if (
    !Number.isSafeInteger(cohortTimeoutMs) ||
    cohortTimeoutMs < 1 ||
    cohortTimeoutMs > DEFAULT_COHORT_TIMEOUT_MS
  )
    throw new Error('approval-gate-rejected');

  const pendingByInput = new WeakMap<object, PendingInvocation>();
  const pendingByToolCall = new Map<string, PendingInvocation>();
  const cohorts = new Map<string, CohortState>();
  const failedCohorts = new Map<string, true>();
  const completedCohorts = new Map<string, true>();
  const decoratedByName = new Map<string, PublicToolDefinition>();
  let lookup: DefinitionLookup | undefined;
  // Permanent: shutdown, tombstone saturation or an unverifiable reload.
  let sessionClosed = false;
  // Transient: the gate admits nothing while Pi rebuilds its runtime.
  let reloadsInFlight = 0;

  function isActiveDefinition(name: string, definition: PublicToolDefinition): boolean {
    if (!lookup || sessionClosed || reloadsInFlight > 0) return false;
    try {
      return lookup(name) === definition;
    } catch {
      return false;
    }
  }

  function rememberFailed(key: string): void {
    if (failedCohorts.has(key)) return;
    if (failedCohorts.size >= MAX_FAILED_COHORTS) {
      // Never evict a tombstone and permit an old late sibling to revive it.
      // Saturation closes this session gate fail-safe until a fresh gate exists.
      sessionClosed = true;
      return;
    }
    failedCohorts.set(key, true);
  }

  function rememberCompleted(key: string): void {
    // Eviction is safe: a completed key is only consulted so that a late Pi
    // error event cannot conjure an empty cohort; it never grants anything.
    completedCohorts.delete(key);
    completedCohorts.set(key, true);
    if (completedCohorts.size > MAX_COMPLETED_COHORTS) {
      completedCohorts.delete(completedCohorts.keys().next().value!);
    }
  }

  function erasePending(pending: PendingInvocation): void {
    if (pending.settled) return;
    pending.settled = true;
    if (pending.abortListener && pending.signal) {
      pending.signal.removeEventListener('abort', pending.abortListener);
    }
    if (pending.originalInput) pendingByInput.delete(pending.originalInput);
    pendingByToolCall.delete(pending.toolCallId);
    pending.originalInput = undefined;
    pending.params = undefined;
    pending.signal = undefined;
    pending.abortListener = undefined;
    pending.approval = undefined;
  }

  function abandon(cohort: CohortState, reason: ApprovalAbandonPayload['reason']): void {
    if (!cohort.failed) {
      cohort.failed = true;
      cohort.releaseRegistered(false);
      cohort.releaseAllReady(false);
      cohort.releaseGroup(false);
      clearTimeout(cohort.timer);
      rememberFailed(cohort.key);
      cohorts.delete(cohort.key);
      for (const pending of cohort.members.values()) erasePending(pending);
      cohort.members.clear();
      cohort.groupGrants.clear();
    }
    if (cohort.abandonSent) return;
    cohort.abandonSent = true;
    // The host only knows cohorts it has seen a request for. With none sent it
    // has nothing to cancel, and an abandon for an unknown cohort is fatal to
    // the whole generation there; the local tombstone alone keeps it closed.
    if (!cohort.hostRegistered) return;
    void host
      .abandonApproval({
        method: 'approval.abandon',
        schemaVersion: 2,
        generation: context.generation,
        sessionId: context.sessionId,
        workspaceId: context.workspaceId,
        workspaceRevision: context.workspaceRevision,
        assistantEntryId: cohort.descriptor.assistantEntryId,
        cohortDigest: cohort.descriptor.cohortDigest,
        reason,
      })
      .catch(() => undefined);
  }

  function finish(pending: PendingInvocation): void {
    if (pending.settled) return;
    const cohort = pending.cohort;
    erasePending(pending);
    cohort.members.delete(pending.toolCallId);
    cohort.groupGrants.delete(pending.toolCallId);
    cohort.completed += 1;
    maybeComplete(cohort);
  }

  function maybeComplete(cohort: CohortState): void {
    if (
      cohort.failed ||
      cohort.completed + cohort.prefailed.size < cohort.descriptor.orderedMembers.length
    ) {
      return;
    }
    clearTimeout(cohort.timer);
    cohorts.delete(cohort.key);
    rememberCompleted(cohort.key);
    cohort.members.clear();
    cohort.groupGrants.clear();
  }

  function verifyCurrent(pending: PendingInvocation): boolean {
    if (
      pending.cohort.failed ||
      !pending.params ||
      !pending.originalInput ||
      pending.signal?.aborted ||
      pending.params !== pending.originalInput ||
      !isActiveDefinition(pending.toolName, pending.definition)
    )
      return false;
    let canonical: ReturnType<typeof canonicaliseApprovalInput> | undefined;
    try {
      canonical = canonicaliseApprovalInput(pending.params);
      return canonical.digest === pending.digest;
    } catch {
      return false;
    } finally {
      canonical?.bytes.fill(0);
    }
  }

  function maybeReleaseRegistered(cohort: CohortState): void {
    const expected = expectedMembers(cohort);
    if (cohort.failed || expected.length === 0 || cohort.members.size !== expected.length) return;
    const complete = expected.every((member) => {
      const pending = cohort.members.get(member.toolCallId);
      return pending?.toolName === member.toolName;
    });
    if (!complete) abandon(cohort, 'extension-error');
    else cohort.releaseRegistered(true);
  }

  function maybeReleaseAllReady(cohort: CohortState): void {
    const expected = expectedMembers(cohort);
    if (cohort.failed || expected.length === 0 || cohort.members.size !== expected.length) return;
    const ready = expected.every((member) => {
      const pending = cohort.members.get(member.toolCallId);
      return Boolean(
        pending &&
          pending.wrapperStarted &&
          pending.readySent &&
          pending.readyAcknowledged &&
          verifyCurrent(pending),
      );
    });
    if (ready) cohort.releaseAllReady(true);
  }

  function acceptGroupGrant(pending: PendingInvocation, grant: ApprovalGrant): Promise<boolean> {
    const cohort = pending.cohort;
    const commit = grant.groupCommit;
    if (
      !commit ||
      // A group decision must cover the complete cohort; a shrunk one has none.
      cohort.prefailed.size > 0 ||
      commit.cohortDigest !== cohort.descriptor.cohortDigest ||
      commit.memberCount !== cohort.descriptor.orderedMembers.length ||
      grant.transactionId !== commit.transactionId ||
      cohort.groupGrants.has(pending.toolCallId)
    ) {
      abandon(cohort, 'extension-error');
      return cohort.groupRelease;
    }
    cohort.groupGrants.set(pending.toolCallId, grant);
    if (cohort.groupGrants.size === cohort.descriptor.orderedMembers.length) {
      const valid =
        !cohort.failed &&
        cohort.descriptor.orderedMembers.every((member) => {
          const exact = cohort.members.get(member.toolCallId);
          const exactGrant = cohort.groupGrants.get(member.toolCallId);
          return Boolean(
            exact &&
              exactGrant &&
              exact.wrapperStarted &&
              exact.readySent &&
              exact.readyAcknowledged &&
              exactGrant.invocationId === exact.invocationId &&
              exactGrant.toolCallId === exact.toolCallId &&
              exactGrant.inputDigest === exact.digest &&
              exactGrant.scopeIds.length === 1 &&
              verifyCurrent(exact),
          );
        });
      if (!valid) abandon(cohort, 'extension-error');
      else cohort.releaseGroup(true);
    }
    return cohort.groupRelease;
  }

  function openCohort(descriptor: ApprovalCohortDescriptor): CohortState {
    const key = privateCohortKey(context, descriptor);
    if (failedCohorts.has(key)) throw new Error('approval-cohort-rejected');
    const existing = cohorts.get(key);
    if (existing) {
      if (sameDescriptor(existing.descriptor, descriptor)) return existing;
      abandon(existing, 'extension-error');
      throw new Error('approval-cohort-rejected');
    }
    if (cohorts.size >= MAX_ACTIVE_COHORTS) throw new Error('approval-cohort-capacity');
    let created!: CohortState;
    created = createCohort(key, descriptor, cohortTimeoutMs, () => {
      abandon(created, 'extension-error');
    });
    cohorts.set(key, created);
    return created;
  }

  /**
   * Pi finalises an unknown tool or invalid arguments as an error before any
   * `tool_call` handler runs. Such a member can never register, and so can
   * never pass its wrapper; its siblings stop waiting for it instead of timing
   * out. Every other member still needs its own exact host approval, and a
   * shrunk cohort can never receive a group decision.
   */
  function recordPiFailedMember(
    ctx: PublicExtensionContext,
    toolCallId: string,
    toolName: string,
  ): void {
    let cohort: CohortState;
    try {
      const descriptor = deriveCohort(ctx, toolCallId, toolName);
      const key = privateCohortKey(context, descriptor);
      if (completedCohorts.has(key)) return;
      cohort = openCohort(descriptor);
    } catch {
      // Not a member of the current assistant cohort, or already closed.
      return;
    }
    if (cohort.failed || cohort.registeredIds.has(toolCallId) || cohort.prefailed.has(toolCallId)) {
      return;
    }
    cohort.prefailed.add(toolCallId);
    maybeReleaseRegistered(cohort);
    maybeComplete(cohort);
  }

  const extension: PublicInlineExtension = Object.freeze({
    name: 'piui-approval-gate',
    hidden: true,
    factory(pi) {
      pi.on('tool_call', (event, ctx) => {
        const originalInput = event.input;
        let canonical: ReturnType<typeof canonicaliseApprovalInput> | undefined;
        let cohort: CohortState | undefined;
        let inputTooLarge = false;
        try {
          const descriptor = deriveCohort(ctx, event.toolCallId, event.toolName);
          cohort = openCohort(descriptor);

          const definition = decoratedByName.get(event.toolName);
          if (
            !definition ||
            !isActiveDefinition(event.toolName, definition) ||
            !isPlainObject(originalInput) ||
            pendingByToolCall.has(event.toolCallId) ||
            pendingByInput.has(originalInput) ||
            cohort.failed ||
            cohort.members.has(event.toolCallId) ||
            cohort.registeredIds.has(event.toolCallId) ||
            // Pi already finalised this member as an error; it may never run.
            cohort.prefailed.has(event.toolCallId) ||
            pendingByToolCall.size >= MAX_ACTIVE_MEMBERS
          ) {
            abandon(cohort, 'extension-error');
            throw new Error('approval-cohort-rejected');
          }

          try {
            canonical = canonicaliseApprovalInput(originalInput);
          } catch (error) {
            inputTooLarge = isApprovalInputTooLarge(error);
            throw error;
          }
          const invocationId = opaque('invocation');
          const approval = host
            .requestApproval({
              method: 'approval.request',
              schemaVersion: 2,
              generation: context.generation,
              sessionId: context.sessionId,
              workspaceId: context.workspaceId,
              workspaceRevision: context.workspaceRevision,
              invocationId,
              toolCallId: event.toolCallId,
              toolName: event.toolName,
              inputDigest: canonical.digest,
              input: canonical.value,
              cohort: descriptor,
            })
            .then<ApprovalOutcome, ApprovalOutcome>(
              (grant) => Object.freeze({ grant, failed: false }),
              () => Object.freeze({ failed: true }),
            );
          cohort.hostRegistered = true;
          cohort.registeredIds.add(event.toolCallId);
          const pending: PendingInvocation = {
            invocationId,
            toolCallId: event.toolCallId,
            toolName: event.toolName,
            definition,
            originalInput,
            digest: canonical.digest,
            cohort,
            approval,
            wrapperStarted: false,
            readySent: false,
            readyAcknowledged: false,
            settled: false,
          };
          cohort.members.set(event.toolCallId, pending);
          pendingByInput.set(originalInput, pending);
          pendingByToolCall.set(event.toolCallId, pending);
          maybeReleaseRegistered(cohort);
          return undefined;
        } catch {
          if (cohort && !cohort.failed) abandon(cohort, 'extension-error');
          return { block: true, reason: inputTooLarge ? TOO_LARGE_BLOCK_REASON : FIXED_BLOCK_REASON };
        } finally {
          canonical?.bytes.fill(0);
        }
      });

      pi.on('tool_execution_end', (event, ctx) => {
        if (!event.isError) return;
        const pending = pendingByToolCall.get(event.toolCallId);
        if (pending) {
          // A registered member failed before its wrapper ran, so a later
          // handler blocked or threw: the complete cohort is abandoned.
          if (!pending.wrapperStarted) {
            abandon(pending.cohort, 'extension-error');
            finish(pending);
          }
          return;
        }
        recordPiFailedMember(ctx, event.toolCallId, event.toolName);
      });

      pi.on('session_shutdown', (event) => {
        // Pi emits a reload shutdown from inside the gate's own reload wrapper,
        // which abandons every cohort and re-verifies the rebuilt tools.
        if (!(reloadsInFlight > 0 && event?.reason === 'reload')) sessionClosed = true;
        for (const cohort of [...cohorts.values()]) abandon(cohort, 'session-shutdown');
      });
    },
  });

  function decorateToolDefinition<T extends PublicToolDefinition>(original: T): T {
    const name = Object.getOwnPropertyDescriptor(original, 'name')?.value;
    const originalExecute = Object.getOwnPropertyDescriptor(original, 'execute')?.value;
    if (
      !isApprovalToolName(name) ||
      typeof originalExecute !== 'function' ||
      decoratedByName.has(name)
    ) {
      throw new Error('approval-wrapper-rejected');
    }

    let decorated!: T;
    const execute: PublicToolDefinition['execute'] = async (
      toolCallId,
      params,
      signal,
      onUpdate,
      ctx,
    ) => {
      const identity =
        params !== null && typeof params === 'object' ? (params as object) : undefined;
      const pending = identity ? pendingByInput.get(identity) : undefined;
      if (
        !pending ||
        pending.toolCallId !== toolCallId ||
        pending.definition !== decorated ||
        pending.wrapperStarted ||
        pending.settled ||
        !pending.approval
      ) {
        throw new Error(FIXED_BLOCK_REASON);
      }

      const approval = pending.approval;
      pending.wrapperStarted = true;
      pending.params = identity;
      pending.signal = signal;
      if (!verifyCurrent(pending)) {
        abandon(pending.cohort, signal?.aborted ? 'pi-abort' : 'definition-change');
        throw new Error(FIXED_BLOCK_REASON);
      }
      pending.abortListener = () => abandon(pending.cohort, 'pi-abort');
      signal?.addEventListener('abort', pending.abortListener, { once: true });

      try {
        // Multi-call turns may be scheduled sequentially by Pi. No individual
        // grant can bypass the exact complete-registration barrier.
        if (!(await pending.cohort.registered) || !verifyCurrent(pending)) {
          throw new Error(FIXED_BLOCK_REASON);
        }

        pending.readySent = true;
        const ready: Promise<ReadyOutcome> = host
          .notifyApprovalReady({
            method: 'approval.ready',
            schemaVersion: 2,
            generation: context.generation,
            invocationId: pending.invocationId,
            toolCallId: pending.toolCallId,
            inputDigest: pending.digest,
            cohortDigest: pending.cohort.descriptor.cohortDigest,
          })
          .then<ReadyOutcome, ReadyOutcome>(
            () => {
              pending.readyAcknowledged = true;
              maybeReleaseAllReady(pending.cohort);
              return Object.freeze({ failed: false });
            },
            () => Object.freeze({ failed: true }),
          );

        const outcomes = await Promise.race([
          Promise.all([ready, approval, pending.cohort.allReady]),
          pending.cohort.groupRelease.then((released) =>
            released ? new Promise<never>(() => undefined) : undefined,
          ),
        ]);
        if (!outcomes) throw new Error(FIXED_BLOCK_REASON);
        const [readyOutcome, approvalOutcome, allReady] = outcomes;
        if (readyOutcome.failed || !allReady || approvalOutcome.failed || !approvalOutcome.grant) {
          abandon(pending.cohort, 'extension-error');
          throw new Error(FIXED_BLOCK_REASON);
        }
        const grant = approvalOutcome.grant;
        if (
          grant.decision !== 'approved' ||
          grant.invocationId !== pending.invocationId ||
          grant.inputDigest !== pending.digest ||
          grant.toolCallId !== pending.toolCallId ||
          grant.cohortDigest !== pending.cohort.descriptor.cohortDigest ||
          grant.scopeIds.length !== 1 ||
          !grant.transactionId
        ) {
          throw new Error(FIXED_BLOCK_REASON);
        }
        if (grant.groupCommit) {
          if (!(await acceptGroupGrant(pending, grant))) throw new Error(FIXED_BLOCK_REASON);
        }
        if (!verifyCurrent(pending)) {
          abandon(pending.cohort, signal?.aborted ? 'pi-abort' : 'digest-change');
          throw new Error(FIXED_BLOCK_REASON);
        }

        // Preserve Pi's exact params identity and five-argument contract while
        // preventing retained references from changing the authorised value.
        deepFreezeApprovalValue(params);
        if (!verifyCurrent(pending)) throw new Error(FIXED_BLOCK_REASON);
        finish(pending);
        let observation: unknown;
        try {
          observation = await options.beforeExecute?.(name, params);
        } catch {
          observation = undefined;
        }
        try {
          const result = (await Reflect.apply(originalExecute, original, [
            toolCallId,
            params,
            signal,
            onUpdate,
            ctx,
          ])) as Awaited<ReturnType<PublicToolDefinition['execute']>>;
          try {
            await options.afterExecute?.(observation, result, undefined);
          } catch {
            // Change evidence is supplementary and must never cause an already
            // completed, approved Pi tool to be re-run.
          }
          return result;
        } catch (error) {
          try {
            await options.afterExecute?.(observation, undefined, error);
          } catch {
            // Preserve the authoritative tool failure.
          }
          throw error;
        }
      } finally {
        finish(pending);
      }
    };

    decorated = copyDefinition(original, execute);
    decoratedByName.set(name, decorated);
    return decorated;
  }

  function bindSession(session: PublicAgentSession): void {
    if (lookup) throw new Error('approval-session-rejected');
    const method = session?.getToolDefinition;
    if (typeof method !== 'function') throw new Error('approval-session-rejected');
    const bound: DefinitionLookup = (name) =>
      Reflect.apply(method, session, [name]) as PublicToolDefinition | undefined;
    for (const [name, definition] of decoratedByName) {
      if (bound(name) !== definition) throw new Error('approval-session-rejected');
    }
    const reload = session.reload;
    if (typeof reload !== 'function') throw new Error('approval-session-rejected');
    const decoratedStillBound = (): boolean => {
      try {
        for (const [name, definition] of decoratedByName) {
          if (bound(name) !== definition) return false;
        }
        return true;
      } catch {
        return false;
      }
    };
    try {
      Object.defineProperty(session, 'reload', {
        configurable: false,
        enumerable: false,
        writable: false,
        value: async (...args: Parameters<PublicAgentSession['reload']>) => {
          // Nothing registered before a reload may run after it: every cohort
          // in flight is abandoned and the gate admits nothing until Pi has
          // rebuilt its runtime.
          reloadsInFlight += 1;
          for (const cohort of [...cohorts.values()]) abandon(cohort, 'session-shutdown');
          let reloaded = false;
          try {
            const result = await Reflect.apply(reload, session, args);
            reloaded = true;
            return result;
          } finally {
            reloadsInFlight -= 1;
            // Re-bind to the rebuilt runtime only if it still resolves every
            // name to the exact decorated definition; otherwise stay closed.
            if (!reloaded || (reloadsInFlight === 0 && !decoratedStillBound())) {
              sessionClosed = true;
            }
          }
        },
      });
    } catch {
      throw new Error('approval-session-rejected');
    }
    lookup = bound;
  }

  return Object.freeze({ extension, decorateToolDefinition, bindSession });
}

export { canonicaliseApprovalInput } from './approval-canonical.js';
export const APPROVAL_GATE_LIMITS = Object.freeze({
  ...APPROVAL_CANONICAL_LIMITS,
  maxCohortMembers: MAX_COHORT_MEMBERS,
  maxActiveCohorts: MAX_ACTIVE_COHORTS,
  maxActiveMembers: MAX_ACTIVE_MEMBERS,
  maxFailedCohorts: MAX_FAILED_COHORTS,
  cohortTimeoutMs: DEFAULT_COHORT_TIMEOUT_MS,
});
