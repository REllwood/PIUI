import { createServer, type Server } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  DefaultResourceLoader,
  ModelRuntime,
  SessionManager,
  SettingsManager,
  createAgentSession,
  type InlineExtension,
  type ToolDefinition,
} from '@earendil-works/pi-coding-agent';
import type { ProtocolEnvelope } from '@piui/protocol';
import {
  HostRequestClient,
  type ApprovalAbandonPayload,
  type ApprovalGrant,
  type ApprovalReadyPayload,
  type CohortApprovalRequestPayload,
} from '../../sidecar/src/bridge/host-requests.js';
import { SidecarRouter } from '../../sidecar/src/bridge/router.js';
import { canonicaliseApprovalInput, createApprovalGate } from '../../sidecar/src/pi/approval-hook.js';

const context = Object.freeze({
  generation: 18,
  sessionId: `session-${'1'.repeat(32)}`,
  workspaceId: `workspace-${'2'.repeat(32)}`,
  workspaceRevision: 4,
});
const ROUTINE = new Set(['read', 'grep', 'find', 'ls']);

type Deferred<T> = {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(error: Error): void;
};

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((onResolve, onReject) => { resolve = onResolve; reject = onReject; });
  return { promise, resolve, reject };
}

class AuthenticApprovalHost {
  readonly requests: CohortApprovalRequestPayload[] = [];
  readonly ready: ApprovalReadyPayload[] = [];
  readonly abandoned: ApprovalAbandonPayload[] = [];
  readonly #waiters = new Map<string, Deferred<ApprovalGrant>>();
  #hangReadyIndex: number | undefined;
  #closed = false;

  requestApproval(payload: CohortApprovalRequestPayload): Promise<ApprovalGrant> {
    if (this.#closed) return Promise.reject(new Error('host-disconnected'));
    const waiter = deferred<ApprovalGrant>();
    this.requests.push(payload);
    this.#waiters.set(payload.invocationId, waiter);
    return waiter.promise;
  }

  async notifyApprovalReady(payload: ApprovalReadyPayload): Promise<void> {
    if (this.#closed) throw new Error('host-disconnected');
    if (this.ready.some((entry) => entry.invocationId === payload.invocationId)) throw new Error('duplicate-ready');
    this.ready.push(payload);
    if (this.ready.length - 1 === this.#hangReadyIndex) {
      await new Promise<void>(() => undefined);
    }
  }

  hangReadyAt(index: number): void {
    this.#hangReadyIndex = index;
  }

  async abandonApproval(payload: ApprovalAbandonPayload): Promise<void> {
    this.abandoned.push(payload);
    this.settleAll('cancelled');
  }

  settleIndividual(index: number, decision: ApprovalGrant['decision']): void {
    const request = this.requests[index];
    const waiter = request ? this.#waiters.get(request.invocationId) : undefined;
    if (!request || !waiter) throw new Error('unknown-individual-decision');
    this.#waiters.delete(request.invocationId);
    waiter.resolve(Object.freeze({
      approvalId: `approval-${(index + 1).toString(16).padStart(32, '0')}`,
      decisionId: `decision-${(index + 10).toString(16).padStart(32, '0')}`,
      transactionId: `transaction-${(index + 20).toString(16).padStart(32, '0')}`,
      invocationId: request.invocationId,
      toolCallId: request.toolCallId,
      inputDigest: request.inputDigest,
      cohortDigest: request.cohort.cohortDigest,
      decision,
      scopeIds: Object.freeze(decision === 'approved' ? [`scope-${(index + 30).toString(16).padStart(32, '0')}`] : []),
    }));
  }

  settleAll(decision: Exclude<ApprovalGrant['decision'], 'approved'>): void {
    for (let index = 0; index < this.requests.length; index += 1) {
      if (this.#waiters.has(this.requests[index].invocationId)) this.settleIndividual(index, decision);
    }
  }

  groupActionable(): boolean {
    const first = this.requests[0];
    if (!first || this.requests.length !== first.cohort.orderedMembers.length
      || this.ready.length !== first.cohort.orderedMembers.length) return false;
    const descriptor = first.cohort;
    return this.requests.every((request, index) => (
      request.cohort.cohortDigest === descriptor.cohortDigest
      && request.toolCallId === descriptor.orderedMembers[index].toolCallId
      && request.toolName === descriptor.orderedMembers[index].toolName
      && ROUTINE.has(request.toolName)
    ));
  }

  settleGroup(overrides: Partial<{ groupId: string; cohortDigest: string; memberCount: number }> = {}): void {
    if (!this.groupActionable()) throw new Error('group-not-actionable');
    const transactionId = `transaction-${'a'.repeat(32)}`;
    const groupId = overrides.groupId ?? `group-${'b'.repeat(32)}`;
    const cohortDigest = overrides.cohortDigest ?? this.requests[0].cohort.cohortDigest;
    const memberCount = overrides.memberCount ?? this.requests.length;
    for (let index = 0; index < this.requests.length; index += 1) {
      const request = this.requests[index];
      const waiter = this.#waiters.get(request.invocationId);
      if (!waiter) throw new Error('group-member-unavailable');
      this.#waiters.delete(request.invocationId);
      waiter.resolve(Object.freeze({
        approvalId: `approval-${(index + 1).toString(16).padStart(32, '0')}`,
        decisionId: `decision-${(index + 1).toString(16).padStart(32, '0')}`,
        transactionId,
        invocationId: request.invocationId,
        toolCallId: request.toolCallId,
        inputDigest: request.inputDigest,
        cohortDigest,
        decision: 'approved',
        scopeIds: Object.freeze([`scope-${(index + 1).toString(16).padStart(32, '0')}`]),
        groupCommit: Object.freeze({
          groupId,
          groupDecisionId: `decision-${'c'.repeat(32)}`,
          transactionId,
          cohortDigest,
          memberCount,
        }),
      }));
    }
  }

  disconnect(): void {
    this.#closed = true;
    for (const waiter of this.#waiters.values()) waiter.reject(new Error('host-disconnected'));
    this.#waiters.clear();
  }
}

type Fixture = {
  session: Awaited<ReturnType<typeof createAgentSession>>['session'];
  host: AuthenticApprovalHost;
  markers: string[];
  root: string;
  server: Server;
  close(): Promise<void>;
};

const openFixtures: Fixture[] = [];
afterEach(async () => {
  while (openFixtures.length) await openFixtures.pop()!.close();
});

function assistantChunk(toolNames: readonly string[]): Record<string, unknown>[] {
  return toolNames.map((name, index) => ({
    id: 'fixture-turn', object: 'chat.completion.chunk', created: 1, model: 'fixture-model',
    choices: [{ index: 0, delta: { tool_calls: [{
      index, id: `fixture-call-${index + 1}`, type: 'function',
      function: { name, arguments: JSON.stringify({ value: `${name}-${index + 1}` }) },
    }] }, finish_reason: null }],
  }));
}

async function createFixture(
  toolNames: readonly string[] = ['read', 'grep', 'find'],
  laterExtensions: readonly InlineExtension[] = [],
  executionModes: readonly ('parallel' | 'sequential')[] = [],
  cohortTimeoutMs = 125_000,
): Promise<Fixture> {
  let providerTurn = 0;
  const server = createServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => { body += String(chunk); });
    request.on('end', () => {
      JSON.parse(body);
      response.writeHead(200, { 'content-type': 'text/event-stream' });
      const emit = (value: unknown) => response.write(`data: ${JSON.stringify(value)}\n\n`);
      if (providerTurn++ % 2 === 0) {
        for (const chunk of assistantChunk(toolNames)) emit(chunk);
        emit({ id: 'fixture-turn', object: 'chat.completion.chunk', created: 1, model: 'fixture-model',
          choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }] });
      } else {
        emit({ id: 'fixture-stop', object: 'chat.completion.chunk', created: 1, model: 'fixture-model',
          choices: [{ index: 0, delta: { content: 'complete' }, finish_reason: null }] });
        emit({ id: 'fixture-stop', object: 'chat.completion.chunk', created: 1, model: 'fixture-model',
          choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] });
      }
      response.end('data: [DONE]\n\n');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('loopback-unavailable');

  const root = await mkdtemp(join(tmpdir(), 'piui-a18-session-'));
  const agentDir = join(root, 'agent');
  const settingsManager = SettingsManager.inMemory({
    compaction: { enabled: false }, retry: { enabled: false },
  }, { projectTrusted: false });
  const host = new AuthenticApprovalHost();
  const gate = createApprovalGate(host, context, { cohortTimeoutMs });
  const loader = new DefaultResourceLoader({
    cwd: root, agentDir, settingsManager,
    extensionFactories: [gate.extension, ...laterExtensions],
    noExtensions: true, noSkills: true, noPromptTemplates: true,
    noThemes: true, noContextFiles: true, systemPrompt: '',
  });
  await loader.reload();
  const modelRuntime = await ModelRuntime.create({
    credentials: { read: async () => undefined, list: async () => [], write: async () => undefined, remove: async () => undefined } as never,
    modelsPath: null, allowModelNetwork: false,
  });
  modelRuntime.registerProvider('fixture', {
    baseUrl: `http://127.0.0.1:${address.port}/v1`, apiKey: 'fixture-key', api: 'openai-completions',
    models: [{ id: 'fixture-model', name: 'Fixture', reasoning: false, input: ['text'],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 4_096, maxTokens: 512 }],
  });
  const model = modelRuntime.getModel('fixture', 'fixture-model');
  if (!model) throw new Error('fixture-model-unavailable');

  const markers: string[] = [];
  const parameters = { type: 'object', properties: { value: { type: 'string' } }, required: ['value'], additionalProperties: false } as never;
  const definitions = toolNames.map((name, index): ToolDefinition => ({
    name, label: name, description: name, parameters,
    executionMode: executionModes[index] ?? 'parallel',
    async execute(toolCallId, params) {
      markers.push(`${name}:${toolCallId}:${String((params as { value: string }).value)}`);
      return { content: [{ type: 'text', text: name }], details: {} };
    },
  }));
  const decorated = definitions.map((definition) => gate.decorateToolDefinition(definition));
  const { session } = await createAgentSession({
    cwd: root, agentDir, model, thinkingLevel: 'off', modelRuntime,
    settingsManager, sessionManager: SessionManager.inMemory(root), resourceLoader: loader,
    customTools: decorated, tools: [...toolNames],
  });
  gate.bindSession(session);

  let closed = false;
  const fixture: Fixture = {
    session, host, markers, root, server,
    async close() {
      if (closed) return;
      closed = true;
      host.disconnect();
      session.dispose();
      await rm(root, { recursive: true, force: true });
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
  openFixtures.push(fixture);
  return fixture;
}

async function waitFor(predicate: () => boolean, label: string): Promise<void> {
  for (let attempt = 0; attempt < 2_000; attempt += 1) {
    if (predicate()) return;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  throw new Error(`fixture barrier timed out: ${label}`);
}

describe('A.18 authentic fail-closed parallel approval', () => {
  it('registers one exact sealed three-call assistant cohort before settlement and releases one individual only', async () => {
    const fixture = await createFixture();
    let promptSettled = false;
    const prompt = fixture.session.prompt('run the three fixture tools').finally(() => { promptSettled = true; });
    await waitFor(() => fixture.host.requests.length === 3, 'registrations');
    expect(fixture.markers).toEqual([]);
    expect(promptSettled).toBe(false);
    const descriptors = fixture.host.requests.map((request) => request.cohort);
    expect(descriptors.map((descriptor) => descriptor.cohortDigest)).toEqual(Array(3).fill(descriptors[0].cohortDigest));
    expect(descriptors.map((descriptor) => descriptor.assistantEntryId)).toEqual(Array(3).fill(descriptors[0].assistantEntryId));
    expect(descriptors[0].orderedMembers.map(({ ordinal, toolCallId, toolName }) => ({ ordinal, toolCallId, toolName }))).toEqual([
      { ordinal: 0, toolCallId: 'fixture-call-1', toolName: 'read' },
      { ordinal: 1, toolCallId: 'fixture-call-2', toolName: 'grep' },
      { ordinal: 2, toolCallId: 'fixture-call-3', toolName: 'find' },
    ]);
    await waitFor(() => fixture.host.ready.length === 3, 'wrapper ready');
    fixture.host.settleIndividual(0, 'approved');
    await waitFor(() => fixture.markers.length === 1, 'individual execution');
    expect(fixture.markers[0]).toContain('read:fixture-call-1');
    expect(promptSettled).toBe(false);
    fixture.host.settleIndividual(1, 'denied');
    fixture.host.settleIndividual(2, 'cancelled');
    await prompt;
    expect(fixture.markers).toHaveLength(1);
  });

  it('releases an eligible routine cohort only after every wrapper is ready', async () => {
    const fixture = await createFixture();
    const prompt = fixture.session.prompt('run the group');
    await waitFor(() => fixture.host.requests.length === 3, 'registrations');
    expect(fixture.markers).toEqual([]);
    await waitFor(() => fixture.host.ready.length === 3, 'ready barrier');
    expect(fixture.host.groupActionable()).toBe(true);
    fixture.host.settleGroup();
    await prompt;
    expect(fixture.markers).toHaveLength(3);
    expect(fixture.markers.map((marker) => marker.split(':')[0])).toEqual(['read', 'grep', 'find']);
  });

  it.each([
    { name: 'destructive', tools: ['read', 'bash', 'find'] },
    { name: 'external', tools: ['read', 'web_fetch', 'find'] },
    { name: 'deny-only', tools: ['read', 'invented', 'find'] },
    { name: 'mixed-sensitive', tools: ['read', 'write', 'find'] },
  ])('does not expose a group action for $name cohorts', async ({ tools }) => {
    const fixture = await createFixture(tools);
    const prompt = fixture.session.prompt('run mixed tools');
    await waitFor(() => fixture.host.requests.length === 3, 'mixed registrations');
    await waitFor(() => fixture.host.ready.length === 3, 'mixed ready');
    expect(fixture.host.groupActionable()).toBe(false);
    expect(() => fixture.host.settleGroup()).toThrow('group-not-actionable');
    expect(() => fixture.host.settleGroup({ groupId: `group-${'f'.repeat(32)}`, memberCount: 2 })).toThrow('group-not-actionable');
    fixture.host.settleAll('cancelled');
    await prompt;
    expect(fixture.markers).toEqual([]);
  });

  it.each(['expired', 'cancelled'] as const)('executes zero members after authoritative %s settlement', async (decision) => {
    const fixture = await createFixture();
    const prompt = fixture.session.prompt('run then fail');
    await waitFor(() => fixture.host.ready.length === 3, 'failure ready');
    fixture.host.settleAll(decision);
    await prompt;
    expect(fixture.markers).toEqual([]);
  });

  it('executes zero after abort, host disconnect and stale late settlement', async () => {
    const abortFixture = await createFixture();
    const abortPrompt = abortFixture.session.prompt('abort this group');
    await waitFor(() => abortFixture.host.ready.length === 3, 'abort ready');
    const abort = abortFixture.session.abort();
    await Promise.all([abort, abortPrompt]);
    expect(abortFixture.markers).toEqual([]);
    expect(abortFixture.host.abandoned.some((entry) => entry.reason === 'pi-abort')).toBe(true);

    const disconnectFixture = await createFixture();
    const disconnectPrompt = disconnectFixture.session.prompt('disconnect this group');
    await waitFor(() => disconnectFixture.host.ready.length === 3, 'disconnect ready');
    disconnectFixture.host.disconnect();
    await disconnectPrompt;
    expect(disconnectFixture.markers).toEqual([]);
    expect(() => disconnectFixture.host.settleGroup()).toThrow();
  });

  it('normal session shutdown aborts all waiting wrappers without execution', async () => {
    const fixture = await createFixture();
    const prompt = fixture.session.prompt('shut down this group');
    await waitFor(() => fixture.host.ready.length === 3, 'shutdown ready');
    fixture.session.dispose();
    await prompt;
    expect(fixture.host.abandoned.some((entry) => entry.reason === 'pi-abort')).toBe(true);
    expect(fixture.markers).toEqual([]);
  });

  it.each(['block', 'throw'] as const)('a later handler %s abandons the complete cohort before any delegate', async (behaviour) => {
    const later: InlineExtension = {
      name: `later-${behaviour}`, hidden: true,
      factory(pi) {
        pi.on('tool_call', (event) => {
          if (event.toolCallId !== 'fixture-call-2') return undefined;
          if (behaviour === 'throw') throw new Error('fixture later handler error');
          return { block: true, reason: 'fixture later handler block' };
        });
      },
    };
    const fixture = await createFixture(['read', 'grep', 'find'], [later]);
    await fixture.session.prompt('later handler failure');
    expect(fixture.host.requests).toHaveLength(2);
    expect(fixture.host.requests[0].cohort.orderedMembers).toHaveLength(3);
    expect(fixture.host.ready.length).toBeLessThan(3);
    expect(fixture.host.abandoned.some((entry) => entry.reason === 'extension-error')).toBe(true);
    expect(fixture.markers).toEqual([]);
  });

  it('a mixed sequential batch times out incomplete and a late sibling cannot revive it', async () => {
    const fixture = await createFixture(
      ['read', 'grep', 'find'],
      [],
      ['parallel', 'sequential', 'parallel'],
      10,
    );
    await fixture.session.prompt('mixed sequential failure');
    expect(fixture.host.requests).toHaveLength(1);
    expect(fixture.host.abandoned).toHaveLength(1);
    expect(fixture.markers).toEqual([]);
  });

  it('bounds repeated incomplete mixed cohorts and erases each before the next turn', async () => {
    const fixture = await createFixture(
      ['read', 'grep', 'find'],
      [],
      ['parallel', 'sequential', 'parallel'],
      5,
    );
    for (let turn = 0; turn < 6; turn += 1) {
      await fixture.session.prompt(`mixed sequential failure ${turn}`);
    }
    expect(fixture.host.requests).toHaveLength(6);
    expect(fixture.host.abandoned).toHaveLength(6);
    expect(fixture.markers).toEqual([]);
  });

  it('later mutation abandons every exact wrapper before any delegate', async () => {
    const mutator: InlineExtension = {
      name: 'later-mutator', hidden: true,
      factory(pi) {
        pi.on('tool_call', (event) => {
          if (event.toolCallId === 'fixture-call-2') {
            (event.input as { value: string }).value = 'mutated-after-approval';
          }
        });
      },
    };
    const fixture = await createFixture(['read', 'grep', 'find'], [mutator]);
    await fixture.session.prompt('mutate a later member');
    expect(fixture.host.requests).toHaveLength(3);
    expect(fixture.host.abandoned.some((entry) => entry.reason === 'definition-change'
      || entry.reason === 'digest-change')).toBe(true);
    expect(fixture.markers).toEqual([]);
  });

  it('missing ready and ready-abort races abandon every waiter with zero delegates', async () => {
    const missing = await createFixture(['read', 'grep', 'find'], [], [], 10);
    missing.host.hangReadyAt(1);
    await missing.session.prompt('one wrapper never acknowledges ready');
    expect(missing.host.ready).toHaveLength(3);
    expect(missing.host.abandoned).toHaveLength(1);
    expect(missing.markers).toEqual([]);

    const raced = await createFixture(['read', 'grep', 'find'], [], [], 125_000);
    raced.host.hangReadyAt(1);
    const prompt = raced.session.prompt('abort while ready is partial');
    await waitFor(() => raced.host.ready.length === 3, 'partial ready race');
    await Promise.all([raced.session.abort(), prompt]);
    expect(raced.host.abandoned.some((entry) => entry.reason === 'pi-abort')).toBe(true);
    expect(raced.markers).toEqual([]);
  });

  it('prevalidates one complete private group frame before resolving any member promise', async () => {
    const written: ProtocolEnvelope[] = [];
    const client = new HostRequestClient({ router: new SidecarRouter(), write: (envelope) => written.push(envelope) });
    const descriptorInput = {
      assistantEntryId: 'assistant-entry-frame',
      orderedMembers: ['read', 'grep', 'find'].map((toolName, ordinal) => ({ ordinal, toolCallId: `frame-call-${ordinal + 1}`, toolName })),
    };
    const descriptorCanonical = canonicaliseApprovalInput(descriptorInput);
    const cohort = { ...descriptorInput, cohortDigest: descriptorCanonical.digest };
    descriptorCanonical.bytes.fill(0);
    const promises = cohort.orderedMembers.map((member, index) => {
      const input = { value: index + 1 };
      const canonical = canonicaliseApprovalInput(input);
      const promise = client.requestApproval({
        method: 'approval.request', schemaVersion: 2, ...context,
        invocationId: `invocation-${(index + 1).toString(16).padStart(32, '0')}`,
        toolCallId: member.toolCallId, toolName: member.toolName,
        inputDigest: canonical.digest, input, cohort,
      });
      canonical.bytes.fill(0);
      return promise;
    });
    expect(client.pendingApprovalCount).toBe(3);
    const registrations = written.slice();
    const members = registrations.map((registration, index) => ({
      correlationId: registration.id,
      approvalId: `approval-${(index + 1).toString(16).padStart(32, '0')}`,
      decisionId: `decision-${(index + 1).toString(16).padStart(32, '0')}`,
      invocationId: `invocation-${(index + 1).toString(16).padStart(32, '0')}`,
      toolCallId: `frame-call-${index + 1}`,
      inputDigest: (registration.payload as CohortApprovalRequestPayload).inputDigest,
      scopeId: `scope-${(index + 1).toString(16).padStart(32, '0')}`,
    }));
    expect(client.consume({
      version: 1, kind: 'host-response', id: 'rust-group-frame', correlationId: registrations[0].id,
      decisionId: `decision-${'a'.repeat(32)}`, sequence: 50,
      payload: { schemaVersion: 2, method: 'approval.group-commit', ...context,
        assistantEntryId: cohort.assistantEntryId, groupId: `group-${'b'.repeat(32)}`,
        transactionId: `transaction-${'c'.repeat(32)}`, cohortDigest: cohort.cohortDigest,
        decision: 'approved', members },
    })).toBe(true);
    const grants = await Promise.all(promises);
    expect(grants).toHaveLength(3);
    expect(grants.every((grant) => grant.groupCommit?.memberCount === 3)).toBe(true);
    expect(client.pendingApprovalCount).toBe(0);
    client.disconnect();
  });

  it('matches identical cohort digests by the complete private context', async () => {
    const written: ProtocolEnvelope[] = [];
    const client = new HostRequestClient({ router: new SidecarRouter(), write: (envelope) => written.push(envelope) });
    const descriptorInput = {
      assistantEntryId: 'assistant-entry-isolated',
      orderedMembers: ['read', 'grep'].map((toolName, ordinal) => ({
        ordinal, toolCallId: `isolated-call-${ordinal + 1}`, toolName,
      })),
    };
    const canonicalDescriptor = canonicaliseApprovalInput(descriptorInput);
    const cohort = { ...descriptorInput, cohortDigest: canonicalDescriptor.digest };
    canonicalDescriptor.bytes.fill(0);
    const otherContext = { ...context, sessionId: `session-${'9'.repeat(32)}` };
    const promises: Promise<ApprovalGrant>[] = [];
    for (const [contextIndex, exactContext] of [context, otherContext].entries()) {
      for (const [memberIndex, member] of cohort.orderedMembers.entries()) {
        const input = { contextIndex, memberIndex };
        const canonical = canonicaliseApprovalInput(input);
        promises.push(client.requestApproval({
          method: 'approval.request', schemaVersion: 2, ...exactContext,
          invocationId: `invocation-${(contextIndex * 8 + memberIndex + 1).toString(16).padStart(32, '0')}`,
          toolCallId: member.toolCallId, toolName: member.toolName,
          inputDigest: canonical.digest, input, cohort,
        }));
        canonical.bytes.fill(0);
      }
    }
    const firstRegistrations = written.slice(0, 2);
    const members = firstRegistrations.map((registration, index) => ({
      correlationId: registration.id,
      approvalId: `approval-${(index + 1).toString(16).padStart(32, '0')}`,
      decisionId: `decision-${(index + 1).toString(16).padStart(32, '0')}`,
      invocationId: `invocation-${(index + 1).toString(16).padStart(32, '0')}`,
      toolCallId: `isolated-call-${index + 1}`,
      inputDigest: (registration.payload as CohortApprovalRequestPayload).inputDigest,
      scopeId: `scope-${(index + 1).toString(16).padStart(32, '0')}`,
    }));
    expect(client.consume({
      version: 1, kind: 'host-response', id: 'rust-isolated-group',
      correlationId: firstRegistrations[0].id, decisionId: `decision-${'a'.repeat(32)}`, sequence: 70,
      payload: { schemaVersion: 2, method: 'approval.group-commit', ...context,
        assistantEntryId: cohort.assistantEntryId, groupId: `group-${'b'.repeat(32)}`,
        transactionId: `transaction-${'c'.repeat(32)}`, cohortDigest: cohort.cohortDigest,
        decision: 'approved', members },
    })).toBe(true);
    expect((await Promise.all(promises.slice(0, 2))).map((grant) => grant.decision))
      .toEqual(['approved', 'approved']);
    expect(client.pendingApprovalCount).toBe(2);
    const remaining = Promise.all(promises.slice(2)).catch((error: unknown) => error);
    client.disconnect();
    await expect(remaining).resolves.toMatchObject({ code: 'approval-unavailable' });
  });

  it('makes exact prior-generation individual and group frames fatal to a fresh broker', async () => {
    const replacementContext = Object.freeze({
      ...context,
      generation: context.generation + 1,
      sessionId: `session-${'8'.repeat(32)}`,
    });

    const individualDescriptor = {
      assistantEntryId: 'assistant-entry-old-individual',
      orderedMembers: [{ ordinal: 0, toolCallId: 'old-individual-call', toolName: 'read' }],
    };
    const individualDescriptorCanonical = canonicaliseApprovalInput(individualDescriptor);
    const individualCohort = {
      ...individualDescriptor,
      cohortDigest: individualDescriptorCanonical.digest,
    };
    individualDescriptorCanonical.bytes.fill(0);
    const oldIndividualInput = { value: 'old-individual' };
    const oldIndividualCanonical = canonicaliseApprovalInput(oldIndividualInput);
    const oldIndividualWritten: ProtocolEnvelope[] = [];
    const oldIndividualBroker = new HostRequestClient({
      router: new SidecarRouter(),
      write: (envelope) => oldIndividualWritten.push(envelope),
    });
    const oldIndividualPending = oldIndividualBroker.requestApproval({
      method: 'approval.request', schemaVersion: 2, ...context,
      invocationId: `invocation-${'1'.repeat(32)}`,
      toolCallId: 'old-individual-call', toolName: 'read',
      inputDigest: oldIndividualCanonical.digest, input: oldIndividualInput,
      cohort: individualCohort,
    }).catch((error: unknown) => error);
    const oldIndividualFrame: ProtocolEnvelope = {
      version: 1, kind: 'host-response', id: 'rust-old-individual',
      correlationId: oldIndividualWritten[0]!.id,
      decisionId: `decision-${'2'.repeat(32)}`, sequence: 40,
      payload: {
        schemaVersion: 2, method: 'approval.resolve',
        approvalId: `approval-${'3'.repeat(32)}`,
        transactionId: `transaction-${'4'.repeat(32)}`,
        invocationId: `invocation-${'1'.repeat(32)}`,
        toolCallId: 'old-individual-call',
        inputDigest: oldIndividualCanonical.digest,
        cohortDigest: individualCohort.cohortDigest,
        decision: 'approved', scopeIds: [`scope-${'5'.repeat(32)}`],
      },
    };

    const replacementIndividualWritten: ProtocolEnvelope[] = [];
    const replacementIndividualBroker = new HostRequestClient({
      router: new SidecarRouter(),
      write: (envelope) => replacementIndividualWritten.push(envelope),
    });
    const replacementIndividualPending = replacementIndividualBroker.requestApproval({
      method: 'approval.request', schemaVersion: 2, ...replacementContext,
      invocationId: `invocation-${'6'.repeat(32)}`,
      toolCallId: 'old-individual-call', toolName: 'read',
      inputDigest: oldIndividualCanonical.digest, input: oldIndividualInput,
      cohort: individualCohort,
    }).catch((error: unknown) => error);
    expect(replacementIndividualWritten[0]!.id).toBe(oldIndividualFrame.correlationId);
    expect(() => replacementIndividualBroker.consume(oldIndividualFrame))
      .toThrow('Approval response rejected');
    await expect(replacementIndividualPending).resolves.toMatchObject({
      code: 'approval-response-rejected',
    });
    expect(replacementIndividualBroker.credentialGeneration.signal.aborted).toBe(true);
    expect(replacementIndividualBroker.pendingApprovalCount).toBe(0);
    oldIndividualBroker.disconnect();
    await expect(oldIndividualPending).resolves.toMatchObject({ code: 'approval-unavailable' });
    oldIndividualCanonical.bytes.fill(0);

    const groupDescriptor = {
      assistantEntryId: 'assistant-entry-old-group',
      orderedMembers: ['read', 'grep'].map((toolName, ordinal) => ({
        ordinal, toolCallId: `old-group-call-${ordinal + 1}`, toolName,
      })),
    };
    const groupDescriptorCanonical = canonicaliseApprovalInput(groupDescriptor);
    const oldGroupCohort = { ...groupDescriptor, cohortDigest: groupDescriptorCanonical.digest };
    groupDescriptorCanonical.bytes.fill(0);
    const oldGroupWritten: ProtocolEnvelope[] = [];
    const oldGroupBroker = new HostRequestClient({
      router: new SidecarRouter(),
      write: (envelope) => oldGroupWritten.push(envelope),
    });
    const oldGroupCanonicals = groupDescriptor.orderedMembers.map((_, index) => (
      canonicaliseApprovalInput({ value: `old-group-${index + 1}` })
    ));
    const oldGroupPending = groupDescriptor.orderedMembers.map((member, index) => (
      oldGroupBroker.requestApproval({
        method: 'approval.request', schemaVersion: 2, ...context,
        invocationId: `invocation-${(index + 10).toString(16).padStart(32, '0')}`,
        toolCallId: member.toolCallId, toolName: member.toolName,
        inputDigest: oldGroupCanonicals[index]!.digest,
        input: { value: `old-group-${index + 1}` }, cohort: oldGroupCohort,
      }).catch((error: unknown) => error)
    ));
    const oldGroupFrame: ProtocolEnvelope = {
      version: 1, kind: 'host-response', id: 'rust-old-group',
      correlationId: oldGroupWritten[0]!.id,
      decisionId: `decision-${'a'.repeat(32)}`, sequence: 41,
      payload: {
        schemaVersion: 2, method: 'approval.group-commit', ...context,
        assistantEntryId: oldGroupCohort.assistantEntryId,
        groupId: `group-${'b'.repeat(32)}`,
        transactionId: `transaction-${'c'.repeat(32)}`,
        cohortDigest: oldGroupCohort.cohortDigest,
        decision: 'approved',
        members: oldGroupWritten.map((registration, index) => ({
          correlationId: registration.id,
          approvalId: `approval-${(index + 20).toString(16).padStart(32, '0')}`,
          decisionId: `decision-${(index + 30).toString(16).padStart(32, '0')}`,
          invocationId: `invocation-${(index + 10).toString(16).padStart(32, '0')}`,
          toolCallId: `old-group-call-${index + 1}`,
          inputDigest: oldGroupCanonicals[index]!.digest,
          scopeId: `scope-${(index + 40).toString(16).padStart(32, '0')}`,
        })),
      },
    };

    const replacementGroupDescriptor = {
      ...groupDescriptor,
      assistantEntryId: 'assistant-entry-replacement-group',
    };
    const replacementGroupDescriptorCanonical = canonicaliseApprovalInput(replacementGroupDescriptor);
    const replacementGroupCohort = {
      ...replacementGroupDescriptor,
      cohortDigest: replacementGroupDescriptorCanonical.digest,
    };
    replacementGroupDescriptorCanonical.bytes.fill(0);
    const replacementGroupWritten: ProtocolEnvelope[] = [];
    const replacementGroupBroker = new HostRequestClient({
      router: new SidecarRouter(),
      write: (envelope) => replacementGroupWritten.push(envelope),
    });
    const replacementGroupPending = replacementGroupDescriptor.orderedMembers.map((member, index) => (
      replacementGroupBroker.requestApproval({
        method: 'approval.request', schemaVersion: 2, ...replacementContext,
        invocationId: `invocation-${(index + 50).toString(16).padStart(32, '0')}`,
        toolCallId: member.toolCallId, toolName: member.toolName,
        inputDigest: oldGroupCanonicals[index]!.digest,
        input: { value: `old-group-${index + 1}` }, cohort: replacementGroupCohort,
      }).catch((error: unknown) => error)
    ));
    expect(replacementGroupWritten.map((entry) => entry.id))
      .toEqual(oldGroupWritten.map((entry) => entry.id));
    expect(() => replacementGroupBroker.consume(oldGroupFrame))
      .toThrow('Approval response rejected');
    expect((await Promise.all(replacementGroupPending)).map((error) => (error as { code: string }).code))
      .toEqual(['approval-unavailable', 'approval-unavailable']);
    expect(replacementGroupBroker.credentialGeneration.signal.aborted).toBe(true);
    expect(replacementGroupBroker.pendingApprovalCount).toBe(0);
    oldGroupBroker.disconnect();
    expect((await Promise.all(oldGroupPending)).map((error) => (error as { code: string }).code))
      .toEqual(['approval-unavailable', 'approval-unavailable']);
    for (const canonical of oldGroupCanonicals) canonical.bytes.fill(0);
  });

  it('makes cross-kind and forged partial approval frames fatal to every private waiter', async () => {
    const crossWritten: ProtocolEnvelope[] = [];
    const cross = new HostRequestClient({ router: new SidecarRouter(), write: (envelope) => crossWritten.push(envelope) });
    const input = { value: 1 };
    const canonical = canonicaliseApprovalInput(input);
    const approval = cross.requestApproval({
      method: 'approval.request', schemaVersion: 1, ...context,
      invocationId: `invocation-${'1'.repeat(32)}`, toolName: 'read',
      inputDigest: canonical.digest, input,
    }).catch((error: unknown) => error);
    const credential = cross.list().catch((error: unknown) => error);
    const credentialRequest = crossWritten.find((entry) => entry.payload.method === 'credential.list')!;
    expect(() => cross.consume({
      version: 1, kind: 'host-response', id: 'cross-kind-private',
      correlationId: credentialRequest.id, decisionId: `decision-${'2'.repeat(32)}`, sequence: 1,
      payload: { schemaVersion: 1, approvalId: `approval-${'3'.repeat(32)}`,
        invocationId: `invocation-${'1'.repeat(32)}`, inputDigest: canonical.digest,
        decision: 'approved', scopeIds: [`scope-${'4'.repeat(32)}`] },
    })).toThrow('Credential response rejected');
    await expect(credential).resolves.toMatchObject({ code: 'credential-response-rejected' });
    await expect(approval).resolves.toMatchObject({ code: 'approval-unavailable' });

    const forgedWritten: ProtocolEnvelope[] = [];
    const forged = new HostRequestClient({ router: new SidecarRouter(), write: (envelope) => forgedWritten.push(envelope) });
    const descriptorInput = {
      assistantEntryId: 'assistant-entry-forged',
      orderedMembers: ['read', 'grep'].map((toolName, ordinal) => ({
        ordinal, toolCallId: `forged-call-${ordinal + 1}`, toolName,
      })),
    };
    const descriptorCanonical = canonicaliseApprovalInput(descriptorInput);
    const cohort = { ...descriptorInput, cohortDigest: descriptorCanonical.digest };
    descriptorCanonical.bytes.fill(0);
    const forgedPromises = cohort.orderedMembers.map((member, index) => forged.requestApproval({
      method: 'approval.request', schemaVersion: 2, ...context,
      invocationId: `invocation-${(index + 8).toString(16).padStart(32, '0')}`,
      toolCallId: member.toolCallId, toolName: member.toolName,
      inputDigest: canonical.digest, input, cohort,
    }).catch((error: unknown) => error));
    expect(() => forged.consume({
      version: 1, kind: 'host-response', id: 'forged-partial-group',
      correlationId: forgedWritten[0].id, decisionId: `decision-${'5'.repeat(32)}`, sequence: 2,
      payload: { schemaVersion: 2, method: 'approval.group-commit', ...context,
        assistantEntryId: cohort.assistantEntryId, groupId: `group-${'6'.repeat(32)}`,
        transactionId: `transaction-${'7'.repeat(32)}`, cohortDigest: cohort.cohortDigest,
        decision: 'approved', members: [] },
    })).toThrow('Approval response rejected');
    expect((await Promise.all(forgedPromises)).map((error) => (error as { code: string }).code))
      .toEqual(['approval-unavailable', 'approval-unavailable']);
    canonical.bytes.fill(0);
  });

  it('makes malformed, wrong-kind and replayed approval responses generation-fatal', async () => {
    const written: ProtocolEnvelope[] = [];
    const client = new HostRequestClient({ router: new SidecarRouter(), write: (envelope) => written.push(envelope) });
    const input = { value: 1 };
    const canonical = canonicaliseApprovalInput(input);
    const make = (index: number) => client.requestApproval({
      method: 'approval.request', schemaVersion: 1, ...context,
      invocationId: `invocation-${index.toString(16).padStart(32, '0')}`,
      toolName: 'read', inputDigest: canonical.digest, input,
    });
    const first = make(1).catch((error: unknown) => error);
    const second = make(2).catch((error: unknown) => error);
    const credential = client.list().catch((error: unknown) => error);
    expect(() => client.consume({
      version: 1, kind: 'response', id: 'wrong-kind-approval',
      correlationId: written[0].id, sequence: 1, payload: {},
    })).toThrow('Approval response rejected');
    await expect(first).resolves.toMatchObject({ code: 'approval-response-rejected' });
    await expect(second).resolves.toMatchObject({ code: 'approval-unavailable' });
    await expect(credential).resolves.toMatchObject({ code: 'credential-host-disconnected' });

    const replayWritten: ProtocolEnvelope[] = [];
    const replay = new HostRequestClient({ router: new SidecarRouter(), write: (envelope) => replayWritten.push(envelope) });
    const pending = replay.requestApproval({
      method: 'approval.request', schemaVersion: 1, ...context,
      invocationId: `invocation-${'f'.repeat(32)}`, toolName: 'read',
      inputDigest: canonical.digest, input,
    });
    const response: ProtocolEnvelope = {
      version: 1, kind: 'host-response', id: 'approval-once', correlationId: replayWritten[0].id,
      decisionId: `decision-${'d'.repeat(32)}`, sequence: 2,
      payload: { schemaVersion: 1, approvalId: `approval-${'e'.repeat(32)}`,
        invocationId: `invocation-${'f'.repeat(32)}`, inputDigest: canonical.digest,
        decision: 'approved', scopeIds: [`scope-${'a'.repeat(32)}`] },
    };
    expect(replay.consume(response)).toBe(true);
    expect((await pending).decision).toBe('approved');
    expect(() => replay.consume({ ...response, id: 'approval-replay', sequence: 3 }))
      .toThrow('Approval response rejected');
    expect(replay.credentialGeneration.signal.aborted).toBe(true);
    canonical.bytes.fill(0);
  });
});
