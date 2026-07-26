import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import {
  DefaultResourceLoader,
  ModelRuntime,
  SessionManager,
  SettingsManager,
  createAgentSession,
  createReadToolDefinition,
  type ToolDefinition,
} from '@earendil-works/pi-coding-agent';
import {
  assertApprovalRequestPayload,
  assertApprovalResponsePayload,
  HostRequestClient,
  isApprovalToolName,
  type ApprovalGrant,
  type ApprovalRequestPayload,
} from '../../sidecar/src/bridge/host-requests.js';
import { canonicaliseApprovalInput, createApprovalGate } from '../../sidecar/src/pi/approval-hook.js';
import { SidecarRouter } from '../../sidecar/src/bridge/router.js';

const context = Object.freeze({
  generation: 7,
  sessionId: 'session-11111111111111111111111111111111',
  workspaceId: 'workspace-22222222222222222222222222222222',
  workspaceRevision: 3,
});

function approvalPayload(input: Record<string, unknown> = {}): ApprovalRequestPayload {
  const canonical = canonicaliseApprovalInput(input);
  const payload: ApprovalRequestPayload = {
    method: 'approval.request', schemaVersion: 1, ...context,
    invocationId: `invocation-${'3'.repeat(32)}`, toolName: 'read',
    inputDigest: canonical.digest, input,
  };
  canonical.bytes.fill(0);
  return payload;
}

function deferredHost() {
  const requests: ApprovalRequestPayload[] = [];
  const settlers: Array<(grant: ApprovalGrant) => void> = [];
  return {
    requests,
    host: {
      requestApproval(payload: ApprovalRequestPayload): Promise<ApprovalGrant> {
        requests.push(payload);
        return new Promise((resolve) => settlers.push(resolve));
      },
      notifyApprovalReady: async () => undefined,
      abandonApproval: async () => undefined,
    },
    settle(decision: ApprovalGrant['decision'], index = 0) {
      const request = requests[index];
      if (request.schemaVersion !== 2) throw new Error('expected cohort request');
      settlers[index](Object.freeze({
        approvalId: `approval-${'a'.repeat(32)}`,
        decisionId: `decision-${'b'.repeat(32)}`,
        transactionId: `transaction-${'d'.repeat(32)}`,
        invocationId: request.invocationId,
        toolCallId: request.toolCallId,
        cohortDigest: request.cohort.cohortDigest,
        inputDigest: request.inputDigest,
        decision,
        scopeIds: Object.freeze(decision === 'approved' ? [`scope-${'c'.repeat(32)}`] : []),
      }));
    },
  };
}

async function settleTurn(): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve));
}

function appendAssistant(session: Awaited<ReturnType<typeof authenticSession>>['session'], calls: Array<{ id: string; name: string; arguments: Record<string, unknown> }>): void {
  session.sessionManager.appendMessage({
    role: 'assistant',
    content: calls.map((call) => ({ type: 'toolCall', ...call })),
    api: 'openai-completions', provider: 'fixture', model: 'fixture',
    usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
    stopReason: 'toolUse', timestamp: Date.now(),
  } as never);
}

async function authenticSession(gate: ReturnType<typeof createApprovalGate>, definition: ToolDefinition) {
  const root = await mkdtemp(join(tmpdir(), 'piui-a17-session-'));
  const agentDir = join(root, 'agent');
  const settingsManager = SettingsManager.inMemory({}, { projectTrusted: false });
  const loader = new DefaultResourceLoader({
    cwd: root,
    agentDir,
    settingsManager,
    extensionFactories: [gate.extension],
    noExtensions: true,
    noSkills: true,
    noPromptTemplates: true,
    noThemes: true,
    noContextFiles: true,
    systemPrompt: '',
  });
  await loader.reload();
  const credentials = {
    read: async () => undefined,
    list: async () => [],
    write: async () => undefined,
    remove: async () => undefined,
  };
  const modelRuntime = await ModelRuntime.create({ credentials: credentials as never, modelsPath: null });
  const { session } = await createAgentSession({
    cwd: root,
    agentDir,
    modelRuntime,
    settingsManager,
    sessionManager: SessionManager.inMemory(root),
    resourceLoader: loader,
    customTools: [definition],
    tools: [definition.name],
  });
  return { session, root };
}

describe('A.17 authoritative approval proof', () => {
  it('matches shared request, response and canonical byte fixtures', async () => {
    const fixture = JSON.parse(await readFile(new URL('../../packages/protocol/fixtures/approval-contract.json', import.meta.url), 'utf8'));
    for (const request of fixture.validRequests) expect(() => assertApprovalRequestPayload(request)).not.toThrow();
    for (const request of fixture.invalidRequests) expect(() => assertApprovalRequestPayload(request)).toThrow();
    for (const response of fixture.validResponses) expect(() => assertApprovalResponsePayload(response)).not.toThrow();
    for (const response of fixture.invalidResponses) expect(() => assertApprovalResponsePayload(response)).toThrow();
    const baseRequest = fixture.validRequests[1];
    for (const toolName of fixture.toolNameCases.valid) {
      expect(Buffer.byteLength(toolName, 'utf8')).toBeLessThanOrEqual(96);
      expect(isApprovalToolName(toolName)).toBe(true);
      expect(() => assertApprovalRequestPayload({ ...baseRequest, toolName })).not.toThrow();
    }
    for (const toolName of fixture.toolNameCases.invalid) {
      expect(isApprovalToolName(toolName)).toBe(false);
      expect(() => assertApprovalRequestPayload({ ...baseRequest, toolName })).toThrow();
    }
    const approvalSchema = JSON.parse(await readFile(new URL('../../packages/protocol/schema/approval.schema.json', import.meta.url), 'utf8'));
    expect(approvalSchema.$defs.toolName).toEqual({ type: 'string', pattern: '^[A-Za-z][A-Za-z0-9_-]{0,95}$', maxLength: 96 });
    for (const entry of fixture.canonicalCases) {
      const canonical = canonicaliseApprovalInput(JSON.parse(entry.jsonText));
      expect(canonical.bytes.toString('utf8')).toBe(entry.canonical);
      expect(canonical.digest).toBe(entry.sha256);
      canonical.bytes.fill(0);
    }
    for (const entry of fixture.canonicalRejections) {
      expect(() => canonicaliseApprovalInput(JSON.parse(entry.jsonText))).toThrow('approval-input-rejected');
    }
  });

  it('enforces exact depth, node and byte bounds plus hostile JavaScript graph rejection', () => {
    let depth: unknown = 0;
    for (let index = 0; index < 15; index += 1) depth = [depth];
    expect(() => canonicaliseApprovalInput({ v: depth })).not.toThrow();
    expect(() => canonicaliseApprovalInput({ v: [depth] })).toThrow();
    expect(canonicaliseApprovalInput({ v: Array(254).fill(0) }).bytes.length).toBeLessThan(65_536);
    expect(() => canonicaliseApprovalInput({ v: Array(255).fill(0) })).toThrow();
    expect(canonicaliseApprovalInput({ v: 'x'.repeat(65_528) }).bytes.length).toBe(65_536);
    expect(() => canonicaliseApprovalInput({ v: 'x'.repeat(65_529) })).toThrow();

    const accessor = Object.defineProperty({}, 'secret', { enumerable: true, get: () => 'x' });
    const custom = Object.create({ inherited: true }); custom.safe = true;
    const sparse = { values: Array(2) };
    const cycle: Record<string, unknown> = {}; cycle.self = cycle;
    const symbol = { safe: true } as Record<PropertyKey, unknown>; symbol[Symbol('hidden')] = true;
    for (const value of [accessor, custom, sparse, cycle, symbol, { value: 1.5 }, { value: Number.NaN }, { value: Number.POSITIVE_INFINITY }, { value: -0 }, { value: 9_007_199_254_740_992 }, { value: '\ud800' }]) {
      expect(() => canonicaliseApprovalInput(value)).toThrow('approval-input-rejected');
    }
  });

  it('keeps approval and credential capacities independent and correlations exact', async () => {
    const written: Array<Record<string, unknown>> = [];
    const client = new HostRequestClient({
      router: new SidecarRouter(), write: (envelope) => written.push(envelope as unknown as Record<string, unknown>),
      maxPending: 1, maxApprovalPending: 1,
    });
    const payload = approvalPayload();
    const approval = client.requestApproval(payload);
    const credentials = client.list();
    await expect(client.requestApproval({ ...payload, invocationId: `invocation-${'7'.repeat(32)}` })).rejects.toMatchObject({ code: 'approval-unavailable' });
    await expect(client.list()).rejects.toMatchObject({ code: 'credential-host-capacity' });
    expect(client.pendingApprovalCount).toBe(1);
    expect(client.pendingCredentialCount).toBe(1);

    const approvalRequest = written.find((entry) => (entry.payload as Record<string, unknown>).method === 'approval.request')!;
    const credentialRequest = written.find((entry) => (entry.payload as Record<string, unknown>).method === 'credential.list')!;
    expect(client.consume({ version: 1, kind: 'host-response', id: 'response-credential', correlationId: credentialRequest.id as string, sequence: 50, payload: { entries: [] } })).toBe(true);
    expect(await credentials).toEqual([]);
    expect(client.consume({ version: 1, kind: 'host-response', id: 'response-approval', correlationId: approvalRequest.id as string, decisionId: `decision-${'4'.repeat(32)}`, sequence: 51, payload: { schemaVersion: 1, approvalId: `approval-${'5'.repeat(32)}`, invocationId: payload.invocationId, inputDigest: payload.inputDigest, decision: 'approved', scopeIds: [`scope-${'6'.repeat(32)}`] } })).toBe(true);
    expect((await approval).decision).toBe('approved');
    client.disconnect();
  });

  it('uses a 125 second approval guard and treats any post-retirement response as fatal replay', async () => {
    vi.useFakeTimers();
    try {
      const written: Array<Record<string, unknown>> = [];
      const client = new HostRequestClient({ router: new SidecarRouter(), write: (envelope) => written.push(envelope as unknown as Record<string, unknown>) });
      const payload = approvalPayload();
      const pending = client.requestApproval(payload);
      const timedOut = expect(pending).rejects.toMatchObject({ code: 'approval-timeout' });
      await vi.advanceTimersByTimeAsync(125_000);
      await timedOut;
      const request = written[0];
      expect(() => client.consume({ version: 1, kind: 'host-response', id: 'late-expiry', correlationId: request.id as string, decisionId: `decision-${'4'.repeat(32)}`, sequence: 2, payload: { schemaVersion: 1, approvalId: `approval-${'5'.repeat(32)}`, invocationId: payload.invocationId, inputDigest: payload.inputDigest, decision: 'expired', scopeIds: [] } })).toThrow('Approval response rejected');
      expect(client.credentialGeneration.signal.aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it('mediates the real Pi five-argument execution path using original params identity once', async () => {
    const deferred = deferredHost();
    const gate = createApprovalGate(deferred.host, context);
    const observed: unknown[][] = [];
    const packageDefinition = createReadToolDefinition('/workspace', {
      operations: { access: async () => undefined, readFile: async () => Buffer.from('public-sdk-result') },
    });
    const originalExecute = packageDefinition.execute;
    const instrumented = { ...packageDefinition, async execute(...args: Parameters<typeof originalExecute>) { observed.push(args); return originalExecute(...args); } };
    const decorated = gate.decorateToolDefinition(instrumented);
    const { session, root } = await authenticSession(gate, decorated);
    try {
      gate.bindSession(session);
      expect(session.getToolDefinition('read')).toBe(decorated);
      const params = { path: 'private/a' };
      appendAssistant(session, [{ id: 'tool-1', name: 'read', arguments: params }]);
      const agent = (session as unknown as { agent: { beforeToolCall(input: unknown): Promise<unknown> } }).agent;
      expect(await agent.beforeToolCall({ toolCall: { id: 'tool-1', name: 'read' }, args: params })).toBeUndefined();
      const active = session.state.tools.find((tool) => tool.name === 'read')!;
      const execution = active.execute('tool-1', params, undefined, undefined);
      await settleTurn();
      expect(observed).toHaveLength(0);
      deferred.settle('approved');
      const result = await execution;
      expect(result.content[0]).toMatchObject({ type: 'text', text: 'public-sdk-result' });
      expect(observed).toHaveLength(1);
      expect(observed[0]).toHaveLength(5);
      expect(observed[0][0]).toBe('tool-1');
      expect(observed[0][1]).toBe(params);
      expect(Object.isFrozen(observed[0][1])).toBe(true);
      expect(observed[0][4]).toEqual(expect.objectContaining({ cwd: expect.any(String) }));
      await expect(active.execute('tool-1', params, undefined, undefined)).rejects.toThrow('not approved');
    } finally {
      session.dispose();
      await rm(root, { recursive: true, force: true });
    }
  });

  it('blocks same-name replacement, registry replacement, mutation, denial and unwrapped definitions', async () => {
    const deferred = deferredHost();
    const gate = createApprovalGate(deferred.host, context);
    const original = createReadToolDefinition('/workspace');
    const decorated = gate.decorateToolDefinition(original);
    const { session, root } = await authenticSession(gate, decorated);
    try {
      gate.bindSession(session);
      const agent = (session as unknown as { agent: { beforeToolCall(input: unknown): Promise<unknown> } }).agent;
      const deniedParams = { path: 'private/denied' };
      appendAssistant(session, [{ id: 'deny', name: 'read', arguments: deniedParams }]);
      expect(await agent.beforeToolCall({ toolCall: { id: 'deny', name: 'read' }, args: deniedParams })).toBeUndefined();
      const active = session.state.tools.find((tool) => tool.name === 'read')!;
      const denial = active.execute('deny', deniedParams, undefined, undefined);
      await settleTurn(); deferred.settle('denied');
      await expect(denial).rejects.toThrow('not approved');

      const mutable = { path: 'private/original' };
      appendAssistant(session, [{ id: 'mutated', name: 'read', arguments: mutable }]);
      await agent.beforeToolCall({ toolCall: { id: 'mutated', name: 'read' }, args: mutable });
      const approved = active.execute('mutated', mutable, undefined, undefined);
      await settleTurn();
      mutable.path = 'private/replacement';
      deferred.settle('approved', 1);
      await expect(approved).rejects.toThrow('not approved');

      const replacement = { ...original };
      const registry = (session as unknown as { _toolDefinitions: Map<string, unknown> })._toolDefinitions;
      registry.set('read', { definition: replacement, sourceInfo: {} });
      appendAssistant(session, [{ id: 'replacement', name: 'read', arguments: { path: 'x' } }]);
      expect(await agent.beforeToolCall({ toolCall: { id: 'replacement', name: 'read' }, args: { path: 'x' } })).toEqual({ block: true, reason: 'This action was not approved.' });
      await session.reload();
      expect(session.getToolDefinition('read')).toBe(decorated);
      appendAssistant(session, [{ id: 'reload', name: 'read', arguments: { path: 'x' } }]);
      expect(await agent.beforeToolCall({ toolCall: { id: 'reload', name: 'read' }, args: { path: 'x' } })).toEqual({ block: true, reason: 'This action was not approved.' });
    } finally {
      session.dispose();
      await rm(root, { recursive: true, force: true });
    }

    const second = createApprovalGate(deferred.host, context);
    const secondDecorated = second.decorateToolDefinition(createReadToolDefinition('/workspace'));
    const replacement = { ...secondDecorated, execute: createReadToolDefinition('/workspace').execute };
    const authentic = await authenticSession(second, replacement);
    try {
      expect(() => second.bindSession(authentic.session)).toThrow('approval-session-rejected');
    } finally {
      authentic.session.dispose();
      await rm(authentic.root, { recursive: true, force: true });
    }
  });
});
