import { appendFile, mkdir, mkdtemp, readFile, readdir, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { getAgentDir } from '@earendil-works/pi-coding-agent';
import type { ProtocolEnvelope } from '@piui/protocol';
import {
  HostRequestClient,
  type CohortApprovalRequestPayload,
} from '../../sidecar/src/bridge/host-requests.js';
import { SidecarRouter } from '../../sidecar/src/bridge/router.js';
import type { AdapterTurnEvent } from '../../sidecar/src/pi/adapter.js';
import {
  publicFauxAssistantMessage,
  publicFauxProvider,
  publicFauxToolCall,
} from '../../sidecar/src/pi/ai-public-sdk.js';
import { Pi082Adapter } from '../../sidecar/src/pi/pi-082-adapter.js';
import { ProductRuntime } from '../../sidecar/src/pi/product-router.js';

// Drives real Pi 0.82 turns through ProductRuntime -> Pi082Adapter with pi-ai's
// faux provider standing in for the model. Credentials and approvals travel
// through the real HostRequestClient, answered by a scripted fake Rust host.

const PROVIDER = 'piui-e2e-provider';
const MODEL = 'piui-e2e-model';
const workspaceId = `workspace-${'e'.repeat(32)}`;

type Deferred = { promise: Promise<void>; resolve(): void };
function deferred(): Deferred {
  let resolve!: () => void;
  const promise = new Promise<void>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

function hex(value: number): string {
  return value.toString(16).padStart(32, '0');
}

/** Answers the sidecar's private host requests the way Rust would. */
class ScriptedHost {
  readonly approvals: CohortApprovalRequestPayload[] = [];
  readonly methods: string[] = [];
  readonly client: HostRequestClient;
  #sequence = 1;

  constructor() {
    this.client = new HostRequestClient({
      router: new SidecarRouter(),
      write: (envelope) => {
        // Reply asynchronously, as the real pipe does.
        setImmediate(() => this.#respond(envelope));
      },
    });
  }

  #respond(request: ProtocolEnvelope): void {
    if (request.kind !== 'host-request') return;
    const payload = request.payload as Record<string, unknown>;
    const method = String(payload.method);
    this.methods.push(method);
    const count = this.#sequence++;
    const base = {
      version: 1 as const,
      kind: 'host-response' as const,
      id: `host-response-${count}`,
      correlationId: request.id,
      sequence: count,
    };
    if (method === 'credential.list') {
      this.client.consume({ ...base, payload: { entries: [] } });
    } else if (method === 'credential.get') {
      this.client.consume({ ...base, payload: { found: false } });
    } else if (method === 'approval.request') {
      const approval = payload as unknown as CohortApprovalRequestPayload;
      this.approvals.push(approval);
      const index = this.approvals.length;
      this.client.consume({
        ...base,
        decisionId: `decision-${hex(index)}`,
        payload: {
          schemaVersion: 2,
          method: 'approval.resolve',
          approvalId: `approval-${hex(index)}`,
          transactionId: `transaction-${hex(index)}`,
          invocationId: approval.invocationId,
          toolCallId: approval.toolCallId,
          inputDigest: approval.inputDigest,
          cohortDigest: approval.cohort.cohortDigest,
          decision: 'approved',
          scopeIds: [`scope-${hex(index)}`],
        },
      });
    } else if (method === 'approval.ready') {
      this.client.consume({
        ...base,
        payload: {
          schemaVersion: 2,
          method: 'approval.ready-ack',
          invocationId: payload.invocationId,
          accepted: true,
        },
      });
    } else if (method === 'approval.abandon') {
      this.client.consume({
        ...base,
        payload: {
          schemaVersion: 2,
          method: 'approval.abandon-ack',
          cohortDigest: payload.cohortDigest,
          cancelled: true,
        },
      });
    }
  }
}

let requestNumber = 0;
function productRequest(payload: Record<string, unknown>): ProtocolEnvelope {
  requestNumber += 1;
  return {
    version: 1,
    kind: 'request',
    id: `rust-product-e2e-${requestNumber}`,
    sequence: requestNumber,
    payload,
  };
}

function turnRequest(sessionId: string, generation: number, text: string): ProtocolEnvelope {
  requestNumber += 1;
  return {
    version: 1,
    kind: 'request',
    id: `web-e2e-turn-${requestNumber}`,
    sequence: requestNumber,
    payload: {
      method: 'product.turn.start',
      schemaVersion: 1,
      sessionId,
      generation,
      text,
      retryPrevious: false,
      attachments: [],
    },
  };
}

async function collect(stream: AsyncIterable<AdapterTurnEvent>): Promise<AdapterTurnEvent[]> {
  const events: AdapterTurnEvent[] = [];
  for await (const event of stream) events.push(event);
  return events;
}

function streamedText(events: readonly AdapterTurnEvent[]): string {
  return events
    .filter((event) => event.type === 'text')
    .map((event) => event.text)
    .join('');
}

type Session = { id: string; generation: number; writable: boolean };

function fauxProduct() {
  const faux = publicFauxProvider({
    api: 'piui-e2e-api',
    provider: PROVIDER,
    models: [
      {
        id: MODEL,
        name: 'PIUI end-to-end model',
        reasoning: false,
        input: ['text'],
        contextWindow: 200_000,
        maxTokens: 4_096,
      },
    ],
    tokenSize: { min: 3, max: 3 },
  });
  const host = new ScriptedHost();
  const product = new ProductRuntime(host.client, 1, (options) =>
    Pi082Adapter.create({
      ...options,
      allowModelNetwork: false,
      prepareModelRuntime: (modelRuntime) => modelRuntime.registerNativeProvider(faux.provider),
    }),
  );
  return { faux, host, product };
}

async function workspace(root: string): Promise<{ workspacePath: string; agentDir: string }> {
  const workspacePath = join(root, 'workspace');
  const agentDir = join(root, 'agent');
  await mkdir(workspacePath);
  await mkdir(agentDir);
  return { workspacePath, agentDir };
}

async function createSession(
  product: ProductRuntime,
  workspacePath: string,
  agentDir: string,
): Promise<Session> {
  const created = (await product.handle(
    productRequest({
      method: 'product.session.create',
      schemaVersion: 1,
      workspaceId,
      workspaceRevision: 1,
      workspacePath,
      agentDir,
      title: 'End to end',
      providerId: PROVIDER,
      modelId: MODEL,
    }),
  )) as { session: Session };
  return created.session;
}

describe('product runtime end to end with real Pi turns', () => {
  const originalHome = process.env.HOME;
  const originalAgentDir = process.env.PIUI_PI_AGENT_DIR;
  let root = '';
  let runtime: ProductRuntime | undefined;

  beforeEach(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), 'piui-product-e2e-')));
    process.env.HOME = join(root, 'sealed-home');
    await mkdir(process.env.HOME);
    delete process.env.PIUI_PI_AGENT_DIR;
  });

  afterEach(async () => {
    await runtime?.close();
    runtime = undefined;
    delete process.env.PIUI_USER_HOME;
    delete process.env.PIUI_USER_PATH;
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalAgentDir === undefined) delete process.env.PIUI_PI_AGENT_DIR;
    else process.env.PIUI_PI_AGENT_DIR = originalAgentDir;
    await rm(root, { recursive: true, force: true });
  });

  it('creates, streams, approves a tool, queues follow-ups, resumes and forks', async () => {
    const { workspacePath, agentDir } = await workspace(root);
    const { faux, host, product } = fauxProduct();
    runtime = product;

    // 1. A brand-new session has no file on disk until Pi's first assistant reply.
    const session = await createSession(product, workspacePath, agentDir);
    expect(session).toMatchObject({ generation: 1, writable: true });

    // 2. A plain text turn streams to completion and persists the session file.
    faux.setResponses([publicFauxAssistantMessage('Hello from the faux model.')]);
    const first = await collect(
      runtime.stream(turnRequest(session.id, 1, 'Say hello'), new AbortController().signal),
    );
    expect(first.at(0)?.type).toBe('started');
    expect(first.at(-1)?.type).toBe('complete');
    expect(streamedText(first)).toBe('Hello from the faux model.');

    // 3. A tool call is approved through the host and its change is recorded.
    faux.setResponses([
      publicFauxAssistantMessage(
        publicFauxToolCall('write', { path: 'notes.txt', content: 'written by Pi\n' }),
        { stopReason: 'toolUse' },
      ),
      publicFauxAssistantMessage('The note is written.'),
    ]);
    const second = await collect(
      runtime.stream(turnRequest(session.id, 1, 'Write a note'), new AbortController().signal),
    );
    expect(second.at(-1)?.type).toBe('complete');
    expect(second.filter((event) => event.type === 'tool').map((event) => event.code)).toEqual([
      'started',
      'complete',
    ]);
    expect(host.approvals.map((approval) => approval.toolName)).toEqual(['write']);
    expect(await readFile(join(workspacePath, 'notes.txt'), 'utf8')).toBe('written by Pi\n');
    const changes = (await runtime.handle(
      productRequest({
        method: 'product.changes.list',
        schemaVersion: 1,
        sessionId: session.id,
        expectedGeneration: 1,
      }),
    )) as { changes: readonly { path: string; state: string }[] };
    expect(changes.changes).toMatchObject([{ path: 'notes.txt', state: 'added' }]);

    // 4. Follow-ups can be queued and replaced while PIUI's own turn is writing.
    const release = deferred();
    const providerWaiting = deferred();
    const followUpContexts: string[] = [];
    faux.setResponses([
      async () => {
        providerWaiting.resolve();
        await release.promise;
        return publicFauxAssistantMessage('Working on the first request.');
      },
      (context) => {
        const last = context.messages.at(-1);
        followUpContexts.push(
          last?.role === 'user'
            ? typeof last.content === 'string'
              ? last.content
              : last.content.map((part) => (part.type === 'text' ? part.text : '')).join('')
            : '',
        );
        return publicFauxAssistantMessage('Handled the follow-up.');
      },
    ]);
    const third = collect(
      runtime.stream(turnRequest(session.id, 1, 'Start a long task'), new AbortController().signal),
    );
    await providerWaiting.promise;
    const queued = (await runtime.handle(
      productRequest({
        method: 'product.queue.followup',
        schemaVersion: 1,
        sessionId: session.id,
        expectedGeneration: 1,
        text: 'Also check the tests',
      }),
    )) as { queue: { number: number } };
    expect(queued.queue.number).toBe(1);
    const replaced = (await runtime.handle(
      productRequest({
        method: 'product.queue.replace',
        schemaVersion: 1,
        sessionId: session.id,
        expectedGeneration: 1,
        texts: ['Only check the README'],
      }),
    )) as { queue: { count: number } };
    expect(replaced.queue.count).toBe(1);
    release.resolve();
    const thirdEvents = await third;
    expect(thirdEvents.at(-1)?.type).toBe('complete');
    expect(streamedText(thirdEvents)).toBe('Working on the first request.Handled the follow-up.');
    expect(followUpContexts).toEqual(['Only check the README']);

    // The turn end re-acknowledged Pi's own appends, so ordinary work continues.
    const renamed = (await runtime.handle(
      productRequest({
        method: 'product.session.rename',
        schemaVersion: 1,
        sessionId: session.id,
        expectedGeneration: 1,
        title: 'Renamed after turns',
      }),
    )) as { session: Session & { title: string } };
    expect(renamed.session.title).toBe('Renamed after turns');

    // 5. Resuming reopens the persisted file under a new generation.
    const resumed = (await runtime.handle(
      productRequest({
        method: 'product.session.resume',
        schemaVersion: 1,
        sessionId: session.id,
        expectedGeneration: 1,
      }),
    )) as { session: Session };
    expect(resumed.session).toMatchObject({ id: session.id, generation: 2, writable: true });
    const inspected = (await runtime.handle(
      productRequest({
        method: 'product.session.inspect',
        schemaVersion: 1,
        sessionId: session.id,
        expectedGeneration: 2,
      }),
    )) as { messages: readonly { role: string; text: string }[] };
    expect(inspected.messages.map((message) => `${message.role}:${message.text}`)).toEqual([
      'user:Say hello',
      'assistant:Hello from the faux model.',
      'user:Write a note',
      'assistant:The note is written.',
      'user:Start a long task',
      'assistant:Working on the first request.',
      'user:Only check the README',
      'assistant:Handled the follow-up.',
    ]);
    faux.setResponses([publicFauxAssistantMessage('Resumed and ready.')]);
    const afterResume = await collect(
      runtime.stream(turnRequest(session.id, 2, 'Are you there?'), new AbortController().signal),
    );
    expect(afterResume.at(-1)?.type).toBe('complete');
    expect(streamedText(afterResume)).toBe('Resumed and ready.');

    // 6. Forking copies the persisted history into a new writable session.
    const forked = (await runtime.handle(
      productRequest({
        method: 'product.session.fork',
        schemaVersion: 1,
        sessionId: session.id,
        expectedGeneration: 2,
      }),
    )) as { session: Session };
    expect(forked.session.id).not.toBe(session.id);
    expect(forked.session).toMatchObject({ generation: 1, writable: true });
    faux.setResponses([publicFauxAssistantMessage('Answering on the branch.')]);
    const onFork = await collect(
      runtime.stream(
        turnRequest(forked.session.id, 1, 'Continue on the branch'),
        new AbortController().signal,
      ),
    );
    expect(onFork.at(-1)?.type).toBe('complete');
    const forkMessages = (await runtime.handle(
      productRequest({
        method: 'product.session.inspect',
        schemaVersion: 1,
        sessionId: forked.session.id,
        expectedGeneration: 1,
      }),
    )) as { messages: readonly { role: string; text: string }[] };
    expect(forkMessages.messages.at(-3)?.text).toBe('Resumed and ready.');
    expect(forkMessages.messages.at(-1)?.text).toBe('Answering on the branch.');
    expect(faux.getPendingResponseCount()).toBe(0);
  }, 30_000);

  it('retires the turn registry entry when a retry turns out to be stale', async () => {
    const { workspacePath, agentDir } = await workspace(root);
    const { product } = fauxProduct();
    runtime = product;
    const session = await createSession(product, workspacePath, agentDir);
    const retry = turnRequest(session.id, 1, 'Nothing to retry');
    retry.payload.retryPrevious = true;
    await expect(collect(product.stream(retry, new AbortController().signal))).rejects.toThrow(
      'turn-retry-stale',
    );
    // A leaked entry would still report the finished turn as stoppable.
    expect(await product.stop(retry.id)).toBe('too-late');
  });

  it('coalesces a long streamed reply into a few well-formed delta events', async () => {
    const { workspacePath, agentDir } = await workspace(root);
    const { faux, product } = fauxProduct();
    runtime = product;
    const session = await createSession(product, workspacePath, agentDir);
    // The faux provider streams 12 UTF-16 units per token, so many tokens end
    // halfway through an emoji's surrogate pair.
    const reply = `a${'😀'.repeat(3_000)} done`;
    faux.setResponses([publicFauxAssistantMessage(reply)]);
    const events = await collect(
      product.stream(turnRequest(session.id, 1, 'Long reply'), new AbortController().signal),
    );
    const deltas = events.filter((event) => event.type === 'text');
    expect(streamedText(events)).toBe(reply);
    // Over 500 provider tokens; size flushes alone need only four events, and a
    // slow machine may add a few 32 ms flushes.
    expect(Math.ceil(reply.length / 12)).toBeGreaterThan(500);
    expect(deltas.length).toBeLessThanOrEqual(16);
    expect(
      deltas.every(
        (event) =>
          !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(
            event.text ?? '',
          ),
      ),
    ).toBe(true);
    expect(events.at(-1)?.type).toBe('complete');
  });

  it("runs approved bash commands with the user's HOME and PATH from the host", async () => {
    const { workspacePath, agentDir } = await workspace(root);
    const userHome = join(root, 'user-home');
    await mkdir(userHome);
    process.env.PIUI_USER_HOME = userHome;
    process.env.PIUI_USER_PATH = '/usr/bin:/bin:/opt/piui-user/bin';
    const { faux, host, product } = fauxProduct();
    runtime = product;
    const session = await createSession(product, workspacePath, agentDir);
    const toolOutput: string[] = [];
    faux.setResponses([
      publicFauxAssistantMessage(
        publicFauxToolCall('bash', { command: 'printf "%s\\n%s" "$HOME" "$PATH"' }),
        { stopReason: 'toolUse' },
      ),
      (context) => {
        const result = context.messages.at(-1);
        if (result?.role === 'toolResult') {
          for (const part of result.content) if (part.type === 'text') toolOutput.push(part.text);
        }
        return publicFauxAssistantMessage('Checked the environment.');
      },
    ]);
    const events = await collect(
      product.stream(
        turnRequest(session.id, 1, 'Show the environment'),
        new AbortController().signal,
      ),
    );
    expect(events.at(-1)?.type).toBe('complete');
    expect(host.approvals.map((approval) => approval.toolName)).toEqual(['bash']);
    expect(toolOutput.join('')).toBe(
      `${userHome}\n${join(getAgentDir(), 'bin')}:/usr/bin:/bin:/opt/piui-user/bin`,
    );
  });

  it("still reports an external writer that appends during PIUI's own turn", async () => {
    const { workspacePath, agentDir } = await workspace(root);
    const { faux, product } = fauxProduct();
    runtime = product;
    const session = await createSession(product, workspacePath, agentDir);
    faux.setResponses([publicFauxAssistantMessage('First reply.')]);
    await collect(
      product.stream(turnRequest(session.id, 1, 'Hello'), new AbortController().signal),
    );
    const sessionFiles = (await readdir(join(agentDir, 'sessions'), { recursive: true })).filter(
      (name) => name.endsWith('.jsonl'),
    );
    expect(sessionFiles).toHaveLength(1);
    const sessionFile = join(agentDir, 'sessions', sessionFiles[0] ?? '');

    const release = deferred();
    const providerWaiting = deferred();
    faux.setResponses([
      async () => {
        providerWaiting.resolve();
        await release.promise;
        return publicFauxAssistantMessage('Second reply.');
      },
    ]);
    const turn = collect(
      product.stream(turnRequest(session.id, 1, 'Again'), new AbortController().signal),
    );
    await providerWaiting.promise;
    await appendFile(
      sessionFile,
      `${JSON.stringify({ type: 'custom', id: 'intruder', parentId: null, customType: 'other' })}\n`,
    );
    release.resolve();
    expect((await turn).at(-1)).toMatchObject({ type: 'failed', code: 'session-external-change' });
    await expect(
      product.handle(
        productRequest({
          method: 'product.session.rename',
          schemaVersion: 1,
          sessionId: session.id,
          expectedGeneration: 1,
          title: 'Must not be written',
        }),
      ),
    ).rejects.toThrow('session-external-change');
  });
});
