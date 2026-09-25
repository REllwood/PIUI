// @vitest-environment jsdom

import { act, cleanup, render, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ProductProvider, useProduct, type ProductContextValue } from '../app/ProductContext';
import { productionBridgeStore } from '../bridge/store';
import * as native from '../platform/native';
import { emptyProductSnapshot } from './fixtures';

vi.mock('../platform/native', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../platform/native')>()),
  nativeHostStatus: vi.fn(),
  startLocalHelper: vi.fn(),
  listProductProviders: vi.fn(),
  nativeDiagnosticsSnapshot: vi.fn(),
  listProductSessions: vi.fn(),
  resumeProductSession: vi.fn(),
  inspectProductSession: vi.fn(),
  listProductSettings: vi.fn(),
  listProductResources: vi.fn(),
  listProductChanges: vi.fn(),
  listPendingApprovals: vi.fn(),
  sendNativeNotification: vi.fn(),
  startProductTurn: vi.fn(),
  queueProductFollowUp: vi.fn(),
  createProductSession: vi.fn(),
  saveProductSetting: vi.fn(),
  renameProductSession: vi.fn(),
  inspectWorkspace: vi.fn(),
  authoriseWorkspace: vi.fn(),
  loadTrustedWorkspace: vi.fn(),
}));

const session: native.NativeProductSession = {
  id: 'session-a',
  generation: 2,
  title: 'Existing',
  workspaceId: 'workspace-a',
  writable: true,
  updatedAtUnixMs: 1,
  preview: '',
  messageCount: 0,
};
const nextSession = { ...session, id: 'session-b', generation: 3, title: 'New conversation' };
const setting = (key: string, value: unknown): native.NativeProductSetting => ({
  key,
  value,
  scope: 'project',
  revision: 7,
  origin: 'Current Pi session',
});
const preferences = [
  setting('model.provider', 'chosen'),
  setting('model.id', 'preferred'),
  setting('reasoning.level', 'high'),
];
const provider = (id: string, modelId: string): native.NativeProvider => ({
  id,
  name: id,
  methods: [],
  status: 'connected',
  models: [
    { id: modelId, name: modelId, reasoning: true, acceptsImages: true, contextWindow: 1000 },
  ],
});
const message = (
  id: string,
  role: 'user' | 'assistant',
  text: string,
): native.NativeProductMessage => ({
  id,
  role,
  text,
  kind: 'message',
  timestampUnixMs: 1,
});
const history = [
  message('u1', 'user', 'First task'),
  message('a1', 'assistant', 'First answer'),
  message('u2', 'user', 'Follow-up task'),
  message('a2', 'assistant', 'Second answer'),
];

let product: ProductContextValue | undefined;
let turn: Parameters<typeof native.startProductTurn>[0] | undefined;

function currentProduct() {
  if (!product) throw new Error('Product provider is not mounted');
  return product;
}
function currentTurn() {
  if (!turn) throw new Error('No turn has started');
  return turn;
}
function Probe() {
  product = useProduct();
  return null;
}
async function boot() {
  const mounted = render(
    <ProductProvider
      applicationData={{
        ...native.defaultNativeApplicationData,
        recentWorkspaces: [
          {
            capabilityId: 'workspace-a',
            displayLabel: 'Project',
            trustState: 'trusted',
            workspaceRevision: 1,
            lastOpenedUnixMs: 1,
          },
        ],
      }}
      onPersist={async () => undefined}
    >
      <Probe />
    </ProductProvider>,
  );
  await waitFor(() => expect(currentProduct().settings).toEqual(preferences));
  return mounted;
}
async function queueFollowUp() {
  await act(async () => {
    await currentProduct().send('First task');
  });
  await act(async () => {
    await currentProduct().queue('Follow-up task');
  });
  act(() => {
    currentTurn().onDelta('First answerSecond answer');
  });
}

beforeEach(() => {
  vi.resetAllMocks();
  product = undefined;
  turn = undefined;
  productionBridgeStore.updateLocalFixture(emptyProductSnapshot);
  vi.mocked(native.nativeHostStatus).mockResolvedValue(
    {} as Awaited<ReturnType<typeof native.nativeHostStatus>>,
  );
  vi.mocked(native.startLocalHelper).mockResolvedValue({ running: true, failed: false } as Awaited<
    ReturnType<typeof native.startLocalHelper>
  >);
  vi.mocked(native.listProductProviders).mockResolvedValue([
    provider('first', 'default'),
    provider('chosen', 'preferred'),
  ]);
  vi.mocked(native.nativeDiagnosticsSnapshot).mockResolvedValue({
    checks: [],
    environment: [],
    logs: [],
    helperFailure: null,
  });
  vi.mocked(native.listProductSessions).mockResolvedValue([session]);
  vi.mocked(native.resumeProductSession).mockResolvedValue(session);
  vi.mocked(native.inspectProductSession).mockResolvedValue([]);
  vi.mocked(native.listProductSettings).mockResolvedValue(preferences);
  vi.mocked(native.listProductResources).mockResolvedValue([]);
  vi.mocked(native.listProductChanges).mockResolvedValue([]);
  vi.mocked(native.listPendingApprovals).mockResolvedValue([]);
  vi.mocked(native.sendNativeNotification).mockResolvedValue(true);
  vi.mocked(native.queueProductFollowUp).mockResolvedValue({ queueId: 'queue-1', number: 1 });
  vi.mocked(native.createProductSession).mockResolvedValue(nextSession);
  vi.mocked(native.startProductTurn).mockImplementation(async (request) => {
    turn = request;
    request.onStarted('request-a');
    return 'request-a';
  });
});

afterEach(cleanup);

describe('production conversation continuity', () => {
  it('does not rewrite preferences that the new Pi session already inherited', async () => {
    await boot();
    await act(async () => {
      expect(await currentProduct().createSession()).toBe(true);
    });
    expect(native.saveProductSetting).not.toHaveBeenCalled();
    expect(currentProduct().snapshot.activeSessionId).toBe('session-b');
  });

  it('starts with the selected model and restores thinking using the new setting revision', async () => {
    await boot();
    vi.mocked(native.listProductSettings).mockResolvedValue(
      preferences.map((value) =>
        value.key === 'reasoning.level' ? { ...value, value: 'medium', revision: 9 } : value,
      ),
    );
    vi.mocked(native.saveProductSetting).mockResolvedValue({
      ...setting('reasoning.level', 'high'),
      revision: 10,
    });
    await act(async () => {
      expect(await currentProduct().createSession()).toBe(true);
    });
    expect(native.createProductSession).toHaveBeenCalledWith(
      expect.objectContaining({ providerId: 'chosen', modelId: 'preferred' }),
    );
    expect(native.saveProductSetting).toHaveBeenCalledWith('session-b', 3, {
      key: 'reasoning.level',
      value: 'high',
      scope: 'project',
      expectedRevision: 9,
    });
    expect(currentProduct().settings.find((value) => value.key === 'reasoning.level')?.value).toBe(
      'high',
    );
  });

  it('keeps a created conversation active and reports an unconfirmed preference save', async () => {
    await boot();
    vi.mocked(native.listProductSettings).mockResolvedValue(
      preferences.map((value) =>
        value.key === 'reasoning.level' ? { ...value, value: 'medium' } : value,
      ),
    );
    vi.mocked(native.saveProductSetting).mockRejectedValue(new Error('setting-save-conflict'));
    await act(async () => {
      expect(await currentProduct().createSession()).toBe(true);
    });
    expect(currentProduct().snapshot.activeSessionId).toBe('session-b');
    expect(currentProduct().settings.find((value) => value.key === 'reasoning.level')?.value).toBe(
      'medium',
    );
    expect(currentProduct().snapshot.diagnostics).toContainEqual(
      expect.objectContaining({ id: 'new-session-preferences', status: 'warning' }),
    );
  });

  it('reconstructs queued user messages and separate assistant replies from Pi history', async () => {
    await boot();
    await queueFollowUp();
    vi.mocked(native.inspectProductSession).mockResolvedValue(history);
    act(() => {
      currentTurn().onComplete('complete');
    });
    await waitFor(() =>
      expect(currentProduct().snapshot.messages.map((value) => value.markdown)).toEqual(
        history.map((value) => value.text),
      ),
    );
    expect(currentProduct().snapshot.queue).toEqual([]);
  });

  it('preserves visible text and reports a failed history inspection', async () => {
    await boot();
    await queueFollowUp();
    vi.mocked(native.inspectProductSession).mockRejectedValue(new Error('inspection-unavailable'));
    act(() => {
      currentTurn().onComplete('complete');
    });
    await waitFor(() =>
      expect(currentProduct().snapshot.diagnostics).toContainEqual(
        expect.objectContaining({ id: 'transcript-refresh', status: 'warning' }),
      ),
    );
    expect(currentProduct().snapshot.messages.at(-1)?.markdown).toBe('First answerSecond answer');
  });

  it.each(['cancelled', 'failed'] as const)(
    'preserves the partial transcript after a %s turn',
    async (terminal) => {
      await boot();
      await queueFollowUp();
      vi.mocked(native.inspectProductSession).mockClear();
      act(() => {
        if (terminal === 'failed') currentTurn().onFailed('provider-turn-failed');
        else currentTurn().onComplete('cancelled');
      });
      expect(native.inspectProductSession).not.toHaveBeenCalled();
      expect(currentProduct().snapshot.messages.at(-1)?.markdown).toBe('First answerSecond answer');
      expect(currentProduct().snapshot.messages.at(-1)?.status).toBe(
        terminal === 'failed' ? 'failed' : 'partial',
      );
    },
  );

  it('discards an inspection result that arrives after another turn has started', async () => {
    await boot();
    await queueFollowUp();
    let finishInspection: ((value: readonly native.NativeProductMessage[]) => void) | undefined;
    vi.mocked(native.inspectProductSession).mockImplementation(
      () =>
        new Promise((resolve) => {
          finishInspection = resolve;
        }),
    );
    act(() => {
      currentTurn().onComplete('complete');
    });
    await waitFor(() => expect(finishInspection).toBeTypeOf('function'));
    await act(async () => {
      await currentProduct().send('A newer task');
    });
    await act(async () => {
      finishInspection?.(history);
    });
    expect(currentProduct().snapshot.messages.at(-2)?.markdown).toBe('A newer task');
    expect(currentProduct().snapshot.turnStatus).toBe('streaming');
  });

  it('leaves the store untouched when an approval poll finds nothing new', async () => {
    vi.mocked(native.listPendingApprovals).mockResolvedValue([
      {
        approvalId: 'approval-1',
        decisionId: 'decision-1',
        revision: 1,
        state: 'awaiting',
        verb: 'Run command',
        target: 'pnpm test',
        risk: 'routine',
        scopeIds: [],
        expiresInMs: 60_000,
        subject: { label: 'Command', text: 'pnpm test', truncated: false },
      },
    ]);
    await boot();
    await waitFor(() => expect(currentProduct().snapshot.approvals).toHaveLength(1));
    const before = productionBridgeStore.getSnapshot().product;
    const polls = vi.mocked(native.listPendingApprovals).mock.calls.length;
    await waitFor(
      () =>
        expect(vi.mocked(native.listPendingApprovals).mock.calls.length).toBeGreaterThan(
          polls + 1,
        ),
      { timeout: 2_500 },
    );
    expect(productionBridgeStore.getSnapshot().product).toBe(before);
  });

  it('applies a burst of streamed text as one transcript update', async () => {
    await boot();
    await act(async () => {
      await currentProduct().send('Stream a reply');
    });
    const transcripts = new Set<unknown>();
    const unsubscribe = productionBridgeStore.subscribe(() => {
      transcripts.add(productionBridgeStore.getSnapshot().product.messages);
    });
    act(() => {
      currentTurn().onDelta('Planning ');
      currentTurn().onDelta('a safe ');
      currentTurn().onDelta('change');
    });
    expect(transcripts.size).toBe(0);
    await waitFor(() =>
      expect(currentProduct().snapshot.messages.at(-1)?.markdown).toBe('Planning a safe change'),
    );
    unsubscribe();
    expect(transcripts.size).toBe(1);
  });

  it('records a started tool as running work until it reports an outcome', async () => {
    await boot();
    await act(async () => {
      await currentProduct().send('Run the checks');
    });
    act(() => {
      currentTurn().onTool('tool-1', 'bash', 'started');
    });
    expect(currentProduct().snapshot.activity).toContainEqual(
      expect.objectContaining({ id: 'activity-tool-1', state: 'running' }),
    );
    expect(currentProduct().snapshot.turnStatus).toBe('tool-running');
    act(() => {
      currentTurn().onTool('tool-1', 'bash', 'complete');
    });
    expect(currentProduct().snapshot.activity).toContainEqual(
      expect.objectContaining({ id: 'activity-tool-1', state: 'complete' }),
    );
  });

  it('asks for the project to be trusted again and re-lists sessions once it is', async () => {
    await boot();
    vi.mocked(native.renameProductSession).mockRejectedValue('session-workspace-untrusted');
    await act(async () => {
      await expect(currentProduct().renameSession('session-a', 'Renamed')).rejects.toBe(
        'session-workspace-untrusted',
      );
    });
    expect(currentProduct().snapshot.workspace?.trust).toBe('untrusted');

    const trustedSummary: native.NativeWorkspaceSummary = {
      workspaceId: 'workspace-a',
      displayLabel: 'Project',
      revision: 2,
      trustState: 'trusted',
      resourceState: 'loaded',
    };
    // The host moved the revision while the project was untrusted.
    vi.mocked(native.inspectWorkspace).mockResolvedValue({
      ...trustedSummary,
      revision: 3,
      trustState: 'untrusted',
      resourceState: 'not-loaded',
    });
    vi.mocked(native.authoriseWorkspace).mockResolvedValue(trustedSummary);
    vi.mocked(native.loadTrustedWorkspace).mockResolvedValue(trustedSummary);
    vi.mocked(native.listProductSessions).mockClear();
    vi.mocked(native.listProductSessions).mockResolvedValue([{ ...session, generation: 5 }]);
    await act(async () => {
      await currentProduct().trustProject();
    });
    expect(native.authoriseWorkspace).toHaveBeenCalledWith('workspace-a', 3);
    expect(native.listProductSessions).toHaveBeenCalledWith('workspace-a', 2);
    expect(currentProduct().snapshot.workspace?.trust).toBe('trusted');
    expect(currentProduct().snapshot.sessions).toContainEqual(
      expect.objectContaining({ id: 'session-a', generation: 5, status: 'active' }),
    );
  });

  it('offers Reconnect with plain-English copy when the host stream is interrupted', async () => {
    await boot();
    await act(async () => {
      await currentProduct().send('Keep going');
    });
    act(() => {
      currentTurn().onFailed('host-stream-interrupted');
    });
    expect(currentProduct().snapshot.connection).toBe('restart-offered');
    expect(currentProduct().snapshot.messages.at(-1)?.markdown).toBe(
      'The connection to Pi was interrupted before the reply finished. Reconnect to Pi, then try again. Your message remains in the conversation.',
    );
  });

  it('retires pending inspection and turn callbacks when the provider unmounts', async () => {
    const mounted = await boot();
    await queueFollowUp();
    let finishInspection: ((value: readonly native.NativeProductMessage[]) => void) | undefined;
    vi.mocked(native.inspectProductSession).mockImplementation(
      () =>
        new Promise((resolve) => {
          finishInspection = resolve;
        }),
    );
    act(() => {
      currentTurn().onComplete('complete');
    });
    await waitFor(() => expect(finishInspection).toBeTypeOf('function'));
    mounted.unmount();
    const before = productionBridgeStore.getSnapshot().product;
    await act(async () => {
      finishInspection?.(history);
      currentTurn().onDelta('Unexpected late text');
    });
    expect(productionBridgeStore.getSnapshot().product.messages).toBe(before.messages);
  });
});
