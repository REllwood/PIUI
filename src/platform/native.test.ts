import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

type Handler = (event: { payload: unknown }) => void;

const bridge = vi.hoisted(() => ({
  handler: undefined as Handler | undefined,
  unlisten: vi.fn(),
  onStart: undefined as ((requestId: string) => void) | undefined,
}));

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async (_event: string, handler: Handler) => {
    bridge.handler = handler;
    return bridge.unlisten;
  }),
}));

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(async (command: string, args?: { requestData?: { requestId?: string } }) => {
    if (command === 'product_turn_start') bridge.onStart?.(args?.requestData?.requestId ?? '');
    return undefined;
  }),
}));

import { invoke } from '@tauri-apps/api/core';
import {
  MAX_PENDING_TURN_EVENTS,
  TURN_TERMINAL_TIMEOUT_MS,
  listPendingApprovals,
  startProductTurn,
} from './native';

function hostApproval(extra: Record<string, unknown> = {}) {
  return {
    approvalId: 'approval-1',
    decisionId: 'decision-1',
    revision: 1,
    state: 'awaiting',
    verb: 'Run command',
    target: 'Project',
    risk: 'routine',
    scopes: [],
    expiresInMs: 60_000,
    ...extra,
  };
}

describe('approval subject', () => {
  it('reads a missing or null subject as no subject', async () => {
    vi.mocked(invoke).mockResolvedValueOnce([hostApproval(), hostApproval({ subject: null })]);
    const approvals = await listPendingApprovals();
    expect(approvals.map((approval) => approval.subject)).toEqual([null, null]);
  });

  it('keeps a well-formed subject as plain data', async () => {
    const subject = { label: 'Command', text: 'pnpm test', truncated: false };
    vi.mocked(invoke).mockResolvedValueOnce([hostApproval({ subject })]);
    expect((await listPendingApprovals())[0]?.subject).toEqual(subject);
  });

  it.each([
    ['an unknown label', { label: 'Script', text: 'x', truncated: false }],
    ['text that is not a string', { label: 'Command', text: 42, truncated: false }],
    ['text past the bound', { label: 'Command', text: 'x'.repeat(2_001), truncated: true }],
    ['a missing truncation flag', { label: 'File', text: 'README.md' }],
    ['a non-object subject', 'pnpm test'],
  ])('rejects %s like any other malformed approval', async (_case, subject) => {
    vi.mocked(invoke).mockResolvedValueOnce([hostApproval({ subject })]);
    await expect(listPendingApprovals()).rejects.toThrow('approval-response-invalid');
  });
});

function emit(requestId: string, payload: Record<string, unknown>) {
  bridge.handler?.({ payload: { correlationId: requestId, payload } });
}

function callbacks() {
  return {
    onStarted: vi.fn(),
    onDelta: vi.fn(),
    onTool: vi.fn(),
    onFailed: vi.fn(),
    onComplete: vi.fn(),
  };
}

const turn = { sessionId: 'session-a', generation: 1, text: 'Hello' };

beforeEach(() => {
  bridge.handler = undefined;
  bridge.onStart = undefined;
  bridge.unlisten.mockReset();
  vi.mocked(invoke).mockClear();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('product turn listener', () => {
  it('replays events that arrive before the host acknowledges the turn', async () => {
    const handlers = callbacks();
    bridge.onStart = (requestId) => {
      emit(requestId, { eventType: 'stream.delta', text: 'Early ' });
      emit(requestId, { eventType: 'stream.complete' });
      emit(requestId, { eventType: 'stream.delta', text: 'after the end' });
    };
    await startProductTurn({ ...turn, ...handlers });
    expect(handlers.onDelta).toHaveBeenCalledTimes(1);
    expect(handlers.onDelta).toHaveBeenCalledWith('Early ');
    expect(handlers.onComplete).toHaveBeenCalledWith('complete');
    expect(bridge.unlisten).toHaveBeenCalledTimes(1);
  });

  it('reports a failed turn instead of silently dropping early events past the bound', async () => {
    const handlers = callbacks();
    let requestId = '';
    bridge.onStart = (id) => {
      requestId = id;
      for (let index = 0; index <= MAX_PENDING_TURN_EVENTS; index += 1) {
        emit(id, { eventType: 'stream.delta', text: 'x' });
      }
    };
    await startProductTurn({ ...turn, ...handlers });
    expect(handlers.onFailed).toHaveBeenCalledWith('turn-events-overflowed');
    expect(handlers.onDelta).not.toHaveBeenCalled();
    expect(bridge.unlisten).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledWith('product_turn_stop', { requestData: { requestId } });
  });

  it('fails and stops listening when no terminal event arrives before the deadline', async () => {
    vi.useFakeTimers();
    const handlers = callbacks();
    let requestId = '';
    bridge.onStart = (id) => {
      requestId = id;
    };
    await startProductTurn({ ...turn, ...handlers });
    vi.advanceTimersByTime(TURN_TERMINAL_TIMEOUT_MS - 1);
    expect(handlers.onFailed).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(handlers.onFailed).toHaveBeenCalledWith('turn-terminal-timeout');
    expect(bridge.unlisten).toHaveBeenCalledTimes(1);
    emit(requestId, { eventType: 'stream.complete' });
    expect(handlers.onComplete).not.toHaveBeenCalled();
  });

  it('clears the deadline and unlistens once the turn completes', async () => {
    vi.useFakeTimers();
    const handlers = callbacks();
    let requestId = '';
    bridge.onStart = (id) => {
      requestId = id;
    };
    await startProductTurn({ ...turn, ...handlers });
    emit(requestId, { eventType: 'stream.failed', code: 'provider-model-unavailable' });
    vi.advanceTimersByTime(TURN_TERMINAL_TIMEOUT_MS);
    expect(handlers.onFailed).toHaveBeenCalledTimes(1);
    expect(handlers.onFailed).toHaveBeenCalledWith('provider-model-unavailable');
    expect(bridge.unlisten).toHaveBeenCalledTimes(1);
  });
});
