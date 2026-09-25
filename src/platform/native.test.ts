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
import { MAX_PENDING_TURN_EVENTS, TURN_TERMINAL_TIMEOUT_MS, startProductTurn } from './native';

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
