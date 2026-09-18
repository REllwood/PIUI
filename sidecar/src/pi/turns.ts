import type { AdapterTurnEvent, AdapterTurnRequest } from './adapter.js';

export class TurnRegistry {
  #active = new Map<string, AbortController>();
  #terminal = new Map<string, 'stopped' | 'complete'>();

  begin(
    request: AdapterTurnRequest,
    parentSignal: AbortSignal,
  ): Readonly<{ controller: AbortController; nextSequence: () => number }> {
    if (this.#active.has(request.requestId) || this.#terminal.has(request.requestId))
      throw new Error('turn-request-duplicate');
    const controller = new AbortController();
    const abort = () => controller.abort(parentSignal.reason);
    if (parentSignal.aborted) abort();
    else parentSignal.addEventListener('abort', abort, { once: true });
    this.#active.set(request.requestId, controller);
    let sequence = 0;
    return Object.freeze({ controller, nextSequence: () => ++sequence });
  }

  finish(requestId: string, terminal: 'stopped' | 'complete'): void {
    this.#active.delete(requestId);
    this.#terminal.set(requestId, terminal);
    if (this.#terminal.size > 512) {
      const oldest = this.#terminal.keys().next().value;
      if (oldest) this.#terminal.delete(oldest);
    }
  }

  stop(requestId: string): 'stopped' | 'too-late' | 'unknown' {
    const active = this.#active.get(requestId);
    if (active) {
      active.abort('user-stop');
      return 'stopped';
    }
    if (this.#terminal.has(requestId)) return 'too-late';
    return 'unknown';
  }
}

export function normaliseTurnEvent(
  requestId: string,
  sequence: number,
  value: unknown,
): AdapterTurnEvent {
  if (!value || typeof value !== 'object')
    return { requestId, sequence, type: 'failed', code: 'turn-event-invalid' };
  const event = value as Record<string, unknown>;
  const type = event.type;
  if (type === 'message_update' && typeof event.text === 'string')
    return { requestId, sequence, type: 'text', text: event.text.slice(0, 262_144) };
  if (typeof type === 'string' && type.includes('tool'))
    return {
      requestId,
      sequence,
      type: 'tool',
      text: typeof event.toolName === 'string' ? event.toolName.slice(0, 128) : 'Tool activity',
      ...(typeof event.toolCallId === 'string' && /^[A-Za-z0-9._:-]{1,160}$/u.test(event.toolCallId)
        ? { toolCallId: event.toolCallId }
        : {}),
    };
  if (type === 'turn_end' || type === 'agent_end') return { requestId, sequence, type: 'complete' };
  return { requestId, sequence, type: 'started' };
}
