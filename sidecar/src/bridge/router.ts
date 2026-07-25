import type { ProtocolEnvelope } from '@piui/protocol';

export type RouteReply = (envelope: ProtocolEnvelope) => void;

type StreamSnapshot = { text: string; terminal?: 'complete' | 'cancelled' };

export class SidecarRouter {
  #sequence = 1;
  #seen = new Map<string, ProtocolEnvelope>();
  #streams = new Map<string, StreamSnapshot>();

  next(kind: ProtocolEnvelope['kind'], _suggestedId: string, payload: Record<string, unknown>, correlationId?: string): ProtocolEnvelope {
    const sequence = this.#sequence++;
    if (kind === 'event' && correlationId) this.#recordStreamEvent(correlationId, payload);
    return {
      version: 1,
      kind,
      id: `sidecar-${sequence}`,
      sequence,
      payload,
      ...(correlationId ? { correlationId } : {}),
    };
  }

  get currentSequence(): number {
    return this.#sequence - 1;
  }

  get currentState(): Readonly<Record<string, unknown>> {
    return {
      status: 'ready',
      streams: Object.fromEntries(
        [...this.#streams].map(([requestId, stream]) => [requestId, { ...stream }]),
      ),
    };
  }

  idempotent(request: ProtocolEnvelope, create: () => ProtocolEnvelope): ProtocolEnvelope {
    const prior = this.#seen.get(request.id);
    if (prior) {
      const sequence = this.#sequence++;
      return {
        ...prior,
        id: `sidecar-${sequence}`,
        sequence,
      };
    }
    const reply = create();
    this.#seen.set(request.id, reply);
    if (this.#seen.size > 512) this.#seen.delete(this.#seen.keys().next().value!);
    return reply;
  }

  #recordStreamEvent(correlationId: string, payload: Record<string, unknown>): void {
    const eventType = payload.eventType;
    if (eventType === 'stream.delta' && typeof payload.text === 'string') {
      const current = this.#streams.get(correlationId) ?? { text: '' };
      this.#streams.delete(correlationId);
      this.#streams.set(correlationId, { ...current, text: current.text + payload.text });
    } else if (eventType === 'stream.complete' || eventType === 'stream.cancelled') {
      const current = this.#streams.get(correlationId) ?? { text: '' };
      this.#streams.delete(correlationId);
      this.#streams.set(correlationId, {
        ...current,
        terminal: eventType === 'stream.complete' ? 'complete' : 'cancelled',
      });
    }
    if (this.#streams.size > 128) this.#streams.delete(this.#streams.keys().next().value!);
  }
}
