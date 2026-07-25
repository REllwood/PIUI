import type { ProtocolEnvelope } from '@piui/protocol';

export type RouteReply = (envelope: ProtocolEnvelope) => void;

export class SidecarRouter {
  #sequence = 1;
  #replay = 0;
  #seen = new Map<string, ProtocolEnvelope>();

  next(kind: ProtocolEnvelope['kind'], id: string, payload: Record<string, unknown>, correlationId?: string): ProtocolEnvelope {
    return { version: 1, kind, id, sequence: this.#sequence++, payload, ...(correlationId ? { correlationId } : {}) };
  }

  get currentSequence(): number {
    return this.#sequence - 1;
  }

  idempotent(request: ProtocolEnvelope, create: () => ProtocolEnvelope): ProtocolEnvelope {
    const prior = this.#seen.get(request.id);
    if (prior) {
      return {
        ...prior,
        id: `replay-${++this.#replay}`,
        sequence: this.#sequence++,
      };
    }
    const reply = create();
    this.#seen.set(request.id, reply);
    if (this.#seen.size > 512) this.#seen.delete(this.#seen.keys().next().value!);
    return reply;
  }
}
