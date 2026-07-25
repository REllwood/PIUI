import type { ProtocolEnvelope } from '@piui/protocol';

export type RouteReply = (envelope: ProtocolEnvelope) => void;

export class SidecarRouter {
  #sequence = 1;
  #seen = new Map<string, ProtocolEnvelope>();

  next(kind: ProtocolEnvelope['kind'], _suggestedId: string, payload: Record<string, unknown>, correlationId?: string): ProtocolEnvelope {
    const sequence = this.#sequence++;
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
}
