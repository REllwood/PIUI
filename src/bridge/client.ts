import type { ProtocolEnvelope } from '@piui/protocol';

export type BridgeSnapshot = { sequence: number; state: Readonly<Record<string, unknown>> };

export class BridgeClient {
  #sequence = 0;
  #state: Readonly<Record<string, unknown>> = {};
  #resyncRequested = false;
  #acked = new Set<string>();

  receive(envelope: ProtocolEnvelope): 'accepted' | 'duplicate' | 'stale' | 'gap' {
    if (envelope.kind === 'ack' && envelope.correlationId) {
      if (this.#acked.has(envelope.correlationId)) return 'duplicate';
      this.#acked.add(envelope.correlationId);
    }
    if (envelope.sequence <= this.#sequence) return envelope.sequence === this.#sequence ? 'duplicate' : 'stale';
    if (this.#sequence !== 0 && envelope.sequence !== this.#sequence + 1) {
      this.#resyncRequested = true;
      return 'gap';
    }
    this.#sequence = envelope.sequence;
    this.#state = Object.freeze({ ...this.#state, ...envelope.payload });
    return 'accepted';
  }

  applySnapshot(snapshot: BridgeSnapshot): void {
    if (!Number.isSafeInteger(snapshot.sequence) || snapshot.sequence < this.#sequence) return;
    this.#sequence = snapshot.sequence;
    this.#state = Object.freeze({ ...snapshot.state });
    this.#resyncRequested = false;
  }

  get snapshot(): BridgeSnapshot { return { sequence: this.#sequence, state: this.#state }; }
  takeResynchronisationRequest(): boolean { const value = this.#resyncRequested; this.#resyncRequested = false; return value; }
}
