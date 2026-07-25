import type { ProtocolEnvelope } from '@piui/protocol';

export type BridgeSnapshot = {
  sequence: number;
  state: Readonly<Record<string, unknown>>;
};

export type BridgeClientOptions = {
  idPrefix?: string;
  maxInFlight?: number;
  requestTimeoutMs?: number;
  now?: () => number;
};

type PendingRequest = { deadline: number; method: string };

export class BridgeClient {
  #incomingSequence = 0;
  #outgoingSequence = 0;
  #requestCounter = 0;
  #state: Readonly<Record<string, unknown>> = {};
  #resynchronisationNeeded = false;
  #resynchronisationIssued = false;
  #acknowledged = new Set<string>();
  #acknowledgementOrder: string[] = [];
  #inFlight = new Map<string, PendingRequest>();
  readonly #idPrefix: string;
  readonly #maxInFlight: number;
  readonly #requestTimeoutMs: number;
  readonly #now: () => number;

  constructor(options: BridgeClientOptions = {}) {
    this.#idPrefix = options.idPrefix ?? `web-${globalThis.crypto.randomUUID()}`;
    this.#maxInFlight = options.maxInFlight ?? 128;
    this.#requestTimeoutMs = options.requestTimeoutMs ?? 5_000;
    this.#now = options.now ?? Date.now;
  }

  createRequest(
    method: string,
    payload: Readonly<Record<string, unknown>> = {},
  ): ProtocolEnvelope {
    if (this.#inFlight.size >= this.#maxInFlight) throw new Error('bridge-capacity-exceeded');
    const id = `${this.#idPrefix}-${++this.#requestCounter}`;
    const request: ProtocolEnvelope = {
      version: 1,
      kind: 'request',
      id,
      sequence: ++this.#outgoingSequence,
      payload: { ...payload, method },
    };
    this.#inFlight.set(id, {
      deadline: this.#now() + this.#requestTimeoutMs,
      method,
    });
    return request;
  }

  createCancellation(correlationId: string): ProtocolEnvelope {
    if (this.#inFlight.size >= this.#maxInFlight) throw new Error('bridge-capacity-exceeded');
    const id = `${this.#idPrefix}-${++this.#requestCounter}`;
    const cancellation: ProtocolEnvelope = {
      version: 1,
      kind: 'cancel',
      id,
      correlationId,
      sequence: ++this.#outgoingSequence,
      payload: {},
    };
    this.#inFlight.set(id, {
      deadline: this.#now() + this.#requestTimeoutMs,
      method: 'cancel',
    });
    return cancellation;
  }

  receive(envelope: ProtocolEnvelope): 'accepted' | 'duplicate' | 'stale' | 'gap' {
    if (envelope.sequence <= this.#incomingSequence) {
      return envelope.sequence === this.#incomingSequence ? 'duplicate' : 'stale';
    }
    if (this.#incomingSequence !== 0 && envelope.sequence !== this.#incomingSequence + 1) {
      this.#resynchronisationNeeded = true;
      return 'gap';
    }

    const completesRequest =
      envelope.kind === 'ack' ||
      envelope.kind === 'response' ||
      (envelope.kind === 'event' &&
        (envelope.payload.terminal === 'complete' || envelope.payload.terminal === 'cancelled'));
    if (completesRequest && envelope.correlationId) {
      if (this.#acknowledged.has(envelope.correlationId)) {
        this.#incomingSequence = envelope.sequence;
        return 'duplicate';
      }
      this.#rememberAcknowledgement(envelope.correlationId);
      this.#inFlight.delete(envelope.correlationId);
    }

    this.#incomingSequence = envelope.sequence;
    this.#state = Object.freeze({ ...this.#state, ...envelope.payload });
    return 'accepted';
  }

  takeResynchronisationRequest(): ProtocolEnvelope | null {
    if (!this.#resynchronisationNeeded || this.#resynchronisationIssued) return null;
    this.#resynchronisationIssued = true;
    return this.createRequest('snapshot', { afterSequence: this.#incomingSequence });
  }

  applySnapshot(snapshot: BridgeSnapshot, correlationId?: string): boolean {
    if (
      !Number.isSafeInteger(snapshot.sequence) ||
      snapshot.sequence < this.#incomingSequence ||
      (correlationId !== undefined && this.#acknowledged.has(correlationId))
    ) {
      return false;
    }
    if (correlationId !== undefined) {
      this.#rememberAcknowledgement(correlationId);
      this.#inFlight.delete(correlationId);
    }
    this.#incomingSequence = snapshot.sequence;
    this.#state = Object.freeze({ ...snapshot.state });
    this.#resynchronisationNeeded = false;
    this.#resynchronisationIssued = false;
    return true;
  }

  expireRequests(now = this.#now()): readonly string[] {
    const expired: string[] = [];
    for (const [id, pending] of this.#inFlight) {
      if (pending.deadline <= now) {
        expired.push(id);
        this.#inFlight.delete(id);
      }
    }
    return expired;
  }

  get snapshot(): BridgeSnapshot {
    return { sequence: this.#incomingSequence, state: this.#state };
  }

  get inFlightCount(): number {
    return this.#inFlight.size;
  }

  #rememberAcknowledgement(id: string): void {
    this.#acknowledged.add(id);
    this.#acknowledgementOrder.push(id);
    if (this.#acknowledgementOrder.length > 512) {
      const oldest = this.#acknowledgementOrder.shift();
      if (oldest) this.#acknowledged.delete(oldest);
    }
  }
}
