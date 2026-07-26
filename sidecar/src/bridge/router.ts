import type { ProtocolEnvelope } from '@piui/protocol';

export type RouteReply = (envelope: ProtocolEnvelope) => void;

const MAX_STREAM_SNAPSHOTS = 32;
const MAX_STREAM_SNAPSHOT_TEXT = 8_192;
type StreamSnapshot = {
  text: string;
  terminal?: 'complete' | 'cancelled';
  truncated?: true;
};

function normaliseAndTruncateUtf16(value: string, maximumUnits: number): string {
  let normalised = '';
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        normalised += value[index] + value[index + 1];
        index += 1;
      } else normalised += '\ufffd';
    } else if (unit >= 0xdc00 && unit <= 0xdfff) normalised += '\ufffd';
    else normalised += value[index];
  }
  if (normalised.length <= maximumUnits) return normalised;
  let end = maximumUnits;
  const last = normalised.charCodeAt(end - 1);
  const next = normalised.charCodeAt(end);
  if (last >= 0xd800 && last <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) end -= 1;
  return normalised.slice(0, end);
}

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
      const appended = current.text + payload.text;
      const text = normaliseAndTruncateUtf16(appended, MAX_STREAM_SNAPSHOT_TEXT);
      this.#streams.delete(correlationId);
      this.#streams.set(correlationId, {
        ...current,
        text,
        ...(appended.length > MAX_STREAM_SNAPSHOT_TEXT ? { truncated: true as const } : {}),
      });
    } else if (eventType === 'stream.complete' || eventType === 'stream.cancelled') {
      const current = this.#streams.get(correlationId) ?? { text: '' };
      this.#streams.delete(correlationId);
      this.#streams.set(correlationId, {
        ...current,
        terminal: eventType === 'stream.complete' ? 'complete' : 'cancelled',
      });
    }
    if (this.#streams.size > MAX_STREAM_SNAPSHOTS) {
      this.#streams.delete(this.#streams.keys().next().value!);
    }
  }
}
