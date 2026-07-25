import { describe, expect, it } from 'vitest';
import type { ProtocolEnvelope } from '@piui/protocol';
import { ProtocolDecoder } from '@piui/protocol/codec';
import { BridgeClient } from '../../src/bridge/client';
import { SidecarRouter } from '../../sidecar/src/bridge/router';

const event = (id: string, sequence: number, value: string): ProtocolEnvelope => ({
  version: 1,
  kind: 'event',
  id,
  sequence,
  payload: { eventType: 'sidecar.status', value },
});

describe('correlation and sequencing', () => {
  it('preserves acknowledged state and requests one bounded resynchronisation after a gap', () => {
    const client = new BridgeClient({ idPrefix: 'test' });
    expect(client.receive(event('a', 1, 'one'))).toBe('accepted');
    expect(client.receive(event('a', 1, 'bad'))).toBe('duplicate');
    expect(client.receive(event('old', 0, 'bad'))).toBe('stale');
    expect(client.receive(event('gap', 3, 'bad'))).toBe('gap');
    expect(client.snapshot).toEqual({
      sequence: 1,
      state: { eventType: 'sidecar.status', value: 'one' },
    });

    const resynchronise = client.takeResynchronisationRequest();
    expect(resynchronise?.payload).toEqual({ method: 'snapshot', afterSequence: 1 });
    expect(client.takeResynchronisationRequest()).toBeNull();
    expect(
      client.applySnapshot(
        { sequence: 3, state: { value: 'snapshot' } },
        resynchronise?.id,
      ),
    ).toBe(true);
    expect(client.inFlightCount).toBe(0);
    expect(client.snapshot).toEqual({ sequence: 3, state: { value: 'snapshot' } });
    expect(
      client.applySnapshot(
        { sequence: 4, state: { value: 'replayed' } },
        resynchronise?.id,
      ),
    ).toBe(false);
    expect(client.applySnapshot({ sequence: 2, state: { value: 'stale' } })).toBe(false);
  });

  it('creates unique monotonic requests and expires bounded in-flight work', () => {
    let now = 1_000;
    const client = new BridgeClient({
      idPrefix: 'window-1',
      maxInFlight: 2,
      requestTimeoutMs: 50,
      now: () => now,
    });
    const first = client.createRequest('status');
    const second = client.createRequest('snapshot');
    expect([first.id, second.id]).toEqual(['window-1-1', 'window-1-2']);
    expect([first.sequence, second.sequence]).toEqual([1, 2]);
    expect(() => client.createCancellation(first.id)).toThrow('bridge-capacity-exceeded');
    now = 1_050;
    expect(client.expireRequests()).toEqual(['window-1-1', 'window-1-2']);
    expect(client.inFlightCount).toBe(0);
  });

  it('acknowledges a request idempotently without advancing on a duplicate', () => {
    const client = new BridgeClient({ idPrefix: 'ack' });
    const request = client.createRequest('status');
    expect(client.receive(event('state-1', 1, 'ready'))).toBe('accepted');
    const response: ProtocolEnvelope = {
      version: 1,
      kind: 'response',
      id: 'response-1',
      correlationId: request.id,
      sequence: 2,
      payload: { status: 'ready' },
    };
    expect(client.receive(response)).toBe('accepted');
    expect(client.inFlightCount).toBe(0);
    expect(client.receive(response)).toBe('duplicate');
    expect(client.snapshot.sequence).toBe(2);
  });

  it('returns one idempotent sidecar response for a repeated request', () => {
    const router = new SidecarRouter();
    const request = {
      version: 1,
      kind: 'request',
      id: 'r1',
      sequence: 1,
      payload: { method: 'status' },
    } as ProtocolEnvelope;
    const first = router.idempotent(request, () =>
      router.next('response', 'reply', { ok: true }, request.id),
    );
    const second = router.idempotent(request, () =>
      router.next('response', 'wrong', {}, request.id),
    );
    expect(second.payload).toEqual(first.payload);
    expect(second.correlationId).toBe(first.correlationId);
    expect(second.id).not.toBe(first.id);
    expect(second.sequence).toBeGreaterThan(first.sequence);
    expect(router.currentSequence).toBe(2);
  });

  it('replays a completed request through the real decoder without reusing an envelope id', () => {
    const decoder = new ProtocolDecoder();
    const router = new SidecarRouter();
    const line = `${JSON.stringify({
      version: 1,
      kind: 'request',
      id: 'repeat-status',
      sequence: 1,
      payload: { method: 'status' },
    })}\n`;
    const firstRequest = decoder.decode(line);
    const firstReply = router.idempotent(firstRequest, () =>
      router.next('response', 'status-reply', { status: 'ready' }, firstRequest.id),
    );
    decoder.acknowledge(firstRequest.id);
    const replayRequest = decoder.decode(line);
    const replayReply = router.idempotent(replayRequest, () => {
      throw new Error('completed request effect ran twice');
    });
    expect(replayReply.payload).toEqual(firstReply.payload);
    expect(replayReply.id).not.toBe(firstReply.id);
  });
});
