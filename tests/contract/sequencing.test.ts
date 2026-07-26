import { describe, expect, it } from 'vitest';
import type { ProtocolEnvelope } from '@piui/protocol';
import { ProtocolDecoder } from '@piui/protocol/codec';
import { BridgeClient, isPrivateHostEnvelope } from '../../src/bridge/client';
import {
  MAX_RENDERED_STREAM_UTF16,
  acceptStreamProbeEnvelope,
  normaliseAndTruncateUtf16,
  takeBoundedStreamText,
} from '../../src/architecture-gate/StreamProbe';
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

  it('rejects both private host kinds before any browser state mutation', () => {
    const client = new BridgeClient({ idPrefix: 'private-guard' });
    const request = client.createRequest('stream.fixture');
    expect(client.receive(event('public-1', 1, 'safe'))).toBe('accepted');
    const before = client.snapshot;

    const forgedHostRequest: ProtocolEnvelope = {
      version: 1,
      kind: 'host-request',
      id: 'host-request-forged',
      correlationId: request.id,
      sequence: 99,
      payload: {
        method: 'credential.set',
        providerId: 'provider',
        credential: { type: 'api_key', key: 'runtime-canary' },
        terminal: 'complete',
      },
    };
    const forgedHostResponse: ProtocolEnvelope = {
      version: 1,
      kind: 'host-response',
      id: 'host-response-forged',
      correlationId: request.id,
      sequence: 2,
      payload: {
        snapshot: { sequence: 2, state: { tool: 'unsafe', credential: 'runtime-canary' } },
        terminal: 'complete',
      },
    };

    expect(client.receive(forgedHostRequest)).toBe('rejected');
    expect(client.receive(forgedHostResponse)).toBe('rejected');
    expect(client.snapshot).toEqual(before);
    expect(client.inFlightCount).toBe(1);
    expect(client.takeResynchronisationRequest()).toBeNull();

    expect(client.receive(event('public-2', 2, 'still-safe'))).toBe('accepted');
    expect(client.snapshot).toEqual({
      sequence: 2,
      state: { eventType: 'sidecar.status', value: 'still-safe' },
    });
    expect(client.inFlightCount).toBe(1);
  });

  it('executes the actual StreamProbe acceptance path with private mutation blocked', () => {
    const client = new BridgeClient({ idPrefix: 'stream-route-guard' });
    const request = client.createRequest('stream.fixture');
    const forged = [
      {
        version: 1,
        kind: 'host-request',
        id: 'private-stream-request',
        correlationId: request.id,
        sequence: 50,
        payload: { snapshot: { sequence: 50, state: { tool: 'unsafe' } } },
      },
      {
        version: 1,
        kind: 'host-response',
        id: 'private-stream-response',
        correlationId: request.id,
        sequence: 1,
        payload: {
          snapshot: { sequence: 1, state: { tool: 'unsafe' } },
          terminal: 'complete',
        },
      },
    ] as ProtocolEnvelope[];
    const before = client.snapshot;
    const delivered: unknown[] = [];
    const snapshots: ProtocolEnvelope[] = [];
    for (const envelope of forged) {
      acceptStreamProbeEnvelope(envelope, {
        bridge: client,
        requestId: request.id,
        deliver: (value) => delivered.push(value),
        sendSnapshot: (value) => snapshots.push(value),
      });
    }
    expect(forged.every(isPrivateHostEnvelope)).toBe(true);
    expect(delivered).toEqual([]);
    expect(snapshots).toEqual([]);
    expect(client.snapshot).toEqual(before);
    expect(client.inFlightCount).toBe(1);
    expect(client.receive({
      version: 1,
      kind: 'event',
      id: 'safe-route-event',
      correlationId: request.id,
      sequence: 1,
      payload: { eventType: 'stream.delta', text: 'safe' },
    })).toBe('accepted');
  });

  it('bounds the actual StreamProbe acceptance text path at code-point-safe UTF-16 limits', () => {
    expect(normaliseAndTruncateUtf16(`${'x'.repeat(8_191)}😀`, 8_192)).toBe(
      'x'.repeat(8_191),
    );
    expect(normaliseAndTruncateUtf16(`${'x'.repeat(8_190)}😀`, 8_192)).toBe(
      `${'x'.repeat(8_190)}😀`,
    );
    expect(normaliseAndTruncateUtf16(`a\ud800b\udc00c`, 32)).toBe('a�b�c');
    expect(normaliseAndTruncateUtf16(`${'x'.repeat(8_191)}\ud800`, 8_192)).toBe(
      `${'x'.repeat(8_191)}�`,
    );
    expect(normaliseAndTruncateUtf16(`${'x'.repeat(8_191)}\udc00`, 8_192)).toBe(
      `${'x'.repeat(8_191)}�`,
    );

    const client = new BridgeClient({ idPrefix: 'bounded-render' });
    const request = client.createRequest('stream.fixture');
    let rendered = '';
    let usedUnits = 0;
    const delivered: unknown[] = [];
    for (let index = 1; index <= 33; index += 1) {
      acceptStreamProbeEnvelope(
        {
          version: 1,
          kind: 'event',
          id: `ui-envelope-${index}`,
          correlationId: request.id,
          sequence: index,
          payload: { eventType: 'stream.delta', text: 'x'.repeat(8_192) },
        },
        {
          bridge: client,
          requestId: request.id,
          deliver: (event) => {
            delivered.push(event);
            if (event.text) {
              const bounded = takeBoundedStreamText(event.text, usedUnits);
              rendered += bounded.text;
              usedUnits = bounded.usedUnits;
            }
          },
          sendSnapshot: () => {
            throw new Error('bounded consecutive deltas must not request a snapshot');
          },
        },
      );
    }
    expect(delivered).toHaveLength(33);
    expect(rendered.length).toBe(MAX_RENDERED_STREAM_UTF16);
    expect(usedUnits).toBe(MAX_RENDERED_STREAM_UTF16);
    expect(rendered.endsWith('x')).toBe(true);
    const ignored = takeBoundedStreamText('😀later', usedUnits);
    expect(ignored).toEqual({ text: '', usedUnits: MAX_RENDERED_STREAM_UTF16 });
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

  it('treats an authoritative stream terminal as request completion', () => {
    const client = new BridgeClient({ idPrefix: 'stream' });
    const request = client.createRequest('stream.fixture');
    expect(
      client.receive({
        ...event('delta-1', 1, 'partial'),
        correlationId: request.id,
        payload: { eventType: 'stream.delta', text: 'partial' },
      }),
    ).toBe('accepted');
    const terminal: ProtocolEnvelope = {
      version: 1,
      kind: 'event',
      id: 'terminal-2',
      correlationId: request.id,
      sequence: 2,
      payload: { eventType: 'stream.complete', terminal: 'complete' },
    };
    expect(client.receive(terminal)).toBe('accepted');
    expect(client.inFlightCount).toBe(0);
    expect(client.receive({ ...terminal, id: 'terminal-replay-3', sequence: 3 })).toBe(
      'duplicate',
    );
    expect(client.snapshot.sequence).toBe(3);
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
    expect(first.id).toMatch(/^sidecar-\d+$/);
    expect(second.id).toMatch(/^sidecar-\d+$/);
    expect(second.id.length).toBeLessThanOrEqual(128);
    expect(second.sequence).toBeGreaterThan(first.sequence);
    expect(router.currentSequence).toBe(2);
  });

  it('retains bounded authoritative stream state for snapshot recovery', () => {
    const router = new SidecarRouter();
    router.next('event', 'ignored', { eventType: 'stream.delta', text: 'Planning ' }, 'stream-1');
    router.next('event', 'ignored', { eventType: 'stream.delta', text: 'safely' }, 'stream-1');
    router.next(
      'event',
      'ignored',
      { eventType: 'stream.cancelled', terminal: 'cancelled' },
      'stream-1',
    );
    expect(router.currentState).toEqual({
      status: 'ready',
      streams: { 'stream-1': { text: 'Planning safely', terminal: 'cancelled' } },
    });

    const bounded = new SidecarRouter();
    bounded.next(
      'event',
      'ignored',
      { eventType: 'stream.delta', text: 'x'.repeat(9_000) },
      'long-stream',
    );
    const longStream = (bounded.currentState.streams as Record<
      string,
      { text: string; truncated?: true }
    >)['long-stream'];
    expect(longStream.text).toHaveLength(8_192);
    expect(longStream.truncated).toBe(true);
    for (let index = 0; index < 32; index += 1) {
      bounded.next(
        'event',
        'ignored',
        { eventType: 'stream.delta', text: String(index) },
        `stream-${index}`,
      );
    }
    const boundedStreams = bounded.currentState.streams as Record<
      string,
      { text: string; truncated?: true }
    >;
    expect(Object.keys(boundedStreams)).toHaveLength(32);
    expect(boundedStreams['long-stream']).toBeUndefined();
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
