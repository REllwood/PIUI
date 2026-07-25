import { describe, expect, it } from 'vitest';
import type { ProtocolEnvelope } from '@piui/protocol';
import { BridgeClient } from '../../src/bridge/client';
import { SidecarRouter } from '../../sidecar/src/bridge/router';
const event = (id: string, sequence: number, value: string): ProtocolEnvelope => ({ version: 1, kind: 'event', id, sequence, payload: { eventType: 'sidecar.status', value } });
describe('correlation and sequencing', () => {
  it('preserves acknowledged state through duplicate, stale and one gap', () => { const client = new BridgeClient(); expect(client.receive(event('a', 1, 'one'))).toBe('accepted'); expect(client.receive(event('a', 1, 'bad'))).toBe('duplicate'); expect(client.receive(event('old', 0, 'bad'))).toBe('stale'); expect(client.receive(event('gap', 3, 'bad'))).toBe('gap'); expect(client.snapshot).toEqual({ sequence: 1, state: { eventType: 'sidecar.status', value: 'one' } }); expect(client.takeResynchronisationRequest()).toBe(true); expect(client.takeResynchronisationRequest()).toBe(false); client.applySnapshot({ sequence: 3, state: { value: 'snapshot' } }); expect(client.snapshot.state.value).toBe('snapshot'); });
  it('returns one idempotent response for a repeated request', () => { const router = new SidecarRouter(); const request = { version: 1, kind: 'request', id: 'r1', sequence: 1, payload: { method: 'status' } } as ProtocolEnvelope; const first = router.idempotent(request, () => router.next('response', 'reply', { ok: true }, request.id)); const second = router.idempotent(request, () => router.next('response', 'wrong', {}, request.id)); expect(second).toEqual(first); });
});
