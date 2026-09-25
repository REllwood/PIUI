import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ProtocolDecoder, encodeEnvelope } from '../src/codec';
import { PROTOCOL_LIMITS } from '../src/index';
import type { ProtocolEnvelope } from '../src/types';
import { jsonDepth } from '../src/validate';

const fixtureRoot = resolve(import.meta.dirname, '../fixtures');

function fixtureLines(name: string): Buffer[] {
  const raw = readFileSync(resolve(fixtureRoot, name));
  if (name === 'invalid-oversized.jsonl') {
    const directive = JSON.parse(raw.toString('utf8'));
    return [Buffer.from(`${JSON.stringify({ value: 'x'.repeat(directive.bytes) })}\n`)];
  }
  const text = raw.toString('utf8');
  if (!text.endsWith('\n')) return [raw];
  return text.slice(0, -1).split('\n').map((line) => Buffer.from(`${line}\n`));
}

function eventEnvelope(id: string, payload: Record<string, unknown> = { eventType: 'sidecar.status', status: 'ready' }): ProtocolEnvelope {
  return { version: 1, kind: 'event', id, sequence: 1, payload };
}

function line(value: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
}

describe('private protocol codec', () => {
  const divergenceCases = JSON.parse(readFileSync(resolve(fixtureRoot, 'divergence-verdicts.json'), 'utf8')) as Array<{
    name: string;
    valid: boolean;
    line?: string;
    file?: string;
  }>;

  for (const fixture of divergenceCases) {
    it(`shared verdict: ${fixture.name}`, () => {
      const bytes = fixture.file ? readFileSync(resolve(fixtureRoot, fixture.file)) : Buffer.from(fixture.line ?? '', 'utf8');
      const decode = () => new ProtocolDecoder().decode(bytes);
      if (fixture.valid) expect(decode).not.toThrow();
      else expect(decode).toThrow();
    });
  }

  for (const name of readdirSync(fixtureRoot).filter((file) => file.endsWith('.jsonl')).sort()) {
    it(`${name} has the expected outcome`, () => {
      const decode = () => {
        const decoder = new ProtocolDecoder();
        return fixtureLines(name).map((line) => decoder.decode(line));
      };
      if (name.startsWith('valid-')) expect(decode).not.toThrow();
      else expect(decode).toThrow();
    });
  }

  it('preserves an unknown event only as redacted diagnostics', () => {
    const decoder = new ProtocolDecoder();
    const event = decoder.decode(readFileSync(resolve(fixtureRoot, 'valid-messages.jsonl')).toString('utf8').split('\n').filter(Boolean).map((line) => `${line}\n`)[2]);
    expect(event.payload).toEqual({
      eventType: 'unknown-event',
      originalEventType: 'future.valid-event',
      redacted: true,
      keys: ['eventType', 'detail'],
    });
  });

  it('preserves the authoritative cancelled stream terminal', () => {
    const decoder = new ProtocolDecoder();
    const lines = fixtureLines('valid-messages.jsonl');
    const messages = lines.map((line) => decoder.decode(line));
    expect(messages.at(-1)?.payload).toEqual({
      eventType: 'stream.cancelled',
      terminal: 'cancelled',
    });
  });

  it('round trips a bounded known envelope', () => {
    const envelope: ProtocolEnvelope = { version: 1, kind: 'event', id: 'round-trip', sequence: 9, payload: { eventType: 'sidecar.status', status: 'ready' } };
    expect(new ProtocolDecoder().decode(encodeEnvelope(envelope))).toEqual(envelope);
  });

  it('closes versioned workspace request payloads while leaving paths private', () => {
    const request: ProtocolEnvelope = {
      version: 1,
      kind: 'request',
      id: 'rust-workspace-schema-1',
      sequence: 1,
      payload: {
        method: 'workspace.openUntrusted',
        schemaVersion: 1,
        workspaceId: 'workspace-0123456789abcdef0123456789abcdef',
        generation: 1,
        revision: 0,
      },
    };
    expect(new ProtocolDecoder().decode(encodeEnvelope(request))).toEqual(request);
    expect(() => new ProtocolDecoder().decode(encodeEnvelope({
      ...request,
      id: 'rust-workspace-schema-extra',
      payload: { ...request.payload, path: '/private/canary' },
    }))).toThrow('Envelope failed schema validation');
  });

  it('rejects malformed framing and invalid UTF-8 deterministically', () => {
    const valid = encodeEnvelope(eventEnvelope('framing-valid'));
    const cases: Array<[string, Uint8Array | string, string]> = [
      ['empty input', new Uint8Array(), 'one LF-delimited line'],
      ['missing LF', valid.subarray(0, -1), 'one LF-delimited line'],
      ['CRLF', Buffer.from(`${Buffer.from(valid).toString('utf8').trimEnd()}\r\n`), 'one LF-delimited line'],
      ['two JSON lines', Buffer.concat([Buffer.from(valid), Buffer.from(valid)]), 'Invalid JSON'],
      ['invalid UTF-8', Uint8Array.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xc3, 0x28, 0x7d, 0x0a]), 'Invalid UTF-8'],
      ['invalid JSON', '{"version":1,}\n', 'Invalid JSON'],
    ];

    for (const [name, input, message] of cases) {
      expect(() => new ProtocolDecoder().decode(input), name).toThrow(message);
    }
  });

  it('enforces line, payload and JSON-depth resource limits', () => {
    const oversizedLine = Buffer.alloc(PROTOCOL_LIMITS.maxLineBytes + 1, 0x20);
    oversizedLine[oversizedLine.length - 1] = 0x0a;
    expect(() => new ProtocolDecoder().decode(oversizedLine)).toThrow('Line limit exceeded');

    const oversizedPayload = eventEnvelope('oversized-payload', {
      eventType: 'sidecar.status',
      detail: 'x'.repeat(PROTOCOL_LIMITS.maxPayloadBytes),
    });
    expect(() => new ProtocolDecoder().decode(line(oversizedPayload))).toThrow('Payload limit exceeded');

    let nested: Record<string, unknown> = { terminal: true };
    for (let depth = 0; depth <= PROTOCOL_LIMITS.maxDepth; depth += 1) nested = { child: nested };
    expect(() => new ProtocolDecoder().decode(line(eventEnvelope('excessive-depth', {
      eventType: 'future.deep-event',
      nested,
    })))).toThrow('JSON depth limit exceeded');
  });

  it('measures very wide and very deep values without exhausting the stack', () => {
    const wide = Array.from({ length: 200_000 }, () => 0);
    expect(jsonDepth({ wide })).toBe(2);
    expect(jsonDepth([])).toBe(0);
    expect(jsonDepth({ a: { b: {} } })).toBe(2);
    let deep: unknown = 0;
    for (let level = 0; level < 100_000; level += 1) deep = [deep];
    expect(jsonDepth(deep)).toBe(PROTOCOL_LIMITS.maxDepth + 1);
    expect(jsonDepth(deep, 40)).toBe(41);
    expect(() => new ProtocolDecoder().decode(line(eventEnvelope('wide-event', {
      eventType: 'future.wide-event',
      wide,
    })))).not.toThrow(RangeError);
  });

  it('allows the private host lanes exactly two more levels than ordinary envelopes', () => {
    const nestedAt = (depth: number): Record<string, unknown> => {
      let value: Record<string, unknown> = {};
      for (let level = 0; level < depth; level += 1) value = { child: value };
      return value;
    };
    // payload.<field> sits at envelope depth 2, so field depth d gives d + 2.
    const privateLimit = PROTOCOL_LIMITS.maxDepth + 2;
    const hostRequest = (id: string, depth: number) => line({
      version: 1, kind: 'host-request', id, sequence: 1,
      payload: { method: 'credential.set', providerId: 'fixture', credential: nestedAt(depth - 2) },
    });
    const hostResponse = (id: string, depth: number) => line({
      version: 1, kind: 'host-response', id, correlationId: 'request-1', sequence: 1,
      payload: { found: true, credential: nestedAt(depth - 2) },
    });
    const event = (id: string, depth: number) => line(eventEnvelope(id, {
      eventType: 'future.deep-event', nested: nestedAt(depth - 2),
    }));

    expect(() => new ProtocolDecoder().decode(hostRequest('host-request-max', privateLimit))).not.toThrow();
    expect(() => new ProtocolDecoder().decode(hostResponse('host-response-max', privateLimit))).not.toThrow();
    expect(() => new ProtocolDecoder().decode(hostRequest('host-request-over', privateLimit + 1)))
      .toThrow('JSON depth limit exceeded');
    expect(() => new ProtocolDecoder().decode(hostResponse('host-response-over', privateLimit + 1)))
      .toThrow('JSON depth limit exceeded');
    expect(() => new ProtocolDecoder().decode(event('event-max', PROTOCOL_LIMITS.maxDepth))).not.toThrow();
    expect(() => new ProtocolDecoder().decode(event('event-over', PROTOCOL_LIMITS.maxDepth + 1)))
      .toThrow('JSON depth limit exceeded');
  });

  it('preserves the authoritative failed stream terminal as a known event', () => {
    const failed: ProtocolEnvelope = {
      version: 1, kind: 'event', id: 'stream-failed', correlationId: 'turn-1', sequence: 4,
      payload: { eventType: 'stream.failed', terminal: 'failed', code: 'provider-turn-failed' },
    };
    const decoded = new ProtocolDecoder().decode(encodeEnvelope(failed));
    expect(decoded).toEqual(failed);
    expect(decoded.payload.eventType).toBe('stream.failed');
    expect(() => new ProtocolDecoder().decode(line({
      ...failed, id: 'stream-failed-secret', payload: { ...failed.payload, apiKey: 'canary' },
    }))).toThrow('Secret-shaped diagnostic field rejected');
  });

  it('bounds pending IDs and reclaims acknowledged IDs', () => {
    const decoder = new ProtocolDecoder();
    for (let index = 0; index < PROTOCOL_LIMITS.maxPendingIds; index += 1) {
      decoder.decode(encodeEnvelope(eventEnvelope(`pending-${index}`)));
    }
    expect(() => decoder.decode(encodeEnvelope(eventEnvelope('pending-overflow')))).toThrow('Pending ID limit exceeded');

    decoder.acknowledge('pending-0');
    expect(decoder.decode(encodeEnvelope(eventEnvelope('pending-reclaimed'))).id).toBe('pending-reclaimed');
    expect(() => decoder.decode(encodeEnvelope(eventEnvelope('pending-reclaimed')))).toThrow('Duplicate envelope ID');
  });

  it('redacts unknown events to bounded non-secret diagnostics', () => {
    const payload: Record<string, unknown> = {
      eventType: `future.${'x'.repeat(121)}`,
      apiToken: 'must-not-survive',
    };
    for (let index = 0; index < 40; index += 1) payload[`safeKey${String(index).padStart(2, '0')}`] = index;

    expect(() => new ProtocolDecoder().decode(line(eventEnvelope('secret-unknown', payload)))).toThrow(
      'Secret-shaped diagnostic field rejected',
    );

    delete payload.apiToken;
    const result = new ProtocolDecoder().decode(line(eventEnvelope('bounded-unknown', payload)));
    expect(result.payload).toMatchObject({ eventType: 'unknown-event', redacted: true });
    expect(String(result.payload.originalEventType)).toHaveLength(128);
    expect(result.payload.keys).toHaveLength(32);
    expect(JSON.stringify(result.payload)).not.toContain('must-not-survive');
  });

  it('rejects a deterministic mutation corpus without weakening valid envelopes', () => {
    const base = eventEnvelope('mutation-base');
    const mutations: unknown[] = [
      { ...base, version: 2 },
      { ...base, kind: 'notification' },
      { ...base, id: '' },
      { ...base, id: '../escape' },
      { ...base, sequence: -1 },
      { ...base, sequence: 1.25 },
      { ...base, payload: [] },
      { ...base, payload: {} },
      { ...base, unexpected: true },
      { ...base, error: { category: 'other', message: 'no' } },
      { ...base, error: { category: 'internal', message: '' } },
      null,
      [],
      'event',
    ];

    for (const [index, mutation] of mutations.entries()) {
      expect(() => new ProtocolDecoder().decode(line(mutation)), `mutation ${index}`).toThrow();
    }
    expect(new ProtocolDecoder().decode(encodeEnvelope(base))).toEqual(base);
  });
});
