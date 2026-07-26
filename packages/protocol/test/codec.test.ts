import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ProtocolDecoder, encodeEnvelope } from '../src/codec';
import type { ProtocolEnvelope } from '../src/types';

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
});
