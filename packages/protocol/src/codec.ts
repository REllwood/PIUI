import { PROTOCOL_LIMITS } from './index.js';
import type { ProtocolEnvelope, UnknownEventDiagnostic } from './types.js';
import { ProtocolValidationError, validateParsedEnvelope } from './validate.js';

export class ProtocolDecoder {
  readonly #seenIds = new Set<string>();

  decode(line: Uint8Array | string): ProtocolEnvelope | UnknownEventDiagnostic {
    const bytes = typeof line === 'string' ? Buffer.from(line, 'utf8') : Buffer.from(line);
    if (bytes.length > PROTOCOL_LIMITS.maxLineBytes) throw new ProtocolValidationError('Line limit exceeded');
    if (bytes.length === 0 || bytes.at(-1) !== 0x0a || bytes.includes(0x0d)) {
      throw new ProtocolValidationError('Protocol input must be one LF-delimited line');
    }
    let text: string;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, -1));
    } catch {
      throw new ProtocolValidationError('Invalid UTF-8');
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new ProtocolValidationError('Invalid JSON');
    }
    const envelope = validateParsedEnvelope(parsed);
    if (this.#seenIds.has(envelope.id)) throw new ProtocolValidationError('Duplicate envelope ID');
    if (this.#seenIds.size >= PROTOCOL_LIMITS.maxPendingIds) throw new ProtocolValidationError('Pending ID limit exceeded');
    this.#seenIds.add(envelope.id);
    return envelope;
  }

  acknowledge(id: string): void {
    this.#seenIds.delete(id);
  }
}

export function encodeEnvelope(envelope: ProtocolEnvelope): Uint8Array {
  const validated = validateParsedEnvelope(envelope);
  const encoded = Buffer.from(`${JSON.stringify(validated)}\n`, 'utf8');
  if (encoded.length > PROTOCOL_LIMITS.maxLineBytes) throw new ProtocolValidationError('Encoded line limit exceeded');
  return encoded;
}
