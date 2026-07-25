import Ajv2020, { type ErrorObject, type ValidateFunction } from 'ajv/dist/2020.js';
import envelopeSchema from '../schema/envelope.schema.json' with { type: 'json' };
import messagesSchema from '../schema/messages.schema.json' with { type: 'json' };
import { PROTOCOL_LIMITS } from './index.js';
import type { ProtocolEnvelope, UnknownEventDiagnostic } from './types.js';

const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
const validateEnvelope = ajv.compile(envelopeSchema) as ValidateFunction<ProtocolEnvelope>;
const validateMessage = ajv.compile(messagesSchema) as ValidateFunction<ProtocolEnvelope>;
const secretNeedles = ['secret', 'token', 'password', 'apikey', 'authorization', 'credential'] as const;
const knownEvents = new Set(['sidecar.status', 'stream.delta', 'stream.complete', 'tool.activity']);

export class ProtocolValidationError extends Error {
  readonly category = 'invalid-request' as const;
  constructor(message: string, readonly details: readonly ErrorObject[] = []) {
    super(message);
    this.name = 'ProtocolValidationError';
  }
}

export function jsonDepth(value: unknown, level = 0): number {
  if (level > PROTOCOL_LIMITS.maxDepth) return level;
  if (value === null || typeof value !== 'object') return level;
  return Math.max(level, ...Object.values(value).map((child) => jsonDepth(child, level + 1)));
}

function isSecretKey(key: string): boolean {
  const normalised = key.toLowerCase().replaceAll('_', '').replaceAll('-', '');
  return secretNeedles.some((needle) => normalised.includes(needle));
}

function containsSecretKey(value: unknown): boolean {
  if (value === null || typeof value !== 'object') return false;
  return Object.entries(value).some(([key, child]) => isSecretKey(key) || containsSecretKey(child));
}

function unknownEvent(envelope: ProtocolEnvelope): UnknownEventDiagnostic {
  const originalEventType = String(envelope.payload.eventType ?? 'missing');
  return {
    ...envelope,
    payload: {
      eventType: 'unknown-event',
      originalEventType: originalEventType.slice(0, 128),
      redacted: true,
      keys: Object.keys(envelope.payload).filter((key) => !isSecretKey(key)).slice(0, 32),
    },
  };
}

export function validateParsedEnvelope(value: unknown): ProtocolEnvelope | UnknownEventDiagnostic {
  if (jsonDepth(value) > PROTOCOL_LIMITS.maxDepth) throw new ProtocolValidationError('JSON depth limit exceeded');
  if (!validateEnvelope(value) || !validateMessage(value)) {
    throw new ProtocolValidationError('Envelope failed schema validation', [
      ...(validateEnvelope.errors ?? []),
      ...(validateMessage.errors ?? []),
    ]);
  }
  const envelope = value as ProtocolEnvelope;
  const payloadBytes = Buffer.byteLength(JSON.stringify(envelope.payload));
  if (payloadBytes > PROTOCOL_LIMITS.maxPayloadBytes) throw new ProtocolValidationError('Payload limit exceeded');
  if (envelope.kind === 'event') {
    if (containsSecretKey(envelope.payload)) throw new ProtocolValidationError('Secret-shaped diagnostic field rejected');
    const eventType = String(envelope.payload.eventType);
    if (!knownEvents.has(eventType)) return unknownEvent(envelope);
  }
  return envelope;
}
