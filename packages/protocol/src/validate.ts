import Ajv2020, { type ErrorObject, type ValidateFunction } from 'ajv/dist/2020.js';
import envelopeSchema from '../schema/envelope.schema.json' with { type: 'json' };
import messagesSchema from '../schema/messages.schema.json' with { type: 'json' };
import approvalSchema from '../schema/approval.schema.json' with { type: 'json' };
import { PROTOCOL_LIMITS } from './index.js';
import type { ProtocolEnvelope, UnknownEventDiagnostic } from './types.js';

const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
const validateEnvelope = ajv.compile(envelopeSchema) as ValidateFunction<ProtocolEnvelope>;
const validateMessage = ajv.compile(messagesSchema) as ValidateFunction<ProtocolEnvelope>;
const validateApprovalPayload = ajv.compile(approvalSchema) as ValidateFunction<Record<string, unknown>>;
const secretNeedles = ['secret', 'token', 'password', 'apikey', 'authorization', 'credential'] as const;
const knownEvents = new Set([
  'sidecar.status',
  'stream.delta',
  'stream.complete',
  'stream.cancelled',
  'stream.failed',
  'tool.activity',
]);

export class ProtocolValidationError extends Error {
  readonly category = 'invalid-request' as const;
  constructor(message: string, readonly details: readonly ErrorObject[] = []) {
    super(message);
    this.name = 'ProtocolValidationError';
  }
}

// Private host lanes carry one credential or approval input validated at depth
// zero beneath `payload.<field>`; the envelope and payload wrappers add exactly
// two levels. This mirrors Rust's PRIVATE_HOST_REQUEST_MAX_DEPTH.
const PRIVATE_HOST_MAX_DEPTH = PROTOCOL_LIMITS.maxDepth + 2;

/**
 * Depth of the deepest leaf, counting each object or array level once. The
 * walk is iterative and stops as soon as `limit` is exceeded, so neither very
 * wide arrays nor very deep nesting can exhaust the call stack or argument
 * spread limits. Values deeper than `limit` report `limit + 1`.
 */
export function jsonDepth(value: unknown, limit: number = PROTOCOL_LIMITS.maxDepth): number {
  let deepest = 0;
  const stack: Array<[unknown, number]> = [[value, 0]];
  while (stack.length > 0) {
    const [current, level] = stack.pop()!;
    if (level > deepest) deepest = level;
    if (deepest > limit) return limit + 1;
    if (current === null || typeof current !== 'object') continue;
    for (const child of Object.values(current)) stack.push([child, level + 1]);
  }
  return deepest;
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
  const kind = value !== null && typeof value === 'object' ? (value as Record<string, unknown>).kind : undefined;
  const depthLimit = kind === 'host-request' || kind === 'host-response' ? PRIVATE_HOST_MAX_DEPTH : PROTOCOL_LIMITS.maxDepth;
  if (jsonDepth(value, depthLimit) > depthLimit) throw new ProtocolValidationError('JSON depth limit exceeded');
  if (!validateEnvelope(value) || !validateMessage(value)) {
    throw new ProtocolValidationError('Envelope failed schema validation', [
      ...(validateEnvelope.errors ?? []),
      ...(validateMessage.errors ?? []),
    ]);
  }
  const envelope = value as ProtocolEnvelope;
  const privateApproval = (envelope.kind === 'host-request' || envelope.kind === 'host-response')
    && (String(envelope.payload.method ?? '').startsWith('approval.') || envelope.decisionId !== undefined);
  if (privateApproval && !validateApprovalPayload(envelope.payload)) {
    throw new ProtocolValidationError('Approval payload failed schema validation', validateApprovalPayload.errors ?? []);
  }
  const payloadBytes = Buffer.byteLength(JSON.stringify(envelope.payload));
  if (payloadBytes > PROTOCOL_LIMITS.maxPayloadBytes) throw new ProtocolValidationError('Payload limit exceeded');
  if (envelope.kind === 'event') {
    if (containsSecretKey(envelope.payload)) throw new ProtocolValidationError('Secret-shaped diagnostic field rejected');
    const eventType = String(envelope.payload.eventType);
    if (!knownEvents.has(eventType)) return unknownEvent(envelope);
  }
  return envelope;
}
