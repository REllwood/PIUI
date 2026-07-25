export const PROTOCOL_VERSION = 1 as const;
export const PROTOCOL_LIMITS = Object.freeze({
  maxLineBytes: 1_048_576,
  maxPayloadBytes: 524_288,
  maxDepth: 32,
  maxPendingIds: 4_096,
});

export const PROTOCOL_KINDS = Object.freeze([
  'handshake',
  'request',
  'response',
  'event',
  'host-request',
  'host-response',
  'cancel',
  'ack',
] as const);

export type ProtocolKind = (typeof PROTOCOL_KINDS)[number];
export type { ProtocolEnvelope, ProtocolError, ProtocolErrorCategory, UnknownEventDiagnostic } from './types.js';
