import type { ProtocolKind } from './index.js';

export type ProtocolErrorCategory =
  | 'invalid-request'
  | 'unsupported-version'
  | 'unavailable'
  | 'cancelled'
  | 'timeout'
  | 'permission-denied'
  | 'conflict'
  | 'internal';

export type ProtocolError = {
  category: ProtocolErrorCategory;
  message: string;
  retryable?: boolean;
  diagnosticId?: string;
};

export type ProtocolEnvelope<TPayload extends Record<string, unknown> = Record<string, unknown>> = {
  version: 1;
  kind: ProtocolKind;
  id: string;
  correlationId?: string;
  decisionId?: string;
  sequence: number;
  payload: TPayload;
  error?: ProtocolError;
};

export type UnknownEventDiagnostic = ProtocolEnvelope<{
  eventType: 'unknown-event';
  originalEventType: string;
  redacted: true;
  keys: string[];
}>;
