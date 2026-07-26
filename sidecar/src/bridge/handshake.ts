import type { ProtocolEnvelope } from '@piui/protocol';

export const PROTOCOL_VERSION = 1 as const;
export const PI_VERSION = '0.82.0' as const;
export const NODE_VERSION = '22.23.1' as const;
export const REQUIRED_CAPABILITIES = [
  'cancel',
  'status',
  'stream',
  'host-credentials',
  'workspace-trust-v1',
] as const;

export type HandshakeExpectation = {
  nonce: string;
  desktopVersion: string;
  protocolVersion: number;
  nodeVersion: string;
  piVersion: string;
  architecture: string;
  capabilities: readonly string[];
};

export function createHandshake(
  expectation: HandshakeExpectation,
  sequence = 0,
): ProtocolEnvelope {
  return {
    version: 1,
    kind: 'handshake',
    id: 'sidecar-handshake',
    sequence,
    payload: { ...expectation, capabilities: [...expectation.capabilities] },
  };
}

export function validateHandshake(
  envelope: ProtocolEnvelope,
  expected: HandshakeExpectation,
): void {
  if (envelope.kind !== 'handshake') throw new Error('incompatible-sidecar');
  const payload = envelope.payload;
  for (const field of [
    'nonce',
    'desktopVersion',
    'protocolVersion',
    'nodeVersion',
    'piVersion',
    'architecture',
  ] as const) {
    if (payload[field] !== expected[field]) throw new Error('incompatible-sidecar');
  }
  const capabilities = new Set(
    Array.isArray(payload.capabilities)
      ? payload.capabilities.filter((value): value is string => typeof value === 'string')
      : [],
  );
  if (expected.capabilities.some((capability) => !capabilities.has(capability))) {
    throw new Error('incompatible-sidecar');
  }
}
