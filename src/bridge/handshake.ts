import type { ProtocolEnvelope } from '@piui/protocol';

export const REQUIRED_CAPABILITIES = ['cancel', 'status', 'stream', 'host-credentials'] as const;

export type HandshakeExpectation = {
  nonce: string;
  desktopVersion: string;
  protocolVersion: number;
  nodeVersion: string;
  piVersion: string;
  architecture: string;
  capabilities: readonly string[];
};

export type HandshakeState =
  | { status: 'ready' }
  | {
      status: 'incompatible';
      message: 'PIUI’s local helper is incompatible. Reinstall PIUI or open Diagnostics.';
    };

export function acceptHandshake(
  envelope: ProtocolEnvelope,
  expected: HandshakeExpectation,
): HandshakeState {
  const payload = envelope.payload;
  const capabilities = new Set(
    Array.isArray(payload.capabilities)
      ? payload.capabilities.filter((value): value is string => typeof value === 'string')
      : [],
  );
  const compatible =
    envelope.kind === 'handshake' &&
    payload.nonce === expected.nonce &&
    payload.desktopVersion === expected.desktopVersion &&
    payload.protocolVersion === expected.protocolVersion &&
    payload.nodeVersion === expected.nodeVersion &&
    payload.piVersion === expected.piVersion &&
    payload.architecture === expected.architecture &&
    expected.capabilities.every((capability) => capabilities.has(capability));

  return compatible
    ? { status: 'ready' }
    : {
        status: 'incompatible',
        message: 'PIUI’s local helper is incompatible. Reinstall PIUI or open Diagnostics.',
      };
}
