import type { ProtocolEnvelope } from '@piui/protocol';
import { validateHandshake, type HandshakeExpectation } from '../../sidecar/src/bridge/handshake';

export type HandshakeState =
  | { status: 'ready' }
  | { status: 'incompatible'; message: 'PIUI’s local helper is incompatible. Reinstall PIUI or open Diagnostics.' };

export function acceptHandshake(envelope: ProtocolEnvelope, expected: HandshakeExpectation): HandshakeState {
  try {
    validateHandshake(envelope, expected);
    return { status: 'ready' };
  } catch {
    return { status: 'incompatible', message: 'PIUI’s local helper is incompatible. Reinstall PIUI or open Diagnostics.' };
  }
}
