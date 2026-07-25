import { describe, expect, it } from 'vitest';
import { createHandshake, validateHandshake, REQUIRED_CAPABILITIES } from '../../sidecar/src/bridge/handshake';
import { acceptHandshake } from '../../src/bridge/handshake';

const expected = { nonce: '0123456789abcdef', desktopVersion: '0.1.0', protocolVersion: 1, nodeVersion: '22.23.1', piVersion: '0.82.0', architecture: 'arm64', capabilities: REQUIRED_CAPABILITIES };
describe('version and capability handshake', () => {
  it('accepts the pinned matrix', () => { const message = createHandshake(expected); expect(() => validateHandshake(message, expected)).not.toThrow(); expect(acceptHandshake(message, expected)).toEqual({ status: 'ready' }); });
  for (const field of ['nonce', 'protocolVersion', 'piVersion'] as const) it(`rejects altered ${field} safely`, () => {
    const message = createHandshake({ ...expected, [field]: field === 'protocolVersion' ? 2 : 'altered' });
    const state = acceptHandshake(message, expected); expect(state.status).toBe('incompatible'); expect(JSON.stringify(state)).not.toContain('altered');
  });
});
