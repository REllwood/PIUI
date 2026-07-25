import { describe, expect, it } from 'vitest';
import {
  createHandshake,
  validateHandshake,
  REQUIRED_CAPABILITIES,
} from '../../sidecar/src/bridge/handshake';
import { acceptHandshake } from '../../src/bridge/handshake';

const expected = {
  nonce: '0123456789abcdef',
  desktopVersion: '0.1.0',
  protocolVersion: 1,
  nodeVersion: '22.23.1',
  piVersion: '0.82.0',
  architecture: 'arm64',
  capabilities: REQUIRED_CAPABILITIES,
} as const;

describe('version and capability handshake', () => {
  it('accepts the pinned matrix and required capability subset', () => {
    const message = createHandshake({
      ...expected,
      capabilities: [...expected.capabilities, 'future-capability'],
    });
    expect(() => validateHandshake(message, expected)).not.toThrow();
    expect(acceptHandshake(message, expected)).toEqual({ status: 'ready' });
  });

  for (const [name, changed] of [
    ['nonce', { nonce: 'altered-nonce' }],
    ['protocol', { protocolVersion: 2 }],
    ['Pi', { piVersion: '0.83.0' }],
    ['Node', { nodeVersion: '23.0.0' }],
    ['architecture', { architecture: 'x64' }],
    ['desktop', { desktopVersion: '9.9.9' }],
  ] as const) {
    it(`rejects an altered ${name} without reflecting details`, () => {
      const message = createHandshake({ ...expected, ...changed });
      expect(() => validateHandshake(message, expected)).toThrow('incompatible-sidecar');
      const state = acceptHandshake(message, expected);
      expect(state.status).toBe('incompatible');
      expect(JSON.stringify(state)).not.toContain(Object.values(changed)[0]);
    });
  }

  it('rejects a missing required capability', () => {
    const capabilities = expected.capabilities.filter((capability) => capability !== 'host-credentials');
    const message = createHandshake({ ...expected, capabilities });
    expect(() => validateHandshake(message, expected)).toThrow('incompatible-sidecar');
    expect(acceptHandshake(message, expected).status).toBe('incompatible');
  });
});
