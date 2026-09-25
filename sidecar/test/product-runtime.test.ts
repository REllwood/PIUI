import type { ProtocolEnvelope } from '@piui/protocol';
import { describe, expect, it } from 'vitest';
import { HostRequestClient } from '../src/bridge/host-requests';
import { SidecarRouter } from '../src/bridge/router';
import type { PiAdapter } from '../src/pi/adapter';
import { ProductRuntime } from '../src/pi/product-router';

function host(): HostRequestClient {
  return new HostRequestClient({ router: new SidecarRouter(), write: () => undefined });
}

function providersRequest(sequence: number): ProtocolEnvelope {
  return {
    version: 1,
    kind: 'request',
    id: `rust-product-providers-${sequence}`,
    sequence,
    payload: { method: 'product.providers.list' },
  };
}

const adapter = Object.freeze({
  listProviders: async () => [],
  close: async () => undefined,
}) as unknown as PiAdapter;

describe('ProductRuntime adapter construction', () => {
  it('constructs the adapter again after a transient construction failure', async () => {
    let attempts = 0;
    const runtime = new ProductRuntime(host(), 1, async () => {
      attempts += 1;
      if (attempts === 1) throw new Error('credential-request-timeout');
      return adapter;
    });
    await expect(runtime.handle(providersRequest(1))).rejects.toThrow('credential-request-timeout');
    await expect(runtime.handle(providersRequest(2))).resolves.toEqual({
      schemaVersion: 1,
      providers: [],
    });
    await expect(runtime.handle(providersRequest(3))).resolves.toBeDefined();
    expect(attempts).toBe(2);
  });

  it('shares one in-flight construction and closes cleanly after a failure', async () => {
    let attempts = 0;
    const runtime = new ProductRuntime(host(), 1, async () => {
      attempts += 1;
      throw new Error('adapter-unavailable');
    });
    const results = await Promise.allSettled([
      runtime.handle(providersRequest(4)),
      runtime.handle(providersRequest(5)),
    ]);
    expect(results.map((result) => result.status)).toEqual(['rejected', 'rejected']);
    expect(attempts).toBe(1);
    await expect(runtime.close()).resolves.toBeUndefined();
  });
});
