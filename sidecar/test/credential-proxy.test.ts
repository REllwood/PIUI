import { createHash, randomBytes } from 'node:crypto';
import type { ProtocolEnvelope } from '@piui/protocol';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  CREDENTIAL_PROXY_LIMITS,
  HostRequestClient,
  HostRequestError,
  assertCredentialHostRequestEnvelope,
} from '../src/bridge/host-requests';
import { createZeroingProtocolWriter } from '../src/bridge/protocol-writer';
import { SidecarRouter } from '../src/bridge/router';
import {
  PiCredentialStore,
  type PiCredentialStoreOptions,
} from '../src/credentials/store-proxy';
import type { PublicCredential } from '../src/pi/public-sdk';

function runtimeSecret(): string {
  return randomBytes(24).toString('base64url');
}

function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function sameSecret(actual: unknown, expected: string): boolean {
  return typeof actual === 'string' && digest(actual) === digest(expected);
}

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

type TraceEntry = {
  method: string;
  providerId?: string;
};

type PersistentHost = {
  credentials: Map<string, PublicCredential>;
  metadata: Map<string, PublicCredential['type']>;
  secretReads: number;
};

function createPersistentHost(): PersistentHost {
  return {
    credentials: new Map(),
    metadata: new Map(),
    secretReads: 0,
  };
}

type HostHarness = {
  client: HostRequestClient;
  proxy: PiCredentialStore;
  trace: TraceEntry[];
  responsePayloadKeys: string[][];
  secretReadCount(): number;
  failNextSet(): void;
};

function createHostHarness(
  persistent: PersistentHost = createPersistentHost(),
  proxyOptions: PiCredentialStoreOptions = {},
): HostHarness {
  const router = new SidecarRouter();
  const trace: TraceEntry[] = [];
  const responsePayloadKeys: string[][] = [];
  let sequence = 1;
  let shouldFailNextSet = false;
  let client!: HostRequestClient;

  const respond = (request: ProtocolEnvelope) => {
    const method = request.payload.method;
    const providerId = typeof request.payload.providerId === 'string'
      ? request.payload.providerId
      : undefined;
    trace.push({ method: String(method), ...(providerId ? { providerId } : {}) });

    let payload: Record<string, unknown> = {};
    let error: ProtocolEnvelope['error'];
    if (method === 'credential.get' && providerId) {
      persistent.secretReads += 1;
      const credential = persistent.credentials.get(providerId);
      payload = credential
        ? { found: true, credential: structuredClone(credential) }
        : { found: false };
    } else if (method === 'credential.list') {
      payload = {
        entries: [...persistent.metadata].map(([storedProviderId, type]) => ({
          providerId: storedProviderId,
          type,
        })),
      };
    } else if (method === 'credential.set' && providerId) {
      if (shouldFailNextSet) {
        shouldFailNextSet = false;
        error = {
          category: 'internal',
          message: 'Credential operation failed',
          retryable: false,
        };
      } else {
        const credential = structuredClone(
          request.payload.credential as PublicCredential,
        );
        persistent.credentials.set(providerId, credential);
        persistent.metadata.set(providerId, credential.type);
        payload = { stored: true };
      }
    } else if (method === 'credential.remove' && providerId) {
      persistent.credentials.delete(providerId);
      persistent.metadata.delete(providerId);
      payload = { removed: true };
    }
    responsePayloadKeys.push(Object.keys(payload));

    client.consume({
      version: 1,
      kind: 'host-response',
      id: `fake-host-${sequence}`,
      correlationId: request.id,
      sequence: sequence++,
      payload,
      ...(error ? { error } : {}),
    });
  };

  client = new HostRequestClient({
    router,
    write: (request) => queueMicrotask(() => respond(request)),
  });
  return {
    client,
    proxy: new PiCredentialStore(client, proxyOptions),
    trace,
    responsePayloadKeys,
    secretReadCount: () => persistent.secretReads,
    failNextSet: () => {
      shouldFailNextSet = true;
    },
  };
}

function apiCredential(): { credential: PublicCredential; values: string[] } {
  const key = runtimeSecret();
  const account = runtimeSecret();
  const zone = runtimeSecret();
  return {
    credential: {
      type: 'api_key',
      key,
      env: { PIUI_ACCOUNT: account, PIUI_ZONE: zone },
    },
    values: [key, account, zone],
  };
}

function oauthCredential(expires = Date.now() + 60_000): {
  credential: PublicCredential;
  values: string[];
} {
  const access = runtimeSecret();
  const refresh = runtimeSecret();
  const accountId = runtimeSecret();
  const enterpriseUrl = runtimeSecret();
  const scope = runtimeSecret();
  const modelId = runtimeSecret();
  return {
    credential: {
      type: 'oauth',
      access,
      refresh,
      expires,
      accountId,
      enterpriseUrl,
      scope,
      availableModelIds: [modelId],
    },
    values: [access, refresh, accountId, enterpriseUrl, scope, modelId],
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('Pi credential-store proxy', () => {
  it('round-trips API-key and bounded OAuth extension fields while list stays metadata-only', async () => {
    const host = createHostHarness();
    const api = apiCredential();
    const oauth = oauthCredential();

    await host.proxy.modify('api-provider', async () => api.credential);
    await host.proxy.modify('oauth-provider', async () => oauth.credential);
    const readApi = await host.proxy.read('api-provider');
    const readOauth = await host.proxy.read('oauth-provider');
    const secretReadsBeforeList = host.secretReadCount();
    const list = await host.proxy.list();

    expect(readApi?.type).toBe('api_key');
    expect(api.values.every((value) => {
      if (readApi?.type !== 'api_key') return false;
      return [readApi.key, ...Object.values(readApi.env ?? {})]
        .some((actual) => sameSecret(actual, value));
    })).toBe(true);
    expect(readOauth?.type).toBe('oauth');
    expect(oauth.values.every((value) => {
      if (readOauth?.type !== 'oauth') return false;
      return [
        readOauth.access,
        readOauth.refresh,
        readOauth.accountId,
        readOauth.enterpriseUrl,
        readOauth.scope,
        ...(Array.isArray(readOauth.availableModelIds) ? readOauth.availableModelIds : []),
      ].some((actual) => sameSecret(actual, value));
    })).toBe(true);
    expect(list).toEqual([
      { providerId: 'api-provider', type: 'api_key' },
      { providerId: 'oauth-provider', type: 'oauth' },
    ]);
    expect(list.every((entry) => Object.keys(entry).sort().join(',') === 'providerId,type')).toBe(true);
    expect(host.secretReadCount()).toBe(secretReadsBeforeList);
    expect(host.responsePayloadKeys.filter((keys) => keys.includes('stored')))
      .toEqual([['stored'], ['stored']]);
  });

  it('implements missing and reference modify semantics without an unintended write', async () => {
    const host = createHostHarness();
    const current = apiCredential();
    expect(await host.proxy.read('missing-provider')).toBeUndefined();
    await expect(host.proxy.delete('missing-provider')).resolves.toBeUndefined();
    await host.proxy.modify('modify-provider', async () => current.credential);
    host.trace.length = 0;

    let callbackSawCurrent = false;
    const unchanged = await host.proxy.modify('modify-provider', async (credential) => {
      callbackSawCurrent = credential?.type === 'api_key'
        && sameSecret(credential.key, current.values[0]!);
      return undefined;
    });
    expect(callbackSawCurrent).toBe(true);
    expect(unchanged?.type === 'api_key' && sameSecret(unchanged.key, current.values[0]!)).toBe(true);
    expect(host.trace.map(({ method }) => method)).toEqual(['credential.get']);

    await expect(host.proxy.modify('modify-provider', async () => {
      throw new Error('credential-callback-failed');
    })).rejects.toThrow('credential-callback-failed');
    expect(host.trace.filter(({ method }) => method === 'credential.set')).toHaveLength(0);

    host.failNextSet();
    await expect(host.proxy.modify('modify-provider', async () => apiCredential().credential))
      .rejects.toMatchObject({
        code: 'credential-operation-failed',
        message: 'Credential operation failed',
      });
  });

  it('serialises refresh then logout across the whole asynchronous callback', async () => {
    const host = createHostHarness();
    const initial = oauthCredential(0);
    const refreshed = oauthCredential();
    await host.proxy.modify('serial-provider', async () => initial.credential);
    host.trace.length = 0;

    const entered = deferred();
    const release = deferred();
    const refresh = host.proxy.modify('serial-provider', async () => {
      entered.resolve();
      await release.promise;
      return refreshed.credential;
    });
    await entered.promise;
    const logout = host.proxy.delete('serial-provider');
    release.resolve();
    await Promise.all([refresh, logout]);

    expect(host.trace.map(({ method }) => method)).toEqual([
      'credential.get',
      'credential.set',
      'credential.remove',
    ]);
    expect(await host.proxy.read('serial-provider')).toBeUndefined();
  });

  it('serialises logout then refresh so missing state cannot be resurrected', async () => {
    const host = createHostHarness();
    const initial = oauthCredential(0);
    await host.proxy.modify('logout-first-provider', async () => initial.credential);
    host.trace.length = 0;

    const logout = host.proxy.delete('logout-first-provider');
    let sawMissing = false;
    const refresh = host.proxy.modify('logout-first-provider', async (current) => {
      sawMissing = current === undefined;
      return undefined;
    });
    await Promise.all([logout, refresh]);

    expect(sawMissing).toBe(true);
    expect(host.trace.map(({ method }) => method)).toEqual([
      'credential.remove',
      'credential.get',
    ]);
    expect(host.trace.some(({ method }) => method === 'credential.set')).toBe(false);
  });

  it('queues a same-provider read behind the complete modify callback', async () => {
    const host = createHostHarness();
    const initial = oauthCredential(0);
    const refreshed = oauthCredential();
    await host.proxy.modify('read-queue-provider', async () => initial.credential);

    const entered = deferred();
    const release = deferred();
    const modifying = host.proxy.modify('read-queue-provider', async () => {
      entered.resolve();
      await release.promise;
      return refreshed.credential;
    });
    await entered.promise;
    let readSettled = false;
    const reading = host.proxy.read('read-queue-provider').then((credential) => {
      readSettled = true;
      return credential;
    });
    await Promise.resolve();
    expect(readSettled).toBe(false);

    release.resolve();
    await modifying;
    const read = await reading;
    expect(read?.type === 'oauth' && sameSecret(read.access, refreshed.values[0]!)).toBe(true);
  });

  it('allows only one of two queued refreshes to rotate an expired credential', async () => {
    const host = createHostHarness();
    const expired = oauthCredential(0);
    const refreshed = oauthCredential();
    await host.proxy.modify('refresh-provider', async () => expired.credential);
    host.trace.length = 0;

    const entered = deferred();
    const release = deferred();
    let refreshCalls = 0;
    const refresh = async (current: PublicCredential | undefined) => {
      if (current?.type !== 'oauth' || current.expires > Date.now()) return undefined;
      refreshCalls += 1;
      entered.resolve();
      await release.promise;
      return refreshed.credential;
    };
    const first = host.proxy.modify('refresh-provider', refresh);
    await entered.promise;
    const second = host.proxy.modify('refresh-provider', refresh);
    release.resolve();
    await Promise.all([first, second]);

    expect(refreshCalls).toBe(1);
    expect(host.trace.map(({ method }) => method)).toEqual([
      'credential.get',
      'credential.set',
      'credential.get',
    ]);
  });

  it('allows different provider queues to overlap without unlinking queued work', async () => {
    const host = createHostHarness();
    const firstEntered = deferred();
    const secondEntered = deferred();
    const releaseFirst = deferred();
    const releaseSecond = deferred();

    const first = host.proxy.modify('parallel-a', async () => {
      firstEntered.resolve();
      await releaseFirst.promise;
      return apiCredential().credential;
    });
    await firstEntered.promise;
    const second = host.proxy.modify('parallel-b', async () => {
      secondEntered.resolve();
      await releaseSecond.promise;
      return oauthCredential().credential;
    });
    await secondEntered.promise;

    expect(host.proxy.queueCountsForTest).toEqual({ providers: 2, operations: 2 });
    releaseSecond.resolve();
    await second;
    expect(host.proxy.queueCountsForTest).toEqual({ providers: 1, operations: 1 });
    releaseFirst.resolve();
    await first;
    expect(host.proxy.queueCountsForTest).toEqual({ providers: 0, operations: 0 });
  });

  it('rejects queue limits outside fixed maxima', () => {
    const client = new HostRequestClient({
      router: new SidecarRouter(),
      write: () => undefined,
    });
    expect(() => new PiCredentialStore(client, {
      maxQueuedOperationsPerProvider: 0,
    })).toThrow('Credential request rejected');
    expect(() => new PiCredentialStore(client, {
      maxQueuedOperationsPerProvider:
        CREDENTIAL_PROXY_LIMITS.maxQueuedOperationsPerProvider + 1,
    })).toThrow('Credential request rejected');
    expect(() => new PiCredentialStore(client, {
      maxQueuedOperationsTotal: CREDENTIAL_PROXY_LIMITS.maxQueuedOperationsTotal + 1,
    })).toThrow('Credential request rejected');
  });

  it('bounds same-provider and total queued operations with the stable capacity error', async () => {
    const perProvider = createHostHarness(createPersistentHost(), {
      maxQueuedOperationsPerProvider: 2,
      maxQueuedOperationsTotal: 4,
    });
    const firstEntered = deferred();
    const releaseFirst = deferred();
    const first = perProvider.proxy.modify('bounded-provider', async () => {
      firstEntered.resolve();
      await releaseFirst.promise;
      return undefined;
    });
    await firstEntered.promise;
    const second = perProvider.proxy.read('bounded-provider');
    const rejectedPerProvider = await perProvider.proxy.read('bounded-provider')
      .catch((error: unknown) => error);
    expect(rejectedPerProvider).toMatchObject({ code: 'credential-host-capacity' });
    expect(perProvider.proxy.queueCountsForTest).toEqual({ providers: 1, operations: 2 });
    releaseFirst.resolve();
    await Promise.all([first, second]);

    const total = createHostHarness(createPersistentHost(), {
      maxQueuedOperationsPerProvider: 2,
      maxQueuedOperationsTotal: 2,
    });
    const firstTotalEntered = deferred();
    const secondTotalEntered = deferred();
    const releaseFirstTotal = deferred();
    const releaseSecondTotal = deferred();
    const firstTotal = total.proxy.modify('total-a', async () => {
      firstTotalEntered.resolve();
      await releaseFirstTotal.promise;
      return undefined;
    });
    const secondTotal = total.proxy.modify('total-b', async () => {
      secondTotalEntered.resolve();
      await releaseSecondTotal.promise;
      return undefined;
    });
    await Promise.all([firstTotalEntered.promise, secondTotalEntered.promise]);
    const rejectedTotal = await total.proxy.read('total-c').catch((error: unknown) => error);
    expect(rejectedTotal).toMatchObject({ code: 'credential-host-capacity' });
    expect(total.proxy.queueCountsForTest).toEqual({ providers: 2, operations: 2 });
    releaseFirstTotal.resolve();
    releaseSecondTotal.resolve();
    await Promise.all([firstTotal, secondTotal]);
  });

  it('keeps a same-provider tail linked while an earlier operation cleans up', async () => {
    const host = createHostHarness();
    const firstEntered = deferred();
    const secondEntered = deferred();
    const releaseFirst = deferred();
    const releaseSecond = deferred();
    const first = host.proxy.modify('tail-provider', async () => {
      firstEntered.resolve();
      await releaseFirst.promise;
      return undefined;
    });
    await firstEntered.promise;
    const second = host.proxy.modify('tail-provider', async () => {
      secondEntered.resolve();
      await releaseSecond.promise;
      return undefined;
    });
    const third = host.proxy.read('tail-provider');

    releaseFirst.resolve();
    await first;
    await secondEntered.promise;
    expect(host.proxy.queueCountsForTest).toEqual({ providers: 1, operations: 2 });

    releaseSecond.resolve();
    await Promise.all([second, third]);
    expect(host.proxy.queueCountsForTest).toEqual({ providers: 0, operations: 0 });
  });

  it('continues FIFO work after a rejected same-provider tail', async () => {
    const host = createHostHarness();
    const entered = deferred();
    const release = deferred();
    const rejected = host.proxy.modify('rejected-tail-provider', async () => {
      entered.resolve();
      await release.promise;
      throw new Error('credential-callback-failed');
    });
    await entered.promise;
    const continued = host.proxy.read('rejected-tail-provider');
    release.resolve();

    await expect(rejected).rejects.toThrow('credential-callback-failed');
    await expect(continued).resolves.toBeUndefined();
    expect(host.trace.map(({ method }) => method)).toEqual([
      'credential.get',
      'credential.get',
    ]);
  });

  it('orders a same-provider delete before a following read', async () => {
    const host = createHostHarness();
    await host.proxy.modify('delete-read-provider', async () => apiCredential().credential);
    host.trace.length = 0;

    const deleting = host.proxy.delete('delete-read-provider');
    const reading = host.proxy.read('delete-read-provider');
    await deleting;
    await expect(reading).resolves.toBeUndefined();
    expect(host.trace.map(({ method }) => method)).toEqual([
      'credential.remove',
      'credential.get',
    ]);
  });

  it('promptly rejects queued and in-progress modify work on disconnect without a late set', async () => {
    const host = createHostHarness();
    const entered = deferred();
    const release = deferred();
    const callbackReturned = deferred();
    const lateCredential = oauthCredential();
    const modifying = host.proxy.modify('disconnect-queue-provider', async () => {
      entered.resolve();
      await release.promise;
      callbackReturned.resolve();
      return lateCredential.credential;
    }).catch((error: unknown) => error);
    await entered.promise;
    const queued = host.proxy.read('disconnect-queue-provider')
      .catch((error: unknown) => error);
    expect(host.proxy.queueCountsForTest).toEqual({ providers: 1, operations: 2 });

    host.client.disconnect();
    await expect(modifying).resolves.toMatchObject({ code: 'credential-host-disconnected' });
    await expect(queued).resolves.toMatchObject({ code: 'credential-host-disconnected' });
    expect(host.proxy.queueCountsForTest).toEqual({ providers: 0, operations: 0 });

    release.resolve();
    await callbackReturned.promise;
    await Promise.resolve();
    await Promise.resolve();
    expect(host.trace.map(({ method }) => method)).toEqual(['credential.get']);
  });

  it('prevents generation-one work from settling or writing into generation two', async () => {
    const persistent = createPersistentHost();
    const host = createHostHarness(persistent);
    const oldEntered = deferred();
    const releaseOld = deferred();
    const oldReturned = deferred();
    const oldCredential = oauthCredential();
    const newCredential = oauthCredential();
    const oldModify = host.proxy.modify('rotated-provider', async () => {
      oldEntered.resolve();
      await releaseOld.promise;
      oldReturned.resolve();
      return oldCredential.credential;
    }).catch((error: unknown) => error);
    await oldEntered.promise;
    const oldQueued = host.proxy.read('rotated-provider').catch((error: unknown) => error);

    host.client.abortAll();
    await expect(oldModify).resolves.toMatchObject({ code: 'credential-request-cancelled' });
    await expect(oldQueued).resolves.toMatchObject({ code: 'credential-request-cancelled' });
    await host.proxy.modify('rotated-provider', async () => newCredential.credential);

    releaseOld.resolve();
    await oldReturned.promise;
    await Promise.resolve();
    await Promise.resolve();
    const recovered = await host.proxy.read('rotated-provider');
    expect(
      recovered?.type === 'oauth'
      && sameSecret(recovered.access, newCredential.values[0]!),
    ).toBe(true);
    expect(host.trace.filter(({ method }) => method === 'credential.set')).toHaveLength(1);
  });

  it('recovers through a new client generation when the fake host store outlives the client', async () => {
    const persistent = createPersistentHost();
    const generationOne = createHostHarness(persistent);
    const stored = oauthCredential();
    await generationOne.proxy.modify('restart-provider', async () => stored.credential);
    generationOne.client.disconnect();

    const generationTwo = createHostHarness(persistent);
    const recovered = await generationTwo.proxy.read('restart-provider');
    expect(recovered?.type === 'oauth' && sameSecret(recovered.access, stored.values[0]!)).toBe(true);
    expect(generationOne.client.pendingCount).toBe(0);
  });
});

describe('strict credential host-request validation', () => {
  function envelope(payload: Record<string, unknown>): ProtocolEnvelope {
    return {
      version: 1,
      kind: 'host-request',
      id: 'strict-host-request',
      sequence: 1,
      payload,
    };
  }

  function expectRejected(value: unknown): void {
    let rejected: unknown;
    try {
      assertCredentialHostRequestEnvelope(value);
    } catch (error) {
      rejected = error;
    }
    expect(rejected).toMatchObject({
      code: 'credential-request-rejected',
      message: 'Credential request rejected',
    });
  }

  it('accepts only exact method-specific request shapes', () => {
    expect(() => assertCredentialHostRequestEnvelope(
      envelope({ method: 'credential.list' }),
    )).not.toThrow();
    expect(() => assertCredentialHostRequestEnvelope(
      envelope({ method: 'credential.get', providerId: 'strict-provider' }),
    )).not.toThrow();
    expect(() => assertCredentialHostRequestEnvelope(
      envelope({ method: 'credential.remove', providerId: 'strict-provider' }),
    )).not.toThrow();
    expect(() => assertCredentialHostRequestEnvelope(envelope({
      method: 'credential.set',
      providerId: 'strict-provider',
      credential: { type: 'api_key', key: runtimeSecret() },
    }))).not.toThrow();

    expectRejected(envelope({ method: 'credential.unknown' }));
    expectRejected(envelope({ method: 'credential.get' }));
    expectRejected(envelope({
      method: 'credential.get',
      providerId: 'strict-provider',
      extra: true,
    }));
    expectRejected({ ...envelope({ method: 'credential.list' }), extra: true });
    expectRejected({ ...envelope({ method: 'credential.list' }), id: '' });
    expectRejected({ ...envelope({ method: 'credential.list' }), sequence: -1 });
  });

  it('enforces provider, credential, depth, size, safe-number and list bounds', () => {
    expectRejected(envelope({ method: 'credential.get', providerId: '' }));
    expectRejected(envelope({
      method: 'credential.get',
      providerId: 'x'.repeat(129),
    }));
    expectRejected(envelope({
      method: 'credential.get',
      providerId: 'line\nbreak',
    }));
    expectRejected(envelope({
      method: 'credential.set',
      providerId: 'strict-provider',
    }));
    expectRejected(envelope({
      method: 'credential.set',
      providerId: 'strict-provider',
      credential: { type: 'api_key', unexpected: runtimeSecret() },
    }));
    expectRejected(envelope({
      method: 'credential.set',
      providerId: 'strict-provider',
      credential: { type: 'api_key', key: 'x'.repeat(65_537) },
    }));
    expectRejected(envelope({
      method: 'credential.set',
      providerId: 'strict-provider',
      credential: {
        type: 'oauth',
        access: runtimeSecret(),
        refresh: runtimeSecret(),
        expires: Number.MAX_SAFE_INTEGER + 1,
      },
    }));
    expectRejected(envelope({
      method: 'credential.set',
      providerId: 'strict-provider',
      credential: {
        type: 'oauth',
        access: runtimeSecret(),
        refresh: runtimeSecret(),
        expires: 1,
        availableModelIds: Array.from({ length: 257 }, () => 'model'),
      },
    }));

    let nested: unknown = 'bounded-leaf';
    for (let depth = 0; depth < 33; depth += 1) nested = { nested };
    expectRejected(envelope({
      method: 'credential.set',
      providerId: 'strict-provider',
      credential: {
        type: 'oauth',
        access: runtimeSecret(),
        refresh: runtimeSecret(),
        expires: 1,
        extension: nested,
      },
    }));
    expectRejected(envelope({
      method: 'credential.set',
      providerId: 'strict-provider',
      credential: {
        type: 'oauth',
        access: runtimeSecret(),
        refresh: runtimeSecret(),
        expires: 1,
        extension: Object.fromEntries(
          Array.from({ length: 129 }, (_, index) => [`field-${index}`, index]),
        ),
      },
    }));
  });

  it('invokes the strict validator immediately before transport write', async () => {
    let writes = 0;
    const client = new HostRequestClient({
      router: {
        next: () => envelope({
          method: 'credential.get',
          providerId: 'strict-provider',
          extra: true,
        }),
      },
      write: () => {
        writes += 1;
      },
    });
    await expect(client.get('strict-provider')).rejects.toMatchObject({
      code: 'credential-operation-failed',
    });
    expect(writes).toBe(0);
  });
});

describe('private credential host requests', () => {
  it('disconnects every pending request and rejects a late private response without reflection', async () => {
    const router = new SidecarRouter();
    let requestId = '';
    const client = new HostRequestClient({
      router,
      write: (request) => {
        requestId = request.id;
      },
    });
    const canary = runtimeSecret();
    const pending = client.get('disconnect-provider').catch((error: unknown) => error);
    expect(client.pendingCount).toBe(1);
    client.disconnect();
    const disconnected = await pending;

    expect(disconnected).toMatchObject({
      code: 'credential-host-disconnected',
      message: 'Credential host disconnected',
    });
    expect(client.pendingCount).toBe(0);

    let lateError: unknown;
    try {
      client.consume({
        version: 1,
        kind: 'host-response',
        id: 'late-host-response',
        correlationId: requestId,
        sequence: 1,
        payload: {
          found: true,
          credential: {
            type: 'oauth',
            access: canary,
            refresh: runtimeSecret(),
            expires: Date.now() + 60_000,
          },
        },
      });
    } catch (error) {
      lateError = error;
    }
    expect(lateError).toMatchObject({
      code: 'credential-response-rejected',
      message: 'Credential response rejected',
    });
    expect(String(lateError).includes(canary)).toBe(false);
  });

  it('contains responses before ordinary routing and rejects duplicate or wrong-kind correlations', async () => {
    const router = new SidecarRouter();
    const requests: ProtocolEnvelope[] = [];
    const client = new HostRequestClient({ router, write: (request) => requests.push(request) });
    let ordinaryRoutes = 0;
    const dispatch = (envelope: ProtocolEnvelope) => {
      if (!client.consume(envelope)) ordinaryRoutes += 1;
    };

    const first = client.get('contained-provider');
    const firstResponse: ProtocolEnvelope = {
      version: 1,
      kind: 'host-response',
      id: 'contained-response-1',
      correlationId: requests[0]!.id,
      sequence: 1,
      payload: { found: false },
    };
    dispatch(firstResponse);
    await expect(first).resolves.toBeUndefined();
    expect(ordinaryRoutes).toBe(0);

    let delayedWrongKindRejected = false;
    try {
      dispatch({
        version: 1,
        kind: 'response',
        id: 'contained-wrong-kind-delayed',
        correlationId: requests[0]!.id,
        sequence: 2,
        payload: {},
      });
    } catch (error) {
      delayedWrongKindRejected = error instanceof HostRequestError
        && error.code === 'credential-response-rejected';
    }
    expect(delayedWrongKindRejected).toBe(true);

    let duplicateRejected = false;
    try {
      dispatch({ ...firstResponse, id: 'contained-response-duplicate', sequence: 3 });
    } catch (error) {
      duplicateRejected = error instanceof HostRequestError
        && error.code === 'credential-response-rejected';
    }
    expect(duplicateRejected).toBe(true);

    const second = client.get('wrong-kind-provider').catch((error: unknown) => error);
    let wrongKindRejected = false;
    try {
      dispatch({
        version: 1,
        kind: 'response',
        id: 'wrong-kind-response',
        correlationId: requests[1]!.id,
        sequence: 4,
        payload: {},
      });
    } catch (error) {
      wrongKindRejected = error instanceof HostRequestError
        && error.code === 'credential-response-rejected';
    }
    expect(wrongKindRejected).toBe(true);
    expect(await second).toMatchObject({ code: 'credential-response-rejected' });
    expect(ordinaryRoutes).toBe(0);
  });

  it('uses exact stable host errors and never reflects a malformed private error', async () => {
    const router = new SidecarRouter();
    const requests: ProtocolEnvelope[] = [];
    const client = new HostRequestClient({ router, write: (request) => requests.push(request) });
    const unavailable = client.list().catch((error: unknown) => error);
    client.consume({
      version: 1,
      kind: 'host-response',
      id: 'unavailable-response',
      correlationId: requests[0]!.id,
      sequence: 1,
      payload: {},
      error: {
        category: 'unavailable',
        message: 'Credential store unavailable',
        retryable: true,
      },
    });
    expect(await unavailable).toMatchObject({
      code: 'credential-store-unavailable',
      message: 'Credential store unavailable',
      retryable: true,
    });

    const canary = runtimeSecret();
    const malformed = client.get('malformed-provider').catch((error: unknown) => error);
    let protocolFailure: unknown;
    try {
      client.consume({
        version: 1,
        kind: 'host-response',
        id: 'malformed-error-response',
        correlationId: requests[1]!.id,
        sequence: 2,
        payload: {},
        error: {
          category: 'internal',
          message: canary,
          retryable: false,
        },
      });
    } catch (error) {
      protocolFailure = error;
    }
    const rejected = await malformed;
    expect(protocolFailure).toMatchObject({ code: 'credential-response-rejected' });
    expect(rejected).toMatchObject({ code: 'credential-response-rejected' });
    expect(`${String(protocolFailure)}${String(rejected)}`.includes(canary)).toBe(false);
  });

  it('rejects an over-limit metadata response list', async () => {
    const requests: ProtocolEnvelope[] = [];
    const client = new HostRequestClient({
      router: new SidecarRouter(),
      write: (request) => requests.push(request),
    });
    const pending = client.list().catch((error: unknown) => error);
    expect(() => client.consume({
      version: 1,
      kind: 'host-response',
      id: 'over-limit-list-response',
      correlationId: requests[0]!.id,
      sequence: 1,
      payload: {
        entries: Array.from(
          { length: CREDENTIAL_PROXY_LIMITS.maxListEntries + 1 },
          (_, index) => ({ providerId: `provider-${index}`, type: 'api_key' }),
        ),
      },
    })).toThrow('Credential response rejected');
    expect(await pending).toMatchObject({ code: 'credential-response-rejected' });
  });

  it('bounds pending work, cancels it, and times out without replay', async () => {
    vi.useFakeTimers();
    const router = new SidecarRouter();
    let writes = 0;
    const client = new HostRequestClient({
      router,
      write: () => {
        writes += 1;
      },
      maxPending: 1,
      timeoutMs: 25,
    });
    const pending = client.get('timeout-provider').catch((error: unknown) => error);
    const atCapacity = await client.get('capacity-provider').catch((error: unknown) => error);
    expect(atCapacity).toMatchObject({ code: 'credential-host-capacity' });
    await vi.advanceTimersByTimeAsync(25);
    expect(await pending).toMatchObject({ code: 'credential-request-timeout' });
    expect(client.pendingCount).toBe(0);
    expect(writes).toBe(1);

    const cancelled = client.get('cancelled-provider').catch((error: unknown) => error);
    client.abortAll();
    expect(await cancelled).toMatchObject({ code: 'credential-request-cancelled' });
    expect(client.pendingCount).toBe(0);
    expect(writes).toBe(2);
  });

  it('times out, aborts and disconnects credential.set without replaying mutations', async () => {
    vi.useFakeTimers();
    const credential = apiCredential().credential;

    const timeoutRequests: ProtocolEnvelope[] = [];
    const timeoutClient = new HostRequestClient({
      router: new SidecarRouter(),
      write: (request) => timeoutRequests.push(request),
      timeoutMs: 20,
    });
    const timedOut = timeoutClient.set('set-timeout-provider', credential)
      .catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(20);
    expect(await timedOut).toMatchObject({ code: 'credential-request-timeout' });
    expect(timeoutRequests).toHaveLength(1);
    expect(() => timeoutClient.consume({
      version: 1,
      kind: 'response',
      id: 'late-timeout-wrong-kind',
      correlationId: timeoutRequests[0]!.id,
      sequence: 1,
      payload: {},
    })).toThrow('Credential response rejected');
    expect(timeoutRequests).toHaveLength(1);

    const abortRequests: ProtocolEnvelope[] = [];
    const abortClient = new HostRequestClient({
      router: new SidecarRouter(),
      write: (request) => abortRequests.push(request),
    });
    const aborted = abortClient.set('set-abort-provider', credential)
      .catch((error: unknown) => error);
    abortClient.abortAll();
    expect(await aborted).toMatchObject({ code: 'credential-request-cancelled' });
    expect(() => abortClient.consume({
      version: 1,
      kind: 'response',
      id: 'late-abort-wrong-kind',
      correlationId: abortRequests[0]!.id,
      sequence: 2,
      payload: {},
    })).toThrow('Credential response rejected');
    expect(abortRequests).toHaveLength(1);

    const disconnectRequests: ProtocolEnvelope[] = [];
    const disconnectClient = new HostRequestClient({
      router: new SidecarRouter(),
      write: (request) => disconnectRequests.push(request),
    });
    const disconnected = disconnectClient.set('set-disconnect-provider', credential)
      .catch((error: unknown) => error);
    disconnectClient.disconnect();
    expect(await disconnected).toMatchObject({ code: 'credential-host-disconnected' });
    expect(() => disconnectClient.consume({
      version: 1,
      kind: 'response',
      id: 'late-disconnect-wrong-kind',
      correlationId: disconnectRequests[0]!.id,
      sequence: 3,
      payload: {},
    })).toThrow('Credential response rejected');
    expect(disconnectRequests).toHaveLength(1);
  });

  it('keeps retired private correlations bounded with fixed-cap eviction', async () => {
    const requests: ProtocolEnvelope[] = [];
    const client = new HostRequestClient({
      router: new SidecarRouter(),
      write: (request) => requests.push(request),
    });
    let firstRequestId = '';
    let lastRequestId = '';
    for (
      let index = 0;
      index < CREDENTIAL_PROXY_LIMITS.maxRetiredCorrelations + 1;
      index += 1
    ) {
      const pending = client.get(`retired-provider-${index}`);
      const request = requests.at(-1)!;
      firstRequestId ||= request.id;
      lastRequestId = request.id;
      client.consume({
        version: 1,
        kind: 'host-response',
        id: `retired-response-${index}`,
        correlationId: request.id,
        sequence: index + 1,
        payload: { found: false },
      });
      await pending;
    }
    expect(client.retiredCorrelationCount)
      .toBe(CREDENTIAL_PROXY_LIMITS.maxRetiredCorrelations);
    expect(client.consume({
      version: 1,
      kind: 'response',
      id: 'evicted-retired-correlation',
      correlationId: firstRequestId,
      sequence: 600,
      payload: {},
    })).toBe(false);
    expect(() => client.consume({
      version: 1,
      kind: 'response',
      id: 'retained-retired-correlation',
      correlationId: lastRequestId,
      sequence: 601,
      payload: {},
    })).toThrow('Credential response rejected');
  });

  it('makes callback-time protocol output failure fatal to private work', async () => {
    const router = new SidecarRouter();
    let captured: Buffer | undefined;
    let settle: ((error?: Error | null) => void) | undefined;
    let client!: HostRequestClient;
    const write = createZeroingProtocolWriter((bytes, settled) => {
      captured = bytes;
      settle = settled;
    }, () => client.disconnect());
    client = new HostRequestClient({ router, write });

    const pending = client.set('writer-failure-provider', apiCredential().credential)
      .catch((error: unknown) => error);
    expect(client.pendingCount).toBe(1);
    const sequenceAtFailure = router.currentSequence;
    settle?.(new Error('callback-time-output-failure'));

    expect(await pending).toMatchObject({ code: 'credential-host-disconnected' });
    expect(client.pendingCount).toBe(0);
    expect(captured?.every((byte) => byte === 0)).toBe(true);
    expect(write.failed).toBe(true);
    await expect(client.get('writer-failure-late-provider'))
      .rejects.toMatchObject({ code: 'credential-host-disconnected' });
    expect(router.currentSequence).toBe(sequenceAtFailure);
    expect(() => write({
      version: 1,
      kind: 'host-request',
      id: 'writer-failure-late-envelope',
      sequence: sequenceAtFailure + 1,
      payload: { method: 'credential.list' },
    })).toThrow('protocol-write-failed');
  });

  it('clears the practical mutable output buffer after the sink settles', () => {
    const canary = runtimeSecret();
    let captured: Buffer | undefined;
    let settle: ((error?: Error | null) => void) | undefined;
    const write = createZeroingProtocolWriter((bytes, settled) => {
      captured = bytes;
      settle = settled;
    });
    write({
      version: 1,
      kind: 'host-request',
      id: 'zeroing-request',
      sequence: 1,
      payload: {
        method: 'credential.set',
        providerId: 'zeroing-provider',
        credential: { type: 'api_key', key: canary },
      },
    });

    expect(captured?.includes(Buffer.from(canary))).toBe(true);
    settle?.();
    expect(captured?.every((byte) => byte === 0)).toBe(true);
  });
});
