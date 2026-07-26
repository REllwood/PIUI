import {
  CREDENTIAL_PROXY_LIMITS,
  HostRequestError,
  assertCredentialProviderId,
  type CredentialHostGeneration,
  type CredentialHostTransport,
} from '../bridge/host-requests.js';
import type {
  PublicCredential,
  PublicCredentialInfo,
  PublicCredentialStore,
} from '../pi/public-sdk.js';

export type PiCredentialStoreOptions = {
  maxProviderQueues?: number;
  maxQueuedOperationsPerProvider?: number;
  maxQueuedOperationsTotal?: number;
};

type ProviderQueue = {
  readonly generation: CredentialHostGeneration;
  count: number;
  tail: Promise<unknown>;
};

function validateLimit(value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new HostRequestError('credential-request-rejected');
  }
  return value;
}

function generationError(generation: CredentialHostGeneration): HostRequestError {
  const reason = generation.signal.reason;
  if (reason instanceof HostRequestError) return new HostRequestError(reason.code);
  return new HostRequestError('credential-request-cancelled');
}

function assertGenerationActive(generation: CredentialHostGeneration): void {
  if (generation.signal.aborted) throw generationError(generation);
}

/**
 * Public-SDK-compatible credential store backed by the private Rust host.
 * JavaScript credential objects remain GC-managed; only mutable protocol wire
 * buffers have a deterministic zeroing point.
 */
export class PiCredentialStore implements PublicCredentialStore {
  readonly #host: CredentialHostTransport;
  readonly #maxProviderQueues: number;
  readonly #maxQueuedOperationsPerProvider: number;
  readonly #maxQueuedOperationsTotal: number;
  readonly #queues = new Map<string, ProviderQueue>();
  #queuedOperationCount = 0;

  constructor(host: CredentialHostTransport, options: PiCredentialStoreOptions = {}) {
    this.#maxProviderQueues = validateLimit(
      options.maxProviderQueues ?? CREDENTIAL_PROXY_LIMITS.maxProviderQueues,
      CREDENTIAL_PROXY_LIMITS.maxProviderQueues,
    );
    this.#maxQueuedOperationsPerProvider = validateLimit(
      options.maxQueuedOperationsPerProvider
        ?? CREDENTIAL_PROXY_LIMITS.maxQueuedOperationsPerProvider,
      CREDENTIAL_PROXY_LIMITS.maxQueuedOperationsPerProvider,
    );
    this.#maxQueuedOperationsTotal = validateLimit(
      options.maxQueuedOperationsTotal
        ?? CREDENTIAL_PROXY_LIMITS.maxQueuedOperationsTotal,
      CREDENTIAL_PROXY_LIMITS.maxQueuedOperationsTotal,
    );
    this.#host = host;
  }

  /** @internal Test observability only; contains counts, never provider IDs. */
  get queueCountsForTest(): Readonly<{ providers: number; operations: number }> {
    return Object.freeze({
      providers: this.#queues.size,
      operations: this.#queuedOperationCount,
    });
  }

  read(providerId: string): Promise<PublicCredential | undefined> {
    return this.#enqueue(providerId, () => this.#host.get(providerId));
  }

  list(): Promise<readonly PublicCredentialInfo[]> {
    return this.#host.list();
  }

  modify(
    providerId: string,
    fn: (current: PublicCredential | undefined) => Promise<PublicCredential | undefined>,
  ): Promise<PublicCredential | undefined> {
    return this.#enqueue(providerId, async (generation) => {
      const current = await this.#host.get(providerId);
      assertGenerationActive(generation);
      const next = await fn(current);
      assertGenerationActive(generation);
      if (next === undefined) return current;
      await this.#host.set(providerId, next);
      return next;
    });
  }

  delete(providerId: string): Promise<void> {
    return this.#enqueue(providerId, () => this.#host.remove(providerId));
  }

  #enqueue<T>(
    providerId: string,
    task: (generation: CredentialHostGeneration) => Promise<T>,
  ): Promise<T> {
    assertCredentialProviderId(providerId);
    const generation = this.#host.credentialGeneration;
    if (generation.signal.aborted) return Promise.reject(generationError(generation));

    const current = this.#queues.get(providerId);
    const queue = current?.generation === generation ? current : undefined;
    if (
      (!queue && this.#queues.size >= this.#maxProviderQueues)
      || (queue?.count ?? 0) >= this.#maxQueuedOperationsPerProvider
      || this.#queuedOperationCount >= this.#maxQueuedOperationsTotal
    ) {
      return Promise.reject(new HostRequestError('credential-host-capacity'));
    }

    const state = queue ?? {
      generation,
      count: 0,
      tail: Promise.resolve(),
    };
    const previous = state.count === 0 ? undefined : state.tail;
    state.count += 1;
    this.#queuedOperationCount += 1;

    const execution = (async () => {
      await previous?.catch(() => undefined);
      assertGenerationActive(generation);
      return task(generation);
    })();

    let released = false;
    let operation!: Promise<T>;
    operation = new Promise<T>((resolve, reject) => {
      const release = () => {
        if (released) return false;
        released = true;
        generation.signal.removeEventListener('abort', onAbort);
        state.count -= 1;
        this.#queuedOperationCount -= 1;
        if (
          state.count === 0
          && state.tail === operation
          && this.#queues.get(providerId) === state
        ) {
          this.#queues.delete(providerId);
        }
        return true;
      };
      const onAbort = () => {
        if (release()) reject(generationError(generation));
      };

      generation.signal.addEventListener('abort', onAbort, { once: true });
      execution.then(
        (value) => {
          if (release()) resolve(value);
        },
        (error: unknown) => {
          if (release()) reject(error);
        },
      );
    });

    state.tail = operation;
    this.#queues.set(providerId, state);
    return operation;
  }
}
