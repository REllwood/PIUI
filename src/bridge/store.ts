import type { ProductSnapshot } from '../domain/types';
import { emptyProductSnapshot, productFixture } from '../domain/fixtures';
import { validateBridgeProductSnapshot, type BridgeProductSnapshot } from './snapshot';

export type BridgeStoreState = Readonly<{
  status: 'restoring' | 'ready' | 'resynchronising' | 'unavailable';
  generation: number;
  sequence: number;
  product: ProductSnapshot;
  lastError?: string;
}>;

export type BridgeEvent = Readonly<{
  generation: number;
  sequence: number;
  patch: Partial<ProductSnapshot>;
}>;

export type BridgeStoreOptions = Readonly<{
  initialSnapshot?: ProductSnapshot;
  requestSnapshot?: (afterSequence: number) => Promise<unknown>;
  requestAnimationFrame?: (callback: FrameRequestCallback) => number;
  cancelAnimationFrame?: (handle: number) => void;
}>;

type Listener = () => void;

const defaultRequestFrame: (callback: FrameRequestCallback) => number =
  typeof requestAnimationFrame === 'function'
    ? requestAnimationFrame
    : (callback) => Number(setTimeout(() => callback(performance.now()), 0));
const defaultCancelFrame: (handle: number) => void =
  typeof cancelAnimationFrame === 'function'
    ? cancelAnimationFrame
    : (handle) => clearTimeout(handle);

export class BridgeStore {
  #state: BridgeStoreState;
  #listeners = new Set<Listener>();
  #queuedPatch: Partial<ProductSnapshot> | null = null;
  #frame: number | null = null;
  readonly #requestSnapshot?: (afterSequence: number) => Promise<unknown>;
  readonly #requestAnimationFrame: (callback: FrameRequestCallback) => number;
  readonly #cancelAnimationFrame: (handle: number) => void;

  constructor(options: BridgeStoreOptions = {}) {
    const fixtureRequested =
      import.meta.env.DEV &&
      typeof window !== 'undefined' &&
      new URLSearchParams(window.location.search).has('fixture');
    const product =
      options.initialSnapshot ?? (fixtureRequested ? productFixture : emptyProductSnapshot);
    this.#state = Object.freeze({
      status: 'ready',
      generation: product.generation,
      sequence: product.sequence,
      product,
    });
    this.#requestSnapshot = options.requestSnapshot;
    this.#requestAnimationFrame = options.requestAnimationFrame ?? defaultRequestFrame;
    this.#cancelAnimationFrame = options.cancelAnimationFrame ?? defaultCancelFrame;
  }

  getSnapshot = (): BridgeStoreState => this.#state;

  subscribe = (listener: Listener): (() => void) => {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  };

  receive(event: BridgeEvent): 'accepted' | 'stale' | 'gap' {
    if (event.generation < this.#state.generation) return 'stale';
    if (event.generation > this.#state.generation) {
      void this.resynchronise();
      return 'gap';
    }
    if (event.sequence <= this.#state.sequence) return 'stale';
    if (event.sequence !== this.#state.sequence + 1) {
      void this.resynchronise();
      return 'gap';
    }
    const streamOnly = Object.keys(event.patch).every(
      (key) => key === 'messages' || key === 'turnStatus',
    );
    if (streamOnly) {
      this.#queuedPatch = { ...this.#queuedPatch, ...event.patch };
      this.#state = Object.freeze({ ...this.#state, sequence: event.sequence });
      this.#scheduleFrame();
      return 'accepted';
    }
    this.#replace({
      ...this.#state,
      sequence: event.sequence,
      product: Object.freeze({ ...this.#state.product, ...event.patch, sequence: event.sequence }),
    });
    return 'accepted';
  }

  async resynchronise(): Promise<void> {
    if (this.#state.status === 'resynchronising') return;
    if (!this.#requestSnapshot) {
      this.#replace({
        ...this.#state,
        status: 'unavailable',
        lastError: 'bridge-snapshot-unavailable',
      });
      return;
    }
    this.#replace({ ...this.#state, status: 'resynchronising' });
    try {
      const raw = await this.#requestSnapshot(this.#state.sequence);
      this.applySnapshot(validateBridgeProductSnapshot(raw));
    } catch (error) {
      const message = error instanceof Error ? error.message : 'bridge-resynchronisation-failed';
      this.#replace({ ...this.#state, status: 'unavailable', lastError: message });
    }
  }

  applySnapshot(snapshot: BridgeProductSnapshot): boolean {
    if (snapshot.generation < this.#state.generation) return false;
    if (snapshot.generation === this.#state.generation && snapshot.sequence < this.#state.sequence)
      return false;
    this.#cancelPendingFrame();
    this.#replace({
      status: 'ready',
      generation: snapshot.generation,
      sequence: snapshot.sequence,
      product: snapshot.product,
    });
    return true;
  }

  updateLocalFixture(patch: Partial<ProductSnapshot>): void {
    this.#replace({
      ...this.#state,
      product: Object.freeze({ ...this.#state.product, ...patch }),
    });
  }

  destroy(): void {
    this.#cancelPendingFrame();
    this.#listeners.clear();
  }

  #scheduleFrame(): void {
    if (this.#frame !== null) return;
    this.#frame = this.#requestAnimationFrame(() => {
      this.#frame = null;
      const patch = this.#queuedPatch;
      this.#queuedPatch = null;
      if (!patch) return;
      this.#replace({
        ...this.#state,
        product: Object.freeze({
          ...this.#state.product,
          ...patch,
          sequence: this.#state.sequence,
        }),
      });
    });
  }

  #cancelPendingFrame(): void {
    if (this.#frame !== null) this.#cancelAnimationFrame(this.#frame);
    this.#frame = null;
    this.#queuedPatch = null;
  }

  #replace(next: BridgeStoreState): void {
    this.#state = Object.freeze(next);
    for (const listener of this.#listeners) listener();
  }
}

export const productionBridgeStore = new BridgeStore();
