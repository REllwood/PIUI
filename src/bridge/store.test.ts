import { describe, expect, it, vi } from 'vitest';
import { productFixture } from '../domain/fixtures';
import { BridgeStore } from './store';

describe('BridgeStore', () => {
  it('batches stream-only patches into one visual commit', () => {
    const frames: FrameRequestCallback[] = [];
    const listener = vi.fn();
    const store = new BridgeStore({
      initialSnapshot: productFixture,
      requestAnimationFrame: (callback) => {
        frames.push(callback);
        return frames.length;
      },
      cancelAnimationFrame: () => undefined,
    });
    store.subscribe(listener);

    expect(store.receive({ generation: 1, sequence: 19, patch: { turnStatus: 'streaming' } })).toBe(
      'accepted',
    );
    expect(store.receive({ generation: 1, sequence: 20, patch: { turnStatus: 'complete' } })).toBe(
      'accepted',
    );
    expect(frames).toHaveLength(1);
    expect(listener).not.toHaveBeenCalled();
    frames[0]?.(performance.now());
    expect(store.getSnapshot().product.turnStatus).toBe('complete');
    expect(store.getSnapshot().product.sequence).toBe(20);
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('requests one validated snapshot after a gap and rejects stale snapshots', async () => {
    const requestSnapshot = vi.fn(async (afterSequence: number) => ({
      generation: 1,
      sequence: 22,
      product: Object.freeze({ ...productFixture, sequence: 22 }),
      afterSequence,
    }));
    const store = new BridgeStore({
      initialSnapshot: productFixture,
      requestSnapshot,
      requestAnimationFrame: () => 1,
      cancelAnimationFrame: () => undefined,
    });
    expect(store.receive({ generation: 1, sequence: 21, patch: { turnStatus: 'complete' } })).toBe(
      'gap',
    );
    await vi.waitFor(() => expect(requestSnapshot).toHaveBeenCalledTimes(1));
    await vi.waitFor(() => expect(store.getSnapshot().status).toBe('ready'));
    expect(store.getSnapshot().sequence).toBe(22);
    expect(
      store.applySnapshot({
        generation: 1,
        sequence: 20,
        product: { ...productFixture, sequence: 20 },
      }),
    ).toBe(false);
  });
});
