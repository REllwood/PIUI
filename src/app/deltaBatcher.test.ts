import { describe, expect, it, vi } from 'vitest';
import { createDeltaBatcher, type FrameScheduler } from './deltaBatcher';

function manualFrames() {
  const callbacks = new Map<number, () => void>();
  let next = 1;
  const scheduler: FrameScheduler = {
    request: (callback) => {
      const handle = next++;
      callbacks.set(handle, callback);
      return handle;
    },
    cancel: (handle) => {
      callbacks.delete(handle);
    },
  };
  const runFrame = () => {
    const pending = [...callbacks.values()];
    callbacks.clear();
    for (const callback of pending) callback();
  };
  return { scheduler, runFrame, pendingFrames: () => callbacks.size };
}

describe('delta batching', () => {
  it('applies every delta in a frame as one update', () => {
    const frames = manualFrames();
    const apply = vi.fn();
    const batcher = createDeltaBatcher(apply, frames.scheduler);
    batcher.push('Plan');
    batcher.push('ning a ');
    batcher.push('change');
    expect(apply).not.toHaveBeenCalled();
    expect(frames.pendingFrames()).toBe(1);
    frames.runFrame();
    expect(apply).toHaveBeenCalledTimes(1);
    expect(apply).toHaveBeenCalledWith('Planning a change');
  });

  it('flushes synchronously so a terminal event sees the full text', () => {
    const frames = manualFrames();
    const apply = vi.fn();
    const batcher = createDeltaBatcher(apply, frames.scheduler);
    batcher.push('Partial answer');
    batcher.flush();
    expect(apply).toHaveBeenCalledWith('Partial answer');
    expect(frames.pendingFrames()).toBe(0);
    frames.runFrame();
    expect(apply).toHaveBeenCalledTimes(1);
  });

  it('drops pending text when cancelled', () => {
    const frames = manualFrames();
    const apply = vi.fn();
    const batcher = createDeltaBatcher(apply, frames.scheduler);
    batcher.push('Never shown');
    batcher.cancel();
    frames.runFrame();
    batcher.flush();
    expect(apply).not.toHaveBeenCalled();
  });
});
