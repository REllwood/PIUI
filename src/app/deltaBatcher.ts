export type FrameScheduler = Readonly<{
  request: (callback: () => void) => number;
  cancel: (handle: number) => void;
}>;

const animationFrames: FrameScheduler = Object.freeze({
  request: (callback: () => void) => requestAnimationFrame(() => callback()),
  cancel: (handle: number) => cancelAnimationFrame(handle),
});

export type DeltaBatcher = Readonly<{
  push: (text: string) => void;
  flush: () => void;
  cancel: () => void;
}>;

// Collects streamed text and applies it at most once per animation frame, so a fast
// stream patches the store (and re-renders the app) once per frame rather than once per
// token. Callers flush before any event that must see the full text, such as a tool
// update, a failure or completion.
export function createDeltaBatcher(
  apply: (text: string) => void,
  scheduler: FrameScheduler = animationFrames,
): DeltaBatcher {
  let pending = '';
  let handle: number | null = null;
  const flush = () => {
    if (handle !== null) {
      scheduler.cancel(handle);
      handle = null;
    }
    if (!pending) return;
    const text = pending;
    pending = '';
    apply(text);
  };
  return Object.freeze({
    push(text: string) {
      if (!text) return;
      pending += text;
      if (handle !== null) return;
      handle = scheduler.request(() => {
        handle = null;
        flush();
      });
    },
    flush,
    cancel() {
      if (handle !== null) scheduler.cancel(handle);
      handle = null;
      pending = '';
    },
  });
}
