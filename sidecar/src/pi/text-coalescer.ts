export const TEXT_COALESCE_MAX_BYTES = 4_096;
export const TEXT_COALESCE_MAX_DELAY_MS = 32;

/**
 * Pi reports assistant text one provider token at a time, which would put one
 * protocol frame on the wire per token. Consecutive deltas are gathered and
 * emitted once 32 ms have passed since the first of them or once 4 KiB of UTF-8
 * is waiting, whichever comes first. Callers flush before tool activity and
 * before the terminal event so ordering is unchanged. A timed or size flush
 * never ends on a high surrogate: that half waits for its pair.
 */
export class TextDeltaCoalescer {
  readonly #emit: (text: string) => void;
  #text = '';
  #bytes = 0;
  #timer: ReturnType<typeof setTimeout> | undefined;

  constructor(emit: (text: string) => void) {
    this.#emit = emit;
  }

  push(delta: string): void {
    if (!delta) return;
    this.#text += delta;
    this.#bytes += Buffer.byteLength(delta, 'utf8');
    if (this.#bytes >= TEXT_COALESCE_MAX_BYTES) this.#release(false);
    else this.#timer ??= setTimeout(() => this.#release(false), TEXT_COALESCE_MAX_DELAY_MS);
  }

  /** Emits everything waiting, including an unpaired trailing surrogate. */
  flush(): void {
    this.#release(true);
  }

  /** Drops anything waiting without emitting it. */
  dispose(): void {
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = undefined;
    this.#text = '';
    this.#bytes = 0;
  }

  #release(final: boolean): void {
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = undefined;
    let text = this.#text;
    let held = '';
    const last = text.charCodeAt(text.length - 1);
    if (!final && last >= 0xd800 && last <= 0xdbff) {
      held = text.slice(-1);
      text = text.slice(0, -1);
    }
    // A held half restarts no timer: its pair's push or the final flush sends it.
    this.#text = held;
    this.#bytes = held ? Buffer.byteLength(held, 'utf8') : 0;
    if (text) this.#emit(text);
  }
}
