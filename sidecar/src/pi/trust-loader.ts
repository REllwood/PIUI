import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import type { TrustedResourceCounts } from './public-sdk.js';

const WORKER_TIMEOUT_MS = 22_000;
const MAX_ACTIVE_WORKERS = 8;

export class TrustLoaderError extends Error {
  constructor(readonly launched: boolean) {
    super(launched ? 'workspace-execution-uncertain' : 'workspace-worker-unavailable');
    this.name = 'TrustLoaderError';
    this.stack = `${this.name}: ${this.message}`;
  }
}

async function terminateWorkerGroup(child: ChildProcess): Promise<void> {
  const pid = child.pid;
  if (!pid) return;
  if (process.platform !== 'win32') {
    try { process.kill(-pid, 'SIGTERM'); } catch { /* already absent */ }
    await new Promise((resolve) => setTimeout(resolve, 50));
    try { process.kill(-pid, 'SIGKILL'); } catch { /* already absent */ }
  } else {
    try { child.kill('SIGKILL'); } catch { /* already absent */ }
  }
}

/**
 * Process isolation protects PIUI protocol and credential state; it is not an
 * OS sandbox. Trusted code still runs as the same macOS user and can exercise
 * that user's ambient read authority. This gate's pinned Node permission model
 * denies child processes, addons and WASI, so project code cannot create a
 * descendant here; owned worker/executor processes are still group-terminated.
 * A future full trusted-extension runtime needs its own explicit isolation and
 * descendant policy. Revocation removes PIUI authority and cannot undo effects.
 */
export class TrustLoaderSupervisor {
  readonly #workers = new Map<number, ChildProcess>();
  readonly #workerEntrypoint: string;
  readonly #timeoutMs: number;
  #disconnected = false;

  constructor(
    workerEntrypoint = fileURLToPath(new URL('./trust-loader-worker.js', import.meta.url)),
    timeoutMs = WORKER_TIMEOUT_MS,
  ) {
    this.#workerEntrypoint = workerEntrypoint;
    this.#timeoutMs = timeoutMs;
  }

  run(snapshotRoot: string, agentRoot: string): Promise<TrustedResourceCounts> {
    if (this.#disconnected || this.#workers.size >= MAX_ACTIVE_WORKERS) {
      return Promise.reject(new TrustLoaderError(false));
    }
    let child: ChildProcess;
    try {
      child = spawn(process.execPath, [this.#workerEntrypoint, snapshotRoot, agentRoot, String(process.pid)], {
        cwd: snapshotRoot,
        detached: process.platform !== 'win32',
        env: {
          HOME: agentRoot,
          NODE_ENV: 'production',
          PI_CODING_AGENT_DIR: agentRoot,
          PI_OFFLINE: '1',
        },
        stdio: 'ignore',
      });
    } catch {
      return Promise.reject(new TrustLoaderError(false));
    }

    return new Promise((resolve, reject) => {
      let launched = false;
      let settled = false;
      let timer: ReturnType<typeof setTimeout>;
      const settle = async (success: boolean) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (child.pid) this.#workers.delete(child.pid);
        await terminateWorkerGroup(child);
        if (success && launched && !this.#disconnected) {
          // Worker exit 0 is produced only after its child supplied the exact
          // challenge-authenticated ready/completion transcript. Ordinary
          // executor exit 0, extra bytes or an incomplete transcript are fatal.
          // Counts remain unknown because same-user code could forge a file.
          resolve(Object.freeze({
            extensions: 0,
            skills: 0,
            prompts: 0,
            themes: 0,
            packages: 0,
            truncated: true,
          }));
        } else {
          reject(new TrustLoaderError(launched));
        }
      };
      child.once('spawn', () => {
        launched = true;
        if (child.pid) this.#workers.set(child.pid, child);
      });
      child.once('error', () => { void settle(false); });
      child.once('exit', (code, signal) => {
        void settle(signal === null && code === 0);
      });
      timer = setTimeout(() => { void settle(false); }, this.#timeoutMs);
      timer.unref?.();
    });
  }

  disconnect(): void {
    if (this.#disconnected) return;
    this.#disconnected = true;
    for (const worker of this.#workers.values()) {
      const pid = worker.pid;
      if (pid && process.platform !== 'win32') {
        try { process.kill(-pid, 'SIGKILL'); } catch { /* already absent */ }
      } else {
        try { worker.kill('SIGKILL'); } catch { /* already absent */ }
      }
    }
    this.#workers.clear();
  }
}

export const TRUST_LOADER_LIMITS = Object.freeze({
  maxActiveWorkers: MAX_ACTIVE_WORKERS,
  timeoutMs: WORKER_TIMEOUT_MS,
});
