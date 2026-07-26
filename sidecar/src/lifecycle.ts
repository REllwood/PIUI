import { spawn } from 'node:child_process';

export type AbortableWork = ReadonlyMap<string, AbortController>;

export function installParentPipeLifecycle(
  work: AbortableWork,
  onDisconnect: () => void = () => undefined,
): void {
  let closed = false;
  const parentPipeLiveness = setInterval(() => undefined, 60_000);

  const close = () => {
    if (closed) return;
    closed = true;
    clearInterval(parentPipeLiveness);
    try {
      onDisconnect();
    } catch {
      process.exitCode = 70;
    }
    for (const controller of work.values()) controller.abort();

    const exitCode = process.exitCode ?? 0;
    if (process.env.PIUI_OWN_PROCESS_GROUP !== '1' || process.platform === 'win32') {
      process.exit(exitCode);
    }

    // Rust places the sidecar in a dedicated process group. If Rust disappears,
    // no parent remains to escalate cleanup, so launch a tiny detached watchdog
    // in its own group before terminating this complete owned group. Cooperative
    // descendants receive SIGTERM; the watchdog removes any straggler with
    // SIGKILL, then exits. A SIGTERM handler preserves intentional exit codes.
    try {
      const watchdog = spawn(
        process.execPath,
        [
          '-e',
          "const g=Number(process.argv[1]);setTimeout(()=>{try{process.kill(-g,'SIGKILL')}catch{}},250)",
          String(process.pid),
        ],
        { detached: true, stdio: 'ignore', env: {} },
      );
      watchdog.unref();
    } catch {
      // The immediate group signal below still provides bounded cleanup.
    }

    process.once('SIGTERM', () => process.exit(exitCode));
    try {
      process.kill(-process.pid, 'SIGTERM');
    } catch {
      process.exit(exitCode);
    }
  };

  // The inherited pipe is the sidecar's authority and lifetime token. There is
  // no orphan mode: EOF, parent loss or an explicitly destroyed input closes
  // all work and terminates with the previously selected exit status.
  process.stdin.resume();
  process.stdin.once('end', close);
  process.stdin.once('close', close);
}
