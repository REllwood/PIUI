import { expect, test } from '@playwright/test';
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createInterface } from 'node:readline';
import { resolve } from 'node:path';

type Envelope = {
  kind: string;
  id: string;
  correlationId?: string;
  sequence: number;
  payload: Record<string, unknown>;
};

const projectRoot = resolve(import.meta.dirname, '../..');
const cargoManifest = resolve(projectRoot, 'src-tauri/Cargo.toml');
const harness = resolve(projectRoot, 'src-tauri/target/debug/stream-harness');

test.setTimeout(60_000);

test('streams through Rust and acknowledges cancellation before the terminal', async ({ page }) => {
  // Staging first also unlocks any prior read-only Tauri resource copies before
  // the build script refreshes them.
  execFileSync('pnpm', ['stage:sidecar'], { cwd: projectRoot, stdio: 'pipe' });
  execFileSync(
    'cargo',
    ['build', '--manifest-path', cargoManifest, '--bin', 'stream-harness'],
    { cwd: projectRoot, stdio: 'pipe' },
  );
  const child = spawn(harness, [], {
    cwd: projectRoot,
    env: { PATH: process.env.PATH ?? '' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const stderr: string[] = [];
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk: string) => stderr.push(chunk));

  const lines = createInterface({ input: child.stdout });
  const received: Envelope[] = [];
  let droppedDelta = false;
  let acknowledgementAt = 0;
  let acknowledgementResolve: ((accepted: boolean) => void) | undefined;
  const acknowledgement = new Promise<boolean>((resolveAcknowledgement) => {
    acknowledgementResolve = resolveAcknowledgement;
  });
  let terminalResolve: (() => void) | undefined;
  const terminal = new Promise<void>((resolveTerminal) => {
    terminalResolve = resolveTerminal;
  });
  let browserDelivery = Promise.resolve();
  lines.on('line', (line) => {
    const envelope = JSON.parse(line) as Envelope;
    received.push(envelope);
    if (envelope.kind === 'ack') {
      acknowledgementAt = Date.now();
      acknowledgementResolve?.(envelope.payload.accepted === true);
    }
    if (envelope.kind === 'event' && envelope.payload.terminal) {
      terminalResolve?.();
    }
    if (
      envelope.kind === 'event' &&
      envelope.payload.text === 'a safe ' &&
      !droppedDelta
    ) {
      droppedDelta = true;
    } else {
      browserDelivery = browserDelivery.then(() =>
        page.evaluate((payload) => {
          window.dispatchEvent(new CustomEvent('piui-bridge-envelope', { detail: payload }));
        }, envelope),
      );
    }
  });

  const write = (envelope: Envelope) => {
    child.stdin.write(`${JSON.stringify(envelope)}\n`);
  };
  await page.exposeFunction('__piuiStart', write);
  await page.exposeFunction('__piuiCancel', write);
  await page.exposeFunction('__piuiSend', write);
  await page.addInitScript(() => {
    const exposed = window as unknown as {
      __piuiStart: (envelope: Envelope) => Promise<void>;
      __piuiCancel: (envelope: Envelope) => Promise<void>;
      __piuiSend: (envelope: Envelope) => Promise<void>;
      __PIUI_STREAM_HARNESS__: {
        start: (envelope: Envelope) => Promise<void>;
        cancel: (envelope: Envelope) => Promise<void>;
        send: (envelope: Envelope) => Promise<void>;
      };
    };
    exposed.__PIUI_STREAM_HARNESS__ = {
      start: (envelope) => exposed.__piuiStart(envelope),
      cancel: (envelope) => exposed.__piuiCancel(envelope),
      send: (envelope) => exposed.__piuiSend(envelope),
    };
  });

  try {
    await page.goto('/?spike=stream');
    const output = page.getByTestId('stream-output');
    await expect(output).toContainText('Planning a safe local change', { timeout: 5_000 });
    expect(droppedDelta).toBe(true);
    expect(
      received.some(
        (envelope) => envelope.kind === 'response' && typeof envelope.payload.snapshot === 'object',
      ),
    ).toBe(true);

    const started = Date.now();
    await page.getByRole('button', { name: 'Stop' }).click();
    await expect.poll(() => acknowledgement).toBe(true);
    await expect(page.getByTestId('stream-terminal')).toHaveText('cancelled', {
      timeout: 1_000,
    });
    await terminal;
    expect(acknowledgementAt - started).toBeLessThan(1_000);
    expect(Date.now() - started).toBeLessThan(1_000);
    const ackIndex = received.findIndex((envelope) => envelope.kind === 'ack');
    const terminalIndex = received.findIndex(
      (envelope) => envelope.kind === 'event' && envelope.payload.terminal === 'cancelled',
    );
    expect(ackIndex).toBeGreaterThanOrEqual(0);
    expect(terminalIndex).toBeGreaterThan(ackIndex);

    const retained = await output.textContent();
    expect(retained).toBeTruthy();
    expect('Planning a safe local change…'.startsWith(retained ?? '')).toBe(true);
    expect(retained).not.toBe('Planning a safe local change…');
    expect(stderr.join('')).toBe('');
  } finally {
    await browserDelivery.catch(() => undefined);
    lines.close();
    child.stdin.end();
    await waitForExit(child);
  }
});

async function waitForExit(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (child.exitCode !== null) return;
  const exited = new Promise<void>((resolveExit) => child.once('exit', () => resolveExit()));
  const timeout = new Promise<void>((resolveTimeout) =>
    setTimeout(() => {
      child.kill('SIGKILL');
      resolveTimeout();
    }, 2_000),
  );
  await Promise.race([exited, timeout]);
}
