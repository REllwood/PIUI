import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import type { ProtocolEnvelope } from '@piui/protocol';

// Spawns the built sidecar (test:contract builds it first) and speaks the real
// JSONL protocol over its pipes.
const sidecar = resolve(import.meta.dirname, '../../sidecar');

type Harness = {
  child: ChildProcessWithoutNullStreams;
  frames: ProtocolEnvelope[];
  rawStdout: string[];
  send(envelope: ProtocolEnvelope): void;
  waitFor(
    predicate: (frame: ProtocolEnvelope) => boolean,
    label: string,
  ): Promise<ProtocolEnvelope>;
};

const running: Harness[] = [];
const roots: string[] = [];

afterEach(async () => {
  for (const harness of running.splice(0)) {
    harness.child.stdin.end();
    harness.child.kill('SIGKILL');
  }
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

async function startSidecar(extraEnv: Record<string, string> = {}): Promise<Harness> {
  const home = await mkdtemp(join(tmpdir(), 'piui-sidecar-process-'));
  roots.push(home);
  const child = spawn(process.execPath, [join(sidecar, 'dist/index.js')], {
    cwd: sidecar,
    env: {
      HOME: home,
      NODE_ENV: 'production',
      PI_OFFLINE: '1',
      PIUI_DESKTOP_VERSION: '0.1.0',
      PIUI_HANDSHAKE_NONCE: 'process-test-00000001',
      ...extraEnv,
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const frames: ProtocolEnvelope[] = [];
  const rawStdout: string[] = [];
  const waiters: Array<{
    predicate: (frame: ProtocolEnvelope) => boolean;
    settle(frame: ProtocolEnvelope): void;
  }> = [];
  createInterface({ input: child.stdout }).on('line', (line) => {
    rawStdout.push(line);
    const frame = JSON.parse(line) as ProtocolEnvelope;
    frames.push(frame);
    for (const waiter of [...waiters]) {
      if (waiter.predicate(frame)) {
        waiters.splice(waiters.indexOf(waiter), 1);
        waiter.settle(frame);
      }
    }
  });
  child.stderr.resume();
  const harness: Harness = {
    child,
    frames,
    rawStdout,
    send: (envelope) => child.stdin.write(`${JSON.stringify(envelope)}\n`),
    waitFor: (predicate, label) => {
      const existing = frames.find(predicate);
      if (existing) return Promise.resolve(existing);
      return new Promise((settle, reject) => {
        const timer = setTimeout(() => reject(new Error(`timed out waiting for ${label}`)), 10_000);
        waiters.push({
          predicate,
          settle: (frame) => {
            clearTimeout(timer);
            settle(frame);
          },
        });
      });
    },
  };
  running.push(harness);
  await harness.waitFor((frame) => frame.kind === 'handshake', 'handshake');
  return harness;
}

function request(id: string, sequence: number, payload: Record<string, unknown>): ProtocolEnvelope {
  return { version: 1, kind: 'request', id, sequence, payload };
}

const correlated = (id: string) => (frame: ProtocolEnvelope) => frame.correlationId === id;

describe('sidecar process protocol', () => {
  it('rejects the crash and stream fixtures unless test methods are enabled', async () => {
    const harness = await startSidecar();
    harness.send(request('fixture-stream-1', 1, { method: 'stream.fixture' }));
    const stream = await harness.waitFor(correlated('fixture-stream-1'), 'stream rejection');
    expect(stream.kind).toBe('response');
    expect(stream.error).toMatchObject({ category: 'invalid-request' });
    harness.send(request('fixture-crash-1', 2, { method: 'spike.crash' }));
    const crash = await harness.waitFor(correlated('fixture-crash-1'), 'crash rejection');
    expect(crash.error).toMatchObject({ category: 'invalid-request' });
    harness.send(request('status-1', 3, { method: 'status' }));
    expect((await harness.waitFor(correlated('status-1'), 'status')).payload).toMatchObject({
      status: 'ready',
    });
    expect(harness.child.exitCode).toBeNull();
  });

  it('serves the stream fixture when test methods are enabled', async () => {
    const harness = await startSidecar({ PIUI_ENABLE_TEST_METHODS: '1' });
    harness.send(request('fixture-stream-2', 1, { method: 'stream.fixture' }));
    const terminal = await harness.waitFor(
      (frame) =>
        frame.correlationId === 'fixture-stream-2' && frame.payload.terminal === 'complete',
      'stream terminal',
    );
    expect(terminal.kind).toBe('event');
    expect(
      harness.frames.some(
        (frame) =>
          frame.correlationId === 'fixture-stream-2' && frame.payload.eventType === 'stream.delta',
      ),
    ).toBe(true);
  });

  it('keeps stdout for protocol frames while other writers are sent to stderr', async () => {
    const guard = pathToFileURL(join(sidecar, 'dist/bridge/stdout-guard.js')).href;
    const writer = pathToFileURL(join(sidecar, 'dist/bridge/protocol-writer.js')).href;
    const script = `
      const { claimProtocolStdout } = await import(${JSON.stringify(guard)});
      const { createZeroingProtocolWriter } = await import(${JSON.stringify(writer)});
      const write = createZeroingProtocolWriter(claimProtocolStdout());
      console.log('extension log token=abc123');
      console.info('library info');
      console.debug('library debug');
      process.stdout.write('raw stdout chunk\\n');
      process.stdout.write(Buffer.from('raw stdout buffer\\n'));
      write({ version: 1, kind: 'event', id: 'sidecar-1', sequence: 1, payload: { eventType: 'probe' } });
    `;
    const child = spawn(process.execPath, ['--input-type=module', '-e', script], {
      env: {},
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
    const code = await new Promise<number | null>((settle) => child.once('exit', settle));
    expect(code).toBe(0);
    expect(stdout).toBe(
      `${JSON.stringify({ version: 1, kind: 'event', id: 'sidecar-1', sequence: 1, payload: { eventType: 'probe' } })}\n`,
    );
    for (const text of [
      'extension log',
      'library info',
      'library debug',
      'raw stdout chunk',
      'raw stdout buffer',
    ]) {
      expect(stderr).toContain(text);
    }
    expect(stderr).not.toContain('abc123');
  });

  it('reports a rejected product request by its code', async () => {
    const harness = await startSidecar();
    harness.send(
      request('rust-product-process-1', 1, { method: 'product.providers.list', extra: true }),
    );
    const response = await harness.waitFor(correlated('rust-product-process-1'), 'product error');
    expect(response.error).toEqual({
      category: 'invalid-request',
      message: 'product-request-rejected',
      retryable: false,
    });
  });
});
