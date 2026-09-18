import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { createInterface } from 'node:readline';
import { resolve } from 'node:path';

// `product.auth.start` is a streaming method, so the staged sidecar must answer it with
// stream events. A generic `product.*` fallback once swallowed it and replied with an error
// response instead, which the WebView cannot terminate on, so provider sign-in hung forever.
const root = resolve(import.meta.dirname, '..');
const sidecar = resolve(root, 'src-tauri/resources/sidecar');
const home = await mkdtemp(resolve(tmpdir(), 'piui-auth-routing-'));
const runtime = spawn(
  resolve(root, 'src-tauri/binaries/piui-node-aarch64-apple-darwin'),
  [resolve(sidecar, 'dist/index.js')],
  {
    cwd: sidecar,
    env: {
      NODE_ENV: 'production',
      PIUI_DESKTOP_VERSION: '0.1.0',
      PIUI_HANDSHAKE_NONCE: 'auth-routing-00000001',
      PI_OFFLINE: '1',
      HOME: home,
      PATH: '/usr/bin:/bin',
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  },
);
const stderr = [];
runtime.stderr.setEncoding('utf8');
runtime.stderr.on('data', (chunk) => stderr.push(chunk));
const lines = createInterface({ input: runtime.stdout });
const request = {
  version: 1,
  kind: 'request',
  id: 'web-auth-routing-0001',
  sequence: 1,
  payload: {
    method: 'product.auth.start',
    schemaVersion: 1,
    providerId: 'not-a-provider',
    authMethod: 'subscription',
  },
};
let responseSequence = 0;
let terminal;
let errorResponse;

const settled = new Promise((resolveSettled, rejectSettled) => {
  const timeout = setTimeout(
    () => rejectSettled(new Error('Sidecar auth routing test timed out without a stream terminal')),
    10_000,
  );
  lines.on('line', (line) => {
    const envelope = JSON.parse(line);
    if (envelope.kind === 'handshake') {
      runtime.stdin.write(`${JSON.stringify(request)}\n`);
      return;
    }
    if (envelope.kind === 'host-request') {
      // Answer the credential probes the adapter makes while it resolves the provider.
      const method = envelope.payload?.method;
      const payload =
        method === 'credential.list'
          ? { entries: [] }
          : method === 'credential.get'
            ? { found: false }
            : undefined;
      if (!payload) return;
      responseSequence += 1;
      runtime.stdin.write(
        `${JSON.stringify({
          version: 1,
          kind: 'host-response',
          id: `host-auth-routing-${responseSequence}`,
          correlationId: envelope.id,
          sequence: responseSequence,
          payload,
        })}\n`,
      );
      return;
    }
    if (envelope.correlationId !== request.id) return;
    if (envelope.kind === 'response') {
      errorResponse = envelope;
      clearTimeout(timeout);
      resolveSettled();
      return;
    }
    if (envelope.kind === 'event' && envelope.payload?.eventType === 'stream.failed') {
      terminal = envelope;
      clearTimeout(timeout);
      resolveSettled();
    }
  });
  runtime.once('error', rejectSettled);
  runtime.once('exit', (code) => {
    if (!terminal && !errorResponse) rejectSettled(new Error(`Sidecar exited early with code ${code}`));
  });
});

try {
  await settled;
} finally {
  runtime.stdin.end();
  runtime.kill('SIGKILL');
  await new Promise((resolveExit) => runtime.once('exit', resolveExit));
  lines.close();
  await rm(home, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
}
if (errorResponse) {
  throw new Error(
    `product.auth.start was answered with a response instead of a stream terminal: ${JSON.stringify(errorResponse.error ?? errorResponse.payload)}`,
  );
}
if (terminal?.payload?.terminal !== 'failed' || typeof terminal.payload.code !== 'string') {
  throw new Error(`Sidecar auth terminal was malformed: ${JSON.stringify(terminal)}`);
}
if (stderr.join('') !== '') throw new Error(`Unexpected sidecar diagnostic: ${stderr.join('').slice(0, 200)}`);
console.log(`Sidecar auth routing passed: terminal=${terminal.payload.eventType}, code=${terminal.payload.code}`);
