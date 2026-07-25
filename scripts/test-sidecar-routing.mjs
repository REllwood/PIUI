import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const sidecar = resolve(root, 'src-tauri/resources/sidecar');
const runtime = spawn(
  resolve(root, 'src-tauri/binaries/piui-node-aarch64-apple-darwin'),
  [resolve(sidecar, 'dist/index.js')],
  {
    cwd: sidecar,
    env: {
      NODE_ENV: 'production',
      PIUI_DESKTOP_VERSION: '0.1.0',
      PIUI_HANDSHAKE_NONCE: 'routing-test-00000001',
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
  id: 'routing-stream-1',
  sequence: 1,
  payload: { method: 'stream.fixture' },
};
let deltas = 0;
let terminals = 0;
let replayStarted = 0;
let replayElapsed = Number.POSITIVE_INFINITY;

const complete = new Promise((resolveComplete, rejectComplete) => {
  const timeout = setTimeout(() => rejectComplete(new Error('Sidecar routing test timed out')), 8_000);
  lines.on('line', (line) => {
    const envelope = JSON.parse(line);
    if (envelope.kind === 'handshake') {
      runtime.stdin.write(`${JSON.stringify(request)}\n`);
      return;
    }
    if (envelope.payload?.eventType === 'stream.delta') deltas += 1;
    if (envelope.payload?.terminal === 'complete') {
      terminals += 1;
      if (terminals === 1) {
        setTimeout(() => {
          replayStarted = Date.now();
          runtime.stdin.write(`${JSON.stringify(request)}\n`);
        }, 25);
      } else {
        replayElapsed = Date.now() - replayStarted;
        clearTimeout(timeout);
        resolveComplete();
      }
    }
  });
  runtime.once('error', rejectComplete);
  runtime.once('exit', (code) => {
    if (terminals < 2) rejectComplete(new Error(`Sidecar exited early with code ${code}`));
  });
});

await complete;
runtime.stdin.end();
await new Promise((resolveExit) => runtime.once('exit', resolveExit));
lines.close();
if (stderr.join('') !== '') throw new Error(`Unexpected sidecar diagnostic: ${stderr.join('').slice(0, 200)}`);
if (deltas !== 4) throw new Error(`Completed request effect ran more than once: deltas=${deltas}`);
if (terminals !== 2 || replayElapsed >= 500) {
  throw new Error(`Completed request replay was not immediate: terminals=${terminals}, elapsed=${replayElapsed}`);
}
console.log(`Sidecar routing replay passed: deltas=${deltas}, replay=${replayElapsed}ms`);
