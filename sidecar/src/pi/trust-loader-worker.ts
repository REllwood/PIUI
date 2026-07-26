import { spawn } from 'node:child_process';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { isAbsolute } from 'node:path';
import type { Readable, Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';

const terminate = process.exit.bind(process);
const originalFill = Uint8Array.prototype.fill;
const zero = (value: Uint8Array) => { Reflect.apply(originalFill, value, [0]); };
const [snapshotRoot, agentRoot, parentText] = process.argv.slice(2);
const expectedParent = Number(parentText);
const executor = fileURLToPath(new URL('./trust-loader-executor.js', import.meta.url));
const CHALLENGE_BYTES = 32;
const MAX_TRANSCRIPT_BYTES = 256;

if (
  process.argv.length !== 5
  || !snapshotRoot
  || !agentRoot
  || !isAbsolute(snapshotRoot)
  || !isAbsolute(agentRoot)
  || !Number.isSafeInteger(expectedParent)
  || expectedParent <= 1
) {
  terminate(64);
} else {
  // This challenge exists only in the supervisor-worker lexical scope and the
  // dedicated worker-to-executor pipe. It is never placed in argv, env, cwd,
  // files, stdout or a project-visible global.
  const challenge = randomBytes(CHALLENGE_BYTES);
  const child = spawn(process.execPath, [
    '--permission',
    '--disable-sigusr1',
    '--allow-worker',
    // Pi's trusted-user loader semantics require package/source reads outside
    // the synthetic root. Writes remain confined to the snapshot + agent roots.
    '--allow-fs-read=*',
    `--allow-fs-write=${snapshotRoot}`,
    `--allow-fs-write=${agentRoot}`,
    executor,
    snapshotRoot,
    agentRoot,
  ], {
    cwd: snapshotRoot,
    env: {
      HOME: agentRoot,
      NODE_ENV: 'production',
      PI_CODING_AGENT_DIR: agentRoot,
      PI_OFFLINE: '1',
      PIUI_PROJECT_LOADER_ISOLATE: '1',
    },
    // fd 3 carries exactly one challenge towards the executor. fd 4 carries
    // only the bounded authenticated transcript back to this worker.
    stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'],
  });
  const challengePipe = child.stdio[3] as Writable;
  const transcriptPipe = child.stdio[4] as Readable;
  const transcript: Buffer[] = [];
  let transcriptBytes = 0;
  let transcriptInvalid = false;
  let challengeWritten = false;
  let settled = false;

  const finish = (code: number) => {
    if (settled) return;
    settled = true;
    clearInterval(parentWatch);
    clearTimeout(deadline);
    if (code !== 0) {
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
    }
    zero(challenge);
    for (const chunk of transcript) zero(chunk);
    terminate(code);
  };
  const killOwnedGroup = () => {
    try {
      process.kill(-process.pid, 'SIGKILL');
    } catch {
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      finish(74);
    }
  };
  const parentWatch = setInterval(() => {
    if (process.ppid !== expectedParent) killOwnedGroup();
  }, 25);
  parentWatch.unref();
  const deadline = setTimeout(() => {
    try { child.kill('SIGKILL'); } catch { /* already gone */ }
    finish(75);
  }, 20_000);
  deadline.unref();

  transcriptPipe.on('data', (value: Buffer | string) => {
    const chunk = Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(value, 'utf8');
    transcriptBytes += chunk.length;
    if (chunk.some((byte) => byte > 0x7f) || transcriptBytes > MAX_TRANSCRIPT_BYTES) {
      zero(chunk);
      transcriptInvalid = true;
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      return;
    }
    transcript.push(chunk);
  });
  transcriptPipe.once('error', () => {
    transcriptInvalid = true;
    try { child.kill('SIGKILL'); } catch { /* already gone */ }
  });
  challengePipe.once('error', () => {
    transcriptInvalid = true;
    try { child.kill('SIGKILL'); } catch { /* already gone */ }
  });
  challengePipe.end(challenge, () => { challengeWritten = true; });

  child.once('error', () => finish(71));
  // `close`, rather than `exit`, guarantees all control-pipe bytes have been
  // drained before an exact transcript verdict is made.
  child.once('close', (code, signal) => {
    const text = Buffer.concat(transcript, transcriptBytes).toString('ascii');
    const match = /^READY ([a-f0-9]{64}) ([a-f0-9]{64})\nCOMPLETE ([a-f0-9]{64})\n$/.exec(text);
    let authenticated = false;
    if (match) {
      const nonce = Buffer.from(match[1], 'hex');
      const ready = Buffer.from(match[2], 'hex');
      const complete = Buffer.from(match[3], 'hex');
      const expectedReady = createHmac('sha256', challenge)
        .update('piui-ready-v1\0', 'utf8')
        .update(nonce)
        .digest();
      const expectedComplete = createHmac('sha256', challenge)
        .update('piui-complete-v1\0', 'utf8')
        .update(nonce)
        .digest();
      authenticated = ready.length === expectedReady.length
        && complete.length === expectedComplete.length
        && timingSafeEqual(ready, expectedReady)
        && timingSafeEqual(complete, expectedComplete);
      zero(nonce);
      zero(ready);
      zero(complete);
      zero(expectedReady);
      zero(expectedComplete);
    }
    finish(
      signal === null
      && code === 0
      && challengeWritten
      && !transcriptInvalid
      && authenticated
        ? 0
        : 72,
    );
  });
}
