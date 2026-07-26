import { createHmac, randomBytes } from 'node:crypto';
import { closeSync, readSync, writeSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MessageChannel, Worker } from 'node:worker_threads';

const terminate = process.exit.bind(process);
const originalRead = readSync.bind(undefined);
const originalWrite = writeSync.bind(undefined);
const originalClose = closeSync.bind(undefined);
const originalRandomBytes = randomBytes.bind(undefined);
const originalCreateHmac = createHmac.bind(undefined);
const originalFill = Uint8Array.prototype.fill;
const zero = (value: Uint8Array) => { Reflect.apply(originalFill, value, [0]); };
const [snapshotRoot, agentRoot] = process.argv.slice(2);
const projectEntrypoint = fileURLToPath(new URL('./trust-loader-project-thread.js', import.meta.url));
const CHALLENGE_FD = 3;
const TRANSCRIPT_FD = 4;
const CHALLENGE_BYTES = 32;
const PROJECT_TIMEOUT_MS = 18_000;

function readExactChallenge(): Buffer {
  const value = Buffer.alloc(CHALLENGE_BYTES + 1);
  let offset = 0;
  while (offset < value.length) {
    const read = originalRead(CHALLENGE_FD, value, offset, value.length - offset, null);
    if (read === 0) break;
    offset += read;
  }
  originalClose(CHALLENGE_FD);
  if (offset !== CHALLENGE_BYTES) {
    zero(value);
    throw new Error('completion-challenge-rejected');
  }
  return value.subarray(0, CHALLENGE_BYTES);
}

function writeExact(value: Buffer): void {
  let offset = 0;
  while (offset < value.length) {
    const written = originalWrite(TRANSCRIPT_FD, value, offset, value.length - offset);
    if (written <= 0) throw new Error('completion-transcript-rejected');
    offset += written;
  }
}

function exactPrivateMessage(value: unknown, phase: 'ready' | 'complete'): boolean {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  return keys.length === 2
    && keys.includes('version')
    && keys.includes('phase')
    && record.version === 1
    && record.phase === phase;
}

if (
  process.argv.length !== 4
  || !snapshotRoot
  || !agentRoot
  || !isAbsolute(snapshotRoot)
  || !isAbsolute(agentRoot)
) {
  terminate(64);
} else {
  let challenge: Buffer | undefined;
  let nonce: Buffer | undefined;
  try {
    // Challenge, nonce and HMAC primitives exist only in this main isolate. It
    // never imports Pi or project modules.
    challenge = readExactChallenge();
    nonce = originalRandomBytes(32);
    const { port1, port2 } = new MessageChannel();
    let phase = 0;
    let invalid = false;
    let portClosed = false;
    let workerExited = false;
    let workerCode: number | null = null;
    let settled = false;
    let deadline: ReturnType<typeof setTimeout> | undefined;

    const projectWorker = new Worker(projectEntrypoint, {
      workerData: { snapshotRoot, agentRoot, completionPort: port2 },
      transferList: [port2],
      // The main isolate needs --allow-worker only to create this isolate. The
      // project isolate deliberately does not inherit it, preventing a nested
      // Worker from dropping permission flags and regaining process authority.
      execArgv: [
        '--permission',
        '--disable-sigusr1',
        '--frozen-intrinsics',
        '--allow-fs-read=*',
        `--allow-fs-write=${snapshotRoot}`,
        `--allow-fs-write=${agentRoot}`,
      ],
    });
    // Ordinary parentPort traffic is explicitly non-authoritative.
    projectWorker.on('message', () => undefined);

    const finish = (success: boolean) => {
      if (settled) return;
      settled = true;
      if (deadline) clearTimeout(deadline);
      if (!success) {
        void projectWorker.terminate();
        try { port1.close(); } catch { /* already closed */ }
        try { originalClose(TRANSCRIPT_FD); } catch { /* already closed */ }
        zero(challenge!);
        zero(nonce!);
        terminate(70);
        return;
      }
      const ready = originalCreateHmac('sha256', challenge!)
        .update('piui-ready-v1\0', 'utf8')
        .update(nonce!)
        .digest('hex');
      const complete = originalCreateHmac('sha256', challenge!)
        .update('piui-complete-v1\0', 'utf8')
        .update(nonce!)
        .digest('hex');
      writeExact(Buffer.from(`READY ${nonce!.toString('hex')} ${ready}\n`, 'ascii'));
      writeExact(Buffer.from(`COMPLETE ${complete}\n`, 'ascii'));
      originalClose(TRANSCRIPT_FD);
      zero(challenge!);
      zero(nonce!);
      terminate(0);
    };
    const evaluate = () => {
      if (invalid) finish(false);
      if (workerExited && portClosed) {
        finish(workerCode === 0 && phase === 2);
      }
    };

    port1.on('message', (value) => {
      if (phase === 0 && exactPrivateMessage(value, 'ready')) phase = 1;
      else if (phase === 1 && exactPrivateMessage(value, 'complete')) phase = 2;
      else invalid = true;
      evaluate();
    });
    port1.once('messageerror', () => {
      invalid = true;
      evaluate();
    });
    port1.once('close', () => {
      portClosed = true;
      evaluate();
    });
    projectWorker.once('error', () => {
      invalid = true;
      evaluate();
    });
    projectWorker.once('exit', (code) => {
      workerExited = true;
      workerCode = code;
      evaluate();
    });
    deadline = setTimeout(() => {
      invalid = true;
      evaluate();
    }, PROJECT_TIMEOUT_MS);
    deadline.unref();
  } catch {
    try { originalClose(TRANSCRIPT_FD); } catch { /* already closed */ }
    if (challenge) zero(challenge);
    if (nonce) zero(nonce);
    terminate(70);
  }
}
