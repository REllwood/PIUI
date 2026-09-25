import { format } from 'node:util';
import { redactDiagnostic } from '../pi/diagnostics.js';
import type { ProtocolBufferSink } from './protocol-writer.js';

let protocolSink: ProtocolBufferSink | undefined;

/**
 * Makes the protocol writer the only writer on stdout. The first call keeps
 * stdout's original write for the returned sink, then points
 * process.stdout.write and console.log/info/debug at stderr, so extension or
 * library code running in this process cannot interleave bytes with protocol
 * frames. Redirected text is redacted like any other sidecar diagnostic.
 * Later calls return the same sink.
 */
export function claimProtocolStdout(): ProtocolBufferSink {
  if (protocolSink) return protocolSink;
  const stdout = process.stdout;
  const protocolWrite = stdout.write.bind(stdout);
  const stderrWrite = process.stderr.write.bind(process.stderr);

  const redirectedWrite = (
    chunk: unknown,
    encodingOrCallback?: unknown,
    callback?: unknown,
  ): boolean => {
    const done = (typeof encodingOrCallback === 'function' ? encodingOrCallback : callback) as
      | ((error?: Error | null) => void)
      | undefined;
    const encoding =
      typeof encodingOrCallback === 'string' && Buffer.isEncoding(encodingOrCallback)
        ? encodingOrCallback
        : 'utf8';
    const text =
      typeof chunk === 'string'
        ? Buffer.from(chunk, encoding).toString('utf8')
        : chunk instanceof Uint8Array
          ? Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength).toString('utf8')
          : String(chunk);
    return stderrWrite(redactDiagnostic(text), done);
  };
  stdout.write = redirectedWrite as typeof stdout.write;

  const toStderr = (...values: unknown[]): void => {
    stderrWrite(`${redactDiagnostic(format(...values))}\n`);
  };
  console.log = toStderr;
  console.info = toStderr;
  console.debug = toStderr;

  protocolSink = (bytes, settled) => {
    protocolWrite(bytes, settled);
  };
  return protocolSink;
}
