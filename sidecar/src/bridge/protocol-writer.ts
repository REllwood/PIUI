import type { ProtocolEnvelope } from '@piui/protocol';

export type ProtocolBufferSink = (
  bytes: Buffer,
  settled: (error?: Error | null) => void,
) => void;

export type ProtocolEnvelopeWriter = ((envelope: ProtocolEnvelope) => void) & {
  readonly failed?: boolean;
};

const stdoutSink: ProtocolBufferSink = (bytes, settled) => {
  process.stdout.write(bytes, settled);
};

/**
 * Serialises one envelope into a mutable wire buffer and clears that buffer as
 * soon as the sink has finished with it. Parsed JavaScript strings and objects
 * remain garbage-collected values and are not claimed to be zeroisable.
 */
export function createZeroingProtocolWriter(
  sink: ProtocolBufferSink = stdoutSink,
  onError: () => void = () => undefined,
): ProtocolEnvelopeWriter {
  let failed = false;
  const failGeneration = () => {
    if (failed) return;
    failed = true;
    try {
      onError();
    } catch {
      // The writer remains permanently failed even if its failure hook faults.
    }
  };

  const write = ((envelope: ProtocolEnvelope) => {
    if (failed) throw new Error('protocol-write-failed');

    const bytes = Buffer.from(`${JSON.stringify(envelope)}\n`, 'utf8');
    let cleared = false;
    const settled = (error?: Error | null) => {
      if (cleared) return;
      cleared = true;
      bytes.fill(0);
      if (error) failGeneration();
    };

    try {
      sink(bytes, settled);
    } catch {
      settled(new Error('protocol-write-failed'));
      failGeneration();
      throw new Error('protocol-write-failed');
    }
  }) as ProtocolEnvelopeWriter;

  Object.defineProperty(write, 'failed', {
    enumerable: false,
    get: () => failed,
  });
  return write;
}
