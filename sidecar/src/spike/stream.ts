import type { ProtocolEnvelope } from '@piui/protocol';
import type { ProtocolEnvelopeWriter } from '../bridge/protocol-writer.js';
import type { SidecarRouter } from '../bridge/router.js';

const chunks = ['Planning ', 'a safe ', 'local change', '…'];

export async function streamFixture(
  request: ProtocolEnvelope,
  router: SidecarRouter,
  write: ProtocolEnvelopeWriter,
  signal: AbortSignal,
): Promise<'complete' | 'cancelled'> {
  for (const [index, text] of chunks.entries()) {
    if (signal.aborted) break;
    await new Promise((resolve) => setTimeout(resolve, 700));
    if (signal.aborted || write.failed) break;
    write(router.next('event', `${request.id}-chunk-${index}`, { eventType: 'stream.delta', text }, request.id));
  }
  const terminal = signal.aborted ? 'cancelled' : 'complete';
  if (write.failed) return terminal;
  write(router.next('event', `${request.id}-terminal`, {
    eventType: terminal === 'cancelled' ? 'stream.cancelled' : 'stream.complete',
    terminal,
  }, request.id));
  return terminal;
}
