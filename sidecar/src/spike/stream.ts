import type { ProtocolEnvelope } from '@piui/protocol';
import type { SidecarRouter } from '../bridge/router.js';

const chunks = ['Planning ', 'a safe ', 'local change', '…'];

export async function streamFixture(
  request: ProtocolEnvelope,
  router: SidecarRouter,
  write: (envelope: ProtocolEnvelope) => void,
  signal: AbortSignal,
): Promise<void> {
  for (const [index, text] of chunks.entries()) {
    if (signal.aborted) break;
    await new Promise((resolve) => setTimeout(resolve, 300));
    if (signal.aborted) break;
    write(router.next('event', `${request.id}-chunk-${index}`, { eventType: 'stream.delta', text }, request.id));
  }
  write(router.next('event', `${request.id}-terminal`, {
    eventType: signal.aborted ? 'stream.cancelled' : 'stream.complete',
    terminal: signal.aborted ? 'cancelled' : 'complete',
  }, request.id));
}
