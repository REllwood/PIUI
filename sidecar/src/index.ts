import { ProtocolDecoder } from '@piui/protocol/codec';
import type { ProtocolEnvelope } from '@piui/protocol';
import { createHandshake, REQUIRED_CAPABILITIES } from './bridge/handshake.js';
import { SidecarRouter } from './bridge/router.js';
import { assertPublicSdk, publicSdkMetadata } from './pi/public-sdk.js';
import { crashFixture } from './spike/crash.js';
import { streamFixture } from './spike/stream.js';
import { installParentPipeLifecycle } from './lifecycle.js';

const decoder = new ProtocolDecoder();
const router = new SidecarRouter();
const streams = new Map<string, AbortController>();
const completedStreams = new Map<string, 'complete' | 'cancelled'>();
let input = Buffer.alloc(0);
function write(envelope: ProtocolEnvelope): void { process.stdout.write(`${JSON.stringify(envelope)}\n`); }
function diagnostic(message: string): void { process.stderr.write(`[piui-sidecar] ${message.replace(/[\r\n]/g, ' ').slice(0, 256)}\n`); }
function fail(request: ProtocolEnvelope): ProtocolEnvelope { return { ...router.next('response', `error-${request.id}`, {}, request.id), error: { category: 'invalid-request', message: 'Unsupported sidecar request', retryable: false } }; }

assertPublicSdk();
const sdk = publicSdkMetadata();
write(createHandshake({ nonce: process.env.PIUI_HANDSHAKE_NONCE ?? 'sidecar-startup-0000', desktopVersion: process.env.PIUI_DESKTOP_VERSION ?? '0.1.0', protocolVersion: 1, nodeVersion: sdk.nodeVersion, piVersion: sdk.piVersion, architecture: sdk.architecture, capabilities: [...REQUIRED_CAPABILITIES, ...sdk.capabilities] }));

async function route(incoming: ProtocolEnvelope): Promise<void> {
  const method = 'method' in incoming.payload ? incoming.payload.method : undefined;
  if (incoming.kind === 'request' && method === 'status') {
    write(router.idempotent(incoming, () => router.next('response', `response-${incoming.id}`, { status: 'ready', ...sdk }, incoming.id)));
  } else if (incoming.kind === 'request' && method === 'snapshot') {
    write(router.idempotent(incoming, () => router.next('response', `response-${incoming.id}`, {
      snapshot: { sequence: router.currentSequence, state: router.currentState },
    }, incoming.id)));
  } else if (incoming.kind === 'request' && method === 'spike.crash') {
    crashFixture();
  } else if (incoming.kind === 'request' && method === 'stream.fixture') {
    const completed = completedStreams.get(incoming.id);
    if (completed) {
      write(router.next('event', `${incoming.id}-replay-terminal`, {
        eventType: completed === 'cancelled' ? 'stream.cancelled' : 'stream.complete',
        terminal: completed,
      }, incoming.id));
      return;
    }
    if (streams.has(incoming.id)) return;
    const controller = new AbortController(); streams.set(incoming.id, controller);
    const terminal = await streamFixture(incoming, router, write, controller.signal)
      .finally(() => streams.delete(incoming.id));
    completedStreams.delete(incoming.id);
    completedStreams.set(incoming.id, terminal);
    if (completedStreams.size > 512) completedStreams.delete(completedStreams.keys().next().value!);
  } else if (incoming.kind === 'cancel' && incoming.correlationId) {
    const controller = streams.get(incoming.correlationId);
    if (controller) controller.abort();
    write(router.idempotent(incoming, () => router.next('ack', `ack-${incoming.id}`, { accepted: Boolean(controller) }, incoming.id)));
  } else write(router.idempotent(incoming, () => fail(incoming)));
}

process.stdin.on('data', (chunk: Buffer) => {
  input = Buffer.concat([input, chunk]);
  if (input.length > 1_048_576) { diagnostic('input limit exceeded'); process.exitCode = 64; process.stdin.destroy(); return; }
  while (true) {
    const lf = input.indexOf(0x0a); if (lf < 0) break;
    const line = input.subarray(0, lf + 1); input = input.subarray(lf + 1);
    try {
      const incoming = decoder.decode(line);
      void route(incoming)
        .catch(() => {
          diagnostic('request failed');
          process.exitCode = 70;
        })
        .finally(() => decoder.acknowledge(incoming.id));
    } catch {
      diagnostic('invalid protocol input rejected');
      process.exitCode = 65;
      process.stdin.destroy();
      return;
    }
  }
});
installParentPipeLifecycle(streams);
process.on('uncaughtException', () => { diagnostic('uncaught sidecar error'); process.exit(70); });
process.on('unhandledRejection', () => { diagnostic('unhandled sidecar rejection'); process.exit(70); });
