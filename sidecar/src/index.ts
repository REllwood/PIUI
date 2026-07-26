import { ProtocolDecoder } from '@piui/protocol/codec';
import type { ProtocolEnvelope } from '@piui/protocol';
import { createHandshake, REQUIRED_CAPABILITIES } from './bridge/handshake.js';
import { HostRequestClient, HostRequestError } from './bridge/host-requests.js';
import { createZeroingProtocolWriter } from './bridge/protocol-writer.js';
import { SidecarRouter } from './bridge/router.js';
import { assertPublicSdk, publicSdkMetadata } from './pi/public-sdk.js';
import {
  assertWorkspaceRequestEnvelope,
  TrustGate,
  WorkspaceGateError,
} from './pi/trust-gate.js';
import { crashFixture } from './spike/crash.js';
import { streamFixture } from './spike/stream.js';
import { installParentPipeLifecycle } from './lifecycle.js';

const decoder = new ProtocolDecoder();
const router = new SidecarRouter();
const streams = new Map<string, AbortController>();
const completedStreams = new Map<string, 'complete' | 'cancelled'>();
let input = Buffer.alloc(0);
let outputFailed = false;
let terminalExitCode: number | undefined;
let disconnectPrivateWork: () => void = () => undefined;

function diagnostic(message: string): void {
  process.stderr.write(`[piui-sidecar] ${message.replace(/[\r\n]/g, ' ').slice(0, 256)}\n`);
}

function selectTerminalExitCode(code: number): void {
  terminalExitCode ??= code;
  process.exitCode = terminalExitCode;
}

function clearInput(): void {
  input.fill(0);
  input = Buffer.alloc(0);
}

function failOutputGeneration(): void {
  if (outputFailed) return;
  outputFailed = true;
  selectTerminalExitCode(74);
  diagnostic('protocol output failed');
  disconnectPrivateWork();
  for (const controller of streams.values()) controller.abort();
  clearInput();
  process.stdin.destroy();
  process.stdout.destroy();
}

const write = createZeroingProtocolWriter(undefined, failOutputGeneration);
const hostRequests = new HostRequestClient({ router, write });
const parsedGeneration = Number(process.env.PIUI_SUPERVISOR_GENERATION ?? '1');
const trustGate = new TrustGate(
  Number.isSafeInteger(parsedGeneration) && parsedGeneration > 0
    ? parsedGeneration
    : 1,
);
disconnectPrivateWork = () => {
  hostRequests.disconnect();
  trustGate.disconnect();
};

function fail(request: ProtocolEnvelope): ProtocolEnvelope {
  return {
    ...router.next('response', `error-${request.id}`, {}, request.id),
    error: {
      category: 'invalid-request',
      message: 'Unsupported sidecar request',
      retryable: false,
    },
  };
}

assertPublicSdk();
const sdk = publicSdkMetadata();
try {
  write(createHandshake({
    nonce: process.env.PIUI_HANDSHAKE_NONCE ?? 'sidecar-startup-0000',
    desktopVersion: process.env.PIUI_DESKTOP_VERSION ?? '0.1.0',
    protocolVersion: 1,
    nodeVersion: sdk.nodeVersion,
    piVersion: sdk.piVersion,
    architecture: sdk.architecture,
    capabilities: [...REQUIRED_CAPABILITIES, ...sdk.capabilities],
  }));
} catch {
  failOutputGeneration();
}

async function route(incoming: ProtocolEnvelope): Promise<void> {
  if (outputFailed) return;
  if (hostRequests.consume(incoming)) return;

  const method = 'method' in incoming.payload ? incoming.payload.method : undefined;
  if (incoming.kind === 'request' && method === 'status') {
    write(router.idempotent(
      incoming,
      () => router.next(
        'response',
        `response-${incoming.id}`,
        { status: 'ready', ...sdk },
        incoming.id,
      ),
    ));
  } else if (incoming.kind === 'request' && method === 'snapshot') {
    write(router.idempotent(incoming, () => router.next('response', `response-${incoming.id}`, {
      snapshot: { sequence: router.currentSequence, state: router.currentState },
    }, incoming.id)));
  } else if (
    incoming.kind === 'request'
    && typeof method === 'string'
    && method.startsWith('workspace.')
  ) {
    try {
      assertWorkspaceRequestEnvelope(incoming);
      const payload = await trustGate.handle(incoming.payload);
      if (outputFailed) return;
      write(router.next('response', `response-${incoming.id}`, payload, incoming.id));
    } catch (error) {
      if (outputFailed) return;
      const rejected = error instanceof WorkspaceGateError
        ? error
        : new WorkspaceGateError('workspace-request-rejected');
      write({
        ...router.next('response', `error-${incoming.id}`, {}, incoming.id),
        error: {
          category: rejected.category,
          message: rejected.message,
          retryable: rejected.retryable,
        },
      });
    }
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
    const controller = new AbortController();
    streams.set(incoming.id, controller);
    const terminal = await streamFixture(incoming, router, write, controller.signal)
      .finally(() => streams.delete(incoming.id));
    if (outputFailed) return;
    completedStreams.delete(incoming.id);
    completedStreams.set(incoming.id, terminal);
    if (completedStreams.size > 512) {
      completedStreams.delete(completedStreams.keys().next().value!);
    }
  } else if (incoming.kind === 'cancel' && incoming.correlationId) {
    const controller = streams.get(incoming.correlationId);
    if (controller) controller.abort();
    write(router.idempotent(
      incoming,
      () => router.next(
        'ack',
        `ack-${incoming.id}`,
        { accepted: Boolean(controller) },
        incoming.id,
      ),
    ));
  } else {
    write(router.idempotent(incoming, () => fail(incoming)));
  }
}

process.stdin.on('data', (chunk: Buffer) => {
  if (outputFailed) {
    chunk.fill(0);
    return;
  }
  const combined = Buffer.concat([input, chunk]);
  input.fill(0);
  chunk.fill(0);
  input = combined;
  if (input.length > 1_048_576) {
    clearInput();
    diagnostic('input limit exceeded');
    selectTerminalExitCode(64);
    process.stdin.destroy();
    return;
  }
  while (true) {
    const lf = input.indexOf(0x0a);
    if (lf < 0) break;
    const line = input.subarray(0, lf + 1);
    input = input.subarray(lf + 1);
    try {
      const incoming = decoder.decode(line);
      void route(incoming)
        .catch((error: unknown) => {
          if (outputFailed) return;
          diagnostic('request failed');
          selectTerminalExitCode(70);
          if (
            error instanceof HostRequestError
            && (error.code === 'credential-response-rejected'
              || error.code === 'approval-response-rejected')
          ) {
            disconnectPrivateWork();
            clearInput();
            process.stdin.destroy();
          }
        })
        .finally(() => decoder.acknowledge(incoming.id));
    } catch {
      diagnostic('invalid protocol input rejected');
      selectTerminalExitCode(65);
      disconnectPrivateWork();
      clearInput();
      process.stdin.destroy();
      return;
    } finally {
      line.fill(0);
    }
  }
});

installParentPipeLifecycle(streams, () => {
  disconnectPrivateWork();
  clearInput();
});
process.on('uncaughtException', () => {
  diagnostic('uncaught sidecar error');
  selectTerminalExitCode(70);
  process.exit(terminalExitCode);
});
process.on('unhandledRejection', () => {
  diagnostic('unhandled sidecar rejection');
  selectTerminalExitCode(70);
  process.exit(terminalExitCode);
});
