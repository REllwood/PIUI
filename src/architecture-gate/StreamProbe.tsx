import { useCallback, useEffect, useRef, useState } from 'react';
import type { ProtocolEnvelope } from '@piui/protocol';
import { BridgeClient, isPrivateHostEnvelope } from '../bridge/client';

export type StreamProbeEvent = {
  text?: string;
  replaceText?: string;
  terminal?: 'complete' | 'cancelled';
};

export const MAX_RENDERED_STREAM_UTF16 = 262_144;

export function normaliseAndTruncateUtf16(value: string, maximumUnits: number): string {
  if (maximumUnits <= 0) return '';
  let normalised = '';
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        normalised += value[index] + value[index + 1];
        index += 1;
      } else normalised += '\ufffd';
    } else if (unit >= 0xdc00 && unit <= 0xdfff) normalised += '\ufffd';
    else normalised += value[index];
  }
  if (normalised.length <= maximumUnits) return normalised;
  let end = maximumUnits;
  const last = normalised.charCodeAt(end - 1);
  const next = normalised.charCodeAt(end);
  if (last >= 0xd800 && last <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) end -= 1;
  return normalised.slice(0, end);
}

export function takeBoundedStreamText(
  value: string,
  usedUnits: number,
): { text: string; usedUnits: number } {
  const remaining = Math.max(0, MAX_RENDERED_STREAM_UTF16 - usedUnits);
  const text = normaliseAndTruncateUtf16(value, remaining);
  return { text, usedUnits: usedUnits + text.length };
}

type StreamHarness = {
  start: (request: ProtocolEnvelope) => void | Promise<void>;
  cancel: (cancellation: ProtocolEnvelope) => void | Promise<void>;
  send: (envelope: ProtocolEnvelope) => void | Promise<void>;
};

declare global {
  interface Window {
    __PIUI_STREAM_HARNESS__?: StreamHarness;
  }
}

export type StreamEnvelopeAcceptance = {
  bridge: BridgeClient;
  requestId: string;
  deliver: (event: StreamProbeEvent) => void;
  sendSnapshot: (snapshot: ProtocolEnvelope) => void;
};

export function acceptStreamProbeEnvelope(
  envelope: ProtocolEnvelope,
  context: StreamEnvelopeAcceptance,
): void {
  if (isPrivateHostEnvelope(envelope)) return;

  if (envelope.kind === 'response' && 'snapshot' in envelope.payload) {
    const snapshot = envelope.payload.snapshot;
    if (
      typeof snapshot === 'object' &&
      snapshot !== null &&
      !Array.isArray(snapshot) &&
      Number.isSafeInteger((snapshot as { sequence?: unknown }).sequence) &&
      Number((snapshot as { sequence: number }).sequence) <= envelope.sequence &&
      typeof (snapshot as { state?: unknown }).state === 'object' &&
      (snapshot as { state?: unknown }).state !== null &&
      !Array.isArray((snapshot as { state?: unknown }).state)
    ) {
      const state = (snapshot as { state: Record<string, unknown> }).state;
      const applied = context.bridge.applySnapshot(
        { sequence: envelope.sequence, state },
        envelope.correlationId,
      );
      const streams = state.streams;
      const stream =
        typeof streams === 'object' && streams !== null && !Array.isArray(streams)
          ? (streams as Record<string, unknown>)[context.requestId]
          : undefined;
      if (applied && typeof stream === 'object' && stream !== null && !Array.isArray(stream)) {
        const streamState = stream as { text?: unknown; terminal?: unknown };
        context.deliver({
          replaceText: typeof streamState.text === 'string' ? streamState.text : '',
          terminal:
            streamState.terminal === 'complete' || streamState.terminal === 'cancelled'
              ? streamState.terminal
              : undefined,
        });
      }
    }
    return;
  }

  const outcome = context.bridge.receive(envelope);
  if (outcome === 'gap') {
    const snapshot = context.bridge.takeResynchronisationRequest();
    if (snapshot) context.sendSnapshot(snapshot);
    return;
  }
  if (
    outcome !== 'accepted' ||
    envelope.kind !== 'event' ||
    envelope.correlationId !== context.requestId
  ) {
    return;
  }
  context.deliver({
    text: typeof envelope.payload.text === 'string' ? envelope.payload.text : undefined,
    terminal:
      envelope.payload.terminal === 'complete' || envelope.payload.terminal === 'cancelled'
        ? envelope.payload.terminal
        : undefined,
  });
}

export function StreamProbe({
  subscribe,
  cancel,
}: {
  subscribe: (accept: (event: StreamProbeEvent) => void) => () => void;
  cancel: () => void;
}) {
  const [text, setText] = useState('');
  const [terminal, setTerminal] = useState<'running' | 'complete' | 'cancelled'>('running');
  const queuedText = useRef('');
  const queuedReplacementText = useRef<string | null>(null);
  const queuedTerminal = useRef<'complete' | 'cancelled' | null>(null);
  const acceptedTextUnits = useRef(0);
  const frame = useRef<number | null>(null);

  useEffect(() => {
    const flushInFrame = () => {
      if (frame.current !== null) return;
      frame.current = requestAnimationFrame(() => {
        const textToAppend = queuedText.current;
        const replacementText = queuedReplacementText.current;
        const terminalToApply = queuedTerminal.current;
        queuedText.current = '';
        queuedReplacementText.current = null;
        queuedTerminal.current = null;
        if (replacementText !== null) setText(replacementText + textToAppend);
        else if (textToAppend) setText((current) => current + textToAppend);
        if (terminalToApply) setTerminal(terminalToApply);
        frame.current = null;
      });
    };
    const unsubscribe = subscribe((event) => {
      if (event.replaceText !== undefined) {
        const bounded = takeBoundedStreamText(event.replaceText, 0);
        queuedReplacementText.current = bounded.text;
        queuedText.current = '';
        acceptedTextUnits.current = bounded.usedUnits;
      }
      if (event.text) {
        const bounded = takeBoundedStreamText(event.text, acceptedTextUnits.current);
        if (bounded.text) queuedText.current += bounded.text;
        acceptedTextUnits.current = bounded.usedUnits;
      }
      if (event.terminal) queuedTerminal.current = event.terminal;
      flushInFrame();
    });
    return () => {
      unsubscribe();
      if (frame.current !== null) cancelAnimationFrame(frame.current);
    };
  }, [subscribe]);

  return (
    <section aria-label="Stream probe">
      <output aria-live="polite" data-testid="stream-output">
        {text}
      </output>
      <p role="status" data-testid="stream-terminal">
        {terminal}
      </p>
      <button type="button" onClick={cancel} disabled={terminal !== 'running'}>
        Stop
      </button>
    </section>
  );
}

export function StreamProbeRoute() {
  const bridge = useRef<BridgeClient | null>(null);
  bridge.current ??= new BridgeClient({ requestTimeoutMs: 5_000 });
  const request = useRef<ProtocolEnvelope | null>(null);
  request.current ??= bridge.current.createRequest('stream.fixture');
  const cancellation = useRef<ProtocolEnvelope | null>(null);
  const cancelIssued = useRef(false);
  const startIssued = useRef(false);
  const listeners = useRef(new Set<(event: StreamProbeEvent) => void>());

  const subscribe = useCallback((accept: (event: StreamProbeEvent) => void) => {
    listeners.current.add(accept);
    return () => listeners.current.delete(accept);
  }, []);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    const deliver = (event: StreamProbeEvent) => {
      for (const listener of listeners.current) listener(event);
    };
    const acceptEnvelope = (envelope: ProtocolEnvelope) => {
      acceptStreamProbeEnvelope(envelope, {
        bridge: bridge.current!,
        requestId: request.current!.id,
        deliver,
        sendSnapshot: (snapshot) => {
          if (window.__PIUI_STREAM_HARNESS__) void window.__PIUI_STREAM_HARNESS__.send(snapshot);
          else {
            void import('@tauri-apps/api/core').then(({ invoke }) =>
              invoke('bridge_send', { envelope: snapshot }),
            );
          }
        },
      });
    };

    void (async () => {
      if (window.__PIUI_STREAM_HARNESS__) {
        const receive = (event: Event) => {
          acceptEnvelope((event as CustomEvent<ProtocolEnvelope>).detail);
        };
        window.addEventListener('piui-bridge-envelope', receive);
        unlisten = () => window.removeEventListener('piui-bridge-envelope', receive);
        if (!startIssued.current) {
          startIssued.current = true;
          await window.__PIUI_STREAM_HARNESS__.start(request.current!);
        }
        return;
      }

      const [{ listen }, { invoke }] = await Promise.all([
        import('@tauri-apps/api/event'),
        import('@tauri-apps/api/core'),
      ]);
      const stopListening = await listen<ProtocolEnvelope>('piui://stream-probe', ({ payload }) => {
        acceptEnvelope(payload);
      });
      if (disposed) {
        stopListening();
        return;
      }
      unlisten = stopListening;
      if (!startIssued.current) {
        startIssued.current = true;
        await invoke('stream_probe', { request: request.current });
      }
    })().catch(() => deliver({ terminal: 'cancelled' }));

    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  const cancel = useCallback(() => {
    if (cancelIssued.current) return;
    cancelIssued.current = true;
    cancellation.current ??= bridge.current!.createCancellation(request.current!.id);
    if (window.__PIUI_STREAM_HARNESS__) {
      void window.__PIUI_STREAM_HARNESS__.cancel(cancellation.current);
      return;
    }
    void import('@tauri-apps/api/core').then(({ invoke }) =>
      invoke('cancel_stream', { cancellation: cancellation.current }),
    );
  }, []);

  return <StreamProbe subscribe={subscribe} cancel={cancel} />;
}
