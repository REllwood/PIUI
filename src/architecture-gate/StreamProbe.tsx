import { useCallback, useEffect, useRef, useState } from 'react';
import type { ProtocolEnvelope } from '@piui/protocol';

export type StreamProbeEvent = {
  text?: string;
  terminal?: 'complete' | 'cancelled';
};

type StreamHarness = {
  start: (requestId: string) => void | Promise<void>;
  cancel: (requestId: string) => void | Promise<void>;
};

declare global {
  interface Window {
    __PIUI_STREAM_HARNESS__?: StreamHarness;
  }
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
  const queued = useRef('');
  const frame = useRef<number | null>(null);

  useEffect(() => {
    const unsubscribe = subscribe((event) => {
      if (event.text) queued.current += event.text;
      if (queued.current && frame.current === null) {
        frame.current = requestAnimationFrame(() => {
          setText((current) => current + queued.current);
          queued.current = '';
          frame.current = null;
        });
      }
      if (event.terminal) setTerminal(event.terminal);
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
  const requestId = useRef('stream-probe-1');
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

    void (async () => {
      if (window.__PIUI_STREAM_HARNESS__) {
        const receive = (event: Event) => {
          deliver((event as CustomEvent<StreamProbeEvent>).detail);
        };
        window.addEventListener('piui-stream-event', receive);
        unlisten = () => window.removeEventListener('piui-stream-event', receive);
        await window.__PIUI_STREAM_HARNESS__.start(requestId.current);
        return;
      }

      const [{ listen }, { invoke }] = await Promise.all([
        import('@tauri-apps/api/event'),
        import('@tauri-apps/api/core'),
      ]);
      const stopListening = await listen<ProtocolEnvelope>('piui://stream-probe', ({ payload }) => {
        deliver({
          text: typeof payload.payload.text === 'string' ? payload.payload.text : undefined,
          terminal:
            payload.payload.terminal === 'complete' || payload.payload.terminal === 'cancelled'
              ? payload.payload.terminal
              : undefined,
        });
      });
      if (disposed) {
        stopListening();
        return;
      }
      unlisten = stopListening;
      await invoke('stream_probe', { requestId: requestId.current });
    })().catch(() => deliver({ terminal: 'cancelled' }));

    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  const cancel = useCallback(() => {
    if (window.__PIUI_STREAM_HARNESS__) {
      void window.__PIUI_STREAM_HARNESS__.cancel(requestId.current);
      return;
    }
    void import('@tauri-apps/api/core').then(({ invoke }) =>
      invoke('cancel_stream', { requestId: requestId.current }),
    );
  }, []);

  return <StreamProbe subscribe={subscribe} cancel={cancel} />;
}
