import { useEffect, useRef, useState } from 'react';

export type StreamProbeEvent = { text?: string; terminal?: 'complete' | 'cancelled' };

export function StreamProbe({ subscribe, cancel }: { subscribe: (accept: (event: StreamProbeEvent) => void) => () => void; cancel: () => void }) {
  const [text, setText] = useState('');
  const [terminal, setTerminal] = useState<'running' | 'complete' | 'cancelled'>('running');
  const queued = useRef('');
  const frame = useRef<number | null>(null);
  useEffect(() => subscribe((event) => {
    if (event.text) queued.current += event.text;
    if (frame.current === null) frame.current = requestAnimationFrame(() => {
      setText((current) => current + queued.current); queued.current = ''; frame.current = null;
    });
    if (event.terminal) setTerminal(event.terminal);
  }), [subscribe]);
  return <section aria-label="Stream probe"><output aria-live="polite">{text}</output><p>{terminal}</p><button type="button" onClick={cancel} disabled={terminal !== 'running'}>Stop</button></section>;
}
