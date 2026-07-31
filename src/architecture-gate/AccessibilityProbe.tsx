import { useVirtualizer } from '@tanstack/react-virtual';
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
} from 'react';
import {
  A28_HUMAN_WITNESS_READY_EVENT,
  assertA28HumanWitnessLease,
  type A28HumanWitnessLease,
} from './a28WitnessContract';

export const A28_ACCESSIBILITY_ROUTE = 'accessibility-packaged';
export const A28_ACCESSIBILITY_TEST_ACTIVE =
  import.meta.env.VITE_PIUI_A28_ACCESSIBILITY_TEST === '1';
export const A28_TRANSCRIPT_COUNT = 100;

type TranscriptItem = Readonly<{
  id: string;
  ordinal: number;
  speaker: 'Assistant' | 'You';
  text: string;
}>;

type TranscriptMode = 'virtualised' | 'accessible';
type Appearance = 'dark' | 'light';

const transcriptPrompts = Object.freeze([
  'Reviewing the project boundary before any local extension is loaded.',
  'Checking the acknowledged session state and the active branch.',
  'Summarising the proposed change without exposing private paths.',
  'Waiting for an explicit tool decision before continuing.',
  'Recording the completed operation and its safe recovery action.',
]);

export const A28_TRANSCRIPT: readonly TranscriptItem[] = Object.freeze(
  Array.from({ length: A28_TRANSCRIPT_COUNT }, (_, index) => {
    const ordinal = index + 1;
    return Object.freeze({
      id: `a28-transcript-row-${ordinal}`,
      ordinal,
      speaker: index % 3 === 0 ? 'You' : 'Assistant',
      text: transcriptPrompts[index % transcriptPrompts.length] ?? '',
    });
  }),
);

export function nextA28TranscriptIndex(
  current: number,
  key: string,
  pageSize = 10,
): number | null {
  if (!Number.isSafeInteger(current)
    || current < 0
    || current >= A28_TRANSCRIPT_COUNT
    || !Number.isSafeInteger(pageSize)
    || pageSize < 1) return null;
  const last = A28_TRANSCRIPT_COUNT - 1;
  if (key === 'ArrowDown') return Math.min(last, current + 1);
  if (key === 'ArrowUp') return Math.max(0, current - 1);
  if (key === 'Home') return 0;
  if (key === 'End') return last;
  if (key === 'PageDown') return Math.min(last, current + pageSize);
  if (key === 'PageUp') return Math.max(0, current - pageSize);
  return null;
}

function afterPaint(signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new DOMException('A.28 preparation cancelled', 'AbortError'));
      return;
    }
    let frame = 0;
    const cancel = () => {
      window.cancelAnimationFrame(frame);
      reject(new DOMException('A.28 preparation cancelled', 'AbortError'));
    };
    signal.addEventListener('abort', cancel, { once: true });
    frame = window.requestAnimationFrame(() => {
      frame = window.requestAnimationFrame(() => {
        signal.removeEventListener('abort', cancel);
        resolve();
      });
    });
  });
}

function cancellablePause(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new DOMException('A.28 preparation cancelled', 'AbortError'));
      return;
    }
    const timer = window.setTimeout(() => {
      signal.removeEventListener('abort', cancel);
      resolve();
    }, milliseconds);
    const cancel = () => {
      window.clearTimeout(timer);
      reject(new DOMException('A.28 preparation cancelled', 'AbortError'));
    };
    signal.addEventListener('abort', cancel, { once: true });
  });
}

type TranscriptRowProps = Readonly<{
  item: TranscriptItem;
  focusedIndex: number;
  onFocus: (index: number) => void;
  onKeyDown: (event: KeyboardEvent<HTMLDivElement>, index: number) => void;
  measure?: (element: HTMLDivElement | null) => void;
  virtualStart?: number;
}>;

function TranscriptRow({
  item,
  focusedIndex,
  onFocus,
  onKeyDown,
  measure,
  virtualStart,
}: TranscriptRowProps) {
  const index = item.ordinal - 1;
  return (
    <div
      id={item.id}
      ref={measure}
      role="listitem"
      className={`a28-transcript__row${virtualStart === undefined
        ? ''
        : ' a28-transcript__virtual-position'}`}
      aria-posinset={item.ordinal}
      aria-setsize={A28_TRANSCRIPT_COUNT}
      data-a28-row={item.ordinal}
      data-index={virtualStart === undefined ? undefined : index}
      style={virtualStart === undefined
        ? undefined
        : { transform: `translateY(${virtualStart}px)` }}
      tabIndex={focusedIndex === index ? 0 : -1}
      onFocus={() => onFocus(index)}
      onKeyDown={(event) => onKeyDown(event, index)}
    >
      <span className="a28-transcript__ordinal" aria-hidden="true">
        {String(item.ordinal).padStart(3, '0')}
      </span>
      <span className="a28-transcript__content">
        <span className="a28-transcript__speaker">{item.speaker}</span>
        <span>{item.text}</span>
      </span>
    </div>
  );
}

export function AccessibilityProbe() {
  const viewport = useRef<HTMLDivElement>(null);
  const preparation = useRef<AbortController | null>(null);
  const [phase, setPhase] = useState<'idle' | 'preparing' | 'ready' | 'failed'>('idle');
  const [mode, setMode] = useState<TranscriptMode>('virtualised');
  const [appearance, setAppearance] = useState<Appearance>('dark');
  const [focusedIndex, setFocusedIndex] = useState(0);
  const [humanWitness, setHumanWitness] =
    useState<A28HumanWitnessLease | null>(null);
  const virtualizer = useVirtualizer({
    count: A28_TRANSCRIPT_COUNT,
    estimateSize: () => 82,
    getScrollElement: () => viewport.current,
    overscan: 6,
  });
  const virtualRows = virtualizer.getVirtualItems();
  useEffect(() => () => preparation.current?.abort(), []);
  useEffect(() => {
    const receiveHumanWitnessLease = (event: Event) => {
      if (!(event instanceof CustomEvent)) {
        setPhase('failed');
        return;
      }
      try {
        setHumanWitness(assertA28HumanWitnessLease(event.detail));
      } catch {
        setPhase('failed');
      }
    };
    window.addEventListener(
      A28_HUMAN_WITNESS_READY_EVENT,
      receiveHumanWitnessLease,
    );
    return () => {
      window.removeEventListener(
        A28_HUMAN_WITNESS_READY_EVENT,
        receiveHumanWitnessLease,
      );
    };
  }, []);

  const prepareTranscript = () => {
    if (preparation.current) return;
    const controller = new AbortController();
    preparation.current = controller;
    setPhase('preparing');
    void Promise.all([
      afterPaint(controller.signal),
      cancellablePause(400, controller.signal),
    ])
      .then(() => setPhase('ready'))
      .catch((error: unknown) => {
        if (!(error instanceof DOMException && error.name === 'AbortError')) setPhase('failed');
      })
      .finally(() => {
        if (preparation.current === controller) preparation.current = null;
      });
  };

  const focusRow = useCallback((index: number) => {
    setFocusedIndex(index);
    if (mode === 'virtualised') virtualizer.scrollToIndex(index, { align: 'auto' });
    window.requestAnimationFrame(() => {
      document.getElementById(A28_TRANSCRIPT[index]?.id ?? '')?.focus({ preventScroll: true });
    });
  }, [mode, virtualizer]);

  const handleRowKeyDown = useCallback((
    event: KeyboardEvent<HTMLDivElement>,
    index: number,
  ) => {
    const next = nextA28TranscriptIndex(index, event.key);
    if (next === null) return;
    event.preventDefault();
    focusRow(next);
  }, [focusRow]);

  const visibleRange = useMemo(() => {
    if (mode === 'accessible') return `All ${A28_TRANSCRIPT_COUNT} rows are rendered.`;
    const first = (virtualRows.at(0)?.index ?? 0) + 1;
    const last = (virtualRows.at(-1)?.index ?? 0) + 1;
    return `Rows ${first} to ${last} of ${A28_TRANSCRIPT_COUNT} are rendered.`;
  }, [mode, virtualRows]);

  const selectMode = (nextMode: TranscriptMode) => {
    setMode(nextMode);
    window.requestAnimationFrame(() => {
      if (nextMode === 'virtualised') virtualizer.scrollToIndex(focusedIndex, { align: 'center' });
    });
  };

  const busy = phase === 'preparing';
  if (phase === 'failed') {
    return (
      <main className="a28-probe a28-probe--dark" aria-labelledby="a28-title">
        <section className="a28-probe__error" role="alert">
          <h1 id="a28-title">Accessibility fixture unavailable</h1>
          <p>The packaged accessibility fixture could not be prepared.</p>
        </section>
      </main>
    );
  }

  return (
    <main
      className={`a28-probe a28-probe--${appearance}`}
      data-a28-appearance={appearance}
      data-a28-mode={mode}
      aria-busy={busy}
      aria-labelledby="a28-title"
    >
      <header className="a28-probe__header">
        <p className="a28-probe__eyebrow">Packaged accessibility proof</p>
        <h1 id="a28-title">Long transcript operability</h1>
        <p>
          A fixed 100-row transcript checks order, names, keyboard movement and focus retention in
          the release WebView.
        </p>
      </header>

      {humanWitness ? (
        <section
          className="a28-probe__human-witness"
          aria-busy="true"
          aria-labelledby="a28-human-witness-title"
          data-a28-human-witness=""
          data-a28-witness-pid={humanWitness.applicationPid}
          data-a28-witness-nonce={humanWitness.witnessNonce}
        >
          <div>
            <p className="a28-probe__eyebrow">Human VoiceOver witness</p>
            <h2 id="a28-human-witness-title">Exact packaged twin retained</h2>
            <p role="status" aria-live="polite">
              Complete all four VoiceOver checks while this application remains open. The
              automation runner is waiting for your explicit completion record.
            </p>
          </div>
          <progress aria-label="Waiting for human VoiceOver evidence" />
          <dl>
            <div>
              <dt>Application PID</dt>
              <dd>{humanWitness.applicationPid}</dd>
            </div>
            <div>
              <dt>macOS</dt>
              <dd>{humanWitness.macosVersion}</dd>
            </div>
            <div>
              <dt>Evidence directory</dt>
              <dd><code>{humanWitness.evidenceDirectory}</code></dd>
            </div>
            <div>
              <dt>Source digest</dt>
              <dd><code>{humanWitness.sourceDigest}</code></dd>
            </div>
            <div>
              <dt>Production fingerprint</dt>
              <dd><code>{humanWitness.productionFingerprint}</code></dd>
            </div>
            <div>
              <dt>Automation-twin fingerprint</dt>
              <dd><code>{humanWitness.automationTwinFingerprint}</code></dd>
            </div>
            <div>
              <dt>Witness nonce</dt>
              <dd><code>{humanWitness.witnessNonce}</code></dd>
            </div>
          </dl>
        </section>
      ) : null}

      {phase === 'idle' ? (
        <section className="a28-probe__start">
          <p>The fixed fixture is ready to be prepared without loading project content.</p>
          <button type="button" onClick={prepareTranscript}>
            Prepare accessibility fixture
          </button>
        </section>
      ) : busy ? (
        <section className="a28-probe__loading" role="status" aria-live="polite">
          <span className="a28-probe__spinner" aria-hidden="true" />
          <span>Preparing the accessibility transcript…</span>
        </section>
      ) : (
        <section className="a28-probe__workspace" aria-label="Accessibility test controls">
          <div className="a28-probe__toolbar">
            <div className="a28-probe__control-group" aria-label="Transcript rendering mode">
              <span className="a28-probe__control-label">Rendering</span>
              <button
                type="button"
                aria-pressed={mode === 'virtualised'}
                onClick={() => selectMode('virtualised')}
              >
                Virtualised transcript
              </button>
              <button
                type="button"
                aria-pressed={mode === 'accessible'}
                onClick={() => selectMode('accessible')}
              >
                Accessible transcript
              </button>
            </div>
            <div className="a28-probe__control-group" aria-label="Appearance">
              <span className="a28-probe__control-label">Appearance</span>
              <button
                type="button"
                aria-pressed={appearance === 'dark'}
                onClick={() => setAppearance('dark')}
              >
                Dark
              </button>
              <button
                type="button"
                aria-pressed={appearance === 'light'}
                onClick={() => setAppearance('light')}
              >
                Light
              </button>
            </div>
          </div>

          <p className="a28-probe__instructions" id="a28-keyboard-help">
            Move through rows with Arrow keys, Home, End, Page Up and Page Down.
          </p>
          <p className="a28-probe__range" role="status" aria-live="polite">
            {visibleRange} Focused row {focusedIndex + 1}.
          </p>

          {mode === 'virtualised' ? (
            <div
              ref={viewport}
              className="a28-transcript a28-transcript--virtualised"
              data-a28-virtualised="true"
              aria-describedby="a28-keyboard-help"
            >
              <div
                role="list"
                className="a28-transcript__virtual-canvas"
                aria-label="Architecture accessibility transcript"
                style={{ height: `${virtualizer.getTotalSize()}px` }}
              >
                {virtualRows.map((virtualRow) => {
                  const item = A28_TRANSCRIPT[virtualRow.index];
                  if (!item) return null;
                  return (
                    <TranscriptRow
                      key={item.id}
                      item={item}
                      focusedIndex={focusedIndex}
                      measure={virtualizer.measureElement}
                      onFocus={setFocusedIndex}
                      onKeyDown={handleRowKeyDown}
                      virtualStart={virtualRow.start}
                    />
                  );
                })}
              </div>
            </div>
          ) : (
            <div className="a28-transcript a28-transcript--accessible" data-a28-virtualised="false">
              <div
                role="list"
                className="a28-transcript__all-rows"
                aria-label="Architecture accessibility transcript"
                aria-describedby="a28-keyboard-help"
              >
                {A28_TRANSCRIPT.map((item) => (
                  <TranscriptRow
                    key={item.id}
                    item={item}
                    focusedIndex={focusedIndex}
                    onFocus={setFocusedIndex}
                    onKeyDown={handleRowKeyDown}
                  />
                ))}
              </div>
            </div>
          )}
        </section>
      )}
    </main>
  );
}
