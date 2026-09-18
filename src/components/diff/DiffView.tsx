import { useEffect, useMemo, useState } from 'react';
import { LoadingLabel } from '../primitives/LoadingLabel';
import type { FileChange } from '../../domain/types';

type DiffMode = 'unified' | 'side-by-side' | 'plain';

export function DiffView({ change }: Readonly<{ change: FileChange }>) {
  const [mode, setMode] = useState<DiffMode>('unified');
  const [wrap, setWrap] = useState(true);
  const [copyState, setCopyState] = useState<'idle' | 'copying' | 'copied' | 'failed'>('idle');
  const lines = Math.max(change.before.length, change.after.length);
  const isFallback = change.state === 'binary' || change.state === 'failed' || lines === 0;
  const sideBySideEligible = change.state === 'modified' && lines > 0 && lines <= 1_000;
  const plainText = useMemo(
    () =>
      (change.after.length > 0 ? change.after : change.before).join('\n').slice(0, 262_144),
    [change.after, change.before],
  );

  useEffect(() => {
    if ((isFallback || (mode === 'side-by-side' && !sideBySideEligible)) && mode !== 'plain') {
      setMode('plain');
    }
  }, [isFallback, mode, sideBySideEligible]);

  const copy = async () => {
    if (copyState === 'copying' || !plainText) return;
    setCopyState('copying');
    try {
      await navigator.clipboard.writeText(plainText);
      setCopyState('copied');
    } catch {
      setCopyState('failed');
    }
  };

  return (
    <section className="diff" aria-labelledby={`diff-${change.id}`}>
      <header className="diff__header">
        <div>
          <h3 id={`diff-${change.id}`}>{change.path}</h3>
          <p>
            <span className="diff__added">+{change.additions}</span>{' '}
            <span className="diff__deleted">−{change.deletions}</span> · {change.state}
          </p>
        </div>
        <div className="diff__controls" aria-label="Diff presentation">
          <select
            className="select"
            value={mode}
            onChange={(event) => setMode(event.target.value as DiffMode)}
            aria-label="Diff view"
          >
            <option value="unified">Unified</option>
            <option value="side-by-side" disabled={!sideBySideEligible}>
              Side by side
            </option>
            <option value="plain">Plain text</option>
          </select>
          <button
            type="button"
            className="button button--quiet"
            aria-pressed={wrap}
            onClick={() => setWrap((current) => !current)}
          >
            {wrap ? 'Wrap on' : 'Wrap off'}
          </button>
          <button
            type="button"
            className="button button--quiet"
            disabled={!plainText || copyState === 'copying'}
            onClick={() => void copy()}
          >
            {copyState === 'copying' ? (
              <LoadingLabel>Copying…</LoadingLabel>
            ) : copyState === 'copied' ? (
              'Copied'
            ) : copyState === 'failed' ? (
              'Copy unavailable'
            ) : (
              'Copy'
            )}
          </button>
        </div>
      </header>
      <div
        className="diff__body"
        data-mode={mode}
        data-wrap={wrap}
        tabIndex={0}
        aria-label={`Changes in ${change.path}`}
      >
        {isFallback ? (
          <div className="diff__fallback" role="note">
            <strong>
              {change.state === 'binary'
                ? 'Binary file preview unavailable'
                : change.state === 'failed'
                  ? 'Diff could not be produced'
                  : 'No textual lines are available'}
            </strong>
            <span>
              PIUI keeps the file record visible without attempting to render unbounded or unsafe
              content.
            </span>
          </div>
        ) : (
          Array.from({ length: lines }, (_, index) => {
          const before = change.before[index];
          const after = change.after[index];
          if (mode === 'plain')
            return (
              <div key={index} className="diff__plain">
                {after ?? before ?? ''}
              </div>
            );
          if (mode === 'side-by-side') {
            return (
              <div key={index} className="diff__pair">
                <span data-kind="removed">{before ?? ''}</span>
                <span data-kind="added">{after ?? ''}</span>
              </div>
            );
          }
          return (
            <div key={index} className="diff__unified">
              {before !== after && before !== undefined ? (
                <span data-kind="removed">
                  <b>−</b>
                  {before}
                </span>
              ) : null}
              {before !== after && after !== undefined ? (
                <span data-kind="added">
                  <b>+</b>
                  {after}
                </span>
              ) : null}
              {before === after ? (
                <span data-kind="context">
                  <b> </b>
                  {before}
                </span>
              ) : null}
            </div>
          );
          })
        )}
      </div>
    </section>
  );
}
