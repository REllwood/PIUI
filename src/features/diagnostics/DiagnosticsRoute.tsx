import { useState } from 'react';
import { useProduct } from '../../app/ProductContext';
import { Icon } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { StatusPill } from '../../components/primitives/StatusPill';
import { redactForDisplay } from '../../domain/errors';

export function DiagnosticsRoute() {
  const { snapshot, activeOperation, runDiagnostics, reconnect } = useProduct();
  const [repair, setRepair] = useState<string | null>(null);
  const [repairing, setRepairing] = useState(false);
  const [copyState, setCopyState] = useState<'idle' | 'copying' | 'copied' | 'failed'>('idle');
  const running = activeOperation === 'diagnostics';
  const health = snapshot.diagnostics.some((check) => ['fail', 'warning'].includes(check.status))
    ? 'Some checks need attention.'
    : 'PIUI’s local foundations are healthy.';
  const copyReport = async () => {
    if (copyState === 'copying') return;
    setCopyState('copying');
    const report = redactForDisplay(
      snapshot.diagnostics
        .map((check) => `${check.id}: ${check.status} — ${check.detail}`)
        .join('\n'),
    );
    try {
      await navigator.clipboard.writeText(report);
      setCopyState('copied');
    } catch (error) {
      setCopyState('failed');
    }
  };
  const confirmRepair = async () => {
    setRepairing(true);
    try {
      if (repair === 'sidecar') await reconnect();
      await runDiagnostics();
    } finally {
      setRepairing(false);
      setRepair(null);
    }
  };
  return (
    <div className="diagnostics-section">
      <div className="health-sentence">
        <Icon name="shield" />
        <div>
          <h3>{health}</h3>
          <p>
            Checks expose only bounded, redacted evidence. Nothing is repaired without confirmation.
          </p>
        </div>
        <button
          type="button"
          className="button"
          onClick={() => void runDiagnostics()}
          disabled={running}
        >
          {running ? (
            <LoadingLabel>Running checks…</LoadingLabel>
          ) : (
            <>
              <Icon name="refresh" />
              Run checks
            </>
          )}
        </button>
      </div>
      <div className="diagnostic-list">
        {snapshot.diagnostics.map((check) => (
          <article key={check.id} className="diagnostic-row" data-status={check.status}>
            <span className="diagnostic-node" aria-hidden="true" />
            <div>
              <h3>{check.label}</h3>
              <p>{check.detail}</p>
              {check.recovery ? <small>{check.recovery}</small> : null}
            </div>
            <StatusPill
              tone={
                check.status === 'pass'
                  ? 'success'
                  : check.status === 'fail'
                    ? 'danger'
                    : check.status === 'warning' || check.status === 'offline'
                      ? 'warning'
                      : 'work'
              }
            >
              {check.status === 'offline' ? 'Not run — offline' : check.status}
            </StatusPill>
            {check.recovery ? (
              <button type="button" className="button" onClick={() => setRepair(check.id)}>
                {check.id === 'sidecar' ? 'Preview recovery' : 'View recovery'}
              </button>
            ) : null}
          </article>
        ))}
      </div>
      <button
        type="button"
        className="button button--quiet"
        onClick={() => void copyReport()}
        disabled={copyState === 'copying'}
      >
        {copyState === 'copying' ? (
          <LoadingLabel>Copying…</LoadingLabel>
        ) : (
          <>
            <Icon name="copy" />
            {copyState === 'copied'
              ? 'Safe report copied'
              : copyState === 'failed'
                ? 'Copy unavailable'
                : 'Copy safe report'}
          </>
        )}
      </button>
      {repair ? (
        <div
          className="repair-preview"
          role="dialog"
          aria-modal="true"
          aria-labelledby="repair-title"
        >
          <h3 id="repair-title">Review recovery</h3>
          {repair === 'sidecar' ? (
            <p>
              PIUI will explicitly restart the bundled local helper, reconnect its private transport
              and then run the checks again. It will not overwrite configuration or credentials.
            </p>
          ) : (
            <p>
              PIUI will not change this item automatically. Follow the recovery guidance shown in
              the check, then run the checks again.
            </p>
          )}
          <div>
            <button type="button" className="button" onClick={() => setRepair(null)}>
              Cancel
            </button>
            {repair === 'sidecar' ? (
              <button
                type="button"
                className="button button--primary"
                disabled={repairing}
                onClick={() => void confirmRepair()}
              >
                {repairing ? <LoadingLabel>Restarting…</LoadingLabel> : 'Restart helper'}
              </button>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}
