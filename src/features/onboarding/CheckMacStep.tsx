import { useState } from 'react';
import { Icon } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { StatusPill } from '../../components/primitives/StatusPill';
import { redactForDisplay } from '../../domain/errors';
import type { NativeDiagnosticCheck } from '../../platform/native';

export function CheckMacStep({
  status,
  checks,
  onRun,
}: Readonly<{
  status: 'idle' | 'running' | 'pass' | 'fail' | 'offline';
  checks: readonly NativeDiagnosticCheck[];
  onRun: () => void;
}>) {
  const [copyState, setCopyState] = useState<'idle' | 'copying' | 'copied' | 'failed'>('idle');
  const rows: readonly NativeDiagnosticCheck[] =
    status === 'idle' || status === 'running'
      ? [
          {
            id: 'host',
            label: 'macOS and architecture',
            status: status === 'running' ? 'running' : 'not-run',
            detail: 'PIUI will verify the native host and supported architecture.',
          },
          {
            id: 'sidecar',
            label: 'Bundled local helper',
            status: status === 'running' ? 'running' : 'not-run',
            detail: 'PIUI will validate the bundled Node.js and pinned Pi SDK handshake.',
          },
          {
            id: 'application-data',
            label: 'Application data',
            status: status === 'running' ? 'running' : 'not-run',
            detail: 'PIUI will verify atomic non-secret preference storage.',
          },
          {
            id: 'network',
            label: 'Provider network',
            status: status === 'running' ? 'running' : 'not-run',
            detail: 'Provider access is attempted only after you start sign-in.',
          },
        ]
      : checks;
  const copySafeReport = async () => {
    if (copyState === 'copying') return;
    setCopyState('copying');
    const report = redactForDisplay(
      rows.map((row) => `${row.label}: ${row.status} — ${row.detail}`).join('\n'),
    );
    try {
      await navigator.clipboard.writeText(report);
      setCopyState('copied');
    } catch {
      setCopyState('failed');
    }
  };
  return (
    <div className="onboarding-step onboarding-check">
      <div className="onboarding-copy">
        <p className="ui-label">Check this Mac</p>
        <h1>Let’s make sure the local foundations are ready.</h1>
        <p className="onboarding-lead">
          These checks do not load project code or inspect credential values.
        </p>
        <button type="button" className="button" onClick={onRun} disabled={status === 'running'}>
          {status === 'running' ? (
            <LoadingLabel>Checking this Mac…</LoadingLabel>
          ) : (
            <>
              <Icon name="refresh" />
              {status === 'idle' ? 'Run checks' : 'Run checks again'}
            </>
          )}
        </button>
        {status !== 'idle' && status !== 'running' ? (
          <button
            type="button"
            className="button button--quiet"
            onClick={() => void copySafeReport()}
            disabled={copyState === 'copying'}
          >
            {copyState === 'copying' ? (
              <LoadingLabel>Copying report…</LoadingLabel>
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
        ) : null}
      </div>
      <section
        className="check-list"
        aria-label="Environment checks"
        aria-busy={status === 'running'}
      >
        {rows.map((row) => (
          <article key={row.id} data-status={row.status}>
            <span className="check-node" aria-hidden="true" />
            <div>
              <h2>{row.label}</h2>
              <p>{row.detail}</p>
              {row.recovery ? <small>{row.recovery}</small> : null}
            </div>
            <StatusPill
              tone={
                row.status === 'pass'
                  ? 'success'
                  : row.status === 'offline' || row.status === 'warning'
                    ? 'warning'
                    : row.status === 'running'
                      ? 'work'
                      : 'neutral'
              }
            >
              {row.status === 'not-run' ? 'Not run' : row.status}
            </StatusPill>
          </article>
        ))}
        {status === 'offline' ? (
          <div className="inline-notice" data-tone="warning">
            Network checks were not run because this Mac is offline. You can continue and connect
            later.
          </div>
        ) : null}
      </section>
    </div>
  );
}
