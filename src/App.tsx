import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

type HostStatus = {
  status: 'ready';
  architecture: string;
  transport: 'inherited-stdio';
  listener: false;
};

export function App() {
  const [host, setHost] = useState<HostStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    invoke<HostStatus>('host_status')
      .then((status) => {
        if (active) setHost(status);
      })
      .catch(() => {
        if (active) setError('The native host did not respond.');
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <main className="gate" aria-labelledby="gate-title">
      <section className="gate__card">
        <p className="gate__eyebrow">Release-mode proof</p>
        <h1 id="gate-title">PIUI architecture gate</h1>
        <p className="gate__summary">
          A minimal trusted desktop boundary is being verified before product features are built.
        </p>
        <dl className="gate__status" aria-live="polite">
          <div>
            <dt>Native host</dt>
            <dd>{host ? 'Ready' : error ?? 'Checking…'}</dd>
          </div>
          <div>
            <dt>Transport</dt>
            <dd>{host?.transport ?? 'Pending'}</dd>
          </div>
          <div>
            <dt>Network listener</dt>
            <dd>{host ? 'None' : 'Pending'}</dd>
          </div>
        </dl>
      </section>
    </main>
  );
}
