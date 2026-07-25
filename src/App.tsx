import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { CredentialProbe } from './architecture-gate/CredentialProbe';
import { StreamProbeRoute } from './architecture-gate/StreamProbe';

type HostStatus = {
  status: 'ready';
  architecture: string;
  transport: 'inherited-stdio';
  listener: false;
};

type SidecarStatus = {
  running: boolean;
  failed: boolean;
  protocolVersion?: number;
  nodeVersion?: string;
  piVersion?: string;
};

export function App() {
  const spike = new URLSearchParams(window.location.search).get('spike');
  if (spike === 'credential') return <CredentialProbe />;
  if (spike === 'stream') return <StreamProbeRoute />;
  return <ArchitectureGate />;
}

function ArchitectureGate() {
  const [host, setHost] = useState<HostStatus | null>(null);
  const [sidecar, setSidecar] = useState<SidecarStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void Promise.all([
      invoke<HostStatus>('host_status'),
      invoke<SidecarStatus>('sidecar_start'),
    ])
      .then(([hostStatus, sidecarStatus]) => {
        if (!active) return;
        setHost(hostStatus);
        setSidecar(sidecarStatus);
      })
      .catch(() => {
        if (active) {
          setError('PIUI’s local helper is incompatible. Reinstall PIUI or open Diagnostics.');
        }
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
            <dd>{host ? 'Ready' : (error ?? 'Checking…')}</dd>
          </div>
          <div>
            <dt>Local helper</dt>
            <dd>{sidecar?.running ? 'Compatible' : (error ?? 'Checking…')}</dd>
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
