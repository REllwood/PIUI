import { lazy, Suspense, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  A27_LIFECYCLE_ROUTE,
  A27_LIFECYCLE_TEST_ACTIVE,
  A28_ACCESSIBILITY_ROUTE,
  A28_ACCESSIBILITY_TEST_ACTIVE,
} from './architecture-gate/routeActivation';
import {
  A26_MARKDOWN_ROUTE,
  A26_MARKDOWN_TEST_ACTIVE,
} from './architecture-gate/a26MarkdownPrelude';
import { LoadingLabel } from './components/primitives/LoadingLabel';

// Probe routes exist only in development or in the architecture-test build that sets
// their flag. Each lazy import sits behind that compile-time gate, so a production build
// drops the probe chunks (and the hostile Markdown fixture) entirely.
const CredentialProbe =
  import.meta.env.DEV || import.meta.env.VITE_PIUI_A23_CREDENTIAL_TEST === '1'
    ? lazy(() =>
        import('./architecture-gate/CredentialProbe').then((module) => ({
          default: module.CredentialProbe,
        })),
      )
    : null;
const LifecycleProbe =
  import.meta.env.VITE_PIUI_A27_LIFECYCLE_TEST === '1'
    ? lazy(() =>
        import('./architecture-gate/LifecycleProbe').then((module) => ({
          default: module.LifecycleProbe,
        })),
      )
    : null;
const MarkdownProbe =
  import.meta.env.VITE_PIUI_A26_MARKDOWN_TEST === '1'
    ? lazy(() =>
        import('./architecture-gate/MarkdownProbe').then((module) => ({
          default: module.MarkdownProbe,
        })),
      )
    : null;
const StreamProbeRoute = import.meta.env.DEV
  ? lazy(() =>
      import('./architecture-gate/StreamProbe').then((module) => ({
        default: module.StreamProbeRoute,
      })),
    )
  : null;
const AccessibilityProbe =
  import.meta.env.VITE_PIUI_A28_ACCESSIBILITY_TEST === '1'
    ? lazy(() =>
        import('./architecture-gate/AccessibilityProbe').then((module) => ({
          default: module.AccessibilityProbe,
        })),
      )
    : null;
const SafeMarkdownSpikeRoute = import.meta.env.DEV
  ? lazy(() =>
      import('./security/SafeMarkdownSpikeRoute').then((module) => ({
        default: module.SafeMarkdownSpikeRoute,
      })),
    )
  : null;
const ProductionApp = lazy(() =>
  import('./app/ProductionApp').then((module) => ({ default: module.ProductionApp })),
);
const FixtureProductionApp = import.meta.env.DEV
  ? lazy(() => import('./testing/FixtureProductionApp'))
  : null;
const FixtureOnboardingApp = import.meta.env.DEV
  ? lazy(() => import('./testing/FixtureOnboardingApp'))
  : null;

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
  const fixture = new URLSearchParams(window.location.search).get('fixture');
  if (import.meta.env.DEV && fixture === 'product' && FixtureProductionApp) {
    return (
      <Suspense
        fallback={
          <main className="startup-status" role="status">
            <LoadingLabel>Loading test fixture…</LoadingLabel>
          </main>
        }
      >
        <FixtureProductionApp />
      </Suspense>
    );
  }
  if (import.meta.env.DEV && fixture === 'onboarding' && FixtureOnboardingApp) {
    return (
      <Suspense
        fallback={
          <main className="startup-status" role="status">
            <LoadingLabel>Loading onboarding fixture…</LoadingLabel>
          </main>
        }
      >
        <FixtureOnboardingApp />
      </Suspense>
    );
  }
  const spike = new URLSearchParams(window.location.search).get('spike');
  if (CredentialProbe && spike === 'credential') {
    return <DeferredRoute><CredentialProbe /></DeferredRoute>;
  }
  if (StreamProbeRoute && spike === 'stream') {
    return <DeferredRoute><StreamProbeRoute /></DeferredRoute>;
  }
  if (SafeMarkdownSpikeRoute && spike === 'markdown') {
    return <DeferredRoute><SafeMarkdownSpikeRoute /></DeferredRoute>;
  }
  if (A26_MARKDOWN_TEST_ACTIVE && MarkdownProbe && spike === A26_MARKDOWN_ROUTE) {
    return <DeferredRoute><MarkdownProbe /></DeferredRoute>;
  }
  if (A27_LIFECYCLE_TEST_ACTIVE && LifecycleProbe && spike === A27_LIFECYCLE_ROUTE) {
    return <DeferredRoute><LifecycleProbe /></DeferredRoute>;
  }
  if (A28_ACCESSIBILITY_TEST_ACTIVE && AccessibilityProbe && spike === A28_ACCESSIBILITY_ROUTE) {
    return <DeferredRoute><AccessibilityProbe /></DeferredRoute>;
  }
  if (import.meta.env.DEV && spike === 'architecture-gate') return <ArchitectureGate />;
  return (
    <Suspense
      fallback={
        <main className="startup-status" role="status">
          <LoadingLabel>Loading PIUI…</LoadingLabel>
        </main>
      }
    >
      <ProductionApp />
    </Suspense>
  );
}

function DeferredRoute({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <Suspense
      fallback={
        <main className="startup-status" role="status">
          <LoadingLabel>Loading local view…</LoadingLabel>
        </main>
      }
    >
      {children}
    </Suspense>
  );
}

function ArchitectureGate() {
  const [host, setHost] = useState<HostStatus | null>(null);
  const [sidecar, setSidecar] = useState<SidecarStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void Promise.all([invoke<HostStatus>('host_status'), invoke<SidecarStatus>('sidecar_start')])
      .then(([hostStatus, sidecarStatus]) => {
        if (!active) return;
        setHost(hostStatus);
        setSidecar(sidecarStatus);
      })
      .catch(() => {
        if (active) {
          setError("PIUI's local helper is incompatible. Reinstall PIUI or open Diagnostics.");
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
