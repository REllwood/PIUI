import { useState } from 'react';
import { Icon } from '../../components/icons/Icon';
import { StatusPill } from '../../components/primitives/StatusPill';
import { ProductTour } from './ProductTour';

export function ReadyStep({
  provider,
  project,
}: Readonly<{
  provider: Readonly<{ name: string; accountLabel: string }> | null;
  project: Readonly<{ name: string; trust: 'untrusted' | 'trusted' | 'revoked' }> | null;
}>) {
  const [showTour, setShowTour] = useState(true);
  return (
    <div className="onboarding-step onboarding-ready">
      <div className="onboarding-copy">
        <p className="ui-label">Ready</p>
        <h1>Your local workspace is ready.</h1>
        <p className="onboarding-lead">
          PIUI will open in Simple mode. You can replay the short tour or enable Advanced mode later
          in Settings.
        </p>
        <ul className="ready-summary">
          <li>
            <Icon name="conversation" />
            <span>
              <strong>Provider</strong>
              <small>
                {provider ? `${provider.name} · ${provider.accountLabel}` : 'No provider selected'}
              </small>
            </span>
            <StatusPill tone={provider ? 'success' : 'warning'}>
              {provider ? 'Connected' : 'Not connected'}
            </StatusPill>
          </li>
          <li>
            <Icon name="folder" />
            <span>
              <strong>Project</strong>
              <small>
                {project?.name ?? 'No project selected'} · {project?.trust ?? 'not selected'}
              </small>
            </span>
            <StatusPill tone={project ? (project.trust === 'trusted' ? 'success' : 'warning') : 'warning'}>
              {project ? (project.trust === 'trusted' ? 'Trusted' : 'Selected') : 'Not selected'}
            </StatusPill>
          </li>
          <li>
            <Icon name="shield" />
            <span>
              <strong>Data boundaries</strong>
              <small>
                Credentials in Keychain; non-secret preferences in PIUI application data.
              </small>
            </span>
            <StatusPill>Local</StatusPill>
          </li>
        </ul>
      </div>
      {showTour ? (
        <ProductTour onSkip={() => setShowTour(false)} />
      ) : (
        <div className="ready-preview">
          <div className="ready-orb" aria-hidden="true" />
          <h2>Tour skipped</h2>
          <p>You can replay the product tour from General Settings at any time.</p>
          <button type="button" className="button" onClick={() => setShowTour(true)}>
            Replay tour
          </button>
        </div>
      )}
    </div>
  );
}
