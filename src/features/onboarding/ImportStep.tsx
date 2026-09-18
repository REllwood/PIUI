import { useState } from 'react';
import { Icon } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { Toggle } from '../appearance/AppearanceControls';

export function ImportStep({
  state,
  providerCount,
  onImport,
  onSkip,
}: Readonly<{
  state: 'checking' | 'available' | 'unavailable' | 'importing' | 'complete' | 'failed';
  providerCount: number;
  onImport: () => Promise<void>;
  onSkip: () => void;
}>) {
  const [consent, setConsent] = useState(false);
  const importing = state === 'checking' || state === 'importing';
  const complete = state === 'complete';
  return (
    <div className="onboarding-step onboarding-import">
      <div className="onboarding-copy">
        <p className="ui-label">Import existing setup</p>
        <h1>Bring across existing provider access, if you want to.</h1>
        <p className="onboarding-lead">
          Import is one-way and optional. PIUI leaves ordinary Pi configuration unchanged and never
          shows credential values here.
        </p>
        <div className="boundary-note">
          <Icon name="shield" />
          <p>
            Selected credentials are copied into macOS Keychain. PIUI does not write them back to
            the Pi command-line setup.
          </p>
        </div>
      </div>
      <section className="choice-card">
        <div className="choice-card__heading">
          <Icon name="download" />
          <div>
            <h2>
              {state === 'unavailable' ? 'No importable Pi setup found' : 'Existing Pi setup'}
            </h2>
            <p>
              {state === 'checking'
                ? 'Checking restrictive source permissions…'
                : state === 'available' || complete
                  ? `${providerCount} provider ${providerCount === 1 ? 'record is' : 'records are'} available. Values have not been read into this screen.`
                  : state === 'failed'
                    ? 'The source could not be validated safely. Nothing was imported.'
                    : 'You can skip this step and connect a provider next.'}
            </p>
          </div>
        </div>
        <Toggle
          label="Import selected provider credentials"
          detail="Off by default. Source permissions and provider records are validated first."
          checked={consent}
          onChange={setConsent}
        />
        {complete ? (
          <p className="inline-notice" data-tone="success">
            Import completed. The source was not changed.
          </p>
        ) : null}
        <div className="choice-card__actions">
          <button type="button" className="button button--quiet" onClick={onSkip}>
            Skip import
          </button>
          <button
            type="button"
            className="button button--primary"
            disabled={!consent || importing || complete || state !== 'available'}
            onClick={() => void onImport()}
          >
            {importing ? (
              <LoadingLabel>Importing securely…</LoadingLabel>
            ) : complete ? (
              <>
                <Icon name="check" />
                Imported
              </>
            ) : (
              'Import to Keychain'
            )}
          </button>
        </div>
      </section>
    </div>
  );
}
