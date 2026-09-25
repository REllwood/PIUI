import { ONBOARDING_STEPS } from '../../domain/onboardingMachine';
import { Icon } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { CheckMacStep } from './CheckMacStep';
import { ChooseProjectStep } from './ChooseProjectStep';
import { ConnectProviderStep } from './ConnectProviderStep';
import { ImportStep } from './ImportStep';
import { ReadyStep } from './ReadyStep';
import { useOnboarding } from './useOnboarding';
import type { OnboardingServices } from './useOnboarding';
import { WelcomeStep } from './WelcomeStep';
import './onboarding.css';
import type {
  NativeApplicationData,
  NativeApplicationDataUpdate,
} from '../../platform/native';

const labels = ['Welcome', 'Check', 'Import', 'Connect', 'Project', 'Ready'] as const;

export function OnboardingRoute({
  applicationData,
  onPersist,
  onFinish,
  services,
}: Readonly<{
  applicationData: NativeApplicationData;
  onPersist: (update: NativeApplicationDataUpdate) => Promise<void>;
  onFinish: () => void;
  services?: OnboardingServices;
}>) {
  const onboarding = useOnboarding(onFinish, applicationData, onPersist, services);
  const { state } = onboarding;
  const index = ONBOARDING_STEPS.indexOf(state.step);
  const content = {
    welcome: <WelcomeStep />,
    check: (
      <CheckMacStep
        status={onboarding.checkState}
        checks={onboarding.checkResults}
        onRun={onboarding.runChecks}
      />
    ),
    import: (
      <ImportStep
        state={onboarding.importState}
        providerCount={onboarding.importCandidates.length}
        onImport={onboarding.importExistingCredentials}
        onSkip={() => onboarding.dispatch({ type: 'skip-import' })}
      />
    ),
    connect: (
      <ConnectProviderStep
        state={onboarding.authState}
        provider={onboarding.provider}
        providers={onboarding.providerCatalogue}
        notice={onboarding.authNotice}
        onConnect={onboarding.connectProvider}
        onApiKey={onboarding.connectApiKey}
      />
    ),
    project: (
      <ChooseProjectStep
        project={onboarding.project}
        busy={onboarding.projectBusy}
        error={onboarding.projectError}
        onChoose={onboarding.chooseProject}
        onTrust={onboarding.trustProject}
      />
    ),
    ready: (
      <ReadyStep provider={onboarding.providerSummary} project={onboarding.project} />
    ),
  }[state.step];
  const canContinue =
    state.step === 'check'
      ? onboarding.checkState === 'pass' || onboarding.checkState === 'offline'
      : state.step === 'connect'
        ? state.providerConnected
        : state.step === 'project'
          ? state.projectSelected
          : true;
  const waiting =
    onboarding.checkState === 'running' ||
    onboarding.authState === 'opening' ||
    onboarding.authState === 'waiting' ||
    onboarding.projectBusy;

  return (
    <main className="onboarding-shell" aria-labelledby="onboarding-title">
      <header className="onboarding-toolbar" data-tauri-drag-region>
        <div className="onboarding-brand">
          <span className="brand-mark" aria-hidden="true">
            π
          </span>
          <strong>PIUI</strong>
        </div>
        <span>Private local setup</span>
        <button type="button" className="button button--quiet" onClick={onFinish}>
          Set up later
        </button>
      </header>
      <div className="onboarding-stage">
        <nav className="onboarding-progress" aria-label="Setup progress">
          <ol>
            {labels.map((label, stepIndex) => (
              <li
                key={label}
                aria-current={stepIndex === index ? 'step' : undefined}
                data-complete={stepIndex < index}
              >
                <span>{stepIndex < index ? <Icon name="check" /> : stepIndex + 1}</span>
                <strong>{label}</strong>
              </li>
            ))}
          </ol>
          <div className="onboarding-progress__privacy">
            <Icon name="shield" />
            <p>
              <strong>Secrets stay outside this screen.</strong>Provider credentials are handled
              only by trusted local code and macOS Keychain.
            </p>
          </div>
        </nav>
        <section className="onboarding-content">
          <h1 id="onboarding-title" className="sr-only">
            PIUI setup — {labels[index]}
          </h1>
          {content}
        </section>
      </div>
      <footer className="onboarding-actions">
        <span>
          Step {index + 1} of {labels.length}
        </span>
        <div>
          {index > 0 ? (
            <button
              type="button"
              className="button"
              onClick={() => onboarding.dispatch({ type: 'back' })}
              disabled={waiting}
            >
              Back
            </button>
          ) : null}
          {state.step === 'ready' ? (
            <button
              type="button"
              className="button button--primary"
              onClick={() => void onboarding.finish()}
              disabled={onboarding.finishing}
            >
              {onboarding.finishing ? (
                <LoadingLabel>Saving setup…</LoadingLabel>
              ) : (
                <>
                  <Icon name="check" />
                  Finish and open PIUI
                </>
              )}
            </button>
          ) : (
            <button
              type="button"
              className="button button--primary"
              onClick={() => onboarding.dispatch({ type: 'continue' })}
              disabled={!canContinue || waiting}
            >
              {waiting ? (
                <LoadingLabel>Waiting…</LoadingLabel>
              ) : (
                <>
                  Continue
                  <Icon name="chevron-right" />
                </>
              )}
            </button>
          )}
        </div>
      </footer>
    </main>
  );
}
