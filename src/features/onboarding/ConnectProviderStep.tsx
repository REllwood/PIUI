import { useState } from 'react';
import { Icon } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { StatusPill } from '../../components/primitives/StatusPill';
import type { NativeAuthNotice, NativeProvider } from '../../platform/native';

export function ConnectProviderStep({
  state,
  provider,
  providers,
  notice,
  onConnect,
  onApiKey,
}: Readonly<{
  state: 'idle' | 'opening' | 'waiting' | 'validated' | 'cancelled' | 'expired' | 'failed';
  provider: string | null;
  providers: readonly NativeProvider[];
  notice: NativeAuthNotice | null;
  onConnect: (id: string) => void;
  onApiKey: (id: string, label: string) => Promise<void>;
}>) {
  const [more, setMore] = useState(false);
  const [apiKey, setApiKey] = useState(false);
  const waiting = state === 'opening' || state === 'waiting';
  const mainstreamIds = new Set(['openai-codex', 'anthropic', 'anthropic-claude']);
  const additionalProviders = providers.filter(
    (candidate) =>
      !mainstreamIds.has(candidate.id) &&
      candidate.methods.some((method) => method.id === 'subscription' || method.id === 'api-key'),
  );
  const connectedProvider = providers.find((candidate) => candidate.id === provider);
  return (
    <div className="onboarding-step onboarding-connect">
      <div className="onboarding-copy">
        <p className="ui-label">Connect a provider</p>
        <h1>Use a subscription you already have.</h1>
        <p className="onboarding-lead">
          Sign-in opens in your browser. PIUI receives only a validated account label; provider
          tokens stay in trusted local code.
        </p>
        {waiting ? (
          <div className="auth-wait" role="status">
            <LoadingLabel>
              {state === 'opening'
                ? 'Opening the trusted sign-in flow…'
                : 'Checking provider confirmation…'}
            </LoadingLabel>
            <p>PIUI is checking the private credential store. No token is sent to this screen.</p>
            {notice?.type === 'device-code' ? (
              <p>
                Enter code <strong>{notice.userCode}</strong> in the browser window.
              </p>
            ) : null}
            {notice?.type === 'progress' ? <p>{notice.message}</p> : null}
          </div>
        ) : null}
        {state === 'validated' ? (
          <div className="inline-notice" data-tone="success">
            <Icon name="check" />
            {connectedProvider?.name ?? 'Provider'} connected and validated.
          </div>
        ) : null}
        {state === 'failed' ? (
          <div className="inline-notice" data-tone="warning">
            The subscription sign-in was not completed. Retry it, or use the native API-key fallback
            below.
          </div>
        ) : null}
        {state === 'cancelled' ? (
          <div className="inline-notice">Credential entry was cancelled. Nothing was saved.</div>
        ) : null}
      </div>
      <section className="provider-choices">
        <button
          type="button"
          className="provider-choice"
          disabled={waiting || state === 'validated'}
          onClick={() => onConnect('openai-codex')}
        >
          <span className="provider-glyph">C</span>
          <span>
            <strong>Continue with ChatGPT / Codex</strong>
            <small>For ChatGPT Plus or Pro subscriptions</small>
          </span>
          <Icon name="external" />
        </button>
        <button
          type="button"
          className="provider-choice"
          disabled={waiting || state === 'validated'}
          onClick={() => onConnect('anthropic')}
        >
          <span className="provider-glyph">A</span>
          <span>
            <strong>Continue with Claude</strong>
            <small>For Claude Pro or Max subscriptions</small>
          </span>
          <Icon name="external" />
        </button>
        <button
          type="button"
          className="provider-choice provider-choice--more"
          aria-expanded={more}
          onClick={() => setMore((current) => !current)}
        >
          <Icon name={more ? 'chevron-down' : 'chevron-right'} />
          <span>
            <strong>More providers</strong>
            <small>Browse all providers supported by Pi</small>
          </span>
        </button>
        {more ? (
          <div className="more-providers">
            {additionalProviders.map((candidate) => (
              <button
                key={candidate.id}
                type="button"
                className="button"
                disabled={waiting}
                onClick={() => {
                  if (candidate.methods.some((method) => method.id === 'subscription')) {
                    onConnect(candidate.id);
                  } else {
                    void onApiKey(candidate.id, candidate.name);
                  }
                }}
              >
                {candidate.methods.find((method) => method.id === 'subscription')?.label ??
                  `Use a ${candidate.name} API key`}
              </button>
            ))}
            {additionalProviders.length === 0 ? (
              <p>No additional subscription providers are available in this Pi build.</p>
            ) : null}
          </div>
        ) : null}
        <button
          type="button"
          className="api-key-disclosure"
          aria-expanded={apiKey}
          onClick={() => setApiKey((current) => !current)}
        >
          Use an API key instead <Icon name={apiKey ? 'chevron-down' : 'chevron-right'} />
        </button>
        {apiKey ? (
          <div className="boundary-note">
            <Icon name="shield" />
            <p>
              PIUI will open a native macOS sheet for the key. No secret input appears in this
              WebView.
            </p>
            <div className="choice-card__actions">
              <button
                type="button"
                className="button"
                disabled={waiting}
                onClick={() => void onApiKey('openai', 'OpenAI')}
              >
                Enter OpenAI API key
              </button>
              <button
                type="button"
                className="button"
                disabled={waiting}
                onClick={() => void onApiKey('anthropic', 'Anthropic')}
              >
                Enter Anthropic API key
              </button>
            </div>
          </div>
        ) : null}
      </section>
    </div>
  );
}
