import { useMemo, useRef, useState } from 'react';
import type {
  NativeApplicationData,
  NativeApplicationDataUpdate,
  NativeProvider,
  NativeWorkspaceSummary,
} from '../platform/native';
import { defaultNativeApplicationData } from '../platform/native';
import { AppearanceProvider } from '../features/appearance/AppearanceProvider';
import { OnboardingRoute } from '../features/onboarding/OnboardingRoute';
import type { OnboardingServices } from '../features/onboarding/useOnboarding';
import FixtureProductionApp from './FixtureProductionApp';
import '../styles/tokens.css';
import '../styles/theme-dark.css';
import '../styles/theme-light.css';
import '../styles/typography.css';
import '../styles/base.css';

function waitForFixture(): Promise<void> {
  return new Promise((resolve) => {
    // Only the deterministic preview waits; native operations use their actual duration.
    window.setTimeout(resolve, 250);
  });
}

function providerCatalogue(connectedProvider: string | null): readonly NativeProvider[] {
  return Object.freeze([
    {
      id: 'openai-codex',
      name: 'ChatGPT / Codex',
      methods: Object.freeze([
        { id: 'subscription', label: 'Continue with ChatGPT / Codex', classification: 'recommended' },
      ]),
      models: Object.freeze([
        {
          id: 'gpt-5.6',
          name: 'GPT-5.6',
          reasoning: true,
          acceptsImages: true,
          contextWindow: 200_000,
        },
      ]),
      status: connectedProvider === 'openai-codex' ? 'connected' : 'not-connected',
      ...(connectedProvider === 'openai-codex' ? { accountLabel: 'Local test account' } : {}),
    },
    {
      id: 'anthropic',
      name: 'Claude',
      methods: Object.freeze([
        { id: 'subscription', label: 'Continue with Claude', classification: 'recommended' },
      ]),
      models: Object.freeze([
        {
          id: 'claude-sonnet',
          name: 'Claude Sonnet',
          reasoning: true,
          acceptsImages: true,
          contextWindow: 200_000,
        },
      ]),
      status: connectedProvider === 'anthropic' ? 'connected' : 'not-connected',
      ...(connectedProvider === 'anthropic' ? { accountLabel: 'Local test account' } : {}),
    },
    {
      id: 'openai',
      name: 'OpenAI API',
      methods: Object.freeze([
        { id: 'api-key', label: 'Use an OpenAI API key', classification: 'fallback' },
      ]),
      models: Object.freeze([]),
      status: connectedProvider === 'openai' ? 'connected' : 'not-connected',
      ...(connectedProvider === 'openai' ? { accountLabel: 'OpenAI API key' } : {}),
    },
  ] satisfies readonly NativeProvider[]);
}

const untrustedWorkspace: NativeWorkspaceSummary = Object.freeze({
  workspaceId: 'workspace-fixture-0000000000000001',
  displayLabel: 'PIUI Fixture Project',
  revision: 1,
  trustState: 'untrusted',
  resourceState: 'not-loaded',
});

export default function FixtureOnboardingApp() {
  const requestedTheme = new URLSearchParams(window.location.search).get('theme') === 'light'
    ? 'light'
    : 'dark';
  const [applicationData, setApplicationData] = useState<NativeApplicationData>(
    defaultNativeApplicationData,
  );
  const [finished, setFinished] = useState(false);
  const connectedProvider = useRef<string | null>(null);

  const services = useMemo<OnboardingServices>(
    () => ({
      inspectNativeCredentialImport: async () => {
        await waitForFixture();
        return Object.freeze({
          available: true,
          candidates: Object.freeze([
            Object.freeze({ providerId: 'openai-codex', credentialType: 'subscription' as const }),
          ]),
        });
      },
      listProductProviders: async () => {
        await waitForFixture();
        return providerCatalogue(connectedProvider.current);
      },
      nativeHostStatus: async () => {
        await waitForFixture();
        return Object.freeze({
          status: 'ready' as const,
          architecture: 'arm64',
          transport: 'inherited-stdio' as const,
          listener: false as const,
        });
      },
      startLocalHelper: async () => {
        await waitForFixture();
        return Object.freeze({
          running: true,
          failed: false,
          protocolVersion: 1,
          nodeVersion: '22.23.1',
          piVersion: '0.82.0',
        });
      },
      nativeDiagnosticsSnapshot: async () => {
        await waitForFixture();
        return Object.freeze({
          checks: Object.freeze([
            Object.freeze({
              id: 'host',
              label: 'macOS and architecture',
              status: 'pass' as const,
              detail: 'Supported arm64 macOS host.',
            }),
            Object.freeze({
              id: 'sidecar',
              label: 'Bundled local helper',
              status: 'pass' as const,
              detail: 'Pinned runtime and Pi SDK handshake verified.',
            }),
            Object.freeze({
              id: 'network',
              label: 'Provider network',
              status: 'pass' as const,
              detail: 'Provider sign-in can be opened on request.',
            }),
          ]),
          environment: Object.freeze([]),
          logs: Object.freeze([]),
          helperFailure: null,
        });
      },
      importNativeCredentials: async (providerIds) => {
        await waitForFixture();
        return Object.freeze({
          importedProviderIds: Object.freeze([...providerIds]),
          sourceUnchanged: true as const,
        });
      },
      startProductAuthentication: async (request) => {
        request.onStarted('fixture-auth-request');
        request.onNotice({ type: 'progress', message: 'Waiting for provider confirmation.' });
        await waitForFixture();
        connectedProvider.current = request.providerId;
        request.onNotice({
          type: 'validated',
          providerId: request.providerId,
          accountLabel: 'Local test account',
        });
        return 'fixture-auth-request';
      },
      openDisclosedExternal: async () => undefined,
      presentNativeCredentialSheet: async (request) => {
        await waitForFixture();
        connectedProvider.current = request.providerId;
        return Object.freeze({
          savedState: 'saved' as const,
          credentialReference: 'credential-fixture-reference',
          accountLabel: request.accountLabel,
          validationState: 'saved-not-validated' as const,
        });
      },
      selectWorkspaceDirectory: async () => {
        await waitForFixture();
        return untrustedWorkspace;
      },
      inspectWorkspace: async () => {
        await waitForFixture();
        return untrustedWorkspace;
      },
      openWorkspaceUntrusted: async () => {
        await waitForFixture();
        return untrustedWorkspace;
      },
      authoriseWorkspace: async () => {
        await waitForFixture();
        return Object.freeze({
          ...untrustedWorkspace,
          revision: 2,
          trustState: 'trusted' as const,
          resourceState: 'preparing' as const,
        });
      },
      loadTrustedWorkspace: async () => {
        await waitForFixture();
        return Object.freeze({
          ...untrustedWorkspace,
          revision: 3,
          trustState: 'trusted' as const,
          resourceState: 'loaded' as const,
        });
      },
    }),
    [],
  );

  const persist = async (update: NativeApplicationDataUpdate): Promise<void> => {
    await waitForFixture();
    setApplicationData((current) =>
      typeof update === 'function' ? update(current) : update,
    );
  };

  if (finished) return <FixtureProductionApp />;

  return (
    <AppearanceProvider
      initialPreferences={{
        theme: requestedTheme,
        increasedContrast: false,
        reduceTransparency: false,
        reduceMotion: true,
        accessibleTranscript: false,
      }}
    >
      <div className="piui" data-test-fixture="onboarding">
        <OnboardingRoute
          applicationData={applicationData}
          onPersist={persist}
          onFinish={() => setFinished(true)}
          services={services}
        />
      </div>
    </AppearanceProvider>
  );
}
