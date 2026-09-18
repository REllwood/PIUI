import { describe, expect, it } from 'vitest';
import { describeProviders } from '../../sidecar/src/pi/providers';
import type { PublicModelRuntimeInstance } from '../../sidecar/src/pi/public-sdk';

function runtimeFixture(): PublicModelRuntimeInstance {
  const providers = [
    {
      id: 'generic-provider',
      name: 'Generic Provider',
      auth: {
        oauth: { loginLabel: 'Sign in to Generic Provider' },
        apiKey: { login: true },
      },
    },
    {
      id: 'anthropic',
      name: 'Anthropic',
      auth: { oauth: { loginLabel: 'Sign in' }, apiKey: { login: true } },
    },
    {
      id: 'openai-codex',
      name: 'OpenAI Codex',
      auth: { oauth: { loginLabel: 'Sign in' }, apiKey: { login: true } },
    },
  ];
  return {
    getProviders: () => providers,
    checkAuth: async (providerId: string) => providerId === 'openai-codex',
    getModels: (providerId: string) => [
      {
        id: `${providerId}-model`,
        name: `${providerId} model`,
        reasoning: true,
        input: ['text', 'image'],
        contextWindow: 128_000,
      },
    ],
  } as unknown as PublicModelRuntimeInstance;
}

describe('provider projection', () => {
  it('prioritises mainstream subscription sign-in and keeps API keys secondary', async () => {
    const providers = await describeProviders(runtimeFixture());
    expect(providers.map((provider) => provider.id)).toEqual([
      'openai-codex',
      'anthropic',
      'generic-provider',
    ]);
    expect(providers[0]?.methods).toEqual([
      {
        id: 'subscription',
        label: 'Continue with ChatGPT / Codex',
        classification: 'recommended',
      },
      { id: 'api-key', label: 'Use an API key instead', classification: 'fallback' },
    ]);
    expect(providers[1]?.methods[0]?.label).toBe('Continue with Claude');
    expect(providers[2]?.methods[0]?.classification).toBe('supported');
    expect(providers[0]?.status).toBe('connected');
    expect(providers[1]?.status).toBe('not-connected');
    expect(JSON.stringify(providers)).not.toMatch(/token|secret|credential/iu);
  });
});
