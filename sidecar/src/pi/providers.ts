import type { PublicModelRuntimeInstance } from './public-sdk.js';
import type { ProviderDescriptor, ProviderMethod } from './adapter.js';

type RuntimeProvider = ReturnType<PublicModelRuntimeInstance['getProviders']>[number];

function tailoredOAuth(provider: RuntimeProvider): ProviderMethod {
  if (provider.id === 'openai-codex')
    return {
      id: 'subscription',
      label: 'Continue with ChatGPT / Codex',
      classification: 'recommended',
    };
  if (provider.id === 'anthropic' || provider.id === 'anthropic-claude')
    return { id: 'subscription', label: 'Continue with Claude', classification: 'recommended' };
  return {
    id: 'subscription',
    label: provider.auth.oauth?.loginLabel ?? `Continue with ${provider.name}`,
    classification: 'supported',
  };
}

function providerMethods(provider: RuntimeProvider): readonly ProviderMethod[] {
  const methods: ProviderMethod[] = [];
  if (provider.auth.oauth) methods.push(tailoredOAuth(provider));
  if (provider.auth.apiKey?.login)
    methods.push({ id: 'api-key', label: 'Use an API key instead', classification: 'fallback' });
  else if (provider.auth.apiKey)
    methods.push({
      id: 'ambient',
      label: 'Use configured local credentials',
      classification: 'supported',
    });
  return Object.freeze(methods);
}

export async function describeProviders(
  runtime: PublicModelRuntimeInstance,
): Promise<readonly ProviderDescriptor[]> {
  const providers = runtime.getProviders();
  const result = await Promise.all(
    providers.map(async (provider) => {
      let status: ProviderDescriptor['status'] = 'unknown';
      try {
        status = (await runtime.checkAuth(provider.id)) ? 'connected' : 'not-connected';
      } catch {
        status = 'unknown';
      }
      const models = runtime
        .getModels(provider.id)
        .slice(0, 512)
        .map((model) =>
          Object.freeze({
            id: model.id,
            name: model.name,
            reasoning: model.reasoning,
            acceptsImages: model.input.includes('image'),
            contextWindow: model.contextWindow,
          }),
        );
      return Object.freeze({
        id: provider.id,
        name: provider.name,
        methods: providerMethods(provider),
        models: Object.freeze(models),
        status,
      });
    }),
  );
  return Object.freeze(
    result.sort((left, right) => {
      const rank = (id: string) => (id === 'openai-codex' ? 0 : id.includes('anthropic') ? 1 : 2);
      return rank(left.id) - rank(right.id) || left.name.localeCompare(right.name, 'en-AU');
    }),
  );
}
