import {
  fauxAssistantMessage,
  fauxProvider,
  type AssistantMessage,
  type Provider,
  type SimpleStreamOptions,
} from '@earendil-works/pi-ai';

// A.22's only pi-ai import. Keep the deterministic provider on the exact
// package root; production code must never reach into package internals.
export const publicFauxAssistantMessage = fauxAssistantMessage;
export const publicFauxProvider = fauxProvider;
export type PublicAssistantMessage = AssistantMessage;
export type PublicAiProvider = Provider;
export type PublicSimpleStreamOptions = SimpleStreamOptions;
