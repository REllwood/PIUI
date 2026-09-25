import {
  fauxAssistantMessage,
  fauxProvider,
  fauxToolCall,
  type AssistantMessage,
  type AuthEvent,
  type AuthInteraction,
  type AuthPrompt,
  type Provider,
  type SimpleStreamOptions,
} from '@earendil-works/pi-ai';

// The sidecar's only pi-ai import. Keep every pi-ai value and type on the
// exact package root; production code must never reach into package internals.
export const publicFauxAssistantMessage = fauxAssistantMessage;
export const publicFauxProvider = fauxProvider;
export const publicFauxToolCall = fauxToolCall;
export type PublicAssistantMessage = AssistantMessage;
export type PublicAiProvider = Provider;
export type PublicSimpleStreamOptions = SimpleStreamOptions;
export type PublicAuthEvent = AuthEvent;
export type PublicAuthInteraction = AuthInteraction;
export type PublicAuthPrompt = AuthPrompt;
