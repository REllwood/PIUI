import { createHash } from 'node:crypto';
import {
  publicFauxAssistantMessage,
  publicFauxProvider,
  type PublicAiProvider,
  type PublicAssistantMessage,
} from './ai-public-sdk.js';
import type { DeterministicTurnEvidence } from './session-spike.js';
import type {
  PublicAgentSession,
  PublicAgentSessionEvent,
  PublicModelRuntimeInstance,
} from './public-sdk.js';

type Options = Readonly<{
  session: PublicAgentSession;
  modelRuntime: PublicModelRuntimeInstance;
  credentialWrites(): number;
  approvalHostCalls(): number;
}>;

export async function runFixedDeterministicTurn(options: Options): Promise<DeterministicTurnEvidence> {
  const forbidden = 'A22-FORBIDDEN-FINAL-CHUNK';
  const faux = publicFauxProvider({
    api: 'a22-offline-api',
    provider: 'a22-offline-provider',
    models: [{ id: 'a22-model', name: 'A.22 offline model', reasoning: false, input: ['text'], contextWindow: 8_192, maxTokens: 256 }],
    tokenSize: { min: 1, max: 1 },
    tokensPerSecond: 1_000,
  });
  faux.setResponses([publicFauxAssistantMessage(`A22-PARTIAL-${'x'.repeat(128)}-${forbidden}`, { timestamp: 0 })]);

  let providerCalls = 0;
  let providerAbortObserved = false;
  const observeSignal = (signal: AbortSignal | undefined): void => {
    providerCalls += 1;
    if (!signal) throw new Error('deterministic-turn-rejected');
    signal.addEventListener('abort', () => { providerAbortObserved = true; }, { once: true });
  };
  const observedStream: PublicAiProvider['stream'] = (model, context, streamOptions) => {
    observeSignal(streamOptions?.signal);
    return faux.provider.stream(model, context, streamOptions);
  };
  const observedStreamSimple: PublicAiProvider['streamSimple'] = (model, context, streamOptions) => {
    observeSignal(streamOptions?.signal);
    return faux.provider.streamSimple(model, context, streamOptions);
  };
  const provider: PublicAiProvider = Object.freeze({ ...faux.provider, stream: observedStream, streamSimple: observedStreamSimple });
  options.modelRuntime.registerNativeProvider(provider);
  await options.session.setModel(faux.getModel());

  let messageStarts = 0;
  let textDeltas = 0;
  let abortedTerminals = 0;
  let completeTerminals = 0;
  let terminalSeen = false;
  let postTerminalEvents = 0;
  let partial = '';
  let resolveFirstDelta: (() => void) | undefined;
  const firstDelta = new Promise<void>((resolveFirst) => { resolveFirstDelta = resolveFirst; });
  const unsubscribe = options.session.subscribe((event: PublicAgentSessionEvent) => {
    if (terminalSeen && event.type === 'message_update') postTerminalEvents += 1;
    if (event.type === 'message_start' && event.message.role === 'assistant') messageStarts += 1;
    if (event.type === 'message_update' && event.assistantMessageEvent.type === 'text_delta') {
      textDeltas += 1;
      partial += event.assistantMessageEvent.delta;
      resolveFirstDelta?.();
      resolveFirstDelta = undefined;
    }
    if (event.type === 'message_end' && event.message.role === 'assistant') {
      terminalSeen = true;
      if (event.message.stopReason === 'aborted') abortedTerminals += 1;
      else completeTerminals += 1;
    }
  });

  const prompt = options.session.prompt('A.22 fixed cancellation probe', { expandPromptTemplates: false });
  const readinessTimeout = new Promise<never>((_, rejectTimeout) => {
    setTimeout(() => rejectTimeout(new Error('deterministic-turn-rejected')), 2_000).unref();
  });
  await Promise.race([firstDelta, readinessTimeout]);
  const cancellationStart = performance.now();
  await options.session.abort();
  await prompt;
  const cancellationLatencyMilliseconds = Math.ceil(performance.now() - cancellationStart);
  unsubscribe();
  await Promise.resolve();

  const finalAssistant = [...options.session.messages].reverse().find(
    (message): message is PublicAssistantMessage => message.role === 'assistant',
  );
  const partialBytes = Buffer.byteLength(partial, 'utf8');
  if (providerCalls !== 1 || !providerAbortObserved || messageStarts !== 1 || textDeltas < 1 || textDeltas > 32
    || abortedTerminals !== 1 || completeTerminals !== 0 || postTerminalEvents !== 0
    || finalAssistant?.stopReason !== 'aborted' || partial.includes(forbidden)
    || partialBytes < 1 || partialBytes > 1_024 || cancellationLatencyMilliseconds > 1_000
    || options.credentialWrites() !== 0 || options.approvalHostCalls() !== 0) {
    throw new Error('deterministic-turn-rejected');
  }
  return Object.freeze({
    providerCalls: 1 as const,
    providerAbortObserved: true as const,
    messageStarts: 1 as const,
    textDeltas,
    abortedTerminals: 1 as const,
    completeTerminals: 0 as const,
    postTerminalEvents: 0 as const,
    forbiddenFinalChunkAbsent: true as const,
    partialBytes,
    partialSha256: createHash('sha256').update(partial, 'utf8').digest('hex'),
    cancellationLatencyMilliseconds,
  });
}
