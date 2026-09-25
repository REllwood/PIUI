import { isSaveableThinkingLevel } from './thinking';
import type { ProductSnapshot } from './types';

type SessionProvider = Readonly<{
  id: string;
  status: string;
  models: readonly Readonly<{ id: string }>[];
}>;

type SessionSetting = Readonly<{ key: string; value: unknown }>;

export function preferredSessionModel(
  providers: readonly SessionProvider[],
  settings: readonly SessionSetting[],
): Readonly<{ providerId: string; modelId: string }> | null {
  const providerId = settings.find((setting) => setting.key === 'model.provider')?.value;
  const modelId = settings.find((setting) => setting.key === 'model.id')?.value;
  const connected = providers.filter(
    (provider) => provider.status === 'connected' && provider.models.length > 0,
  );
  const preferred = connected.find(
    (provider) =>
      provider.id === providerId && provider.models.some((model) => model.id === modelId),
  );
  if (preferred && typeof modelId === 'string') {
    return { providerId: preferred.id, modelId };
  }
  const fallback = connected[0];
  const model = fallback?.models[0];
  return fallback && model ? { providerId: fallback.id, modelId: model.id } : null;
}

export function preferredSessionThinking(settings: readonly SessionSetting[]): string | null {
  const value = settings.find((setting) => setting.key === 'reasoning.level')?.value;
  return isSaveableThinkingLevel(value) ? value : null;
}

export type CompletedTranscript = Readonly<{
  sessionId: string;
  generation: number;
  messages: ProductSnapshot['messages'];
}>;

export function canReconcileTranscript(
  completed: CompletedTranscript,
  current: ProductSnapshot,
): boolean {
  return (
    current.activeSessionId === completed.sessionId &&
    current.sessions.some(
      (session) =>
        session.id === completed.sessionId && session.generation === completed.generation,
    ) &&
    current.connection === 'ready' &&
    current.turnStatus === 'complete' &&
    // A later send, reload, compaction or session switch replaces the transcript.
    current.messages === completed.messages
  );
}
