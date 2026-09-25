import { isTurnActive } from './machines';
import type { ProductSnapshot } from './types';

// A new conversation needs a trusted project and a connected provider that reports a model.
export function hasConversationPrerequisites(
  snapshot: Pick<ProductSnapshot, 'workspace' | 'providers'>,
): boolean {
  return (
    snapshot.workspace?.trust === 'trusted' &&
    snapshot.providers.some((provider) => provider.connected && provider.models.length > 0)
  );
}

// Every surface that offers "New conversation" shares this rule so they enable together.
export function canCreateConversation(
  snapshot: Pick<ProductSnapshot, 'workspace' | 'providers' | 'turnStatus'>,
  activeOperation: string | null,
): boolean {
  return (
    hasConversationPrerequisites(snapshot) &&
    !isTurnActive(snapshot.turnStatus) &&
    activeOperation === null
  );
}
