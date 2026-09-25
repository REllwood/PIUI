import { describe, expect, it } from 'vitest';
import { productFixture } from './fixtures';
import { canCreateConversation, hasConversationPrerequisites } from './readiness';
import type { ProductSnapshot } from './types';

const ready: ProductSnapshot = {
  ...productFixture,
  turnStatus: 'idle',
  workspace: productFixture.workspace
    ? { ...productFixture.workspace, trust: 'trusted' }
    : {
        capabilityId: 'workspace-a',
        name: 'Project',
        displayPath: 'Project',
        trust: 'trusted',
        lastOpenedAt: 'Just now',
      },
  providers: [
    {
      id: 'provider',
      name: 'Provider',
      detail: '',
      connected: true,
      methods: [],
      models: [{ id: 'model', name: 'Model', reasoning: true, acceptsImages: false }],
    },
  ],
};

describe('conversation readiness', () => {
  it('allows creation with a trusted project, a usable provider and no work running', () => {
    expect(canCreateConversation(ready, null)).toBe(true);
  });

  it('requires the connected provider to report at least one model', () => {
    const modelless = {
      ...ready,
      providers: ready.providers.map((provider) => ({ ...provider, models: [] })),
    };
    expect(hasConversationPrerequisites(modelless)).toBe(false);
    expect(canCreateConversation(modelless, null)).toBe(false);
  });

  it('waits for the active turn and any operation to finish', () => {
    expect(canCreateConversation({ ...ready, turnStatus: 'streaming' }, null)).toBe(false);
    expect(canCreateConversation(ready, 'session')).toBe(false);
  });

  it('requires an explicitly trusted project', () => {
    const untrusted = {
      ...ready,
      workspace: ready.workspace ? { ...ready.workspace, trust: 'untrusted' as const } : null,
    };
    expect(canCreateConversation(untrusted, null)).toBe(false);
  });
});
