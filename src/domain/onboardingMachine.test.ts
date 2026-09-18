import { describe, expect, it } from 'vitest';
import {
  initialOnboardingState,
  reduceOnboarding,
  restoreOnboarding,
  serialiseOnboarding,
} from './onboardingMachine';

describe('onboarding state', () => {
  it('blocks provider and project progression until their prerequisites are acknowledged', () => {
    const connect = { ...initialOnboardingState, step: 'connect' as const };
    expect(reduceOnboarding(connect, { type: 'continue' })).toBe(connect);
    const connected = reduceOnboarding(connect, { type: 'provider-connected' });
    expect(reduceOnboarding(connected, { type: 'continue' }).step).toBe('project');
    const project = { ...connected, step: 'project' as const };
    expect(reduceOnboarding(project, { type: 'continue' })).toBe(project);
  });

  it('restores only known steps from versioned data', () => {
    const restored = restoreOnboarding(
      JSON.stringify({ version: 1, completed: ['welcome', 'unknown', 'check'], finished: false }),
    );
    expect(restored.completed).toEqual(['welcome', 'check']);
    expect(restored.step).toBe('import');
    expect(restoreOnboarding('{broken')).toBe(initialOnboardingState);
  });

  it('restores acknowledged provider and project gates without repeating them', () => {
    const restored = restoreOnboarding(
      JSON.stringify({
        version: 1,
        completed: ['welcome', 'check', 'import', 'connect', 'project'],
        finished: false,
      }),
    );
    expect(restored.step).toBe('ready');
    expect(restored.providerConnected).toBe(true);
    expect(restored.projectSelected).toBe(true);
  });

  it('serialises a finished ready state deterministically', () => {
    const finished = reduceOnboarding(
      { ...initialOnboardingState, step: 'ready' },
      { type: 'finish' },
    );
    expect(JSON.parse(serialiseOnboarding(finished))).toMatchObject({ version: 1, finished: true });
  });
});
