export const ONBOARDING_STEPS = [
  'welcome',
  'check',
  'import',
  'connect',
  'project',
  'ready',
] as const;
export type OnboardingStep = (typeof ONBOARDING_STEPS)[number];

export type OnboardingState = Readonly<{
  step: OnboardingStep;
  completed: readonly OnboardingStep[];
  skippedImport: boolean;
  providerConnected: boolean;
  projectSelected: boolean;
  finished: boolean;
}>;

export const initialOnboardingState: OnboardingState = Object.freeze({
  step: 'welcome',
  completed: [],
  skippedImport: false,
  providerConnected: false,
  projectSelected: false,
  finished: false,
});

export type OnboardingEvent =
  | Readonly<{ type: 'continue' }>
  | Readonly<{ type: 'back' }>
  | Readonly<{ type: 'skip-import' }>
  | Readonly<{ type: 'provider-connected' }>
  | Readonly<{ type: 'project-selected' }>
  | Readonly<{ type: 'finish' }>
  | Readonly<{ type: 'resume'; completed: readonly OnboardingStep[] }>;

function uniqueSteps(steps: readonly OnboardingStep[]): readonly OnboardingStep[] {
  return ONBOARDING_STEPS.filter((step) => steps.includes(step));
}

export function reduceOnboarding(state: OnboardingState, event: OnboardingEvent): OnboardingState {
  const index = ONBOARDING_STEPS.indexOf(state.step);
  if (event.type === 'back') {
    return { ...state, step: ONBOARDING_STEPS[Math.max(0, index - 1)] };
  }
  if (event.type === 'resume') {
    const completed = uniqueSteps(event.completed);
    const firstIncomplete = ONBOARDING_STEPS.find((step) => !completed.includes(step)) ?? 'ready';
    return {
      ...state,
      completed,
      step: firstIncomplete,
      providerConnected: completed.includes('connect'),
      projectSelected: completed.includes('project'),
      finished: completed.length === ONBOARDING_STEPS.length,
    };
  }
  if (event.type === 'skip-import') return { ...state, skippedImport: true };
  if (event.type === 'provider-connected') return { ...state, providerConnected: true };
  if (event.type === 'project-selected') return { ...state, projectSelected: true };
  if (event.type === 'finish' && state.step === 'ready') {
    return { ...state, completed: ONBOARDING_STEPS, finished: true };
  }
  if (event.type !== 'continue' || index >= ONBOARDING_STEPS.length - 1) return state;
  if (state.step === 'connect' && !state.providerConnected) return state;
  if (state.step === 'project' && !state.projectSelected) return state;
  const completed = uniqueSteps([...state.completed, state.step]);
  return { ...state, completed, step: ONBOARDING_STEPS[index + 1] };
}

export function serialiseOnboarding(state: OnboardingState): string {
  return JSON.stringify({ version: 1, completed: state.completed, finished: state.finished });
}

export function restoreOnboarding(value: string | null): OnboardingState {
  if (!value) return initialOnboardingState;
  try {
    const parsed: unknown = JSON.parse(value);
    if (!parsed || typeof parsed !== 'object') return initialOnboardingState;
    const record = parsed as Record<string, unknown>;
    if (record.version !== 1 || !Array.isArray(record.completed)) return initialOnboardingState;
    const completed = record.completed.filter(
      (step): step is OnboardingStep =>
        typeof step === 'string' && ONBOARDING_STEPS.includes(step as OnboardingStep),
    );
    const restored = reduceOnboarding(initialOnboardingState, { type: 'resume', completed });
    return record.finished === true
      ? { ...restored, completed: ONBOARDING_STEPS, step: 'ready', finished: true }
      : restored;
  } catch (error) {
    if (error instanceof SyntaxError) return initialOnboardingState;
    throw error;
  }
}
