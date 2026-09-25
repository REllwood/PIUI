// Pi 0.82's ThinkingLevel, in order, with the one set of labels every surface uses so a
// saved value always reads the same in the composer, Settings and the conversation.
export const THINKING_LEVELS = [
  { value: 'off', label: 'Off', detail: 'Respond without extended thinking.' },
  { value: 'minimal', label: 'Minimal', detail: 'A little thinking for straightforward tasks.' },
  { value: 'low', label: 'Quick', detail: 'Keep thinking brief for everyday questions.' },
  { value: 'medium', label: 'Balanced', detail: 'A balance of depth and response time.' },
  { value: 'high', label: 'Deep', detail: 'Spend more time on complex changes and decisions.' },
  { value: 'xhigh', label: 'Extended', detail: 'More thinking time for demanding work.' },
  { value: 'max', label: 'Maximum', detail: 'The most thinking time the model allows.' },
] as const;

export type ThinkingOption = (typeof THINKING_LEVELS)[number];
export type ThinkingLevel = ThinkingOption['value'];

export const DEFAULT_THINKING_LEVEL: ThinkingLevel = 'medium';

// PIUI's helper accepts these levels when saving. Pi can report `max` from its own
// settings; PIUI shows it faithfully but only offers it while it is the saved value.
const SAVEABLE_THINKING_LEVELS: ReadonlySet<ThinkingLevel> = new Set([
  'off',
  'minimal',
  'low',
  'medium',
  'high',
  'xhigh',
]);

export function thinkingOption(value: unknown): ThinkingOption | undefined {
  return THINKING_LEVELS.find((option) => option.value === value);
}

export function isThinkingLevel(value: unknown): value is ThinkingLevel {
  return thinkingOption(value) !== undefined;
}

export function isSaveableThinkingLevel(value: unknown): value is ThinkingLevel {
  return isThinkingLevel(value) && SAVEABLE_THINKING_LEVELS.has(value);
}

export function thinkingLabel(value: unknown): string | null {
  return thinkingOption(value)?.label ?? null;
}

// The levels a person can choose, keeping the current saved value visible even when
// PIUI cannot set it itself.
export function thinkingChoices(current: unknown): readonly ThinkingOption[] {
  return THINKING_LEVELS.filter(
    (option) => SAVEABLE_THINKING_LEVELS.has(option.value) || option.value === current,
  );
}
