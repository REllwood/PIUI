import { describe, expect, it } from 'vitest';
import { preferredSessionThinking } from './sessionContinuity';
import {
  THINKING_LEVELS,
  isSaveableThinkingLevel,
  thinkingChoices,
  thinkingLabel,
} from './thinking';

describe('thinking levels', () => {
  it("covers every level in Pi 0.82's ThinkingLevel in order", () => {
    expect(THINKING_LEVELS.map((option) => option.value)).toEqual([
      'off',
      'minimal',
      'low',
      'medium',
      'high',
      'xhigh',
      'max',
    ]);
  });

  it('labels every saved level, including the ones Settings used to omit', () => {
    expect(thinkingLabel('off')).toBe('Off');
    expect(thinkingLabel('minimal')).toBe('Minimal');
    expect(thinkingLabel('xhigh')).toBe('Extended');
    expect(thinkingLabel('max')).toBe('Maximum');
    expect(thinkingLabel('unexpected')).toBeNull();
  });

  it('keeps a saved level visible as a choice even when PIUI cannot set it', () => {
    expect(thinkingChoices('medium').map((option) => option.value)).not.toContain('max');
    expect(thinkingChoices('max').map((option) => option.value)).toContain('max');
    expect(thinkingChoices('off').map((option) => option.value)).toContain('off');
    expect(isSaveableThinkingLevel('max')).toBe(false);
  });

  it('only carries a saveable level into a new conversation', () => {
    const setting = (value: unknown) => [{ key: 'reasoning.level', value }];
    expect(preferredSessionThinking(setting('minimal'))).toBe('minimal');
    expect(preferredSessionThinking(setting('max'))).toBeNull();
    expect(preferredSessionThinking(setting('unexpected'))).toBeNull();
  });
});
