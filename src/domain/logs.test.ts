import { describe, expect, it } from 'vitest';
import { visibleLogLines } from './logs';

const lines = [
  '[info] provider sign-in complete token=canary-secret-value',
  '[warn] helper restarted for /Users/example/project',
  '[error] session file unavailable',
];

describe('visible log lines', () => {
  it('does not match text that redaction removes', () => {
    expect(visibleLogLines(lines, 'canary-secret', 'all')).toEqual([]);
    expect(visibleLogLines(lines, 'example', 'all')).toEqual([]);
  });

  it('matches and returns the redacted form', () => {
    expect(visibleLogLines(lines, 'token=[redacted]', 'all')).toEqual([
      '[info] provider sign-in complete token=[redacted]',
    ]);
    expect(visibleLogLines(lines, '', 'warn')).toEqual([
      '[warn] helper restarted for /Users/[home]/project',
    ]);
  });
});
