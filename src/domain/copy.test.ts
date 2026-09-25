import { describe, expect, it } from 'vitest';
import { countLabel } from './copy';

describe('count copy', () => {
  it('uses the singular only for exactly one', () => {
    expect(countLabel(1, 'addition')).toBe('1 addition');
    expect(countLabel(1, 'deletion')).toBe('1 deletion');
  });

  it('uses the plural for none and for many', () => {
    expect(countLabel(0, 'deletion')).toBe('0 deletions');
    expect(countLabel(148, 'addition')).toBe('148 additions');
  });

  it('accepts an irregular plural', () => {
    expect(countLabel(1, 'match', 'matches')).toBe('1 match');
    expect(countLabel(3, 'match', 'matches')).toBe('3 matches');
  });
});
