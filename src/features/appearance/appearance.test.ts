import { describe, expect, it, vi } from 'vitest';
import {
  APPEARANCE_STORAGE_KEY,
  defaultAppearance,
  readAppearance,
  resolvedTheme,
  writeAppearance,
} from './preferences';

describe('appearance preferences', () => {
  it('resolves System without overriding explicit themes', () => {
    expect(resolvedTheme('system', true)).toBe('dark');
    expect(resolvedTheme('system', false)).toBe('light');
    expect(resolvedTheme('light', true)).toBe('light');
    expect(resolvedTheme('dark', false)).toBe('dark');
  });

  it('bounds malformed storage to safe defaults', () => {
    expect(readAppearance({ getItem: () => '{invalid' })).toBe(defaultAppearance);
    expect(
      readAppearance({ getItem: () => JSON.stringify({ theme: 'neon', increasedContrast: true }) }),
    ).toEqual({ ...defaultAppearance, increasedContrast: true });
  });

  it('writes only the versioned appearance record', () => {
    const setItem = vi.fn();
    writeAppearance({ ...defaultAppearance, theme: 'light', reduceMotion: true }, { setItem });
    expect(setItem).toHaveBeenCalledWith(
      APPEARANCE_STORAGE_KEY,
      JSON.stringify({ ...defaultAppearance, theme: 'light', reduceMotion: true }),
    );
  });
});
