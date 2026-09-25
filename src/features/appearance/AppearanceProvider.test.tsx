// @vitest-environment jsdom

import { StrictMode } from 'react';
import { act, cleanup, render } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AppearancePreferences } from '../../domain/types';
import { AppearanceProvider, useAppearance } from './AppearanceProvider';
import { defaultAppearance } from './preferences';

let update: ((patch: Partial<AppearancePreferences>) => void) | undefined;

function Probe() {
  update = useAppearance().update;
  return null;
}

beforeEach(() => {
  update = undefined;
  // jsdom has no media queries; the provider only needs a stable dark-mode answer.
  vi.stubGlobal(
    'matchMedia',
    vi.fn(() => ({
      matches: true,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    })),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('appearance provider', () => {
  it('persists each change once, outside the state updater, and composes quick changes', () => {
    const onChange = vi.fn();
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    render(
      <StrictMode>
        <AppearanceProvider initialPreferences={defaultAppearance} onChange={onChange}>
          <Probe />
        </AppearanceProvider>
      </StrictMode>,
    );
    act(() => {
      update?.({ theme: 'light' });
      update?.({ reduceMotion: true });
    });
    expect(onChange).toHaveBeenCalledTimes(2);
    expect(onChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ theme: 'light', reduceMotion: true }),
    );
    expect(document.documentElement.dataset.theme).toBe('light');
    expect(consoleError).not.toHaveBeenCalled();
  });
});
