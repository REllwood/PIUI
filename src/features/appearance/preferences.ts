import type { AppearancePreferences, ThemePreference } from '../../domain/types';

export const APPEARANCE_STORAGE_KEY = 'piui.appearance.v1';

export const defaultAppearance: AppearancePreferences = Object.freeze({
  theme: 'system',
  increasedContrast: false,
  reduceTransparency: false,
  reduceMotion: false,
  accessibleTranscript: false,
});

function isTheme(value: unknown): value is ThemePreference {
  return value === 'system' || value === 'light' || value === 'dark';
}

export function readAppearance(
  storage: Pick<Storage, 'getItem'> = localStorage,
): AppearancePreferences {
  try {
    const raw = storage.getItem(APPEARANCE_STORAGE_KEY);
    if (!raw) return defaultAppearance;
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return defaultAppearance;
    const record = parsed as Record<string, unknown>;
    return Object.freeze({
      theme: isTheme(record.theme) ? record.theme : defaultAppearance.theme,
      increasedContrast: record.increasedContrast === true,
      reduceTransparency: record.reduceTransparency === true,
      reduceMotion: record.reduceMotion === true,
      accessibleTranscript: record.accessibleTranscript === true,
    });
  } catch (error) {
    if (error instanceof SyntaxError) return defaultAppearance;
    throw error;
  }
}

export function writeAppearance(
  preferences: AppearancePreferences,
  storage: Pick<Storage, 'setItem'> = localStorage,
): void {
  storage.setItem(APPEARANCE_STORAGE_KEY, JSON.stringify(preferences));
}

export function resolvedTheme(
  preference: ThemePreference,
  systemIsDark: boolean,
): 'light' | 'dark' {
  return preference === 'system' ? (systemIsDark ? 'dark' : 'light') : preference;
}
