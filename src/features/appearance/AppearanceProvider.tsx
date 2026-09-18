import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import type { AppearancePreferences } from '../../domain/types';
import { defaultAppearance, resolvedTheme } from './preferences';

type AppearanceContextValue = Readonly<{
  preferences: AppearancePreferences;
  update: (patch: Partial<AppearancePreferences>) => void;
}>;

const AppearanceContext = createContext<AppearanceContextValue>({
  preferences: defaultAppearance,
  update: () => undefined,
});

export function AppearanceProvider({
  children,
  initialPreferences = defaultAppearance,
  onChange,
}: Readonly<{
  children: ReactNode;
  initialPreferences?: AppearancePreferences;
  onChange?: (preferences: AppearancePreferences) => void;
}>) {
  const [preferences, setPreferences] = useState<AppearancePreferences>(initialPreferences);
  const [systemIsDark, setSystemIsDark] = useState(
    () => matchMedia('(prefers-color-scheme: dark)').matches,
  );

  useEffect(() => {
    const query = matchMedia('(prefers-color-scheme: dark)');
    const listener = (event: MediaQueryListEvent) => setSystemIsDark(event.matches);
    query.addEventListener('change', listener);
    return () => query.removeEventListener('change', listener);
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = resolvedTheme(preferences.theme, systemIsDark);
    root.dataset.contrast = preferences.increasedContrast ? 'increased' : 'standard';
    root.dataset.transparency = preferences.reduceTransparency ? 'reduced' : 'standard';
    root.dataset.motion = preferences.reduceMotion ? 'reduced' : 'standard';
    root.style.colorScheme = resolvedTheme(preferences.theme, systemIsDark);
  }, [preferences, systemIsDark]);

  const update = useCallback(
    (patch: Partial<AppearancePreferences>) => {
      setPreferences((current) => {
        const next = Object.freeze({ ...current, ...patch });
        onChange?.(next);
        return next;
      });
    },
    [onChange],
  );

  const value = useMemo(() => ({ preferences, update }), [preferences, update]);
  return <AppearanceContext.Provider value={value}>{children}</AppearanceContext.Provider>;
}

export function useAppearance(): AppearanceContextValue {
  return useContext(AppearanceContext);
}
