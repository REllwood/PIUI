import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
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

  // The latest preferences, including an update not yet rendered, so quick successive
  // changes compose. Persistence runs here, outside the state updater, because React
  // may call an updater more than once.
  const latest = useRef(preferences);
  const update = useCallback(
    (patch: Partial<AppearancePreferences>) => {
      const next = Object.freeze({ ...latest.current, ...patch });
      latest.current = next;
      setPreferences(next);
      onChange?.(next);
    },
    [onChange],
  );

  const value = useMemo(() => ({ preferences, update }), [preferences, update]);
  return <AppearanceContext.Provider value={value}>{children}</AppearanceContext.Provider>;
}

export function useAppearance(): AppearanceContextValue {
  return useContext(AppearanceContext);
}
