import { useCallback, useEffect, useRef, useState } from 'react';
import { LoadingLabel } from '../components/primitives/LoadingLabel';
import type { AppearancePreferences } from '../domain/types';
import { AppearanceProvider } from '../features/appearance/AppearanceProvider';
import { OnboardingRoute } from '../features/onboarding/OnboardingRoute';
import { AppShell } from './AppShell';
import { ProductProvider } from './ProductContext';
import {
  applyNativeWindowState,
  defaultNativeApplicationData,
  listenForNativeWindowState,
  loadNativeApplicationState,
  saveNativeApplicationState,
  type NativeApplicationData,
  type NativeApplicationDataUpdate,
} from '../platform/native';
import '../styles/tokens.css';
import '../styles/theme-dark.css';
import '../styles/theme-light.css';
import '../styles/typography.css';
import '../styles/base.css';
import './shell.css';

function shouldShowOnboarding(data: NativeApplicationData): boolean {
  const query = new URLSearchParams(window.location.search);
  if (query.get('onboarding') === '1') return true;
  if (query.get('workspace') === '1') return false;
  return !data.onboarding.finished;
}

export function ProductionApp() {
  const [data, setData] = useState<NativeApplicationData | null>(null);
  const [onboarding, setOnboarding] = useState<boolean | null>(null);
  const [persistenceError, setPersistenceError] = useState(false);
  const latestData = useRef<NativeApplicationData>(defaultNativeApplicationData);
  const saveChain = useRef<Promise<unknown>>(Promise.resolve());

  const persist = useCallback((update: NativeApplicationDataUpdate): Promise<void> => {
    const next = typeof update === 'function' ? update(latestData.current) : update;
    latestData.current = next;
    setData(next);
    const operation = saveChain.current
      .catch(() => undefined)
      .then(() => saveNativeApplicationState(next))
      .then((saved) => {
        if (latestData.current === next) {
          latestData.current = saved;
          setData(saved);
        }
        setPersistenceError(false);
      })
      .catch((error: unknown) => {
        setPersistenceError(true);
        throw error;
      });
    saveChain.current = operation;
    return operation;
  }, []);

  useEffect(() => {
    let active = true;
    let unlisten: (() => void) | undefined;
    let persistTimer: number | undefined;
    void loadNativeApplicationState()
      .then(async (loaded) => {
        if (!active) return;
        if (loaded.window) {
          try {
            await applyNativeWindowState(loaded.window);
          } catch {
            // Invalid or unavailable window geometry must not prevent the app from opening.
          }
        }
        if (!active) return;
        latestData.current = loaded;
        setData(loaded);
        setOnboarding(shouldShowOnboarding(loaded));
        unlisten = await listenForNativeWindowState((nextWindow) => {
          if (!active) return;
          if (persistTimer !== undefined) window.clearTimeout(persistTimer);
          persistTimer = window.setTimeout(() => {
            const next = {
              width: Math.round(nextWindow.width),
              height: Math.round(nextWindow.height),
              maximised: nextWindow.maximised,
            };
            void persist((current) => {
              if (
                current.window?.width === next.width &&
                current.window.height === next.height &&
                current.window.maximised === next.maximised
              ) {
                return current;
              }
              return { ...current, window: next };
            }).catch(() => undefined);
          }, 250);
        });
      })
      .catch(() => {
        if (!active) return;
        if (import.meta.env.DEV) {
          latestData.current = defaultNativeApplicationData;
          setData(defaultNativeApplicationData);
          setOnboarding(shouldShowOnboarding(defaultNativeApplicationData));
        } else {
          setPersistenceError(true);
        }
      });
    return () => {
      active = false;
      unlisten?.();
      if (persistTimer !== undefined) window.clearTimeout(persistTimer);
    };
  }, [persist]);

  const persistAppearance = useCallback(
    (preferences: AppearancePreferences) => {
      void persist((current) => ({
        ...current,
        preferences: {
          ...current.preferences,
          theme: preferences.theme,
          increasedContrast: preferences.increasedContrast,
          reduceTransparency: preferences.reduceTransparency,
          reduceMotion: preferences.reduceMotion,
          accessibleTranscript: preferences.accessibleTranscript,
        },
      })).catch(() => undefined);
    },
    [persist],
  );

  if (!data || onboarding === null) {
    if (persistenceError && !import.meta.env.DEV) {
      return (
        <main className="startup-status">
          <h1>PIUI could not open its local settings.</h1>
          <p>Restart PIUI. Your Pi sessions and provider credentials have not been changed.</p>
        </main>
      );
    }
    return (
      <main className="startup-status" role="status">
        <LoadingLabel>Restoring PIUI…</LoadingLabel>
      </main>
    );
  }
  const appearance: AppearancePreferences = {
    theme: data.preferences.theme,
    increasedContrast: data.preferences.increasedContrast,
    reduceTransparency: data.preferences.reduceTransparency,
    reduceMotion: data.preferences.reduceMotion,
    accessibleTranscript: data.preferences.accessibleTranscript,
  };
  return (
    <AppearanceProvider initialPreferences={appearance} onChange={persistAppearance}>
      <div className="piui">
        {onboarding ? (
          <OnboardingRoute
            applicationData={data}
            onPersist={persist}
            onFinish={() => setOnboarding(false)}
          />
        ) : (
          <ProductProvider applicationData={data} onPersist={persist}>
            <AppShell />
          </ProductProvider>
        )}
        {persistenceError ? (
          <div className="persistence-warning" role="alert">
            PIUI could not save the latest non-secret preference. Try the change again.
          </div>
        ) : null}
      </div>
    </AppearanceProvider>
  );
}
