import { useSyncExternalStore } from 'react';
import type { BridgeStore, BridgeStoreState } from './store';

export function useBridgeSelector<T>(
  store: BridgeStore,
  selector: (state: BridgeStoreState) => T,
): T {
  return useSyncExternalStore(
    store.subscribe,
    () => selector(store.getSnapshot()),
    () => selector(store.getSnapshot()),
  );
}
