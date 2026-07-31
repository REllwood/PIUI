export const A26_MARKDOWN_ROUTE = 'markdown-packaged';
export const A26_MARKDOWN_TEST_ACTIVE = import.meta.env.VITE_PIUI_A26_MARKDOWN_TEST === '1';

export type A26BrowserPreludeEvidence = Readonly<{
  schemaVersion: 1;
  networkApiAttempts: number;
  navigationApiAttempts: number;
  popupAttempts: number;
  cspViolations: number;
  wasmApiAttempts: number;
  runtimeErrors: number;
  unhandledRejections: number;
  disclosedExternalOpens: number;
  unexpectedResourceEntries: number;
  rasterResourceEntries: number;
  locationUnchanged: boolean;
  scriptCanaryExecuted: boolean;
  eventCanaryExecuted: boolean;
  loadingIndicatorPresented: boolean;
  codeLoadingIndicatorPresented: boolean;
}>;

export type A26MarkdownPrelude = Readonly<{
  begin: (expectedRasterUrl: string) => void;
  recordDisclosedExternalOpen: () => void;
  recordLoadingIndicator: () => void;
  stopAndSnapshot: () => A26BrowserPreludeEvidence;
}>;

declare global {
  interface Window {
    __PIUI_A26_MARKDOWN_PRELUDE__?: A26MarkdownPrelude;
    __PIUI_MARKDOWN_SCRIPT_EXECUTED__?: boolean;
    __PIUI_MARKDOWN_EVENT_EXECUTED__?: boolean;
  }
}

type MutableCounters = {
  networkApiAttempts: number;
  navigationApiAttempts: number;
  popupAttempts: number;
  cspViolations: number;
  wasmApiAttempts: number;
  runtimeErrors: number;
  unhandledRejections: number;
  disclosedExternalOpens: number;
};

function blankCounters(): MutableCounters {
  return {
    networkApiAttempts: 0,
    navigationApiAttempts: 0,
    popupAttempts: 0,
    cspViolations: 0,
    wasmApiAttempts: 0,
    runtimeErrors: 0,
    unhandledRejections: 0,
    disclosedExternalOpens: 0,
  };
}

function isExpectedResource(url: string, expectedRasterUrl: string): boolean {
  if (url === expectedRasterUrl) return true;
  try {
    const candidate = new URL(url);
    return candidate.protocol === window.location.protocol
      && candidate.host === window.location.host
      && candidate.username === ''
      && candidate.password === '';
  } catch {
    return false;
  }
}

export function installA26MarkdownPrelude(): A26MarkdownPrelude {
  const installed = window.__PIUI_A26_MARKDOWN_PRELUDE__;
  if (installed) return installed;

  let active = false;
  let begun = false;
  let initialLocation = '';
  let expectedRasterUrl = '';
  let resourceBaseline = 0;
  let counters = blankCounters();
  let loadingIndicatorPresented = false;
  let codeLoadingIndicatorPresented = false;
  let contentObserver: MutationObserver | null = null;

  const recordNetwork = () => {
    if (active) counters.networkApiAttempts += 1;
  };
  const recordNavigation = () => {
    if (active) counters.navigationApiAttempts += 1;
  };

  const nativeFetch = window.fetch.bind(window);
  window.fetch = (input, init) => {
    recordNetwork();
    return nativeFetch(input, init);
  };

  const nativeXhrOpen = XMLHttpRequest.prototype.open as unknown as (
    this: XMLHttpRequest,
    method: string,
    url: string | URL,
    asynchronous: boolean,
    username?: string | null,
    password?: string | null,
  ) => void;
  XMLHttpRequest.prototype.open = function a26ObservedXhrOpen(
    this: XMLHttpRequest,
    method: string,
    url: string | URL,
    asynchronous = true,
    username?: string | null,
    password?: string | null,
  ) {
    recordNetwork();
    return Reflect.apply(nativeXhrOpen, this, [method, url, asynchronous, username, password]);
  };

  window.WebSocket = new Proxy(window.WebSocket, {
    construct(target, argumentsList, newTarget) {
      recordNetwork();
      return Reflect.construct(target, argumentsList, newTarget);
    },
  });
  window.EventSource = new Proxy(window.EventSource, {
    construct(target, argumentsList, newTarget) {
      recordNetwork();
      return Reflect.construct(target, argumentsList, newTarget);
    },
  });

  const nativeSendBeacon = navigator.sendBeacon.bind(navigator);
  Object.defineProperty(navigator, 'sendBeacon', {
    configurable: true,
    value: (url: string | URL, data?: BodyInit | null) => {
      recordNetwork();
      return nativeSendBeacon(url, data);
    },
  });

  const nativeOpen = window.open.bind(window);
  window.open = (...argumentsList) => {
    if (active) counters.popupAttempts += 1;
    return nativeOpen(...argumentsList);
  };

  const nativePushState = history.pushState.bind(history);
  const nativeReplaceState = history.replaceState.bind(history);
  history.pushState = (data, unused, url) => {
    recordNavigation();
    nativePushState(data, unused, url);
  };
  history.replaceState = (data, unused, url) => {
    recordNavigation();
    nativeReplaceState(data, unused, url);
  };
  for (const eventName of ['beforeunload', 'hashchange', 'pagehide', 'popstate'] as const) {
    window.addEventListener(eventName, recordNavigation);
  }
  window.addEventListener('error', () => {
    if (active) counters.runtimeErrors += 1;
  });
  window.addEventListener('unhandledrejection', () => {
    if (active) counters.unhandledRejections += 1;
  });
  document.addEventListener('securitypolicyviolation', () => {
    if (active) counters.cspViolations += 1;
  });

  const recordWasm = () => {
    if (active) counters.wasmApiAttempts += 1;
  };
  const nativeCompile = WebAssembly.compile.bind(WebAssembly);
  WebAssembly.compile = (...argumentsList) => {
    recordWasm();
    return nativeCompile(...argumentsList);
  };
  const nativeInstantiate = WebAssembly.instantiate.bind(WebAssembly);
  WebAssembly.instantiate = ((...argumentsList: Parameters<typeof WebAssembly.instantiate>) => {
    recordWasm();
    return Reflect.apply(nativeInstantiate, WebAssembly, argumentsList);
  }) as typeof WebAssembly.instantiate;
  const nativeCompileStreaming = WebAssembly.compileStreaming.bind(WebAssembly);
  WebAssembly.compileStreaming = (...argumentsList) => {
    recordWasm();
    return nativeCompileStreaming(...argumentsList);
  };
  const nativeInstantiateStreaming = WebAssembly.instantiateStreaming.bind(WebAssembly);
  WebAssembly.instantiateStreaming = (...argumentsList) => {
    recordWasm();
    return nativeInstantiateStreaming(...argumentsList);
  };
  const nativeValidate = WebAssembly.validate.bind(WebAssembly);
  WebAssembly.validate = (...argumentsList) => {
    recordWasm();
    return nativeValidate(...argumentsList);
  };
  const nativeModule = WebAssembly.Module;
  WebAssembly.Module = new Proxy(nativeModule, {
    construct(target, argumentsList, newTarget) {
      recordWasm();
      return Reflect.construct(target, argumentsList, newTarget);
    },
  });
  const nativeInstance = WebAssembly.Instance;
  WebAssembly.Instance = new Proxy(nativeInstance, {
    construct(target, argumentsList, newTarget) {
      recordWasm();
      return Reflect.construct(target, argumentsList, newTarget);
    },
  });
  const nativeMemory = WebAssembly.Memory;
  WebAssembly.Memory = new Proxy(nativeMemory, {
    construct(target, argumentsList, newTarget) {
      recordWasm();
      return Reflect.construct(target, argumentsList, newTarget);
    },
  });
  const nativeTable = WebAssembly.Table;
  WebAssembly.Table = new Proxy(nativeTable, {
    construct(target, argumentsList, newTarget) {
      recordWasm();
      return Reflect.construct(target, argumentsList, newTarget);
    },
  });
  const nativeGlobal = WebAssembly.Global;
  WebAssembly.Global = new Proxy(nativeGlobal, {
    construct(target, argumentsList, newTarget) {
      recordWasm();
      return Reflect.construct(target, argumentsList, newTarget);
    },
  });

  const prelude: A26MarkdownPrelude = Object.freeze({
    begin(rasterUrl: string) {
      if (active || begun || !/^piui-raster:\/\/localhost\/__piui_markdown_asset__\/[0-9a-f]{32}\.(?:png|jpg|webp)$/.test(rasterUrl)) {
        throw new Error('A.26 Markdown prelude rejected');
      }
      begun = true;
      counters = blankCounters();
      loadingIndicatorPresented = false;
      codeLoadingIndicatorPresented = false;
      initialLocation = window.location.href;
      expectedRasterUrl = rasterUrl;
      resourceBaseline = performance.getEntriesByType('resource').length;
      window.__PIUI_MARKDOWN_SCRIPT_EXECUTED__ = false;
      window.__PIUI_MARKDOWN_EVENT_EXECUTED__ = false;
      active = true;
      contentObserver = new MutationObserver((records) => {
        for (const record of records) {
          for (const node of record.addedNodes) {
            if (
              node instanceof Element
              && (
                node.matches('.markdown__code-loading')
                || node.querySelector('.markdown__code-loading')
              )
            ) {
              codeLoadingIndicatorPresented = true;
              return;
            }
          }
        }
      });
      contentObserver.observe(document.documentElement, { childList: true, subtree: true });
    },
    recordDisclosedExternalOpen() {
      if (active) counters.disclosedExternalOpens += 1;
    },
    recordLoadingIndicator() {
      loadingIndicatorPresented = true;
    },
    stopAndSnapshot() {
      if (!active) throw new Error('A.26 Markdown prelude rejected');
      active = false;
      contentObserver?.disconnect();
      contentObserver = null;
      const resources = performance
        .getEntriesByType('resource')
        .slice(resourceBaseline)
        .map((entry) => entry.name);
      return Object.freeze({
        schemaVersion: 1 as const,
        ...counters,
        unexpectedResourceEntries: resources.filter(
          (resource) => !isExpectedResource(resource, expectedRasterUrl),
        ).length,
        rasterResourceEntries: resources.filter((resource) => resource === expectedRasterUrl).length,
        locationUnchanged: window.location.href === initialLocation,
        scriptCanaryExecuted: window.__PIUI_MARKDOWN_SCRIPT_EXECUTED__ === true,
        eventCanaryExecuted: window.__PIUI_MARKDOWN_EVENT_EXECUTED__ === true,
        loadingIndicatorPresented,
        codeLoadingIndicatorPresented,
      });
    },
  });
  window.__PIUI_A26_MARKDOWN_PRELUDE__ = prelude;
  return prelude;
}

if (A26_MARKDOWN_TEST_ACTIVE) installA26MarkdownPrelude();
