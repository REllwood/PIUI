import { createRequire, syncBuiltinESMExports } from 'node:module';
import processDefault, * as processNamed from 'node:process';
import v8Default, * as v8Named from 'node:v8';
import {
  MessagePort,
  workerData,
} from 'node:worker_threads';

const terminateThread = process.exit.bind(process);
const safeDefine = Object.defineProperty;
const safeOwnDescriptor = Object.getOwnPropertyDescriptor;
const safeFreeze = Object.freeze;
const safeIsFrozen = Object.isFrozen;
const safeReflectDelete = Reflect.deleteProperty;
const SafeError = Error;

function lockReflectionHooks(): void {
  const emptyHandles = () => safeFreeze([] as unknown[]);
  const unavailableBinding = () => { throw new SafeError('project-reflection-hook-disabled'); };
  const emptyQuery = () => safeFreeze([] as unknown[]);
  safeFreeze(emptyHandles);
  safeFreeze(unavailableBinding);
  safeFreeze(emptyQuery);

  const replacements: ReadonlyArray<readonly [string, (...args: never[]) => unknown]> = [
    ['_getActiveHandles', emptyHandles],
    ['_getActiveRequests', emptyHandles],
    ['getActiveResourcesInfo', emptyHandles],
    ['binding', unavailableBinding],
    ['_linkedBinding', unavailableBinding],
  ];
  for (let index = 0; index < replacements.length; index += 1) {
    const [name, replacement] = replacements[index];
    safeDefine(processDefault, name, {
      value: replacement,
      configurable: false,
      enumerable: true,
      writable: false,
    });
  }
  safeDefine(v8Default, 'queryObjects', {
    value: emptyQuery,
    configurable: false,
    enumerable: true,
    writable: false,
  });
  safeDefine(globalThis, 'process', {
    value: processDefault,
    configurable: false,
    enumerable: false,
    writable: false,
  });
  syncBuiltinESMExports();

  const requiredProcessExports = processNamed as unknown as Record<string, unknown>;
  for (let index = 0; index < replacements.length; index += 1) {
    const [name, replacement] = replacements[index];
    const descriptor = safeOwnDescriptor(processDefault, name);
    if (
      !descriptor
      || descriptor.value !== replacement
      || descriptor.configurable
      || descriptor.writable
      || requiredProcessExports[name] !== replacement
    ) {
      throw new SafeError('project-reflection-hardening-failed');
    }
  }
  const require = createRequire(import.meta.url);
  const cjsProcess = require('node:process') as unknown;
  const cjsV8 = require('node:v8') as unknown as Record<string, unknown>;
  const globalProcess = safeOwnDescriptor(globalThis, 'process');
  const queryDescriptor = safeOwnDescriptor(v8Default, 'queryObjects');
  if (
    cjsProcess !== processDefault
    || globalProcess?.value !== processDefault
    || globalProcess.configurable
    || globalProcess.writable
    || !queryDescriptor
    || queryDescriptor.value !== emptyQuery
    || queryDescriptor.configurable
    || queryDescriptor.writable
    || (v8Named.queryObjects as unknown) !== emptyQuery
    || cjsV8.queryObjects !== emptyQuery
  ) {
    throw new SafeError('project-reflection-hardening-failed');
  }
}

function lockIntrinsicBindings(): void {
  const bindings: ReadonlyArray<readonly [string, unknown]> = [
    ['Array', Array],
    ['Object', Object],
    ['Reflect', Reflect],
    ['Promise', Promise],
    ['Map', Map],
    ['Set', Set],
    ['Error', Error],
    ['TypeError', TypeError],
    ['JSON', JSON],
    ['Math', Math],
    ['URL', URL],
    ['URLSearchParams', URLSearchParams],
    ['TextEncoder', TextEncoder],
    ['TextDecoder', TextDecoder],
    ['Uint8Array', Uint8Array],
  ];
  for (let index = 0; index < bindings.length; index += 1) {
    const [name, original] = bindings[index];
    if ((typeof original !== 'function' && (typeof original !== 'object' || original === null))) {
      throw new Error('project-intrinsic-hardening-failed');
    }
    const prototype = typeof original === 'function'
      ? (original as { prototype?: unknown }).prototype
      : undefined;
    if (prototype && typeof prototype === 'object') {
      safeFreeze(prototype);
      if (!safeIsFrozen(prototype)) throw new Error('project-intrinsic-hardening-failed');
    }
    safeFreeze(original);
    if (!safeIsFrozen(original)) throw new Error('project-intrinsic-hardening-failed');
    safeDefine(globalThis, name, {
      value: original,
      configurable: false,
      enumerable: false,
      writable: false,
    });
    const descriptor = safeOwnDescriptor(globalThis, name);
    if (!descriptor || descriptor.value !== original || descriptor.configurable || descriptor.writable) {
      throw new Error('project-intrinsic-hardening-failed');
    }
  }
  if (!safeIsFrozen(Array.prototype) || !safeIsFrozen(Object.prototype)) {
    throw new Error('project-intrinsic-hardening-failed');
  }
}

const data = workerData as Record<string, unknown>;
const candidate = data.completionPort;
const snapshotRoot = data.snapshotRoot;
const agentRoot = data.agentRoot;
if (
  !(candidate instanceof MessagePort)
  || typeof snapshotRoot !== 'string'
  || typeof agentRoot !== 'string'
) {
  terminateThread(64);
} else {
  const privatePort = candidate;
  const privatePost = privatePort.postMessage.bind(privatePort);
  const privateClose = privatePort.close.bind(privatePort);
  // Remove the only ordinary bootstrap reference before importing Pi/project
  // code. A later `node:worker_threads` import sees null, not the private port.
  safeReflectDelete(data, 'completionPort');
  safeDefine(data, 'completionPort', {
    value: null,
    configurable: false,
    enumerable: false,
    writable: false,
  });

  try {
    lockIntrinsicBindings();
    lockReflectionHooks();
    privatePost(safeFreeze({ version: 1, phase: 'ready' }));
    const { loadTrustedProjectSnapshot } = await import('./public-sdk.js');
    await loadTrustedProjectSnapshot({ snapshotRoot, agentRoot });
    privatePost(safeFreeze({ version: 1, phase: 'complete' }));
    privateClose();
    terminateThread(0);
  } catch {
    try { privateClose(); } catch { /* already closed */ }
    terminateThread(70);
  }
}
