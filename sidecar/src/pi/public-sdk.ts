import {
  AgentSession,
  AgentSessionRuntime,
  DefaultPackageManager,
  DefaultResourceLoader,
  ModelRuntime,
  ProjectTrustStore,
  SessionManager,
  SettingsManager,
  VERSION,
  createAgentSession,
  type CreateModelRuntimeOptions,
} from '@earendil-works/pi-coding-agent';

export type PublicCredentialStore = NonNullable<CreateModelRuntimeOptions['credentials']>;
export type PublicCredential = NonNullable<Awaited<ReturnType<PublicCredentialStore['read']>>>;
export type PublicCredentialInfo = Awaited<ReturnType<PublicCredentialStore['list']>>[number];

export const REQUIRED_PUBLIC_CAPABILITIES = Object.freeze({
  AgentSession: typeof AgentSession === 'function',
  AgentSessionRuntime: typeof AgentSessionRuntime === 'function',
  DefaultPackageManager: typeof DefaultPackageManager === 'function',
  DefaultResourceLoader: typeof DefaultResourceLoader === 'function',
  ModelRuntime: typeof ModelRuntime === 'function',
  ProjectTrustStore: typeof ProjectTrustStore === 'function',
  SessionManager: typeof SessionManager === 'function',
  SettingsManager: typeof SettingsManager === 'function',
  createAgentSession: typeof createAgentSession === 'function',
});

// Captured before any project isolate can execute. Post-reload success checks
// must not perform project-mutable prototype/static lookups.
const safeApply = Reflect.apply;
const safeBind = Function.prototype.bind;
const safeArrayIsArray = Array.isArray;
const safeInteger = Number.isSafeInteger;
const safeOwnDescriptor = Object.getOwnPropertyDescriptor;
const safeGetPrototype = Object.getPrototypeOf;
const safeHasOwn = Object.prototype.hasOwnProperty;
const safeFreeze = Object.freeze;
const safeIsFrozen = Object.isFrozen;
const originalArray = Array;
const originalArrayPush = Array.prototype.push;
const loaderPrototype = DefaultResourceLoader.prototype as unknown as Record<string, unknown>;
const criticalLoaderMethods = [
  'reload',
  'loadFinalExtensionSet',
  'loadExtensionFactories',
  'addExtensionConflictDiagnostics',
  'getExtensions',
  'getSkills',
  'getPrompts',
  'getThemes',
] as const;
const originalLoaderMethods: Record<string, unknown> = {};
for (let index = 0; index < criticalLoaderMethods.length; index += 1) {
  const name = criticalLoaderMethods[index];
  const descriptor = safeOwnDescriptor(loaderPrototype, name);
  if (!descriptor || typeof descriptor.value !== 'function') {
    throw new Error('trusted-loader-hardening-failed');
  }
  originalLoaderMethods[name] = descriptor.value;
}

function freezePiClass(value: unknown): void {
  if (typeof value !== 'function') throw new Error('trusted-loader-hardening-failed');
  let prototype = (value as { prototype?: object }).prototype;
  while (prototype && prototype !== Object.prototype) {
    safeFreeze(prototype);
    if (!safeIsFrozen(prototype)) throw new Error('trusted-loader-hardening-failed');
    prototype = safeGetPrototype(prototype) as object | undefined;
  }
  safeFreeze(value);
  if (!safeIsFrozen(value)) throw new Error('trusted-loader-hardening-failed');
}

const isProjectLoaderIsolate = process.env.PIUI_PROJECT_LOADER_ISOLATE === '1';

function assertLoaderIntegrity(): void {
  if (!isProjectLoaderIsolate) throw new Error('trusted-loader-hardening-failed');
  const globalArray = safeOwnDescriptor(globalThis, 'Array');
  const pushDescriptor = safeOwnDescriptor(Array.prototype, 'push');
  if (
    !pushDescriptor
    || pushDescriptor.configurable
    || (safeApply(safeHasOwn, pushDescriptor, ['writable']) && pushDescriptor.writable)
    || globalArray?.value !== originalArray
    || globalArray.configurable
    || globalArray.writable
    || Array.prototype.push !== originalArrayPush
    || !safeIsFrozen(Array.prototype)
    || !safeIsFrozen(Object.prototype)
    || !safeIsFrozen(DefaultResourceLoader)
    || !safeIsFrozen(loaderPrototype)
  ) {
    throw new Error('trusted-loader-hardening-failed');
  }
  for (let index = 0; index < criticalLoaderMethods.length; index += 1) {
    const name = criticalLoaderMethods[index];
    const descriptor = safeOwnDescriptor(loaderPrototype, name);
    if (
      !descriptor
      || descriptor.value !== originalLoaderMethods[name]
      || descriptor.configurable
      || descriptor.writable
    ) {
      throw new Error('trusted-loader-hardening-failed');
    }
  }
}
if (isProjectLoaderIsolate) {
  freezePiClass(DefaultResourceLoader);
  freezePiClass(DefaultPackageManager);
  freezePiClass(SettingsManager);
  safeFreeze(originalLoaderMethods);
  assertLoaderIntegrity();
}

function bindOriginal<T extends (...args: never[]) => unknown>(
  method: T,
  receiver: object,
): T {
  return safeApply(safeBind, method, [receiver]) as T;
}

function ownData(value: unknown, key: string): unknown {
  if (value === null || typeof value !== 'object') throw new Error('trusted-resource-observer-rejected');
  const descriptor = safeOwnDescriptor(value, key);
  if (!descriptor || !safeApply(safeHasOwn, descriptor, ['value'])) {
    throw new Error('trusted-resource-observer-rejected');
  }
  return descriptor.value;
}

function boundedArrayLength(value: unknown): number {
  if (!safeArrayIsArray(value)) throw new Error('trusted-resource-observer-rejected');
  const length = ownData(value, 'length');
  if (!safeInteger(length) || (length as number) < 0 || (length as number) > 1_024) {
    throw new Error('trusted-resource-observer-rejected');
  }
  return length as number;
}

export type TrustedResourceCounts = Readonly<{
  extensions: number;
  skills: number;
  prompts: number;
  themes: number;
  packages: number;
  truncated: boolean;
}>;

/**
 * The only A.16 Pi construction seam. It uses public package-root exports,
 * isolated in-memory settings and an explicitly empty agent directory. The
 * caller must establish containment and the exact trust lease first.
 */
export async function loadTrustedProjectSnapshot(options: Readonly<{
  snapshotRoot: string;
  agentRoot: string;
}>): Promise<TrustedResourceCounts> {
  // This is intentionally process-lifetime. Restoring a permissive value while
  // loaded extension callbacks remain alive would reopen package acquisition.
  process.env.PI_OFFLINE = '1';

  const settingsManager = SettingsManager.inMemory({}, { projectTrusted: false });
  const packageManager = new DefaultPackageManager({
    cwd: options.snapshotRoot,
    agentDir: options.agentRoot,
    settingsManager,
  });

  // Prove missing sources use the public skip policy even though the isolated
  // settings contain no configured packages. The loader's subsequent resolve
  // is additionally fenced by PI_OFFLINE=1.
  await packageManager.resolve(async () => 'skip');
  settingsManager.setProjectTrusted(true);

  assertLoaderIntegrity();
  const loader = new DefaultResourceLoader({
    cwd: options.snapshotRoot,
    agentDir: options.agentRoot,
    settingsManager,
    // Pi 0.82 has no public root-confined ancestor-skill resolver. Skills are
    // therefore disabled in this spike; extensions, prompts and themes are
    // discovered only from the descriptor-copied synthetic project root.
    noSkills: true,
    noContextFiles: true,
    systemPrompt: '',
    appendSystemPrompt: [],
  });
  // Capture the exact private instance's implementation functions before
  // reload imports any project module. A project may mutate Pi prototypes, but
  // completion uses only these already-bound originals and captured intrinsics.
  const reload = bindOriginal(loader.reload, loader);
  const getExtensions = bindOriginal(loader.getExtensions, loader);
  const getSkills = bindOriginal(loader.getSkills, loader);
  const getPrompts = bindOriginal(loader.getPrompts, loader);
  const getThemes = bindOriginal(loader.getThemes, loader);

  await reload();
  assertLoaderIntegrity();

  // Never call a project-mutable observer/prototype after reload. Accept only
  // own data properties and native arrays with bounded own lengths.
  const extensionsResult = getExtensions();
  const extensionCount = boundedArrayLength(ownData(extensionsResult, 'extensions'));
  const extensionErrors = boundedArrayLength(ownData(extensionsResult, 'errors'));
  if (extensionErrors !== 0) throw new Error('trusted-resource-load-failed');

  const skillsResult = getSkills();
  const skillCount = boundedArrayLength(ownData(skillsResult, 'skills'));
  const skillDiagnostics = boundedArrayLength(ownData(skillsResult, 'diagnostics'));
  const promptsResult = getPrompts();
  const promptCount = boundedArrayLength(ownData(promptsResult, 'prompts'));
  const promptDiagnostics = boundedArrayLength(ownData(promptsResult, 'diagnostics'));
  const themesResult = getThemes();
  const themeCount = boundedArrayLength(ownData(themesResult, 'themes'));
  const themeDiagnostics = boundedArrayLength(ownData(themesResult, 'diagnostics'));
  if (skillDiagnostics !== 0 || promptDiagnostics !== 0 || themeDiagnostics !== 0) {
    throw new Error('trusted-resource-load-failed');
  }

  const maximum = 64;
  return safeFreeze({
    extensions: extensionCount > maximum ? maximum : extensionCount,
    skills: skillCount > maximum ? maximum : skillCount,
    prompts: promptCount > maximum ? maximum : promptCount,
    themes: themeCount > maximum ? maximum : themeCount,
    packages: 0,
    truncated: extensionCount > maximum
      || skillCount > maximum
      || promptCount > maximum
      || themeCount > maximum,
  });
}

export function publicSdkMetadata() {
  return {
    piVersion: VERSION,
    nodeVersion: process.versions.node,
    architecture: process.arch,
    capabilities: Object.entries(REQUIRED_PUBLIC_CAPABILITIES).filter(([, available]) => available).map(([name]) => name).sort(),
  };
}

export function assertPublicSdk(): void {
  const unavailable = Object.entries(REQUIRED_PUBLIC_CAPABILITIES).filter(([, available]) => !available).map(([name]) => name);
  if (VERSION !== '0.82.0') throw new Error('Pinned Pi SDK version mismatch');
  if (unavailable.length) throw new Error(`Required public Pi capabilities unavailable: ${unavailable.join(', ')}`);
}
