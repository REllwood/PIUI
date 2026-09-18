import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readFile, readdir, rename } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';

export type ResourceKind = 'skill' | 'prompt' | 'theme' | 'extension' | 'package';
export type ResourceSource = 'global' | 'project' | 'package';
export type ResourceOperation = 'enable' | 'disable' | 'install' | 'update' | 'remove';

export type AdapterResource = Readonly<{
  id: string;
  kind: ResourceKind;
  name: string;
  version: string;
  source: ResourceSource;
  trusted: boolean;
  enabled: boolean;
  executable: boolean;
  description: string;
  contributedSettings: readonly string[];
  operations: readonly ResourceOperation[];
}>;

export type ExecutableResource = Pick<
  AdapterResource,
  'id' | 'kind' | 'trusted' | 'enabled' | 'source'
>;

type PrivateResource = Readonly<{
  view: AdapterResource;
  privatePath?: string;
  packageSource?: string;
  packageScope?: 'global' | 'project';
  packageInstalled?: boolean;
}>;

export type PackageLifecyclePort = Readonly<{
  installAndPersist: (source: string, options?: { local?: boolean }) => Promise<void>;
  update: (source?: string) => Promise<void>;
  removeAndPersist: (source: string, options?: { local?: boolean }) => Promise<boolean>;
  getInstalledPath: (source: string, scope: 'user' | 'project') => string | undefined;
}>;

type ResourceScope = 'global' | 'project';
type ResourceState = Readonly<{
  version: 1;
  revision: number;
  enabled: Readonly<Record<string, boolean>>;
}>;

type EnabledChange = Readonly<{
  apply: () => void;
  rollback: () => void;
  persist: () => Promise<void>;
  restorePersisted: () => Promise<void>;
}>;

type SourceInfoLike = Readonly<{
  path: string;
  scope: 'user' | 'project' | 'temporary';
  origin: 'package' | 'top-level';
}>;

type NamedResourceLike = Readonly<{
  name: string;
  description?: string;
  filePath?: string;
  path?: string;
  sourceInfo: SourceInfoLike;
}>;

const EXECUTABLE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts']);

export class ResourceRegistry {
  readonly #workspacePath: string;
  readonly #agentDir: string;
  readonly #resources = new Map<string, PrivateResource>();
  readonly #paths: Readonly<Record<ResourceScope, string>>;
  readonly #states = new Map<ResourceScope, ResourceState>();
  readonly #enabled = new Map<string, boolean>();
  readonly #packages?: PackageLifecyclePort;
  readonly enabledExtensionPaths: string[] = [];

  private constructor(workspacePath: string, agentDir: string, packages?: PackageLifecyclePort) {
    this.#workspacePath = workspacePath;
    this.#agentDir = agentDir;
    this.#packages = packages;
    this.#paths = Object.freeze({
      global: join(agentDir, 'piui-resources.json'),
      project: join(workspacePath, '.pi', 'piui-resources.json'),
    });
  }

  static async create(
    workspacePath: string,
    agentDir: string,
    packages?: PackageLifecyclePort,
  ): Promise<ResourceRegistry> {
    const registry = new ResourceRegistry(workspacePath, agentDir, packages);
    const global = await readResourceState(registry.#paths.global);
    const project = await readResourceState(registry.#paths.project);
    registry.#states.set('global', global);
    registry.#states.set('project', project);
    for (const id of new Set([...Object.keys(global.enabled), ...Object.keys(project.enabled)])) {
      registry.#enabled.set(id, project.enabled[id] ?? global.enabled[id] ?? true);
    }
    return registry;
  }

  async discoverExecutableMetadata(): Promise<void> {
    await this.#discoverExtensions(join(this.#workspacePath, '.pi', 'extensions'), 'project');
    await this.#discoverExtensions(join(this.#agentDir, 'extensions'), 'global');
    await this.#discoverPackages(join(this.#workspacePath, '.pi', 'settings.json'), 'project');
    await this.#discoverPackages(join(this.#agentDir, 'settings.json'), 'global');
  }

  filterSkills<T extends NamedResourceLike, D>(base: { skills: T[]; diagnostics: D[] }) {
    return {
      ...base,
      skills: base.skills.filter((resource) => this.#record('skill', resource)),
    };
  }

  filterPrompts<T extends NamedResourceLike, D>(base: { prompts: T[]; diagnostics: D[] }) {
    return {
      ...base,
      prompts: base.prompts.filter((resource) => this.#record('prompt', resource)),
    };
  }

  filterThemes<
    T extends Readonly<{
      name?: string;
      sourcePath?: string;
      sourceInfo?: SourceInfoLike;
    }>,
    D,
  >(base: { themes: T[]; diagnostics: D[] }) {
    return {
      ...base,
      themes: base.themes.filter((resource) => this.#recordTheme(resource)),
    };
  }

  list(): readonly AdapterResource[] {
    return Object.freeze(
      [...this.#resources.values()]
        .map((resource) => resource.view)
        .sort((left, right) =>
          `${left.kind}\0${left.name}`.localeCompare(`${right.kind}\0${right.name}`, 'en-AU'),
        ),
    );
  }

  prepareEnabledChange(
    resourceId: string,
    enabled: boolean,
    acknowledgedExecutableRisk: boolean,
  ): EnabledChange {
    const resource = this.#resources.get(resourceId);
    if (!resource) throw new Error('resource-unknown');
    if (resource.view.kind === 'package' && !resource.packageInstalled) {
      throw new Error('resource-package-not-installed');
    }
    if (resource.view.executable && enabled && !acknowledgedExecutableRisk) {
      throw new Error('resource-risk-acknowledgement-required');
    }
    const scope: ResourceScope =
      resource.packageScope ?? (resource.view.source === 'global' ? 'global' : 'project');
    const hadExplicitValue = this.#enabled.has(resourceId);
    const wasEnabled = resource.view.enabled;
    const oldExtensionPaths = [...this.enabledExtensionPaths];
    const apply = () => {
      this.#enabled.set(resourceId, enabled);
      if (resource.view.kind === 'extension' && resource.privatePath) {
        this.enabledExtensionPaths.splice(0, this.enabledExtensionPaths.length);
        for (const path of oldExtensionPaths) this.enabledExtensionPaths.push(path);
        const existing = this.enabledExtensionPaths.indexOf(resource.privatePath);
        if (enabled && existing < 0) this.enabledExtensionPaths.push(resource.privatePath);
        if (!enabled && existing >= 0) this.enabledExtensionPaths.splice(existing, 1);
      }
      this.#updateView(resourceId, enabled, resource.view.executable && enabled);
    };
    const rollback = () => {
      if (hadExplicitValue) this.#enabled.set(resourceId, wasEnabled);
      else this.#enabled.delete(resourceId);
      this.enabledExtensionPaths.splice(0, this.enabledExtensionPaths.length, ...oldExtensionPaths);
      this.#updateView(resourceId, wasEnabled, resource.view.trusted);
    };
    const persist = async () => {
      await this.#persistEnabled(scope, resourceId, enabled, wasEnabled);
    };
    const restorePersisted = async () => {
      await this.#persistEnabled(scope, resourceId, wasEnabled, enabled);
    };
    return Object.freeze({ apply, rollback, persist, restorePersisted });
  }

  get(resourceId: string): AdapterResource {
    const resource = this.#resources.get(resourceId);
    if (!resource) throw new Error('resource-unknown');
    return resource.view;
  }

  get enabledPackageSources(): readonly string[] {
    return Object.freeze(
      [...this.#resources.values()].flatMap((resource) =>
        resource.view.kind === 'package' &&
        resource.view.enabled &&
        resource.packageInstalled &&
        resource.packageSource
          ? [resource.packageSource]
          : [],
      ),
    );
  }

  async installPackage(
    source: string,
    scope: 'global' | 'project',
    online: boolean,
    acknowledgedExecutableRisk: boolean,
  ): Promise<AdapterResource> {
    this.#assertPackageMutation(online, acknowledgedExecutableRisk);
    assertPackageSource(source);
    const packages = this.#packages;
    if (!packages) throw new Error('resource-package-manager-unavailable');
    await packages.installAndPersist(source, { local: scope === 'project' });
    return this.#recordPackage(source, scope, true).view;
  }

  async mutatePackage(
    resourceId: string,
    operation: 'update' | 'remove',
    online: boolean,
    acknowledgedExecutableRisk: boolean,
  ): Promise<AdapterResource | null> {
    this.#assertPackageMutation(online, acknowledgedExecutableRisk);
    const resource = this.#resources.get(resourceId);
    const packages = this.#packages;
    if (
      !resource ||
      resource.view.kind !== 'package' ||
      !resource.packageSource ||
      !resource.packageScope ||
      !packages
    ) {
      throw new Error('resource-package-unavailable');
    }
    if (operation === 'update') {
      if (!resource.packageInstalled) throw new Error('resource-package-not-installed');
      await packages.update(resource.packageSource);
      const updated = this.#recordPackage(resource.packageSource, resource.packageScope, true);
      return updated.view;
    }
    const enabledChange = this.prepareEnabledChange(resourceId, false, true);
    enabledChange.apply();
    try {
      await enabledChange.persist();
    } catch (error) {
      enabledChange.rollback();
      throw error;
    }
    try {
      const removed = await packages.removeAndPersist(resource.packageSource, {
        local: resource.packageScope === 'project',
      });
      if (!removed) throw new Error('resource-package-remove-failed');
    } catch (error) {
      try {
        const packageScope = resource.packageScope === 'project' ? 'project' : 'user';
        if (!packages.getInstalledPath(resource.packageSource, packageScope)) {
          await packages.installAndPersist(resource.packageSource, {
            local: resource.packageScope === 'project',
          });
        }
        await enabledChange.restorePersisted();
        enabledChange.rollback();
      } catch (restorationError) {
        throw new AggregateError(
          [error, restorationError],
          'resource-package-remove-rollback-failed',
        );
      }
      throw error;
    }
    this.#resources.delete(resourceId);
    return null;
  }

  #record(kind: 'skill' | 'prompt' | 'theme', resource: NamedResourceLike): boolean {
    const path = resource.filePath ?? resource.path ?? resource.sourceInfo.path;
    const id = resourceId(kind, path);
    const source = sourceFrom(resource.sourceInfo);
    const enabled = this.#enabled.get(id) ?? true;
    this.#resources.set(
      id,
      Object.freeze({
        view: Object.freeze({
          id,
          kind,
          name: bounded(resource.name, 160, `Untitled ${kind}`),
          version: 'Pi 0.82 resource',
          source,
          trusted: true,
          enabled,
          executable: false,
          description: bounded(resource.description ?? `${kind} discovered by Pi.`, 1_024, ''),
          contributedSettings: Object.freeze([]),
          operations: Object.freeze([enabled ? 'disable' : 'enable']) as readonly ResourceOperation[],
        }),
        privatePath: path,
      }),
    );
    return enabled;
  }

  #recordTheme(
    resource: Readonly<{
      name?: string;
      sourcePath?: string;
      sourceInfo?: SourceInfoLike;
    }>,
  ): boolean {
    const path = resource.sourcePath ?? resource.sourceInfo?.path;
    if (!path) return true;
    const id = resourceId('theme', path);
    const source = resource.sourceInfo ? sourceFrom(resource.sourceInfo) : 'project';
    const enabled = this.#enabled.get(id) ?? true;
    this.#resources.set(
      id,
      Object.freeze({
        view: Object.freeze({
          id,
          kind: 'theme' as const,
          name: bounded(resource.name ?? basename(path), 160, 'Untitled theme'),
          version: 'Pi 0.82 resource',
          source,
          trusted: true,
          enabled,
          executable: false,
          description: 'Theme discovered by Pi.',
          contributedSettings: Object.freeze([]),
          operations: Object.freeze([enabled ? 'disable' : 'enable']) as readonly ResourceOperation[],
        }),
        privatePath: path,
      }),
    );
    return enabled;
  }

  async #discoverExtensions(
    directory: string,
    source: Extract<ResourceSource, 'global' | 'project'>,
  ): Promise<void> {
    const directoryMetadata = await lstat(directory).catch((error: unknown) => {
      if (isMissing(error)) return null;
      throw new Error('resource-discovery-failed');
    });
    if (!directoryMetadata) return;
    if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) return;
    const entries = await readdir(directory, { withFileTypes: true }).catch((error: unknown) => {
      if (isMissing(error)) return [];
      throw new Error('resource-discovery-failed');
    });
    for (const entry of entries.slice(0, 64)) {
      if (entry.isSymbolicLink() || (!entry.isFile() && !entry.isDirectory())) continue;
      const extension = entry.isFile() ? `.${entry.name.split('.').at(-1) ?? ''}` : '';
      if (entry.isFile() && !EXECUTABLE_EXTENSIONS.has(extension)) continue;
      const privatePath = join(directory, entry.name);
      const id = resourceId('extension', privatePath);
      const enabled = this.#enabled.get(id) ?? false;
      if (enabled) this.enabledExtensionPaths.push(privatePath);
      this.#resources.set(
        id,
        Object.freeze({
          view: Object.freeze({
            id,
            kind: 'extension' as const,
            name: bounded(entry.name.replace(/\.[^.]+$/u, ''), 160, 'Project extension'),
            version: source === 'project' ? 'Project resource' : 'Global resource',
            source,
            trusted: enabled,
            enabled,
            executable: true,
            description: `Executable ${source} extension discovered as metadata.`,
            contributedSettings: Object.freeze([]),
            operations: Object.freeze([enabled ? 'disable' : 'enable']) as readonly ResourceOperation[],
          }),
          privatePath,
        }),
      );
    }
  }

  async #discoverPackages(settingsPath: string, scope: 'global' | 'project'): Promise<void> {
    let bytes: Buffer;
    try {
      bytes = await readFile(settingsPath);
    } catch (error) {
      if (isMissing(error)) return;
      throw new Error('resource-discovery-failed');
    }
    try {
      if (bytes.byteLength > 1_048_576) throw new Error('resource-discovery-failed');
      let parsed: unknown;
      try {
        parsed = JSON.parse(bytes.toString('utf8'));
      } catch {
        return;
      }
      if (!isRecord(parsed) || !Array.isArray(parsed.packages)) return;
      for (const value of parsed.packages.slice(0, 64)) {
        const source =
          typeof value === 'string'
            ? value
            : isRecord(value) && typeof value.source === 'string'
              ? value.source
              : null;
        if (!source || source.length > 512 || /\p{Cc}/u.test(source)) continue;
        const installed = Boolean(
          this.#packages?.getInstalledPath(source, scope === 'project' ? 'project' : 'user'),
        );
        this.#recordPackage(source, scope, installed);
      }
    } finally {
      bytes.fill(0);
    }
  }

  #updateView(id: string, enabled: boolean, trusted: boolean): void {
    const resource = this.#resources.get(id);
    if (!resource) return;
    this.#resources.set(
      id,
      Object.freeze({
        ...resource,
        view: Object.freeze({
          ...resource.view,
          enabled,
          trusted,
          operations: this.#operations(resource, enabled),
        }),
      }),
    );
  }

  async #persistEnabled(
    scope: ResourceScope,
    resourceId: string,
    enabled: boolean,
    expectedEnabled: boolean,
  ): Promise<void> {
    const current = await readResourceState(this.#paths[scope]);
    const baseline = this.#states.get(scope) ?? EMPTY_RESOURCE_STATE;
    const expectedStored = baseline.enabled[resourceId];
    const currentStored = current.enabled[resourceId];
    if (currentStored !== expectedStored && (currentStored ?? expectedEnabled) !== expectedEnabled) {
      throw new Error('resource-state-conflict');
    }
    const revision = current.revision + 1;
    if (!Number.isSafeInteger(revision)) throw new Error('resource-state-exhausted');
    const next = Object.freeze({
      version: 1 as const,
      revision,
      enabled: Object.freeze({ ...current.enabled, [resourceId]: enabled }),
    });
    await writeResourceState(this.#paths[scope], next);
    this.#states.set(scope, next);
  }

  #recordPackage(
    source: string,
    scope: 'global' | 'project',
    installed: boolean,
  ): PrivateResource {
    const id = resourceId('package', source);
    const enabled = installed && (this.#enabled.get(id) ?? false);
    const record = Object.freeze({
      view: Object.freeze({
        id,
        kind: 'package' as const,
        name: bounded(packageDisplayName(source), 160, 'Pi package'),
        version: installed ? 'Installed' : 'Configured source',
        source: 'package' as const,
        trusted: enabled,
        enabled,
        executable: true,
        description: installed
          ? `Installed ${scope} Pi package. It remains disabled until explicitly enabled.`
          : `Configured ${scope} Pi package. Install it only after reviewing the executable-code warning.`,
        contributedSettings: Object.freeze([]),
        operations: Object.freeze(
          installed ? [enabled ? 'disable' : 'enable', 'update', 'remove'] : ['install', 'remove'],
        ) as readonly ResourceOperation[],
      }),
      packageSource: source,
      packageScope: scope,
      packageInstalled: installed,
    });
    this.#resources.set(id, record);
    return record;
  }

  #assertPackageMutation(online: boolean, acknowledgedExecutableRisk: boolean): void {
    if (!online) throw new Error('resource-offline-unavailable');
    if (!acknowledgedExecutableRisk) throw new Error('resource-risk-acknowledgement-required');
  }

  #operations(resource: PrivateResource, enabled: boolean): readonly ResourceOperation[] {
    if (resource.view.kind !== 'package') return Object.freeze([enabled ? 'disable' : 'enable']);
    return Object.freeze(
      resource.packageInstalled
        ? [enabled ? 'disable' : 'enable', 'update', 'remove']
        : ['install', 'remove'],
    );
  }
}

const EMPTY_RESOURCE_STATE: ResourceState = Object.freeze({
  version: 1,
  revision: 0,
  enabled: Object.freeze({}),
});

async function readResourceState(path: string): Promise<ResourceState> {
  let bytes: Buffer;
  try {
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 1_048_576) {
      throw new Error('resource-state-invalid');
    }
    bytes = await readFile(path);
  } catch (error) {
    if (isMissing(error)) return EMPTY_RESOURCE_STATE;
    throw error instanceof Error && error.message === 'resource-state-invalid'
      ? error
      : new Error('resource-state-unavailable');
  }
  try {
    const parsed: unknown = JSON.parse(bytes.toString('utf8'));
    if (!isRecord(parsed) || parsed.version !== 1 || !Number.isSafeInteger(parsed.revision)) {
      throw new Error('resource-state-invalid');
    }
    if (!isRecord(parsed.enabled) || Object.keys(parsed.enabled).length > 512) {
      throw new Error('resource-state-invalid');
    }
    const enabled: Record<string, boolean> = {};
    for (const [id, value] of Object.entries(parsed.enabled)) {
      if (!/^resource-[a-f0-9]{32}$/u.test(id) || typeof value !== 'boolean') {
        throw new Error('resource-state-invalid');
      }
      enabled[id] = value;
    }
    return Object.freeze({
      version: 1,
      revision: parsed.revision as number,
      enabled: Object.freeze(enabled),
    });
  } catch (error) {
    throw error instanceof Error && error.message === 'resource-state-invalid'
      ? error
      : new Error('resource-state-invalid');
  } finally {
    bytes.fill(0);
  }
}

async function writeResourceState(path: string, state: ResourceState): Promise<void> {
  const directory = dirname(path);
  let metadata = await lstat(directory).catch((error: unknown) => {
    if (isMissing(error)) return null;
    throw new Error('resource-state-unavailable');
  });
  if (!metadata) {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    metadata = await lstat(directory);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error('resource-state-invalid');
  }
  const temporary = join(directory, `.piui-resources-${randomUUID()}.tmp`);
  const handle = await open(
    temporary,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    await handle.writeFile(`${JSON.stringify(state, null, 2)}\n`, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporary, path);
  const directoryHandle = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    await directoryHandle.sync();
  } finally {
    await directoryHandle.close();
  }
}

function resourceId(kind: ResourceKind, value: string): string {
  return `resource-${createHash('sha256').update(`${kind}\0${value}`, 'utf8').digest('hex').slice(0, 32)}`;
}

function sourceFrom(info: SourceInfoLike): ResourceSource {
  if (info.origin === 'package') return 'package';
  return info.scope === 'project' ? 'project' : 'global';
}

function bounded(value: string, maximum: number, fallback: string): string {
  const clean = [...value.replaceAll(/\p{Cc}/gu, ' ').trim()].slice(0, maximum).join('');
  return clean || fallback;
}

const PACKAGE_SOURCE = /^(?:npm:)?(?:@[a-z0-9][a-z0-9._-]{0,63}\/[a-z0-9][a-z0-9._-]{0,127}|[a-z0-9][a-z0-9._-]{0,127})(?:@(?:[0-9]+(?:\.[0-9]+){0,2}(?:-[a-z0-9.-]+)?|[a-z][a-z0-9._-]{0,63}))?$/u;

export function assertPackageSource(source: string): void {
  if (typeof source !== 'string' || source.length > 256 || !PACKAGE_SOURCE.test(source)) {
    throw new Error('resource-package-source-invalid');
  }
}

function packageDisplayName(source: string): string {
  const withoutPrefix = source.startsWith('npm:') ? source.slice(4) : source;
  const versionIndex = withoutPrefix.lastIndexOf('@');
  return versionIndex > 0 ? withoutPrefix.slice(0, versionIndex) : withoutPrefix;
}

function isMissing(error: unknown): boolean {
  return isRecord(error) && error.code === 'ENOENT';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function canLoadResource(
  resource: ExecutableResource,
  workspaceTrusted: boolean,
  advancedMode: boolean,
): boolean {
  const executable = resource.kind === 'extension' || resource.kind === 'package';
  if (resource.source === 'project' && !workspaceTrusted) return false;
  if (executable && (!resource.trusted || !advancedMode)) return false;
  return resource.enabled;
}

export function canMutateResource(
  resource: ExecutableResource,
  online: boolean,
  acknowledgedExecutableRisk: boolean,
): boolean {
  const executable = resource.kind === 'extension' || resource.kind === 'package';
  return online && (!executable || acknowledgedExecutableRisk);
}
