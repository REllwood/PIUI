import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readFile, readdir, readlink, realpath, rename } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, sep } from 'node:path';
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

type ResolvedPackageResource = Readonly<{ path: string; enabled: boolean }>;
export type ResolvedPackagePaths = Readonly<{
  extensions: readonly ResolvedPackageResource[];
  skills: readonly ResolvedPackageResource[];
  prompts: readonly ResolvedPackageResource[];
  themes: readonly ResolvedPackageResource[];
}>;

export type PackageLifecyclePort = Readonly<{
  installAndPersist: (source: string, options?: { local?: boolean }) => Promise<void>;
  update: (source?: string) => Promise<void>;
  removeAndPersist: (source: string, options?: { local?: boolean }) => Promise<boolean>;
  getInstalledPath: (source: string, scope: 'user' | 'project') => string | undefined;
  resolveExtensionSources?: (
    sources: string[],
    options?: { local?: boolean },
  ) => Promise<ResolvedPackagePaths>;
}>;

type ResourceScope = 'global' | 'project';
type ResourceState = Readonly<{
  version: 1;
  revision: number;
  enabled: Readonly<Record<string, boolean>>;
}>;

/**
 * PIUI-owned acknowledgement of executable code. It lives only under the
 * agent directory and maps an executable resource ID (kind, scope, canonical
 * workspace and source) to the content digest the user acknowledged.
 */
type ExecutableApprovalState = Readonly<{
  version: 1;
  revision: number;
  approvals: Readonly<Record<string, string>>;
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
const EXECUTABLE_APPROVALS_FILE = 'piui-executable-approvals.json';
const MAX_EXECUTABLE_APPROVALS = 4_096;
const MAX_DIGEST_ENTRIES = 4_096;
const MAX_DIGEST_BYTES = 64 * 1_048_576;
const RESOURCE_ID = /^resource-[a-f0-9]{32}$/u;
const CONTENT_DIGEST = /^[a-f0-9]{64}$/u;

// Package resolution must never reach the network: an approved package whose
// exact installed copy is missing or stale is skipped rather than reinstalled.
let offlineResolutions = 0;
let offlineRestore: string | undefined;

async function withPiOffline<T>(operation: () => Promise<T>): Promise<T> {
  if (offlineResolutions === 0) {
    offlineRestore = process.env.PI_OFFLINE;
    process.env.PI_OFFLINE = '1';
  }
  offlineResolutions += 1;
  try {
    return await operation();
  } finally {
    offlineResolutions -= 1;
    if (offlineResolutions === 0) {
      if (offlineRestore === undefined) delete process.env.PI_OFFLINE;
      else process.env.PI_OFFLINE = offlineRestore;
    }
  }
}

export class ResourceRegistry {
  readonly #workspacePath: string;
  readonly #agentDir: string;
  readonly #resources = new Map<string, PrivateResource>();
  readonly #paths: Readonly<Record<ResourceScope, string>>;
  readonly #approvalsPath: string;
  readonly #states = new Map<ResourceScope, ResourceState>();
  readonly #enabled = new Map<string, boolean>();
  readonly #packages?: PackageLifecyclePort;
  #workspaceIdentity: string | undefined;
  #approvalStoreTrusted = false;
  #approvals: ExecutableApprovalState = EMPTY_APPROVAL_STATE;
  readonly enabledExtensionPaths: string[] = [];

  private constructor(workspacePath: string, agentDir: string, packages?: PackageLifecyclePort) {
    this.#workspacePath = workspacePath;
    this.#agentDir = agentDir;
    this.#packages = packages;
    this.#paths = Object.freeze({
      global: join(agentDir, 'piui-resources.json'),
      project: join(workspacePath, '.pi', 'piui-resources.json'),
    });
    this.#approvalsPath = join(agentDir, EXECUTABLE_APPROVALS_FILE);
  }

  static async create(
    workspacePath: string,
    agentDir: string,
    packages?: PackageLifecyclePort,
  ): Promise<ResourceRegistry> {
    const registry = new ResourceRegistry(workspacePath, agentDir, packages);
    // The workspace file is repository content. It may toggle non-executable
    // resources only; executable enablement is read from PIUI-owned state.
    const global = await readResourceState(registry.#paths.global);
    const project = await readResourceState(registry.#paths.project);
    registry.#states.set('global', global);
    registry.#states.set('project', project);
    for (const id of new Set([...Object.keys(global.enabled), ...Object.keys(project.enabled)])) {
      registry.#enabled.set(id, project.enabled[id] ?? global.enabled[id] ?? true);
    }
    registry.#workspaceIdentity = await realpath(workspacePath).catch(() => undefined);
    const agentIdentity = await canonicalPath(agentDir).catch(() => undefined);
    // Acknowledgements stored inside the workspace would be repository
    // controlled, so such a layout can never enable executable code.
    registry.#approvalStoreTrusted = Boolean(
      registry.#workspaceIdentity &&
        agentIdentity &&
        !contained(registry.#workspaceIdentity, agentIdentity),
    );
    if (registry.#approvalStoreTrusted) {
      registry.#approvals = await readApprovalState(registry.#approvalsPath);
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
    if (resource.view.executable && enabled && !this.#approvalStoreTrusted) {
      throw new Error('resource-approval-store-untrusted');
    }
    const scope: ResourceScope =
      resource.packageScope ?? (resource.view.source === 'global' ? 'global' : 'project');
    const hadExplicitValue = this.#enabled.has(resourceId);
    const wasEnabled = resource.view.enabled;
    const previousApproval = this.#approvals.approvals[resourceId];
    const oldExtensionPaths = [...this.enabledExtensionPaths];
    const apply = () => {
      if (!resource.view.executable) this.#enabled.set(resourceId, enabled);
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
      if (!resource.view.executable) {
        if (hadExplicitValue) this.#enabled.set(resourceId, wasEnabled);
        else this.#enabled.delete(resourceId);
      }
      this.enabledExtensionPaths.splice(0, this.enabledExtensionPaths.length, ...oldExtensionPaths);
      this.#updateView(resourceId, wasEnabled, resource.view.trusted);
    };
    const persist = async () => {
      if (!resource.view.executable) {
        await this.#persistEnabled(scope, resourceId, enabled, wasEnabled);
        return;
      }
      let digest: string | undefined;
      if (enabled) {
        // Bind the acknowledgement to the exact bytes that will be loaded.
        const target = this.#executablePath(resource);
        digest = target ? await digestResource(target) : undefined;
        if (!digest) throw new Error('resource-digest-unavailable');
      }
      await this.#persistApproval(resourceId, digest, previousApproval);
    };
    const restorePersisted = async () => {
      if (!resource.view.executable) {
        await this.#persistEnabled(scope, resourceId, wasEnabled, enabled);
        return;
      }
      await this.#persistApproval(
        resourceId,
        previousApproval,
        this.#approvals.approvals[resourceId],
      );
    };
    return Object.freeze({ apply, rollback, persist, restorePersisted });
  }

  get(resourceId: string): AdapterResource {
    const resource = this.#resources.get(resourceId);
    if (!resource) throw new Error('resource-unknown');
    return resource.view;
  }

  /**
   * Sources of packages the user acknowledged. Loading must go through
   * `resolveEnabledPackagePaths`, which re-verifies the acknowledged digest and
   * resolves each package in its own scope without network installation.
   */
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

  async resolveEnabledPackagePaths(): Promise<ResolvedPackagePaths> {
    const resolved = {
      extensions: [] as ResolvedPackageResource[],
      skills: [] as ResolvedPackageResource[],
      prompts: [] as ResolvedPackageResource[],
      themes: [] as ResolvedPackageResource[],
    };
    const packages = this.#packages;
    const resolve = packages?.resolveExtensionSources;
    if (!packages || !resolve || !this.#approvalStoreTrusted) return resolved;
    for (const [id, resource] of this.#resources) {
      if (
        resource.view.kind !== 'package' ||
        !resource.view.enabled ||
        !resource.packageInstalled ||
        !resource.packageSource ||
        !resource.packageScope
      ) {
        continue;
      }
      const source = resource.packageSource;
      const scope = resource.packageScope === 'project' ? 'project' : 'user';
      const approved = this.#approvals.approvals[id];
      const installedPath = packages.getInstalledPath(source, scope);
      if (!approved || !installedPath || (await digestResource(installedPath)) !== approved) {
        continue;
      }
      const root = await realpath(installedPath).catch(() => undefined);
      if (!root) continue;
      const paths = await withPiOffline(() =>
        Reflect.apply(resolve, packages, [[source], { local: scope === 'project' }]) as Promise<
          ResolvedPackagePaths
        >,
      );
      // Resolution must not have replaced the acknowledged copy.
      if (
        packages.getInstalledPath(source, scope) !== installedPath ||
        (await digestResource(installedPath)) !== approved
      ) {
        continue;
      }
      for (const key of ['extensions', 'skills', 'prompts', 'themes'] as const) {
        for (const entry of paths[key] ?? []) {
          if (!entry.enabled || typeof entry.path !== 'string') continue;
          const target = await realpath(entry.path).catch(() => undefined);
          if (target && contained(root, target)) {
            resolved[key].push(Object.freeze({ path: entry.path, enabled: true }));
          }
        }
      }
    }
    return Object.freeze({
      extensions: Object.freeze(resolved.extensions),
      skills: Object.freeze(resolved.skills),
      prompts: Object.freeze(resolved.prompts),
      themes: Object.freeze(resolved.themes),
    });
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
    return (await this.#observePackage(source, scope)).view;
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
      if (resource.view.enabled && this.#approvalStoreTrusted) {
        // The update itself was acknowledged; carry the acknowledgement to the
        // updated bytes, or withdraw it if they can no longer be identified.
        const installedPath = packages.getInstalledPath(
          resource.packageSource,
          resource.packageScope === 'project' ? 'project' : 'user',
        );
        const digest = installedPath ? await digestResource(installedPath) : undefined;
        await this.#persistApproval(resourceId, digest, this.#approvals.approvals[resourceId]);
      }
      const updated = await this.#observePackage(resource.packageSource, resource.packageScope);
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
      const id = this.#executableId('extension', source, privatePath);
      if (!id) continue;
      const enabled = await this.#isApproved(id, privatePath);
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
        await this.#observePackage(source, scope);
      }
    } finally {
      bytes.fill(0);
    }
  }

  async #observePackage(source: string, scope: 'global' | 'project'): Promise<PrivateResource> {
    const installedPath = this.#packages?.getInstalledPath(
      source,
      scope === 'project' ? 'project' : 'user',
    );
    const id = this.#executableId('package', scope, source);
    const enabled = Boolean(id && installedPath && (await this.#isApproved(id, installedPath)));
    return this.#recordPackage(source, scope, Boolean(installedPath), enabled);
  }

  #executableId(
    kind: 'extension' | 'package',
    scope: 'global' | 'project',
    source: string,
  ): string | undefined {
    // Project IDs are bound to the canonical workspace, so the same source in
    // another repository, or in global scope, is a different resource.
    if (scope === 'project' && !this.#workspaceIdentity) return undefined;
    const workspace = scope === 'project' ? (this.#workspaceIdentity ?? '') : '';
    return resourceId(kind, `${scope}\0${workspace}\0${source}`);
  }

  async #isApproved(id: string, path: string): Promise<boolean> {
    if (!this.#approvalStoreTrusted) return false;
    const approved = this.#approvals.approvals[id];
    return Boolean(approved && (await digestResource(path)) === approved);
  }

  #executablePath(resource: PrivateResource): string | undefined {
    if (resource.view.kind === 'extension') return resource.privatePath;
    if (resource.view.kind !== 'package' || !resource.packageSource) return undefined;
    return this.#packages?.getInstalledPath(
      resource.packageSource,
      resource.packageScope === 'project' ? 'project' : 'user',
    );
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

  async #persistApproval(
    resourceId: string,
    digest: string | undefined,
    expected: string | undefined,
  ): Promise<void> {
    if (!this.#approvalStoreTrusted) {
      if (digest === undefined) return;
      throw new Error('resource-approval-store-untrusted');
    }
    const current = await readApprovalState(this.#approvalsPath);
    const stored = current.approvals[resourceId];
    if (stored !== expected && stored !== digest) throw new Error('resource-state-conflict');
    const approvals: Record<string, string> = { ...current.approvals };
    if (digest === undefined) delete approvals[resourceId];
    else approvals[resourceId] = digest;
    if (Object.keys(approvals).length > MAX_EXECUTABLE_APPROVALS) {
      throw new Error('resource-state-exhausted');
    }
    const revision = current.revision + 1;
    if (!Number.isSafeInteger(revision)) throw new Error('resource-state-exhausted');
    const next: ExecutableApprovalState = Object.freeze({
      version: 1 as const,
      revision,
      approvals: Object.freeze(approvals),
    });
    await writeResourceState(this.#approvalsPath, next);
    this.#approvals = next;
  }

  #recordPackage(
    source: string,
    scope: 'global' | 'project',
    installed: boolean,
    enabled: boolean,
  ): PrivateResource {
    const id = this.#executableId('package', scope, source) ?? resourceId('package', source);
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

const EMPTY_APPROVAL_STATE: ExecutableApprovalState = Object.freeze({
  version: 1,
  revision: 0,
  approvals: Object.freeze({}),
});

async function readStateBytes(path: string): Promise<Buffer | undefined> {
  try {
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 1_048_576) {
      throw new Error('resource-state-invalid');
    }
    return await readFile(path);
  } catch (error) {
    if (isMissing(error)) return undefined;
    throw error instanceof Error && error.message === 'resource-state-invalid'
      ? error
      : new Error('resource-state-unavailable');
  }
}

async function readResourceState(path: string): Promise<ResourceState> {
  const bytes = await readStateBytes(path);
  if (!bytes) return EMPTY_RESOURCE_STATE;
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
      if (!RESOURCE_ID.test(id) || typeof value !== 'boolean') {
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

async function readApprovalState(path: string): Promise<ExecutableApprovalState> {
  const bytes = await readStateBytes(path);
  if (!bytes) return EMPTY_APPROVAL_STATE;
  try {
    const parsed: unknown = JSON.parse(bytes.toString('utf8'));
    if (
      !isRecord(parsed) ||
      parsed.version !== 1 ||
      !Number.isSafeInteger(parsed.revision) ||
      !isRecord(parsed.approvals) ||
      Object.keys(parsed.approvals).length > MAX_EXECUTABLE_APPROVALS
    ) {
      throw new Error('resource-state-invalid');
    }
    const approvals: Record<string, string> = {};
    for (const [id, digest] of Object.entries(parsed.approvals)) {
      if (!RESOURCE_ID.test(id) || typeof digest !== 'string' || !CONTENT_DIGEST.test(digest)) {
        throw new Error('resource-state-invalid');
      }
      approvals[id] = digest;
    }
    return Object.freeze({
      version: 1,
      revision: parsed.revision as number,
      approvals: Object.freeze(approvals),
    });
  } catch {
    throw new Error('resource-state-invalid');
  } finally {
    bytes.fill(0);
  }
}

async function writeResourceState(
  path: string,
  state: ResourceState | ExecutableApprovalState,
): Promise<void> {
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

/**
 * Bounded content identity of an executable resource: a single file, or a
 * directory tree walked without following links. Symbolic links contribute
 * their target text, so retargeting one changes the digest. Anything outside
 * the bounds has no identity and therefore cannot be acknowledged.
 */
export async function digestResource(path: string): Promise<string | undefined> {
  const root = await realpath(path).catch(() => undefined);
  if (!root) return undefined;
  const hash = createHash('sha256');
  let entries = 0;
  let bytes = 0;
  const visit = async (absolute: string, relativePath: string): Promise<boolean> => {
    entries += 1;
    if (entries > MAX_DIGEST_ENTRIES) return false;
    const metadata = await lstat(absolute).catch(() => undefined);
    if (!metadata) return false;
    if (metadata.isSymbolicLink()) {
      const target = await readlink(absolute).catch(() => undefined);
      if (target === undefined) return false;
      hash.update(`link\0${relativePath}\0${target}\0`, 'utf8');
      return true;
    }
    if (metadata.isFile()) {
      bytes += metadata.size;
      if (bytes > MAX_DIGEST_BYTES) return false;
      const content = await readFile(absolute).catch(() => undefined);
      if (!content || content.byteLength !== metadata.size) return false;
      hash.update(`file\0${relativePath}\0${content.byteLength}\0`, 'utf8');
      hash.update(content);
      return true;
    }
    if (!metadata.isDirectory()) return false;
    hash.update(`dir\0${relativePath}\0`, 'utf8');
    const names = await readdir(absolute).catch(() => undefined);
    if (!names) return false;
    names.sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
    for (const name of names) {
      if (!(await visit(join(absolute, name), relativePath ? `${relativePath}/${name}` : name))) {
        return false;
      }
    }
    return true;
  };
  return (await visit(root, '')) ? hash.digest('hex') : undefined;
}

async function canonicalPath(path: string): Promise<string> {
  try {
    return await realpath(path);
  } catch (error) {
    const parent = dirname(path);
    if (!isMissing(error) || parent === path) throw error;
    return join(await canonicalPath(parent), basename(path));
  }
}

function contained(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === '' || (!path.startsWith(`..${sep}`) && path !== '..' && !isAbsolute(path));
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
