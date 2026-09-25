import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  ResourceRegistry,
  type PackageLifecyclePort,
  type ResolvedPackagePaths,
} from '../src/pi/resources.js';

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'piui-resources-test-'));
  const workspace = join(root, 'workspace');
  const agentDir = join(root, 'agent');
  const extensions = join(workspace, '.pi', 'extensions');
  await mkdir(extensions, { recursive: true });
  await mkdir(agentDir, { recursive: true });
  await writeFile(join(extensions, 'review.mjs'), 'export default () => undefined;\n');
  return { root, workspace, agentDir };
}

const EMPTY_PATHS: ResolvedPackagePaths = Object.freeze({
  extensions: [],
  skills: [],
  prompts: [],
  themes: [],
});

// Installs each package as a real directory so digests are computed over
// genuine bytes, as they are for Pi's own package manager.
function installedPackages(root: string, overrides: Partial<PackageLifecyclePort> = {}) {
  const installed = new Map<string, string>();
  const directory = (source: string) => join(root, 'installed', source.replaceAll('/', '_'));
  const port: PackageLifecyclePort = {
    async installAndPersist(source) {
      const target = directory(source);
      await mkdir(target, { recursive: true });
      await writeFile(join(target, 'index.mjs'), `export default () => '${source}';\n`);
      installed.set(source, target);
    },
    async update() {},
    async removeAndPersist(source) {
      return installed.delete(source);
    },
    getInstalledPath(source) {
      return installed.get(source);
    },
    ...overrides,
  };
  return { port, installed, directory };
}

describe('ResourceRegistry persistence', () => {
  it('keeps executable project resources disabled until acknowledged and persists the choice', async () => {
    const paths = await fixture();
    const initial = await ResourceRegistry.create(paths.workspace, paths.agentDir);
    await initial.discoverExecutableMetadata();
    const extension = initial.list().find((resource) => resource.kind === 'extension');
    expect(extension?.enabled).toBe(false);

    const change = initial.prepareEnabledChange(extension?.id ?? '', true, true);
    change.apply();
    await change.persist();

    const reopened = await ResourceRegistry.create(paths.workspace, paths.agentDir);
    await reopened.discoverExecutableMetadata();
    const restored = reopened.list().find((resource) => resource.id === extension?.id);
    expect(restored?.enabled).toBe(true);
    expect(restored?.trusted).toBe(true);
    expect(reopened.enabledExtensionPaths).toHaveLength(1);
  });

  it('rolls in-memory state back without broadening executable trust', async () => {
    const paths = await fixture();
    const registry = await ResourceRegistry.create(paths.workspace, paths.agentDir);
    await registry.discoverExecutableMetadata();
    const extension = registry.list().find((resource) => resource.kind === 'extension');
    const change = registry.prepareEnabledChange(extension?.id ?? '', true, true);
    change.apply();
    expect(registry.get(extension?.id ?? '').enabled).toBe(true);
    change.rollback();
    expect(registry.get(extension?.id ?? '').enabled).toBe(false);
    expect(registry.enabledExtensionPaths).toHaveLength(0);
  });

  it('requires a fresh acknowledgement before enabling executable code', async () => {
    const paths = await fixture();
    const registry = await ResourceRegistry.create(paths.workspace, paths.agentDir);
    await registry.discoverExecutableMetadata();
    const extension = registry.list().find((resource) => resource.kind === 'extension');
    expect(() =>
      registry.prepareEnabledChange(extension?.id ?? '', true, false),
    ).toThrow('resource-risk-acknowledgement-required');
  });

  it('runs acknowledged package install, enable, update and remove through the public port', async () => {
    const paths = await fixture();
    const calls: string[] = [];
    const { port, installed } = installedPackages(paths.root);
    const packages: PackageLifecyclePort = {
      ...port,
      async installAndPersist(source, options) {
        calls.push(`install:${source}:${options?.local === true ? 'project' : 'global'}`);
        await port.installAndPersist(source, options);
      },
      async update(source) {
        calls.push(`update:${source ?? 'all'}`);
      },
      async removeAndPersist(source, options) {
        calls.push(`remove:${source}:${options?.local === true ? 'project' : 'global'}`);
        return installed.delete(source);
      },
    };
    const registry = await ResourceRegistry.create(paths.workspace, paths.agentDir, packages);
    const added = await registry.installPackage('@piui/example@1.2.3', 'project', true, true);
    expect(added).toMatchObject({ kind: 'package', enabled: false, operations: ['enable', 'update', 'remove'] });

    const enable = registry.prepareEnabledChange(added.id, true, true);
    enable.apply();
    await enable.persist();
    expect(registry.enabledPackageSources).toEqual(['@piui/example@1.2.3']);
    expect(registry.get(added.id).operations).toEqual(['disable', 'update', 'remove']);

    const updated = await registry.mutatePackage(added.id, 'update', true, true);
    expect(updated).toMatchObject({ id: added.id, enabled: true });
    expect(await registry.mutatePackage(added.id, 'remove', true, true)).toBeNull();
    expect(registry.list()).toHaveLength(0);
    expect(calls).toEqual([
      'install:@piui/example@1.2.3:project',
      'update:@piui/example@1.2.3',
      'remove:@piui/example@1.2.3:project',
    ]);
  });

  it('rejects offline, unacknowledged and malformed package mutations before side effects', async () => {
    const paths = await fixture();
    let calls = 0;
    const packages: PackageLifecyclePort = {
      async installAndPersist() { calls += 1; },
      async update() { calls += 1; },
      async removeAndPersist() { calls += 1; return true; },
      getInstalledPath() { return undefined; },
    };
    const registry = await ResourceRegistry.create(paths.workspace, paths.agentDir, packages);
    await expect(registry.installPackage('valid-package', 'global', false, true)).rejects.toThrow('resource-offline-unavailable');
    await expect(registry.installPackage('valid-package', 'global', true, false)).rejects.toThrow('resource-risk-acknowledgement-required');
    await expect(registry.installPackage('https://example.invalid/code', 'global', true, true)).rejects.toThrow('resource-package-source-invalid');
    expect(calls).toBe(0);
  });

  it('restores an enabled package when removal does not complete', async () => {
    const paths = await fixture();
    const { port } = installedPackages(paths.root, { async removeAndPersist() { return false; } });
    const registry = await ResourceRegistry.create(paths.workspace, paths.agentDir, port);
    const added = await registry.installPackage('@piui/rollback@1.0.0', 'global', true, true);
    const enable = registry.prepareEnabledChange(added.id, true, true);
    enable.apply();
    await enable.persist();

    await expect(registry.mutatePackage(added.id, 'remove', true, true)).rejects.toThrow(
      'resource-package-remove-failed',
    );
    expect(registry.get(added.id).enabled).toBe(true);
    expect(registry.enabledPackageSources).toEqual(['@piui/rollback@1.0.0']);
  });

  it('reinstalls a package before restoring state after an uncertain removal failure', async () => {
    const paths = await fixture();
    let removalAttempts = 0;
    let installAttempts = 0;
    const base = installedPackages(paths.root);
    const packages: PackageLifecyclePort = {
      ...base.port,
      async installAndPersist(source, options) {
        installAttempts += 1;
        await base.port.installAndPersist(source, options);
      },
      async removeAndPersist(source) {
        removalAttempts += 1;
        base.installed.delete(source);
        throw new Error('package-manager-interrupted');
      },
    };
    const registry = await ResourceRegistry.create(paths.workspace, paths.agentDir, packages);
    const added = await registry.installPackage('@piui/recover@1.0.0', 'project', true, true);
    const enable = registry.prepareEnabledChange(added.id, true, true);
    enable.apply();
    await enable.persist();

    await expect(registry.mutatePackage(added.id, 'remove', true, true)).rejects.toThrow(
      'package-manager-interrupted',
    );
    expect(removalAttempts).toBe(1);
    expect(installAttempts).toBe(2);
    expect(registry.get(added.id).enabled).toBe(true);
    expect(base.installed.has('@piui/recover@1.0.0')).toBe(true);
  });
});

const HOSTILE_FIXTURE = resolve(import.meta.dirname, '../../tests/fixtures/hostile-project');
const HOSTILE_PACKAGE = 'missing-hostile-package@1.0.0';

async function hostileWorkspace() {
  const root = await mkdtemp(join(tmpdir(), 'piui-hostile-resources-'));
  const workspace = join(root, 'workspace');
  const agentDir = join(root, 'agent');
  await cp(HOSTILE_FIXTURE, workspace, { recursive: true });
  await mkdir(agentDir, { recursive: true });
  // The repository also ships a "pre-installed" project copy of its package.
  const projectCopy = join(workspace, '.pi', 'npm', 'node_modules', 'missing-hostile-package');
  await mkdir(projectCopy, { recursive: true });
  await writeFile(join(projectCopy, 'index.mjs'), 'throw new Error("hostile package executed");\n');
  const resolutions: string[] = [];
  const packages: PackageLifecyclePort = {
    async installAndPersist() { throw new Error('unexpected-install'); },
    async update() { throw new Error('unexpected-update'); },
    async removeAndPersist() { throw new Error('unexpected-remove'); },
    getInstalledPath(source, scope) {
      return source === HOSTILE_PACKAGE && scope === 'project' ? projectCopy : undefined;
    },
    async resolveExtensionSources(sources, options) {
      resolutions.push(`${sources.join(',')}:${options?.local === true ? 'project' : 'user'}`);
      return {
        ...EMPTY_PATHS,
        extensions: [{ path: join(projectCopy, 'index.mjs'), enabled: true }],
      };
    },
  };
  return { root, workspace, agentDir, projectCopy, packages, resolutions };
}

async function forgeWorkspaceEnablement(workspace: string, ids: readonly string[]) {
  // Everything a repository can write: every listed ID, flagged enabled, in
  // the workspace-local PIUI state file.
  await writeFile(
    join(workspace, '.pi', 'piui-resources.json'),
    `${JSON.stringify({ version: 1, revision: 7, enabled: Object.fromEntries(ids.map((id) => [id, true])) })}\n`,
  );
}

describe('ResourceRegistry hostile workspace', () => {
  it('cannot self-enable a project extension or package from workspace-controlled files', async () => {
    const hostile = await hostileWorkspace();
    try {
      const probe = await ResourceRegistry.create(hostile.workspace, hostile.agentDir, hostile.packages);
      await probe.discoverExecutableMetadata();
      const executable = probe.list().filter((resource) => resource.executable);
      expect(executable.map((resource) => resource.kind).sort()).toEqual(['extension', 'package']);
      expect(executable.every((resource) => !resource.enabled)).toBe(true);

      // The attacker knows the exact IDs (they are derived from public inputs).
      await forgeWorkspaceEnablement(hostile.workspace, executable.map((resource) => resource.id));

      const registry = await ResourceRegistry.create(hostile.workspace, hostile.agentDir, hostile.packages);
      await registry.discoverExecutableMetadata();
      expect(registry.list().filter((resource) => resource.executable && resource.enabled)).toEqual([]);
      expect(registry.enabledExtensionPaths).toEqual([]);
      expect(registry.enabledPackageSources).toEqual([]);
      expect(await registry.resolveEnabledPackagePaths()).toEqual(EMPTY_PATHS);
      expect(hostile.resolutions).toEqual([]);
      await expect(readFile(join(hostile.workspace, 'import-marker.log'))).rejects.toThrow();
    } finally {
      await rm(hostile.root, { recursive: true, force: true });
    }
  });

  it('never applies a global package acknowledgement to a same-named project copy', async () => {
    const hostile = await hostileWorkspace();
    try {
      const globalCopy = join(hostile.root, 'agent-npm', 'missing-hostile-package');
      await mkdir(globalCopy, { recursive: true });
      await writeFile(join(globalCopy, 'index.mjs'), 'export default () => undefined;\n');
      await writeFile(
        join(hostile.agentDir, 'settings.json'),
        `${JSON.stringify({ packages: [HOSTILE_PACKAGE] })}\n`,
      );
      const packages: PackageLifecyclePort = {
        ...hostile.packages,
        getInstalledPath(source, scope) {
          if (source !== HOSTILE_PACKAGE) return undefined;
          return scope === 'project' ? hostile.projectCopy : globalCopy;
        },
      };
      const registry = await ResourceRegistry.create(hostile.workspace, hostile.agentDir, packages);
      await registry.discoverExecutableMetadata();
      const listed = registry.list().filter((resource) => resource.kind === 'package');
      expect(listed).toHaveLength(2);
      expect(new Set(listed.map((resource) => resource.id)).size).toBe(2);
      const globalPackage = listed.find((resource) => resource.description.includes('global'))!;
      const enable = registry.prepareEnabledChange(globalPackage.id, true, true);
      enable.apply();
      await enable.persist();

      const reopened = await ResourceRegistry.create(hostile.workspace, hostile.agentDir, packages);
      await reopened.discoverExecutableMetadata();
      const reopenedPackages = reopened.list().filter((resource) => resource.kind === 'package');
      expect(reopenedPackages.find((resource) => resource.id === globalPackage.id)?.enabled).toBe(true);
      expect(reopenedPackages.filter((resource) => resource.enabled)).toHaveLength(1);
      await reopened.resolveEnabledPackagePaths();
      expect(hostile.resolutions).toEqual([`${HOSTILE_PACKAGE}:user`]);
    } finally {
      await rm(hostile.root, { recursive: true, force: true });
    }
  });

  it('withdraws an acknowledgement when the executable bytes change', async () => {
    const hostile = await hostileWorkspace();
    try {
      const registry = await ResourceRegistry.create(hostile.workspace, hostile.agentDir, hostile.packages);
      await registry.discoverExecutableMetadata();
      const extension = registry.list().find((resource) => resource.kind === 'extension')!;
      const projectPackage = registry.list().find((resource) => resource.kind === 'package')!;
      for (const id of [extension.id, projectPackage.id]) {
        const change = registry.prepareEnabledChange(id, true, true);
        change.apply();
        await change.persist();
      }
      const approved = await ResourceRegistry.create(hostile.workspace, hostile.agentDir, hostile.packages);
      await approved.discoverExecutableMetadata();
      expect(approved.enabledExtensionPaths).toHaveLength(1);
      expect((await approved.resolveEnabledPackagePaths()).extensions).toHaveLength(1);
      expect(hostile.resolutions).toEqual([`${HOSTILE_PACKAGE}:project`]);

      // A later pull swaps the acknowledged code for something else.
      await writeFile(join(hostile.workspace, '.pi', 'extensions', 'probe.mjs'), 'export default () => 1;\n');
      await writeFile(join(hostile.projectCopy, 'index.mjs'), 'export default () => 2;\n');
      const changed = await ResourceRegistry.create(hostile.workspace, hostile.agentDir, hostile.packages);
      await changed.discoverExecutableMetadata();
      expect(changed.list().filter((resource) => resource.executable && resource.enabled)).toEqual([]);
      expect(changed.enabledExtensionPaths).toEqual([]);
      expect(await changed.resolveEnabledPackagePaths()).toEqual(EMPTY_PATHS);
    } finally {
      await rm(hostile.root, { recursive: true, force: true });
    }
  });

  it('refuses executable acknowledgements when the agent directory lies inside the workspace', async () => {
    const hostile = await hostileWorkspace();
    try {
      const nestedAgent = join(hostile.workspace, '.pi', 'agent');
      await mkdir(nestedAgent, { recursive: true });
      const registry = await ResourceRegistry.create(hostile.workspace, nestedAgent, hostile.packages);
      await registry.discoverExecutableMetadata();
      const extension = registry.list().find((resource) => resource.kind === 'extension')!;
      expect(() => registry.prepareEnabledChange(extension.id, true, true)).toThrow(
        'resource-approval-store-untrusted',
      );
      await writeFile(
        join(nestedAgent, 'piui-executable-approvals.json'),
        `${JSON.stringify({ version: 1, revision: 1, approvals: { [extension.id]: 'a'.repeat(64) } })}\n`,
      );
      const reopened = await ResourceRegistry.create(hostile.workspace, nestedAgent, hostile.packages);
      await reopened.discoverExecutableMetadata();
      expect(reopened.enabledExtensionPaths).toEqual([]);
    } finally {
      await rm(hostile.root, { recursive: true, force: true });
    }
  });
});
