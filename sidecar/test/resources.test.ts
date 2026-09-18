import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ResourceRegistry, type PackageLifecyclePort } from '../src/pi/resources.js';

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'piui-resources-test-'));
  const workspace = join(root, 'workspace');
  const agentDir = join(root, 'agent');
  const extensions = join(workspace, '.pi', 'extensions');
  await mkdir(extensions, { recursive: true });
  await mkdir(agentDir, { recursive: true });
  await writeFile(join(extensions, 'review.mjs'), 'export default () => undefined;\n');
  return { workspace, agentDir };
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
    const installed = new Set<string>();
    const packages: PackageLifecyclePort = {
      async installAndPersist(source, options) {
        calls.push(`install:${source}:${options?.local === true ? 'project' : 'global'}`);
        installed.add(source);
      },
      async update(source) {
        calls.push(`update:${source ?? 'all'}`);
      },
      async removeAndPersist(source, options) {
        calls.push(`remove:${source}:${options?.local === true ? 'project' : 'global'}`);
        return installed.delete(source);
      },
      getInstalledPath(source) {
        return installed.has(source) ? `/isolated/${source}` : undefined;
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

    await registry.mutatePackage(added.id, 'update', true, true);
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
    const installed = new Set<string>();
    const packages: PackageLifecyclePort = {
      async installAndPersist(source) { installed.add(source); },
      async update() {},
      async removeAndPersist() { return false; },
      getInstalledPath(source) { return installed.has(source) ? `/isolated/${source}` : undefined; },
    };
    const registry = await ResourceRegistry.create(paths.workspace, paths.agentDir, packages);
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
    const installed = new Set<string>();
    let removalAttempts = 0;
    let installAttempts = 0;
    const packages: PackageLifecyclePort = {
      async installAndPersist(source) {
        installAttempts += 1;
        installed.add(source);
      },
      async update() {},
      async removeAndPersist(source) {
        removalAttempts += 1;
        installed.delete(source);
        throw new Error('package-manager-interrupted');
      },
      getInstalledPath(source) { return installed.has(source) ? `/isolated/${source}` : undefined; },
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
    expect(installed.has('@piui/recover@1.0.0')).toBe(true);
  });
});
