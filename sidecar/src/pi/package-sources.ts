import type { PublicPackageManagerInstance } from './public-sdk.js';

type PackagePaths = Awaited<ReturnType<PublicPackageManagerInstance['resolveExtensionSources']>>;
type PackageResolver = Pick<
  PublicPackageManagerInstance,
  'listConfiguredPackages' | 'resolveExtensionSources'
>;

/**
 * Resolves PIUI-enabled Pi packages in the scope Pi's settings configure them
 * in. Pi 0.82's resolveExtensionSources(sources) looks every source up in user
 * scope unless told `{ local: true }`, so a project package would otherwise
 * resolve against the wrong install root. A source configured in both scopes
 * resolves in project scope, matching Pi's own precedence.
 */
export async function resolveEnabledPackagePaths(
  packageManager: PackageResolver,
  enabledSources: readonly string[],
): Promise<PackagePaths> {
  const paths: PackagePaths = { extensions: [], skills: [], prompts: [], themes: [] };
  if (enabledSources.length === 0) return paths;
  const projectSources = new Set(
    packageManager
      .listConfiguredPackages()
      .filter((configured) => configured.scope === 'project')
      .map((configured) => configured.source),
  );
  const project = enabledSources.filter((source) => projectSources.has(source));
  const user = enabledSources.filter((source) => !projectSources.has(source));
  const resolved: PackagePaths[] = [];
  if (user.length) resolved.push(await packageManager.resolveExtensionSources([...user]));
  if (project.length) {
    resolved.push(await packageManager.resolveExtensionSources([...project], { local: true }));
  }
  for (const next of resolved) {
    paths.extensions.push(...next.extensions);
    paths.skills.push(...next.skills);
    paths.prompts.push(...next.prompts);
    paths.themes.push(...next.themes);
  }
  return paths;
}
