import { describe, expect, it } from 'vitest';
import { resolveEnabledPackagePaths } from '../src/pi/package-sources';

function resource(path: string) {
  return { path, enabled: true, metadata: {} };
}

describe('enabled Pi package resolution', () => {
  it('resolves each enabled package in the scope Pi configures it in', async () => {
    const calls: Array<{ sources: string[]; options?: { local?: boolean } }> = [];
    const packageManager = {
      listConfiguredPackages: () => [
        { source: 'npm:user-package', scope: 'user', filtered: false },
        { source: 'npm:project-package', scope: 'project', filtered: false },
        { source: 'npm:both', scope: 'user', filtered: false },
        { source: 'npm:both', scope: 'project', filtered: false },
      ],
      resolveExtensionSources: async (sources: string[], options?: { local?: boolean }) => {
        calls.push({ sources, ...(options ? { options } : {}) });
        const scope = options?.local ? 'project' : 'user';
        return {
          extensions: sources.map((source) => resource(`${scope}/${source}/extension.js`)),
          skills: [resource(`${scope}/skill`)],
          prompts: [],
          themes: [],
        };
      },
    } as unknown as Parameters<typeof resolveEnabledPackagePaths>[0];

    const paths = await resolveEnabledPackagePaths(packageManager, [
      'npm:user-package',
      'npm:project-package',
      'npm:both',
    ]);
    expect(calls).toEqual([
      { sources: ['npm:user-package'] },
      { sources: ['npm:project-package', 'npm:both'], options: { local: true } },
    ]);
    expect(paths.extensions.map((entry) => entry.path)).toEqual([
      'user/npm:user-package/extension.js',
      'project/npm:project-package/extension.js',
      'project/npm:both/extension.js',
    ]);
    expect(paths.skills.map((entry) => entry.path)).toEqual(['user/skill', 'project/skill']);
  });

  it('does not consult the package manager when nothing is enabled', async () => {
    const packageManager = {
      listConfiguredPackages: () => {
        throw new Error('unexpected');
      },
      resolveExtensionSources: () => {
        throw new Error('unexpected');
      },
    } as unknown as Parameters<typeof resolveEnabledPackagePaths>[0];
    expect(await resolveEnabledPackagePaths(packageManager, [])).toEqual({
      extensions: [],
      skills: [],
      prompts: [],
      themes: [],
    });
  });
});
