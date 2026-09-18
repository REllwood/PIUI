import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { AdapterCapability, PiAdapter } from '../src/pi/adapter';
import { PI_082_CAPABILITIES, RAW_RPC_DIAGNOSTIC_ENABLED } from '../src/pi/capabilities';
import { Pi082Adapter } from '../src/pi/pi-082-adapter';

const requiredCapabilities = [
  'providers',
  'authentication',
  'workspaces',
  'sessions',
  'streaming',
  'queues',
  'compaction',
  'tools',
  'resources',
  'settings',
  'diagnostics',
] as const satisfies readonly AdapterCapability[];

const requiredMethods = [
  'listProviders',
  'login',
  'logout',
  'listSessions',
  'createSession',
  'resumeSession',
  'forkSession',
  'renameSession',
  'inspectSession',
  'compactSession',
  'trashSessionTarget',
  'confirmSessionTrashed',
  'listChanges',
  'undoChange',
  'changeTarget',
  'listSettings',
  'saveSetting',
  'previewSettingReset',
  'listResources',
  'setResourceEnabled',
  'installPackage',
  'mutatePackage',
  'queueFollowUp',
  'replaceFollowUpQueue',
  'exportSession',
  'streamTurn',
  'stopTurn',
  'diagnosticSnapshot',
  'close',
] as const satisfies readonly (keyof PiAdapter)[];

function sourceFiles(directory: string): string[] {
  return readdirSync(directory).flatMap((entry) => {
    const target = join(directory, entry);
    return statSync(target).isDirectory() ? sourceFiles(target) : target.endsWith('.ts') ? [target] : [];
  });
}

describe('Pi 0.82 adapter contract', () => {
  it('implements every required typed operation at runtime', () => {
    const prototype = Pi082Adapter.prototype as unknown as Record<string, unknown>;
    for (const method of requiredMethods) expect(prototype[method], method).toBeTypeOf('function');
    expect(new Set(requiredMethods).size).toBe(requiredMethods.length);
  });

  it('publishes one explicit support decision for every capability', () => {
    expect(Object.keys(PI_082_CAPABILITIES).sort()).toEqual([...requiredCapabilities].sort());
    expect(Object.values(PI_082_CAPABILITIES).every((support) => support === 'supported' || support === 'unavailable')).toBe(true);
    expect(PI_082_CAPABILITIES).toEqual(Object.fromEntries(requiredCapabilities.map((capability) => [capability, 'supported'])));
    expect(RAW_RPC_DIAGNOSTIC_ENABLED).toBe(false);
  });

  it('keeps Pi imports confined to the public package root seam', () => {
    const sourceRoot = resolve(import.meta.dirname, '../src');
    const sources = sourceFiles(sourceRoot).map((file) => readFileSync(file, 'utf8')).join('\n');
    expect(sources).not.toMatch(/@earendil-works\/pi-coding-agent\//u);
    expect(sources.match(/from ['"]@earendil-works\/pi-coding-agent['"]/gu)).toHaveLength(1);
  });
});

// A stored credential is what makes Pi refresh (and therefore open) its models
// store during construction, so the placement of that store is observable.
function offlineAdapterOptions() {
  return {
    credentials: {
      read: async (providerId: string) =>
        providerId === 'anthropic' ? { type: 'api_key', key: 'offline-test-key' } : undefined,
      list: async () => ['anthropic'],
      modify: async () => undefined,
      delete: async () => undefined,
    },
    allowModelNetwork: false,
    generation: 1,
    approvalHost: Object.freeze({
      requestApproval: async () => {
        throw new Error('approval-unavailable');
      },
      notifyApprovalReady: async () => {
        throw new Error('approval-unavailable');
      },
      abandonApproval: async () => {
        throw new Error('approval-unavailable');
      },
    }),
  } as unknown as Parameters<typeof Pi082Adapter.create>[0];
}

describe('Pi 0.82 adapter models placement', () => {
  const originalHome = process.env.HOME;
  const originalAgentDir = process.env.PIUI_PI_AGENT_DIR;
  const temporaryRoots: string[] = [];

  afterEach(async () => {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalAgentDir === undefined) delete process.env.PIUI_PI_AGENT_DIR;
    else process.env.PIUI_PI_AGENT_DIR = originalAgentDir;
    for (const root of temporaryRoots.splice(0)) await rm(root, { force: true, recursive: true });
  });

  async function temporaryRoot(prefix: string): Promise<string> {
    const root = await mkdtemp(join(tmpdir(), prefix));
    temporaryRoots.push(root);
    return root;
  }

  it('writes no Pi state into the sealed home when no agent directory is supplied', async () => {
    const home = await temporaryRoot('piui-sealed-home-');
    process.env.HOME = home;
    delete process.env.PIUI_PI_AGENT_DIR;
    const adapter = await Pi082Adapter.create(offlineAdapterOptions());
    expect(Array.isArray(await adapter.listProviders())).toBe(true);
    await adapter.close();
    expect(existsSync(join(home, '.pi'))).toBe(false);
    expect(readdirSync(home)).toEqual([]);
  });

  it('writes no Pi state into the sealed home when an agent directory is supplied', async () => {
    const home = await temporaryRoot('piui-sealed-home-');
    const agentDir = await temporaryRoot('piui-agent-dir-');
    process.env.HOME = home;
    process.env.PIUI_PI_AGENT_DIR = agentDir;
    const adapter = await Pi082Adapter.create(offlineAdapterOptions());
    expect(Array.isArray(await adapter.listProviders())).toBe(true);
    await adapter.close();
    expect(existsSync(join(home, '.pi'))).toBe(false);
    expect(readdirSync(home)).toEqual([]);
  });
});
