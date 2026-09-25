import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { TypedSettingsAdapter, isThinkingLevel } from '../src/pi/settings';

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

async function settingsRoot(): Promise<{ workspace: string; agent: string }> {
  const root = await mkdtemp(join(tmpdir(), 'piui-settings-'));
  roots.push(root);
  const workspace = join(root, 'workspace');
  const agent = join(root, 'agent');
  await mkdir(workspace);
  await mkdir(agent);
  return { workspace, agent };
}

describe('thinking level settings', () => {
  it('accepts every level Pi 0.82 accepts, including max, and nothing else', () => {
    for (const level of ['off', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max']) {
      expect(isThinkingLevel(level)).toBe(true);
    }
    for (const value of ['ultra', 'MAX', ' max', '', 'hasOwnProperty', '__proto__', 3, null]) {
      expect(isThinkingLevel(value)).toBe(false);
    }
  });

  it('seeds a session already at max and saves and reloads max', async () => {
    const { workspace, agent } = await settingsRoot();
    const settings = await TypedSettingsAdapter.create(workspace, agent);
    expect(settings.seed('reasoning.level', 'max', 'project', 'Current Pi session')).toMatchObject({
      value: 'max',
    });
    await expect(settings.save('reasoning.level', 'max', 'global', 0)).resolves.toMatchObject({
      value: 'max',
      scope: 'global',
    });
    const reloaded = await TypedSettingsAdapter.create(workspace, agent);
    expect(reloaded.seed('reasoning.level', 'off', 'project', 'Current Pi session')).toMatchObject({
      value: 'max',
      origin: 'PIUI global setting',
    });
    await expect(reloaded.save('reasoning.level', 'maximum', 'global', 1)).rejects.toThrow(
      'setting-value-invalid',
    );
  });
});
