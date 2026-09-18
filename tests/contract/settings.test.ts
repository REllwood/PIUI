import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { TypedSettingsAdapter } from '../../sidecar/src/pi/settings';

function fixtureRoot(label: string): string {
  return resolve(
    process.env.TMPDIR ?? '/tmp',
    `piui-settings-contract-${process.pid}-${Date.now()}-${label}`,
  );
}

describe('typed settings persistence', () => {
  it('persists acknowledged typed values and detects a competing writer', async () => {
    const root = fixtureRoot('save');
    const workspace = resolve(root, 'workspace');
    const agent = resolve(root, 'agent');
    await mkdir(workspace, { recursive: true, mode: 0o700 });
    await mkdir(agent, { recursive: true, mode: 0o700 });
    const first = await TypedSettingsAdapter.create(workspace, agent);
    const stale = await TypedSettingsAdapter.create(workspace, agent);
    first.seed('reasoning.level', 'medium', 'global', 'Pi default');
    stale.seed('reasoning.level', 'medium', 'global', 'Pi default');
    const saved = await first.save('reasoning.level', 'high', 'global', 0);
    expect(saved).toMatchObject({ value: 'high', revision: 1, scope: 'global' });
    await expect(stale.save('reasoning.level', 'low', 'global', 0)).rejects.toThrow(
      'setting-save-conflict',
    );
    expect(stale.read('reasoning.level')?.value).toBe('medium');
  });

  it('rejects unsupported keys and invalid values before touching storage', async () => {
    const root = fixtureRoot('validation');
    const workspace = resolve(root, 'workspace');
    const agent = resolve(root, 'agent');
    await mkdir(workspace, { recursive: true, mode: 0o700 });
    await mkdir(agent, { recursive: true, mode: 0o700 });
    const settings = await TypedSettingsAdapter.create(workspace, agent);
    expect(() => settings.seed('credential.token', 'secret', 'global', 'fixture')).toThrow(
      'setting-key-unsupported',
    );
    expect(() => settings.seed('reasoning.level', 'unbounded', 'global', 'fixture')).toThrow(
      'setting-value-invalid',
    );
  });
});
