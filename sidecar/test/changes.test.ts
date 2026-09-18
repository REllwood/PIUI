import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ChangeRegistry } from '../src/pi/changes.js';

async function registry() {
  const workspacePath = await mkdtemp(join(tmpdir(), 'piui-change-test-'));
  return {
    workspacePath,
    registry: await ChangeRegistry.create({
      workspaceId: 'workspace-test',
      workspaceRevision: 1,
      workspacePath,
      sessionId: 'session-test',
      sessionGeneration: 1,
    }),
  };
}

describe('ChangeRegistry', () => {
  it('restores an unchanged modified file through the open file identity', async () => {
    const test = await registry();
    const target = join(test.workspacePath, 'notes.txt');
    await writeFile(target, 'before\n');
    const token = await test.registry.beforeExecute('edit', { path: target });
    await writeFile(target, 'after\n');
    await test.registry.afterExecute(token, {}, undefined);

    const [change] = await test.registry.list();
    expect(change?.undo).toBe('safe');
    await test.registry.undo(change?.id ?? '', 1);
    expect(await readFile(target, 'utf8')).toBe('before\n');
  });

  it('revokes undo after an external modification', async () => {
    const test = await registry();
    const target = join(test.workspacePath, 'notes.txt');
    await writeFile(target, 'before\n');
    const token = await test.registry.beforeExecute('edit', { path: target });
    await writeFile(target, 'after\n');
    await test.registry.afterExecute(token, {}, undefined);
    await writeFile(target, 'external\n');

    const [change] = await test.registry.list();
    expect(change?.undo).toBe('revoked');
    await expect(test.registry.undo(change?.id ?? '', 1)).rejects.toThrow('change-undo-revoked');
    expect(await readFile(target, 'utf8')).toBe('external\n');
  });

  it('never offers automatic deletion as undo for a newly added file', async () => {
    const test = await registry();
    const target = join(test.workspacePath, 'new.txt');
    const token = await test.registry.beforeExecute('write', { path: target });
    await writeFile(target, 'new\n');
    await test.registry.afterExecute(token, {}, undefined);

    const [change] = await test.registry.list();
    expect(change?.state).toBe('added');
    expect(change?.undo).toBe('revoked');
    await expect(test.registry.undo(change?.id ?? '', 1)).rejects.toThrow('change-undo-revoked');
    expect(await readFile(target, 'utf8')).toBe('new\n');
  });
});
