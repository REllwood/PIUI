import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CHANGE_RETENTION_LIMITS, ChangeRegistry, ChangeRetention } from '../src/pi/changes.js';

async function registry(retention?: ChangeRetention, sessionId = 'session-test') {
  const workspacePath = await mkdtemp(join(tmpdir(), 'piui-change-test-'));
  return {
    workspacePath,
    registry: await ChangeRegistry.create({
      workspaceId: 'workspace-test',
      workspaceRevision: 1,
      workspacePath,
      sessionId,
      sessionGeneration: 1,
      ...(retention ? { retention } : {}),
    }),
  };
}

// Records one modified-file change: a 1,000 byte undo snapshot plus diff lines
// of 1,000 UTF-16 units on each side (4,000 bytes), so 5,000 bytes retained.
async function recordEdit(test: Awaited<ReturnType<typeof registry>>, name: string) {
  const target = join(test.workspacePath, name);
  await writeFile(target, 'b'.repeat(1_000));
  const token = await test.registry.beforeExecute('edit', { path: target });
  await writeFile(target, 'a'.repeat(1_000));
  await test.registry.afterExecute(token, {}, undefined);
  return target;
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

describe('ChangeRegistry retention', () => {
  it('uses a 64 MiB and 256 change budget by default', () => {
    expect(CHANGE_RETENTION_LIMITS).toEqual({
      maxRetainedBytes: 64 * 1024 * 1024,
      maxChangesPerSession: 256,
    });
  });

  it('keeps at most the per-session number of changes, dropping the oldest', async () => {
    const retention = new ChangeRetention({ maxChangesPerSession: 2 });
    const test = await registry(retention);
    const first = await recordEdit(test, 'first.txt');
    const [oldest] = await test.registry.list();
    await recordEdit(test, 'second.txt');
    await recordEdit(test, 'third.txt');

    const changes = await test.registry.list();
    expect(changes.map((change) => change.path)).toEqual(['second.txt', 'third.txt']);
    expect(changes.every((change) => change.undo === 'safe')).toBe(true);
    await expect(test.registry.undo(oldest?.id ?? '', 1)).rejects.toThrow('change-undo-revoked');
    expect(await readFile(first, 'utf8')).toBe('a'.repeat(1_000));
    expect(retention.retainedBytes).toBe(10_000);
  });

  it('releases the oldest undo snapshots across sessions once over the byte budget', async () => {
    const retention = new ChangeRetention({ maxRetainedBytes: 9_500 });
    const older = await registry(retention, 'session-older');
    const newer = await registry(retention, 'session-newer');
    await recordEdit(older, 'older.txt');
    expect(retention.retainedBytes).toBe(5_000);
    const target = await recordEdit(newer, 'newer.txt');

    expect(retention.retainedBytes).toBe(9_000);
    const [released] = await older.registry.list();
    expect(released?.undo).toBe('revoked');
    await expect(older.registry.undo(released?.id ?? '', 1)).rejects.toThrow('change-undo-revoked');
    const [kept] = await newer.registry.list();
    expect(kept?.undo).toBe('safe');
    await newer.registry.undo(kept?.id ?? '', 1);
    expect(await readFile(target, 'utf8')).toBe('b'.repeat(1_000));
    expect(retention.retainedBytes).toBe(8_000);

    older.registry.close();
    newer.registry.close();
    expect(retention.retainedBytes).toBe(0);
  });

  it('drops the oldest changes when diff text alone exceeds the budget', async () => {
    const retention = new ChangeRetention({ maxRetainedBytes: 4_500 });
    const test = await registry(retention);
    await recordEdit(test, 'first.txt');
    await recordEdit(test, 'second.txt');

    const changes = await test.registry.list();
    expect(changes.map((change) => [change.path, change.undo])).toEqual([
      ['second.txt', 'revoked'],
    ]);
    expect(retention.retainedBytes).toBe(4_000);
  });
});
