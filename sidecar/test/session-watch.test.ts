import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { SessionWatch, observeSessionFile } from '../src/pi/session-watch';

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

async function sessionPath(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'piui-session-watch-'));
  roots.push(root);
  return join(root, 'session.jsonl');
}

describe('SessionWatch', () => {
  it('treats a not-yet-written session file as current while it stays absent', async () => {
    const path = await sessionPath();
    const watch = new SessionWatch();
    expect(await observeSessionFile(path)).toBeNull();
    const generation = watch.acknowledge(await observeSessionFile(path));
    expect(watch.verify(await observeSessionFile(path), generation)).toBe('current');
  });

  it('reports a file that appears without re-acknowledgement as an external change', async () => {
    const path = await sessionPath();
    const watch = new SessionWatch();
    const generation = watch.acknowledge(await observeSessionFile(path));
    await writeFile(path, '{"type":"session","id":"external"}\n');
    expect(watch.verify(await observeSessionFile(path), generation)).toBe('external-change');
    const next = watch.acknowledge(await observeSessionFile(path));
    expect(watch.verify(await observeSessionFile(path), next)).toBe('current');
  });

  it('keeps detecting external writers and removal once the file exists', async () => {
    const path = await sessionPath();
    await writeFile(path, '{"type":"session","id":"own"}\n');
    const watch = new SessionWatch();
    const generation = watch.acknowledge(await observeSessionFile(path));
    expect(watch.verify(await observeSessionFile(path), generation)).toBe('current');
    expect(watch.verify(await observeSessionFile(path), generation - 1)).toBe('stale-generation');
    await writeFile(path, '{"type":"session","id":"own"}\n{"type":"custom","id":"x"}\n');
    expect(watch.verify(await observeSessionFile(path), generation)).toBe('external-change');
    await rm(path);
    expect(watch.verify(await observeSessionFile(path), generation)).toBe('external-change');
  });

  it('never treats an unacknowledged watch as current', () => {
    expect(new SessionWatch().verify(null, 0)).toBe('external-change');
  });
});
