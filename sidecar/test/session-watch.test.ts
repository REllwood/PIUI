import { appendFile, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { SessionWatch, observeSessionFile, verifyOwnAppends } from '../src/pi/session-watch';

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

describe('SessionWatch own-write window', () => {
  const header = '{"type":"session","id":"own"}\n';

  it('accepts growth of the same file while PIUI writes and rejects replacement', async () => {
    const path = await sessionPath();
    await writeFile(path, header);
    const watch = new SessionWatch();
    const generation = watch.acknowledge(await observeSessionFile(path));
    expect(watch.beginOwnWrite()).not.toBeNull();
    expect(() => watch.beginOwnWrite()).toThrow('session-busy');
    await appendFile(path, '{"type":"message","id":"a"}\n');
    expect(watch.verify(await observeSessionFile(path), generation)).toBe('current');
    await rm(path);
    await writeFile(path, `${header}{"type":"message","id":"a"}\n`);
    expect(watch.verify(await observeSessionFile(path), generation)).toBe('external-change');
    watch.endOwnWrite();
    expect(watch.ownWriteActive).toBe(false);
  });

  it('acknowledges exactly the entries Pi appended since the baseline', async () => {
    const path = await sessionPath();
    await writeFile(path, header);
    const baseline = await observeSessionFile(path);
    await appendFile(path, '{"type":"message","id":"a"}\n{"type":"message","id":"b"}\n');
    const identity = await verifyOwnAppends(path, baseline, [
      { type: 'message', id: 'a' },
      { type: 'message', id: 'b' },
    ]);
    expect(identity).toEqual(await observeSessionFile(path));
  });

  it('accepts Pi first writing a new file and a file that is still unwritten', async () => {
    const path = await sessionPath();
    expect(await verifyOwnAppends(path, null, [{ type: 'session', id: 'own' }])).toBeNull();
    await writeFile(path, `${header}{"type":"message","id":"a"}\n`);
    expect(
      await verifyOwnAppends(path, null, [
        { type: 'session', id: 'own' },
        { type: 'message', id: 'a' },
      ]),
    ).toEqual(await observeSessionFile(path));
  });

  it('rejects an external line, a partial line, truncation and removal', async () => {
    const path = await sessionPath();
    await writeFile(path, header);
    const baseline = await observeSessionFile(path);
    const own = [{ type: 'message', id: 'a' }];
    await appendFile(path, '{"type":"message","id":"a"}\n{"type":"custom","id":"intruder"}\n');
    await expect(verifyOwnAppends(path, baseline, own)).rejects.toThrow('session-external-change');
    await writeFile(path, `${header}{"type":"message","id":"a"}\n{"type":"cust`);
    await expect(verifyOwnAppends(path, baseline, own)).rejects.toThrow('session-external-change');
    await writeFile(path, '');
    await expect(verifyOwnAppends(path, baseline, [])).rejects.toThrow('session-external-change');
    await rm(path);
    await expect(verifyOwnAppends(path, baseline, [])).rejects.toThrow('session-external-change');
  });
});
