import { constants } from 'node:fs';
import { open, stat } from 'node:fs/promises';

export type FileIdentity = Readonly<{
  device: bigint;
  inode: bigint;
  size: bigint;
  modifiedNs: bigint;
}>;

/**
 * `null` is an explicit observation that the session file does not exist yet.
 * Pi 0.82 creates a new or forked-without-reply session file only when the
 * first assistant message is persisted, so a PIUI-created session starts here.
 */
export type ObservedIdentity = FileIdentity | null;

export type SessionEntryMarker = Readonly<{ type: string; id: string }>;

const READ_CHUNK_BYTES = 1_048_576;
const MAX_ENTRY_LINE_BYTES = 64 * 1_048_576;

export class SessionWatch {
  // `undefined` until the first acknowledgement: nothing is current before then.
  #identity: ObservedIdentity | undefined;
  #generation = 0;
  #ownWrite = false;

  acknowledge(identity: ObservedIdentity): number {
    this.#identity = identity === null ? null : Object.freeze({ ...identity });
    return ++this.#generation;
  }

  verify(
    identity: ObservedIdentity,
    expectedGeneration: number,
  ): 'current' | 'stale-generation' | 'external-change' {
    if (expectedGeneration !== this.#generation) return 'stale-generation';
    const current = this.#identity;
    if (current === undefined) return 'external-change';
    // While PIUI's own turn runs, Pi appends to the file it owns. Accept only
    // growth of the same file (or Pi's first write of an absent one); the exact
    // appended entries are checked when the turn ends.
    if (this.#ownWrite) return continuesFrom(current, identity) ? 'current' : 'external-change';
    // An absent file stays current only while it is still absent; any file that
    // appears without PIUI re-acknowledging it is somebody else's write.
    if (current === null || identity === null) {
      return current === identity ? 'current' : 'external-change';
    }
    return sameIdentity(current, identity) ? 'current' : 'external-change';
  }

  get ownWriteActive(): boolean {
    return this.#ownWrite;
  }

  /** Returns the acknowledged baseline that the own-write window grows from. */
  beginOwnWrite(): ObservedIdentity {
    if (this.#ownWrite || this.#identity === undefined) throw new Error('session-busy');
    this.#ownWrite = true;
    return this.#identity;
  }

  endOwnWrite(): void {
    this.#ownWrite = false;
  }
}

export async function observeSessionFile(path: string): Promise<ObservedIdentity> {
  try {
    return identityOf(await stat(path, { bigint: true }));
  } catch (error) {
    if (isNodeError(error) && error.code === 'ENOENT') return null;
    throw error;
  }
}

/**
 * Confirms that everything written to the session file since `baseline` is
 * exactly Pi's own appended entries, in order, and returns the new identity.
 * Pi writes one JSON line per entry; a first write of an absent file carries
 * the session header followed by every entry held in memory until then.
 */
export async function verifyOwnAppends(
  path: string,
  baseline: ObservedIdentity,
  expected: readonly SessionEntryMarker[],
): Promise<ObservedIdentity> {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    // Pi still holds a never-written session in memory (no assistant reply yet).
    if (isNodeError(error) && error.code === 'ENOENT' && baseline === null) return null;
    throw new Error('session-external-change', { cause: error });
  }
  try {
    const before = identityOf(await handle.stat({ bigint: true }));
    if (baseline && !continuesFrom(baseline, before)) throw new Error('session-external-change');
    const markers = await readAppendedMarkers(handle, baseline?.size ?? 0n, before.size);
    const after = identityOf(await handle.stat({ bigint: true }));
    if (
      !sameIdentity(before, after) ||
      markers.length !== expected.length ||
      markers.some(
        (marker, index) =>
          marker.type !== expected[index]?.type || marker.id !== expected[index]?.id,
      )
    ) {
      throw new Error('session-external-change');
    }
    return after;
  } finally {
    await handle.close();
  }
}

async function readAppendedMarkers(
  handle: Awaited<ReturnType<typeof open>>,
  start: bigint,
  end: bigint,
): Promise<SessionEntryMarker[]> {
  const markers: SessionEntryMarker[] = [];
  const buffer = Buffer.alloc(READ_CHUNK_BYTES);
  let pending: Buffer[] = [];
  let pendingBytes = 0;
  let position = start;
  while (position < end) {
    const wanted = Number(end - position < BigInt(buffer.length) ? end - position : buffer.length);
    const { bytesRead } = await handle.read(buffer, 0, wanted, position);
    if (bytesRead === 0) throw new Error('session-external-change');
    position += BigInt(bytesRead);
    let offset = 0;
    while (offset < bytesRead) {
      const newline = buffer.indexOf(0x0a, offset);
      const stop = newline < 0 || newline >= bytesRead ? bytesRead : newline;
      pending.push(Buffer.from(buffer.subarray(offset, stop)));
      pendingBytes += stop - offset;
      if (pendingBytes > MAX_ENTRY_LINE_BYTES) throw new Error('session-external-change');
      if (stop === bytesRead) break;
      markers.push(entryMarker(Buffer.concat(pending, pendingBytes)));
      pending = [];
      pendingBytes = 0;
      offset = stop + 1;
    }
  }
  // Pi terminates every entry line; a partial trailing line is not Pi's write.
  if (pendingBytes > 0) throw new Error('session-external-change');
  return markers;
}

function entryMarker(line: Buffer): SessionEntryMarker {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line.toString('utf8'));
  } catch {
    throw new Error('session-external-change');
  }
  if (!parsed || typeof parsed !== 'object') throw new Error('session-external-change');
  const record = parsed as Record<string, unknown>;
  if (typeof record.type !== 'string' || typeof record.id !== 'string') {
    throw new Error('session-external-change');
  }
  return Object.freeze({ type: record.type, id: record.id });
}

function identityOf(value: {
  isFile(): boolean;
  dev: bigint;
  ino: bigint;
  size: bigint;
  mtimeNs: bigint;
}): FileIdentity {
  if (!value.isFile()) throw new Error('session-file-unavailable');
  return Object.freeze({
    device: value.dev,
    inode: value.ino,
    size: value.size,
    modifiedNs: value.mtimeNs,
  });
}

function sameIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return (
    left.device === right.device &&
    left.inode === right.inode &&
    left.size === right.size &&
    left.modifiedNs === right.modifiedNs
  );
}

function continuesFrom(baseline: ObservedIdentity, observed: ObservedIdentity): boolean {
  if (baseline === null) return true;
  return (
    observed !== null &&
    observed.device === baseline.device &&
    observed.inode === baseline.inode &&
    observed.size >= baseline.size
  );
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error;
}
