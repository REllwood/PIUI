import { stat } from 'node:fs/promises';

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

export class SessionWatch {
  // `undefined` until the first acknowledgement: nothing is current before then.
  #identity: ObservedIdentity | undefined;
  #generation = 0;

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
    // An absent file stays current only while it is still absent; any file that
    // appears without PIUI re-acknowledging it is somebody else's write.
    if (current === null || identity === null) {
      return current === identity ? 'current' : 'external-change';
    }
    return sameIdentity(current, identity) ? 'current' : 'external-change';
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

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error;
}
