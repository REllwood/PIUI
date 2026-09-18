export type FileIdentity = Readonly<{
  device: bigint;
  inode: bigint;
  size: bigint;
  modifiedNs: bigint;
}>;

export class SessionWatch {
  #identity: FileIdentity | null = null;
  #generation = 0;

  acknowledge(identity: FileIdentity): number {
    this.#identity = Object.freeze({ ...identity });
    return ++this.#generation;
  }

  verify(
    identity: FileIdentity,
    expectedGeneration: number,
  ): 'current' | 'stale-generation' | 'external-change' {
    if (expectedGeneration !== this.#generation) return 'stale-generation';
    const current = this.#identity;
    if (
      !current ||
      current.device !== identity.device ||
      current.inode !== identity.inode ||
      current.size !== identity.size ||
      current.modifiedNs !== identity.modifiedNs
    )
      return 'external-change';
    return 'current';
  }
}
