import { constants } from 'node:fs';
import { open, realpath, type FileHandle } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

export type NormalisedChange = Readonly<{
  pathLabel: string;
  state: 'added' | 'modified' | 'deleted' | 'binary' | 'fallback';
  additions: number;
  deletions: number;
  text: string;
  truncated: boolean;
}>;

export function normaliseChange(value: unknown): NormalisedChange {
  if (!value || typeof value !== 'object')
    return {
      pathLabel: 'Unknown file',
      state: 'fallback',
      additions: 0,
      deletions: 0,
      text: 'Diff unavailable.',
      truncated: false,
    };
  const change = value as Record<string, unknown>;
  const raw = typeof change.diff === 'string' ? change.diff : '';
  const maximum = 262_144;
  const text = raw.slice(0, maximum);
  const lines = text.split('\n');
  return Object.freeze({
    pathLabel:
      typeof change.path === 'string'
        ? change.path.replaceAll('\\', '/').split('/').slice(-3).join('/')
        : 'Unknown file',
    state:
      change.binary === true
        ? 'binary'
        : change.state === 'added' || change.state === 'deleted'
          ? change.state
          : raw
            ? 'modified'
            : 'fallback',
    additions: lines.filter((line) => line.startsWith('+') && !line.startsWith('+++')).length,
    deletions: lines.filter((line) => line.startsWith('-') && !line.startsWith('---')).length,
    text,
    truncated: raw.length > maximum,
  });
}

export type AdapterChange = Readonly<{
  id: string;
  path: string;
  state: 'added' | 'modified' | 'deleted' | 'binary' | 'failed';
  additions: number;
  deletions: number;
  before: readonly string[];
  after: readonly string[];
  undo: 'safe' | 'revoked' | 'complete';
}>;

type Snapshot = Readonly<{
  exists: boolean;
  bytes: Buffer | null;
  digest: string;
  binary: boolean;
}>;

type PendingObservation = Readonly<{
  sessionId: string;
  sessionGeneration: number;
  target: string;
  pathLabel: string;
  before: Snapshot;
}>;

type StoredChange = {
  view: AdapterChange;
  sessionId: string;
  sessionGeneration: number;
  workspaceId: string;
  workspaceRevision: number;
  target: string;
  before: Snapshot;
  afterDigest: string;
  retention: ChangeRetentionEntry;
};

const MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024;
const MAX_DIFF_LINES = 4_000;

export const CHANGE_RETENTION_LIMITS = Object.freeze({
  maxRetainedBytes: 64 * 1024 * 1024,
  maxChangesPerSession: 256,
});

export type ChangeRetentionEntry = {
  /** Bytes still held for the change: its undo snapshot plus its diff lines. */
  bytes: number;
  /** Drops the undo snapshot (undo becomes unavailable); returns the bytes freed. */
  releaseSnapshot(): number;
  /** Removes the change from its registry altogether. */
  evict(): void;
};

/**
 * One memory budget shared by every ChangeRegistry in the sidecar. Each change
 * can hold a 2 MiB undo snapshot plus diff text, so without a bound a long run
 * of edits grows without limit. Past the byte cap the oldest undo snapshots are
 * released first (those changes stay listed, undo-unavailable); if diff text
 * alone is still over, the oldest changes are dropped.
 */
export class ChangeRetention {
  readonly #maxRetainedBytes: number;
  readonly #maxChangesPerSession: number;
  readonly #entries = new Set<ChangeRetentionEntry>();
  #bytes = 0;

  constructor(
    limits: Readonly<{ maxRetainedBytes?: number; maxChangesPerSession?: number }> = {},
  ) {
    const maxRetainedBytes = limits.maxRetainedBytes ?? CHANGE_RETENTION_LIMITS.maxRetainedBytes;
    const maxChangesPerSession =
      limits.maxChangesPerSession ?? CHANGE_RETENTION_LIMITS.maxChangesPerSession;
    if (
      !Number.isSafeInteger(maxRetainedBytes) ||
      maxRetainedBytes < 0 ||
      !Number.isSafeInteger(maxChangesPerSession) ||
      maxChangesPerSession < 1
    ) {
      throw new Error('change-retention-invalid');
    }
    this.#maxRetainedBytes = maxRetainedBytes;
    this.#maxChangesPerSession = maxChangesPerSession;
  }

  get retainedBytes(): number {
    return this.#bytes;
  }

  get maxChangesPerSession(): number {
    return this.#maxChangesPerSession;
  }

  admit(entry: ChangeRetentionEntry): void {
    if (this.#entries.has(entry)) return;
    this.#entries.add(entry);
    this.#bytes += entry.bytes;
    // Sets iterate oldest first, across every registry sharing this budget.
    for (const oldest of this.#entries) {
      if (this.#bytes <= this.#maxRetainedBytes) return;
      this.#bytes -= oldest.releaseSnapshot();
    }
    for (const oldest of [...this.#entries]) {
      if (this.#bytes <= this.#maxRetainedBytes) return;
      oldest.evict();
    }
  }

  /** Accounts for a snapshot its registry released itself. */
  released(entry: ChangeRetentionEntry, bytes: number): void {
    if (this.#entries.has(entry)) this.#bytes -= bytes;
  }

  forget(entry: ChangeRetentionEntry): void {
    if (this.#entries.delete(entry)) this.#bytes -= entry.bytes;
  }
}

const SHARED_RETENTION = new ChangeRetention();

export class ChangeRegistry {
  readonly #workspaceId: string;
  readonly #workspaceRevision: number;
  readonly #workspacePath: string;
  readonly #sessionId: string;
  readonly #sessionGeneration: number;
  readonly #changes = new Map<string, StoredChange>();
  readonly #retention: ChangeRetention;

  private constructor(options: {
    workspaceId: string;
    workspaceRevision: number;
    workspacePath: string;
    sessionId: string;
    sessionGeneration: number;
    retention: ChangeRetention;
  }) {
    this.#workspaceId = options.workspaceId;
    this.#workspaceRevision = options.workspaceRevision;
    this.#workspacePath = options.workspacePath;
    this.#sessionId = options.sessionId;
    this.#sessionGeneration = options.sessionGeneration;
    this.#retention = options.retention;
  }

  static async create(options: {
    workspaceId: string;
    workspaceRevision: number;
    workspacePath: string;
    sessionId: string;
    sessionGeneration: number;
    retention?: ChangeRetention;
  }): Promise<ChangeRegistry> {
    return new ChangeRegistry({
      ...options,
      workspacePath: await realpath(options.workspacePath),
      retention: options.retention ?? SHARED_RETENTION,
    });
  }

  async beforeExecute(toolName: string, params: unknown): Promise<PendingObservation | undefined> {
    if (toolName !== 'edit' && toolName !== 'write') return undefined;
    if (!params || typeof params !== 'object') return undefined;
    const fields = params as Record<string, unknown>;
    const path = typeof fields.path === 'string' ? fields.path : fields.file_path;
    if (typeof path !== 'string' || !path || path.length > 4_096 || /\p{Cc}/u.test(path)) {
      return undefined;
    }
    const target = await canonicalTarget(this.#workspacePath, path);
    if (!inside(this.#workspacePath, target)) return undefined;
    return Object.freeze({
      sessionId: this.#sessionId,
      sessionGeneration: this.#sessionGeneration,
      target,
      pathLabel: relative(this.#workspacePath, target).replaceAll(sep, '/').slice(0, 1_024),
      before: await snapshot(target),
    });
  }

  async afterExecute(token: unknown, _result: unknown, error: unknown | undefined): Promise<void> {
    if (!isPendingObservation(token) || token.sessionId !== this.#sessionId) return;
    if (error !== undefined) {
      token.before.bytes?.fill(0);
      return;
    }
    const after = await snapshot(token.target);
    if (token.before.digest === after.digest && token.before.exists === after.exists) {
      token.before.bytes?.fill(0);
      after.bytes?.fill(0);
      return;
    }
    const beforeLines = displayLines(token.before);
    const afterLines = displayLines(after);
    const binary = token.before.binary || after.binary;
    const id = `change-${randomUUID().replaceAll('-', '')}`;
    const view: AdapterChange = Object.freeze({
      id,
      path: token.pathLabel,
      state: binary
        ? 'binary'
        : !token.before.exists
          ? 'added'
          : !after.exists
            ? 'deleted'
            : 'modified',
      additions: binary ? 0 : countAdditions(beforeLines, afterLines),
      deletions: binary ? 0 : countAdditions(afterLines, beforeLines),
      before: Object.freeze(beforeLines),
      after: Object.freeze(afterLines),
      undo:
        token.before.exists &&
        after.exists &&
        token.before.bytes !== null &&
        after.bytes !== null &&
        token.sessionGeneration === this.#sessionGeneration
          ? 'safe'
          : 'revoked',
    });
    const change: StoredChange = {
      view,
      sessionId: this.#sessionId,
      sessionGeneration: this.#sessionGeneration,
      workspaceId: this.#workspaceId,
      workspaceRevision: this.#workspaceRevision,
      target: token.target,
      before: token.before,
      afterDigest: after.digest,
      retention: {
        bytes: linesBytes(beforeLines) + linesBytes(afterLines),
        releaseSnapshot: () => this.#releaseSnapshot(change),
        evict: () => this.#evict(change),
      },
    };
    after.bytes?.fill(0);
    // A change that can never be undone has no reason to keep its snapshot.
    if (view.undo === 'safe') change.retention.bytes += change.before.bytes?.byteLength ?? 0;
    else this.#releaseSnapshot(change);
    this.#changes.set(id, change);
    this.#retention.admit(change.retention);
    for (const oldest of this.#changes.values()) {
      if (this.#changes.size <= this.#retention.maxChangesPerSession) break;
      this.#evict(oldest);
    }
  }

  async list(): Promise<readonly AdapterChange[]> {
    const result: AdapterChange[] = [];
    for (const change of this.#changes.values()) {
      if (change.view.undo === 'safe') {
        const current = await snapshot(change.target);
        if (current.digest !== change.afterDigest) this.#revoke(change);
      }
      result.push(change.view);
    }
    return Object.freeze(result);
  }

  async undo(changeId: string, expectedSessionGeneration: number): Promise<AdapterChange> {
    const change = this.#changes.get(changeId);
    if (
      !change ||
      change.sessionGeneration !== expectedSessionGeneration ||
      change.view.undo !== 'safe' ||
      change.before.bytes === null
    ) {
      throw new Error('change-undo-revoked');
    }
    // Work on a private copy: the retention budget may release the stored
    // snapshot while this undo is still writing.
    const restore = Buffer.from(change.before.bytes);
    try {
      return await this.#restore(change, restore);
    } finally {
      restore.fill(0);
    }
  }

  async #restore(change: StoredChange, restore: Buffer): Promise<AdapterChange> {
    let handle: FileHandle;
    try {
      handle = await open(change.target, constants.O_RDWR | constants.O_NOFOLLOW);
    } catch (error) {
      this.#revoke(change);
      if (isNodeError(error) && (error.code === 'ENOENT' || error.code === 'ELOOP')) {
        throw new Error('change-undo-revoked', { cause: error });
      }
      throw error;
    }
    try {
      const current = await snapshotHandle(handle);
      if (current.bytes === null || current.digest !== change.afterDigest) {
        current.bytes?.fill(0);
        this.#revoke(change);
        throw new Error('change-undo-revoked');
      }
      try {
        await replaceHandleContents(handle, restore);
      } catch (writeError) {
        try {
          await replaceHandleContents(handle, current.bytes);
        } catch (rollbackError) {
          current.bytes.fill(0);
          this.#revoke(change);
          throw new Error('change-state-uncertain', {
            cause: new AggregateError([writeError, rollbackError], 'Undo and rollback failed'),
          });
        }
        current.bytes.fill(0);
        throw writeError;
      }
      current.bytes.fill(0);
    } finally {
      await handle.close();
    }
    this.#revoke(change);
    change.view = Object.freeze({ ...change.view, undo: 'complete' });
    return change.view;
  }

  target(changeId: string): Readonly<{
    workspaceId: string;
    workspaceRevision: number;
    privatePath: string;
  }> {
    const change = this.#changes.get(changeId);
    if (!change) throw new Error('change-unknown');
    return Object.freeze({
      workspaceId: change.workspaceId,
      workspaceRevision: change.workspaceRevision,
      privatePath: change.target,
    });
  }

  close(): void {
    for (const change of this.#changes.values()) {
      change.before.bytes?.fill(0);
      this.#retention.forget(change.retention);
    }
    this.#changes.clear();
  }

  /** Zeroes and drops the undo snapshot, making undo unavailable. */
  #releaseSnapshot(change: StoredChange): number {
    const bytes = change.before.bytes;
    if (bytes === null) return 0;
    const freed = change.view.undo === 'safe' ? bytes.byteLength : 0;
    bytes.fill(0);
    change.before = Object.freeze({ ...change.before, bytes: null });
    change.retention.bytes -= freed;
    if (change.view.undo === 'safe') {
      change.view = Object.freeze({ ...change.view, undo: 'revoked' });
    }
    return freed;
  }

  #revoke(change: StoredChange): void {
    this.#retention.released(change.retention, this.#releaseSnapshot(change));
  }

  #evict(change: StoredChange): void {
    this.#revoke(change);
    this.#retention.forget(change.retention);
    this.#changes.delete(change.view.id);
  }
}

function inside(root: string, target: string): boolean {
  const path = relative(root, target);
  return path !== '' && path !== '..' && !path.startsWith(`..${sep}`) && !isAbsolute(path);
}

async function canonicalTarget(workspacePath: string, path: string): Promise<string> {
  const candidate = isAbsolute(path) ? resolve(path) : resolve(workspacePath, path);
  try {
    return await realpath(candidate);
  } catch (error) {
    if (!isNodeError(error) || error.code !== 'ENOENT') throw error;
    const parent = await realpath(dirname(candidate));
    return join(parent, basename(candidate));
  }
}

async function snapshot(path: string): Promise<Snapshot> {
  let handle: FileHandle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    if (isNodeError(error) && error.code === 'ENOENT') {
      return Object.freeze({
        exists: false,
        bytes: Buffer.alloc(0),
        digest: 'absent',
        binary: false,
      });
    }
    if (isNodeError(error) && error.code === 'ELOOP') {
      return Object.freeze({
        exists: true,
        bytes: null,
        digest: 'symlink',
        binary: true,
      });
    }
    throw error;
  }
  try {
    return await snapshotHandle(handle);
  } finally {
    await handle.close();
  }
}

async function snapshotHandle(handle: FileHandle): Promise<Snapshot> {
  const before = await handle.stat();
  if (!before.isFile() || before.size > MAX_SNAPSHOT_BYTES) return opaqueSnapshot(before);
  const buffer = Buffer.alloc(MAX_SNAPSHOT_BYTES + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  const after = await handle.stat();
  if (
    offset > MAX_SNAPSHOT_BYTES ||
    before.dev !== after.dev ||
    before.ino !== after.ino ||
    before.size !== after.size ||
    before.mtimeMs !== after.mtimeMs
  ) {
    buffer.fill(0);
    return opaqueSnapshot(after);
  }
  const bytes = Buffer.from(buffer.subarray(0, offset));
  buffer.fill(0);
  return Object.freeze({
    exists: true,
    bytes,
    digest: createHash('sha256').update(bytes).digest('hex'),
    binary: bytes.includes(0),
  });
}

function opaqueSnapshot(metadata: {
  dev: number;
  ino: number;
  size: number;
  mtimeMs: number;
}): Snapshot {
  return Object.freeze({
    exists: true,
    bytes: null,
    digest: identityDigest(metadata),
    binary: true,
  });
}

async function replaceHandleContents(handle: FileHandle, bytes: Buffer): Promise<void> {
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, offset);
    if (bytesWritten === 0) throw new Error('change-write-stalled');
    offset += bytesWritten;
  }
  await handle.truncate(bytes.length);
  await handle.sync();
}

function linesBytes(lines: readonly string[]): number {
  let bytes = 0;
  for (const line of lines) bytes += line.length * 2;
  return bytes;
}

function displayLines(value: Snapshot): string[] {
  if (value.bytes === null || value.binary) return [];
  return value.bytes.toString('utf8').split('\n').slice(0, MAX_DIFF_LINES);
}

function countAdditions(before: readonly string[], after: readonly string[]): number {
  const remaining = new Map<string, number>();
  for (const line of before) remaining.set(line, (remaining.get(line) ?? 0) + 1);
  let additions = 0;
  for (const line of after) {
    const count = remaining.get(line) ?? 0;
    if (count > 0) remaining.set(line, count - 1);
    else additions += 1;
  }
  return additions;
}

function identityDigest(metadata: {
  dev: number;
  ino: number;
  size: number;
  mtimeMs: number;
}): string {
  return createHash('sha256')
    .update(`${metadata.dev}:${metadata.ino}:${metadata.size}:${metadata.mtimeMs}`, 'utf8')
    .digest('hex');
}

function isPendingObservation(value: unknown): value is PendingObservation {
  return Boolean(
    value &&
      typeof value === 'object' &&
      typeof (value as PendingObservation).sessionId === 'string' &&
      typeof (value as PendingObservation).target === 'string',
  );
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error;
}
