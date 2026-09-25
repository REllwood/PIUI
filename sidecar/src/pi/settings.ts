import { constants } from 'node:fs';
import { lstat, mkdir, open, readFile, rename } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { PublicAgentSession } from './public-sdk.js';

export type ThinkingLevel = PublicAgentSession['thinkingLevel'];

// Every level Pi 0.82 accepts. Keyed by Pi's own type so a level added to or
// removed from Pi fails the build here. Pi, not PIUI, clamps a chosen level to
// what the session's current model supports.
const THINKING_LEVELS: Readonly<Record<ThinkingLevel, true>> = Object.freeze({
  off: true,
  minimal: true,
  low: true,
  medium: true,
  high: true,
  xhigh: true,
  max: true,
});

export function isThinkingLevel(value: unknown): value is ThinkingLevel {
  return typeof value === 'string' && Object.hasOwn(THINKING_LEVELS, value);
}

export type SettingScope = 'global' | 'project';
export type SettingRecord = Readonly<{
  key: string;
  value: unknown;
  scope: SettingScope;
  revision: number;
  origin: string;
}>;

type StoredEntry = Readonly<{ value: unknown; revision: number }>;
type StoredState = Readonly<{
  version: 1;
  revision: number;
  values: Readonly<Record<string, StoredEntry>>;
}>;

const EMPTY_STATE: StoredState = Object.freeze({
  version: 1,
  revision: 0,
  values: Object.freeze({}),
});

export class TypedSettingsAdapter {
  readonly #paths: Readonly<Record<SettingScope, string>>;
  readonly #states = new Map<SettingScope, StoredState>();
  readonly #values = new Map<string, SettingRecord>();

  private constructor(workspacePath: string, agentDir: string) {
    this.#paths = Object.freeze({
      global: join(agentDir, 'piui-settings.json'),
      project: join(workspacePath, '.pi', 'piui-settings.json'),
    });
  }

  static async create(workspacePath: string, agentDir: string): Promise<TypedSettingsAdapter> {
    const adapter = new TypedSettingsAdapter(workspacePath, agentDir);
    adapter.#states.set('global', await readStoredState(adapter.#paths.global));
    adapter.#states.set('project', await readStoredState(adapter.#paths.project));
    return adapter;
  }

  read(key: string): SettingRecord | undefined {
    return this.#values.get(key);
  }

  list(): readonly SettingRecord[] {
    return Object.freeze(
      [...this.#values.values()].sort((left, right) => left.key.localeCompare(right.key, 'en-AU')),
    );
  }

  seed(key: string, value: unknown, scope: SettingScope, origin: string): SettingRecord {
    const existing = this.#values.get(key);
    if (existing) return existing;
    assertSettingKey(key);
    if (origin.length > 160) throw new Error('setting-origin-invalid');
    const project = this.#states.get('project')?.values[key];
    const global = this.#states.get('global')?.values[key];
    const stored = project ?? global;
    const storedScope: SettingScope = project ? 'project' : global ? 'global' : scope;
    const nextValue = stored ? stored.value : value;
    assertSettingValue(key, nextValue);
    const record = Object.freeze({
      key,
      value: cloneJson(nextValue),
      scope: storedScope,
      revision: stored?.revision ?? 0,
      origin: stored
        ? storedScope === 'project'
          ? 'PIUI project setting'
          : 'PIUI global setting'
        : origin,
    });
    this.#values.set(key, record);
    return record;
  }

  assertRevision(key: string, expectedRevision: number): void {
    if ((this.#values.get(key)?.revision ?? 0) !== expectedRevision) {
      throw new Error('setting-save-conflict');
    }
  }

  async save(
    key: string,
    value: unknown,
    scope: SettingScope,
    expectedRevision: number,
  ): Promise<SettingRecord> {
    assertSettingKey(key);
    assertSettingValue(key, value);
    this.assertRevision(key, expectedRevision);
    const encodedValue = JSON.stringify(value);
    if (encodedValue === undefined || encodedValue.length > 16_384) {
      throw new Error('setting-value-too-large');
    }
    const currentState = await readStoredState(this.#paths[scope]);
    const currentEntry = currentState.values[key];
    const expectedRecord = this.#values.get(key);
    if (
      (currentEntry?.revision ?? 0) !==
        (expectedRecord?.scope === scope ? expectedRecord.revision : 0) ||
      (currentEntry && expectedRecord?.scope === scope && !sameJson(currentEntry.value, expectedRecord.value))
    ) {
      throw new Error('setting-save-conflict');
    }
    const revision = currentState.revision + 1;
    if (!Number.isSafeInteger(revision)) throw new Error('setting-revision-exhausted');
    const nextState: StoredState = Object.freeze({
      version: 1,
      revision,
      values: Object.freeze({
        ...currentState.values,
        [key]: Object.freeze({ value: cloneJson(value), revision }),
      }),
    });
    await writeStoredState(this.#paths[scope], nextState);
    this.#states.set(scope, nextState);
    const next = Object.freeze({
      key,
      value: cloneJson(value),
      scope,
      revision,
      origin: scope === 'project' ? 'PIUI project setting' : 'PIUI global setting',
    });
    this.#values.set(key, next);
    return next;
  }

  previewReset(key: string): Readonly<{ key: string; current: unknown; next: null }> {
    return Object.freeze({ key, current: this.#values.get(key)?.value, next: null });
  }
}

async function readStoredState(path: string): Promise<StoredState> {
  let bytes: Buffer;
  try {
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 1_048_576) {
      throw new Error('setting-storage-invalid');
    }
    bytes = await readFile(path);
  } catch (error) {
    if (isMissing(error)) return EMPTY_STATE;
    throw error instanceof Error && error.message === 'setting-storage-invalid'
      ? error
      : new Error('setting-storage-unavailable');
  }
  try {
    const parsed: unknown = JSON.parse(bytes.toString('utf8'));
    if (!isRecord(parsed) || parsed.version !== 1 || !Number.isSafeInteger(parsed.revision)) {
      throw new Error('setting-storage-invalid');
    }
    const values = parsed.values;
    if (!isRecord(values) || Object.keys(values).length > 128) {
      throw new Error('setting-storage-invalid');
    }
    const checked: Record<string, StoredEntry> = {};
    for (const [key, entry] of Object.entries(values)) {
      assertSettingKey(key);
      if (
        !isRecord(entry) ||
        !Number.isSafeInteger(entry.revision) ||
        (entry.revision as number) <= 0 ||
        (entry.revision as number) > (parsed.revision as number)
      ) {
        throw new Error('setting-storage-invalid');
      }
      assertSettingValue(key, entry.value);
      checked[key] = Object.freeze({
        value: cloneJson(entry.value),
        revision: entry.revision as number,
      });
    }
    return Object.freeze({
      version: 1,
      revision: parsed.revision as number,
      values: Object.freeze(checked),
    });
  } catch (error) {
    throw error instanceof Error && error.message.startsWith('setting-')
      ? error
      : new Error('setting-storage-invalid');
  } finally {
    bytes.fill(0);
  }
}

async function writeStoredState(path: string, state: StoredState): Promise<void> {
  const directory = dirname(path);
  let directoryMetadata = await lstat(directory).catch((error: unknown) => {
    if (isMissing(error)) return null;
    throw new Error('setting-storage-unavailable');
  });
  if (!directoryMetadata) {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    directoryMetadata = await lstat(directory);
  }
  if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) {
    throw new Error('setting-storage-invalid');
  }
  const existing = await lstat(path).catch((error: unknown) => {
    if (isMissing(error)) return null;
    throw new Error('setting-storage-unavailable');
  });
  if (existing && (!existing.isFile() || existing.isSymbolicLink())) {
    throw new Error('setting-storage-invalid');
  }
  const temporary = join(directory, `.piui-settings-${randomUUID()}.tmp`);
  const handle = await open(
    temporary,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    await handle.writeFile(`${JSON.stringify(state, null, 2)}\n`, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporary, path);
  const directoryHandle = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    await directoryHandle.sync();
  } finally {
    await directoryHandle.close();
  }
}

function assertSettingKey(key: string): void {
  if (!/^[a-z][a-z0-9.-]{0,127}$/u.test(key)) throw new Error('setting-key-invalid');
}

function assertSettingValue(key: string, value: unknown): void {
  switch (key) {
    case 'model.provider':
      if (value !== null && (typeof value !== 'string' || value.length > 128))
        throw new Error('setting-value-invalid');
      return;
    case 'model.id':
      if (value !== null && (typeof value !== 'string' || value.length > 256))
        throw new Error('setting-value-invalid');
      return;
    case 'reasoning.level':
      if (!isThinkingLevel(value)) throw new Error('setting-value-invalid');
      return;
    case 'tools.active':
      if (
        !Array.isArray(value) ||
        value.length > 64 ||
        !value.every((item) => typeof item === 'string' && /^[A-Za-z0-9._:-]{1,128}$/u.test(item))
      )
        throw new Error('setting-value-invalid');
      return;
    case 'compaction.enabled':
    case 'retry.enabled':
      if (typeof value !== 'boolean') throw new Error('setting-value-invalid');
      return;
    case 'queue.follow-up-mode':
      if (value !== 'all' && value !== 'one-at-a-time') throw new Error('setting-value-invalid');
      return;
    default:
      throw new Error('setting-key-unsupported');
  }
}

function cloneJson(value: unknown): unknown {
  if (value === undefined) return null;
  return JSON.parse(JSON.stringify(value)) as unknown;
}

function sameJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function isMissing(error: unknown): boolean {
  return isRecord(error) && error.code === 'ENOENT';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
