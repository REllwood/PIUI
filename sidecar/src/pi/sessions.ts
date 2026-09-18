import type { AdapterSession } from './adapter.js';

type OwnedSession = AdapterSession & Readonly<{ updatedAt: number; parentId?: string }>;
type SessionMutation = Readonly<{
  session: AdapterSession;
  commit: () => void;
  rollback: () => void;
}>;

export class SessionOwnership {
  #sessions = new Map<string, OwnedSession>();
  #active: string | null = null;

  create(
    id: string,
    workspaceId: string,
    title = 'New conversation',
    details: Readonly<{
      updatedAtUnixMs?: number;
      preview?: string;
      messageCount?: number;
      branch?: string;
    }> = {},
  ): AdapterSession {
    if (!/^session-[a-f0-9]{32}$/u.test(id)) throw new Error('session-id-invalid');
    const session: OwnedSession = Object.freeze({
      id,
      generation: 1,
      title: title.slice(0, 160),
      workspaceId,
      writable: true,
      updatedAtUnixMs: details.updatedAtUnixMs ?? Date.now(),
      preview: (details.preview ?? 'Ready for your first message.').slice(0, 1_024),
      messageCount: details.messageCount ?? 0,
      ...(details.branch ? { branch: details.branch.slice(0, 160) } : {}),
      updatedAt: Date.now(),
    });
    this.#freezeActive();
    this.#sessions.set(id, session);
    this.#active = id;
    return session;
  }

  beginCreate(
    id: string,
    workspaceId: string,
    title?: string,
    details?: Readonly<{
      updatedAtUnixMs?: number;
      preview?: string;
      messageCount?: number;
      branch?: string;
    }>,
  ): SessionMutation {
    return this.#begin(() => this.create(id, workspaceId, title, details));
  }

  register(session: AdapterSession): AdapterSession {
    const existing = this.#sessions.get(session.id);
    if (existing) return existing;
    const record: OwnedSession = Object.freeze({
      ...session,
      writable: false,
      updatedAt: session.updatedAtUnixMs,
    });
    this.#sessions.set(record.id, record);
    return record;
  }

  resume(id: string, expectedGeneration: number): AdapterSession {
    const current = this.#require(id, expectedGeneration);
    this.#freezeActive();
    const resumed = Object.freeze({
      ...current,
      generation: current.generation + 1,
      writable: true,
      updatedAtUnixMs: Date.now(),
      updatedAt: Date.now(),
    });
    this.#sessions.set(id, resumed);
    this.#active = id;
    return resumed;
  }
  beginResume(id: string, expectedGeneration: number): SessionMutation {
    return this.#begin(() => this.resume(id, expectedGeneration));
  }

  forkAs(id: string, expectedGeneration: number, forkId: string): AdapterSession {
    if (!/^session-[a-f0-9]{32}$/u.test(forkId)) throw new Error('session-id-invalid');
    const parent = this.#require(id, expectedGeneration);
    this.#freezeActive();
    const fork = Object.freeze({
      ...parent,
      id: forkId,
      generation: 1,
      title: `${parent.title} — branch`,
      writable: true,
      branch: `branch-${forkId.slice(0, 6)}`,
      parentId: parent.id,
      updatedAtUnixMs: Date.now(),
      updatedAt: Date.now(),
    });
    this.#sessions.set(forkId, fork);
    this.#active = forkId;
    return fork;
  }
  beginForkAs(id: string, expectedGeneration: number, forkId: string): SessionMutation {
    return this.#begin(() => this.forkAs(id, expectedGeneration, forkId));
  }

  rename(id: string, expectedGeneration: number, title: string): AdapterSession {
    const current = this.#require(id, expectedGeneration);
    const next = Object.freeze({
      ...current,
      title: title.slice(0, 160),
      updatedAtUnixMs: Date.now(),
      updatedAt: Date.now(),
    });
    this.#sessions.set(id, next);
    return next;
  }

  get(id: string): AdapterSession | undefined {
    return this.#sessions.get(id);
  }
  remove(id: string): void {
    this.#sessions.delete(id);
    if (this.#active === id) this.#active = null;
  }
  list(): readonly AdapterSession[] {
    return Object.freeze(
      [...this.#sessions.values()].sort((left, right) => right.updatedAt - left.updatedAt),
    );
  }
  reconcileInactive(workspaceId: string, listedIds: ReadonlySet<string>): void {
    for (const session of this.#sessions.values()) {
      if (session.workspaceId === workspaceId && !session.writable && !listedIds.has(session.id)) {
        this.remove(session.id);
      }
    }
  }
  close(): void {
    this.#freezeActive();
    this.#active = null;
  }

  #require(id: string, generation: number): OwnedSession {
    const session = this.#sessions.get(id);
    if (!session || session.generation !== generation) throw new Error('session-generation-stale');
    return session;
  }

  #freezeActive(): void {
    if (!this.#active) return;
    const active = this.#sessions.get(this.#active);
    if (active) this.#sessions.set(active.id, Object.freeze({ ...active, writable: false }));
  }
  #begin(mutate: () => AdapterSession): SessionMutation {
    const priorSessions = new Map(this.#sessions);
    const priorActive = this.#active;
    const session = mutate();
    let settled = false;
    return Object.freeze({
      session,
      commit: () => {
        settled = true;
      },
      rollback: () => {
        if (settled) return;
        this.#sessions = new Map(priorSessions);
        this.#active = priorActive;
        settled = true;
      },
    });
  }
}
