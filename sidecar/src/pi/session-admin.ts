import type { AdapterSession } from './adapter.js';

export function searchSessions(
  sessions: readonly AdapterSession[],
  query: string,
): readonly AdapterSession[] {
  const needle = query.trim().toLocaleLowerCase('en-AU');
  if (!needle) return sessions;
  return sessions.filter((session) =>
    `${session.title} ${session.workspaceId} ${session.branch ?? ''}`
      .toLocaleLowerCase('en-AU')
      .includes(needle),
  );
}

export function exportSessionPreview(session: AdapterSession): Readonly<Record<string, unknown>> {
  return Object.freeze({
    schemaVersion: 1,
    id: session.id,
    title: session.title,
    workspaceId: session.workspaceId,
    branch: session.branch ?? null,
    secretFieldsExcluded: true,
  });
}

export function mayTrashSession(
  session: AdapterSession,
  selectedId: string,
  expectedGeneration: number,
): boolean {
  return (
    session.id === selectedId && session.generation === expectedGeneration && !session.writable
  );
}
