import { describe, expect, it } from 'vitest';
import { exportSessionPreview, mayTrashSession, searchSessions } from '../../sidecar/src/pi/session-admin';
import { mayRememberApproval, normaliseToolEvent } from '../../sidecar/src/pi/tools';

const session = Object.freeze({
  id: `session-${'a'.repeat(32)}`,
  generation: 2,
  title: 'Accessibility review',
  workspaceId: 'workspace-piui',
  writable: false,
  updatedAtUnixMs: 1,
  preview: 'Review the interface',
  messageCount: 3,
});

describe('tool and session administration projection', () => {
  it('classifies bounded tool activity and never remembers consequential approval', () => {
    const event = normaliseToolEvent({
      toolName: 'bash',
      verb: 'Running',
      target: 'pnpm test',
      evidence: 'local test',
    });
    expect(event.category).toBe('command');
    expect(mayRememberApproval(event.category, false, false)).toBe(false);
    expect(mayRememberApproval('file', true, false)).toBe(false);
    expect(mayRememberApproval('search', false, true)).toBe(false);
    expect(mayRememberApproval('search', false, false)).toBe(true);
  });

  it('keeps historical search/export isolated and requires exact trash identity', () => {
    expect(searchSessions([session], 'ACCESSIBILITY')).toEqual([session]);
    expect(searchSessions([session], 'other')).toEqual([]);
    expect(exportSessionPreview(session)).toEqual({
      schemaVersion: 1,
      id: session.id,
      title: session.title,
      workspaceId: session.workspaceId,
      branch: null,
      secretFieldsExcluded: true,
    });
    expect(mayTrashSession(session, session.id, 2)).toBe(true);
    expect(mayTrashSession(session, session.id, 1)).toBe(false);
  });
});
