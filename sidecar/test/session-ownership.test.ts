import { describe, expect, it } from 'vitest';
import { SessionOwnership } from '../src/pi/sessions.js';

const firstId = 'session-11111111111111111111111111111111';
const secondId = 'session-22222222222222222222222222222222';

describe('SessionOwnership transactions', () => {
  it('restores the previous writable session when create fails', () => {
    const sessions = new SessionOwnership();
    sessions.create(firstId, 'workspace', 'First');
    const mutation = sessions.beginCreate(secondId, 'workspace', 'Second');
    expect(mutation.session.writable).toBe(true);
    mutation.rollback();

    expect(sessions.get(firstId)?.writable).toBe(true);
    expect(sessions.get(secondId)).toBeUndefined();
  });

  it('restores the prior generation when resume fails', () => {
    const sessions = new SessionOwnership();
    sessions.register({
      id: firstId,
      generation: 3,
      title: 'First',
      workspaceId: 'workspace',
      writable: false,
      updatedAtUnixMs: 1,
      preview: '',
      messageCount: 0,
    });
    const mutation = sessions.beginResume(firstId, 3);
    expect(mutation.session.generation).toBe(4);
    mutation.rollback();

    expect(sessions.get(firstId)?.generation).toBe(3);
    expect(sessions.get(firstId)?.writable).toBe(false);
  });

  it('does not retain a failed branch or freeze its parent', () => {
    const sessions = new SessionOwnership();
    sessions.create(firstId, 'workspace', 'First');
    const mutation = sessions.beginForkAs(firstId, 1, secondId);
    mutation.rollback();

    expect(sessions.get(firstId)?.writable).toBe(true);
    expect(sessions.get(secondId)).toBeUndefined();
  });
});
