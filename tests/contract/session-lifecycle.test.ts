import { describe, expect, it } from 'vitest';
import { SessionOwnership } from '../../sidecar/src/pi/sessions';

const firstId = `session-${'a'.repeat(32)}`;
const secondId = `session-${'b'.repeat(32)}`;
const branchId = `session-${'c'.repeat(32)}`;

describe('session ownership', () => {
  it('keeps exactly one writer through create, resume and fork', () => {
    const ownership = new SessionOwnership();
    const first = ownership.create(firstId, 'workspace-1', 'First');
    expect(first.writable).toBe(true);
    const second = ownership.create(secondId, 'workspace-1', 'Second');
    expect(second.writable).toBe(true);
    expect(ownership.get(firstId)?.writable).toBe(false);
    const resumed = ownership.resume(firstId, 1);
    expect(resumed.generation).toBe(2);
    expect(ownership.get(secondId)?.writable).toBe(false);
    const branch = ownership.forkAs(firstId, 2, branchId);
    expect(branch.writable).toBe(true);
    expect(branch.branch).toBeTruthy();
    expect(ownership.get(firstId)?.writable).toBe(false);
    expect(() => ownership.resume(firstId, 1)).toThrow('session-generation-stale');
  });

  it('rolls back unacknowledged mutations without changing the prior writer', () => {
    const ownership = new SessionOwnership();
    ownership.create(firstId, 'workspace-1', 'First');
    const pending = ownership.beginCreate(secondId, 'workspace-1', 'Second');
    expect(pending.session.writable).toBe(true);
    pending.rollback();
    expect(ownership.get(secondId)).toBeUndefined();
    expect(ownership.get(firstId)?.writable).toBe(true);
  });
});
