import { describe, expect, it } from 'vitest';
import type { ActivityEvent, ActivityState } from './types';
import { focalActivityId, workSummaryLabel } from './workSummary';

function event(id: string, state: ActivityState): ActivityEvent {
  return {
    id,
    category: 'command',
    verb: 'Running',
    target: 'bash',
    state,
    elapsed: '—',
    summary: 'Pi is using this tool.',
  };
}

describe('work summary', () => {
  it('counts a started tool as running rather than complete', () => {
    expect(workSummaryLabel([event('a', 'running')], false, 'tool-running')).toBe('1 running');
    expect(workSummaryLabel([event('a', 'waiting')], false, 'tool-running')).toBe('1 running');
  });

  it('puts a pending approval first', () => {
    expect(workSummaryLabel([event('a', 'running')], true, 'tool-running')).toBe(
      'Waiting for your approval',
    );
  });

  it('does not report completion while the turn is still active', () => {
    expect(workSummaryLabel([event('a', 'complete')], false, 'streaming')).toBe('Pi is working');
  });

  it('reports completion once every tool and the turn have settled', () => {
    expect(
      workSummaryLabel([event('a', 'complete'), event('b', 'failed')], false, 'complete'),
    ).toBe('Work complete');
  });
});

describe('focal work event', () => {
  it('prefers the latest event that is waiting on the person', () => {
    expect(
      focalActivityId([event('a', 'waiting'), event('b', 'running'), event('c', 'waiting')]),
    ).toBe('c');
    expect(
      focalActivityId([event('a', 'complete'), event('b', 'waiting'), event('c', 'running')]),
    ).toBe('b');
  });

  it('otherwise follows the latest event still in progress', () => {
    expect(
      focalActivityId([event('a', 'running'), event('b', 'cancelling'), event('c', 'complete')]),
    ).toBe('b');
  });

  it('falls back to the latest event, or nothing when there is no work', () => {
    expect(focalActivityId([event('a', 'complete'), event('b', 'failed')])).toBe('b');
    expect(focalActivityId([])).toBeNull();
  });
});
