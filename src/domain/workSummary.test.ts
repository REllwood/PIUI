import { describe, expect, it } from 'vitest';
import type { ActivityEvent, ActivityState } from './types';
import { workSummaryLabel } from './workSummary';

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
