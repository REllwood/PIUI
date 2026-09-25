// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import type { ActivityEvent } from '../../domain/types';
import { WorkTrace } from './WorkTrace';

afterEach(cleanup);

describe('WorkTrace', () => {
  it('renders every state with textual evidence independent of colour', () => {
    const states: ActivityEvent['state'][] = [
      'running',
      'waiting',
      'complete',
      'failed',
      'cancelling',
      'too-late',
      'disconnected',
    ];
    const events = states.map(
      (state, index): ActivityEvent => ({
        id: `event-${index}`,
        category: state === 'failed' ? 'error' : 'command',
        verb: state,
        target: `target-${index}`,
        state,
        elapsed: `${index}s`,
        summary: `Summary for ${state}`,
      }),
    );
    render(<WorkTrace events={events} />);
    expect(screen.getAllByRole('listitem')).toHaveLength(states.length);
    for (const state of states) {
      expect(screen.getByText(`Summary for ${state}`)).toBeTruthy();
      expect(document.querySelector(`[data-state="${state}"]`)).toBeTruthy();
    }
  });

  it('marks the focal event, and names it the current step only while it is in progress', () => {
    const event = (id: string, state: ActivityEvent['state']): ActivityEvent => ({
      id,
      category: 'command',
      verb: 'Running',
      target: id,
      state,
      elapsed: '1s',
      summary: `Summary for ${id}`,
    });
    const { rerender } = render(
      <WorkTrace events={[event('a', 'complete'), event('b', 'waiting')]} focusId="b" />,
    );
    const items = () => screen.getAllByRole('listitem');
    expect(items()[1]?.getAttribute('data-focus')).toBe('true');
    expect(items()[1]?.getAttribute('aria-current')).toBe('step');
    expect(items()[0]?.hasAttribute('data-focus')).toBe(false);
    rerender(<WorkTrace events={[event('a', 'complete'), event('b', 'complete')]} focusId="b" />);
    expect(items()[1]?.getAttribute('data-focus')).toBe('true');
    expect(items()[1]?.hasAttribute('aria-current')).toBe(false);
  });
});
