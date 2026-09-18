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
});
