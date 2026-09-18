// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { LoadingLabel } from './LoadingLabel';
import { StatusPill } from './StatusPill';

afterEach(cleanup);

describe('shared primitives', () => {
  it('keeps the spinner decorative and loading copy available to the control name', () => {
    render(
      <button>
        <LoadingLabel>Saving…</LoadingLabel>
      </button>,
    );
    expect(screen.getByRole('button', { name: 'Saving…' })).toBeTruthy();
    expect(document.querySelector('.loading-spinner')?.getAttribute('aria-hidden')).toBe('true');
  });

  it('keeps status meaning in text as well as tone', () => {
    render(<StatusPill tone="danger">Failed</StatusPill>);
    expect(screen.getByText('Failed').getAttribute('data-tone')).toBe('danger');
  });
});
