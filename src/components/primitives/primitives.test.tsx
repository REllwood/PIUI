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

  it('does not open a live region inside buttons or existing status regions', () => {
    const { container } = render(
      <div role="status">
        <LoadingLabel>Checking PIUI…</LoadingLabel>
        <button type="button">
          <LoadingLabel>Saving…</LoadingLabel>
        </button>
      </div>,
    );
    expect(container.querySelectorAll('[role="status"], [aria-live]')).toHaveLength(1);
    expect(screen.getByRole('status').textContent).toContain('Checking PIUI…');
  });

  it('keeps status meaning in text as well as tone', () => {
    render(<StatusPill tone="danger">Failed</StatusPill>);
    expect(screen.getByText('Failed').getAttribute('data-tone')).toBe('danger');
  });
});
