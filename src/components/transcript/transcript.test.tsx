// @vitest-environment jsdom

import { cleanup, render } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Message } from '../../domain/types';
import { prepareMarkdown } from '../../security/markdownPolicy';
import { StableMessageList } from './StableMessageList';

vi.mock('../../security/markdownPolicy', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../security/markdownPolicy')>();
  return { ...actual, prepareMarkdown: vi.fn(actual.prepareMarkdown) };
});

afterEach(cleanup);

function message(id: string, markdown: string): Message {
  return {
    id,
    role: 'assistant',
    author: 'Pi',
    timestamp: '9:00 am',
    markdown,
    status: 'stable',
  };
}

describe('stable transcript rendering', () => {
  it('only re-parses a message whose text changed', () => {
    const first = message('a', 'First answer.');
    const second = message('b', 'Second answer.');
    const { rerender } = render(<StableMessageList messages={[first, second]} accessible={false} />);
    const parses = vi.mocked(prepareMarkdown).mock.calls.length;

    // A poll or unrelated update hands over a new array holding the same messages.
    rerender(<StableMessageList messages={[first, second]} accessible={false} />);
    expect(vi.mocked(prepareMarkdown).mock.calls.length).toBe(parses);

    rerender(
      <StableMessageList
        messages={[first, message('b', 'Second answer, revised.')]}
        accessible={false}
      />,
    );
    expect(vi.mocked(prepareMarkdown).mock.calls.length).toBe(parses + 1);
  });
});
