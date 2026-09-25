// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { BrandMark } from './BrandMark';

afterEach(cleanup);

describe('brand mark', () => {
  it('stays decorative beside visible product text', () => {
    const { container } = render(
      <header>
        <BrandMark />
        <strong>PIUI</strong>
      </header>,
    );
    const mark = container.querySelector('svg.brand-mark');
    expect(mark?.getAttribute('aria-hidden')).toBe('true');
    expect(mark?.getAttribute('focusable')).toBe('false');
    expect(mark?.getAttribute('role')).toBeNull();
    expect(mark?.getAttribute('width')).toBe('34');
  });

  it('names the product where it stands alone', () => {
    render(<BrandMark size={54} label="PIUI" />);
    const mark = screen.getByRole('img', { name: 'PIUI' });
    expect(mark.getAttribute('aria-hidden')).toBeNull();
    expect(mark.getAttribute('height')).toBe('54');
  });

  it('keeps paint servers unique so several marks can share a page', () => {
    const { container } = render(
      <>
        <BrandMark />
        <BrandMark size={54} />
      </>,
    );
    const ids = Array.from(container.querySelectorAll('[id]'), (element) => element.id);
    expect(ids).toHaveLength(12);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^piui-mark-[A-Za-z0-9_-]+$/u);
    const references = Array.from(
      container.querySelectorAll('[fill^="url("], [stroke^="url("], [filter^="url("]'),
      (element) =>
        ['fill', 'stroke', 'filter']
          .map((name) => element.getAttribute(name))
          .find((value) => value?.startsWith('url(')),
    );
    for (const reference of references) {
      expect(ids).toContain(reference?.slice('url(#'.length, -1));
    }
  });

  it('carries no inline style attributes, which the content security policy blocks', () => {
    const { container } = render(<BrandMark />);
    expect(container.querySelectorAll('[style]')).toHaveLength(0);
  });
});
