import { useEffect, useRef } from 'react';
import type { ActivityEvent } from '../../domain/types';
import { isActivityInProgress } from '../../domain/workSummary';
import { Icon } from '../icons/Icon';
import './work-trace.css';

const iconByCategory = {
  file: 'file',
  command: 'command',
  search: 'search',
  extension: 'shield',
  subagent: 'branch',
  error: 'warning',
} as const;

// Scrolls the nearest scrolling ancestor just enough to show the item, honouring that
// container's scroll padding so a sticky heading never covers it. Only that container
// moves: the rest of the window stays where the person left it.
function revealWithinScroller(item: HTMLElement) {
  let scroller = item.parentElement;
  while (scroller) {
    const { overflowY } = getComputedStyle(scroller);
    if (/auto|scroll/u.test(overflowY) && scroller.scrollHeight > scroller.clientHeight) break;
    scroller = scroller.parentElement;
  }
  if (!scroller) return;
  const style = getComputedStyle(scroller);
  const bounds = scroller.getBoundingClientRect();
  const top = bounds.top + (Number.parseFloat(style.scrollPaddingTop) || 0);
  const bottom = bounds.bottom - (Number.parseFloat(style.scrollPaddingBottom) || 0);
  const rect = item.getBoundingClientRect();
  if (rect.bottom > bottom) scroller.scrollTop += Math.min(rect.bottom - bottom, rect.top - top);
  else if (rect.top < top) scroller.scrollTop -= top - rect.top;
}

export function WorkTrace({
  events,
  focusId = null,
  onSelect,
}: Readonly<{
  events: readonly ActivityEvent[];
  // The event to keep in view, such as the one waiting on the person or still running.
  focusId?: string | null;
  onSelect?: (event: ActivityEvent) => void;
}>) {
  const list = useRef<HTMLOListElement>(null);
  const focused = events.find((event) => event.id === focusId);
  const focusKey = focused ? `${focused.id}:${focused.state}` : null;
  // Follow the focal event only when it changes, so reading back through a longer trace is
  // not interrupted by unrelated updates.
  useEffect(() => {
    if (!focusKey) return;
    const item = list.current?.querySelector<HTMLElement>('[data-focus="true"]');
    if (item) revealWithinScroller(item);
  }, [focusKey]);
  return (
    <ol ref={list} className="work-trace" aria-label="Current work">
      {events.map((event) => {
        const isFocus = event.id === focusId;
        return (
          <li
            key={event.id}
            className="work-trace__item"
            data-state={event.state}
            data-focus={isFocus || undefined}
            aria-current={isFocus && isActivityInProgress(event.state) ? 'step' : undefined}
          >
            <span className="work-trace__line" aria-hidden="true" />
            <span className="work-trace__node" aria-hidden="true" />
            <button type="button" className="work-trace__button" onClick={() => onSelect?.(event)}>
              <span className="work-trace__icon">
                <Icon name={iconByCategory[event.category]} />
              </span>
              <span className="work-trace__copy">
                <strong>
                  {event.verb} <span>{event.target}</span>
                </strong>
                <span>{event.summary}</span>
              </span>
              <span className="work-trace__elapsed ui-mono">{event.elapsed}</span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}
