import type { ActivityEvent } from '../../domain/types';
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

export function WorkTrace({
  events,
  onSelect,
}: Readonly<{
  events: readonly ActivityEvent[];
  onSelect?: (event: ActivityEvent) => void;
}>) {
  return (
    <ol className="work-trace" aria-label="Current work">
      {events.map((event) => (
        <li key={event.id} className="work-trace__item" data-state={event.state}>
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
      ))}
    </ol>
  );
}
