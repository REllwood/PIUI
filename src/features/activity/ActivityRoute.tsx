import { useMemo, useState } from 'react';
import { useProduct } from '../../app/ProductContext';
import { Icon } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { StatusPill } from '../../components/primitives/StatusPill';
import { WorkTrace } from '../../components/work-trace/WorkTrace';
import { redactForDisplay } from '../../domain/errors';
import { ActivityDetail } from './ActivityDetail';
import './supporting-routes.css';

export function ActivityRoute() {
  const product = useProduct();
  const { snapshot } = product;
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<'all' | 'running' | 'attention' | 'complete'>('all');
  const [showRaw, setShowRaw] = useState(false);
  const [copying, setCopying] = useState(false);
  const events = useMemo(
    () =>
      snapshot.activity.filter((event) => {
        const matchesQuery = `${event.verb} ${event.target} ${event.summary}`
          .toLowerCase()
          .includes(query.toLowerCase());
        const matchesFilter =
          filter === 'all' ||
          (filter === 'attention'
            ? ['waiting', 'failed', 'disconnected'].includes(event.state)
            : filter === 'complete'
              ? event.state === 'complete'
              : event.state === 'running');
        return matchesQuery && matchesFilter;
      }),
    [filter, query, snapshot.activity],
  );
  const selected = product.selectedActivity ?? events[0] ?? null;

  const copySafeJson = async () => {
    if (copying) return;
    setCopying(true);
    const safe = redactForDisplay(JSON.stringify(selected, null, 2));
    try {
      await navigator.clipboard.writeText(safe);
    } catch {
      // Every clipboard refusal is reported the same way. Re-throwing here only produced an
      // unhandled rejection, because the button invokes this without awaiting the result.
      window.dispatchEvent(new CustomEvent('piui:copy-unavailable'));
    } finally {
      setCopying(false);
    }
  };

  return (
    <main className="supporting-route activity-route" aria-labelledby="activity-title">
      <header className="route-heading">
        <div>
          <p className="ui-label">Redacted local evidence</p>
          <h1 id="activity-title">Activity</h1>
          <p>See what Pi is doing, what finished and what needs your attention.</p>
        </div>
        <StatusPill tone={snapshot.connection === 'ready' ? 'success' : 'warning'}>
          {snapshot.connection}
        </StatusPill>
      </header>
      <div className="supporting-route__stage">
        <section className="route-list-plane" aria-label="Activity ledger">
          <label className="search-field">
            <Icon name="search" />
            <span className="sr-only">Search activity</span>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search actions and targets"
            />
          </label>
          <div className="filter-row" aria-label="Activity filters">
            {(['all', 'running', 'attention', 'complete'] as const).map((item) => (
              <button
                key={item}
                type="button"
                className="filter-chip"
                aria-pressed={filter === item}
                onClick={() => setFilter(item)}
              >
                {item}
              </button>
            ))}
          </div>
          {events.length > 0 ? (
            <WorkTrace events={events} onSelect={product.setSelectedActivity} />
          ) : (
            <div className="empty-state">
              <Icon name="activity" />
              <h2>No matching activity</h2>
              <p>Completed work remains available even when PIUI is offline.</p>
            </div>
          )}
        </section>
        <section className="route-detail-plane" aria-label="Activity evidence">
          {selected ? (
            <>
              <ActivityDetail event={selected} onCancel={product.stop} />
              <div className="raw-event">
                <button
                  type="button"
                  className="raw-event__toggle"
                  aria-expanded={showRaw}
                  onClick={() => setShowRaw((current) => !current)}
                >
                  <Icon name={showRaw ? 'chevron-down' : 'chevron-right'} />
                  Redacted event details
                </button>
                {showRaw ? (
                  <>
                    <pre tabIndex={0}>{redactForDisplay(JSON.stringify(selected, null, 2))}</pre>
                    <button
                      type="button"
                      className="button"
                      onClick={() => void copySafeJson()}
                      disabled={copying}
                    >
                      {copying ? (
                        <LoadingLabel>Copying…</LoadingLabel>
                      ) : (
                        <>
                          <Icon name="copy" />
                          Copy safe JSON
                        </>
                      )}
                    </button>
                  </>
                ) : null}
              </div>
            </>
          ) : (
            <div className="empty-state">
              <Icon name="activity" />
              <h2>Select an activity item</h2>
              <p>Bounded, redacted evidence will appear here.</p>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}
