import { useState } from 'react';
import { Icon, type IconName } from '../../components/icons/Icon';

const pages: readonly Readonly<{
  title: string;
  detail: string;
  icon: IconName;
}>[] = [
  {
    title: 'Ask in plain language',
    detail: 'Describe the outcome you need. The active project and model remain visible beside the composer.',
    icon: 'conversation',
  },
  {
    title: 'Follow the work trace',
    detail: 'Streaming output, tool activity and queued follow-ups use distinct acknowledged states.',
    icon: 'activity',
  },
  {
    title: 'Review consequential work',
    detail: 'Approvals show the exact action and target. Project trust never becomes a blanket tool approval.',
    icon: 'shield',
  },
];

export function ProductTour({ onSkip }: Readonly<{ onSkip: () => void }>) {
  const [page, setPage] = useState(0);
  const current = pages[page] ?? pages[0];
  return (
    <section className="ready-preview" aria-labelledby="product-tour-title">
      <div className="ready-orb" aria-hidden="true" />
      <Icon name={current.icon} />
      <p className="ui-label">Product tour · {page + 1} of {pages.length}</p>
      <h2 id="product-tour-title">{current.title}</h2>
      <p>{current.detail}</p>
      <div className="tour-points" aria-hidden="true">
        {pages.map((item, index) => (
          <span key={item.title} data-active={index === page}>
            <b>{index + 1}</b>{item.title}
          </span>
        ))}
      </div>
      <div className="choice-card__actions">
        <button type="button" className="button button--quiet" onClick={onSkip}>
          Skip tour
        </button>
        {page > 0 ? (
          <button type="button" className="button" onClick={() => setPage((value) => value - 1)}>
            Back
          </button>
        ) : null}
        {page < pages.length - 1 ? (
          <button
            type="button"
            className="button button--primary"
            onClick={() => setPage((value) => value + 1)}
          >
            Next
          </button>
        ) : (
          <button type="button" className="button button--primary" onClick={onSkip}>
            Tour complete
          </button>
        )}
      </div>
    </section>
  );
}
