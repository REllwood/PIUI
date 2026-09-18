import { Icon } from '../../components/icons/Icon';
import { StatusPill } from '../../components/primitives/StatusPill';
import type { UpdateState } from '../../domain/types';

export function UpdateStatus({ update }: Readonly<{ update: UpdateState }>) {
  const configured = update.endpointConfigured && update.publicKeyConfigured;
  return (
    <section className="update-status">
      <div className="feature-status-icon">
        <Icon name="download" />
      </div>
      <div>
        <div className="feature-status-heading">
          <h3>PIUI updates</h3>
          <StatusPill tone={configured ? 'success' : 'warning'}>
            {configured ? update.status : 'Disabled safely'}
          </StatusPill>
        </div>
        <p>{update.message}</p>
        <dl className="compact-facts">
          <div>
            <dt>HTTPS endpoint</dt>
            <dd>{update.endpointConfigured ? 'Configured' : 'Not configured'}</dd>
          </div>
          <div>
            <dt>Verification key</dt>
            <dd>{update.publicKeyConfigured ? 'Configured' : 'Not configured'}</dd>
          </div>
          <div>
            <dt>Automatic checks</dt>
            <dd>Off</dd>
          </div>
        </dl>
        <button type="button" className="button" disabled>
          <Icon name="refresh" />
          Check manually
        </button>
        <small className="disabled-reason-block">
          {configured
            ? 'The signed updater transport is not enabled in this build.'
            : 'Checking remains unavailable until both release prerequisites are configured.'}
        </small>
      </div>
    </section>
  );
}
