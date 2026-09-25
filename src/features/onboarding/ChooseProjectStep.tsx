import { Icon } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { StatusPill } from '../../components/primitives/StatusPill';

export function ChooseProjectStep({
  project,
  busy,
  error = null,
  onChoose,
  onTrust,
}: Readonly<{
  project: Readonly<{
    id: string;
    name: string;
    revision: number;
    trust: 'untrusted' | 'trusted' | 'revoked';
  }> | null;
  busy: boolean;
  error?: string | null;
  onChoose: () => Promise<void>;
  onTrust: () => Promise<void>;
}>) {
  return (
    <div className="onboarding-step onboarding-project">
      <div className="onboarding-copy">
        <p className="ui-label">Choose a project</p>
        <h1>Select the folder where Pi will work.</h1>
        <p className="onboarding-lead">
          PIUI receives an opaque folder capability from macOS. Choosing a folder does not run its
          extensions or grant tool approval.
        </p>
        <button
          type="button"
          className="button button--primary"
          onClick={() => void onChoose()}
          disabled={busy}
        >
          {busy ? (
            <LoadingLabel>Waiting for folder selection…</LoadingLabel>
          ) : (
            <>
              <Icon name="folder" />
              Choose project folder
            </>
          )}
        </button>
        {error ? (
          <div className="inline-notice" data-tone="warning" role="alert">
            {error}
          </div>
        ) : null}
      </div>
      <section className="project-preview">
        {project ? (
          <>
            <div className="project-preview__header">
              <span>
                <Icon name="folder" />
              </span>
              <div>
                <h2>{project.name}</h2>
                <p>Selected local folder · capability {project.id.slice(0, 18)}…</p>
              </div>
              <StatusPill tone={project.trust === 'trusted' ? 'success' : 'warning'}>
                {project.trust === 'trusted' ? 'Trusted' : 'Untrusted'}
              </StatusPill>
            </div>
            <div className="trust-choices">
              <article>
                <Icon name="shield" />
                <h3>Open untrusted</h3>
                <p>Chat and inspect metadata without loading executable project resources.</p>
                <StatusPill tone={project.trust === 'untrusted' ? 'warning' : 'neutral'}>
                  {project.trust === 'untrusted' ? 'Opened untrusted' : 'Untrusted mode available'}
                </StatusPill>
              </article>
              <article data-recommended="true">
                <Icon name="check" />
                <h3>Trust and open</h3>
                <p>
                  Allow explicitly discovered project resources to load. You can revoke trust later.
                </p>
                <button
                  type="button"
                  className="button button--primary"
                  onClick={() => void onTrust()}
                  disabled={busy || project.trust === 'trusted'}
                >
                  {busy ? (
                    <LoadingLabel>Applying trust…</LoadingLabel>
                  ) : project.trust === 'trusted' ? (
                    <>
                      <Icon name="check" />
                      Trusted and ready
                    </>
                  ) : (
                    'Trust and open'
                  )}
                </button>
              </article>
            </div>
            <p className="trust-disclaimer">
              Trust does not change the approval policy. Executable extensions may act outside
              PIUI-mediated approvals.
            </p>
          </>
        ) : (
          <div className="empty-state">
            <Icon name="folder" />
            <h2>No project selected</h2>
            <p>
              The macOS folder picker will show the location. Raw local paths are not sent to this
              screen.
            </p>
          </div>
        )}
      </section>
    </div>
  );
}
