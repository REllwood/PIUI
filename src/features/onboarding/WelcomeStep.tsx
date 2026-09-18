import { Icon } from '../../components/icons/Icon';

export function WelcomeStep() {
  return (
    <div className="onboarding-step onboarding-welcome">
      <div className="onboarding-copy">
        <p className="ui-label">Welcome to PIUI</p>
        <h1>A clear, local place to work with Pi.</h1>
        <p className="onboarding-lead">
          Choose a project, talk through the work and approve consequential actions without needing
          a terminal.
        </p>
        <ul className="privacy-list">
          <li>
            <Icon name="shield" />
            <span>
              <strong>Local by default</strong>
              <small>
                Your projects, settings and sessions stay on this Mac unless you choose a provider
                or integration.
              </small>
            </span>
          </li>
          <li>
            <Icon name="check" />
            <span>
              <strong>Decisions stay explicit</strong>
              <small>
                Project trust and tool approvals are separate. PIUI never assumes a consequential
                decision.
              </small>
            </span>
          </li>
          <li>
            <Icon name="conversation" />
            <span>
              <strong>Simple first</strong>
              <small>Technical controls remain available later in Settings.</small>
            </span>
          </li>
        </ul>
      </div>
      <div className="onboarding-preview" aria-label="PIUI workspace preview">
        <div className="preview-light-field" />
        <div className="preview-window">
          <span className="preview-navigation" />
          <span className="preview-conversation">
            <i />
            <i />
            <i />
          </span>
          <span className="preview-work">
            <b />
            <b />
            <b />
          </span>
        </div>
        <p>Your work stays visible while Pi thinks, asks and changes files.</p>
      </div>
    </div>
  );
}
