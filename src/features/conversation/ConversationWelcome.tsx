import { useState } from 'react';
import { useProduct } from '../../app/ProductContext';
import { Icon, type IconName } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { useComposerDraft } from '../composer/ComposerDrafts';

const starters: readonly { title: string; description: string; icon: IconName; prompt: string }[] =
  [
    {
      title: 'Get to know this project',
      description: 'Find your way around the code',
      icon: 'folder',
      prompt:
        'Help me understand this project. Explain what it does, how it is organised, and where I should start.',
    },
    {
      title: 'Make something new',
      description: 'Turn an idea into a working feature',
      icon: 'plus',
      prompt:
        'I would like to build a new feature in this project. Help me work through the idea and plan the changes. Here is what I have in mind: ',
    },
    {
      title: 'Work through a problem',
      description: 'Find the cause and a way forward',
      icon: 'search',
      prompt:
        'Help me investigate a problem in this project. Explain the cause before making changes. Here is what is happening: ',
    },
    {
      title: 'Review and refine',
      description: 'Find thoughtful ways to improve',
      icon: 'check',
      prompt:
        'Review this project for bugs and opportunities to improve the experience. Explain the most useful changes and help me prioritise them.',
    },
  ];

export function ConversationWelcome({ draftKey }: Readonly<{ draftKey: string }>) {
  const product = useProduct();
  const { draft, setText } = useComposerDraft(draftKey);
  const [error, setError] = useState<string | null>(null);
  const workspace = product.snapshot.workspace;
  const connected = product.snapshot.providers.some(
    (provider) => provider.connected && provider.models.length > 0,
  );
  const hasSession = product.snapshot.sessions.some((session) => session.id === product.snapshot.activeSessionId);
  const ready = workspace?.trust === 'trusted' && connected && hasSession;
  const busy = product.activeOperation !== null;
  const nextStep = !workspace
    ? 'Choose a project'
    : workspace.trust !== 'trusted'
      ? 'Review project access'
      : !connected
        ? 'Connect a model provider'
        : 'Start a conversation';
  const prepare = async () => {
    setError(null);
    try {
      if (!workspace) await product.chooseProject();
      else if (workspace.trust !== 'trusted') product.openSettings('projects');
      else if (!connected) product.openSettings('providers');
      else if (!(await product.createSession()))
        setError(
          'The conversation could not be started. Check your project and provider, then try again.',
        );
    } catch {
      setError('That step could not be completed. Please try again.');
    }
  };
  const insert = (prompt: string) => {
    setText((current) => (current.trim() ? `${current}\n\n${prompt}` : prompt));
    document.querySelector<HTMLTextAreaElement>('#piui-composer')?.focus();
  };

  return (
    <div className="conversation-welcome" tabIndex={0} aria-label="Get started with Pi">
      <div className="conversation-welcome__content">
        <div className="welcome-signature" aria-hidden="true">
          <span>π</span>
          <i />
          <span className="welcome-signature__line" />
        </div>
        <p className="welcome-eyebrow">
          {workspace ? `A little help with ${workspace.name}` : 'A little space for your next idea'}
        </p>
        <h1>
          What would you like
          <br />
          to make possible?
        </h1>
        <p className="welcome-description">
          Build something new, untangle a problem, or explore your project. Start with a
          conversation.
        </p>
        {!ready ? (
          <div className="welcome-setup">
            <div>
              <strong>{nextStep}</strong>
              <p>
                {!workspace
                  ? 'Pick the folder you want Pi to work with.'
                  : workspace.trust !== 'trusted'
                    ? 'Decide whether to allow Pi to work with this folder.'
                    : !connected
                      ? 'Use your existing subscription or an API key.'
                      : 'Your project and provider are ready.'}
              </p>
            </div>
            <button
              type="button"
              className="button button--primary"
              disabled={busy}
              onClick={() => void prepare()}
            >
              {busy ? (
                <LoadingLabel>Getting ready…</LoadingLabel>
              ) : (
                <>
                  {nextStep}
                  <Icon name="chevron-right" />
                </>
              )}
            </button>
          </div>
        ) : (
          <div className="welcome-starters" aria-label="Conversation starters">
            {starters.map((starter) => (
              <button
                type="button"
                key={starter.title}
                className="welcome-starter"
                onClick={() => insert(starter.prompt)}
                title={draft.text.trim() ? 'Add this idea to your draft' : undefined}
              >
                <span className="welcome-starter__icon">
                  <Icon name={starter.icon} />
                </span>
                <span>
                  <strong>{starter.title}</strong>
                  <small>{starter.description}</small>
                </span>
                <Icon name="chevron-right" />
              </button>
            ))}
          </div>
        )}
        {error ? (
          <p className="welcome-error" role="alert">
            {error}
          </p>
        ) : null}
        <p className="welcome-footnote">
          <span />
          Sessions are saved on this Mac. Pi uses your chosen model provider.
        </p>
      </div>
    </div>
  );
}
