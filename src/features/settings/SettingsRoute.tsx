import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { useProduct } from '../../app/ProductContext';
import { Icon, type IconName } from '../../components/icons/Icon';
import { useConfirmation } from '../../components/dialog/ModalDialog';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { StatusPill } from '../../components/primitives/StatusPill';
import { productErrorMessage, redactForDisplay } from '../../domain/errors';
import { visibleLogLines } from '../../domain/logs';
import { isTurnActive } from '../../domain/machines';
import { DEFAULT_THINKING_LEVEL, isThinkingLevel, thinkingChoices } from '../../domain/thinking';
import { AppearanceControls, Toggle } from '../appearance/AppearanceControls';
import { DiagnosticsRoute } from '../diagnostics/DiagnosticsRoute';
import { UpdateStatus } from '../updates/UpdateStatus';
import { AboutPanel } from './AboutPanel';
import { SettingRow } from './SettingRow';
import './settings.css';

type SectionId =
  | 'general'
  | 'providers'
  | 'projects'
  | 'permissions'
  | 'appearance'
  | 'updates'
  | 'models'
  | 'tools'
  | 'resources'
  | 'environment'
  | 'sessions'
  | 'logs'
  | 'diagnostics';
type Section = Readonly<{
  id: SectionId;
  label: string;
  description: string;
  icon: IconName;
  advanced?: boolean;
}>;

const sections: readonly Section[] = [
  {
    id: 'general',
    label: 'General',
    description: 'Mode, start-up and local behaviour',
    icon: 'settings',
  },
  {
    id: 'providers',
    label: 'Providers',
    description: 'Accounts and sign-in methods',
    icon: 'conversation',
  },
  {
    id: 'projects',
    label: 'Projects & trust',
    description: 'Folders and executable resources',
    icon: 'folder',
  },
  {
    id: 'permissions',
    label: 'Permissions',
    description: 'Approval rules and remembered scope',
    icon: 'shield',
  },
  { id: 'appearance', label: 'Appearance', description: 'Theme and accessibility', icon: 'sun' },
  {
    id: 'updates',
    label: 'Updates',
    description: 'User-controlled signed updates',
    icon: 'download',
  },
  {
    id: 'models',
    label: 'Models & reasoning',
    description: 'Model and response depth',
    icon: 'conversation',
    advanced: true,
  },
  {
    id: 'tools',
    label: 'Tools',
    description: 'Available project capabilities',
    icon: 'command',
    advanced: true,
  },
  {
    id: 'resources',
    label: 'Resources',
    description: 'Skills, prompts, themes and packages',
    icon: 'file',
    advanced: true,
  },
  {
    id: 'environment',
    label: 'Environment',
    description: 'Versions and configuration provenance',
    icon: 'activity',
    advanced: true,
  },
  {
    id: 'sessions',
    label: 'Sessions',
    description: 'Storage and compaction behaviour',
    icon: 'sessions',
    advanced: true,
  },
  {
    id: 'logs',
    label: 'Logs',
    description: 'Bounded redacted local logs',
    icon: 'activity',
    advanced: true,
  },
  {
    id: 'diagnostics',
    label: 'Diagnostics',
    description: 'Health checks and safe repairs',
    icon: 'shield',
  },
];

function settingValues(
  settings: ReturnType<typeof useProduct>['settings'],
): Record<string, unknown> {
  return Object.fromEntries(settings.map((setting) => [setting.key, setting.value]));
}

function sameValue(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function SettingsRoute() {
  const product = useProduct();
  const [active, setActive] = useState<SectionId>('general');
  const [query, setQuery] = useState('');
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [draft, setDraft] = useState<Record<string, unknown>>(() =>
    settingValues(product.settings),
  );
  useEffect(() => {
    if (!dirty) setDraft(settingValues(product.settings));
  }, [dirty, product.settings]);
  useEffect(() => {
    if (sections.some((section) => section.id === product.settingsSection)) {
      setActive(product.settingsSection as SectionId);
      setQuery('');
    }
  }, [product.settingsSection]);
  const visibleSections = useMemo(
    () =>
      sections.filter(
        (section) =>
          (!section.advanced || product.mode === 'advanced') &&
          `${section.label} ${section.description} ${section.id}`
            .toLowerCase()
            .includes(query.toLowerCase()),
      ),
    [product.mode, query],
  );
  const selected = sections.find((section) => section.id === active) ?? sections[0];
  const changeSetting = (key: string, value: unknown) => {
    setDraft((current) => ({ ...current, [key]: value }));
    setDirty(true);
    setSaved(false);
    setSaveError(null);
  };
  const resetDraft = () => {
    setDraft(settingValues(product.settings));
    setDirty(false);
    setSaved(false);
    setSaveError(null);
  };
  const save = async () => {
    if (!dirty || saving) return;
    setSaving(true);
    setSaved(false);
    setSaveError(null);
    const changes = product.settings
      .filter((setting) => !sameValue(setting.value, draft[setting.key]))
      .map((setting) => ({
        key: setting.key,
        value: draft[setting.key],
        scope: setting.scope,
        expectedRevision: setting.revision,
      }));
    try {
      await product.saveSettings(changes);
      setSaving(false);
      setDirty(false);
      setSaved(true);
    } catch (error) {
      setSaving(false);
      setSaveError(
        error instanceof Error && error.message.includes('conflict')
          ? 'A setting changed elsewhere. Your draft is preserved; review the latest values or retry.'
          : productErrorMessage(error, 'PIUI could not save every setting. Your draft is preserved.'),
      );
    }
  };
  return (
    <main className="settings-route" aria-labelledby="settings-title">
      <aside className="settings-navigation" aria-label="Settings sections">
        <header>
          <p className="ui-label">PIUI preferences</p>
          <h1 id="settings-title">Settings</h1>
        </header>
        <label className="search-field">
          <Icon name="search" />
          <span className="sr-only">Search Settings</span>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search Settings"
          />
        </label>
        <nav>
          {visibleSections.map((section) => (
            <button
              key={section.id}
              type="button"
              aria-current={active === section.id ? 'page' : undefined}
              onClick={() => setActive(section.id)}
            >
              <Icon name={section.icon} />
              <span>
                <strong>{section.label}</strong>
                <small>{section.description}</small>
              </span>
              {section.advanced ? <StatusPill>Advanced</StatusPill> : null}
            </button>
          ))}
        </nav>
        {visibleSections.length === 0 ? (
          <div className="settings-no-results">
            <p>No settings match “{query}”.</p>
            <button type="button" className="button" onClick={() => setQuery('')}>
              Clear search
            </button>
          </div>
        ) : null}
      </aside>
      <section className="settings-content" aria-labelledby={`settings-${selected.id}`}>
        <header className="settings-content__header">
          <div>
            <p className="ui-label">{selected.advanced ? 'Advanced setting' : 'PIUI setting'}</p>
            <h2 id={`settings-${selected.id}`}>{selected.label}</h2>
            <p>{selected.description}</p>
          </div>
          {selected.advanced ? <StatusPill tone="work">Advanced</StatusPill> : null}
        </header>
        <div className="settings-content__body">
          <SettingsSection id={selected.id} draft={draft} onChange={changeSetting} />
        </div>
        <footer className="settings-action-bar">
          <span>
            {saveError
              ? saveError
              : saved
                ? 'Settings saved.'
                : dirty
                  ? 'Unsaved changes are kept until PIUI confirms the save.'
                  : 'Settings are up to date.'}
          </span>
          {dirty ? (
            <button type="button" className="button" onClick={resetDraft} disabled={saving}>
              Reset draft
            </button>
          ) : null}
          <button
            type="button"
            className="button button--primary"
            onClick={() => void save()}
            disabled={!dirty || saving}
          >
            {saving ? <LoadingLabel>Saving settings…</LoadingLabel> : 'Save settings'}
          </button>
        </footer>
      </section>
    </main>
  );
}

function SettingsSection({
  id,
  draft,
  onChange,
}: Readonly<{
  id: SectionId;
  draft: Readonly<Record<string, unknown>>;
  onChange: (key: string, value: unknown) => void;
}>) {
  const product = useProduct();
  const { snapshot } = product;
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [confirm, confirmation] = useConfirmation();
  useEffect(() => {
    setPendingAction(null);
    setActionMessage(null);
  }, [id]);
  const runAction = async (actionId: string, action: () => Promise<unknown>, success: string) => {
    if (pendingAction) return;
    setPendingAction(actionId);
    setActionMessage(null);
    try {
      const result = await action();
      if (result === false) {
        setActionMessage('No selection was made. Existing access is unchanged.');
        return;
      }
      setActionMessage(success);
    } catch (error) {
      setActionMessage(
        productErrorMessage(error, 'PIUI could not complete that action. No hidden fallback was used.'),
      );
    } finally {
      setPendingAction(null);
    }
  };
  if (id === 'general')
    return (
      <>
        <SectionGroup
          title="Workspace mode"
          description="Simple mode stays focused. Advanced mode adds technical controls without weakening approval or trust policy."
        >
        <SettingRow
          label="Advanced mode"
          description="Show models, tools, resources, environment and logs. Executable code still requires explicit trust."
        >
          <Toggle
            label={product.mode === 'advanced' ? 'Advanced enabled' : 'Simple enabled'}
            detail="Change this preference only from Settings."
            checked={product.mode === 'advanced'}
            onChange={(checked) => product.setMode(checked ? 'advanced' : 'simple')}
          />
        </SettingRow>
        <SettingRow
          label="Product tour"
          description="Replay the short Conversation, work-trace and approval tour."
        >
          <button
            type="button"
            className="button"
            disabled={
              product.activeOperation !== null ||
              isTurnActive(product.snapshot.turnStatus)
            }
            onClick={() => window.location.assign(`${window.location.pathname}?onboarding=1`)}
          >
            Replay product tour
          </button>
        </SettingRow>
        <SettingRow
          label="Open last project"
          description="Restore the last accessible local project when PIUI starts."
        >
          <Toggle
            label="Restore project"
            detail="PIUI requires the folder to be selected again when its native capability has expired."
            checked={product.restoreLastProject}
            onChange={product.setRestoreLastProject}
          />
        </SettingRow>
        </SectionGroup>
        <AboutPanel facts={product.diagnosticEnvironment} />
      </>
    );
  if (id === 'providers')
    return (
      <SectionGroup
        title="Provider accounts"
        description="Subscription sign-in is recommended. API keys remain a secondary native-only option."
      >
        {snapshot.providers.map((provider) => (
          <article key={provider.id} className="provider-card">
            <div className="feature-status-icon">
              <Icon name="conversation" />
            </div>
            <div>
              <div className="feature-status-heading">
                <h3>{provider.name}</h3>
                <StatusPill tone={provider.connected ? 'success' : 'neutral'}>
                  {provider.connected ? (provider.accountLabel ?? 'Connected') : 'Not connected'}
                </StatusPill>
              </div>
              <p>{provider.detail}</p>
              <div className="provider-card__actions">
                {provider.connected ? (
                  <button
                    type="button"
                    className="button"
                    disabled={product.activeOperation !== null}
                    onClick={async () => {
                      const confirmed = await confirm({
                        title: `Disconnect ${provider.name}?`,
                        message:
                          'Its saved credential will be removed from this Mac. You can connect again later.',
                        confirmLabel: 'Disconnect',
                        tone: 'danger',
                      });
                      if (!confirmed) return;
                      await runAction(
                        `logout-${provider.id}`,
                        () => product.logoutProvider(provider.id),
                        `${provider.name} disconnected.`,
                      );
                    }}
                  >
                    {pendingAction === `logout-${provider.id}` ? (
                      <LoadingLabel>Disconnecting…</LoadingLabel>
                    ) : (
                      'Disconnect'
                    )}
                  </button>
                ) : (
                  <button
                    type="button"
                    className="button button--primary"
                    disabled={
                      product.activeOperation !== null ||
                      !provider.methods.some((method) => method.id === 'subscription')
                    }
                    onClick={() =>
                      void runAction(
                        `connect-${provider.id}`,
                        () => product.connectProvider(provider.id),
                        `${provider.name} connected and validated.`,
                      )
                    }
                  >
                    {pendingAction === `connect-${provider.id}` ? (
                      <LoadingLabel>Waiting for sign-in…</LoadingLabel>
                    ) : (
                      (provider.methods.find((method) => method.id === 'subscription')?.label ??
                      'Subscription sign-in unavailable')
                    )}
                  </button>
                )}
                <button
                  type="button"
                  className="button button--quiet"
                  disabled={
                    product.activeOperation !== null ||
                    !provider.methods.some((method) => method.id === 'api-key')
                  }
                  onClick={() =>
                    void runAction(
                      `api-${provider.id}`,
                      () => product.connectProviderApiKey(provider.id, provider.name),
                      `${provider.name} API key saved in Keychain and validated.`,
                    )
                  }
                >
                  {pendingAction === `api-${provider.id}` ? (
                    <LoadingLabel>Opening secure sheet…</LoadingLabel>
                  ) : (
                    'Use an API key instead'
                  )}
                </button>
              </div>
            </div>
          </article>
        ))}
        {product.providerAuthNotice?.type === 'device-code' ? (
          <div className="warning-card" role="status">
            <Icon name="conversation" />
            <div>
              <h3>Complete sign-in in your browser</h3>
              <p>
                Enter code{' '}
                <strong className="ui-mono">{product.providerAuthNotice.userCode}</strong> at the
                provider page PIUI opened.
              </p>
            </div>
          </div>
        ) : product.providerAuthNotice?.type === 'progress' ? (
          <p role="status">{product.providerAuthNotice.message}</p>
        ) : null}
        {actionMessage ? <p role="status">{actionMessage}</p> : null}
        {confirmation}
      </SectionGroup>
    );
  if (id === 'projects')
    return (
      <SectionGroup
        title="Current project"
        description="Folder access and project trust are separate from tool approvals."
      >
        <article className="project-card">
          <Icon name="folder" />
          <div>
            <h3>{snapshot.workspace?.name ?? 'No project selected'}</h3>
            <p>{snapshot.workspace?.displayPath ?? 'Choose a local folder.'}</p>
            <p>
              Trust: <strong>{snapshot.workspace?.trust ?? 'not selected'}</strong>
            </p>
          </div>
          <button
            type="button"
            className="button"
            disabled={product.activeOperation !== null}
            onClick={() =>
              void runAction(
                'choose-project',
                () => product.chooseProject(),
                'Project access updated. Review trust before executable resources are loaded.',
              )
            }
          >
            {pendingAction === 'choose-project' ? (
              <LoadingLabel>Choosing project…</LoadingLabel>
            ) : (
              'Choose another'
            )}
          </button>
          {snapshot.workspace?.trust === 'trusted' ? (
            <button
              type="button"
              className="button button--danger"
              disabled={product.activeOperation !== null}
              onClick={async () => {
                const confirmed = await confirm({
                  title: 'Revoke trust for this project?',
                  message:
                    'Active executable resources will be cut off. You can trust the project again later.',
                  confirmLabel: 'Revoke trust',
                  tone: 'danger',
                });
                if (!confirmed) return;
                await runAction(
                  'revoke-project',
                  () => product.revokeProject(),
                  'Project trust revoked and active project state cleared.',
                );
              }}
            >
              {pendingAction === 'revoke-project' ? (
                <LoadingLabel>Revoking trust…</LoadingLabel>
              ) : (
                'Revoke trust'
              )}
            </button>
          ) : (
            <button
              type="button"
              className="button"
              disabled={!snapshot.workspace || product.activeOperation !== null}
              onClick={() =>
                void runAction(
                  'trust-project',
                  () => product.trustProject(),
                  'Project trust granted and the session catalogue refreshed.',
                )
              }
            >
              {pendingAction === 'trust-project' ? (
                <LoadingLabel>Trusting project…</LoadingLabel>
              ) : (
                'Trust project'
              )}
            </button>
          )}
        </article>
        <div className="warning-card">
          <Icon name="warning" />
          <div>
            <h3>Executable project resources</h3>
            <p>
              Trusted extensions and packages run with your permissions and may act outside
              PIUI-mediated approvals. Trust never creates a blanket tool approval.
            </p>
          </div>
        </div>
        {actionMessage ? <p role="status">{actionMessage}</p> : null}
        {confirmation}
      </SectionGroup>
    );
  if (id === 'permissions')
    return (
      <SectionGroup
        title="Approval policy"
        description="Destructive and external actions always need a fresh decision."
      >
        <SettingRow
          label="Read project files"
          description="The current native approval broker requires a fresh decision for each tool invocation."
          scope="Project"
        >
          <select
            className="select"
            value="ask"
            disabled
            aria-label="Project reads require approval"
          >
            <option value="ask">Ask when needed</option>
          </select>
        </SettingRow>
        <SettingRow
          label="Run local commands"
          description="Ask for each consequential command and show its exact target."
          scope="Project"
        >
          <select className="select" value="ask" disabled aria-label="Commands require approval">
            <option value="ask">Always ask</option>
          </select>
        </SettingRow>
        <SettingRow
          label="External or destructive actions"
          description="Deletion, network effects and publishing cannot receive blanket or group persistence."
          scope="Global"
        >
          <select
            className="select"
            value="always"
            disabled
            aria-label="External actions always require confirmation"
          >
            <option value="always">Always confirm</option>
          </select>
        </SettingRow>
      </SectionGroup>
    );
  if (id === 'appearance')
    return (
      <SectionGroup
        title="Theme and access"
        description="System appearance is respected unless you choose an explicit theme."
      >
        <AppearanceControls />
      </SectionGroup>
    );
  if (id === 'updates')
    return (
      <SectionGroup
        title="User-controlled updates"
        description="PIUI never installs an update silently."
      >
        <UpdateStatus update={snapshot.update} />
      </SectionGroup>
    );
  if (id === 'models')
    return <ModelsSection draft={draft} onChange={onChange} />;
  if (id === 'tools') {
    const availableTools = [
      { id: 'read', label: 'Read project files' },
      { id: 'edit', label: 'Edit project files' },
      { id: 'write', label: 'Write project files' },
      { id: 'grep', label: 'Search file contents' },
      { id: 'find', label: 'Find workspace files' },
      { id: 'ls', label: 'List project folders' },
      { id: 'bash', label: 'Run local commands' },
    ] as const;
    const activeTools = Array.isArray(draft['tools.active'])
      ? draft['tools.active'].filter((tool): tool is string => typeof tool === 'string')
      : [];
    return (
      <SectionGroup
        title="Available tools"
        description="Choose which pinned Pi tools are available. Every invocation remains subject to the native approval policy."
      >
        {availableTools.map((tool) => (
          <SettingRow
            key={tool.id}
            label={tool.label}
            description="Provided by the pinned Pi public SDK and mediated by PIUI."
            scope="Project"
            origin={product.settings.find((setting) => setting.key === 'tools.active')?.origin}
          >
            <Toggle
              label={activeTools.includes(tool.id) ? 'Available' : 'Unavailable'}
              detail="Changing availability does not grant approval to use the tool."
              checked={activeTools.includes(tool.id)}
              onChange={(checked) =>
                onChange(
                  'tools.active',
                  checked
                    ? [...activeTools, tool.id]
                    : activeTools.filter((candidate) => candidate !== tool.id),
                )
              }
            />
          </SettingRow>
        ))}
      </SectionGroup>
    );
  }
  if (id === 'resources') return <ResourcesSection />;
  if (id === 'environment') return <EnvironmentSection />;
  if (id === 'sessions')
    return (
      <SectionGroup title="Session behaviour" description="Pi session files remain authoritative.">
        <SettingRow
          label="Automatic compaction"
          description="Allow Pi to compact older history when the model context becomes constrained."
          scope="Project"
          origin={product.settings.find((setting) => setting.key === 'compaction.enabled')?.origin}
        >
          <Toggle
            label="Compact automatically"
            detail="PIUI always shows labelled compaction markers in the transcript and exports."
            checked={draft['compaction.enabled'] === true}
            onChange={(checked) => onChange('compaction.enabled', checked)}
          />
        </SettingRow>
        <SettingRow
          label="Automatic retry"
          description="Allow Pi to retry eligible transient provider failures."
          scope="Project"
          origin={product.settings.find((setting) => setting.key === 'retry.enabled')?.origin}
        >
          <Toggle
            label="Retry transient failures"
            detail="Retries never bypass tool approval or workspace trust."
            checked={draft['retry.enabled'] === true}
            onChange={(checked) => onChange('retry.enabled', checked)}
          />
        </SettingRow>
        <SettingRow
          label="Follow-up queue"
          description="Control how acknowledged follow-up messages are delivered after the active turn."
          scope="Project"
          origin={
            product.settings.find((setting) => setting.key === 'queue.follow-up-mode')?.origin
          }
        >
          <select
            className="select"
            value={draft['queue.follow-up-mode'] === 'one-at-a-time' ? 'one-at-a-time' : 'all'}
            onChange={(event) => onChange('queue.follow-up-mode', event.target.value)}
          >
            <option value="all">Send all queued follow-ups</option>
            <option value="one-at-a-time">Send one at a time</option>
          </select>
        </SettingRow>
        <SettingRow
          label="Session catalogue"
          description="Refresh non-secret session metadata from Pi's authoritative session store."
        >
          <button
            type="button"
            className="button"
            disabled={product.activeOperation !== null}
            onClick={() => void product.rebuildSessions()}
          >
            {product.activeOperation === 'session' ? (
              <LoadingLabel>Refreshing sessions…</LoadingLabel>
            ) : (
              'Refresh catalogue'
            )}
          </button>
        </SettingRow>
      </SectionGroup>
    );
  if (id === 'logs') return <LogsSection />;
  return <DiagnosticsRoute />;
}

function SectionGroup({
  title,
  description,
  children,
}: Readonly<{ title: string; description: string; children: ReactNode }>) {
  return (
    <section className="settings-group">
      <header>
        <h3>{title}</h3>
        <p>{description}</p>
      </header>
      <div>{children}</div>
    </section>
  );
}

function ModelsSection({
  draft,
  onChange,
}: Readonly<{
  draft: Readonly<Record<string, unknown>>;
  onChange: (key: string, value: unknown) => void;
}>) {
  const product = useProduct();
  const { snapshot } = product;
  const providerId = typeof draft['model.provider'] === 'string' ? draft['model.provider'] : '';
  const provider = snapshot.providers.find((candidate) => candidate.id === providerId);
  const savedReasoning = product.settings.find(
    (setting) => setting.key === 'reasoning.level',
  )?.value;
  const reasoning = isThinkingLevel(draft['reasoning.level'])
    ? draft['reasoning.level']
    : DEFAULT_THINKING_LEVEL;
  return (
    <SectionGroup
      title="Model configuration"
      description="Values show their scope and saved origin."
    >
      <SettingRow
        label="Provider"
        description="The provider used for new turns."
        scope="Project"
        origin={product.settings.find((setting) => setting.key === 'model.provider')?.origin}
      >
        <select
          className="select"
          value={providerId}
          onChange={(event) => {
            const next = snapshot.providers.find(
              (candidate) => candidate.id === event.target.value,
            );
            onChange('model.provider', event.target.value);
            if (next?.models[0]) onChange('model.id', next.models[0].id);
          }}
        >
          {snapshot.providers.map((candidate) => (
            <option key={candidate.id} value={candidate.id} disabled={!candidate.connected}>
              {candidate.name}
              {candidate.connected ? '' : ' — not connected'}
            </option>
          ))}
        </select>
      </SettingRow>
      <SettingRow
        label="Model"
        description="Only models reported by the connected provider are available."
        scope="Project"
        origin={product.settings.find((setting) => setting.key === 'model.id')?.origin}
      >
        <select
          className="select"
          value={typeof draft['model.id'] === 'string' ? draft['model.id'] : ''}
          onChange={(event) => onChange('model.id', event.target.value)}
          disabled={!provider?.connected}
        >
          {(provider?.models ?? []).map((model) => (
            <option key={model.id} value={model.id}>
              {model.name}
              {model.acceptsImages ? ' · images' : ''}
            </option>
          ))}
        </select>
      </SettingRow>
      <SettingRow
        label="Reasoning"
        description="Choose how deeply Pi reasons before responding."
        scope="Project"
        origin={product.settings.find((setting) => setting.key === 'reasoning.level')?.origin}
      >
        <select
          className="select"
          value={reasoning}
          onChange={(event) => onChange('reasoning.level', event.target.value)}
        >
          {thinkingChoices(savedReasoning).map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </SettingRow>
    </SectionGroup>
  );
}

function ResourcesSection() {
  const product = useProduct();
  const { snapshot, mode } = product;
  const [kind, setKind] = useState('all');
  const [pending, setPending] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [packageSource, setPackageSource] = useState('');
  const [packageScope, setPackageScope] = useState<'global' | 'project'>('project');
  const [confirm, confirmation] = useConfirmation();
  const resources = snapshot.resources.filter(
    (resource) => kind === 'all' || resource.kind === kind,
  );
  const manage = async (resource: (typeof snapshot.resources)[number]) => {
    if (pending) return;
    const enabling = !resource.enabled;
    if (
      resource.executable &&
      enabling &&
      !(await confirm({
        title: `Enable “${resource.name}”?`,
        message:
          'This executable code runs with your permissions and may act outside PIUI-mediated approvals.',
        confirmLabel: 'Enable',
      }))
    )
      return;
    setPending(resource.id);
    setMessage(null);
    try {
      await product.setResourceEnabled(resource.id, enabling, resource.executable && enabling);
      setMessage(`${resource.name} ${enabling ? 'enabled' : 'disabled'} and acknowledged by Pi.`);
    } catch (error) {
      setMessage(
        productErrorMessage(
          error,
          resource.executable
            ? 'The executable resource could not be loaded safely. It remains disabled.'
            : 'The resource change was not acknowledged. The previous state is retained.',
        ),
      );
    } finally {
      setPending(null);
    }
  };
  const installPackage = async () => {
    const source = packageSource.trim();
    if (pending || !source) return;
    if (!navigator.onLine) {
      setMessage('Package installation is unavailable while this Mac is offline.');
      return;
    }
    if (
      !(await confirm({
        title: `Install “${source}” from npm?`,
        message:
          'Packages are executable code and may act outside PIUI-mediated approvals. Installation may contact npm.',
        confirmLabel: 'Install',
      }))
    )
      return;
    setPending('package-install');
    setMessage(null);
    try {
      await product.installPackage(source, packageScope);
      setPackageSource('');
      setMessage(`${source} installed but left disabled. Review it before enabling.`);
    } catch (error) {
      setMessage(
        error instanceof Error && error.message.includes('offline')
          ? 'Package installation is unavailable while this Mac is offline.'
          : productErrorMessage(
              error,
              'The package was not installed. PIUI retained the previous catalogue.',
            ),
      );
    } finally {
      setPending(null);
    }
  };
  const mutatePackage = async (
    resource: (typeof snapshot.resources)[number],
    operation: 'update' | 'remove',
  ) => {
    if (pending) return;
    if (!navigator.onLine) {
      setMessage(`Package ${operation} is unavailable while this Mac is offline.`);
      return;
    }
    const confirmed = await confirm(
      operation === 'remove'
        ? {
            title: `Remove “${resource.name}”?`,
            message:
              'It will be removed from Pi and this catalogue, and Pi’s package manager will remove its package files.',
            confirmLabel: 'Remove',
            tone: 'danger',
          }
        : {
            title: `Update “${resource.name}”?`,
            message:
              'Pi’s package manager will update it. Updated executable code keeps its current enabled state.',
            confirmLabel: 'Update',
          },
    );
    if (!confirmed) return;
    setPending(`${resource.id}-${operation}`);
    setMessage(null);
    try {
      await product.mutatePackage(resource.id, operation);
      setMessage(
        operation === 'remove'
          ? `${resource.name} removed.`
          : `${resource.name} updated. Review its trust before continuing.`,
      );
    } catch (error) {
      setMessage(
        productErrorMessage(
          error,
          `The package ${operation} did not complete. Review Diagnostics before retrying.`,
        ),
      );
    } finally {
      setPending(null);
    }
  };
  return (
    <SectionGroup
      title="Skills, prompts, themes and executable resources"
      description="Project resources are discovered as metadata before trust. Extensions and packages are executable code."
    >
      <div className="filter-row">
        {['all', 'skill', 'prompt', 'theme', 'extension', 'package'].map((item) => (
          <button
            key={item}
            type="button"
            className="filter-chip"
            aria-pressed={kind === item}
            onClick={() => setKind(item)}
          >
            {item}
          </button>
        ))}
      </div>
      <div className="package-install-panel">
        <div>
          <h3>Install an npm Pi package</h3>
          <p>
            Use a package name such as <span className="ui-mono">@scope/package</span>. PIUI leaves
            newly installed executable code disabled until you review and enable it.
          </p>
        </div>
        <label>
          <span>Package source</span>
          <input
            value={packageSource}
            onChange={(event) => setPackageSource(event.target.value)}
            placeholder="@scope/package"
            disabled={pending !== null || mode === 'simple'}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
        </label>
        <label>
          <span>Scope</span>
          <select
            className="select"
            value={packageScope}
            onChange={(event) => setPackageScope(event.target.value as 'global' | 'project')}
            disabled={pending !== null || mode === 'simple'}
          >
            <option value="project">Current project</option>
            <option value="global">All projects</option>
          </select>
        </label>
        <button
          type="button"
          className="button button--primary"
          disabled={pending !== null || mode === 'simple' || !packageSource.trim()}
          onClick={() => void installPackage()}
        >
          {pending === 'package-install' ? <LoadingLabel>Installing package…</LoadingLabel> : 'Review and install'}
        </button>
        {mode === 'simple' ? (
          <small className="disabled-reason-block">Enable Advanced mode to manage executable packages.</small>
        ) : null}
      </div>
      <div className="resource-grid">
        {resources.map((resource) => (
          <article
            key={resource.id}
            className="resource-card"
            data-executable={resource.executable}
          >
            <div className="feature-status-icon">
              <Icon name={resource.executable ? 'warning' : 'file'} />
            </div>
            <div>
              <div className="feature-status-heading">
                <h3>{resource.name}</h3>
                <StatusPill
                  tone={resource.enabled ? 'success' : resource.executable ? 'warning' : 'neutral'}
                >
                  {resource.enabled ? 'Enabled' : 'Disabled'}
                </StatusPill>
              </div>
              <p>{resource.description}</p>
              <small>
                {resource.kind} · {resource.version} · {resource.source}
              </small>
              {resource.executable ? (
                <p className="resource-warning">
                  This code runs with your permissions and may act outside PIUI-mediated approvals.
                </p>
              ) : null}
              <button
                type="button"
                className="button"
                disabled={
                  pending !== null ||
                  !resource.operations.includes(resource.enabled ? 'disable' : 'enable') ||
                  (resource.executable && mode === 'simple')
                }
                onClick={() => void manage(resource)}
              >
                {pending === resource.id ? (
                  <LoadingLabel>Applying…</LoadingLabel>
                ) : resource.enabled ? (
                  'Disable'
                ) : resource.executable ? (
                  'Review and enable'
                ) : (
                  'Enable'
                )}
              </button>
              {resource.executable && mode === 'simple' ? (
                <small className="disabled-reason-block">
                  Enable Advanced mode to inspect executable resources.
                </small>
              ) : null}
              {resource.kind === 'package' ? (
                <div className="resource-card__package-actions">
                  {resource.operations.includes('update') ? (
                    <button
                      type="button"
                      className="button button--quiet"
                      disabled={pending !== null || mode === 'simple'}
                      onClick={() => void mutatePackage(resource, 'update')}
                    >
                      {pending === `${resource.id}-update` ? <LoadingLabel>Updating…</LoadingLabel> : 'Update'}
                    </button>
                  ) : null}
                  {resource.operations.includes('remove') ? (
                    <button
                      type="button"
                      className="button button--danger"
                      disabled={pending !== null || mode === 'simple'}
                      onClick={() => void mutatePackage(resource, 'remove')}
                    >
                      {pending === `${resource.id}-remove` ? <LoadingLabel>Removing…</LoadingLabel> : 'Remove'}
                    </button>
                  ) : null}
                </div>
              ) : null}
              {resource.contributedSettings?.length ? (
                <small className="disabled-reason-block">
                  Contributed settings: {resource.contributedSettings.join(', ')}
                </small>
              ) : null}
            </div>
          </article>
        ))}
        {resources.length === 0 ? (
          <div className="empty-state">
            <Icon name="file" />
            <h3>No resources in this catalogue</h3>
            <p>
              PIUI found no matching trusted Pi skills, prompts, themes, extensions or configured
              packages for the active session.
            </p>
          </div>
        ) : null}
      </div>
      {message ? <p role="status">{message}</p> : null}
      {confirmation}
    </SectionGroup>
  );
}

function EnvironmentSection() {
  const product = useProduct();
  const [copying, setCopying] = useState(false);
  const labels: Readonly<Record<string, string>> = {
    piuiVersion: 'PIUI',
    piVersion: 'Pi SDK',
    nodeVersion: 'Node.js',
    architecture: 'Architecture',
    operatingSystem: 'Operating system',
    credentialStore: 'Provider credential store',
  };
  const copy = async () => {
    if (copying) return;
    setCopying(true);
    try {
      const report = [
        ...product.diagnosticEnvironment.map(
          (fact) => `${labels[fact.key] ?? fact.key}: ${fact.value} (${fact.origin})`,
        ),
        ...product.settings.map(
          (setting) => `${setting.key}: ${JSON.stringify(setting.value)} (${setting.origin})`,
        ),
      ].join('\n');
      await navigator.clipboard.writeText(redactForDisplay(report));
    } finally {
      setCopying(false);
    }
  };
  return (
    <SectionGroup
      title="Environment and provenance"
      description="Secret values and personal paths are never displayed or copied."
    >
      <div className="environment-table" role="table" aria-label="Environment values">
        {product.diagnosticEnvironment.map((fact) => (
          <div key={fact.key} role="row">
            <strong role="cell">{labels[fact.key] ?? fact.key}</strong>
            <span role="cell" className="ui-mono">
              {fact.value}
            </span>
            <small role="cell">{fact.origin}</small>
          </div>
        ))}
        {product.settings.map((setting) => (
          <div key={setting.key} role="row">
            <strong role="cell">{setting.key}</strong>
            <span role="cell" className="ui-mono">
              {typeof setting.value === 'string' ? setting.value : JSON.stringify(setting.value)}
            </span>
            <small role="cell">
              {setting.scope} · {setting.origin}
            </small>
          </div>
        ))}
      </div>
      {product.diagnosticEnvironment.length === 0 ? (
        <p role="status">Run Diagnostics to read native environment provenance.</p>
      ) : null}
      <div className="provider-card__actions">
        <button
          type="button"
          className="button"
          disabled={product.activeOperation !== null}
          onClick={() => void product.runDiagnostics()}
        >
          {product.activeOperation === 'diagnostics' ? (
            <LoadingLabel>Reading environment…</LoadingLabel>
          ) : (
            'Refresh environment'
          )}
        </button>
        <button
          type="button"
          className="button button--quiet"
          disabled={copying || product.diagnosticEnvironment.length === 0}
          onClick={() => void copy()}
        >
          {copying ? <LoadingLabel>Copying…</LoadingLabel> : 'Copy safe values'}
        </button>
      </div>
      <div className="warning-card">
        <Icon name="shield" />
        <div>
          <h3>Configuration is capability-backed</h3>
          <p>
            PIUI explains configuration locations without exposing arbitrary local paths or
            encouraging unsafe manual edits.
          </p>
        </div>
      </div>
    </SectionGroup>
  );
}

function LogsSection() {
  const product = useProduct();
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const visible = useMemo(
    () => visibleLogLines(product.diagnosticLogs, query, severity),
    [product.diagnosticLogs, query, severity],
  );
  return (
    <SectionGroup
      title="Redacted local logs"
      description="The view is bounded and excludes raw protocol envelopes, credential values and personal paths."
    >
      <label className="search-field">
        <Icon name="search" />
        <span className="sr-only">Search logs</span>
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search severity, source or code"
        />
      </label>
      <label>
        <span className="sr-only">Filter log severity</span>
        <select
          className="select"
          value={severity}
          onChange={(event) => setSeverity(event.target.value)}
        >
          <option value="all">All severities</option>
          <option value="info">Info</option>
          <option value="warn">Warnings</option>
          <option value="error">Errors</option>
        </select>
      </label>
      <div className="log-list" role="log" aria-label="Local redacted log entries">
        {visible.map((line, index) => (
          <div key={`${index}-${line.slice(0, 40)}`} className="ui-mono">
            {line}
          </div>
        ))}
        {visible.length === 0 ? (
          <div role="status">No redacted log entries match the current filters.</div>
        ) : null}
      </div>
      <button
        type="button"
        className="button"
        disabled={product.activeOperation !== null}
        onClick={() => void product.exportDiagnostics()}
      >
        <Icon name="download" />
        {product.activeOperation === 'diagnostics' ? (
          <LoadingLabel>Preparing export…</LoadingLabel>
        ) : (
          'Export safe diagnostics'
        )}
      </button>
      <p className="retention-note">
        Logs rotate locally and retain only bounded diagnostic evidence.
      </p>
    </SectionGroup>
  );
}
