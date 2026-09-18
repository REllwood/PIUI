import { useCallback, useMemo, useRef, useState, type ReactNode } from 'react';
import { AppShell } from '../app/AppShell';
import { ProductContextFixtureHost, type ProductContextValue } from '../app/ProductContext';
import { productFixture } from '../domain/fixtures';
import type {
  AppearancePreferences,
  ApprovalDecision,
  Message,
  ProductSnapshot,
  QueueItem,
  RouteId,
} from '../domain/types';
import { AppearanceProvider } from '../features/appearance/AppearanceProvider';
import type { NativeEnvironmentFact, NativeProductSetting } from '../platform/native';
import '../styles/tokens.css';
import '../styles/theme-dark.css';
import '../styles/theme-light.css';
import '../styles/typography.css';
import '../styles/base.css';
import '../app/shell.css';

const initialSettings: readonly NativeProductSetting[] = Object.freeze([
  {
    key: 'model.provider',
    value: 'openai-codex',
    scope: 'project',
    revision: 1,
    origin: 'Project',
  },
  { key: 'model.id', value: 'gpt-5.6', scope: 'project', revision: 1, origin: 'Project' },
  { key: 'reasoning.level', value: 'high', scope: 'project', revision: 1, origin: 'Project' },
  { key: 'transport', value: 'auto', scope: 'global', revision: 1, origin: 'Global' },
]);

const initialEnvironment: readonly NativeEnvironmentFact[] = Object.freeze([
  { key: 'PIUI', value: '0.1.0', origin: 'Application bundle' },
  { key: 'Pi SDK', value: '0.82.0', origin: 'Bundled sidecar' },
  { key: 'Node', value: '22.23.1', origin: 'Bundled runtime' },
  { key: 'Architecture', value: 'arm64', origin: 'Native host' },
]);

function delay(instant = false): Promise<void> {
  return new Promise((resolve) => {
    // Keep pending states observable during browser interaction checks.
    requestAnimationFrame(() => {
      if (instant) resolve();
      else window.setTimeout(resolve, 250);
    });
  });
}

function initialProductSnapshot(): ProductSnapshot {
  const query = new URLSearchParams(window.location.search);
  if (query.get('welcome') === 'true')
    return Object.freeze({
      ...productFixture,
      messages: [],
      activity: [],
      approvals: [],
      changes: [],
      queue: [],
      turnStatus: 'idle',
    });
  const requestedCount = Number(query.get('long') ?? 0);
  const count =
    Number.isSafeInteger(requestedCount) && requestedCount >= 0 && requestedCount <= 10_000
      ? requestedCount
      : 0;
  if (count === 0) return productFixture;
  const payloadSize = query.get('payload') === '5000' ? 5_000 : 96;
  const payload = 'Measured local transcript content. '.repeat(
    Math.ceil(payloadSize / 'Measured local transcript content. '.length),
  );
  const messages: Message[] = Array.from({ length: count }, (_, index) => ({
    id: `performance-message-${index}`,
    role: index % 3 === 0 ? 'user' : 'assistant',
    author: index % 3 === 0 ? 'You' : 'Pi',
    timestamp: `${Math.floor(index / 60) % 12 || 12}:${String(index % 60).padStart(2, '0')}`,
    markdown: `${index + 1}. ${payload.slice(0, payloadSize)}`,
    status: 'stable',
  }));
  return Object.freeze({ ...productFixture, messages, turnStatus: 'tool-running' });
}

function FixtureProductProvider({ children }: Readonly<{ children: ReactNode }>) {
  const [snapshot, setSnapshot] = useState<ProductSnapshot>(initialProductSnapshot);
  const [route, setRoute] = useState<RouteId>('conversation');
  const [settingsSection, setSettingsSection] = useState<string | null>(null);
  const [mode, setMode] = useState<'simple' | 'advanced'>('simple');
  const [restoreLastProject, setRestoreLastProject] = useState(true);
  const [activeOperation, setActiveOperation] =
    useState<ProductContextValue['activeOperation']>(null);
  const [selectedActivity, setSelectedActivity] = useState<ProductContextValue['selectedActivity']>(
    snapshot.activity[0] ?? null,
  );
  const [selectedChangeId, setSelectedChangeId] = useState<string | null>(
    snapshot.changes[0]?.id ?? null,
  );
  const [settings, setSettings] = useState(initialSettings);
  const lease = useRef<ProductContextValue['activeOperation']>(null);

  const update = useCallback((patch: Partial<ProductSnapshot>) => {
    setSnapshot((current) => Object.freeze({ ...current, ...patch }));
  }, []);

  const operate = useCallback(
    async <T,>(
      operation: Exclude<ProductContextValue['activeOperation'], null>,
      work: () => T | Promise<T>,
      options?: { readonly instant?: boolean },
    ): Promise<T> => {
      if (lease.current) throw new Error('operation-busy');
      lease.current = operation;
      setActiveOperation(operation);
      try {
        await delay(options?.instant === true);
        return await work();
      } finally {
        lease.current = null;
        setActiveOperation(null);
      }
    },
    [],
  );

  const openSettings = useCallback((section = 'general') => {
    setSettingsSection(section);
    setRoute('settings');
  }, []);

  const value = useMemo<ProductContextValue>(
    () => ({
      snapshot,
      route,
      setRoute,
      settingsSection,
      openSettings,
      mode,
      setMode,
      restoreLastProject,
      setRestoreLastProject,
      activeOperation,
      providerAuthNotice: null,
      diagnosticEnvironment: initialEnvironment,
      diagnosticLogs: Object.freeze([
        '[info] Native host ready',
        '[info] Private sidecar handshake complete',
        '[info] Project capability validated',
      ]),
      helperFailure: null,
      selectedActivity,
      setSelectedActivity,
      selectedChangeId,
      setSelectedChangeId,
      send: async (text) => {
        const trimmed = text.trim();
        if (!trimmed) return false;
        return operate('send', () => {
          const timestamp = new Date().toLocaleTimeString('en-AU', {
            hour: 'numeric',
            minute: '2-digit',
          });
          update({
            messages: [
              ...snapshot.messages.filter((message) => message.status !== 'streaming'),
              {
                id: `fixture-user-${snapshot.sequence + 1}`,
                role: 'user',
                author: 'You',
                timestamp,
                markdown: trimmed,
                status: 'stable',
              },
              {
                id: `fixture-assistant-${snapshot.sequence + 2}`,
                role: 'assistant',
                author: 'Pi',
                timestamp,
                markdown: 'The deterministic fixture accepted this message.',
                status: 'stable',
              },
            ],
            sequence: snapshot.sequence + 2,
            turnStatus: 'complete',
          });
          return true;
        });
      },
      // Stop skips the synthetic latency: the cancellation budget measures how quickly the
      // composer recovers, not how long the fixture pretends to work.
      stop: () => operate('stop', () => update({ turnStatus: 'stopped' }), { instant: true }),
      queue: async (text) => {
        const trimmed = text.trim();
        if (!trimmed) return false;
        return operate('queue', () => {
          const item: QueueItem = {
            localId: `fixture-queue-${snapshot.queue.length + 1}`,
            number: snapshot.queue.length + 1,
            text: trimmed,
            state: 'acknowledged',
          };
          update({ queue: [...snapshot.queue, item] });
          return true;
        });
      },
      retryQueueItem: async (localId) => {
        const item = snapshot.queue.find(
          (candidate) => candidate.localId === localId && candidate.state === 'failed',
        );
        if (!item) return false;
        return operate('queue', () => {
          update({
            queue: snapshot.queue.map((candidate) =>
              candidate.localId === localId ? { ...candidate, state: 'acknowledged' } : candidate,
            ),
          });
          return true;
        });
      },
      removeQueueItem: (localId) =>
        operate('queue', () =>
          update({ queue: snapshot.queue.filter((item) => item.localId !== localId) }),
        ),
      decideApproval: (requestId, decision: ApprovalDecision) =>
        operate('approval', () =>
          update({
            approvals: snapshot.approvals.map((approval) =>
              approval.id === requestId
                ? { ...approval, state: decision === 'deny' ? 'denied' : 'approved' }
                : approval,
            ),
          }),
        ),
      runDiagnostics: () =>
        operate('diagnostics', () =>
          update({
            diagnostics: snapshot.diagnostics.map((check) =>
              check.id === 'updates' ? check : { ...check, status: 'pass' },
            ),
          }),
        ),
      exportDiagnostics: () => operate('export', () => true),
      reconnect: () => operate('diagnostics', () => update({ connection: 'ready' })),
      createSession: () =>
        operate('session', () => {
          const id = `fixture-session-${snapshot.sessions.length + 1}`;
          update({
            sessions: [
              {
                id,
                generation: 1,
                title: 'New conversation',
                project: snapshot.workspace?.name ?? 'Project',
                updatedAt: 'Just now',
                status: 'active',
                preview: 'A deterministic local conversation.',
              },
              ...snapshot.sessions,
            ],
            activeSessionId: id,
            messages: [],
            activity: [],
            approvals: [],
            changes: [],
            queue: [],
            turnStatus: 'idle',
          });
          setRoute('conversation');
          return true;
        }),
      resumeSession: (sessionId) =>
        operate('session', () => {
          update({ activeSessionId: sessionId });
          setRoute('conversation');
        }),
      branchSession: (sessionId) =>
        operate('session', () => {
          const source = snapshot.sessions.find((session) => session.id === sessionId);
          if (!source) return;
          const id = `${sessionId}-fixture-branch`;
          update({
            sessions: [
              {
                ...source,
                id,
                title: `${source.title} branch`,
                branch: 'fixture',
                status: 'active',
              },
              ...snapshot.sessions,
            ],
            activeSessionId: id,
          });
        }),
      renameSession: (sessionId, title) =>
        operate('session', () =>
          update({
            sessions: snapshot.sessions.map((session) =>
              session.id === sessionId ? { ...session, title } : session,
            ),
          }),
        ),
      compactSession: () => operate('session', () => undefined),
      trashSession: (sessionId) =>
        operate('session', () => {
          if (sessionId === snapshot.activeSessionId) throw new Error('active-session');
          update({ sessions: snapshot.sessions.filter((session) => session.id !== sessionId) });
        }),
      rebuildSessions: () => operate('session', () => undefined),
      connectProvider: (providerId) =>
        operate('provider', () =>
          update({
            providers: snapshot.providers.map((provider) =>
              provider.id === providerId
                ? { ...provider, connected: true, accountLabel: 'Fixture account' }
                : provider,
            ),
          }),
        ),
      connectProviderApiKey: (providerId) =>
        operate('provider', () =>
          update({
            providers: snapshot.providers.map((provider) =>
              provider.id === providerId
                ? { ...provider, connected: true, accountLabel: 'Native Keychain reference' }
                : provider,
            ),
          }),
        ),
      logoutProvider: (providerId) =>
        operate('provider', () =>
          update({
            providers: snapshot.providers.map((provider) =>
              provider.id === providerId
                ? { ...provider, connected: false, accountLabel: undefined }
                : provider,
            ),
          }),
        ),
      chooseProject: () => operate('project', () => true),
      trustProject: () =>
        operate('project', () =>
          update({
            workspace: snapshot.workspace ? { ...snapshot.workspace, trust: 'trusted' } : null,
          }),
        ),
      revokeProject: () =>
        operate('project', () =>
          update({
            workspace: snapshot.workspace ? { ...snapshot.workspace, trust: 'revoked' } : null,
          }),
        ),
      discoverFiles: async (query) =>
        ['src/App.tsx', 'src/app/ProductContext.tsx', 'README.md'].filter((path) =>
          path.toLowerCase().includes(query.toLowerCase()),
        ),
      retryLastTurn: () => operate('send', () => update({ turnStatus: 'complete' })),
      exportSession: () => operate('export', () => true),
      // Production marks the change submitting before it awaits, so the fixture does too:
      // the review surface reads that state to label the Undo button while the work runs.
      undoChange: async (changeId) => {
        const submitting = snapshot.changes.map((change) =>
          change.id === changeId ? { ...change, undo: 'submitting' as const } : change,
        );
        update({ changes: submitting });
        try {
          await operate('change', () =>
            update({
              changes: submitting.map((change) =>
                change.id === changeId ? { ...change, undo: 'complete' as const } : change,
              ),
            }),
          );
        } catch (error) {
          update({ changes: snapshot.changes });
          throw error;
        }
      },
      revealChange: () => operate('change', () => undefined),
      settings,
      saveSettings: (drafts) =>
        operate('settings', () =>
          setSettings((current) =>
            current.map((setting) => {
              const draft = drafts.find((candidate) => candidate.key === setting.key);
              return draft
                ? {
                    ...setting,
                    value: draft.value,
                    scope: draft.scope,
                    revision: setting.revision + 1,
                  }
                : setting;
            }),
          ),
        ),
      setResourceEnabled: (resourceId, enabled, acknowledgedExecutableRisk) =>
        operate('resource', () => {
          const resource = snapshot.resources.find((candidate) => candidate.id === resourceId);
          if (resource?.executable && enabled && !acknowledgedExecutableRisk) {
            throw new Error('executable-acknowledgement-required');
          }
          update({
            resources: snapshot.resources.map((candidate) =>
              candidate.id === resourceId
                ? {
                    ...candidate,
                    enabled,
                    trusted: candidate.executable ? enabled : candidate.trusted,
                    operations:
                      candidate.kind === 'package'
                        ? [enabled ? 'disable' : 'enable', 'update', 'remove']
                        : [enabled ? 'disable' : 'enable'],
                  }
                : candidate,
            ),
          });
        }),
      installPackage: (source, scope) =>
        operate('resource', () =>
          update({
            resources: [
              ...snapshot.resources,
              {
                id: 'resource-00000000000000000000000000000001',
                kind: 'package',
                name: source,
                version: 'Installed',
                source: 'package',
                enabled: false,
                trusted: false,
                executable: true,
                description: `Installed ${scope} Pi package. It remains disabled until explicitly enabled.`,
                contributedSettings: [],
                operations: ['enable', 'update', 'remove'],
              },
            ],
          }),
        ),
      mutatePackage: (resourceId, operation) =>
        operate('resource', () =>
          update({
            resources:
              operation === 'remove'
                ? snapshot.resources.filter((candidate) => candidate.id !== resourceId)
                : snapshot.resources.map((candidate) =>
                    candidate.id === resourceId
                      ? { ...candidate, version: 'Updated fixture package' }
                      : candidate,
                  ),
          }),
        ),
    }),
    [
      activeOperation,
      mode,
      openSettings,
      operate,
      restoreLastProject,
      route,
      selectedActivity,
      selectedChangeId,
      settings,
      settingsSection,
      snapshot,
      update,
    ],
  );

  return <ProductContextFixtureHost value={value}>{children}</ProductContextFixtureHost>;
}

export default function FixtureProductionApp() {
  const [appearance, setAppearance] = useState<AppearancePreferences>({
    theme: 'dark',
    increasedContrast: false,
    reduceTransparency: false,
    reduceMotion: new URLSearchParams(window.location.search).get('motion') !== 'standard',
    accessibleTranscript: false,
  });
  return (
    <AppearanceProvider initialPreferences={appearance} onChange={setAppearance}>
      <div className="piui" data-test-fixture="product">
        <FixtureProductProvider>
          <AppShell />
        </FixtureProductProvider>
      </div>
    </AppearanceProvider>
  );
}
