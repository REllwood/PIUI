import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { productionBridgeStore } from '../bridge/store';
import { useBridgeSelector } from '../bridge/useBridgeSelector';
import { createDeltaBatcher } from './deltaBatcher';
import { reconcileApprovals } from '../domain/approvals';
import { GENERIC_PRODUCT_ERROR, productErrorCopy, productErrorMessage } from '../domain/errors';
import { createQueueItem, failQueueItem, isTurnActive, submitApproval } from '../domain/machines';
import {
  canReconcileTranscript,
  preferredSessionModel,
  preferredSessionThinking,
  type CompletedTranscript,
} from '../domain/sessionContinuity';
import type {
  ActivityEvent,
  ApprovalDecision,
  ProductSnapshot,
  QueueItem,
  RouteId,
} from '../domain/types';
import {
  createProductSession,
  compactProductSession,
  forkProductSession,
  exportProductSession,
  inspectProductSession,
  installProductPackage,
  listProductChanges,
  listProductSettings,
  listProductResources,
  listProductSessions,
  listProductProviders,
  logoutProductProvider,
  listPendingApprovals,
  nativeHostStatus,
  nativeDiagnosticsSnapshot,
  exportNativeDiagnostics,
  productDiagnostics,
  queueProductFollowUp,
  replaceProductFollowUpQueue,
  renameProductSession,
  resumeProductSession,
  revealProductChange,
  saveProductSetting,
  sendNativeNotification,
  setProductResourceEnabled,
  mutateProductPackage,
  selectWorkspaceDirectory,
  inspectWorkspace,
  openWorkspaceUntrusted,
  authoriseWorkspace,
  discoverWorkspaceFiles,
  loadTrustedWorkspace,
  revokeWorkspace,
  openDisclosedExternal,
  presentNativeCredentialSheet,
  startProductAuthentication,
  startLocalHelper,
  startProductTurn,
  stopProductTurn,
  trashProductSession,
  submitNativeApproval,
  undoProductChange,
  type NativeProvider,
  type NativeAuthNotice,
  type NativeApproval,
  type NativeProductSession,
  type NativeProductSetting,
  type NativeEnvironmentFact,
  type NativeApplicationData,
  type NativeApplicationDataUpdate,
} from '../platform/native';

export type OperationId =
  | 'send'
  | 'stop'
  | 'queue'
  | 'approval'
  | 'settings'
  | 'diagnostics'
  | 'provider'
  | 'project'
  | 'update'
  | 'session'
  | 'export'
  | 'change'
  | 'resource';

export type ProductContextValue = Readonly<{
  snapshot: ProductSnapshot;
  route: RouteId;
  setRoute: (route: RouteId) => void;
  settingsSection: string | null;
  openSettings: (section?: string) => void;
  mode: 'simple' | 'advanced';
  setMode: (mode: 'simple' | 'advanced') => void;
  restoreLastProject: boolean;
  setRestoreLastProject: (enabled: boolean) => void;
  activeOperation: OperationId | null;
  providerAuthNotice: NativeAuthNotice | null;
  diagnosticEnvironment: readonly NativeEnvironmentFact[];
  diagnosticLogs: readonly string[];
  helperFailure: string | null;
  selectedActivity: ActivityEvent | null;
  setSelectedActivity: (activity: ActivityEvent | null) => void;
  selectedChangeId: string | null;
  setSelectedChangeId: (id: string | null) => void;
  send: (
    text: string,
    attachmentCapabilities?: readonly string[],
    retryPrevious?: boolean,
  ) => Promise<boolean>;
  stop: () => Promise<void>;
  queue: (text: string) => Promise<boolean>;
  retryQueueItem: (localId: string) => Promise<boolean>;
  removeQueueItem: (localId: string) => Promise<void>;
  decideApproval: (requestId: string, decision: ApprovalDecision) => Promise<void>;
  runDiagnostics: () => Promise<void>;
  exportDiagnostics: () => Promise<boolean>;
  reconnect: () => Promise<void>;
  createSession: () => Promise<boolean>;
  resumeSession: (sessionId: string) => Promise<void>;
  branchSession: (sessionId: string) => Promise<void>;
  renameSession: (sessionId: string, title: string) => Promise<void>;
  compactSession: (sessionId: string) => Promise<void>;
  trashSession: (sessionId: string) => Promise<void>;
  rebuildSessions: () => Promise<void>;
  connectProvider: (providerId: string) => Promise<void>;
  connectProviderApiKey: (providerId: string, providerLabel: string) => Promise<void>;
  logoutProvider: (providerId: string) => Promise<void>;
  chooseProject: () => Promise<boolean>;
  trustProject: () => Promise<void>;
  revokeProject: () => Promise<void>;
  discoverFiles: (query: string) => Promise<readonly string[]>;
  retryLastTurn: () => Promise<void>;
  exportSession: (sessionId: string) => Promise<boolean>;
  undoChange: (changeId: string) => Promise<void>;
  revealChange: (changeId: string) => Promise<void>;
  settings: readonly NativeProductSetting[];
  saveSettings: (
    drafts: readonly Readonly<{
      key: string;
      value: unknown;
      scope: 'global' | 'project';
      expectedRevision: number;
    }>[],
  ) => Promise<void>;
  setResourceEnabled: (
    resourceId: string,
    enabled: boolean,
    acknowledgedExecutableRisk: boolean,
  ) => Promise<void>;
  installPackage: (source: string, scope: 'global' | 'project') => Promise<void>;
  mutatePackage: (resourceId: string, operation: 'update' | 'remove') => Promise<void>;
}>;

const ProductContext = createContext<ProductContextValue | null>(null);

export function ProductContextFixtureHost({
  value,
  children,
}: Readonly<{ value: ProductContextValue; children: ReactNode }>) {
  if (!import.meta.env.DEV) throw new Error('fixture-provider-disabled');
  return <ProductContext.Provider value={value}>{children}</ProductContext.Provider>;
}

type StoredWorkspace = Readonly<{
  id: string;
  name: string;
  revision: number;
  trust: 'untrusted' | 'trusted' | 'revoked';
}>;

function storedWorkspace(applicationData: NativeApplicationData): StoredWorkspace | null {
  if (!applicationData.preferences.restoreLastProject) return null;
  const workspace = applicationData.recentWorkspaces[0];
  if (!workspace) return null;
  return {
    id: workspace.capabilityId,
    name: workspace.displayLabel,
    revision: workspace.workspaceRevision,
    trust: workspace.trustState,
  };
}

function providerProfile(provider: NativeProvider) {
  const mainstream =
    provider.id === 'openai-codex'
      ? 'Use an existing ChatGPT Plus or Pro subscription.'
      : provider.id.includes('anthropic')
        ? 'Use an existing Claude Pro or Max subscription.'
        : `Connect ${provider.name} using a method supported by Pi.`;
  return Object.freeze({
    id: provider.id,
    name: provider.name,
    detail: mainstream,
    ...(provider.accountLabel ? { accountLabel: provider.accountLabel } : {}),
    connected: provider.status === 'connected',
    methods: provider.methods
      .filter((method) => method.id !== 'ambient')
      .map((method) => ({ ...method, id: method.id as 'subscription' | 'api-key' })),
    models: provider.models.map((model) => ({
      id: model.id,
      name: model.name,
      reasoning: model.reasoning,
      acceptsImages: model.acceptsImages,
    })),
  });
}

function sessionSummary(session: NativeProductSession, project: string) {
  return Object.freeze({
    id: session.id,
    generation: session.generation,
    title: session.title,
    project,
    updatedAt: relativeTime(session.updatedAtUnixMs),
    status: session.writable
      ? ('active' as const)
      : session.branch
        ? ('branched' as const)
        : ('complete' as const),
    ...(session.branch ? { branch: session.branch } : {}),
    preview: session.preview,
  });
}

const relativeFormatter = new Intl.RelativeTimeFormat('en-AU', { numeric: 'auto' });
const absoluteDateFormatter = new Intl.DateTimeFormat('en-AU', { day: 'numeric', month: 'short' });

function relativeTime(timestamp: number): string {
  // A clock-skewed future timestamp is also shown as just now.
  const elapsed = Date.now() - timestamp;
  if (elapsed < 60_000) return 'Just now';
  if (elapsed < 3_600_000) {
    const minutes = Math.floor(elapsed / 60_000);
    return relativeFormatter.format(-minutes, 'minute');
  }
  if (elapsed < 86_400_000) {
    const hours = Math.floor(elapsed / 3_600_000);
    return relativeFormatter.format(-hours, 'hour');
  }
  return absoluteDateFormatter.format(new Date(timestamp));
}

function messageView(message: import('../platform/native').NativeProductMessage) {
  return Object.freeze({
    id: message.id,
    role: message.role,
    author: message.kind === 'compaction' ? 'Session' : message.role === 'user' ? 'You' : 'Pi',
    timestamp: message.timestampUnixMs
      ? new Date(message.timestampUnixMs).toLocaleTimeString('en-AU', {
          hour: 'numeric',
          minute: '2-digit',
        })
      : '',
    markdown:
      message.kind === 'compaction' ? `Session history compacted\n\n${message.text}` : message.text,
    status: 'stable' as const,
  });
}

function approvalView(approval: NativeApproval, now: number) {
  const consequential = approval.risk === 'destructive' || approval.risk === 'external';
  return Object.freeze({
    id: approval.approvalId,
    decisionId: approval.decisionId,
    revision: approval.revision,
    state: approval.state,
    action: approval.verb,
    target: approval.target,
    reason: 'Pi requested this exact action for the current turn.',
    dataLeavingMac:
      approval.risk === 'external'
        ? 'This action may communicate beyond this Mac.'
        : 'This approval covers the displayed local action only.',
    impact: consequential
      ? 'Review the target carefully; this action may be difficult to reverse.'
      : 'The action is limited to the displayed target and current request.',
    reversible: !consequential,
    // Derived once per revision; reconcileApprovals keeps it steady across polls.
    expiresAt: new Date(now + approval.expiresInMs).toISOString(),
    permittedDecisions: ['approve-once', 'deny'] as const,
    rememberedScopeEligible: false,
    scopeIds: approval.scopeIds,
    subject: approval.subject,
  });
}

export function ProductProvider({
  applicationData,
  onPersist,
  children,
}: Readonly<{
  applicationData: NativeApplicationData;
  onPersist: (update: NativeApplicationDataUpdate) => Promise<void>;
  children: ReactNode;
}>) {
  const startupData = useRef(applicationData).current;
  const snapshot = useBridgeSelector(productionBridgeStore, (state) => state.product);
  const [route, setRoute] = useState<RouteId>('conversation');
  const [settingsSection, setSettingsSection] = useState<string | null>(null);
  const [mode, setModeState] = useState<'simple' | 'advanced'>(
    applicationData.preferences.advancedMode ? 'advanced' : 'simple',
  );
  const [activeOperation, setActiveOperation] = useState<OperationId | null>(null);
  const operationLease = useRef<OperationId | null>(null);
  const beginOperation = useCallback((operation: OperationId): boolean => {
    if (operationLease.current !== null) return false;
    operationLease.current = operation;
    setActiveOperation(operation);
    return true;
  }, []);
  const endOperation = useCallback((operation: OperationId): void => {
    if (operationLease.current !== operation) return;
    operationLease.current = null;
    setActiveOperation(null);
  }, []);
  const [providerAuthNotice, setProviderAuthNotice] = useState<NativeAuthNotice | null>(null);
  const [selectedActivity, setSelectedActivity] = useState<ActivityEvent | null>(null);
  const [selectedChangeId, setSelectedChangeId] = useState<string | null>(
    snapshot.changes[0]?.id ?? null,
  );
  const [settings, setSettings] = useState<readonly NativeProductSetting[]>([]);
  const [diagnosticEnvironment, setDiagnosticEnvironment] = useState<
    readonly NativeEnvironmentFact[]
  >([]);
  const [diagnosticLogs, setDiagnosticLogs] = useState<readonly string[]>([]);
  const [helperFailure, setHelperFailure] = useState<string | null>(null);
  const activeTurnRequest = useRef<string | null>(null);
  const turnContinuity = useRef<(Readonly<{ id: string }> & { hadFollowUps: boolean }) | null>(
    null,
  );
  const [completedTranscript, setCompletedTranscript] = useState<CompletedTranscript | null>(null);
  const notifiedApprovals = useRef(new Set<string>());
  const previousTurnStatus = useRef(snapshot.turnStatus);
  const providerCatalogue = useRef<readonly NativeProvider[]>([]);
  const activeWorkspace = useRef<StoredWorkspace | null>(storedWorkspace(startupData));
  const openSettings = useCallback((section = 'general') => {
    setSettingsSection(section);
    setRoute('settings');
  }, []);

  useEffect(
    () => () => {
      turnContinuity.current = null;
    },
    [],
  );

  useEffect(() => {
    if (!completedTranscript) return undefined;
    let active = true;
    const refresh = async () => {
      try {
        const messages = await inspectProductSession(
          completedTranscript.sessionId,
          completedTranscript.generation,
        );
        if (!messages.length) throw new Error('session-history-empty');
        const live = productionBridgeStore.getSnapshot().product;
        if (!active || !canReconcileTranscript(completedTranscript, live)) return;
        productionBridgeStore.updateLocalFixture({
          messages: messages.map(messageView),
          diagnostics: live.diagnostics.filter((item) => item.id !== 'transcript-refresh'),
        });
      } catch {
        const live = productionBridgeStore.getSnapshot().product;
        if (!active || !canReconcileTranscript(completedTranscript, live)) return;
        productionBridgeStore.updateLocalFixture({
          diagnostics: [
            ...live.diagnostics.filter((item) => item.id !== 'transcript-refresh'),
            {
              id: 'transcript-refresh',
              label: 'Conversation history',
              status: 'warning',
              detail:
                'Pi finished, but the saved follow-up history could not be refreshed. The visible response has been kept.',
              recovery: 'Reopen this conversation from Sessions to load the saved message order.',
            },
          ],
        });
      } finally {
        if (active)
          setCompletedTranscript((current) => (current === completedTranscript ? null : current));
      }
    };
    // Native inspection cannot be cancelled, so cleanup retires its result before
    // it can change a newer conversation or update an unmounted provider.
    void refresh();
    return () => {
      active = false;
    };
  }, [completedTranscript]);

  useEffect(() => {
    let active = true;
    productionBridgeStore.updateLocalFixture({ connection: 'restoring' });
    void Promise.all([nativeHostStatus(), startLocalHelper()])
      .then(async ([, helper]) => {
        if (!active) return;
        if (!helper.running || helper.failed) {
          setHelperFailure(helper.failure ?? null);
          productionBridgeStore.updateLocalFixture({ connection: 'restart-offered' });
          return;
        }
        setHelperFailure(null);
        const [providers, workspace, nativeDiagnostics] = await Promise.all([
          listProductProviders(),
          Promise.resolve(storedWorkspace(startupData)),
          nativeDiagnosticsSnapshot(navigator.onLine),
        ]);
        if (!active) return;
        const profiles = providers.map(providerProfile);
        providerCatalogue.current = providers;
        activeWorkspace.current = workspace;
        const workspaceView = workspace
          ? {
              capabilityId: workspace.id,
              name: workspace.name,
              displayPath: workspace.name,
              trust: workspace.trust,
              lastOpenedAt: 'This session',
            }
          : null;
        let session: NativeProductSession | null = null;
        let sessions: readonly NativeProductSession[] = [];
        let messages: ProductSnapshot['messages'] = [];
        let activeSettings: readonly NativeProductSetting[] = [];
        let activeResources: ProductSnapshot['resources'] = [];
        let sessionFailure = false;
        const connected = providers.find(
          (provider) => provider.status === 'connected' && provider.models.length > 0,
        );
        if (workspace?.trust === 'trusted' && connected) {
          try {
            sessions = await listProductSessions(workspace.id, workspace.revision);
            if (sessions[0]) {
              session = await resumeProductSession(sessions[0].id, sessions[0].generation);
              messages = (await inspectProductSession(session.id, session.generation)).map(
                messageView,
              );
              sessions = [session, ...sessions.filter((item) => item.id !== session?.id)];
            } else {
              session = await createProductSession({
                workspaceId: workspace.id,
                expectedRevision: workspace.revision,
                title: 'New conversation',
                providerId: connected.id,
                modelId: connected.models[0]?.id,
              });
              sessions = [session];
            }
            if (session) {
              [activeSettings, activeResources] = await Promise.all([
                listProductSettings(session.id, session.generation),
                listProductResources(session.id, session.generation),
              ]);
            }
          } catch {
            sessionFailure = true;
          }
        }
        if (!active) return;
        productionBridgeStore.updateLocalFixture({
          generation: 1,
          sequence: 1,
          connection: 'ready',
          providers: profiles,
          workspace: workspaceView,
          sessions: workspace ? sessions.map((item) => sessionSummary(item, workspace.name)) : [],
          activeSessionId: session?.id ?? null,
          messages,
          turnStatus: 'idle',
          queue: [],
          activity: [],
          approvals: [],
          changes: [],
          diagnostics: [
            ...nativeDiagnostics.checks,
            {
              id: 'provider',
              label: 'Provider connection',
              status: connected ? 'pass' : 'warning',
              detail: connected
                ? `${connected.name} is connected.`
                : 'Connect a provider before sending.',
            },
            ...(sessionFailure
              ? [
                  {
                    id: 'workspace',
                    label: 'Project access',
                    status: 'warning' as const,
                    detail: 'The saved project reference must be selected again before a new turn.',
                    recovery: 'Choose the project again to renew native folder access.',
                  },
                ]
              : []),
          ],
          resources: activeResources,
        });
        setSettings(activeSettings);
        setDiagnosticEnvironment(nativeDiagnostics.environment);
        setDiagnosticLogs(nativeDiagnostics.logs);
      })
      .catch(() => {
        if (!active) return;
        productionBridgeStore.updateLocalFixture({ connection: 'restart-failed' });
        // The boot chain only reports that it failed. The host records why, so
        // read the observed reason back before the banner is shown; a failed
        // read simply leaves the banner without one.
        void nativeDiagnosticsSnapshot(navigator.onLine)
          .then((native) => {
            if (!active) return;
            setHelperFailure(native.helperFailure);
            setDiagnosticEnvironment(native.environment);
            setDiagnosticLogs(native.logs);
          })
          .catch(() => undefined);
      });
    return () => {
      active = false;
    };
  }, [startupData]);

  const refreshApprovals = useCallback(async () => {
    try {
      const approvals = await listPendingApprovals();
      const now = Date.now();
      const live = productionBridgeStore.getSnapshot().product;
      const next = reconcileApprovals(
        live.approvals,
        approvals.map((approval) => approvalView(approval, now)),
      );
      // The poll runs every 750 ms; only a real change may patch the store and re-render.
      if (next !== live.approvals) productionBridgeStore.updateLocalFixture({ approvals: next });
    } catch {
      // Connection recovery owns the global offline state. A failed background
      // refresh must not discard an approval already visible to the user.
    }
  }, []);

  useEffect(() => {
    if (snapshot.connection !== 'ready') return undefined;
    void refreshApprovals();
    const timer = window.setInterval(() => {
      void refreshApprovals();
    }, 750);
    return () => window.clearInterval(timer);
  }, [refreshApprovals, snapshot.connection]);

  useEffect(() => {
    for (const approval of snapshot.approvals) {
      if (approval.state !== 'awaiting' || notifiedApprovals.current.has(approval.id)) continue;
      notifiedApprovals.current.add(approval.id);
      void sendNativeNotification(
        'approval-waiting',
        snapshot.workspace?.name ?? 'the current project',
      ).catch(() => undefined);
    }
    const visibleIds = new Set(snapshot.approvals.map((approval) => approval.id));
    for (const approvalId of notifiedApprovals.current) {
      if (!visibleIds.has(approvalId)) notifiedApprovals.current.delete(approvalId);
    }
  }, [snapshot.approvals, snapshot.workspace?.name]);

  useEffect(() => {
    const previous = previousTurnStatus.current;
    previousTurnStatus.current = snapshot.turnStatus;
    if (isTurnActive(previous) && snapshot.turnStatus === 'complete') {
      void sendNativeNotification(
        'work-complete',
        snapshot.workspace?.name ?? 'The current project',
      ).catch(() => undefined);
    }
  }, [snapshot.turnStatus, snapshot.workspace?.name]);

  const setMode = useCallback(
    (next: 'simple' | 'advanced') => {
      setModeState(next);
      void onPersist((current) => ({
        ...current,
        preferences: { ...current.preferences, advancedMode: next === 'advanced' },
      })).catch(() => undefined);
    },
    [onPersist],
  );
  const setRestoreLastProject = useCallback(
    (enabled: boolean) => {
      void onPersist((current) => ({
        ...current,
        preferences: { ...current.preferences, restoreLastProject: enabled },
      })).catch(() => undefined);
    },
    [onPersist],
  );

  const refreshChanges = useCallback(async () => {
    const live = productionBridgeStore.getSnapshot().product;
    const session = live.sessions.find((candidate) => candidate.id === live.activeSessionId);
    if (!session) return;
    try {
      const changes = await listProductChanges(session.id, session.generation);
      productionBridgeStore.updateLocalFixture({ changes });
      setSelectedChangeId((current) =>
        changes.some((change) => change.id === current) ? current : (changes[0]?.id ?? null),
      );
    } catch {
      // A stale session is handled by the next authoritative write/recovery path.
    }
  }, []);

  const refreshProviders = useCallback(async () => {
    const providers = await listProductProviders();
    providerCatalogue.current = providers;
    productionBridgeStore.updateLocalFixture({ providers: providers.map(providerProfile) });
    return providers;
  }, []);

  const persistWorkspace = useCallback(
    async (workspace: StoredWorkspace) => {
      await onPersist((current) => ({
        ...current,
        recentWorkspaces: [
          {
            capabilityId: workspace.id,
            displayLabel: workspace.name,
            trustState: workspace.trust,
            workspaceRevision: workspace.revision,
            lastOpenedUnixMs: Date.now(),
          },
          ...current.recentWorkspaces.filter(
            (candidate) => candidate.capabilityId !== workspace.id,
          ),
        ].slice(0, 32),
      }));
    },
    [onPersist],
  );

  const connectProvider = useCallback(
    async (providerId: string) => {
      const live = productionBridgeStore.getSnapshot().product;
      if (isTurnActive(live.turnStatus)) throw new Error('turn-active');
      if (!beginOperation('provider')) throw new Error('operation-busy');
      setProviderAuthNotice(null);
      try {
        await startLocalHelper();
        let failure: string | null = null;
        await startProductAuthentication({
          providerId,
          onStarted: () => undefined,
          onNotice: (notice) => {
            setProviderAuthNotice(notice);
            const target =
              notice.type === 'opening-browser'
                ? notice.url
                : notice.type === 'device-code'
                  ? notice.verificationUri
                  : null;
            if (target) void openDisclosedExternal(target).catch(() => undefined);
          },
          onFailed: (code) => {
            failure = code;
          },
        });
        const providers = await refreshProviders();
        if (
          failure ||
          providers.find((provider) => provider.id === providerId)?.status !== 'connected'
        ) {
          throw new Error(failure ?? 'provider-validation-failed');
        }
      } finally {
        endOperation('provider');
      }
    },
    [beginOperation, endOperation, refreshProviders],
  );

  const connectProviderApiKey = useCallback(
    async (providerId: string, providerLabel: string) => {
      const live = productionBridgeStore.getSnapshot().product;
      if (isTurnActive(live.turnStatus)) throw new Error('turn-active');
      if (!beginOperation('provider')) throw new Error('operation-busy');
      setProviderAuthNotice(null);
      try {
        const result = await presentNativeCredentialSheet({
          providerId,
          providerLabel,
          accountLabel: `${providerLabel} API key`,
        });
        if (result.savedState === 'cancelled') return;
        await startLocalHelper();
        const providers = await refreshProviders();
        if (providers.find((provider) => provider.id === providerId)?.status !== 'connected') {
          throw new Error('provider-validation-failed');
        }
      } finally {
        endOperation('provider');
      }
    },
    [beginOperation, endOperation, refreshProviders],
  );

  const logoutProvider = useCallback(
    async (providerId: string) => {
      const live = productionBridgeStore.getSnapshot().product;
      if (isTurnActive(live.turnStatus)) throw new Error('turn-active');
      if (!beginOperation('provider')) throw new Error('operation-busy');
      setProviderAuthNotice(null);
      try {
        await logoutProductProvider(providerId);
        await refreshProviders();
      } finally {
        endOperation('provider');
      }
    },
    [beginOperation, endOperation, refreshProviders],
  );

  const chooseProject = useCallback(async () => {
    const live = productionBridgeStore.getSnapshot().product;
    if (isTurnActive(live.turnStatus)) {
      throw new Error('turn-active');
    }
    if (!beginOperation('project')) return false;
    try {
      await startLocalHelper();
      const selected = await selectWorkspaceDirectory();
      if (!selected) return false;
      const inspected = await inspectWorkspace(selected.workspaceId);
      const opened = await openWorkspaceUntrusted(inspected.workspaceId, inspected.revision);
      const workspace: StoredWorkspace = Object.freeze({
        id: opened.workspaceId,
        name: opened.displayLabel,
        revision: opened.revision,
        trust: opened.trustState,
      });
      activeWorkspace.current = workspace;
      setSettings([]);
      productionBridgeStore.updateLocalFixture({
        workspace: {
          capabilityId: workspace.id,
          name: workspace.name,
          displayPath: workspace.name,
          trust: workspace.trust,
          lastOpenedAt: 'Just now',
        },
        sessions: [],
        activeSessionId: null,
        messages: [],
        activity: [],
        changes: [],
        queue: [],
        turnStatus: 'idle',
        connection: 'ready',
      });
      await persistWorkspace(workspace);
      return true;
    } finally {
      endOperation('project');
    }
  }, [beginOperation, endOperation, persistWorkspace]);

  const trustProject = useCallback(async () => {
    const live = productionBridgeStore.getSnapshot().product;
    if (isTurnActive(live.turnStatus)) throw new Error('turn-active');
    const workspace = activeWorkspace.current;
    if (!workspace || workspace.trust === 'trusted') return;
    if (!beginOperation('project')) throw new Error('operation-busy');
    try {
      await startLocalHelper();
      const authorised = await authoriseWorkspace(workspace.id, workspace.revision);
      const loaded = await loadTrustedWorkspace(authorised.workspaceId, authorised.revision);
      const trusted: StoredWorkspace = Object.freeze({
        id: loaded.workspaceId,
        name: loaded.displayLabel,
        revision: loaded.revision,
        trust: loaded.trustState,
      });
      activeWorkspace.current = trusted;
      const listed = await listProductSessions(trusted.id, trusted.revision);
      productionBridgeStore.updateLocalFixture({
        workspace: {
          capabilityId: trusted.id,
          name: trusted.name,
          displayPath: trusted.name,
          trust: trusted.trust,
          lastOpenedAt: 'Just now',
        },
        sessions: listed.map((session) => sessionSummary(session, trusted.name)),
        connection: 'ready',
      });
      await persistWorkspace(trusted);
    } finally {
      endOperation('project');
    }
  }, [beginOperation, endOperation, persistWorkspace]);

  const revokeProject = useCallback(async () => {
    const live = productionBridgeStore.getSnapshot().product;
    if (isTurnActive(live.turnStatus)) {
      throw new Error('turn-active');
    }
    const workspace = activeWorkspace.current;
    if (!workspace || workspace.trust !== 'trusted') return;
    if (!beginOperation('project')) throw new Error('operation-busy');
    try {
      const revoked = await revokeWorkspace(workspace.id, workspace.revision);
      const next: StoredWorkspace = Object.freeze({
        id: revoked.workspaceId,
        name: revoked.displayLabel,
        revision: revoked.revision,
        trust: revoked.trustState,
      });
      activeWorkspace.current = next;
      setSettings([]);
      productionBridgeStore.updateLocalFixture({
        workspace: {
          capabilityId: next.id,
          name: next.name,
          displayPath: next.name,
          trust: next.trust,
          lastOpenedAt: 'Just now',
        },
        sessions: [],
        activeSessionId: null,
        messages: [],
        activity: [],
        changes: [],
        queue: [],
        turnStatus: 'idle',
        connection: 'restart-offered',
      });
      await persistWorkspace(next);
    } finally {
      endOperation('project');
    }
  }, [beginOperation, endOperation, persistWorkspace]);

  const discoverFiles = useCallback(async (query: string) => {
    const workspace = activeWorkspace.current;
    if (!workspace || workspace.trust !== 'trusted') return [];
    return discoverWorkspaceFiles(workspace.id, workspace.revision, query);
  }, []);

  const send = useCallback(
    async (text: string, attachmentCapabilities: readonly string[] = [], retryPrevious = false) => {
      const trimmed = text.trim();
      const current = productionBridgeStore.getSnapshot().product;
      const session = current.sessions.find(
        (candidate) => candidate.id === current.activeSessionId,
      );
      if (
        !trimmed ||
        current.connection !== 'ready' ||
        !session ||
        isTurnActive(current.turnStatus)
      )
        return false;
      if (!beginOperation('send')) return false;
      const now = new Date();
      const message = {
        id: `user-${crypto.randomUUID()}`,
        role: 'user' as const,
        author: 'You',
        timestamp: now.toLocaleTimeString('en-AU', { hour: 'numeric', minute: '2-digit' }),
        markdown: trimmed,
        status: 'stable' as const,
      };
      const responseId = `assistant-${crypto.randomUUID()}`;
      const continuity = { id: responseId, hadFollowUps: false };
      turnContinuity.current = continuity;
      setCompletedTranscript(null);
      const ownsTurn = () => {
        const live = productionBridgeStore.getSnapshot().product;
        return (
          turnContinuity.current === continuity &&
          live.activeSessionId === session.id &&
          live.sessions.some(
            (candidate) =>
              candidate.id === session.id && candidate.generation === session.generation,
          )
        );
      };
      const reversedUserIndex = [...current.messages]
        .reverse()
        .findIndex((item) => item.role === 'user');
      const lastUserIndex =
        reversedUserIndex < 0 ? -1 : current.messages.length - reversedUserIndex - 1;
      const retainedMessages =
        retryPrevious && lastUserIndex >= 0
          ? current.messages.slice(0, lastUserIndex)
          : current.messages.filter((item) => item.status !== 'streaming');
      productionBridgeStore.updateLocalFixture({
        messages: [
          ...retainedMessages,
          message,
          {
            id: responseId,
            role: 'assistant',
            author: 'Pi',
            timestamp: now.toLocaleTimeString('en-AU', { hour: 'numeric', minute: '2-digit' }),
            markdown: '',
            status: 'streaming',
          },
        ],
        turnStatus: 'sending',
      });
      let failed = false;
      // Streamed text reaches the store at most once per frame; every other turn event
      // flushes first so it observes the complete response so far.
      const deltas = createDeltaBatcher((text) => {
        if (!ownsTurn()) return;
        const live = productionBridgeStore.getSnapshot().product;
        productionBridgeStore.updateLocalFixture({
          messages: live.messages.map((item) =>
            item.id === responseId
              ? { ...item, markdown: `${item.markdown}${text}`, status: 'streaming' }
              : item,
          ),
          turnStatus: 'streaming',
        });
      });
      try {
        await startProductTurn({
          sessionId: session.id,
          generation: session.generation,
          text: trimmed,
          retryPrevious,
          attachmentCapabilities,
          onStarted: (requestId) => {
            if (!ownsTurn()) return;
            activeTurnRequest.current = requestId;
            productionBridgeStore.updateLocalFixture({ turnStatus: 'streaming' });
          },
          onDelta: (delta) => {
            if (!ownsTurn()) return;
            deltas.push(delta);
          },
          onTool: (toolCallId, detail, state) => {
            if (!ownsTurn()) return;
            deltas.flush();
            const live = productionBridgeStore.getSnapshot().product;
            const activityId = `activity-${toolCallId}`;
            const category = ['read', 'edit', 'write'].includes(detail)
              ? ('file' as const)
              : ['grep', 'find', 'ls'].includes(detail)
                ? ('search' as const)
                : ('command' as const);
            if (state !== 'started') {
              productionBridgeStore.updateLocalFixture({
                activity: live.activity.map((item) =>
                  item.id === activityId
                    ? {
                        ...item,
                        verb: state === 'failed' ? 'Failed' : 'Completed',
                        state: state === 'failed' ? ('failed' as const) : ('complete' as const),
                        summary:
                          state === 'failed'
                            ? 'The reviewed tool action did not complete.'
                            : 'The reviewed tool action completed.',
                      }
                    : item,
                ),
                turnStatus: 'streaming',
              });
              return;
            }
            productionBridgeStore.updateLocalFixture({
              activity: [
                ...live.activity,
                {
                  // A started tool is running; any approval it needs is polled separately
                  // and takes precedence in the work summary.
                  id: activityId,
                  category,
                  verb: 'Running',
                  target: detail,
                  state: 'running' as const,
                  elapsed: '—',
                  summary: 'Pi is using this tool.',
                },
              ],
              turnStatus: 'tool-running',
            });
            void refreshApprovals();
          },
          onFailed: (code) => {
            if (!ownsTurn()) return;
            deltas.flush();
            failed = true;
            turnContinuity.current = null;
            activeTurnRequest.current = null;
            const live = productionBridgeStore.getSnapshot().product;
            productionBridgeStore.updateLocalFixture({
              messages: live.messages.map((item) =>
                item.id === responseId
                  ? {
                      ...item,
                      markdown:
                        item.markdown ||
                        `${productErrorMessage(
                          code,
                          'Pi could not finish this turn. Try again, or open Diagnostics if it keeps happening.',
                        )} Your message remains in the conversation.`,
                      status: 'failed',
                    }
                  : item,
              ),
              turnStatus: 'failed',
              queue: [],
              ...(code === 'session-external-change'
                ? { connection: 'external-change' as const }
                : {}),
            });
            void refreshChanges();
          },
          onComplete: (terminal) => {
            if (!ownsTurn()) return;
            deltas.flush();
            turnContinuity.current = null;
            activeTurnRequest.current = null;
            const live = productionBridgeStore.getSnapshot().product;
            const messages: ProductSnapshot['messages'] = live.messages.map((item) =>
              item.id === responseId
                ? {
                    ...item,
                    status: failed ? 'failed' : terminal === 'cancelled' ? 'partial' : 'stable',
                  }
                : item,
            );
            productionBridgeStore.updateLocalFixture({
              messages,
              turnStatus: failed ? 'failed' : terminal === 'cancelled' ? 'stopped' : 'complete',
              queue: [],
            });
            if (!failed && terminal === 'complete' && continuity.hadFollowUps) {
              setCompletedTranscript({
                sessionId: session.id,
                generation: session.generation,
                messages,
              });
            }
            void refreshChanges();
          },
        });
        return true;
      } catch (error) {
        deltas.cancel();
        if (!ownsTurn()) return false;
        failed = true;
        turnContinuity.current = null;
        activeTurnRequest.current = null;
        const live = productionBridgeStore.getSnapshot().product;
        const rejection = productErrorCopy(error);
        const known = rejection.code !== GENERIC_PRODUCT_ERROR;
        productionBridgeStore.updateLocalFixture({
          messages: retainedMessages,
          turnStatus: 'failed',
          queue: [],
          diagnostics: [
            ...live.diagnostics.filter((item) => item.id !== 'turn-start'),
            {
              id: 'turn-start',
              label: 'Turn start',
              status: 'fail',
              detail: `${
                known ? rejection.message : 'The provider turn was not accepted.'
              } Your draft has been kept in the composer.`,
              recovery: known
                ? rejection.recovery
                : 'Check Diagnostics, then send the retained draft again.',
            },
          ],
        });
        return false;
      } finally {
        endOperation('send');
      }
    },
    [beginOperation, endOperation, refreshApprovals, refreshChanges],
  );

  const stop = useCallback(async () => {
    const requestId = activeTurnRequest.current;
    if (!requestId || !beginOperation('stop')) return;
    productionBridgeStore.updateLocalFixture({ turnStatus: 'stop-requested' });
    try {
      await stopProductTurn(requestId);
    } catch {
      productionBridgeStore.updateLocalFixture({ turnStatus: 'cancel-too-late' });
    } finally {
      endOperation('stop');
    }
  }, [beginOperation, endOperation]);

  const queue = useCallback(
    async (text: string) => {
      if (!text.trim()) return false;
      const live = productionBridgeStore.getSnapshot().product;
      const session = live.sessions.find((candidate) => candidate.id === live.activeSessionId);
      if (!session) return false;
      if (!beginOperation('queue')) return false;
      // Record the attempt before awaiting the receipt: a fast follow-up can
      // finish before its acknowledgement reaches this WebView.
      if (turnContinuity.current) turnContinuity.current.hadFollowUps = true;
      const item = createQueueItem(`queue-${crypto.randomUUID()}`, text);
      productionBridgeStore.updateLocalFixture({ queue: [...live.queue, item] });
      try {
        const receipt = await queueProductFollowUp({
          sessionId: session.id,
          expectedGeneration: session.generation,
          text: item.text,
        });
        const current = productionBridgeStore.getSnapshot().product;
        productionBridgeStore.updateLocalFixture({
          queue: current.queue.map((candidate) =>
            candidate.localId === item.localId
              ? { ...candidate, number: receipt.number, state: 'acknowledged' }
              : candidate,
          ),
        });
        return true;
      } catch {
        const current = productionBridgeStore.getSnapshot().product;
        productionBridgeStore.updateLocalFixture({
          queue: failQueueItem(current.queue, item.localId),
        });
        return false;
      } finally {
        endOperation('queue');
      }
    },
    [beginOperation, endOperation],
  );

  const retryQueueItem = useCallback(
    async (localId: string) => {
      const original = productionBridgeStore
        .getSnapshot()
        .product.queue.find((item) => item.localId === localId && item.state === 'failed');
      if (!original) return false;
      const acknowledged = await queue(original.text);
      if (!acknowledged) return false;
      const current = productionBridgeStore.getSnapshot().product;
      productionBridgeStore.updateLocalFixture({
        queue: current.queue.filter((item) => item.localId !== localId),
      });
      return true;
    },
    [queue],
  );

  const removeQueueItem = useCallback(
    async (localId: string) => {
      const live = productionBridgeStore.getSnapshot().product;
      const target = live.queue.find((item) => item.localId === localId);
      if (!target) return;
      if (target.state === 'failed') {
        productionBridgeStore.updateLocalFixture({
          queue: live.queue.filter((item) => item.localId !== localId),
        });
        return;
      }
      const session = live.sessions.find((candidate) => candidate.id === live.activeSessionId);
      if (!session) return;
      if (!beginOperation('queue')) return;
      try {
        const remaining = live.queue.filter(
          (item) => item.localId !== localId && item.state === 'acknowledged',
        );
        await replaceProductFollowUpQueue(
          session.id,
          session.generation,
          remaining.map((item) => item.text),
        );
        productionBridgeStore.updateLocalFixture({
          queue: remaining.map((item, index) => ({ ...item, number: index + 1 })),
        });
      } finally {
        endOperation('queue');
      }
    },
    [beginOperation, endOperation],
  );

  const decideApproval = useCallback(
    async (requestId: string, decision: ApprovalDecision) => {
      const request = snapshot.approvals.find((candidate) => candidate.id === requestId);
      if (!request) return;
      const submitting = submitApproval(request, decision, request.decisionId);
      if (submitting === request) return;
      if (!beginOperation('approval')) return;
      productionBridgeStore.updateLocalFixture({
        approvals: snapshot.approvals.map((candidate) =>
          candidate.id === requestId ? submitting : candidate,
        ),
      });
      try {
        if (decision === 'approve-project') throw new Error('remembered-approval-unsupported');
        await submitNativeApproval({
          approvalId: request.id,
          decisionId: request.decisionId,
          scopeIds: request.scopeIds ?? [],
          choice: decision,
        });
        await refreshApprovals();
      } catch {
        const live = productionBridgeStore.getSnapshot().product;
        productionBridgeStore.updateLocalFixture({
          approvals: live.approvals.map((candidate) =>
            candidate.id === requestId ? { ...candidate, state: 'unacknowledged' } : candidate,
          ),
        });
      } finally {
        endOperation('approval');
      }
    },
    [beginOperation, endOperation, snapshot.approvals, refreshApprovals],
  );

  const runDiagnostics = useCallback(async () => {
    if (!beginOperation('diagnostics')) return;
    productionBridgeStore.updateLocalFixture({
      diagnostics: snapshot.diagnostics.map((check) => ({ ...check, status: 'running' })),
    });
    try {
      const native = await nativeDiagnosticsSnapshot(navigator.onLine);
      const sidecarCheck = native.checks.find((check) => check.id === 'sidecar');
      const sidecar: Readonly<Record<string, unknown>> =
        sidecarCheck?.status === 'pass' ? await productDiagnostics() : Object.freeze({});
      setDiagnosticEnvironment(native.environment);
      setDiagnosticLogs(native.logs);
      setHelperFailure(native.helperFailure);
      const live = productionBridgeStore.getSnapshot().product;
      const connected = live.providers.some((provider) => provider.connected);
      productionBridgeStore.updateLocalFixture({
        diagnostics: [
          ...native.checks.map((check) =>
            check.id === 'sidecar' && typeof sidecar.piVersion === 'string'
              ? {
                  ...check,
                  detail: `Pi ${sidecar.piVersion} responded through the private sidecar.`,
                }
              : check,
          ),
          {
            id: 'provider',
            label: 'Provider connection',
            status: connected ? ('pass' as const) : ('warning' as const),
            detail: connected
              ? 'At least one provider is connected and reports available models.'
              : 'No provider is currently connected.',
            ...(!connected ? { recovery: 'Connect a provider in Settings.' } : {}),
          },
          {
            id: 'workspace',
            label: 'Project access',
            status: live.workspace?.trust === 'trusted' ? ('pass' as const) : ('warning' as const),
            detail:
              live.workspace?.trust === 'trusted'
                ? 'The selected project capability is trusted for this process.'
                : 'No trusted project is currently available.',
            ...(live.workspace?.trust !== 'trusted'
              ? { recovery: 'Select and explicitly trust a project in Settings.' }
              : {}),
          },
          {
            id: 'sessions',
            label: 'Session catalogue',
            status: live.sessions.length > 0 ? ('pass' as const) : ('not-run' as const),
            detail:
              live.sessions.length > 0
                ? `${live.sessions.length} session ${live.sessions.length === 1 ? 'record is' : 'records are'} available.`
                : 'Not run — select and trust a project first.',
          },
          {
            id: 'resources',
            label: 'Project resources',
            status: live.workspace?.trust === 'trusted' ? ('pass' as const) : ('not-run' as const),
            detail:
              live.workspace?.trust === 'trusted'
                ? `${live.resources.length} resource ${live.resources.length === 1 ? 'record is' : 'records are'} visible.`
                : 'Not run — resource discovery is trust-gated.',
          },
        ],
      });
    } catch {
      const live = productionBridgeStore.getSnapshot().product;
      productionBridgeStore.updateLocalFixture({
        diagnostics: live.diagnostics.map((check) => ({
          ...check,
          status: check.id === 'sidecar' ? 'fail' : check.status,
        })),
      });
    } finally {
      endOperation('diagnostics');
    }
  }, [beginOperation, endOperation, snapshot.diagnostics]);

  const exportDiagnostics = useCallback(async () => {
    if (!beginOperation('diagnostics')) return false;
    try {
      return await exportNativeDiagnostics(navigator.onLine);
    } finally {
      endOperation('diagnostics');
    }
  }, [beginOperation, endOperation]);

  const reconnect = useCallback(async () => {
    if (!beginOperation('diagnostics')) return;
    productionBridgeStore.updateLocalFixture({ connection: 'reconnecting' });
    try {
      const helper = await startLocalHelper();
      await listProductProviders();
      setHelperFailure(helper.running ? null : (helper.failure ?? null));
      productionBridgeStore.updateLocalFixture({
        connection: helper.running ? 'ready' : 'restart-failed',
      });
    } catch {
      productionBridgeStore.updateLocalFixture({ connection: 'restart-failed' });
      void nativeDiagnosticsSnapshot(navigator.onLine)
        .then((native) => setHelperFailure(native.helperFailure))
        .catch(() => undefined);
    } finally {
      endOperation('diagnostics');
    }
  }, [beginOperation, endOperation]);

  const createSession = useCallback(async () => {
    if (isTurnActive(productionBridgeStore.getSnapshot().product.turnStatus)) {
      throw new Error('turn-active');
    }
    const workspace = activeWorkspace.current;
    const model = preferredSessionModel(providerCatalogue.current, settings);
    const thinking = preferredSessionThinking(settings);
    if (!workspace || workspace.trust !== 'trusted' || !model) return false;
    if (!beginOperation('session')) throw new Error('operation-busy');
    try {
      const created = await createProductSession({
        workspaceId: workspace.id,
        expectedRevision: workspace.revision,
        title: 'New conversation',
        providerId: model.providerId,
        modelId: model.modelId,
      });
      const [settingsResult, resourcesResult] = await Promise.allSettled([
        listProductSettings(created.id, created.generation),
        listProductResources(created.id, created.generation),
      ]);
      let activeSettings = settingsResult.status === 'fulfilled' ? settingsResult.value : [];
      const activeResources = resourcesResult.status === 'fulfilled' ? resourcesResult.value : [];
      let preparationWarning =
        settingsResult.status === 'rejected' || resourcesResult.status === 'rejected';
      const currentThinking = activeSettings.find((setting) => setting.key === 'reasoning.level');
      if (thinking !== null && !currentThinking) preparationWarning = true;
      if (thinking !== null && currentThinking && currentThinking.value !== thinking) {
        try {
          const saved = await saveProductSetting(created.id, created.generation, {
            key: currentThinking.key,
            value: thinking,
            scope: currentThinking.scope,
            expectedRevision: currentThinking.revision,
          });
          activeSettings = activeSettings.map((setting) =>
            setting.key === saved.key ? saved : setting,
          );
        } catch {
          preparationWarning = true;
          try {
            activeSettings = await listProductSettings(created.id, created.generation);
          } catch {
            // A failed acknowledgement can leave the saved result uncertain.
            // Do not display the requested value as if it had been confirmed.
            activeSettings = [];
          }
        }
      }
      const live = productionBridgeStore.getSnapshot().product;
      // Creation already transferred Pi's writable session. Publish that session
      // even if a later settings/resource read fails; there is no rollback API.
      productionBridgeStore.updateLocalFixture({
        sessions: [
          sessionSummary(created, workspace.name),
          ...live.sessions.map((session) =>
            session.status === 'active' ? { ...session, status: 'complete' as const } : session,
          ),
        ],
        activeSessionId: created.id,
        messages: [],
        activity: [],
        changes: [],
        queue: [],
        resources: activeResources,
        turnStatus: 'idle',
        diagnostics: [
          ...live.diagnostics.filter((item) => item.id !== 'new-session-preferences'),
          ...(preparationWarning
            ? [
                {
                  id: 'new-session-preferences',
                  label: 'New conversation setup',
                  status: 'warning' as const,
                  detail:
                    'The conversation was created, but not all preferences or resources could be confirmed.',
                  recovery:
                    'Review Models & reasoning, or reopen this conversation from Sessions before sending.',
                },
              ]
            : []),
        ],
      });
      setSettings(activeSettings);
      setRoute('conversation');
      return true;
    } finally {
      endOperation('session');
    }
  }, [beginOperation, endOperation, settings]);

  const resumeSession = useCallback(
    async (sessionId: string) => {
      if (isTurnActive(productionBridgeStore.getSnapshot().product.turnStatus)) {
        throw new Error('turn-active');
      }
      const live = productionBridgeStore.getSnapshot().product;
      const source = live.sessions.find((candidate) => candidate.id === sessionId);
      if (!source) return;
      if (!beginOperation('session')) throw new Error('operation-busy');
      try {
        const resumed = await resumeProductSession(source.id, source.generation);
        const messages = await inspectProductSession(resumed.id, resumed.generation);
        const [activeSettings, activeResources] = await Promise.all([
          listProductSettings(resumed.id, resumed.generation),
          listProductResources(resumed.id, resumed.generation),
        ]);
        productionBridgeStore.updateLocalFixture({
          sessions: live.sessions.map((candidate) =>
            candidate.id === resumed.id
              ? sessionSummary(resumed, candidate.project)
              : candidate.status === 'active'
                ? { ...candidate, status: 'complete' as const }
                : candidate,
          ),
          activeSessionId: resumed.id,
          messages: messages.map(messageView),
          activity: [],
          changes: [],
          queue: [],
          resources: activeResources,
          turnStatus: 'idle',
          connection: 'ready',
        });
        setSettings(activeSettings);
        setRoute('conversation');
      } catch (error) {
        if (error instanceof Error && error.message.includes('external-change')) {
          productionBridgeStore.updateLocalFixture({ connection: 'external-change' });
        }
        throw error;
      } finally {
        endOperation('session');
      }
    },
    [beginOperation, endOperation],
  );

  const branchSession = useCallback(
    async (sessionId: string) => {
      if (isTurnActive(productionBridgeStore.getSnapshot().product.turnStatus)) {
        throw new Error('turn-active');
      }
      const live = productionBridgeStore.getSnapshot().product;
      const source = live.sessions.find((session) => session.id === sessionId);
      if (!source) return;
      if (!beginOperation('session')) throw new Error('operation-busy');
      try {
        const fork = await forkProductSession(source.id, source.generation);
        const [activeSettings, activeResources] = await Promise.all([
          listProductSettings(fork.id, fork.generation),
          listProductResources(fork.id, fork.generation),
        ]);
        productionBridgeStore.updateLocalFixture({
          sessions: [
            sessionSummary(fork, source.project),
            ...live.sessions.map((session) =>
              session.id === source.id ? { ...session, status: 'branched' as const } : session,
            ),
          ],
          activeSessionId: fork.id,
          messages: [],
          activity: [],
          changes: [],
          queue: [],
          resources: activeResources,
          turnStatus: 'idle',
          connection: 'ready',
        });
        setSettings(activeSettings);
        setRoute('conversation');
      } finally {
        endOperation('session');
      }
    },
    [beginOperation, endOperation],
  );

  const renameSession = useCallback(
    async (sessionId: string, title: string) => {
      if (!title.trim()) return;
      const live = productionBridgeStore.getSnapshot().product;
      if (isTurnActive(live.turnStatus)) throw new Error('turn-active');
      const source = live.sessions.find((candidate) => candidate.id === sessionId);
      if (!source) return;
      if (!beginOperation('settings')) throw new Error('operation-busy');
      try {
        const renamed = await renameProductSession(source.id, source.generation, title.trim());
        productionBridgeStore.updateLocalFixture({
          sessions: live.sessions.map((candidate) =>
            candidate.id === renamed.id ? sessionSummary(renamed, candidate.project) : candidate,
          ),
        });
      } finally {
        endOperation('settings');
      }
    },
    [beginOperation, endOperation],
  );

  const compactSession = useCallback(
    async (sessionId: string) => {
      const live = productionBridgeStore.getSnapshot().product;
      if (isTurnActive(live.turnStatus)) throw new Error('turn-active');
      const session = live.sessions.find((candidate) => candidate.id === sessionId);
      if (!session) return;
      if (!beginOperation('session')) throw new Error('operation-busy');
      try {
        await compactProductSession(session.id, session.generation);
        const messages = await inspectProductSession(session.id, session.generation);
        productionBridgeStore.updateLocalFixture({ messages: messages.map(messageView) });
      } finally {
        endOperation('session');
      }
    },
    [beginOperation, endOperation],
  );

  const trashSession = useCallback(
    async (sessionId: string) => {
      const live = productionBridgeStore.getSnapshot().product;
      if (isTurnActive(live.turnStatus)) throw new Error('turn-active');
      const session = live.sessions.find((candidate) => candidate.id === sessionId);
      if (!session || session.id === live.activeSessionId || session.status === 'active') {
        throw new Error('session-trash-active');
      }
      if (!beginOperation('session')) throw new Error('operation-busy');
      try {
        await trashProductSession(session.id, session.generation);
        const current = productionBridgeStore.getSnapshot().product;
        productionBridgeStore.updateLocalFixture({
          sessions: current.sessions.filter((candidate) => candidate.id !== session.id),
        });
      } finally {
        endOperation('session');
      }
    },
    [beginOperation, endOperation],
  );

  const rebuildSessions = useCallback(async () => {
    const workspace = activeWorkspace.current;
    if (!workspace) return;
    if (!beginOperation('session')) throw new Error('operation-busy');
    try {
      const listed = await listProductSessions(workspace.id, workspace.revision);
      const live = productionBridgeStore.getSnapshot().product;
      const active = live.sessions.find((candidate) => candidate.id === live.activeSessionId);
      productionBridgeStore.updateLocalFixture({
        sessions: listed.map((session) => {
          const summary = sessionSummary(session, workspace.name);
          return active?.id === summary.id
            ? { ...summary, generation: active.generation, status: 'active' as const }
            : summary;
        }),
      });
    } finally {
      endOperation('session');
    }
  }, [beginOperation, endOperation]);

  const retryLastTurn = useCallback(async () => {
    const live = productionBridgeStore.getSnapshot().product;
    const lastUser = [...live.messages].reverse().find((message) => message.role === 'user');
    if (!lastUser) return;
    await send(lastUser.markdown, [], true);
  }, [send]);

  const exportSession = useCallback(
    async (sessionId: string) => {
      const session = productionBridgeStore
        .getSnapshot()
        .product.sessions.find((candidate) => candidate.id === sessionId);
      if (!session) return false;
      if (isTurnActive(productionBridgeStore.getSnapshot().product.turnStatus)) {
        throw new Error('turn-active');
      }
      if (!beginOperation('export')) return false;
      try {
        return await exportProductSession(session.id, session.generation);
      } finally {
        endOperation('export');
      }
    },
    [beginOperation, endOperation],
  );

  const undoChange = useCallback(
    async (changeId: string) => {
      const live = productionBridgeStore.getSnapshot().product;
      const session = live.sessions.find((candidate) => candidate.id === live.activeSessionId);
      const change = live.changes.find((candidate) => candidate.id === changeId);
      if (!session || !change || change.undo !== 'safe') return;
      if (!beginOperation('change')) throw new Error('operation-busy');
      productionBridgeStore.updateLocalFixture({
        changes: live.changes.map((candidate) =>
          candidate.id === changeId ? { ...candidate, undo: 'submitting' as const } : candidate,
        ),
      });
      try {
        const updated = await undoProductChange(session.id, session.generation, changeId);
        const current = productionBridgeStore.getSnapshot().product;
        productionBridgeStore.updateLocalFixture({
          changes: current.changes.map((candidate) =>
            candidate.id === changeId ? updated : candidate,
          ),
        });
      } catch {
        const current = productionBridgeStore.getSnapshot().product;
        productionBridgeStore.updateLocalFixture({
          changes: current.changes.map((candidate) =>
            candidate.id === changeId ? { ...candidate, undo: 'revoked' as const } : candidate,
          ),
        });
      } finally {
        endOperation('change');
      }
    },
    [beginOperation, endOperation],
  );

  const revealChange = useCallback(
    async (changeId: string) => {
      const live = productionBridgeStore.getSnapshot().product;
      const session = live.sessions.find((candidate) => candidate.id === live.activeSessionId);
      if (!session || !live.changes.some((candidate) => candidate.id === changeId)) return;
      if (!beginOperation('change')) throw new Error('operation-busy');
      try {
        await revealProductChange(session.id, session.generation, changeId);
      } finally {
        endOperation('change');
      }
    },
    [beginOperation, endOperation],
  );

  const saveSettings = useCallback(
    async (
      drafts: readonly Readonly<{
        key: string;
        value: unknown;
        scope: 'global' | 'project';
        expectedRevision: number;
      }>[],
    ) => {
      if (drafts.length === 0) return;
      const live = productionBridgeStore.getSnapshot().product;
      if (isTurnActive(live.turnStatus)) throw new Error('turn-active');
      const session = live.sessions.find((candidate) => candidate.id === live.activeSessionId);
      if (!session) throw new Error('session-unavailable');
      if (!beginOperation('settings')) throw new Error('operation-busy');
      try {
        const ordered = [...drafts].sort((left, right) => {
          const rank = (key: string) => (key === 'model.provider' ? 0 : key === 'model.id' ? 1 : 2);
          return rank(left.key) - rank(right.key);
        });
        for (const draft of ordered) {
          await saveProductSetting(session.id, session.generation, draft);
        }
        setSettings(await listProductSettings(session.id, session.generation));
      } catch (error) {
        setSettings(await listProductSettings(session.id, session.generation));
        throw error;
      } finally {
        endOperation('settings');
      }
    },
    [beginOperation, endOperation],
  );

  const setResourceEnabled = useCallback(
    async (resourceId: string, enabled: boolean, acknowledgedExecutableRisk: boolean) => {
      const live = productionBridgeStore.getSnapshot().product;
      if (isTurnActive(live.turnStatus)) throw new Error('turn-active');
      const session = live.sessions.find((candidate) => candidate.id === live.activeSessionId);
      if (!session) throw new Error('session-unavailable');
      if (!beginOperation('resource')) throw new Error('operation-busy');
      try {
        await setProductResourceEnabled(
          session.id,
          session.generation,
          resourceId,
          enabled,
          acknowledgedExecutableRisk,
        );
        productionBridgeStore.updateLocalFixture({
          resources: await listProductResources(session.id, session.generation),
        });
      } finally {
        endOperation('resource');
      }
    },
    [beginOperation, endOperation],
  );

  const installPackage = useCallback(
    async (source: string, scope: 'global' | 'project') => {
      const live = productionBridgeStore.getSnapshot().product;
      if (isTurnActive(live.turnStatus)) throw new Error('turn-active');
      const session = live.sessions.find((candidate) => candidate.id === live.activeSessionId);
      if (!session) throw new Error('session-unavailable');
      if (!beginOperation('resource')) throw new Error('operation-busy');
      try {
        await installProductPackage(
          session.id,
          session.generation,
          source,
          scope,
          navigator.onLine,
        );
        productionBridgeStore.updateLocalFixture({
          resources: await listProductResources(session.id, session.generation),
        });
      } finally {
        endOperation('resource');
      }
    },
    [beginOperation, endOperation],
  );

  const mutatePackage = useCallback(
    async (resourceId: string, operation: 'update' | 'remove') => {
      const live = productionBridgeStore.getSnapshot().product;
      if (isTurnActive(live.turnStatus)) throw new Error('turn-active');
      const session = live.sessions.find((candidate) => candidate.id === live.activeSessionId);
      if (!session) throw new Error('session-unavailable');
      if (!beginOperation('resource')) throw new Error('operation-busy');
      try {
        await mutateProductPackage(
          session.id,
          session.generation,
          resourceId,
          operation,
          navigator.onLine,
        );
        productionBridgeStore.updateLocalFixture({
          resources: await listProductResources(session.id, session.generation),
        });
      } finally {
        endOperation('resource');
      }
    },
    [beginOperation, endOperation],
  );

  const value = useMemo<ProductContextValue>(
    () => ({
      snapshot,
      route,
      setRoute,
      settingsSection,
      openSettings,
      mode,
      setMode,
      restoreLastProject: applicationData.preferences.restoreLastProject,
      setRestoreLastProject,
      activeOperation,
      providerAuthNotice,
      diagnosticEnvironment,
      diagnosticLogs,
      helperFailure,
      selectedActivity,
      setSelectedActivity,
      selectedChangeId,
      setSelectedChangeId,
      send,
      stop,
      queue,
      retryQueueItem,
      removeQueueItem,
      decideApproval,
      runDiagnostics,
      exportDiagnostics,
      reconnect,
      createSession,
      resumeSession,
      branchSession,
      renameSession,
      compactSession,
      trashSession,
      rebuildSessions,
      connectProvider,
      connectProviderApiKey,
      logoutProvider,
      chooseProject,
      trustProject,
      revokeProject,
      discoverFiles,
      retryLastTurn,
      exportSession,
      undoChange,
      revealChange,
      settings,
      saveSettings,
      setResourceEnabled,
      installPackage,
      mutatePackage,
    }),
    [
      snapshot,
      route,
      settingsSection,
      openSettings,
      mode,
      setMode,
      applicationData.preferences.restoreLastProject,
      setRestoreLastProject,
      activeOperation,
      providerAuthNotice,
      diagnosticEnvironment,
      diagnosticLogs,
      helperFailure,
      selectedActivity,
      selectedChangeId,
      send,
      stop,
      queue,
      retryQueueItem,
      removeQueueItem,
      decideApproval,
      runDiagnostics,
      exportDiagnostics,
      reconnect,
      createSession,
      resumeSession,
      branchSession,
      renameSession,
      compactSession,
      trashSession,
      rebuildSessions,
      connectProvider,
      connectProviderApiKey,
      logoutProvider,
      chooseProject,
      trustProject,
      revokeProject,
      discoverFiles,
      retryLastTurn,
      exportSession,
      undoChange,
      revealChange,
      settings,
      saveSettings,
      setResourceEnabled,
      installPackage,
      mutatePackage,
    ],
  );

  return <ProductContext.Provider value={value}>{children}</ProductContext.Provider>;
}

export function useProduct(): ProductContextValue {
  const context = useContext(ProductContext);
  if (!context) throw new Error('ProductProvider is missing');
  return context;
}
