import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

export type NativeWorkspaceSummary = Readonly<{
  workspaceId: string;
  displayLabel: string;
  revision: number;
  trustState: 'untrusted' | 'trusted' | 'revoked';
  resourceState:
    | 'not-loaded'
    | 'preparing'
    | 'loading'
    | 'loaded'
    | 'failed-closed'
    | 'execution-uncertain'
    | 'revoked-prior-effects';
}>;

export type NativeApplicationData = Readonly<{
  version: 1;
  preferences: Readonly<{
    theme: 'system' | 'light' | 'dark';
    advancedMode: boolean;
    restoreLastProject: boolean;
    increasedContrast: boolean;
    reduceTransparency: boolean;
    reduceMotion: boolean;
    accessibleTranscript: boolean;
  }>;
  onboarding: Readonly<{
    completedSteps: readonly string[];
    finished: boolean;
  }>;
  recentWorkspaces: readonly Readonly<{
    capabilityId: string;
    displayLabel: string;
    trustState: 'untrusted' | 'trusted' | 'revoked';
    workspaceRevision: number;
    lastOpenedUnixMs: number;
  }>[];
  window: Readonly<{ width: number; height: number; maximised: boolean }> | null;
}>;

export type NativeApplicationDataUpdate =
  | NativeApplicationData
  | ((current: NativeApplicationData) => NativeApplicationData);

export const defaultNativeApplicationData: NativeApplicationData = Object.freeze({
  version: 1,
  preferences: Object.freeze({
    theme: 'system',
    advancedMode: false,
    restoreLastProject: true,
    increasedContrast: false,
    reduceTransparency: false,
    reduceMotion: false,
    accessibleTranscript: false,
  }),
  onboarding: Object.freeze({ completedSteps: Object.freeze([]), finished: false }),
  recentWorkspaces: Object.freeze([]),
  window: null,
});

export type NativeProvider = Readonly<{
  id: string;
  name: string;
  methods: readonly Readonly<{
    id: 'subscription' | 'api-key' | 'ambient';
    label: string;
    classification: 'recommended' | 'supported' | 'fallback';
  }>[];
  models: readonly Readonly<{
    id: string;
    name: string;
    reasoning: boolean;
    acceptsImages: boolean;
    contextWindow: number;
  }>[];
  status: 'connected' | 'not-connected' | 'unknown';
  accountLabel?: string;
}>;

export type NativeProductSession = Readonly<{
  id: string;
  generation: number;
  title: string;
  workspaceId: string;
  writable: boolean;
  branch?: string;
  updatedAtUnixMs: number;
  preview: string;
  messageCount: number;
}>;

export type NativeProductMessage = Readonly<{
  id: string;
  role: 'user' | 'assistant' | 'system';
  timestampUnixMs: number;
  text: string;
  kind: 'message' | 'compaction';
}>;

export type NativeProductChange = Readonly<{
  id: string;
  path: string;
  state: 'added' | 'modified' | 'deleted' | 'binary' | 'failed';
  additions: number;
  deletions: number;
  before: readonly string[];
  after: readonly string[];
  undo: 'safe' | 'revoked' | 'complete';
}>;

export type NativeProductSetting = Readonly<{
  key: string;
  value: unknown;
  scope: 'global' | 'project';
  revision: number;
  origin: string;
}>;

export type NativeProductResource = Readonly<{
  id: string;
  kind: 'skill' | 'prompt' | 'theme' | 'extension' | 'package';
  name: string;
  version: string;
  source: 'global' | 'project' | 'package';
  trusted: boolean;
  enabled: boolean;
  executable: boolean;
  description: string;
  contributedSettings: readonly string[];
  operations: readonly ('enable' | 'disable' | 'install' | 'update' | 'remove')[];
}>;

export type NativeDiagnosticCheck = Readonly<{
  id: string;
  label: string;
  status: 'not-run' | 'running' | 'pass' | 'warning' | 'fail' | 'offline';
  detail: string;
  recovery?: string;
}>;

export type NativeEnvironmentFact = Readonly<{
  key: string;
  value: string;
  origin: string;
}>;

export type NativeDiagnosticsSnapshot = Readonly<{
  checks: readonly NativeDiagnosticCheck[];
  environment: readonly NativeEnvironmentFact[];
  logs: readonly string[];
  helperFailure: string | null;
}>;

export const APPROVAL_SUBJECT_LABELS = [
  'Command',
  'File',
  'Folder',
  'Pattern',
  'Address',
  'Search',
] as const;
export const MAX_APPROVAL_SUBJECT_UTF16 = 2_000;

// Exactly what the approval would run or change, as plain text for display only.
export type NativeApprovalSubject = Readonly<{
  label: (typeof APPROVAL_SUBJECT_LABELS)[number];
  text: string;
  truncated: boolean;
}>;

export type NativeApproval = Readonly<{
  approvalId: string;
  decisionId: string;
  revision: number;
  state:
    | 'policy-check'
    | 'awaiting'
    | 'submitting'
    | 'approved'
    | 'denied'
    | 'expired'
    | 'cancelled';
  verb: string;
  target: string;
  risk: 'routine' | 'sensitive' | 'destructive' | 'external' | 'deny-only';
  scopeIds: readonly string[];
  expiresInMs: number;
  subject: NativeApprovalSubject | null;
}>;

type StreamEnvelope = Readonly<{
  correlationId?: string;
  payload?: Readonly<{
    eventType?: string;
    text?: string;
    terminal?: string;
    code?: string;
    toolCallId?: string;
  }>;
}>;

export type NativeAuthNotice =
  | Readonly<{ type: 'opening-browser'; url: string; instructions?: string }>
  | Readonly<{
      type: 'device-code';
      verificationUri: string;
      userCode: string;
      expiresInSeconds?: number;
    }>
  | Readonly<{ type: 'progress'; message: string }>
  | Readonly<{ type: 'validated'; providerId: string; accountLabel: string }>;

export async function sendNativeNotification(
  kind: 'approval-waiting' | 'work-complete',
  contextLabel: string,
): Promise<boolean> {
  return invoke<boolean>('notification_send', { request: { kind, contextLabel } });
}

export async function selectWorkspaceDirectory(): Promise<NativeWorkspaceSummary | null> {
  const result = await invoke<unknown>('workspace_select_directory', { request: {} });
  return result === null ? null : validateWorkspaceSummary(result);
}

export async function inspectWorkspace(workspaceId: string): Promise<NativeWorkspaceSummary> {
  return validateWorkspaceSummary(await invoke<unknown>('workspace_inspect', { workspaceId }));
}

export async function openWorkspaceUntrusted(
  workspaceId: string,
  expectedRevision: number,
): Promise<NativeWorkspaceSummary> {
  return validateWorkspaceSummary(
    await invoke<unknown>('workspace_open_untrusted', { workspaceId, expectedRevision }),
  );
}

export async function authoriseWorkspace(
  workspaceId: string,
  expectedRevision: number,
): Promise<NativeWorkspaceSummary> {
  return validateWorkspaceSummary(
    await invoke<unknown>('workspace_authorise', { workspaceId, expectedRevision }),
  );
}

export async function loadTrustedWorkspace(
  workspaceId: string,
  expectedRevision: number,
): Promise<NativeWorkspaceSummary> {
  return validateWorkspaceSummary(
    await invoke<unknown>('workspace_load_trusted', { workspaceId, expectedRevision }),
  );
}

export async function revokeWorkspace(
  workspaceId: string,
  expectedRevision: number,
): Promise<NativeWorkspaceSummary> {
  return validateWorkspaceSummary(
    await invoke<unknown>('workspace_revoke', { workspaceId, expectedRevision }),
  );
}

export async function discoverWorkspaceFiles(
  workspaceId: string,
  expectedRevision: number,
  query: string,
): Promise<readonly string[]> {
  const result = await invoke<unknown>('workspace_discover_files', {
    requestData: { workspaceId, expectedRevision, query },
  });
  if (
    !Array.isArray(result) ||
    result.length > 100 ||
    !result.every(
      (path) =>
        typeof path === 'string' &&
        path.length > 0 &&
        path.length <= 1_024 &&
        !path.startsWith('/') &&
        !path.split('/').some((segment) => segment === '..') &&
        !/\p{Cc}/u.test(path),
    )
  ) {
    throw new Error('workspace-file-discovery-response-invalid');
  }
  return Object.freeze([...(result as string[])]);
}

export async function listProductProviders(): Promise<readonly NativeProvider[]> {
  const result = await invoke<unknown>('product_list_providers');
  if (!isRecord(result) || result.schemaVersion !== 1 || !Array.isArray(result.providers)) {
    throw new Error('provider-response-invalid');
  }
  return result.providers.map(validateProvider);
}

export async function logoutProductProvider(providerId: string): Promise<void> {
  const result = await invoke<unknown>('product_logout_provider', { requestData: { providerId } });
  if (!isRecord(result) || result.schemaVersion !== 1 || result.loggedOut !== true) {
    throw new Error('provider-logout-response-invalid');
  }
}

export async function createProductSession(
  request: Readonly<{
    workspaceId: string;
    expectedRevision: number;
    title?: string;
    providerId?: string;
    modelId?: string;
  }>,
): Promise<NativeProductSession> {
  const result = await invoke<unknown>('product_create_session', { requestData: request });
  if (!isRecord(result) || result.schemaVersion !== 1) throw new Error('session-response-invalid');
  return validateSession(result.session);
}

export async function listProductSessions(
  workspaceId: string,
  expectedRevision: number,
): Promise<readonly NativeProductSession[]> {
  const result = await invoke<unknown>('product_list_sessions', {
    requestData: { workspaceId, expectedRevision },
  });
  if (!isRecord(result) || result.schemaVersion !== 1 || !Array.isArray(result.sessions)) {
    throw new Error('session-list-response-invalid');
  }
  return Object.freeze(result.sessions.map(validateSession));
}

export async function resumeProductSession(
  sessionId: string,
  expectedGeneration: number,
): Promise<NativeProductSession> {
  return productSessionReference('product_resume_session', sessionId, expectedGeneration);
}

export async function forkProductSession(
  sessionId: string,
  expectedGeneration: number,
): Promise<NativeProductSession> {
  return productSessionReference('product_fork_session', sessionId, expectedGeneration);
}

export async function renameProductSession(
  sessionId: string,
  expectedGeneration: number,
  title: string,
): Promise<NativeProductSession> {
  const result = await invoke<unknown>('product_rename_session', {
    requestData: { sessionId, expectedGeneration, title },
  });
  if (!isRecord(result) || result.schemaVersion !== 1) throw new Error('session-response-invalid');
  return validateSession(result.session);
}

export async function inspectProductSession(
  sessionId: string,
  expectedGeneration: number,
): Promise<readonly NativeProductMessage[]> {
  const result = await invoke<unknown>('product_inspect_session', {
    requestData: { sessionId, expectedGeneration },
  });
  if (!isRecord(result) || result.schemaVersion !== 1 || !Array.isArray(result.messages)) {
    throw new Error('session-inspect-response-invalid');
  }
  return Object.freeze(result.messages.map(validateProductMessage));
}

export async function compactProductSession(
  sessionId: string,
  expectedGeneration: number,
): Promise<void> {
  const result = await invoke<unknown>('product_compact_session', {
    requestData: { sessionId, expectedGeneration },
  });
  if (!isRecord(result) || result.schemaVersion !== 1 || result.compacted !== true) {
    throw new Error('session-compact-response-invalid');
  }
}

export async function trashProductSession(
  sessionId: string,
  expectedGeneration: number,
): Promise<boolean> {
  const result = await invoke<unknown>('product_trash_session', {
    requestData: { sessionId, expectedGeneration },
  });
  if (result !== true) throw new Error('session-trash-response-invalid');
  return true;
}

export async function listProductChanges(
  sessionId: string,
  expectedGeneration: number,
): Promise<readonly NativeProductChange[]> {
  const result = await invoke<unknown>('product_list_changes', {
    requestData: { sessionId, expectedGeneration },
  });
  if (!isRecord(result) || result.schemaVersion !== 1 || !Array.isArray(result.changes)) {
    throw new Error('change-list-response-invalid');
  }
  return Object.freeze(result.changes.map(validateProductChange));
}

export async function undoProductChange(
  sessionId: string,
  expectedGeneration: number,
  changeId: string,
): Promise<NativeProductChange> {
  const result = await invoke<unknown>('product_undo_change', {
    requestData: { sessionId, expectedGeneration, changeId },
  });
  if (!isRecord(result) || result.schemaVersion !== 1) throw new Error('change-response-invalid');
  return validateProductChange(result.change);
}

export async function revealProductChange(
  sessionId: string,
  expectedGeneration: number,
  changeId: string,
): Promise<void> {
  await invoke('product_reveal_change', {
    requestData: { sessionId, expectedGeneration, changeId },
  });
}

export async function listProductSettings(
  sessionId: string,
  expectedGeneration: number,
): Promise<readonly NativeProductSetting[]> {
  const result = await invoke<unknown>('product_list_settings', {
    requestData: { sessionId, expectedGeneration },
  });
  if (!isRecord(result) || result.schemaVersion !== 1 || !Array.isArray(result.settings)) {
    throw new Error('setting-list-response-invalid');
  }
  return Object.freeze(result.settings.map(validateProductSetting));
}

export async function listProductResources(
  sessionId: string,
  expectedGeneration: number,
): Promise<readonly NativeProductResource[]> {
  const result = await invoke<unknown>('product_list_resources', {
    requestData: { sessionId, expectedGeneration },
  });
  if (!isRecord(result) || result.schemaVersion !== 1 || !Array.isArray(result.resources)) {
    throw new Error('resource-list-response-invalid');
  }
  return Object.freeze(result.resources.map(validateProductResource));
}

export async function setProductResourceEnabled(
  sessionId: string,
  expectedGeneration: number,
  resourceId: string,
  enabled: boolean,
  acknowledgedExecutableRisk: boolean,
): Promise<NativeProductResource> {
  const result = await invoke<unknown>('product_set_resource_enabled', {
    requestData: {
      sessionId,
      expectedGeneration,
      resourceId,
      enabled,
      acknowledgedExecutableRisk,
    },
  });
  if (!isRecord(result) || result.schemaVersion !== 1) {
    throw new Error('resource-response-invalid');
  }
  return validateProductResource(result.resource);
}

export async function installProductPackage(
  sessionId: string,
  expectedGeneration: number,
  source: string,
  scope: 'global' | 'project',
  online: boolean,
): Promise<NativeProductResource> {
  const result = await invoke<unknown>('product_install_package', {
    requestData: {
      sessionId,
      expectedGeneration,
      source,
      scope,
      online,
      acknowledgedExecutableRisk: true,
    },
  });
  if (!isRecord(result) || result.schemaVersion !== 1) {
    throw new Error('resource-response-invalid');
  }
  return validateProductResource(result.resource);
}

export async function mutateProductPackage(
  sessionId: string,
  expectedGeneration: number,
  resourceId: string,
  operation: 'update' | 'remove',
  online: boolean,
): Promise<NativeProductResource | null> {
  const result = await invoke<unknown>('product_mutate_package', {
    requestData: {
      sessionId,
      expectedGeneration,
      resourceId,
      operation,
      online,
      acknowledgedExecutableRisk: true,
    },
  });
  if (!isRecord(result) || result.schemaVersion !== 1) {
    throw new Error('resource-response-invalid');
  }
  return result.resource === null ? null : validateProductResource(result.resource);
}

export async function saveProductSetting(
  sessionId: string,
  expectedGeneration: number,
  setting: Readonly<{
    key: string;
    value: unknown;
    scope: 'global' | 'project';
    expectedRevision: number;
  }>,
): Promise<NativeProductSetting> {
  const result = await invoke<unknown>('product_save_setting', {
    requestData: { sessionId, expectedGeneration, ...setting },
  });
  if (!isRecord(result) || result.schemaVersion !== 1) throw new Error('setting-response-invalid');
  return validateProductSetting(result.setting);
}

export async function previewProductSettingReset(
  sessionId: string,
  expectedGeneration: number,
  key: string,
): Promise<Readonly<{ key: string; current: unknown; next: null }>> {
  const result = await invoke<unknown>('product_preview_setting_reset', {
    requestData: { sessionId, expectedGeneration, key },
  });
  if (
    !isRecord(result) ||
    result.schemaVersion !== 1 ||
    !isRecord(result.preview) ||
    result.preview.key !== key ||
    result.preview.next !== null
  ) {
    throw new Error('setting-preview-response-invalid');
  }
  return Object.freeze({ key, current: result.preview.current, next: null });
}

export async function exportProductSession(
  sessionId: string,
  expectedGeneration: number,
): Promise<boolean> {
  return invoke<boolean>('product_session_export', {
    requestData: { sessionId, expectedGeneration },
  });
}

export async function queueProductFollowUp(
  request: Readonly<{
    sessionId: string;
    expectedGeneration: number;
    text: string;
  }>,
): Promise<Readonly<{ queueId: string; number: number }>> {
  const result = await invoke<unknown>('product_queue_follow_up', { requestData: request });
  if (
    !isRecord(result) ||
    result.schemaVersion !== 1 ||
    !isRecord(result.queue) ||
    typeof result.queue.queueId !== 'string' ||
    !/^queue-[a-f0-9]{32}$/u.test(result.queue.queueId) ||
    !Number.isSafeInteger(result.queue.number) ||
    (result.queue.number as number) <= 0
  ) {
    throw new Error('queue-response-invalid');
  }
  return Object.freeze({ queueId: result.queue.queueId, number: result.queue.number as number });
}

export async function replaceProductFollowUpQueue(
  sessionId: string,
  expectedGeneration: number,
  texts: readonly string[],
): Promise<number> {
  const result = await invoke<unknown>('product_replace_follow_up_queue', {
    requestData: { sessionId, expectedGeneration, texts: [...texts] },
  });
  if (
    !isRecord(result) ||
    result.schemaVersion !== 1 ||
    !isRecord(result.queue) ||
    !Number.isSafeInteger(result.queue.count) ||
    result.queue.count !== texts.length
  ) {
    throw new Error('queue-replace-response-invalid');
  }
  return result.queue.count as number;
}

// Events that arrive before the host acknowledges the turn are held, up to this bound.
export const MAX_PENDING_TURN_EVENTS = 4_096;
// Slightly above the host's 900 s turn deadline.
export const TURN_TERMINAL_TIMEOUT_MS = 910_000;

export async function startProductTurn(
  request: Readonly<{
    sessionId: string;
    generation: number;
    text: string;
    retryPrevious?: boolean;
    attachmentCapabilities?: readonly string[];
    onStarted: (requestId: string) => void;
    onDelta: (text: string) => void;
    onTool: (toolCallId: string, text: string, state: 'started' | 'complete' | 'failed') => void;
    onFailed: (code: string) => void;
    onComplete: (terminal: 'complete' | 'cancelled') => void;
  }>,
): Promise<string> {
  const requestId = `web-turn-${crypto.randomUUID().replaceAll('-', '')}`;
  let unlisten: UnlistenFn | undefined;
  let accepted = false;
  let finished = false;
  let overflowed = false;
  let terminalTimer: ReturnType<typeof setTimeout> | undefined;
  const pending: StreamEnvelope[] = [];

  const finishListening = () => {
    if (finished) return;
    finished = true;
    if (terminalTimer !== undefined) clearTimeout(terminalTimer);
    terminalTimer = undefined;
    pending.length = 0;
    unlisten?.();
    unlisten = undefined;
  };

  // Stops listening before notifying, so a throwing callback cannot leave the listener behind.
  const settle = (notify: () => void) => {
    if (finished) return;
    finishListening();
    notify();
  };

  // The turn can no longer be followed faithfully, so it is reported as failed and the
  // host is asked to stop it rather than letting it continue out of sight.
  const abandon = (code: string) => {
    settle(() => request.onFailed(code));
    void invoke('product_turn_stop', { requestData: { requestId } }).catch(() => undefined);
  };

  const handleEnvelope = (envelope: StreamEnvelope) => {
    if (
      finished ||
      !isRecord(envelope) ||
      envelope.correlationId !== requestId ||
      !isRecord(envelope.payload)
    )
      return;
    if (!accepted) {
      if (pending.length < MAX_PENDING_TURN_EVENTS) pending.push(envelope);
      else overflowed = true;
      return;
    }
    const event = envelope.payload;
    if (event.eventType === 'stream.delta' && typeof event.text === 'string')
      request.onDelta(event.text);
    else if (
      event.eventType === 'tool.activity' &&
      typeof event.toolCallId === 'string' &&
      /^[A-Za-z0-9._:-]{1,160}$/u.test(event.toolCallId) &&
      typeof event.text === 'string' &&
      ['started', 'complete', 'failed'].includes(String(event.code))
    )
      request.onTool(
        event.toolCallId,
        event.text,
        event.code as 'started' | 'complete' | 'failed',
      );
    else if (event.eventType === 'stream.failed') {
      const code = typeof event.code === 'string' ? event.code : 'provider-turn-failed';
      settle(() => request.onFailed(code));
    } else if (event.eventType === 'stream.complete') {
      settle(() => request.onComplete('complete'));
    } else if (event.eventType === 'stream.cancelled') {
      settle(() => request.onComplete('cancelled'));
    }
  };

  try {
    unlisten = await listen<StreamEnvelope>('piui://stream-probe', ({ payload: envelope }) => {
      handleEnvelope(envelope);
    });
    await invoke('product_turn_start', {
      requestData: {
        requestId,
        sessionId: request.sessionId,
        generation: request.generation,
        text: request.text,
        retryPrevious: request.retryPrevious === true,
        attachmentCapabilities: [...(request.attachmentCapabilities ?? [])],
      },
    });
  } catch (error) {
    finishListening();
    throw error;
  }
  accepted = true;
  // The host ends every turn by its own deadline; a turn still silent after that is
  // treated as lost so its listener cannot outlive it.
  terminalTimer = setTimeout(() => abandon('turn-terminal-timeout'), TURN_TERMINAL_TIMEOUT_MS);
  request.onStarted(requestId);
  if (overflowed) {
    abandon('turn-events-overflowed');
    return requestId;
  }
  for (const envelope of pending.splice(0)) handleEnvelope(envelope);
  return requestId;
}

export async function startProductAuthentication(
  request: Readonly<{
    providerId: string;
    onStarted: (requestId: string) => void;
    onNotice: (notice: NativeAuthNotice) => void;
    onFailed: (code: string) => void;
  }>,
): Promise<string> {
  const requestId = `web-auth-${crypto.randomUUID().replaceAll('-', '')}`;
  request.onStarted(requestId);
  let unlisten: UnlistenFn | undefined;
  try {
    unlisten = await listen<StreamEnvelope>('piui://stream-probe', ({ payload: envelope }) => {
      if (
        !isRecord(envelope) ||
        envelope.correlationId !== requestId ||
        !isRecord(envelope.payload)
      )
        return;
      const event = envelope.payload;
      if (event.eventType === 'stream.delta' && typeof event.text === 'string') {
        const notice = parseAuthNotice(event.text);
        if (notice) request.onNotice(notice);
      } else if (event.eventType === 'stream.failed') {
        request.onFailed(typeof event.code === 'string' ? event.code : 'provider-auth-failed');
      }
    });
    await invoke('product_auth_start', {
      requestData: { requestId, providerId: request.providerId },
    });
    return requestId;
  } finally {
    unlisten?.();
  }
}

export async function stopProductTurn(requestId: string): Promise<void> {
  return invoke('product_turn_stop', { requestData: { requestId } });
}

export async function productDiagnostics(): Promise<Readonly<Record<string, unknown>>> {
  const result = await invoke<unknown>('product_diagnostics');
  if (!isRecord(result) || result.schemaVersion !== 1 || !isRecord(result.diagnostics)) {
    throw new Error('diagnostics-response-invalid');
  }
  return result.diagnostics;
}

export async function nativeDiagnosticsSnapshot(
  networkAvailable: boolean,
): Promise<NativeDiagnosticsSnapshot> {
  const result = await invoke<unknown>('diagnostics_snapshot', { networkAvailable });
  if (
    !isRecord(result) ||
    !Array.isArray(result.checks) ||
    !Array.isArray(result.environment) ||
    !Array.isArray(result.logs)
  ) {
    throw new Error('diagnostics-response-invalid');
  }
  const checks = result.checks.map(validateDiagnosticCheck);
  const environment = result.environment.map((fact) => {
    if (
      !isRecord(fact) ||
      typeof fact.key !== 'string' ||
      typeof fact.value !== 'string' ||
      typeof fact.origin !== 'string' ||
      fact.key.length > 128 ||
      fact.value.length > 512 ||
      fact.origin.length > 128
    ) {
      throw new Error('diagnostics-response-invalid');
    }
    return Object.freeze({ key: fact.key, value: fact.value, origin: fact.origin });
  });
  if (
    result.logs.length > 2_000 ||
    !result.logs.every((line) => typeof line === 'string' && line.length <= 4_096)
  ) {
    throw new Error('diagnostics-response-invalid');
  }
  if (
    result.helperFailure !== null &&
    result.helperFailure !== undefined &&
    (typeof result.helperFailure !== 'string' || result.helperFailure.length > 512)
  ) {
    throw new Error('diagnostics-response-invalid');
  }
  return Object.freeze({
    checks: Object.freeze(checks),
    environment: Object.freeze(environment),
    logs: Object.freeze([...(result.logs as string[])]),
    helperFailure: (result.helperFailure as string | null | undefined) ?? null,
  });
}

export async function exportNativeDiagnostics(networkAvailable: boolean): Promise<boolean> {
  const result = await invoke<unknown>('diagnostics_export', { networkAvailable });
  if (typeof result !== 'boolean') throw new Error('diagnostics-export-response-invalid');
  return result;
}

export async function listPendingApprovals(): Promise<readonly NativeApproval[]> {
  const result = await invoke<unknown>('approval_pending');
  if (!Array.isArray(result)) throw new Error('approval-response-invalid');
  return result.map(validateApproval);
}

export async function submitNativeApproval(
  request: Readonly<{
    approvalId: string;
    decisionId: string;
    scopeIds: readonly string[];
    choice: 'approve-once' | 'deny';
  }>,
): Promise<void> {
  await invoke('approval_submit', {
    submission: {
      approvalId: request.approvalId,
      decisionId: request.decisionId,
      scopeIds: [...request.scopeIds],
      choice: request.choice,
    },
  });
}

export async function presentNativeCredentialSheet(
  request: Readonly<{
    providerId: string;
    providerLabel: string;
    accountLabel: string;
  }>,
): Promise<
  Readonly<{
    savedState: 'saved' | 'cancelled';
    credentialReference: string | null;
    accountLabel: string;
    validationState: 'saved-not-validated' | 'not-run';
  }>
> {
  return invoke('present_credential_sheet', { request });
}

export type NativeCredentialImportCandidate = Readonly<{
  providerId: string;
  credentialType: 'api-key' | 'subscription';
}>;

export async function inspectNativeCredentialImport(): Promise<
  Readonly<{
    available: boolean;
    candidates: readonly NativeCredentialImportCandidate[];
  }>
> {
  const result = await invoke<unknown>('credential_import_inspect');
  if (
    !isRecord(result) ||
    typeof result.available !== 'boolean' ||
    !Array.isArray(result.candidates)
  ) {
    throw new Error('credential-import-response-invalid');
  }
  const candidates = result.candidates.map((candidate) => {
    if (
      !isRecord(candidate) ||
      typeof candidate.providerId !== 'string' ||
      !['api-key', 'subscription'].includes(String(candidate.credentialType))
    ) {
      throw new Error('credential-import-response-invalid');
    }
    return Object.freeze({
      providerId: candidate.providerId,
      credentialType: candidate.credentialType as NativeCredentialImportCandidate['credentialType'],
    });
  });
  return Object.freeze({ available: result.available, candidates: Object.freeze(candidates) });
}

export async function importNativeCredentials(providerIds: readonly string[]): Promise<
  Readonly<{
    importedProviderIds: readonly string[];
    sourceUnchanged: true;
  }>
> {
  const result = await invoke<unknown>('credential_import_selected', {
    providerIds: [...providerIds],
  });
  if (
    !isRecord(result) ||
    result.sourceUnchanged !== true ||
    !Array.isArray(result.importedProviderIds) ||
    !result.importedProviderIds.every((providerId) => typeof providerId === 'string')
  ) {
    throw new Error('credential-import-response-invalid');
  }
  return Object.freeze({
    importedProviderIds: Object.freeze([...result.importedProviderIds] as string[]),
    sourceUnchanged: true,
  });
}

export type NativeAttachment = Readonly<{
  capabilityId: string;
  fileLabel: string;
  mime: 'image/png' | 'image/jpeg' | 'image/webp';
  byteLength: number;
}>;

export async function selectNativeAttachment(): Promise<NativeAttachment | null> {
  const result = await invoke<unknown>('attachment_select');
  if (result === null) return null;
  if (
    !isRecord(result) ||
    typeof result.capabilityId !== 'string' ||
    !/^attachment-[a-f0-9]{32}$/u.test(result.capabilityId) ||
    typeof result.fileLabel !== 'string' ||
    !['image/png', 'image/jpeg', 'image/webp'].includes(String(result.mime)) ||
    !Number.isSafeInteger(result.byteLength) ||
    (result.byteLength as number) <= 0
  ) {
    throw new Error('attachment-response-invalid');
  }
  return Object.freeze({
    capabilityId: result.capabilityId,
    fileLabel: result.fileLabel,
    mime: result.mime as NativeAttachment['mime'],
    byteLength: result.byteLength as number,
  });
}

export async function removeNativeAttachment(capabilityId: string): Promise<void> {
  await invoke('attachment_remove', { capabilityId });
}

export async function nativeHostStatus(): Promise<
  Readonly<{
    status: 'ready';
    architecture: string;
    transport: 'inherited-stdio';
    listener: false;
  }>
> {
  return invoke('host_status');
}

export async function startLocalHelper(): Promise<
  Readonly<{
    running: boolean;
    failed: boolean;
    // The recorded generation-fatal reason. It is a fixed host string that
    // never carries a path or a payload, so the interface may show it as is.
    failure?: string | null;
    protocolVersion?: number;
    nodeVersion?: string;
    piVersion?: string;
  }>
> {
  return invoke('sidecar_start');
}

export async function openDisclosedExternal(target: string): Promise<void> {
  return invoke('open_disclosed_external', { target });
}

export async function closeNativeMainWindow(): Promise<void> {
  await invoke('close_main_window');
}

export type NativeWindowState = Readonly<{
  width: number;
  height: number;
  maximised: boolean;
}>;

function validateWindowState(value: unknown): NativeWindowState {
  if (
    !isRecord(value) ||
    typeof value.width !== 'number' ||
    !Number.isFinite(value.width) ||
    value.width < 680 ||
    value.width > 8_192 ||
    typeof value.height !== 'number' ||
    !Number.isFinite(value.height) ||
    value.height < 560 ||
    value.height > 8_192 ||
    typeof value.maximised !== 'boolean'
  ) {
    throw new Error('window-state-response-invalid');
  }
  return Object.freeze({
    width: value.width,
    height: value.height,
    maximised: value.maximised,
  });
}

export async function currentNativeWindowState(): Promise<NativeWindowState> {
  return validateWindowState(await invoke<unknown>('window_current_state'));
}

export async function applyNativeWindowState(
  windowState: NativeWindowState,
): Promise<NativeWindowState> {
  return validateWindowState(await invoke<unknown>('window_apply_state', { windowState }));
}

export function listenForNativeWindowState(
  onState: (state: NativeWindowState) => void,
): Promise<UnlistenFn> {
  return listen<unknown>('piui://window-state', ({ payload }) => {
    try {
      onState(validateWindowState(payload));
    } catch {
      // Native payloads are rejected at the boundary rather than entering app state.
    }
  });
}

export async function loadNativeApplicationState(): Promise<NativeApplicationData> {
  return invoke<NativeApplicationData>('app_state_load');
}

export async function saveNativeApplicationState(
  data: NativeApplicationData,
): Promise<NativeApplicationData> {
  return invoke<NativeApplicationData>('app_state_save', { data });
}

export function listenForNativeMenuCommand(
  onCommand: (command: string) => void,
): Promise<UnlistenFn> {
  return listen<string>('piui://menu-command', ({ payload }) => {
    if (typeof payload === 'string') onCommand(payload);
  });
}

export async function setNativeMenuEnabledState(menuState: {
  canCreate: boolean;
  canChooseProject: boolean;
  canStop: boolean;
  canSend: boolean;
}): Promise<void> {
  await invoke('menu_set_enabled_state', { menuState });
}

async function productSessionReference(
  command: 'product_resume_session' | 'product_fork_session',
  sessionId: string,
  expectedGeneration: number,
): Promise<NativeProductSession> {
  const result = await invoke<unknown>(command, {
    requestData: { sessionId, expectedGeneration },
  });
  if (!isRecord(result) || result.schemaVersion !== 1) throw new Error('session-response-invalid');
  return validateSession(result.session);
}

function validateWorkspaceSummary(value: unknown): NativeWorkspaceSummary {
  if (
    !isRecord(value) ||
    typeof value.workspaceId !== 'string' ||
    !/^workspace-[a-f0-9]{32}$/u.test(value.workspaceId) ||
    typeof value.displayLabel !== 'string' ||
    value.displayLabel.length === 0 ||
    value.displayLabel.length > 256 ||
    !Number.isSafeInteger(value.revision) ||
    (value.revision as number) < 0 ||
    !['untrusted', 'trusted', 'revoked'].includes(String(value.trustState)) ||
    ![
      'not-loaded',
      'preparing',
      'loading',
      'loaded',
      'failed-closed',
      'execution-uncertain',
      'revoked-prior-effects',
    ].includes(String(value.resourceState))
  ) {
    throw new Error('workspace-response-invalid');
  }
  return Object.freeze({
    workspaceId: value.workspaceId,
    displayLabel: value.displayLabel,
    revision: value.revision as number,
    trustState: value.trustState as NativeWorkspaceSummary['trustState'],
    resourceState: value.resourceState as NativeWorkspaceSummary['resourceState'],
  });
}

function validateDiagnosticCheck(value: unknown): NativeDiagnosticCheck {
  if (
    !isRecord(value) ||
    typeof value.id !== 'string' ||
    typeof value.label !== 'string' ||
    !['not-run', 'running', 'pass', 'warning', 'fail', 'offline'].includes(String(value.status)) ||
    typeof value.detail !== 'string' ||
    !(value.recovery === null || value.recovery === undefined || typeof value.recovery === 'string')
  ) {
    throw new Error('diagnostics-response-invalid');
  }
  return Object.freeze({
    id: value.id,
    label: value.label,
    status: value.status as NativeDiagnosticCheck['status'],
    detail: value.detail,
    ...(typeof value.recovery === 'string' ? { recovery: value.recovery } : {}),
  });
}

function validateSession(value: unknown): NativeProductSession {
  if (
    !isRecord(value) ||
    typeof value.id !== 'string' ||
    !value.id.startsWith('session-') ||
    !Number.isSafeInteger(value.generation) ||
    typeof value.title !== 'string' ||
    typeof value.workspaceId !== 'string' ||
    typeof value.writable !== 'boolean' ||
    !(value.branch === undefined || typeof value.branch === 'string') ||
    !Number.isSafeInteger(value.updatedAtUnixMs) ||
    (value.updatedAtUnixMs as number) < 0 ||
    typeof value.preview !== 'string' ||
    value.preview.length > 4_096 ||
    !Number.isSafeInteger(value.messageCount) ||
    (value.messageCount as number) < 0
  ) {
    throw new Error('session-response-invalid');
  }
  return Object.freeze({
    id: value.id,
    generation: value.generation as number,
    title: value.title,
    workspaceId: value.workspaceId,
    writable: value.writable,
    ...(typeof value.branch === 'string' ? { branch: value.branch } : {}),
    updatedAtUnixMs: value.updatedAtUnixMs as number,
    preview: value.preview,
    messageCount: value.messageCount as number,
  });
}

function validateProductMessage(value: unknown): NativeProductMessage {
  if (
    !isRecord(value) ||
    typeof value.id !== 'string' ||
    value.id.length > 160 ||
    !['user', 'assistant', 'system'].includes(String(value.role)) ||
    !Number.isSafeInteger(value.timestampUnixMs) ||
    (value.timestampUnixMs as number) < 0 ||
    typeof value.text !== 'string' ||
    value.text.length > 262_144 ||
    !['message', 'compaction'].includes(String(value.kind))
  ) {
    throw new Error('session-inspect-response-invalid');
  }
  return Object.freeze({
    id: value.id,
    role: value.role as NativeProductMessage['role'],
    timestampUnixMs: value.timestampUnixMs as number,
    text: value.text,
    kind: value.kind as NativeProductMessage['kind'],
  });
}

function validateProductChange(value: unknown): NativeProductChange {
  if (
    !isRecord(value) ||
    typeof value.id !== 'string' ||
    !/^change-[a-f0-9]{32}$/u.test(value.id) ||
    typeof value.path !== 'string' ||
    value.path.length > 1_024 ||
    !['added', 'modified', 'deleted', 'binary', 'failed'].includes(String(value.state)) ||
    !Number.isSafeInteger(value.additions) ||
    (value.additions as number) < 0 ||
    !Number.isSafeInteger(value.deletions) ||
    (value.deletions as number) < 0 ||
    !Array.isArray(value.before) ||
    !value.before.every((line) => typeof line === 'string') ||
    !Array.isArray(value.after) ||
    !value.after.every((line) => typeof line === 'string') ||
    !['safe', 'revoked', 'complete'].includes(String(value.undo))
  ) {
    throw new Error('change-response-invalid');
  }
  return Object.freeze({
    id: value.id,
    path: value.path,
    state: value.state as NativeProductChange['state'],
    additions: value.additions as number,
    deletions: value.deletions as number,
    before: Object.freeze([...value.before] as string[]),
    after: Object.freeze([...value.after] as string[]),
    undo: value.undo as NativeProductChange['undo'],
  });
}

function validateProductSetting(value: unknown): NativeProductSetting {
  if (
    !isRecord(value) ||
    typeof value.key !== 'string' ||
    !/^[a-z][a-z0-9.-]{0,127}$/u.test(value.key) ||
    !['global', 'project'].includes(String(value.scope)) ||
    !Number.isSafeInteger(value.revision) ||
    (value.revision as number) < 0 ||
    typeof value.origin !== 'string' ||
    value.origin.length > 160
  ) {
    throw new Error('setting-response-invalid');
  }
  return Object.freeze({
    key: value.key,
    value: value.value,
    scope: value.scope as NativeProductSetting['scope'],
    revision: value.revision as number,
    origin: value.origin,
  });
}

function validateProductResource(value: unknown): NativeProductResource {
  if (
    !isRecord(value) ||
    typeof value.id !== 'string' ||
    !/^resource-[a-f0-9]{32}$/u.test(value.id) ||
    !['skill', 'prompt', 'theme', 'extension', 'package'].includes(String(value.kind)) ||
    typeof value.name !== 'string' ||
    typeof value.version !== 'string' ||
    !['global', 'project', 'package'].includes(String(value.source)) ||
    typeof value.trusted !== 'boolean' ||
    typeof value.enabled !== 'boolean' ||
    typeof value.executable !== 'boolean' ||
    typeof value.description !== 'string' ||
    !Array.isArray(value.contributedSettings) ||
    !value.contributedSettings.every(
      (setting) => typeof setting === 'string' && setting.length <= 128,
    ) ||
    !Array.isArray(value.operations) ||
    value.operations.length > 5 ||
    !value.operations.every((operation) =>
      ['enable', 'disable', 'install', 'update', 'remove'].includes(String(operation)),
    )
  ) {
    throw new Error('resource-response-invalid');
  }
  return Object.freeze({
    id: value.id,
    kind: value.kind as NativeProductResource['kind'],
    name: value.name,
    version: value.version,
    source: value.source as NativeProductResource['source'],
    trusted: value.trusted,
    enabled: value.enabled,
    executable: value.executable,
    description: value.description,
    contributedSettings: Object.freeze([...(value.contributedSettings as string[])]),
    operations: Object.freeze([
      ...(value.operations as NativeProductResource['operations']),
    ]),
  });
}

function validateApproval(value: unknown): NativeApproval {
  if (
    !isRecord(value) ||
    typeof value.approvalId !== 'string' ||
    typeof value.decisionId !== 'string' ||
    !Number.isSafeInteger(value.revision) ||
    ![
      'policy-check',
      'awaiting',
      'submitting',
      'approved',
      'denied',
      'expired',
      'cancelled',
    ].includes(String(value.state)) ||
    typeof value.verb !== 'string' ||
    typeof value.target !== 'string' ||
    !['routine', 'sensitive', 'destructive', 'external', 'deny-only'].includes(
      String(value.risk),
    ) ||
    !Array.isArray(value.scopes) ||
    !Number.isSafeInteger(value.expiresInMs)
  ) {
    throw new Error('approval-response-invalid');
  }
  const scopeIds = value.scopes.map((scope) => {
    if (!isRecord(scope) || typeof scope.scopeId !== 'string' || typeof scope.label !== 'string') {
      throw new Error('approval-response-invalid');
    }
    return scope.scopeId;
  });
  const subject = validateApprovalSubject(value.subject);
  return Object.freeze({
    approvalId: value.approvalId,
    decisionId: value.decisionId,
    revision: value.revision as number,
    state: value.state as NativeApproval['state'],
    verb: value.verb,
    target: value.target,
    risk: value.risk as NativeApproval['risk'],
    scopeIds: Object.freeze(scopeIds),
    expiresInMs: value.expiresInMs as number,
    subject,
  });
}

function validateApprovalSubject(value: unknown): NativeApprovalSubject | null {
  // Hosts that predate the subject field omit it; that reads the same as no subject.
  if (value === undefined || value === null) return null;
  if (
    !isRecord(value) ||
    !(APPROVAL_SUBJECT_LABELS as readonly unknown[]).includes(value.label) ||
    typeof value.text !== 'string' ||
    value.text.length > MAX_APPROVAL_SUBJECT_UTF16 ||
    typeof value.truncated !== 'boolean'
  ) {
    throw new Error('approval-response-invalid');
  }
  return Object.freeze({
    label: value.label as NativeApprovalSubject['label'],
    text: value.text,
    truncated: value.truncated,
  });
}

function parseAuthNotice(text: string): NativeAuthNotice | null {
  try {
    const value: unknown = JSON.parse(text);
    if (!isRecord(value) || typeof value.type !== 'string') return null;
    if (
      value.type === 'opening-browser' &&
      typeof value.url === 'string' &&
      (value.instructions === undefined || typeof value.instructions === 'string')
    ) {
      return Object.freeze({
        type: value.type,
        url: value.url,
        ...(value.instructions ? { instructions: value.instructions } : {}),
      });
    }
    if (
      value.type === 'device-code' &&
      typeof value.verificationUri === 'string' &&
      typeof value.userCode === 'string' &&
      (value.expiresInSeconds === undefined || Number.isSafeInteger(value.expiresInSeconds))
    ) {
      return Object.freeze({
        type: value.type,
        verificationUri: value.verificationUri,
        userCode: value.userCode,
        ...(typeof value.expiresInSeconds === 'number'
          ? { expiresInSeconds: value.expiresInSeconds }
          : {}),
      });
    }
    if (value.type === 'progress' && typeof value.message === 'string') {
      return Object.freeze({ type: value.type, message: value.message });
    }
    if (
      value.type === 'validated' &&
      typeof value.providerId === 'string' &&
      typeof value.accountLabel === 'string'
    ) {
      return Object.freeze({
        type: value.type,
        providerId: value.providerId,
        accountLabel: value.accountLabel,
      });
    }
  } catch {
    return null;
  }
  return null;
}

function validateProvider(value: unknown): NativeProvider {
  if (
    !isRecord(value) ||
    typeof value.id !== 'string' ||
    typeof value.name !== 'string' ||
    !Array.isArray(value.methods) ||
    !Array.isArray(value.models) ||
    !['connected', 'not-connected', 'unknown'].includes(String(value.status))
  ) {
    throw new Error('provider-response-invalid');
  }
  const methods = value.methods.map((method) => {
    if (
      !isRecord(method) ||
      !['subscription', 'api-key', 'ambient'].includes(String(method.id)) ||
      typeof method.label !== 'string' ||
      !['recommended', 'supported', 'fallback'].includes(String(method.classification))
    ) {
      throw new Error('provider-response-invalid');
    }
    return Object.freeze({
      id: method.id as 'subscription' | 'api-key' | 'ambient',
      label: method.label,
      classification: method.classification as 'recommended' | 'supported' | 'fallback',
    });
  });
  const models = value.models.map((model) => {
    if (
      !isRecord(model) ||
      typeof model.id !== 'string' ||
      typeof model.name !== 'string' ||
      typeof model.reasoning !== 'boolean' ||
      typeof model.acceptsImages !== 'boolean' ||
      !Number.isSafeInteger(model.contextWindow)
    )
      throw new Error('provider-response-invalid');
    return Object.freeze({
      id: model.id,
      name: model.name,
      reasoning: model.reasoning,
      acceptsImages: model.acceptsImages,
      contextWindow: model.contextWindow as number,
    });
  });
  return Object.freeze({
    id: value.id,
    name: value.name,
    methods: Object.freeze(methods),
    models: Object.freeze(models),
    status: value.status as NativeProvider['status'],
    ...(typeof value.accountLabel === 'string' ? { accountLabel: value.accountLabel } : {}),
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
