export type AsyncStatus = 'idle' | 'loading' | 'ready' | 'saving' | 'offline' | 'failed';

export type ThemePreference = 'system' | 'light' | 'dark';
export type AppMode = 'simple' | 'advanced';
export type RouteId = 'conversation' | 'sessions' | 'activity' | 'settings';
export type TrustState = 'untrusted' | 'trusted' | 'revoked';

export type AppearancePreferences = Readonly<{
  theme: ThemePreference;
  increasedContrast: boolean;
  reduceTransparency: boolean;
  reduceMotion: boolean;
  accessibleTranscript: boolean;
}>;

export type ProviderLoginMethod = Readonly<{
  id: 'subscription' | 'device' | 'api-key';
  label: string;
  classification: 'recommended' | 'supported' | 'fallback';
}>;

export type ProviderProfile = Readonly<{
  id: string;
  name: string;
  detail: string;
  accountLabel?: string;
  connected: boolean;
  methods: readonly ProviderLoginMethod[];
  models: readonly Readonly<{
    id: string;
    name: string;
    reasoning: boolean;
    acceptsImages: boolean;
  }>[];
}>;

export type WorkspaceReference = Readonly<{
  capabilityId: string;
  name: string;
  displayPath: string;
  trust: TrustState;
  lastOpenedAt: string;
}>;

export type SessionSummary = Readonly<{
  id: string;
  generation: number;
  title: string;
  project: string;
  updatedAt: string;
  status: 'active' | 'complete' | 'failed' | 'branched';
  branch?: string;
  preview: string;
}>;

export type Message = Readonly<{
  id: string;
  role: 'user' | 'assistant' | 'system';
  author: string;
  timestamp: string;
  markdown: string;
  status: 'stable' | 'streaming' | 'partial' | 'failed';
}>;

export type TurnStatus =
  | 'idle'
  | 'sending'
  | 'streaming'
  | 'tool-running'
  | 'stop-requested'
  | 'stopped'
  | 'cancel-too-late'
  | 'failed'
  | 'complete'
  | 'offline-queued';

export type QueueItem = Readonly<{
  localId: string;
  number?: number;
  text: string;
  state: 'draft' | 'persisting' | 'acknowledged' | 'failed' | 'dispatching' | 'sent';
}>;

export type ActivityState =
  | 'running'
  | 'waiting'
  | 'complete'
  | 'failed'
  | 'cancelling'
  | 'too-late'
  | 'disconnected';

export type ActivityEvent = Readonly<{
  id: string;
  category: 'file' | 'command' | 'search' | 'extension' | 'subagent' | 'error';
  verb: string;
  target: string;
  state: ActivityState;
  elapsed: string;
  summary: string;
  evidence?: string;
  parentId?: string;
}>;

export type ApprovalDecision = 'approve-once' | 'approve-project' | 'deny';
export type ApprovalRequest = Readonly<{
  id: string;
  decisionId: string;
  state:
    | 'policy-check'
    | 'awaiting'
    | 'submitting'
    | 'unacknowledged'
    | 'approved'
    | 'denied'
    | 'expired'
    | 'cancelled';
  action: string;
  target: string;
  reason: string;
  dataLeavingMac: string;
  impact: string;
  reversible: boolean;
  expiresAt?: string;
  permittedDecisions: readonly ApprovalDecision[];
  rememberedScopeEligible: boolean;
  scopeIds?: readonly string[];
}>;

export type FileChange = Readonly<{
  id: string;
  path: string;
  state: 'added' | 'modified' | 'deleted' | 'binary' | 'failed';
  additions: number;
  deletions: number;
  before: readonly string[];
  after: readonly string[];
  undo: 'safe' | 'submitting' | 'revoked' | 'complete';
}>;

export type DiagnosticCheck = Readonly<{
  id: string;
  label: string;
  status: 'not-run' | 'running' | 'pass' | 'warning' | 'fail' | 'offline';
  detail: string;
  recovery?: string;
}>;

export type ResourceRecord = Readonly<{
  id: string;
  kind: 'skill' | 'prompt' | 'theme' | 'extension' | 'package';
  name: string;
  version: string;
  source: 'global' | 'project' | 'package';
  enabled: boolean;
  trusted: boolean;
  executable: boolean;
  description: string;
  contributedSettings?: readonly string[];
  operations: readonly ('enable' | 'disable' | 'install' | 'update' | 'remove')[];
}>;

export type UpdateState = Readonly<{
  status:
    | 'disabled'
    | 'manual-check'
    | 'checking'
    | 'available'
    | 'downloading'
    | 'verifying'
    | 'ready'
    | 'installing'
    | 'verification-failed'
    | 'install-failed';
  endpointConfigured: boolean;
  publicKeyConfigured: boolean;
  version?: string;
  progress?: number;
  message: string;
}>;

export type ConnectionState =
  | 'ready'
  | 'restoring'
  | 'offline'
  | 'reconnecting'
  | 'restart-offered'
  | 'restart-failed'
  | 'external-change';

export type ProductSnapshot = Readonly<{
  generation: number;
  sequence: number;
  connection: ConnectionState;
  providers: readonly ProviderProfile[];
  workspace: WorkspaceReference | null;
  sessions: readonly SessionSummary[];
  activeSessionId: string | null;
  messages: readonly Message[];
  turnStatus: TurnStatus;
  queue: readonly QueueItem[];
  activity: readonly ActivityEvent[];
  approvals: readonly ApprovalRequest[];
  changes: readonly FileChange[];
  diagnostics: readonly DiagnosticCheck[];
  resources: readonly ResourceRecord[];
  update: UpdateState;
}>;
