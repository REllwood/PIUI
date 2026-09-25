import type { PublicCredentialStore, PublicModelRuntimeInstance } from './public-sdk.js';
import type { AdapterChange } from './changes.js';
import type { SettingRecord, SettingScope } from './settings.js';
import type { AdapterResource } from './resources.js';

export type AdapterCapability =
  | 'providers'
  | 'authentication'
  | 'workspaces'
  | 'sessions'
  | 'streaming'
  | 'queues'
  | 'compaction'
  | 'tools'
  | 'resources'
  | 'settings'
  | 'diagnostics';

export type AdapterSupport = Readonly<Record<AdapterCapability, 'supported' | 'unavailable'>>;

export type ProviderMethod = Readonly<{
  id: 'subscription' | 'api-key' | 'ambient';
  label: string;
  classification: 'recommended' | 'supported' | 'fallback';
}>;

export type ProviderModel = Readonly<{
  id: string;
  name: string;
  reasoning: boolean;
  acceptsImages: boolean;
  contextWindow: number;
}>;

export type ProviderDescriptor = Readonly<{
  id: string;
  name: string;
  methods: readonly ProviderMethod[];
  models: readonly ProviderModel[];
  status: 'connected' | 'not-connected' | 'unknown';
  accountLabel?: string;
}>;

export type AuthNotice =
  | Readonly<{ type: 'opening-browser'; url: string; instructions?: string }>
  | Readonly<{
      type: 'device-code';
      verificationUri: string;
      userCode: string;
      expiresInSeconds?: number;
    }>
  | Readonly<{ type: 'progress'; message: string }>;

export type AuthInteractionPort = Readonly<{
  signal: AbortSignal;
  prompt: (
    prompt: Readonly<{
      type: 'text' | 'secret' | 'select' | 'manual-code';
      message: string;
      options?: readonly Readonly<{ id: string; label: string }>[];
      signal?: AbortSignal;
    }>,
  ) => Promise<string>;
  notify: (notice: AuthNotice) => void;
}>;

export type AuthReceipt = Readonly<{
  providerId: string;
  credentialReference: string;
  accountLabel: string;
  validated: true;
}>;

export type AdapterQueueReceipt = Readonly<{
  queueId: string;
  number: number;
}>;

export type AdapterSession = Readonly<{
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

export type AdapterSessionListRequest = Readonly<{
  workspaceId: string;
  workspaceRevision: number;
  workspacePath: string;
  agentDir: string;
}>;

export type AdapterMessage = Readonly<{
  id: string;
  role: 'user' | 'assistant' | 'system';
  timestampUnixMs: number;
  text: string;
  kind: 'message' | 'compaction';
}>;

export type AdapterSessionCreateRequest = Readonly<{
  workspaceId: string;
  workspaceRevision: number;
  workspacePath: string;
  agentDir: string;
  title?: string;
  providerId?: string;
  modelId?: string;
}>;

export type AdapterTurnRequest = Readonly<{
  requestId: string;
  sessionId: string;
  generation: number;
  text: string;
  retryPrevious: boolean;
  images: readonly Readonly<{
    type: 'image';
    data: string;
    mimeType: 'image/png' | 'image/jpeg' | 'image/webp';
  }>[];
}>;

export type AdapterTurnEvent = Readonly<{
  requestId: string;
  sequence: number;
  type: 'started' | 'text' | 'tool' | 'stopped' | 'failed' | 'complete';
  text?: string;
  code?: string;
  toolCallId?: string;
}>;

export type PiAdapterOptions = Readonly<{
  credentials: PublicCredentialStore;
  allowModelNetwork?: boolean;
  generation: number;
  /**
   * In-process test seam that runs once against the new model runtime before
   * any session exists, for example to register pi-ai's faux provider. No
   * protocol request can reach it and production construction never sets it.
   */
  prepareModelRuntime?: (runtime: PublicModelRuntimeInstance) => void | Promise<void>;
  approvalHost: Readonly<{
    requestApproval: (
      payload: import('../bridge/host-requests.js').CohortApprovalRequestPayload,
    ) => Promise<import('../bridge/host-requests.js').ApprovalGrant>;
    notifyApprovalReady: (
      payload: import('../bridge/host-requests.js').ApprovalReadyPayload,
    ) => Promise<void>;
    abandonApproval: (
      payload: import('../bridge/host-requests.js').ApprovalAbandonPayload,
    ) => Promise<void>;
  }>;
}>;

export interface PiAdapter {
  readonly version: '0.82.0';
  readonly capabilities: AdapterSupport;
  listProviders(): Promise<readonly ProviderDescriptor[]>;
  login(
    providerId: string,
    method: 'subscription' | 'api-key',
    interaction: AuthInteractionPort,
  ): Promise<AuthReceipt>;
  logout(providerId: string): Promise<void>;
  listSessions(request: AdapterSessionListRequest): Promise<readonly AdapterSession[]>;
  createSession(request: AdapterSessionCreateRequest): Promise<AdapterSession>;
  resumeSession(sessionId: string, expectedGeneration: number): Promise<AdapterSession>;
  forkSession(sessionId: string, expectedGeneration: number): Promise<AdapterSession>;
  renameSession(
    sessionId: string,
    expectedGeneration: number,
    title: string,
  ): Promise<AdapterSession>;
  inspectSession(sessionId: string, expectedGeneration: number): Promise<readonly AdapterMessage[]>;
  compactSession(sessionId: string, expectedGeneration: number): Promise<void>;
  trashSessionTarget(
    sessionId: string,
    expectedGeneration: number,
  ): Promise<
    Readonly<{
      workspaceId: string;
      workspaceRevision: number;
      privatePath: string;
      identity: string;
    }>
  >;
  confirmSessionTrashed(sessionId: string, expectedGeneration: number): Promise<void>;
  listChanges(sessionId: string, expectedGeneration: number): Promise<readonly AdapterChange[]>;
  undoChange(
    sessionId: string,
    expectedGeneration: number,
    changeId: string,
  ): Promise<AdapterChange>;
  changeTarget(
    sessionId: string,
    expectedGeneration: number,
    changeId: string,
  ): Promise<
    Readonly<{
      workspaceId: string;
      workspaceRevision: number;
      privatePath: string;
    }>
  >;
  listSettings(sessionId: string, expectedGeneration: number): Promise<readonly SettingRecord[]>;
  saveSetting(
    sessionId: string,
    expectedGeneration: number,
    key: string,
    value: unknown,
    scope: SettingScope,
    expectedRevision: number,
  ): Promise<SettingRecord>;
  previewSettingReset(
    sessionId: string,
    expectedGeneration: number,
    key: string,
  ): Promise<Readonly<{ key: string; current: unknown; next: null }>>;
  listResources(sessionId: string, expectedGeneration: number): Promise<readonly AdapterResource[]>;
  setResourceEnabled(
    sessionId: string,
    expectedGeneration: number,
    resourceId: string,
    enabled: boolean,
    acknowledgedExecutableRisk: boolean,
  ): Promise<AdapterResource>;
  installPackage(
    sessionId: string,
    expectedGeneration: number,
    source: string,
    scope: 'global' | 'project',
    online: boolean,
    acknowledgedExecutableRisk: boolean,
  ): Promise<AdapterResource>;
  mutatePackage(
    sessionId: string,
    expectedGeneration: number,
    resourceId: string,
    operation: 'update' | 'remove',
    online: boolean,
    acknowledgedExecutableRisk: boolean,
  ): Promise<AdapterResource | null>;
  queueFollowUp(
    sessionId: string,
    expectedGeneration: number,
    text: string,
  ): Promise<AdapterQueueReceipt>;
  replaceFollowUpQueue(
    sessionId: string,
    expectedGeneration: number,
    texts: readonly string[],
  ): Promise<Readonly<{ count: number }>>;
  exportSession(sessionId: string, expectedGeneration: number, destination: string): Promise<void>;
  streamTurn(request: AdapterTurnRequest, signal: AbortSignal): AsyncIterable<AdapterTurnEvent>;
  stopTurn(requestId: string): Promise<'stopped' | 'too-late' | 'unknown'>;
  diagnosticSnapshot(): Promise<Readonly<Record<string, unknown>>>;
  close(): Promise<void>;
}
