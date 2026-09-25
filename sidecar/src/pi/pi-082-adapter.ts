import { createHash, randomUUID } from 'node:crypto';
import { isAbsolute, join } from 'node:path';
import { createOAuthInteraction } from '../credentials/oauth.js';
import type { ApprovalHost } from './approval-hook.js';
import { createApprovalGate } from './approval-hook.js';
import type {
  AdapterMessage,
  AdapterSession,
  AdapterSessionCreateRequest,
  AdapterSessionListRequest,
  AdapterTurnEvent,
  AdapterTurnRequest,
  AuthInteractionPort,
  AuthReceipt,
  PiAdapter,
  PiAdapterOptions,
  ProviderDescriptor,
} from './adapter.js';
import { PI_082_CAPABILITIES } from './capabilities.js';
import { ChangeRegistry } from './changes.js';
import { safeDiagnosticSnapshot } from './diagnostics.js';
import {
  PublicModelRuntime,
  PublicPackageManager,
  PublicSessionManager,
  PublicSettingsManager,
  publicCreateAgentSessionFromServices,
  publicCreateAgentSessionServices,
  publicCreateToolDefinitions,
  publicDefaultSessionDir,
  publicPiBinDir,
  publicSdkMetadata,
  type PublicAgentSession,
  type PublicModelRuntimeInstance,
  type PublicSessionManagerInstance,
} from './public-sdk.js';
import { resolveEnabledPackagePaths } from './package-sources.js';
import { describeProviders } from './providers.js';
import { SessionOwnership } from './sessions.js';
import { userShellSpawnHook } from './shell-environment.js';
import {
  SessionWatch,
  observeSessionFile,
  verifyOwnAppends,
  type FileIdentity,
  type ObservedIdentity,
} from './session-watch.js';
import { TypedSettingsAdapter, type SettingScope } from './settings.js';
import { ResourceRegistry } from './resources.js';
import { TextDeltaCoalescer } from './text-coalescer.js';
import { TurnRegistry } from './turns.js';

export class Pi082Adapter implements PiAdapter {
  readonly version = '0.82.0' as const;
  readonly capabilities = PI_082_CAPABILITIES;
  readonly #runtime: PublicModelRuntimeInstance;
  readonly #sessions = new SessionOwnership();
  readonly #turns = new TurnRegistry();
  readonly #runtimeSessions = new Map<
    string,
    Readonly<{
      session: PublicAgentSession;
      workspaceRevision: number;
      workspacePath: string;
      agentDir: string;
      providerId?: string;
      modelId?: string;
      watch: SessionWatch;
      watchGeneration: { value: number };
      changes: ChangeRegistry;
      settings: TypedSettingsAdapter;
      resources: ResourceRegistry;
    }>
  >();
  readonly #sessionSources = new Map<
    string,
    Readonly<{
      path: string;
      workspaceId: string;
      workspaceRevision: number;
      workspacePath: string;
      agentDir: string;
      providerId?: string;
      modelId?: string;
    }>
  >();
  readonly #approvalHost: ApprovalHost;
  readonly #generation: number;
  readonly #queueNumbers = new Map<string, number>();
  #retirementFailures = 0;

  private constructor(runtime: PublicModelRuntimeInstance, options: PiAdapterOptions) {
    this.#runtime = runtime;
    this.#approvalHost = options.approvalHost;
    this.#generation = options.generation;
  }

  static async create(options: PiAdapterOptions): Promise<Pi082Adapter> {
    const runtime = await PublicModelRuntime.create({
      credentials: options.credentials,
      allowModelNetwork: options.allowModelNetwork === true,
      modelsPath: hostModelsPath(),
    });
    await options.prepareModelRuntime?.(runtime);
    return new Pi082Adapter(runtime, options);
  }

  listProviders(): Promise<readonly ProviderDescriptor[]> {
    return describeProviders(this.#runtime);
  }

  async login(
    providerId: string,
    method: 'subscription' | 'api-key',
    interaction: AuthInteractionPort,
  ): Promise<AuthReceipt> {
    const provider = this.#runtime.getProvider(providerId);
    if (!provider) throw new Error('provider-unknown');
    if (method === 'subscription' && !provider.auth.oauth)
      throw new Error('provider-subscription-unsupported');
    if (method === 'api-key' && !provider.auth.apiKey?.login)
      throw new Error('provider-api-key-unsupported');
    await this.#runtime.login(
      providerId,
      method === 'subscription' ? 'oauth' : 'api_key',
      createOAuthInteraction(interaction),
    );
    const status = await this.#runtime.checkAuth(providerId);
    if (!status) throw new Error('provider-validation-failed');
    return Object.freeze({
      providerId,
      credentialReference: `keychain-${randomUUID()}`,
      accountLabel: `${provider.name} account`,
      validated: true,
    });
  }

  logout(providerId: string): Promise<void> {
    return this.#runtime.logout(providerId);
  }

  async listSessions(request: AdapterSessionListRequest): Promise<readonly AdapterSession[]> {
    const listed = await PublicSessionManager.list(
      request.workspacePath,
      publicDefaultSessionDir(request.workspacePath, request.agentDir),
    );
    const listedIds = new Set<string>();
    for (const info of listed.slice(0, 10_000)) {
      const id = opaqueSessionId(info.id);
      listedIds.add(id);
      this.#sessions.register(
        Object.freeze({
          id,
          generation: 1,
          title: boundedTitle(info.name || info.firstMessage || 'Untitled conversation'),
          workspaceId: request.workspaceId,
          writable: false,
          ...(info.parentSessionPath ? { branch: `branch-${id.slice(8, 14)}` } : {}),
          updatedAtUnixMs: info.modified.getTime(),
          preview: boundedPreview(info.firstMessage || 'No message preview is available.'),
          messageCount: info.messageCount,
        }),
      );
      this.#sessionSources.set(
        id,
        Object.freeze({
          path: info.path,
          workspaceId: request.workspaceId,
          workspaceRevision: request.workspaceRevision,
          workspacePath: request.workspacePath,
          agentDir: request.agentDir,
        }),
      );
    }
    this.#sessions.reconcileInactive(request.workspaceId, listedIds);
    for (const [sessionId, source] of this.#sessionSources) {
      if (
        source.workspaceId === request.workspaceId &&
        !listedIds.has(sessionId) &&
        !this.#sessions.get(sessionId)?.writable
      ) {
        this.#sessionSources.delete(sessionId);
      }
    }
    return Object.freeze(
      this.#sessions.list().filter((session) => session.workspaceId === request.workspaceId),
    );
  }
  async createSession(request: AdapterSessionCreateRequest): Promise<AdapterSession> {
    this.#assertNoBusyRuntime();
    const sessionManager = PublicSessionManager.create(
      request.workspacePath,
      publicDefaultSessionDir(request.workspacePath, request.agentDir),
    );
    const mutation = this.#sessions.beginCreate(
      opaqueSessionId(sessionManager.getSessionId()),
      request.workspaceId,
      request.title,
    );
    const metadata = mutation.session;
    try {
      await this.#constructRuntime(metadata, sessionManager, request);
      const path = sessionManager.getSessionFile();
      if (!path) throw new Error('session-file-unavailable');
      this.#sessionSources.set(
        metadata.id,
        Object.freeze({
          path,
          workspaceId: request.workspaceId,
          workspaceRevision: request.workspaceRevision,
          workspacePath: request.workspacePath,
          agentDir: request.agentDir,
          ...(request.providerId ? { providerId: request.providerId } : {}),
          ...(request.modelId ? { modelId: request.modelId } : {}),
        }),
      );
      mutation.commit();
      return metadata;
    } catch (error) {
      const candidate = this.#runtimeSessions.get(metadata.id);
      if (candidate) {
        this.#retireRuntime(candidate);
        this.#runtimeSessions.delete(metadata.id);
      }
      this.#sessionSources.delete(metadata.id);
      mutation.rollback();
      throw error;
    }
  }
  async resumeSession(sessionId: string, expectedGeneration: number): Promise<AdapterSession> {
    this.#assertNoBusyRuntime();
    const source = this.#sessionSources.get(sessionId);
    if (!source) throw new Error('session-runtime-unavailable');
    const mutation = this.#sessions.beginResume(sessionId, expectedGeneration);
    const metadata = mutation.session;
    const existing = this.#runtimeSessions.get(sessionId);
    try {
      const sessionManager = PublicSessionManager.open(
        source.path,
        undefined,
        source.workspacePath,
      );
      await this.#constructRuntime(metadata, sessionManager, {
        workspaceId: metadata.workspaceId,
        workspaceRevision: source.workspaceRevision,
        workspacePath: source.workspacePath,
        agentDir: source.agentDir,
        ...(source.providerId ? { providerId: source.providerId } : {}),
        ...(source.modelId ? { modelId: source.modelId } : {}),
      });
      mutation.commit();
      if (existing) this.#retireRuntime(existing);
      return metadata;
    } catch (error) {
      const candidate = this.#runtimeSessions.get(sessionId);
      if (candidate && candidate !== existing) {
        this.#retireRuntime(candidate);
      }
      if (existing) this.#runtimeSessions.set(sessionId, existing);
      else this.#runtimeSessions.delete(sessionId);
      mutation.rollback();
      throw error;
    }
  }
  async forkSession(sessionId: string, expectedGeneration: number): Promise<AdapterSession> {
    this.#assertNoBusyRuntime();
    const source = this.#runtimeSessions.get(sessionId);
    if (!source) throw new Error('session-runtime-unavailable');
    const sourceFile = source.session.sessionFile;
    // Pi has nothing on disk to fork until the source's first assistant reply.
    if (!sourceFile || (await observeSessionFile(sourceFile)) === null) {
      throw new Error('session-fork-unavailable');
    }
    const sessionManager = PublicSessionManager.forkFrom(
      sourceFile,
      source.workspacePath,
      source.session.sessionManager.getSessionDir(),
    );
    const mutation = this.#sessions.beginForkAs(
      sessionId,
      expectedGeneration,
      opaqueSessionId(sessionManager.getSessionId()),
    );
    const metadata = mutation.session;
    try {
      await this.#constructRuntime(metadata, sessionManager, {
        workspaceId: metadata.workspaceId,
        workspaceRevision: source.workspaceRevision,
        workspacePath: source.workspacePath,
        agentDir: source.agentDir,
        ...(source.providerId ? { providerId: source.providerId } : {}),
        ...(source.modelId ? { modelId: source.modelId } : {}),
      });
      const path = sessionManager.getSessionFile();
      if (!path) throw new Error('session-file-unavailable');
      this.#sessionSources.set(
        metadata.id,
        Object.freeze({
          path,
          workspaceId: metadata.workspaceId,
          workspaceRevision: source.workspaceRevision,
          workspacePath: source.workspacePath,
          agentDir: source.agentDir,
          ...(source.providerId ? { providerId: source.providerId } : {}),
          ...(source.modelId ? { modelId: source.modelId } : {}),
        }),
      );
      mutation.commit();
      return metadata;
    } catch (error) {
      const candidate = this.#runtimeSessions.get(metadata.id);
      if (candidate) {
        this.#retireRuntime(candidate);
        this.#runtimeSessions.delete(metadata.id);
      }
      mutation.rollback();
      throw error;
    }
  }

  async renameSession(
    sessionId: string,
    expectedGeneration: number,
    title: string,
  ): Promise<AdapterSession> {
    const runtime = await this.#ensureRuntime(sessionId, expectedGeneration);
    if (busy(runtime)) throw new Error('session-busy');
    const nextTitle = boundedTitle(title);
    await this.#verifyRuntime(runtime);
    runtime.session.setSessionName(nextTitle);
    await this.#acknowledgeRuntime(runtime);
    return this.#sessions.rename(sessionId, expectedGeneration, nextTitle);
  }

  async inspectSession(
    sessionId: string,
    expectedGeneration: number,
  ): Promise<readonly AdapterMessage[]> {
    const runtime = await this.#ensureRuntime(sessionId, expectedGeneration);
    return Object.freeze(
      runtime.session.sessionManager
        .getBranch()
        .slice(-10_000)
        .flatMap((entry) => projectEntry(entry)),
    );
  }

  async compactSession(sessionId: string, expectedGeneration: number): Promise<void> {
    const runtime = await this.#ensureRuntime(sessionId, expectedGeneration);
    if (busy(runtime)) throw new Error('session-busy');
    await this.#verifyRuntime(runtime);
    await runtime.session.compact();
    await this.#acknowledgeRuntime(runtime);
  }

  async trashSessionTarget(sessionId: string, expectedGeneration: number) {
    const metadata = this.#sessions.get(sessionId);
    if (!metadata || metadata.generation !== expectedGeneration || metadata.writable) {
      throw new Error('session-trash-rejected');
    }
    const source = this.#sessionSources.get(sessionId);
    if (!source) throw new Error('session-trash-rejected');
    const runtime = this.#runtimeSessions.get(sessionId);
    if (runtime) {
      runtime.changes.close();
      runtime.session.dispose();
      this.#runtimeSessions.delete(sessionId);
    }
    const identity = await observeSessionFile(source.path);
    if (!identity) throw new Error('session-trash-rejected');
    return Object.freeze({
      workspaceId: source.workspaceId,
      workspaceRevision: source.workspaceRevision,
      privatePath: source.path,
      identity: serialiseFileIdentity(identity),
    });
  }

  confirmSessionTrashed(sessionId: string, expectedGeneration: number): Promise<void> {
    const metadata = this.#sessions.get(sessionId);
    if (!metadata || metadata.generation !== expectedGeneration || metadata.writable) {
      return Promise.reject(new Error('session-trash-rejected'));
    }
    this.#sessions.remove(sessionId);
    this.#sessionSources.delete(sessionId);
    return Promise.resolve();
  }

  async listChanges(sessionId: string, expectedGeneration: number) {
    return (await this.#ensureRuntime(sessionId, expectedGeneration)).changes.list();
  }

  async undoChange(sessionId: string, expectedGeneration: number, changeId: string) {
    const runtime = await this.#ensureRuntime(sessionId, expectedGeneration);
    await this.#verifyRuntime(runtime);
    return runtime.changes.undo(changeId, expectedGeneration);
  }

  async changeTarget(sessionId: string, expectedGeneration: number, changeId: string) {
    return (await this.#ensureRuntime(sessionId, expectedGeneration)).changes.target(changeId);
  }

  async listSettings(sessionId: string, expectedGeneration: number) {
    return (await this.#ensureRuntime(sessionId, expectedGeneration)).settings.list();
  }

  async saveSetting(
    sessionId: string,
    expectedGeneration: number,
    key: string,
    value: unknown,
    scope: SettingScope,
    expectedRevision: number,
  ) {
    const runtime = await this.#ensureRuntime(sessionId, expectedGeneration);
    if (busy(runtime)) throw new Error('session-busy');
    runtime.settings.assertRevision(key, expectedRevision);
    const previous = runtime.settings.read(key);
    await applySetting(runtime.session, runtime.settings, key, value);
    try {
      const saved = await runtime.settings.save(key, value, scope, expectedRevision);
      await this.#acknowledgeRuntime(runtime);
      return saved;
    } catch (error) {
      if (previous) {
        try {
          await applySetting(runtime.session, runtime.settings, key, previous.value);
        } catch {
          runtime.changes.close();
          runtime.session.dispose();
          this.#runtimeSessions.delete(sessionId);
          throw new Error('setting-state-uncertain');
        }
      }
      throw error;
    }
  }

  async previewSettingReset(sessionId: string, expectedGeneration: number, key: string) {
    return (await this.#ensureRuntime(sessionId, expectedGeneration)).settings.previewReset(key);
  }

  async listResources(sessionId: string, expectedGeneration: number) {
    return (await this.#ensureRuntime(sessionId, expectedGeneration)).resources.list();
  }

  async setResourceEnabled(
    sessionId: string,
    expectedGeneration: number,
    resourceId: string,
    enabled: boolean,
    acknowledgedExecutableRisk: boolean,
  ) {
    const runtime = await this.#ensureRuntime(sessionId, expectedGeneration);
    if (busy(runtime)) throw new Error('session-busy');
    const change = runtime.resources.prepareEnabledChange(
      resourceId,
      enabled,
      acknowledgedExecutableRisk,
    );
    change.apply();
    let persisted = false;
    try {
      await change.persist();
      persisted = true;
      const resource = runtime.resources.get(resourceId);
      if (resource.kind === 'package') {
        this.#retireRuntime(runtime);
        this.#runtimeSessions.delete(sessionId);
      } else {
        await runtime.session.reload();
        await this.#acknowledgeRuntime(runtime);
      }
      return resource;
    } catch (error) {
      change.rollback();
      if (persisted) {
        try {
          await change.restorePersisted();
        } catch (restoreError) {
          this.#retireRuntime(runtime);
          this.#runtimeSessions.delete(sessionId);
          throw new Error('resource-state-uncertain', { cause: restoreError });
        }
        this.#retireRuntime(runtime);
        this.#runtimeSessions.delete(sessionId);
      }
      throw error;
    }
  }

  async installPackage(
    sessionId: string,
    expectedGeneration: number,
    source: string,
    scope: 'global' | 'project',
    online: boolean,
    acknowledgedExecutableRisk: boolean,
  ) {
    const runtime = await this.#ensureRuntime(sessionId, expectedGeneration);
    if (busy(runtime)) throw new Error('session-busy');
    await this.#verifyRuntime(runtime);
    const resource = await runtime.resources.installPackage(
      source,
      scope,
      online,
      acknowledgedExecutableRisk,
    );
    this.#retireRuntime(runtime);
    this.#runtimeSessions.delete(sessionId);
    return resource;
  }

  async mutatePackage(
    sessionId: string,
    expectedGeneration: number,
    resourceId: string,
    operation: 'update' | 'remove',
    online: boolean,
    acknowledgedExecutableRisk: boolean,
  ) {
    const runtime = await this.#ensureRuntime(sessionId, expectedGeneration);
    if (busy(runtime)) throw new Error('session-busy');
    await this.#verifyRuntime(runtime);
    const resource = await runtime.resources.mutatePackage(
      resourceId,
      operation,
      online,
      acknowledgedExecutableRisk,
    );
    this.#retireRuntime(runtime);
    this.#runtimeSessions.delete(sessionId);
    return resource;
  }

  async queueFollowUp(sessionId: string, expectedGeneration: number, text: string) {
    const session = this.#sessions.get(sessionId);
    const runtime = this.#runtimeSessions.get(sessionId);
    if (!session || !runtime || !session.writable || session.generation !== expectedGeneration) {
      throw new Error('session-write-rejected');
    }
    if (!runtime.session.isStreaming) throw new Error('queue-turn-not-running');
    await this.#verifyRuntime(runtime);
    await runtime.session.followUp(text);
    const number = (this.#queueNumbers.get(sessionId) ?? 0) + 1;
    this.#queueNumbers.set(sessionId, number);
    return Object.freeze({ queueId: `queue-${randomUUID().replaceAll('-', '')}`, number });
  }

  async replaceFollowUpQueue(
    sessionId: string,
    expectedGeneration: number,
    texts: readonly string[],
  ) {
    const session = this.#sessions.get(sessionId);
    const runtime = this.#runtimeSessions.get(sessionId);
    if (!session || !runtime || !session.writable || session.generation !== expectedGeneration) {
      throw new Error('session-write-rejected');
    }
    if (!runtime.session.isStreaming) throw new Error('queue-turn-not-running');
    await this.#verifyRuntime(runtime);
    const original = [...runtime.session.getFollowUpMessages()];
    runtime.session.clearQueue();
    try {
      for (const text of texts) await runtime.session.followUp(text);
      this.#queueNumbers.set(sessionId, texts.length);
      return Object.freeze({ count: texts.length });
    } catch (error) {
      runtime.session.clearQueue();
      try {
        for (const text of original) await runtime.session.followUp(text);
      } catch {
        runtime.changes.close();
        runtime.session.dispose();
        this.#runtimeSessions.delete(sessionId);
        this.#sessions.close();
        throw new Error('queue-state-uncertain');
      }
      throw error;
    }
  }

  async exportSession(
    sessionId: string,
    expectedGeneration: number,
    destination: string,
  ): Promise<void> {
    const session = this.#sessions.get(sessionId);
    if (!session || session.generation !== expectedGeneration) {
      throw new Error('session-generation-stale');
    }
    const runtime = await this.#ensureRuntime(sessionId, expectedGeneration);
    runtime.session.exportToJsonl(destination);
  }

  async *streamTurn(
    request: AdapterTurnRequest,
    signal: AbortSignal,
  ): AsyncIterable<AdapterTurnEvent> {
    const session = this.#sessions.get(request.sessionId);
    if (!session || !session.writable || session.generation !== request.generation)
      throw new Error('session-write-rejected');
    const runtime = this.#runtimeSessions.get(request.sessionId);
    if (!runtime) throw new Error('session-runtime-unavailable');
    if (busy(runtime)) throw new Error('session-busy');
    await this.#verifyRuntime(runtime);
    const active = this.#turns.begin(request, signal);
    this.#queueNumbers.set(request.sessionId, 0);
    const abort = () => {
      void runtime.session.abort();
    };
    let unsubscribe: (() => void) | undefined;
    let ownTurn: OwnTurn | undefined;
    let promptStarted = false;
    let text: TextDeltaCoalescer | undefined;
    // Everything after begin() sits inside this try so that every exit,
    // including a stale retry, retires the turn registry entry.
    try {
      yield { requestId: request.requestId, sequence: active.nextSequence(), type: 'started' };
      if (active.controller.signal.aborted) {
        yield { requestId: request.requestId, sequence: active.nextSequence(), type: 'stopped' };
        return;
      }
      // From here until the turn settles, Pi's appends to this session file
      // are PIUI's own writes rather than an external change.
      const turn = this.#beginOwnTurn(runtime);
      ownTurn = turn;
      if (request.retryPrevious) {
        const previous = runtime.session.getUserMessagesForForking().at(-1);
        if (!previous || previous.text !== request.text) throw new Error('turn-retry-stale');
        const navigation = await runtime.session.navigateTree(previous.entryId);
        if (navigation.cancelled || navigation.editorText !== request.text) {
          throw new Error('turn-retry-stale');
        }
      }
      const pending: AdapterTurnEvent[] = [];
      let wake: (() => void) | undefined;
      let terminal = false;
      const push = (event: Omit<AdapterTurnEvent, 'requestId' | 'sequence'>) => {
        pending.push({ ...event, requestId: request.requestId, sequence: active.nextSequence() });
        const release = wake;
        wake = undefined;
        release?.();
      };
      const coalescer = new TextDeltaCoalescer((value) => push({ type: 'text', text: value }));
      text = coalescer;
      unsubscribe = runtime.session.subscribe((event) => {
        if (event.type === 'message_update' && event.assistantMessageEvent.type === 'text_delta') {
          coalescer.push(event.assistantMessageEvent.delta);
        } else if (event.type === 'tool_execution_start') {
          coalescer.flush();
          push({
            type: 'tool',
            text: event.toolName,
            code: 'started',
            toolCallId: event.toolCallId,
          });
        } else if (event.type === 'tool_execution_end') {
          coalescer.flush();
          push({
            type: 'tool',
            text: event.toolName,
            code: event.isError ? 'failed' : 'complete',
            toolCallId: event.toolCallId,
          });
        }
      });
      active.controller.signal.addEventListener('abort', abort, { once: true });
      promptStarted = true;
      void runtime.session
        .prompt(request.text, {
          source: 'interactive',
          images: request.images.map((image) => ({ ...image })),
        })
        .then(
          async () => {
            await this.#finishOwnTurn(runtime, turn);
            coalescer.flush();
            terminal = true;
            push({ type: active.controller.signal.aborted ? 'stopped' : 'complete' });
          },
          async (error: unknown) => {
            runtime.session.clearQueue();
            await this.#finishOwnTurn(runtime, turn);
            coalescer.flush();
            terminal = true;
            const code =
              error instanceof Error && error.message === 'This action was not approved.'
                ? 'tool-not-approved'
                : 'provider-turn-failed';
            push({ type: active.controller.signal.aborted ? 'stopped' : 'failed', code });
          },
        )
        .catch(() => {
          runtime.session.clearQueue();
          coalescer.flush();
          terminal = true;
          push({ type: 'failed', code: 'session-external-change' });
        });
      while (!terminal || pending.length > 0) {
        if (pending.length === 0) {
          await new Promise<void>((resolve) => {
            wake = resolve;
          });
          continue;
        }
        const event = pending.shift();
        if (event) yield event;
      }
    } finally {
      // Once Pi's prompt runs, its own settlement closes the window instead.
      if (ownTurn && !promptStarted) {
        try {
          await this.#finishOwnTurn(runtime, ownTurn);
        } catch {
          // The watch stays unacknowledged, so the next write reports the change.
        }
      }
      this.#queueNumbers.delete(request.sessionId);
      active.controller.signal.removeEventListener('abort', abort);
      unsubscribe?.();
      text?.dispose();
      this.#turns.finish(
        request.requestId,
        active.controller.signal.aborted ? 'stopped' : 'complete',
      );
    }
  }

  async stopTurn(requestId: string): Promise<'stopped' | 'too-late' | 'unknown'> {
    return this.#turns.stop(requestId);
  }

  async diagnosticSnapshot(): Promise<Readonly<Record<string, unknown>>> {
    const metadata = publicSdkMetadata();
    return safeDiagnosticSnapshot({
      ...metadata,
      providerCount: this.#runtime.getProviders().length,
      sessionCount: this.#sessions.list().length,
      rawRpcEnabled: false,
      retirementFailures: this.#retirementFailures,
    });
  }

  async close(): Promise<void> {
    for (const runtime of this.#runtimeSessions.values()) {
      this.#retireRuntime(runtime);
    }
    this.#runtimeSessions.clear();
    this.#sessionSources.clear();
    this.#sessions.close();
  }

  async #ensureRuntime(sessionId: string, expectedGeneration: number) {
    const metadata = this.#sessions.get(sessionId);
    if (!metadata || metadata.generation !== expectedGeneration)
      throw new Error('session-generation-stale');
    const existing = this.#runtimeSessions.get(sessionId);
    if (existing) return existing;
    const source = this.#sessionSources.get(sessionId);
    if (!source) throw new Error('session-runtime-unavailable');
    return this.#constructRuntime(
      metadata,
      PublicSessionManager.open(source.path, undefined, source.workspacePath),
      {
        workspaceId: source.workspaceId,
        workspaceRevision: source.workspaceRevision,
        workspacePath: source.workspacePath,
        agentDir: source.agentDir,
        ...(source.providerId ? { providerId: source.providerId } : {}),
        ...(source.modelId ? { modelId: source.modelId } : {}),
      },
    );
  }

  async #constructRuntime(
    metadata: AdapterSession,
    sessionManager: PublicSessionManagerInstance,
    request: AdapterSessionCreateRequest,
  ) {
    const model = await this.#selectModel(request.providerId, request.modelId);
    const changes = await ChangeRegistry.create({
      workspaceId: request.workspaceId,
      workspaceRevision: request.workspaceRevision,
      workspacePath: request.workspacePath,
      sessionId: metadata.id,
      sessionGeneration: metadata.generation,
    });
    const gate = createApprovalGate(
      this.#approvalHost,
      Object.freeze({
        generation: this.#generation,
        sessionId: metadata.id,
        workspaceId: request.workspaceId,
        workspaceRevision: request.workspaceRevision,
      }),
      {
        beforeExecute: (toolName, params) => changes.beforeExecute(toolName, params),
        afterExecute: (token, result, error) => changes.afterExecute(token, result, error),
      },
    );
    const bashSpawnHook = userShellSpawnHook(process.env, publicPiBinDir());
    const definitions = publicCreateToolDefinitions(
      request.workspacePath,
      bashSpawnHook ? { bashSpawnHook } : {},
    ).map(gate.decorateToolDefinition);
    const settingsManager = PublicSettingsManager.create(request.workspacePath, request.agentDir, {
      projectTrusted: true,
    });
    settingsManager.applyOverrides({
      packages: [],
      extensions: [],
      enableInstallTelemetry: false,
      enableAnalytics: false,
    });
    const packageSettingsManager = PublicSettingsManager.create(
      request.workspacePath,
      request.agentDir,
      { projectTrusted: true },
    );
    packageSettingsManager.applyOverrides({
      enableInstallTelemetry: false,
      enableAnalytics: false,
    });
    const packageManager = new PublicPackageManager({
      cwd: request.workspacePath,
      agentDir: request.agentDir,
      settingsManager: packageSettingsManager,
    });
    const resources = await ResourceRegistry.create(
      request.workspacePath,
      request.agentDir,
      packageManager,
    );
    await resources.discoverExecutableMetadata();
    const packagePaths = await resolveEnabledPackagePaths(
      packageManager,
      resources.enabledPackageSources,
    );
    const services = await publicCreateAgentSessionServices({
      cwd: request.workspacePath,
      agentDir: request.agentDir,
      settingsManager,
      modelRuntime: this.#runtime,
      resourceLoaderOptions: {
        extensionFactories: [gate.extension],
        noExtensions: true,
        noSkills: false,
        noPromptTemplates: false,
        noThemes: false,
        noContextFiles: true,
        additionalExtensionPaths: [
          ...resources.enabledExtensionPaths,
          ...packagePaths.extensions.filter((resource) => resource.enabled).map((resource) => resource.path),
        ],
        additionalSkillPaths: packagePaths.skills
          .filter((resource) => resource.enabled)
          .map((resource) => resource.path),
        additionalPromptTemplatePaths: packagePaths.prompts
          .filter((resource) => resource.enabled)
          .map((resource) => resource.path),
        additionalThemePaths: packagePaths.themes
          .filter((resource) => resource.enabled)
          .map((resource) => resource.path),
        skillsOverride: (base) => resources.filterSkills(base),
        promptsOverride: (base) => resources.filterPrompts(base),
        themesOverride: (base) => resources.filterThemes(base),
        systemPrompt:
          'You are Pi, working in the user-selected local project. Explain consequential work clearly and use tools only when their exact action has been approved by PIUI.',
        appendSystemPrompt: [],
      },
    });
    const created = await publicCreateAgentSessionFromServices({
      services,
      sessionManager,
      model,
      thinkingLevel: 'medium',
      noTools: 'builtin',
      customTools: [...definitions],
    });
    gate.bindSession(created.session);
    const watch = new SessionWatch();
    const watchGeneration = { value: 0 };
    const settings = await TypedSettingsAdapter.create(request.workspacePath, request.agentDir);
    seedSettings(settings, created.session);
    for (const record of settings.list()) {
      if (record.origin.startsWith('PIUI ')) {
        await applySetting(created.session, settings, record.key, record.value);
      }
    }
    const record = Object.freeze({
      session: created.session,
      workspaceRevision: request.workspaceRevision,
      workspacePath: request.workspacePath,
      agentDir: request.agentDir,
      ...(request.providerId ? { providerId: request.providerId } : {}),
      ...(request.modelId ? { modelId: request.modelId } : {}),
      watch,
      watchGeneration,
      changes,
      settings,
      resources,
    });
    try {
      await this.#acknowledgeRuntime(record);
    } catch (error) {
      changes.close();
      created.session.dispose();
      throw error;
    }
    this.#runtimeSessions.set(metadata.id, record);
    return record;
  }

  async #verifyRuntime(runtime: {
    session: PublicAgentSession;
    watch: SessionWatch;
    watchGeneration: { value: number };
  }): Promise<void> {
    const path = runtime.session.sessionFile;
    if (!path) throw new Error('session-file-unavailable');
    const status = runtime.watch.verify(
      await observeSessionFile(path),
      runtime.watchGeneration.value,
    );
    if (status !== 'current') throw new Error('session-external-change');
  }

  async #acknowledgeRuntime(runtime: {
    session: PublicAgentSession;
    watch: SessionWatch;
    watchGeneration: { value: number };
  }): Promise<void> {
    const path = runtime.session.sessionFile;
    if (!path) throw new Error('session-file-unavailable');
    runtime.watchGeneration.value = runtime.watch.acknowledge(await observeSessionFile(path));
  }

  #beginOwnTurn(runtime: { session: PublicAgentSession; watch: SessionWatch }): OwnTurn {
    const identity = runtime.watch.beginOwnWrite();
    return Object.freeze({
      identity,
      entryCount: runtime.session.sessionManager.getEntries().length,
    });
  }

  /**
   * Closes PIUI's own-write window. Everything Pi appended since the turn began
   * must be exactly the entries Pi now holds beyond the baseline (or, for Pi's
   * first write of a new file, the header and every entry) before the new file
   * identity is acknowledged; anything else leaves the watch reporting a change.
   */
  async #finishOwnTurn(
    runtime: {
      session: PublicAgentSession;
      watch: SessionWatch;
      watchGeneration: { value: number };
    },
    turn: OwnTurn,
  ): Promise<void> {
    try {
      const path = runtime.session.sessionFile;
      if (!path) throw new Error('session-file-unavailable');
      const manager = runtime.session.sessionManager;
      const entries = manager.getEntries();
      const header = manager.getHeader();
      const written =
        turn.identity === null
          ? [...(header ? [header] : []), ...entries]
          : entries.slice(turn.entryCount);
      const identity = await verifyOwnAppends(
        path,
        turn.identity,
        written.map((entry) => ({ type: entry.type, id: entry.id })),
      );
      runtime.watchGeneration.value = runtime.watch.acknowledge(identity);
    } finally {
      runtime.watch.endOwnWrite();
    }
  }

  async #selectModel(providerId?: string, modelId?: string) {
    if (providerId && modelId) {
      const exact = this.#runtime.getModel(providerId, modelId);
      if (!exact || !(await this.#runtime.checkAuth(providerId)))
        throw new Error('provider-model-unavailable');
      return exact;
    }
    const available = await this.#runtime.getAvailable(providerId);
    const selected = modelId ? available.find((model) => model.id === modelId) : available[0];
    if (!selected) throw new Error('provider-not-connected');
    return selected;
  }

  #assertNoBusyRuntime(): void {
    if ([...this.#runtimeSessions.values()].some(busy)) {
      throw new Error('session-turn-active');
    }
  }

  #retireRuntime(runtime: { changes: ChangeRegistry; session: PublicAgentSession }): void {
    runtime.changes.close();
    try {
      runtime.session.dispose();
    } catch {
      this.#retirementFailures += 1;
    }
  }
}

type OwnTurn = Readonly<{ identity: ObservedIdentity; entryCount: number }>;

// A runtime stays busy until its turn's own-write window has been verified and
// closed, which is slightly after Pi itself reports idle.
function busy(runtime: { session: PublicAgentSession; watch: SessionWatch }): boolean {
  return !runtime.session.isIdle || runtime.watch.ownWriteActive;
}

// The host clears the sidecar environment and seals HOME inside the signed
// bundle resources, so Pi's default `getAgentDir()/models.json` would read and
// write models state inside those resources. The host passes the user's real
// Pi agent directory instead, which is where the Pi CLI keeps its own models
// configuration and store. Without a trustworthy directory we keep the models
// store in memory: the SDK default is never an acceptable fallback here.
function hostModelsPath(): string | null {
  const agentDir = process.env.PIUI_PI_AGENT_DIR;
  return agentDir !== undefined && isAbsolute(agentDir) ? join(agentDir, 'models.json') : null;
}

function opaqueSessionId(value: string): string {
  return `session-${createHash('sha256').update(value, 'utf8').digest('hex').slice(0, 32)}`;
}

function serialiseFileIdentity(value: FileIdentity): string {
  return `${value.device}:${value.inode}:${value.size}:${value.modifiedNs}`;
}

function boundedTitle(value: string): string {
  const title = [...value.trim().replaceAll(/\p{Cc}/gu, ' ')].slice(0, 160).join('').trim();
  return title || 'Untitled conversation';
}

function boundedPreview(value: string): string {
  return [...value.replaceAll(/\p{Cc}/gu, ' ').trim()].slice(0, 1_024).join('');
}

function projectEntry(entry: unknown): AdapterMessage[] {
  if (!entry || typeof entry !== 'object') return [];
  const record = entry as Record<string, unknown>;
  const id = typeof record.id === 'string' ? record.id.slice(0, 160) : `entry-${randomUUID()}`;
  const parsedTimestamp =
    typeof record.timestamp === 'string' ? Date.parse(record.timestamp) : Number.NaN;
  const timestampUnixMs = Number.isFinite(parsedTimestamp) ? parsedTimestamp : 0;
  if (record.type === 'compaction' && typeof record.summary === 'string') {
    return [
      Object.freeze({
        id,
        role: 'system' as const,
        timestampUnixMs,
        text: boundedMessage(record.summary),
        kind: 'compaction' as const,
      }),
    ];
  }
  if (record.type !== 'message' || !record.message || typeof record.message !== 'object') return [];
  const message = record.message as Record<string, unknown>;
  if (!['user', 'assistant', 'system'].includes(String(message.role))) return [];
  const text = messageText(message.content);
  if (!text) return [];
  return [
    Object.freeze({
      id,
      role: message.role as 'user' | 'assistant' | 'system',
      timestampUnixMs:
        typeof message.timestamp === 'number' && Number.isFinite(message.timestamp)
          ? message.timestamp
          : timestampUnixMs,
      text,
      kind: 'message' as const,
    }),
  ];
}

function messageText(value: unknown): string {
  if (typeof value === 'string') return boundedMessage(value);
  if (!Array.isArray(value)) return '';
  return boundedMessage(
    value
      .flatMap((part) => {
        if (!part || typeof part !== 'object') return [];
        const record = part as Record<string, unknown>;
        return record.type === 'text' && typeof record.text === 'string' ? [record.text] : [];
      })
      .join('\n'),
  );
}

function boundedMessage(value: string): string {
  return value.slice(0, 262_144);
}

function seedSettings(settings: TypedSettingsAdapter, session: PublicAgentSession): void {
  settings.seed('model.provider', session.model?.provider ?? null, 'project', 'Current Pi session');
  settings.seed('model.id', session.model?.id ?? null, 'project', 'Current Pi session');
  settings.seed('reasoning.level', session.thinkingLevel, 'project', 'Current Pi session');
  settings.seed('tools.active', session.getActiveToolNames(), 'project', 'Current Pi session');
  settings.seed(
    'compaction.enabled',
    session.autoCompactionEnabled,
    'project',
    'Current Pi session',
  );
  settings.seed('retry.enabled', session.autoRetryEnabled, 'project', 'Current Pi session');
  settings.seed('queue.follow-up-mode', session.followUpMode, 'project', 'Current Pi session');
}

async function applySetting(
  session: PublicAgentSession,
  settings: TypedSettingsAdapter,
  key: string,
  value: unknown,
): Promise<void> {
  switch (key) {
    case 'model.provider':
      if (value === null) return;
      if (typeof value !== 'string' || value.length > 128) throw new Error('setting-value-invalid');
      return;
    case 'model.id': {
      if (typeof value !== 'string' || value.length > 256) throw new Error('setting-value-invalid');
      const provider = settings.read('model.provider')?.value;
      if (typeof provider !== 'string') throw new Error('setting-value-invalid');
      const model = session.modelRuntime.getModel(provider, value);
      if (!model) throw new Error('provider-model-unavailable');
      await session.setModel(model);
      return;
    }
    case 'reasoning.level':
      if (!['off', 'minimal', 'low', 'medium', 'high', 'xhigh'].includes(String(value))) {
        throw new Error('setting-value-invalid');
      }
      session.setThinkingLevel(value as 'off' | 'minimal' | 'low' | 'medium' | 'high' | 'xhigh');
      return;
    case 'tools.active': {
      if (
        !Array.isArray(value) ||
        value.length > 64 ||
        !value.every((item) => typeof item === 'string' && item.length <= 128)
      ) {
        throw new Error('setting-value-invalid');
      }
      const available = new Set(session.getAllTools().map((tool) => tool.name));
      if (value.some((name) => !available.has(name))) throw new Error('setting-value-invalid');
      session.setActiveToolsByName(value);
      return;
    }
    case 'compaction.enabled':
      if (typeof value !== 'boolean') throw new Error('setting-value-invalid');
      session.setAutoCompactionEnabled(value);
      return;
    case 'retry.enabled':
      if (typeof value !== 'boolean') throw new Error('setting-value-invalid');
      session.setAutoRetryEnabled(value);
      return;
    case 'queue.follow-up-mode':
      if (value !== 'all' && value !== 'one-at-a-time') throw new Error('setting-value-invalid');
      session.setFollowUpMode(value);
      return;
    default:
      throw new Error('setting-key-unsupported');
  }
}
