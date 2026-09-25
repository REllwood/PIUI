import { isAbsolute } from 'node:path';
import { readFile } from 'node:fs/promises';
import type { ProtocolEnvelope } from '@piui/protocol';
import type { HostRequestClient } from '../bridge/host-requests.js';
import { PiCredentialStore } from '../credentials/store-proxy.js';
import type {
  AdapterTurnEvent,
  AdapterTurnRequest,
  PiAdapter,
  PiAdapterOptions,
} from './adapter.js';
import { Pi082Adapter } from './pi-082-adapter.js';

const INTERNAL_ID = /^rust-product-[A-Za-z0-9._:-]{1,111}$/;
const PUBLIC_ID = /^web-[A-Za-z0-9._:-]{1,124}$/;
const OPAQUE_SESSION = /^session-[a-f0-9]{32}$/;
const OPAQUE_WORKSPACE = /^workspace-[a-f0-9]{32}$/;
const MAX_PATH_BYTES = 4_096;
const MAX_TEXT_BYTES = 262_144;

function isRecord(value: unknown): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  );
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => actual.includes(key));
}

function boundedInteger(value: unknown, positive = false): value is number {
  return Number.isSafeInteger(value) && (value as number) >= (positive ? 1 : 0);
}

function optionalIdentifier(value: unknown, maximum: number): value is string | null {
  return (
    value === null ||
    (typeof value === 'string' &&
      value.length > 0 &&
      value.length <= maximum &&
      /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value))
  );
}

function assertEnvelopeBase(value: unknown, id: RegExp): asserts value is ProtocolEnvelope {
  if (
    !isRecord(value) ||
    !exactKeys(value, ['version', 'kind', 'id', 'sequence', 'payload']) ||
    value.version !== 1 ||
    value.kind !== 'request' ||
    typeof value.id !== 'string' ||
    !id.test(value.id) ||
    !boundedInteger(value.sequence) ||
    !isRecord(value.payload)
  ) {
    throw new Error('product-request-rejected');
  }
}

export function assertProductRequestEnvelope(value: unknown): asserts value is ProtocolEnvelope {
  assertEnvelopeBase(value, INTERNAL_ID);
  assertProductRequest(value.payload);
}

export function assertProductTurnEnvelope(value: unknown): asserts value is ProtocolEnvelope {
  assertEnvelopeBase(value, PUBLIC_ID);
  const payload = value.payload;
  if (
    !exactKeys(payload, [
      'method',
      'schemaVersion',
      'sessionId',
      'generation',
      'text',
      'retryPrevious',
      'attachments',
    ]) ||
    payload.method !== 'product.turn.start' ||
    payload.schemaVersion !== 1 ||
    typeof payload.sessionId !== 'string' ||
    !OPAQUE_SESSION.test(payload.sessionId) ||
    !boundedInteger(payload.generation, true) ||
    typeof payload.text !== 'string' ||
    !payload.text.trim() ||
    Buffer.byteLength(payload.text, 'utf8') > MAX_TEXT_BYTES ||
    payload.text.includes('\0') ||
    typeof payload.retryPrevious !== 'boolean' ||
    !Array.isArray(payload.attachments) ||
    payload.attachments.length > 8 ||
    !payload.attachments.every(validAttachment)
  ) {
    throw new Error('product-turn-rejected');
  }
}

export function assertProductAuthEnvelope(value: unknown): asserts value is ProtocolEnvelope {
  assertEnvelopeBase(value, PUBLIC_ID);
  const payload = value.payload;
  if (
    !exactKeys(payload, ['method', 'schemaVersion', 'providerId', 'authMethod']) ||
    payload.method !== 'product.auth.start' ||
    payload.schemaVersion !== 1 ||
    typeof payload.providerId !== 'string' ||
    !optionalIdentifier(payload.providerId, 128) ||
    payload.authMethod !== 'subscription'
  ) {
    throw new Error('product-auth-rejected');
  }
}

function validAttachment(value: unknown): boolean {
  if (!isRecord(value) || !exactKeys(value, ['capabilityId', 'mime', 'byteLength', 'privatePath']))
    return false;
  return (
    typeof value.capabilityId === 'string' &&
    /^attachment-[a-f0-9]{32}$/u.test(value.capabilityId) &&
    ['image/png', 'image/jpeg', 'image/webp'].includes(String(value.mime)) &&
    boundedInteger(value.byteLength, true) &&
    (value.byteLength as number) <= 20 * 1024 * 1024 &&
    typeof value.privatePath === 'string' &&
    isAbsolute(value.privatePath) &&
    Buffer.byteLength(value.privatePath, 'utf8') <= MAX_PATH_BYTES &&
    !/\p{Cc}/u.test(value.privatePath)
  );
}

function assertProductRequest(payload: Record<string, unknown>): void {
  const method = payload.method;
  if (method === 'product.providers.list' || method === 'product.diagnostics') {
    if (!exactKeys(payload, ['method'])) throw new Error('product-request-rejected');
    return;
  }
  if (method === 'product.provider.logout') {
    if (
      !exactKeys(payload, ['method', 'schemaVersion', 'providerId']) ||
      payload.schemaVersion !== 1 ||
      typeof payload.providerId !== 'string' ||
      !optionalIdentifier(payload.providerId, 128)
    ) {
      throw new Error('product-request-rejected');
    }
    return;
  }
  if (method === 'product.session.create') {
    if (
      !exactKeys(payload, [
        'method',
        'schemaVersion',
        'workspaceId',
        'workspaceRevision',
        'workspacePath',
        'agentDir',
        'title',
        'providerId',
        'modelId',
      ]) ||
      payload.schemaVersion !== 1 ||
      typeof payload.workspaceId !== 'string' ||
      !OPAQUE_WORKSPACE.test(payload.workspaceId) ||
      !boundedInteger(payload.workspaceRevision) ||
      typeof payload.workspacePath !== 'string' ||
      !isAbsolute(payload.workspacePath) ||
      Buffer.byteLength(payload.workspacePath, 'utf8') > MAX_PATH_BYTES ||
      /\p{Cc}/u.test(payload.workspacePath) ||
      typeof payload.agentDir !== 'string' ||
      !isAbsolute(payload.agentDir) ||
      Buffer.byteLength(payload.agentDir, 'utf8') > MAX_PATH_BYTES ||
      /\p{Cc}/u.test(payload.agentDir) ||
      !(
        payload.title === null ||
        (typeof payload.title === 'string' &&
          payload.title.length > 0 &&
          [...payload.title].length <= 160 &&
          !/\p{Cc}/u.test(payload.title))
      ) ||
      !optionalIdentifier(payload.providerId, 128) ||
      !optionalIdentifier(payload.modelId, 256)
    ) {
      throw new Error('product-request-rejected');
    }
    return;
  }
  if (method === 'product.sessions.list') {
    if (
      !exactKeys(payload, [
        'method',
        'schemaVersion',
        'workspaceId',
        'workspaceRevision',
        'workspacePath',
        'agentDir',
      ]) ||
      payload.schemaVersion !== 1 ||
      typeof payload.workspaceId !== 'string' ||
      !OPAQUE_WORKSPACE.test(payload.workspaceId) ||
      !boundedInteger(payload.workspaceRevision) ||
      typeof payload.workspacePath !== 'string' ||
      !isAbsolute(payload.workspacePath) ||
      Buffer.byteLength(payload.workspacePath, 'utf8') > MAX_PATH_BYTES ||
      /\p{Cc}/u.test(payload.workspacePath) ||
      typeof payload.agentDir !== 'string' ||
      !isAbsolute(payload.agentDir) ||
      Buffer.byteLength(payload.agentDir, 'utf8') > MAX_PATH_BYTES ||
      /\p{Cc}/u.test(payload.agentDir)
    ) {
      throw new Error('product-request-rejected');
    }
    return;
  }
  if (
    method === 'product.session.resume' ||
    method === 'product.session.fork' ||
    method === 'product.session.inspect' ||
    method === 'product.session.compact' ||
    method === 'product.session.trash-target' ||
    method === 'product.session.trash-complete' ||
    method === 'product.changes.list' ||
    method === 'product.settings.list' ||
    method === 'product.resources.list'
  ) {
    if (
      !exactKeys(payload, ['method', 'schemaVersion', 'sessionId', 'expectedGeneration']) ||
      payload.schemaVersion !== 1 ||
      typeof payload.sessionId !== 'string' ||
      !OPAQUE_SESSION.test(payload.sessionId) ||
      !boundedInteger(payload.expectedGeneration, true)
    ) {
      throw new Error('product-request-rejected');
    }
    return;
  }
  if (method === 'product.resource.set-enabled') {
    if (
      !exactKeys(payload, [
        'method',
        'schemaVersion',
        'sessionId',
        'expectedGeneration',
        'resourceId',
        'enabled',
        'acknowledgedExecutableRisk',
      ]) ||
      payload.schemaVersion !== 1 ||
      typeof payload.sessionId !== 'string' ||
      !OPAQUE_SESSION.test(payload.sessionId) ||
      !boundedInteger(payload.expectedGeneration, true) ||
      typeof payload.resourceId !== 'string' ||
      !/^resource-[a-f0-9]{32}$/u.test(payload.resourceId) ||
      typeof payload.enabled !== 'boolean' ||
      typeof payload.acknowledgedExecutableRisk !== 'boolean'
    ) {
      throw new Error('product-request-rejected');
    }
    return;
  }
  if (method === 'product.package.install') {
    if (
      !exactKeys(payload, [
        'method',
        'schemaVersion',
        'sessionId',
        'expectedGeneration',
        'source',
        'scope',
        'online',
        'acknowledgedExecutableRisk',
      ]) ||
      payload.schemaVersion !== 1 ||
      typeof payload.sessionId !== 'string' ||
      !OPAQUE_SESSION.test(payload.sessionId) ||
      !boundedInteger(payload.expectedGeneration, true) ||
      typeof payload.source !== 'string' ||
      payload.source.length > 256 ||
      /\p{Cc}/u.test(payload.source) ||
      !['global', 'project'].includes(String(payload.scope)) ||
      typeof payload.online !== 'boolean' ||
      typeof payload.acknowledgedExecutableRisk !== 'boolean'
    ) {
      throw new Error('product-request-rejected');
    }
    return;
  }
  if (method === 'product.package.mutate') {
    if (
      !exactKeys(payload, [
        'method',
        'schemaVersion',
        'sessionId',
        'expectedGeneration',
        'resourceId',
        'operation',
        'online',
        'acknowledgedExecutableRisk',
      ]) ||
      payload.schemaVersion !== 1 ||
      typeof payload.sessionId !== 'string' ||
      !OPAQUE_SESSION.test(payload.sessionId) ||
      !boundedInteger(payload.expectedGeneration, true) ||
      typeof payload.resourceId !== 'string' ||
      !/^resource-[a-f0-9]{32}$/u.test(payload.resourceId) ||
      !['update', 'remove'].includes(String(payload.operation)) ||
      typeof payload.online !== 'boolean' ||
      typeof payload.acknowledgedExecutableRisk !== 'boolean'
    ) {
      throw new Error('product-request-rejected');
    }
    return;
  }
  if (method === 'product.setting.save') {
    if (
      !exactKeys(payload, [
        'method',
        'schemaVersion',
        'sessionId',
        'expectedGeneration',
        'key',
        'value',
        'scope',
        'expectedRevision',
      ]) ||
      payload.schemaVersion !== 1 ||
      typeof payload.sessionId !== 'string' ||
      !OPAQUE_SESSION.test(payload.sessionId) ||
      !boundedInteger(payload.expectedGeneration, true) ||
      typeof payload.key !== 'string' ||
      !/^[a-z][a-z0-9.-]{0,127}$/u.test(payload.key) ||
      !['global', 'project'].includes(String(payload.scope)) ||
      !boundedInteger(payload.expectedRevision) ||
      Buffer.byteLength(JSON.stringify(payload.value), 'utf8') > 16_384
    ) {
      throw new Error('product-request-rejected');
    }
    return;
  }
  if (method === 'product.setting.reset-preview') {
    if (
      !exactKeys(payload, ['method', 'schemaVersion', 'sessionId', 'expectedGeneration', 'key']) ||
      payload.schemaVersion !== 1 ||
      typeof payload.sessionId !== 'string' ||
      !OPAQUE_SESSION.test(payload.sessionId) ||
      !boundedInteger(payload.expectedGeneration, true) ||
      typeof payload.key !== 'string' ||
      !/^[a-z][a-z0-9.-]{0,127}$/u.test(payload.key)
    ) {
      throw new Error('product-request-rejected');
    }
    return;
  }
  if (method === 'product.change.undo' || method === 'product.change.target') {
    if (
      !exactKeys(payload, [
        'method',
        'schemaVersion',
        'sessionId',
        'expectedGeneration',
        'changeId',
      ]) ||
      payload.schemaVersion !== 1 ||
      typeof payload.sessionId !== 'string' ||
      !OPAQUE_SESSION.test(payload.sessionId) ||
      !boundedInteger(payload.expectedGeneration, true) ||
      typeof payload.changeId !== 'string' ||
      !/^change-[a-f0-9]{32}$/u.test(payload.changeId)
    ) {
      throw new Error('product-request-rejected');
    }
    return;
  }
  if (method === 'product.session.rename') {
    if (
      !exactKeys(payload, [
        'method',
        'schemaVersion',
        'sessionId',
        'expectedGeneration',
        'title',
      ]) ||
      payload.schemaVersion !== 1 ||
      typeof payload.sessionId !== 'string' ||
      !OPAQUE_SESSION.test(payload.sessionId) ||
      !boundedInteger(payload.expectedGeneration, true) ||
      typeof payload.title !== 'string' ||
      !payload.title.trim() ||
      [...payload.title].length > 160 ||
      /\p{Cc}/u.test(payload.title)
    ) {
      throw new Error('product-request-rejected');
    }
    return;
  }
  if (method === 'product.queue.followup') {
    if (
      !exactKeys(payload, ['method', 'schemaVersion', 'sessionId', 'expectedGeneration', 'text']) ||
      payload.schemaVersion !== 1 ||
      typeof payload.sessionId !== 'string' ||
      !OPAQUE_SESSION.test(payload.sessionId) ||
      !boundedInteger(payload.expectedGeneration, true) ||
      typeof payload.text !== 'string' ||
      !payload.text.trim() ||
      Buffer.byteLength(payload.text, 'utf8') > MAX_TEXT_BYTES ||
      payload.text.includes('\0')
    ) {
      throw new Error('product-request-rejected');
    }
    return;
  }
  if (method === 'product.queue.replace') {
    if (
      !exactKeys(payload, [
        'method',
        'schemaVersion',
        'sessionId',
        'expectedGeneration',
        'texts',
      ]) ||
      payload.schemaVersion !== 1 ||
      typeof payload.sessionId !== 'string' ||
      !OPAQUE_SESSION.test(payload.sessionId) ||
      !boundedInteger(payload.expectedGeneration, true) ||
      !Array.isArray(payload.texts) ||
      payload.texts.length > 64 ||
      !payload.texts.every(
        (text) =>
          typeof text === 'string' &&
          text.trim().length > 0 &&
          Buffer.byteLength(text, 'utf8') <= MAX_TEXT_BYTES &&
          !text.includes('\0'),
      )
    ) {
      throw new Error('product-request-rejected');
    }
    return;
  }
  if (method === 'product.session.export') {
    if (
      !exactKeys(payload, [
        'method',
        'schemaVersion',
        'sessionId',
        'expectedGeneration',
        'privatePath',
      ]) ||
      payload.schemaVersion !== 1 ||
      typeof payload.sessionId !== 'string' ||
      !OPAQUE_SESSION.test(payload.sessionId) ||
      !boundedInteger(payload.expectedGeneration, true) ||
      typeof payload.privatePath !== 'string' ||
      !isAbsolute(payload.privatePath) ||
      Buffer.byteLength(payload.privatePath, 'utf8') > MAX_PATH_BYTES ||
      /\p{Cc}/u.test(payload.privatePath)
    ) {
      throw new Error('product-request-rejected');
    }
    return;
  }
  throw new Error('product-request-rejected');
}

export type PiAdapterFactory = (options: PiAdapterOptions) => Promise<PiAdapter>;

export class ProductRuntime {
  readonly #host: HostRequestClient;
  readonly #generation: number;
  readonly #createAdapter: PiAdapterFactory;
  #adapter: Promise<PiAdapter> | undefined;

  // The factory is an in-process test seam; the sidecar entry point always uses
  // the pinned Pi 0.82 adapter.
  constructor(
    host: HostRequestClient,
    generation: number,
    createAdapter: PiAdapterFactory = (options) => Pi082Adapter.create(options),
  ) {
    this.#host = host;
    this.#generation = generation;
    this.#createAdapter = createAdapter;
  }

  async handle(envelope: ProtocolEnvelope): Promise<Readonly<Record<string, unknown>>> {
    assertProductRequestEnvelope(envelope);
    const adapter = await this.#getAdapter();
    const payload = envelope.payload;
    switch (payload.method) {
      case 'product.providers.list':
        return Object.freeze({ schemaVersion: 1, providers: await adapter.listProviders() });
      case 'product.provider.logout':
        await adapter.logout(payload.providerId as string);
        return Object.freeze({ schemaVersion: 1, loggedOut: true });
      case 'product.session.create': {
        const session = await adapter.createSession({
          workspaceId: payload.workspaceId as string,
          workspaceRevision: payload.workspaceRevision as number,
          workspacePath: payload.workspacePath as string,
          agentDir: payload.agentDir as string,
          ...(typeof payload.title === 'string' ? { title: payload.title } : {}),
          ...(typeof payload.providerId === 'string' ? { providerId: payload.providerId } : {}),
          ...(typeof payload.modelId === 'string' ? { modelId: payload.modelId } : {}),
        });
        return Object.freeze({ schemaVersion: 1, session });
      }
      case 'product.sessions.list':
        return Object.freeze({
          schemaVersion: 1,
          sessions: await adapter.listSessions({
            workspaceId: payload.workspaceId as string,
            workspaceRevision: payload.workspaceRevision as number,
            workspacePath: payload.workspacePath as string,
            agentDir: payload.agentDir as string,
          }),
        });
      case 'product.session.resume':
        return Object.freeze({
          schemaVersion: 1,
          session: await adapter.resumeSession(
            payload.sessionId as string,
            payload.expectedGeneration as number,
          ),
        });
      case 'product.session.fork':
        return Object.freeze({
          schemaVersion: 1,
          session: await adapter.forkSession(
            payload.sessionId as string,
            payload.expectedGeneration as number,
          ),
        });
      case 'product.session.rename':
        return Object.freeze({
          schemaVersion: 1,
          session: await adapter.renameSession(
            payload.sessionId as string,
            payload.expectedGeneration as number,
            payload.title as string,
          ),
        });
      case 'product.session.inspect':
        return Object.freeze({
          schemaVersion: 1,
          messages: await adapter.inspectSession(
            payload.sessionId as string,
            payload.expectedGeneration as number,
          ),
        });
      case 'product.session.compact':
        await adapter.compactSession(
          payload.sessionId as string,
          payload.expectedGeneration as number,
        );
        return Object.freeze({ schemaVersion: 1, compacted: true });
      case 'product.session.trash-target':
        return Object.freeze({
          schemaVersion: 1,
          target: await adapter.trashSessionTarget(
            payload.sessionId as string,
            payload.expectedGeneration as number,
          ),
        });
      case 'product.session.trash-complete':
        await adapter.confirmSessionTrashed(
          payload.sessionId as string,
          payload.expectedGeneration as number,
        );
        return Object.freeze({ schemaVersion: 1, acknowledged: true });
      case 'product.changes.list':
        return Object.freeze({
          schemaVersion: 1,
          changes: await adapter.listChanges(
            payload.sessionId as string,
            payload.expectedGeneration as number,
          ),
        });
      case 'product.change.undo':
        return Object.freeze({
          schemaVersion: 1,
          change: await adapter.undoChange(
            payload.sessionId as string,
            payload.expectedGeneration as number,
            payload.changeId as string,
          ),
        });
      case 'product.change.target':
        return Object.freeze({
          schemaVersion: 1,
          target: await adapter.changeTarget(
            payload.sessionId as string,
            payload.expectedGeneration as number,
            payload.changeId as string,
          ),
        });
      case 'product.settings.list':
        return Object.freeze({
          schemaVersion: 1,
          settings: await adapter.listSettings(
            payload.sessionId as string,
            payload.expectedGeneration as number,
          ),
        });
      case 'product.resources.list':
        return Object.freeze({
          schemaVersion: 1,
          resources: await adapter.listResources(
            payload.sessionId as string,
            payload.expectedGeneration as number,
          ),
        });
      case 'product.resource.set-enabled':
        return Object.freeze({
          schemaVersion: 1,
          resource: await adapter.setResourceEnabled(
            payload.sessionId as string,
            payload.expectedGeneration as number,
            payload.resourceId as string,
            payload.enabled as boolean,
            payload.acknowledgedExecutableRisk as boolean,
          ),
        });
      case 'product.package.install':
        return Object.freeze({
          schemaVersion: 1,
          resource: await adapter.installPackage(
            payload.sessionId as string,
            payload.expectedGeneration as number,
            payload.source as string,
            payload.scope as 'global' | 'project',
            payload.online as boolean,
            payload.acknowledgedExecutableRisk as boolean,
          ),
        });
      case 'product.package.mutate':
        return Object.freeze({
          schemaVersion: 1,
          resource: await adapter.mutatePackage(
            payload.sessionId as string,
            payload.expectedGeneration as number,
            payload.resourceId as string,
            payload.operation as 'update' | 'remove',
            payload.online as boolean,
            payload.acknowledgedExecutableRisk as boolean,
          ),
        });
      case 'product.setting.save':
        return Object.freeze({
          schemaVersion: 1,
          setting: await adapter.saveSetting(
            payload.sessionId as string,
            payload.expectedGeneration as number,
            payload.key as string,
            payload.value,
            payload.scope as 'global' | 'project',
            payload.expectedRevision as number,
          ),
        });
      case 'product.setting.reset-preview':
        return Object.freeze({
          schemaVersion: 1,
          preview: await adapter.previewSettingReset(
            payload.sessionId as string,
            payload.expectedGeneration as number,
            payload.key as string,
          ),
        });
      case 'product.queue.followup':
        return Object.freeze({
          schemaVersion: 1,
          queue: await adapter.queueFollowUp(
            payload.sessionId as string,
            payload.expectedGeneration as number,
            payload.text as string,
          ),
        });
      case 'product.queue.replace':
        return Object.freeze({
          schemaVersion: 1,
          queue: await adapter.replaceFollowUpQueue(
            payload.sessionId as string,
            payload.expectedGeneration as number,
            payload.texts as string[],
          ),
        });
      case 'product.session.export':
        await adapter.exportSession(
          payload.sessionId as string,
          payload.expectedGeneration as number,
          payload.privatePath as string,
        );
        return Object.freeze({ schemaVersion: 1, exported: true });
      case 'product.diagnostics':
        return Object.freeze({ schemaVersion: 1, diagnostics: await adapter.diagnosticSnapshot() });
      default:
        throw new Error('product-request-rejected');
    }
  }

  async *stream(envelope: ProtocolEnvelope, signal: AbortSignal): AsyncIterable<AdapterTurnEvent> {
    assertProductTurnEnvelope(envelope);
    const payload = envelope.payload;
    const images = await Promise.all(
      (payload.attachments as Record<string, unknown>[]).map(async (attachment) => {
        const bytes = await readFile(attachment.privatePath as string);
        if (bytes.byteLength !== attachment.byteLength || bytes.byteLength > 20 * 1024 * 1024) {
          bytes.fill(0);
          throw new Error('attachment-changed-after-selection');
        }
        const data = bytes.toString('base64');
        bytes.fill(0);
        return Object.freeze({
          type: 'image' as const,
          data,
          mimeType: attachment.mime as 'image/png' | 'image/jpeg' | 'image/webp',
        });
      }),
    );
    const request: AdapterTurnRequest = Object.freeze({
      requestId: envelope.id,
      sessionId: payload.sessionId as string,
      generation: payload.generation as number,
      text: payload.text as string,
      retryPrevious: payload.retryPrevious as boolean,
      images: Object.freeze(images),
    });
    yield* (await this.#getAdapter()).streamTurn(request, signal);
  }

  async *authenticate(
    envelope: ProtocolEnvelope,
    signal: AbortSignal,
  ): AsyncIterable<Readonly<Record<string, unknown>>> {
    assertProductAuthEnvelope(envelope);
    const adapter = await this.#getAdapter();
    const pending: Readonly<Record<string, unknown>>[] = [];
    let wake: (() => void) | undefined;
    let terminal = false;
    let failure: unknown;
    const push = (notice: Readonly<Record<string, unknown>>) => {
      pending.push(Object.freeze(notice));
      const release = wake;
      wake = undefined;
      release?.();
    };
    const prompt = (
      request: Parameters<import('./adapter.js').AuthInteractionPort['prompt']>[0],
    ): Promise<string> => {
      if (request.type === 'select') {
        const options = request.options ?? [];
        const selection =
          options.find((option) => option.id === 'device_code') ??
          options.find((option) => option.id === 'browser') ??
          options[0];
        if (selection) return Promise.resolve(selection.id);
      }
      if (request.type !== 'manual-code')
        return Promise.reject(new Error('auth-prompt-unsupported'));
      return new Promise<string>((_resolve, reject) => {
        const abort = () => reject(new Error('auth-prompt-cancelled'));
        if (signal.aborted || request.signal?.aborted) abort();
        else {
          signal.addEventListener('abort', abort, { once: true });
          request.signal?.addEventListener('abort', abort, { once: true });
        }
      });
    };
    void adapter
      .login(
        envelope.payload.providerId as string,
        'subscription',
        Object.freeze({
          signal,
          prompt,
          notify: (notice) => push(notice as unknown as Readonly<Record<string, unknown>>),
        }),
      )
      .then(
        (receipt) =>
          push({
            type: 'validated',
            providerId: receipt.providerId,
            accountLabel: receipt.accountLabel,
          }),
        (error: unknown) => {
          failure = error;
        },
      )
      .finally(() => {
        terminal = true;
        const release = wake;
        wake = undefined;
        release?.();
      });
    while (!terminal || pending.length > 0) {
      if (pending.length === 0) {
        await new Promise<void>((resolve) => {
          wake = resolve;
        });
      } else {
        const notice = pending.shift();
        if (notice) yield notice;
      }
    }
    if (failure) throw failure;
  }

  async stop(requestId: string): Promise<'stopped' | 'too-late' | 'unknown'> {
    return (await this.#getAdapter()).stopTurn(requestId);
  }

  async close(): Promise<void> {
    if (this.#adapter) await (await this.#adapter).close();
  }

  #getAdapter(): Promise<PiAdapter> {
    this.#adapter ??= this.#createAdapter({
      credentials: new PiCredentialStore(this.#host),
      allowModelNetwork: true,
      generation: this.#generation,
      approvalHost: Object.freeze({
        requestApproval: (payload) => this.#host.requestApproval(payload),
        notifyApprovalReady: (payload) => this.#host.notifyApprovalReady(payload),
        abandonApproval: (payload) => this.#host.abandonApproval(payload),
      }),
    });
    return this.#adapter;
  }
}
