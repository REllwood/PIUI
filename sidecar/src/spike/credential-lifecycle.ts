import {
  closeSync,
  constants,
  fdatasyncSync,
  existsSync,
  fsyncSync,
  linkSync,
  openSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { dirname } from 'node:path';
import { PiCredentialStore } from '../credentials/store-proxy.js';
import type { HostRequestClient } from '../bridge/host-requests.js';
import type { PublicCredential } from '../pi/public-sdk.js';

const PROVIDER_ID = 'a23.fixture-provider';
const TRIGGER_POLL_INTERVAL_MS = 50;
const TRIGGER_DEADLINE_MS = 60_000;
const FAILURE_CLEANUP_DEADLINE_MS = 1_000;

type SafeLifecycleEvidence = Readonly<{
  schemaVersion: 1;
  status: 'pass';
  initialGet: 1;
  refreshReads: 1;
  refreshWrites: 1;
  postRefreshGet: 1;
  logoutDelete: 1;
  postDeleteMiss: 1;
  privateChannelQuiesced: true;
}>;

type SafeLifecycleFailure = Readonly<{
  schemaVersion: 1;
  status: 'fail';
}>;

function isApiKey(credential: PublicCredential | undefined): credential is Extract<PublicCredential, { type: 'api_key' }> {
  return credential?.type === 'api_key'
    && typeof credential.key === 'string'
    && credential.key.length > 0;
}

function clearCredential(credential: PublicCredential | undefined): void {
  if (!credential) return;
  if (credential.type === 'api_key' && typeof credential.key === 'string') credential.key = '';
  if (credential.type === 'oauth') {
    credential.access = '';
    credential.refresh = '';
    credential.expires = 0;
  }
}

function pause(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function attemptFailureCleanup(store: PiCredentialStore): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, FAILURE_CLEANUP_DEADLINE_MS);
  });
  try {
    await Promise.race([
      store.delete(PROVIDER_ID).catch(() => undefined),
      deadline,
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export class A23CredentialLifecycle {
  readonly #resultPath: string;
  readonly #triggerPath: string;

  constructor(resultPath: string, triggerPath: string) {
    this.#resultPath = resultPath;
    this.#triggerPath = triggerPath;
  }

  async run(host: HostRequestClient): Promise<void> {
    const store = new PiCredentialStore(host);
    let initial: PublicCredential | undefined;
    let modified: PublicCredential | undefined;
    let reread: PublicCredential | undefined;
    let deleteCompleted = false;
    try {
      const deadline = Date.now() + TRIGGER_DEADLINE_MS;
      while (Date.now() < deadline) {
        if (existsSync(this.#triggerPath)) break;
        await pause(TRIGGER_POLL_INTERVAL_MS);
      }
      if (!existsSync(this.#triggerPath)) throw new Error('credential-lifecycle-rejected');
      initial = await store.read(PROVIDER_ID);
      if (!isApiKey(initial)) throw new Error('credential-lifecycle-rejected');

      modified = await store.modify(PROVIDER_ID, async (current) => {
        if (!isApiKey(current)) throw new Error('credential-lifecycle-rejected');
        return {
          type: 'api_key',
          key: current.key,
          env: { ...(current.env ?? {}), PIUI_A23_REFRESHED: '1' },
        };
      });
      if (!isApiKey(modified) || modified.env?.PIUI_A23_REFRESHED !== '1') {
        throw new Error('credential-lifecycle-rejected');
      }

      reread = await store.read(PROVIDER_ID);
      if (!isApiKey(reread) || reread.env?.PIUI_A23_REFRESHED !== '1') {
        throw new Error('credential-lifecycle-rejected');
      }
      await store.delete(PROVIDER_ID);
      deleteCompleted = true;
      const missing = await store.read(PROVIDER_ID);
      if (missing !== undefined) throw new Error('credential-lifecycle-rejected');

      const evidence: SafeLifecycleEvidence = Object.freeze({
        schemaVersion: 1,
        status: 'pass',
        initialGet: 1,
        refreshReads: 1,
        refreshWrites: 1,
        postRefreshGet: 1,
        logoutDelete: 1,
        postDeleteMiss: 1,
        privateChannelQuiesced: true,
      });
      publishResultAtomically(this.#resultPath, evidence);
    } catch (error) {
      const failure: SafeLifecycleFailure = Object.freeze({ schemaVersion: 1, status: 'fail' });
      try {
        publishResultAtomically(this.#resultPath, failure);
      } catch {
        // A successfully published result is immutable. Any other publication
        // failure terminates this sidecar generation in the caller.
      }
      throw error;
    } finally {
      if (!deleteCompleted) {
        // Do not let a failed private host consume the UI/runner's complete
        // failure deadline. The external `.test.` helper remains authoritative
        // after this bounded best-effort attempt.
        await attemptFailureCleanup(store);
      }
      clearCredential(initial);
      clearCredential(modified);
      clearCredential(reread);
    }
  }
}

function publishResultAtomically(
  resultPath: string,
  evidence: SafeLifecycleEvidence | SafeLifecycleFailure,
): void {
  const pendingPath = `${resultPath}.pending`;
  const bytes = Buffer.from(`${JSON.stringify(evidence)}\n`, 'utf8');
  let descriptor: number | undefined;
  let linked = false;
  try {
    descriptor = openSync(
      pendingPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
      0o600,
    );
    let offset = 0;
    while (offset < bytes.length) offset += writeSync(descriptor, bytes, offset);
    fdatasyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;

    // link(2) is an atomic, no-replace publication point. The reader accepts
    // only the final single-link inode after the private staging name is gone.
    linkSync(pendingPath, resultPath);
    linked = true;
    unlinkSync(pendingPath);
    const directory = openSync(dirname(resultPath), constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      fsyncSync(directory);
    } finally {
      closeSync(directory);
    }
  } finally {
    bytes.fill(0);
    if (descriptor !== undefined) closeSync(descriptor);
    if (!linked && existsSync(pendingPath)) {
      // Leave an incomplete staging inode for the external isolate cleanup;
      // it is never treated as a lifecycle result.
    }
  }
}

export function createA23CredentialLifecycleFromEnvironment(): A23CredentialLifecycle | undefined {
  if (process.env.PIUI_A23_TEST_MODE !== '1') return undefined;
  if (process.env.PIUI_A23_PROVIDER_ID !== PROVIDER_ID) {
    throw new Error('credential-lifecycle-rejected');
  }
  const resultPath = process.env.PIUI_A23_RESULT_PATH;
  const triggerPath = process.env.PIUI_A23_TRIGGER_PATH;
  if (!resultPath?.startsWith('/') || !triggerPath?.startsWith('/')
    || resultPath === triggerPath) {
    throw new Error('credential-lifecycle-rejected');
  }
  return new A23CredentialLifecycle(resultPath, triggerPath);
}
