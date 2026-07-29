import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  writeSync,
  type BigIntStats,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { createApprovalGate, type ApprovalHost } from './approval-hook.js';
import { runFixedDeterministicTurn } from './deterministic-turn.js';
import {
  PUBLIC_SESSION_VERSION,
  PublicModelRuntime,
  PublicSessionManager,
  PublicSettingsManager,
  assertPublicSdk,
  publicCreateAgentSessionFromServices,
  publicCreateAgentSessionRuntime,
  publicCreateAgentSessionServices,
  type PublicAgentSession,
  type PublicAgentSessionRuntime,
  type PublicCreateAgentSessionRuntimeFactory,
  type PublicCredential,
  type PublicCredentialInfo,
  type PublicCredentialStore,
  type PublicSessionEntry,
  type PublicSessionHeader,
  type PublicSessionManagerInstance,
  type PublicToolDefinition,
} from './public-sdk.js';

export const SESSION_SPIKE_LIMITS = Object.freeze({
  maxFileBytes: 1_048_576,
  maxJsonlLineBytes: 65_536,
  maxBranchEntries: 2_048,
  maxIdentifierBytes: 128,
  maxOperationIdBytes: 42,
  maxPathBytes: 4_096,
  maximumLiveSessionReferences: 2,
  maximumForks: 1,
});

export const SESSION_ACKNOWLEDGEMENT_TYPE = 'piui.a19.acknowledgement';
/** Test-only observer key. Symbol-keyed evidence is omitted by serialisation. */
export const SESSION_SPIKE_TEST_OBSERVER: unique symbol = Symbol('piui.a19.test-observer');

const ALLOWED_ENTRY_TYPES = new Set([
  'message',
  'thinking_level_change',
  'model_change',
  'compaction',
  'branch_summary',
  'custom',
  'custom_message',
  'label',
  'session_info',
]);
const OPERATION_ID = /^operation-[0-9a-f]{32}$/;
const ENTRY_ID = /^[A-Za-z0-9._:-]+$/;
const OPAQUE_REFERENCE_ATTEMPTS = 16;
const OPAQUE_REFERENCE = /^session-[0-9a-f]{32}$/;
const TEMPORARY_PREFIX = 'piui-a19-';

let operationReserved = false;

export type SessionSpikeErrorCode =
  | 'session-busy'
  | 'session-input-rejected'
  | 'session-source-rejected'
  | 'session-partial-write'
  | 'session-containment-rejected'
  | 'session-filesystem-rejected'
  | 'session-malformed'
  | 'session-branch-rejected'
  | 'session-selection-rejected'
  | 'session-output-collision'
  | 'session-operation-rejected'
  | 'session-reference-rejected'
  | 'session-recovery-required';

export class SessionSpikeError extends Error {
  readonly code: SessionSpikeErrorCode;

  constructor(code: SessionSpikeErrorCode) {
    super(code);
    this.name = 'SessionSpikeError';
    this.code = code;
  }
}

export type SessionSpikeTestFault =
  | 'replace-before-append'
  | 'throw-after-append'
  | 'replace-before-fork'
  | 'fork-output-collision'
  | 'replace-after-fork'
  | 'throw-after-fork';

export type SessionSpikeOptions = Readonly<{
  fixturePath: string;
  operationId: string;
  selectedAssistantOrdinal?: number;
  /** Test-only scheduling barrier used to prove synchronous busy rejection. */
  testBarrier?: Promise<void>;
  /** Test-only deterministic fault; never retries an SDK mutation. */
  testFault?: SessionSpikeTestFault;
}>;

export type SessionCapabilityView = Readonly<{
  reference: string;
  role: 'source' | 'fork';
  active: boolean;
  writable: boolean;
  entries: number;
  activeBranchEntries: number;
  acknowledgementMarkers: number;
  availableTools: 0;
  toolExecutionAvailable: false;
}>;

export type SessionSpikeProof = Readonly<{
  references: Readonly<{
    source: string;
    fork: string;
  }>;
  counts: Readonly<{
    sourceEntriesBeforeAcknowledgement: number;
    sourceEntriesAfterAcknowledgement: number;
    selectedBranchEntries: number;
    forkEntries: number;
    acknowledgementMarkers: 1;
    liveSessionReferences: 2;
    forks: 1;
  }>;
  proof: Readonly<{
    publicRuntimeSwitchUsed: true;
    publicRuntimeForkAtUsed: true;
    exactSourceSessionCallback: true;
    exactForkSessionCallback: true;
    exactActiveBranchCallbacks: true;
    acknowledgementReturnedAsLeaf: true;
    acknowledgementParentMatched: true;
    acknowledgementReopenedExactlyOnce: true;
    acknowledgementPrecheckedAbsent: true;
    stagedCopyMatchedRepository: true;
    stagedSourceChangedOnce: true;
    sourceIdentityStableAcrossFork: true;
    sourceHashStableAcrossFork: true;
    repositoryHashStable: true;
    forkSessionIdDistinct: true;
    forkFileIdentityDistinct: true;
    forkParentMatched: true;
    forkBranchExactlySelectedPrefix: true;
    forkExcludedLaterSourceHistory: true;
    zeroToolDefinitionsDecoratedBeforeCreate: true;
    exactCreatedSessionsBound: true;
    noToolExecutionPath: true;
    liveCapabilityLeaseRequired: true;
    privateContainmentRevalidated: true;
    descriptorBoundSdkAccessClaimed: false;
    productionSessionAuthorityClaimed: false;
  }>;
}>;

export type SessionSpikeObservedEvidence = Readonly<{
  source: Readonly<{
    sessionId: string;
    branchIds: readonly string[];
    leafId: string;
    entryCount: number;
  }>;
  fork: Readonly<{
    sessionId: string;
    branchIds: readonly string[];
    leafId: string;
    entryCount: number;
    parentMatchesSource: boolean;
  }>;
  selectedEntryId: string;
  selectedPrefixIds: readonly string[];
  acknowledgement: Readonly<{
    count: number;
    id: string | null;
    parentId: string | null;
    leafId: string;
  }>;
  hashes: Readonly<{
    repositoryBefore: string;
    repositoryCurrent: string;
    workingZero: string;
    workingOne: string;
    workingTwo: string;
  }>;
  fileIdentities: Readonly<{
    sourceZero: string;
    sourceCurrent: string;
    forkCurrent: string;
  }>;
  callbacks: Readonly<{
    switchSessionId: string;
    switchBranchIds: readonly string[];
    forkSessionId: string;
    forkBranchIds: readonly string[];
    reboundSessionIds: readonly string[];
    activeRuntimeSessionId: string;
    activeRuntimeBranchIds: readonly string[];
  }>;
  constructions: readonly Readonly<{
    reason: 'initial' | 'resume' | 'fork';
    decorateSequence: number;
    createSequence: number;
    bindSequence: number;
    sessionId: string;
    allToolNames: readonly string[];
    activeToolNames: readonly string[];
    boundExactFactorySession: boolean;
    modelAvailable: boolean;
  }>[];
  isolatedCredentialWrites: number;
  approvalHostCalls: number;
}>;

export type DeterministicTurnEvidence = Readonly<{
  providerCalls: 1;
  providerAbortObserved: true;
  messageStarts: 1;
  textDeltas: number;
  abortedTerminals: 1;
  completeTerminals: 0;
  postTerminalEvents: 0;
  forbiddenFinalChunkAbsent: true;
  partialBytes: number;
  partialSha256: string;
  cancellationLatencyMilliseconds: number;
}>;

export type SessionSpikeLease = SessionSpikeProof & Readonly<{
  inspect(reference: string): SessionCapabilityView;
  runDeterministicTurn(): Promise<DeterministicTurnEvidence>;
  dispose(): Promise<void>;
  [SESSION_SPIKE_TEST_OBSERVER](): SessionSpikeObservedEvidence;
}>;

type FileWitness = Readonly<{
  device: bigint;
  inode: bigint;
  mode: bigint;
  links: bigint;
  size: bigint;
  hash: string;
}>;

type ValidatedManager = Readonly<{
  header: PublicSessionHeader;
  entries: readonly PublicSessionEntry[];
  branch: readonly PublicSessionEntry[];
  leafId: string;
}>;

type ConstructionRecord = Readonly<{
  reason: 'initial' | 'resume' | 'fork';
  decorateSequence: number;
  createSequence: number;
  bindSequence: number;
  session: PublicAgentSession;
  sessionId: string;
  allToolNames: readonly string[];
  activeToolNames: readonly string[];
  boundExactFactorySession: boolean;
  modelAvailable: boolean;
}>;

type ReplacementCallback = Readonly<{
  sessionId: string;
  branchIds: readonly string[];
  exactManager: boolean;
}>;

type CapabilityRecord = {
  readonly role: 'source' | 'fork';
  readonly path: string;
  manager: PublicSessionManagerInstance;
};

function reject(code: SessionSpikeErrorCode): never {
  throw new SessionSpikeError(code);
}

function byteLength(value: string): number {
  return Buffer.byteLength(value, 'utf8');
}

function validateInput(options: SessionSpikeOptions): number {
  if (typeof options.fixturePath !== 'string'
    || !isAbsolute(options.fixturePath)
    || byteLength(options.fixturePath) === 0
    || byteLength(options.fixturePath) > SESSION_SPIKE_LIMITS.maxPathBytes
    || options.fixturePath.includes('\0')
    || basename(options.fixturePath).length === 0
    || !options.fixturePath.endsWith('.jsonl')) {
    reject('session-input-rejected');
  }
  if (typeof options.operationId !== 'string'
    || byteLength(options.operationId) > SESSION_SPIKE_LIMITS.maxOperationIdBytes
    || !OPERATION_ID.test(options.operationId)) {
    reject('session-input-rejected');
  }
  const ordinal = options.selectedAssistantOrdinal ?? 0;
  if (!Number.isSafeInteger(ordinal)
    || ordinal < 0
    || ordinal >= SESSION_SPIKE_LIMITS.maxBranchEntries) {
    reject('session-input-rejected');
  }
  return ordinal;
}

function statNoFollow(path: string): BigIntStats {
  try {
    return lstatSync(path, { bigint: true });
  } catch {
    return reject('session-filesystem-rejected');
  }
}

function assertOwnerPrivateDirectory(path: string): BigIntStats {
  const stats = statNoFollow(path);
  if (!stats.isDirectory()
    || stats.isSymbolicLink()
    || stats.nlink < 1n
    || (stats.mode & 0o777n) !== 0o700n
    || typeof process.getuid !== 'function'
    || stats.uid !== BigInt(process.getuid())) {
    reject('session-filesystem-rejected');
  }
  return stats;
}

function assertRegularSingleLink(path: string, requirePrivateMode: boolean): BigIntStats {
  const stats = statNoFollow(path);
  if (!stats.isFile()
    || stats.isSymbolicLink()
    || stats.nlink !== 1n
    || (requirePrivateMode && (stats.mode & 0o777n) !== 0o600n)
    || typeof process.getuid !== 'function'
    || stats.uid !== BigInt(process.getuid())) {
    reject('session-filesystem-rejected');
  }
  return stats;
}

function sameIdentity(left: Pick<FileWitness, 'device' | 'inode'>, right: BigIntStats): boolean {
  return left.device === right.dev && left.inode === right.ino;
}

function assertSameIdentity(witness: FileWitness, stats: BigIntStats): void {
  if (!sameIdentity(witness, stats)
    || stats.nlink !== witness.links
    || (stats.mode & 0o777n) !== witness.mode) {
    reject('session-filesystem-rejected');
  }
}

function identityToken(witness: Pick<FileWitness, 'device' | 'inode'>): string {
  return `${witness.device.toString(16)}:${witness.inode.toString(16)}`;
}

function assertContained(root: string, target: string): void {
  const resolvedRoot = resolve(root);
  const resolvedTarget = resolve(target);
  const child = relative(resolvedRoot, resolvedTarget);
  if (child === '' || child.startsWith('..') || isAbsolute(child)
    || byteLength(resolvedTarget) > SESSION_SPIKE_LIMITS.maxPathBytes) {
    reject('session-containment-rejected');
  }
  let canonicalParent: string;
  try {
    canonicalParent = realpathSync(dirname(resolvedTarget));
  } catch {
    return reject('session-containment-rejected');
  }
  const parentChild = relative(resolvedRoot, canonicalParent);
  if (parentChild.startsWith('..') || isAbsolute(parentChild)) {
    reject('session-containment-rejected');
  }
  if (existsSync(resolvedTarget)) {
    let canonicalTarget: string;
    try {
      canonicalTarget = realpathSync(resolvedTarget);
    } catch {
      return reject('session-containment-rejected');
    }
    if (canonicalTarget !== resolvedTarget) reject('session-containment-rejected');
  }
}

function validateFraming(bytes: Buffer): number {
  if (bytes.length === 0 || bytes.length > SESSION_SPIKE_LIMITS.maxFileBytes) {
    reject('session-source-rejected');
  }
  if (bytes[bytes.length - 1] !== 0x0a) reject('session-partial-write');
  if (bytes.includes(0x0d)) reject('session-source-rejected');
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return reject('session-source-rejected');
  }

  let frames = 0;
  let start = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== 0x0a) continue;
    const frameLength = index - start;
    if (frameLength === 0 || frameLength > SESSION_SPIKE_LIMITS.maxJsonlLineBytes) {
      reject('session-source-rejected');
    }
    frames += 1;
    if (frames > SESSION_SPIKE_LIMITS.maxBranchEntries + 1) {
      reject('session-source-rejected');
    }
    start = index + 1;
  }
  return frames;
}

function hashBytes(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function witnessFile(path: string, requirePrivateMode = true): FileWitness {
  const stats = assertRegularSingleLink(path, requirePrivateMode);
  if (stats.size > BigInt(SESSION_SPIKE_LIMITS.maxFileBytes)) reject('session-source-rejected');
  const bytes = readFileSync(path);
  if (BigInt(bytes.length) !== stats.size) reject('session-filesystem-rejected');
  validateFraming(bytes);
  return Object.freeze({
    device: stats.dev,
    inode: stats.ino,
    mode: stats.mode & 0o777n,
    links: stats.nlink,
    size: stats.size,
    hash: hashBytes(bytes),
  });
}

function validateRepositoryFixture(path: string): Readonly<{ bytes: Buffer; witness: FileWitness }> {
  let canonical: string;
  try {
    canonical = realpathSync(path);
  } catch {
    return reject('session-source-rejected');
  }
  if (canonical !== resolve(path)) reject('session-filesystem-rejected');
  const witness = witnessFile(path, false);
  const bytes = readFileSync(path);
  if (hashBytes(bytes) !== witness.hash || BigInt(bytes.length) !== witness.size) {
    reject('session-filesystem-rejected');
  }
  return Object.freeze({ bytes, witness });
}

function writeExclusivePrivate(path: string, bytes: Uint8Array): void {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(
      path,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    let offset = 0;
    while (offset < bytes.length) {
      const written = writeSync(descriptor, bytes, offset, bytes.length - offset);
      if (written <= 0) reject('session-filesystem-rejected');
      offset += written;
    }
  } catch (error) {
    if (error instanceof SessionSpikeError) throw error;
    reject('session-filesystem-rejected');
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        reject('session-filesystem-rejected');
      }
    }
  }
  chmodSync(path, 0o600);
}

function validateIdentifier(value: unknown): value is string {
  return typeof value === 'string'
    && byteLength(value) > 0
    && byteLength(value) <= SESSION_SPIKE_LIMITS.maxIdentifierBytes
    && ENTRY_ID.test(value);
}

function validateHeader(header: PublicSessionHeader | null): PublicSessionHeader {
  if (!header
    || header.type !== 'session'
    || header.version !== PUBLIC_SESSION_VERSION
    || !validateIdentifier(header.id)
    || typeof header.timestamp !== 'string'
    || byteLength(header.timestamp) > 64
    || !Number.isFinite(Date.parse(header.timestamp))
    || typeof header.cwd !== 'string'
    || !isAbsolute(header.cwd)
    || byteLength(header.cwd) > SESSION_SPIKE_LIMITS.maxPathBytes
    || (header.parentSession !== undefined
      && (typeof header.parentSession !== 'string'
        || !isAbsolute(header.parentSession)
        || byteLength(header.parentSession) > SESSION_SPIKE_LIMITS.maxPathBytes))) {
    reject('session-malformed');
  }
  return header;
}

function validateManager(
  manager: PublicSessionManagerInstance,
  physicalFrames: number,
  maximumEntries: number = SESSION_SPIKE_LIMITS.maxBranchEntries,
): ValidatedManager {
  const header = validateHeader(manager.getHeader());
  const entries = manager.getEntries();
  if (entries.length === 0
    || entries.length > maximumEntries
    || physicalFrames !== entries.length + 1) {
    reject('session-malformed');
  }

  const seen = new Set<string>();
  let roots = 0;
  for (const entry of entries) {
    if (!ALLOWED_ENTRY_TYPES.has(entry.type)
      || byteLength(entry.type) > 64
      || !validateIdentifier(entry.id)
      || (entry.parentId !== null && !validateIdentifier(entry.parentId))
      || typeof entry.timestamp !== 'string'
      || byteLength(entry.timestamp) > 64
      || !Number.isFinite(Date.parse(entry.timestamp))
      || seen.has(entry.id)) {
      reject('session-malformed');
    }
    if (entry.parentId === null) roots += 1;
    else if (!seen.has(entry.parentId)) reject('session-malformed');
    seen.add(entry.id);
  }
  if (roots !== 1) reject('session-malformed');

  const leafId = manager.getLeafId();
  const leaf = manager.getLeafEntry();
  if (!leafId || !leaf || leafId !== leaf.id || leafId !== entries[entries.length - 1].id) {
    reject('session-branch-rejected');
  }
  const branch = manager.getBranch();
  if (branch.length === 0 || branch.length > SESSION_SPIKE_LIMITS.maxBranchEntries) {
    reject('session-branch-rejected');
  }
  const branchIds = new Set<string>();
  for (let index = 0; index < branch.length; index += 1) {
    const entry = branch[index];
    const expectedParent = index === 0 ? null : branch[index - 1].id;
    if (entry.parentId !== expectedParent || branchIds.has(entry.id) || !seen.has(entry.id)) {
      reject('session-branch-rejected');
    }
    branchIds.add(entry.id);
  }
  if (branch[branch.length - 1].id !== leafId) reject('session-branch-rejected');

  return Object.freeze({ header, entries, branch, leafId });
}

function assistantEntries(branch: readonly PublicSessionEntry[]): PublicSessionEntry[] {
  return branch.filter((entry) => entry.type === 'message' && entry.message.role === 'assistant');
}

function selectAssistant(
  branch: readonly PublicSessionEntry[],
  ordinal: number,
): Readonly<{ entry: PublicSessionEntry; prefix: readonly PublicSessionEntry[] }> {
  const assistants = assistantEntries(branch);
  const selected = assistants[ordinal];
  if (!selected) reject('session-selection-rejected');
  const matches = branch.filter((entry) => entry.id === selected.id);
  const index = branch.findIndex((entry) => entry.id === selected.id);
  if (matches.length !== 1
    || index < 0
    || index >= branch.length - 1
    || selected.type !== 'message'
    || selected.message.role !== 'assistant') {
    reject('session-selection-rejected');
  }
  return Object.freeze({ entry: selected, prefix: branch.slice(0, index + 1) });
}

function markerDataMatches(data: unknown, operationId: string): boolean {
  if (data === null || typeof data !== 'object' || Array.isArray(data)) return false;
  const keys = Object.keys(data).sort();
  if (!isDeepStrictEqual(keys, ['operationId', 'schemaVersion', 'state'])) return false;
  const operation = Object.getOwnPropertyDescriptor(data, 'operationId');
  const version = Object.getOwnPropertyDescriptor(data, 'schemaVersion');
  const state = Object.getOwnPropertyDescriptor(data, 'state');
  return operation?.value === operationId
    && version?.value === 1
    && state?.value === 'acknowledged';
}

function entryHasOperationId(entry: PublicSessionEntry, operationId: string): boolean {
  if (entry.type !== 'custom' || entry.customType !== SESSION_ACKNOWLEDGEMENT_TYPE
    || entry.data === null || typeof entry.data !== 'object' || Array.isArray(entry.data)) {
    return false;
  }
  return Object.getOwnPropertyDescriptor(entry.data, 'operationId')?.value === operationId;
}

function matchingMarkers(entries: readonly PublicSessionEntry[], operationId: string): PublicSessionEntry[] {
  return entries.filter((entry) => entry.type === 'custom'
    && entry.customType === SESSION_ACKNOWLEDGEMENT_TYPE
    && markerDataMatches(entry.data, operationId));
}

function mintOpaqueReference(issued: Set<string>): string {
  for (let attempt = 0; attempt < OPAQUE_REFERENCE_ATTEMPTS; attempt += 1) {
    const candidate = `session-${randomBytes(16).toString('hex')}`;
    if (OPAQUE_REFERENCE.test(candidate) && !issued.has(candidate)) {
      issued.add(candidate);
      return candidate;
    }
  }
  return reject('session-operation-rejected');
}

function ensureExactFiles(directory: string, expected: readonly string[]): void {
  let entries: string[];
  try {
    entries = readdirSync(directory).sort();
  } catch {
    return reject('session-filesystem-rejected');
  }
  const expectedNames = expected.map((path) => basename(path)).sort();
  if (!isDeepStrictEqual(entries, expectedNames)) reject('session-output-collision');
}

function replaceIdentityWithSameBytes(path: string): void {
  const replacement = join(dirname(path), '.identity-replacement');
  const bytes = readFileSync(path);
  writeExclusivePrivate(replacement, bytes);
  renameSync(replacement, path);
}

function samePublicBranch(
  left: readonly PublicSessionEntry[],
  right: readonly PublicSessionEntry[],
): boolean {
  return isDeepStrictEqual(left, right);
}

function branchIds(entries: readonly PublicSessionEntry[]): readonly string[] {
  return Object.freeze(entries.map((entry) => entry.id));
}

function cleanupRoot(root: string, witness: Pick<FileWitness, 'device' | 'inode'>): void {
  if (!existsSync(root)) reject('session-recovery-required');
  const canonicalRoot = realpathSync(root);
  const stats = assertOwnerPrivateDirectory(canonicalRoot);
  if (!sameIdentity(witness, stats) || !basename(canonicalRoot).startsWith(TEMPORARY_PREFIX)) {
    reject('session-recovery-required');
  }
  rmSync(canonicalRoot, { recursive: true, force: false });
  if (existsSync(root) || existsSync(canonicalRoot)) reject('session-recovery-required');
}

function assertRepositoryUnchanged(path: string, witness: FileWitness): FileWitness {
  const current = witnessFile(path, false);
  if (!sameIdentity(witness, assertRegularSingleLink(path, false))
    || current.size !== witness.size
    || current.hash !== witness.hash) {
    reject('session-recovery-required');
  }
  return current;
}

function assertZeroToolSession(session: PublicAgentSession): void {
  if (session.getAllTools().length !== 0 || session.getActiveToolNames().length !== 0) {
    reject('session-operation-rejected');
  }
}

function makeIsolatedCredentialStore(counters: { writes: number }): PublicCredentialStore {
  return Object.freeze({
    async read(_providerId: string): Promise<PublicCredential | undefined> {
      return undefined;
    },
    async list(): Promise<readonly PublicCredentialInfo[]> {
      return [];
    },
    async modify(
      _providerId: string,
      _fn: (current: PublicCredential | undefined) => Promise<PublicCredential | undefined>,
    ): Promise<PublicCredential | undefined> {
      counters.writes += 1;
      return undefined;
    },
    async delete(_providerId: string): Promise<void> {
      counters.writes += 1;
    },
  });
}

/**
 * Disposable A.19 compatibility proof. The returned references are live,
 * process-local capabilities backed by exactly one source and one fork. The
 * owner must call dispose(); until then the owner-private backing tree remains
 * available only through the bounded inspect methods below.
 */
export async function proveSessionResumeAndFork(
  options: SessionSpikeOptions,
): Promise<SessionSpikeLease> {
  if (operationReserved) reject('session-busy');
  operationReserved = true;

  let root: string | undefined;
  let rootWitness: FileWitness | undefined;
  let repositoryWitness: FileWitness | undefined;
  let runtime: PublicAgentSessionRuntime | undefined;
  let mutationMayHaveStarted = false;
  let leasePublished = false;

  try {
    const selectedAssistantOrdinal = validateInput(options);
    if (options.testBarrier) await options.testBarrier;

    const repository = validateRepositoryFixture(options.fixturePath);
    repositoryWitness = repository.witness;

    // The pinned public capability/version gate is deliberately before mkdtemp,
    // directory creation, copying or any other filesystem mutation.
    assertPublicSdk();

    root = mkdtempSync(join(tmpdir(), TEMPORARY_PREFIX));
    chmodSync(root, 0o700);
    root = realpathSync(root);
    const rootStats = assertOwnerPrivateDirectory(root);
    rootWitness = Object.freeze({
      device: rootStats.dev,
      inode: rootStats.ino,
      mode: rootStats.mode & 0o777n,
      links: rootStats.nlink,
      size: rootStats.size,
      hash: '',
    });

    const sessionDirectory = join(root, 'sessions');
    const workspaceDirectory = join(root, 'workspace');
    const agentDirectory = join(root, 'agent');
    for (const directory of [sessionDirectory, workspaceDirectory, agentDirectory]) {
      mkdirSync(directory, { mode: 0o700 });
      chmodSync(directory, 0o700);
      assertOwnerPrivateDirectory(directory);
      assertContained(root, directory);
    }

    const sourcePath = join(sessionDirectory, 'working-session.jsonl');
    assertContained(root, sourcePath);
    writeExclusivePrivate(sourcePath, repository.bytes);
    const workingZero = witnessFile(sourcePath);
    if (sameIdentity(repository.witness, assertRegularSingleLink(sourcePath, true))
      || workingZero.hash !== repository.witness.hash
      || workingZero.size !== repository.witness.size) {
      reject('session-filesystem-rejected');
    }
    const sourceFramesZero = validateFraming(readFileSync(sourcePath));
    const preflightManager = PublicSessionManager.open(sourcePath, sessionDirectory);
    const preflightState = validateManager(
      preflightManager,
      sourceFramesZero,
      SESSION_SPIKE_LIMITS.maxBranchEntries - 1,
    );

    const credentialCounters = { writes: 0 };
    const modelRuntime = await PublicModelRuntime.create({
      credentials: makeIsolatedCredentialStore(credentialCounters),
      modelsPath: null,
      allowModelNetwork: false,
    });
    const constructions: ConstructionRecord[] = [];
    let approvalHostCalls = 0;
    const unreachableApprovalHost: ApprovalHost = Object.freeze({
      async requestApproval() {
        approvalHostCalls += 1;
        throw new Error('session-operation-rejected');
      },
      async notifyApprovalReady() {
        approvalHostCalls += 1;
        throw new Error('session-operation-rejected');
      },
      async abandonApproval() {
        approvalHostCalls += 1;
        throw new Error('session-operation-rejected');
      },
    });
    let constructionSequence = 0;
    const nextConstructionSequence = (): number => {
      constructionSequence += 1;
      return constructionSequence;
    };

    const createRuntime: PublicCreateAgentSessionRuntimeFactory = async ({
      cwd,
      sessionManager,
      sessionStartEvent,
    }) => {
      const reason = sessionStartEvent?.reason === 'resume'
        ? 'resume'
        : sessionStartEvent?.reason === 'fork'
          ? 'fork'
          : 'initial';

      // A.17/A.18 construction ordering is explicit even for the empty set:
      // definitions are decorated before every AgentSession creation and the
      // exact returned session is bound immediately afterwards.
      const gate = createApprovalGate(unreachableApprovalHost, Object.freeze({
        generation: 1,
        sessionId: sessionManager.getSessionId(),
        workspaceId: 'workspace-a19-zero-tool',
        workspaceRevision: 1,
      }));
      const undecorated: readonly PublicToolDefinition[] = Object.freeze([]);
      const decorateSequence = nextConstructionSequence();
      const decorated = Object.freeze(undecorated.map(gate.decorateToolDefinition));
      if (decorated.length !== 0) reject('session-operation-rejected');

      const settingsManager = PublicSettingsManager.inMemory({}, { projectTrusted: false });
      const services = await publicCreateAgentSessionServices({
        cwd,
        agentDir: agentDirectory,
        settingsManager,
        modelRuntime,
        resourceLoaderOptions: {
          noExtensions: true,
          noSkills: true,
          noPromptTemplates: true,
          noThemes: true,
          noContextFiles: true,
          systemPrompt: '',
          appendSystemPrompt: [],
        },
      });
      if (services.resourceLoader.getExtensions().extensions.length !== 0
        || services.resourceLoader.getSkills().skills.length !== 0
        || services.resourceLoader.getPrompts().prompts.length !== 0
        || services.resourceLoader.getThemes().themes.length !== 0
        || services.resourceLoader.getAgentsFiles().agentsFiles.length !== 0) {
        reject('session-operation-rejected');
      }
      const createSequence = nextConstructionSequence();
      const created = await publicCreateAgentSessionFromServices({
        services,
        sessionManager,
        noTools: 'all',
        tools: [],
        customTools: [...decorated],
        thinkingLevel: 'off',
      });
      const bindSequence = nextConstructionSequence();
      const exactSession = created.session;
      gate.bindSession(exactSession);
      assertZeroToolSession(exactSession);
      const allToolNames = Object.freeze(exactSession.getAllTools().map((tool) => tool.name));
      const activeToolNames = Object.freeze(exactSession.getActiveToolNames());
      constructions.push(Object.freeze({
        reason,
        decorateSequence,
        createSequence,
        bindSequence,
        session: exactSession,
        sessionId: exactSession.sessionId,
        allToolNames,
        activeToolNames,
        boundExactFactorySession: exactSession === created.session,
        modelAvailable: modelRuntime.getAvailableSnapshot().length !== 0,
      }));
      return { ...created, services, diagnostics: services.diagnostics };
    };

    const initialManager = PublicSessionManager.inMemory(workspaceDirectory);
    runtime = await publicCreateAgentSessionRuntime(createRuntime, {
      cwd: workspaceDirectory,
      agentDir: agentDirectory,
      sessionManager: initialManager,
    });
    assertZeroToolSession(runtime.session);

    const rebound: PublicAgentSession[] = [];
    runtime.setRebindSession(async (session) => {
      assertZeroToolSession(session);
      rebound.push(session);
    });

    let switchCallback: ReplacementCallback | undefined;
    const switched = await runtime.switchSession(sourcePath, {
      cwdOverride: preflightState.header.cwd,
      withSession: async (context) => {
        switchCallback = Object.freeze({
          sessionId: context.sessionManager.getSessionId(),
          branchIds: branchIds(context.sessionManager.getBranch()),
          exactManager: context.sessionManager === runtime?.session.sessionManager,
        });
      },
    });
    if (switched.cancelled || !switchCallback) reject('session-operation-rejected');
    const sourceSession = runtime.session;
    const activeSourceManager = sourceSession.sessionManager;
    const sourceState = validateManager(activeSourceManager, sourceFramesZero,
      SESSION_SPIKE_LIMITS.maxBranchEntries - 1);
    if (sourceState.header.id !== preflightState.header.id
      || sourceState.leafId !== preflightState.leafId
      || !samePublicBranch(sourceState.branch, preflightState.branch)
      || switchCallback.sessionId !== sourceState.header.id
      || !isDeepStrictEqual(switchCallback.branchIds, branchIds(sourceState.branch))
      || !switchCallback.exactManager
      || rebound.length !== 1
      || rebound[0] !== sourceSession) {
      reject('session-operation-rejected');
    }

    const selection = selectAssistant(sourceState.branch, selectedAssistantOrdinal);
    if (sourceState.entries.filter((entry) => entry.id === selection.entry.id).length !== 1) {
      reject('session-selection-rejected');
    }

    // Replay/idempotency pre-check is before the one permitted append. Any
    // existing marker with this operation ID fails without mutation.
    if (sourceState.entries.some((entry) => entryHasOperationId(entry, options.operationId))) {
      reject('session-operation-rejected');
    }

    if (options.testFault === 'replace-before-append') replaceIdentityWithSameBytes(sourcePath);
    const beforeAppendStats = assertRegularSingleLink(sourcePath, true);
    assertSameIdentity(workingZero, beforeAppendStats);
    const beforeAppend = witnessFile(sourcePath);
    if (beforeAppend.hash !== workingZero.hash || beforeAppend.size !== workingZero.size) {
      reject('session-filesystem-rejected');
    }

    mutationMayHaveStarted = true;
    const acknowledgementId = runtime.session.sessionManager.appendCustomEntry(
      SESSION_ACKNOWLEDGEMENT_TYPE,
      Object.freeze({ schemaVersion: 1, operationId: options.operationId, state: 'acknowledged' }),
    );
    if (options.testFault === 'throw-after-append') reject('session-recovery-required');

    const afterAppendStats = assertRegularSingleLink(sourcePath, true);
    assertSameIdentity(workingZero, afterAppendStats);
    const workingOne = witnessFile(sourcePath);
    if (workingOne.hash === workingZero.hash || workingOne.size <= workingZero.size) {
      reject('session-recovery-required');
    }
    const sourceFramesOne = validateFraming(readFileSync(sourcePath));
    if (sourceFramesOne !== sourceFramesZero + 1) reject('session-recovery-required');

    const reopenedAfterAppend = PublicSessionManager.open(sourcePath, sessionDirectory);
    const afterAppendState = validateManager(reopenedAfterAppend, sourceFramesOne);
    const acknowledgement = reopenedAfterAppend.getEntry(acknowledgementId);
    const markers = matchingMarkers(afterAppendState.entries, options.operationId);
    const markersOnBranch = matchingMarkers(afterAppendState.branch, options.operationId);
    if (!acknowledgement
      || acknowledgement.type !== 'custom'
      || acknowledgement.id !== acknowledgementId
      || acknowledgement.parentId !== sourceState.leafId
      || runtime.session.sessionManager.getLeafId() !== acknowledgementId
      || afterAppendState.leafId !== acknowledgementId
      || afterAppendState.entries.length !== sourceState.entries.length + 1
      || markers.length !== 1
      || markers[0].id !== acknowledgementId
      || markersOnBranch.length !== 1) {
      reject('session-recovery-required');
    }

    const selectedPrefixAfterAppend = reopenedAfterAppend.getBranch(selection.entry.id);
    if (!samePublicBranch(selectedPrefixAfterAppend, selection.prefix)) {
      reject('session-recovery-required');
    }

    if (options.testFault === 'replace-before-fork') replaceIdentityWithSameBytes(sourcePath);
    const immediatelyBeforeFork = witnessFile(sourcePath);
    if (!sameIdentity(workingOne, assertRegularSingleLink(sourcePath, true))
      || immediatelyBeforeFork.hash !== workingOne.hash
      || immediatelyBeforeFork.size !== workingOne.size) {
      reject('session-recovery-required');
    }
    assertContained(root, sourcePath);
    assertOwnerPrivateDirectory(sessionDirectory);
    ensureExactFiles(sessionDirectory, [sourcePath]);
    if (options.testFault === 'fork-output-collision') {
      writeExclusivePrivate(join(sessionDirectory, 'collision.jsonl'), Buffer.from('{}\n'));
      ensureExactFiles(sessionDirectory, [sourcePath]);
    }

    const sourceSessionId = sourceSession.sessionId;
    let forkCallback: ReplacementCallback | undefined;
    const forked = await runtime.fork(selection.entry.id, {
      position: 'at',
      withSession: async (context) => {
        forkCallback = Object.freeze({
          sessionId: context.sessionManager.getSessionId(),
          branchIds: branchIds(context.sessionManager.getBranch()),
          exactManager: context.sessionManager === runtime?.session.sessionManager,
        });
      },
    });
    if (forked.cancelled || forked.selectedText !== undefined || !forkCallback) {
      reject('session-recovery-required');
    }
    if (options.testFault === 'throw-after-fork') reject('session-recovery-required');
    if (options.testFault === 'replace-after-fork') replaceIdentityWithSameBytes(sourcePath);

    const forkSession = runtime.session;
    const forkPath = forkSession.sessionFile;
    if (!forkPath || forkSession === sourceSession) reject('session-recovery-required');
    assertContained(root, forkPath);
    ensureExactFiles(sessionDirectory, [sourcePath, forkPath]);
    chmodSync(forkPath, 0o600);
    const forkWitness = witnessFile(forkPath);
    if (sameIdentity(workingOne, assertRegularSingleLink(forkPath, true))) {
      reject('session-recovery-required');
    }

    const workingTwo = witnessFile(sourcePath);
    if (!sameIdentity(workingOne, assertRegularSingleLink(sourcePath, true))
      || workingTwo.hash !== workingOne.hash
      || workingTwo.size !== workingOne.size) {
      reject('session-recovery-required');
    }
    const sourceFramesTwo = validateFraming(readFileSync(sourcePath));
    if (sourceFramesTwo !== sourceFramesOne) reject('session-recovery-required');

    const reopenedSource = PublicSessionManager.open(sourcePath, sessionDirectory);
    const finalSourceState = validateManager(reopenedSource, sourceFramesTwo);
    const forkFrames = validateFraming(readFileSync(forkPath));
    const reopenedFork = PublicSessionManager.open(forkPath, sessionDirectory);
    const forkState = validateManager(reopenedFork, forkFrames);
    if (finalSourceState.header.id !== sourceSessionId
      || finalSourceState.leafId !== acknowledgementId
      || matchingMarkers(finalSourceState.entries, options.operationId).length !== 1
      || forkState.header.id === sourceSessionId
      || runtime.session.sessionId !== forkState.header.id
      || runtime.session.sessionManager !== forkSession.sessionManager
      || forkState.header.parentSession !== sourcePath
      || forkState.leafId !== selection.entry.id
      || forkState.entries.length !== selection.prefix.length
      || !samePublicBranch(forkState.branch, selection.prefix)
      || forkState.entries.some((entry) => entry.id === acknowledgementId)
      || matchingMarkers(forkState.entries, options.operationId).length !== 0
      || forkState.entries.length >= finalSourceState.entries.length
      || forkCallback.sessionId !== forkState.header.id
      || !isDeepStrictEqual(forkCallback.branchIds, branchIds(forkState.branch))
      || !forkCallback.exactManager
      || Number(rebound.length) !== 2
      || rebound[1] !== forkSession
      || constructions.length !== 3
      || constructions.some((record) => record.decorateSequence >= record.createSequence
        || record.createSequence >= record.bindSequence
        || record.sessionId !== record.session.sessionId
        || record.allToolNames.length !== 0
        || record.activeToolNames.length !== 0
        || !record.boundExactFactorySession
        || record.modelAvailable)
      || credentialCounters.writes !== 0
      || approvalHostCalls !== 0) {
      reject('session-recovery-required');
    }

    assertRepositoryUnchanged(options.fixturePath, repository.witness);

    const issued = new Set<string>();
    const sourceReference = mintOpaqueReference(issued);
    const forkReference = mintOpaqueReference(issued);
    const capabilities = new Map<string, CapabilityRecord>([
      [sourceReference, { role: 'source', path: sourcePath, manager: reopenedSource }],
      [forkReference, { role: 'fork', path: forkPath, manager: reopenedFork }],
    ]);
    if (capabilities.size !== SESSION_SPIKE_LIMITS.maximumLiveSessionReferences) {
      reject('session-recovery-required');
    }

    let disposed = false;
    let disposal: Promise<void> | undefined;

    const assertLive = (): void => {
      if (disposed || capabilities.size !== SESSION_SPIKE_LIMITS.maximumLiveSessionReferences) {
        reject('session-reference-rejected');
      }
    };

    const reopenRecord = (record: CapabilityRecord): ValidatedManager => {
      assertLive();
      assertContained(root!, record.path);
      const frames = validateFraming(readFileSync(record.path));
      const manager = PublicSessionManager.open(record.path, sessionDirectory);
      record.manager = manager;
      return validateManager(manager, frames);
    };

    const inspect = (reference: string): SessionCapabilityView => {
      assertLive();
      if (typeof reference !== 'string' || !OPAQUE_REFERENCE.test(reference)) {
        return reject('session-reference-rejected');
      }
      const record = capabilities.get(reference);
      if (!record) return reject('session-reference-rejected');
      const state = reopenRecord(record);
      const markerCount = matchingMarkers(state.entries, options.operationId).length;
      return Object.freeze({
        reference,
        role: record.role,
        active: record.role === 'fork' && runtime?.session.sessionId === state.header.id,
        writable: record.role === 'fork' && runtime?.session.sessionManager === forkSession.sessionManager,
        entries: state.entries.length,
        activeBranchEntries: state.branch.length,
        acknowledgementMarkers: markerCount,
        availableTools: 0 as const,
        toolExecutionAvailable: false as const,
      });
    };

    let turnStarted = false;
    const runDeterministicTurn = async (): Promise<DeterministicTurnEvidence> => {
      assertLive();
      if (turnStarted || runtime!.session !== forkSession) reject('session-operation-rejected');
      turnStarted = true;
      let evidence: DeterministicTurnEvidence;
      try {
        evidence = await runFixedDeterministicTurn({
          session: forkSession,
          modelRuntime,
          credentialWrites: () => credentialCounters.writes,
          approvalHostCalls: () => approvalHostCalls,
        });
      } catch {
        return reject('session-operation-rejected');
      }
      const sourceAfterTurn = witnessFile(sourcePath);
      if (!sameIdentity(workingOne, assertRegularSingleLink(sourcePath, true))
        || sourceAfterTurn.hash !== workingOne.hash
        || sourceAfterTurn.size !== workingOne.size) {
        reject('session-recovery-required');
      }
      assertRepositoryUnchanged(options.fixturePath, repository.witness);
      return evidence;
    };

    const observeForTest = (): SessionSpikeObservedEvidence => {
      assertLive();
      const sourceRecord = capabilities.get(sourceReference);
      const forkRecord = capabilities.get(forkReference);
      if (!sourceRecord || !forkRecord || !switchCallback || !forkCallback) {
        return reject('session-reference-rejected');
      }
      const observedSource = reopenRecord(sourceRecord);
      const observedFork = reopenRecord(forkRecord);
      const observedMarkers = matchingMarkers(observedSource.entries, options.operationId);
      const observedWorkingTwo = witnessFile(sourcePath);
      const observedForkWitness = witnessFile(forkPath);
      const repositoryCurrent = assertRepositoryUnchanged(options.fixturePath, repository.witness);
      const currentRuntimeBranch = runtime!.session.sessionManager.getBranch();

      return Object.freeze({
        source: Object.freeze({
          sessionId: observedSource.header.id,
          branchIds: branchIds(observedSource.branch),
          leafId: observedSource.leafId,
          entryCount: observedSource.entries.length,
        }),
        fork: Object.freeze({
          sessionId: observedFork.header.id,
          branchIds: branchIds(observedFork.branch),
          leafId: observedFork.leafId,
          entryCount: observedFork.entries.length,
          parentMatchesSource: observedFork.header.parentSession === sourcePath,
        }),
        selectedEntryId: selection.entry.id,
        selectedPrefixIds: branchIds(selection.prefix),
        acknowledgement: Object.freeze({
          count: observedMarkers.length,
          id: observedMarkers[0]?.id ?? null,
          parentId: observedMarkers[0]?.parentId ?? null,
          leafId: observedSource.leafId,
        }),
        hashes: Object.freeze({
          repositoryBefore: repository.witness.hash,
          repositoryCurrent: repositoryCurrent.hash,
          workingZero: workingZero.hash,
          workingOne: workingOne.hash,
          workingTwo: observedWorkingTwo.hash,
        }),
        fileIdentities: Object.freeze({
          sourceZero: identityToken(workingZero),
          sourceCurrent: identityToken(observedWorkingTwo),
          forkCurrent: identityToken(observedForkWitness),
        }),
        callbacks: Object.freeze({
          switchSessionId: switchCallback.sessionId,
          switchBranchIds: switchCallback.branchIds,
          forkSessionId: forkCallback.sessionId,
          forkBranchIds: forkCallback.branchIds,
          reboundSessionIds: Object.freeze(rebound.map((session) => session.sessionId)),
          activeRuntimeSessionId: runtime!.session.sessionId,
          activeRuntimeBranchIds: branchIds(currentRuntimeBranch),
        }),
        constructions: Object.freeze(constructions.map((record) => Object.freeze({
          reason: record.reason,
          decorateSequence: record.decorateSequence,
          createSequence: record.createSequence,
          bindSequence: record.bindSequence,
          sessionId: record.sessionId,
          allToolNames: record.allToolNames,
          activeToolNames: record.activeToolNames,
          boundExactFactorySession: record.session === constructions.find(
            (candidate) => candidate.sessionId === record.sessionId,
          )?.session,
          modelAvailable: record.modelAvailable,
        }))),
        isolatedCredentialWrites: credentialCounters.writes,
        approvalHostCalls,
      });
    };

    const dispose = (): Promise<void> => {
      if (disposal) return disposal;
      disposed = true;
      capabilities.clear();
      disposal = (async () => {
        let failed = false;
        try {
          await runtime!.dispose();
        } catch {
          failed = true;
        }
        try {
          assertRepositoryUnchanged(options.fixturePath, repository.witness);
        } catch {
          failed = true;
        }
        try {
          cleanupRoot(root!, rootWitness!);
        } catch {
          failed = true;
        }
        operationReserved = false;
        if (failed) reject('session-recovery-required');
      })();
      return disposal;
    };

    const proof: SessionSpikeLease = Object.freeze({
      references: Object.freeze({ source: sourceReference, fork: forkReference }),
      counts: Object.freeze({
        sourceEntriesBeforeAcknowledgement: sourceState.entries.length,
        sourceEntriesAfterAcknowledgement: finalSourceState.entries.length,
        selectedBranchEntries: selection.prefix.length,
        forkEntries: forkState.entries.length,
        acknowledgementMarkers: 1 as const,
        liveSessionReferences: 2 as const,
        forks: 1 as const,
      }),
      proof: Object.freeze({
        publicRuntimeSwitchUsed: true as const,
        publicRuntimeForkAtUsed: true as const,
        exactSourceSessionCallback: true as const,
        exactForkSessionCallback: true as const,
        exactActiveBranchCallbacks: true as const,
        acknowledgementReturnedAsLeaf: true as const,
        acknowledgementParentMatched: true as const,
        acknowledgementReopenedExactlyOnce: true as const,
        acknowledgementPrecheckedAbsent: true as const,
        stagedCopyMatchedRepository: true as const,
        stagedSourceChangedOnce: true as const,
        sourceIdentityStableAcrossFork: true as const,
        sourceHashStableAcrossFork: true as const,
        repositoryHashStable: true as const,
        forkSessionIdDistinct: true as const,
        forkFileIdentityDistinct: true as const,
        forkParentMatched: true as const,
        forkBranchExactlySelectedPrefix: true as const,
        forkExcludedLaterSourceHistory: true as const,
        zeroToolDefinitionsDecoratedBeforeCreate: true as const,
        exactCreatedSessionsBound: true as const,
        noToolExecutionPath: true as const,
        liveCapabilityLeaseRequired: true as const,
        privateContainmentRevalidated: true as const,
        descriptorBoundSdkAccessClaimed: false as const,
        productionSessionAuthorityClaimed: false as const,
      }),
      inspect,
      runDeterministicTurn,
      dispose,
      [SESSION_SPIKE_TEST_OBSERVER]: observeForTest,
    });
    leasePublished = true;
    return proof;
  } catch (error) {
    let failedCleanup = false;
    if (runtime) {
      try {
        await runtime.dispose();
      } catch {
        failedCleanup = true;
      }
    }
    if (repositoryWitness) {
      try {
        assertRepositoryUnchanged(options.fixturePath, repositoryWitness);
      } catch {
        failedCleanup = true;
      }
    }
    if (root && rootWitness) {
      try {
        cleanupRoot(root, rootWitness);
      } catch {
        failedCleanup = true;
      }
    }
    if (failedCleanup || mutationMayHaveStarted) {
      throw new SessionSpikeError('session-recovery-required');
    }
    if (error instanceof SessionSpikeError) throw error;
    throw new SessionSpikeError('session-operation-rejected');
  } finally {
    if (!leasePublished) operationReserved = false;
  }
}
