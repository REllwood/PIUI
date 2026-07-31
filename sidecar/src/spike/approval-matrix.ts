import { resolve } from 'node:path';
import type { ProtocolEnvelope } from '@piui/protocol';
import type {
  ApprovalHost,
  createApprovalGate,
} from '../pi/approval-hook.js';
import type {
  HostRequestClient,
  HostRequestError,
} from '../bridge/host-requests.js';
import type { SidecarRouter } from '../bridge/router.js';
import type { canonicaliseApprovalInput } from '../pi/approval-canonical.js';
import type {
  publicFauxAssistantMessage,
  publicFauxProvider,
  publicFauxToolCall,
} from '../pi/ai-public-sdk.js';
import type {
  PublicModelRuntime,
  PublicSessionManager,
  PublicSettingsManager,
  assertPublicSdk,
  publicCreateAgentSessionFromServices,
  publicCreateAgentSessionServices,
} from '../pi/public-sdk.js';
import type { SidecarPrivateFixture } from '../runtime.js';
import {
  A25ApprovalWitness,
  approvalCasesForGeneration,
  createApprovalProbeDefinitions,
  type A25ApprovalCase,
} from './approval-probes.js';

export type A25ApprovalMatrixResult = Readonly<{
  schemaVersion: 1;
  eventType: 'approval-matrix.complete';
  generation: number;
  turns: number;
  delegateCalls: number;
  fiveArgumentViolations: number;
  staleNativeIndividualFrameRejections: number;
  staleNativeGroupFrameRejections: number;
  staleBrokerWaitersRemaining: number;
  staleBrokerGenerationsAborted: number;
}>;

export type A25ApprovalDependencies = Readonly<{
  createApprovalGate: typeof createApprovalGate;
  publicFauxAssistantMessage: typeof publicFauxAssistantMessage;
  publicFauxProvider: typeof publicFauxProvider;
  publicFauxToolCall: typeof publicFauxToolCall;
  PublicModelRuntime: typeof PublicModelRuntime;
  PublicSessionManager: typeof PublicSessionManager;
  PublicSettingsManager: typeof PublicSettingsManager;
  assertPublicSdk: typeof assertPublicSdk;
  publicCreateAgentSessionFromServices: typeof publicCreateAgentSessionFromServices;
  publicCreateAgentSessionServices: typeof publicCreateAgentSessionServices;
  HostRequestClient: typeof HostRequestClient;
  HostRequestError: typeof HostRequestError;
  SidecarRouter: typeof SidecarRouter;
  canonicaliseApprovalInput: typeof canonicaliseApprovalInput;
}>;

type MatrixEnvironment = Readonly<{
  controlRoot: string;
  workspaceId: string;
  workspaceRevision: number;
}>;

type SettlementBarrier = Readonly<{
  promise: Promise<void>;
  release(): void;
}>;

function settlementBarrier(): SettlementBarrier {
  let release!: () => void;
  const promise = new Promise<void>((resolvePromise) => {
    release = resolvePromise;
  });
  return Object.freeze({ promise, release });
}

function approvalSessionId(sessionId: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(sessionId)) {
    throw new Error('approval-matrix-session-rejected');
  }
  return `session-${sessionId.replaceAll('-', '')}`;
}

function matrixEnvironment(): MatrixEnvironment | undefined {
  const mode = process.env.PIUI_A25_TEST_MODE;
  const controlRoot = process.env.PIUI_A25_CONTROL_ROOT;
  const workspaceId = process.env.PIUI_A25_WORKSPACE_ID;
  const revisionText = process.env.PIUI_A25_WORKSPACE_REVISION;
  if (mode === undefined && controlRoot === undefined && workspaceId === undefined && revisionText === undefined) {
    return undefined;
  }
  const workspaceRevision = Number(revisionText);
  if (mode !== '1' || !controlRoot || !workspaceId
    || !/^workspace-[0-9a-f]{32}$/.test(workspaceId)
    || !Number.isSafeInteger(workspaceRevision) || workspaceRevision < 1) {
    throw new Error('approval-matrix-environment-rejected');
  }
  return Object.freeze({ controlRoot, workspaceId, workspaceRevision });
}

function responsesFor(candidate: A25ApprovalCase, dependencies: A25ApprovalDependencies) {
  const calls = candidate.tools.map((toolName, member) => dependencies.publicFauxToolCall(
    toolName,
    Object.freeze({ caseId: candidate.id, value: 'fixed' }),
    { id: `a25-g${candidate.generation}-t${candidate.turn}-m${member}` },
  ));
  return Object.freeze([
    dependencies.publicFauxAssistantMessage(calls, { stopReason: 'toolUse', timestamp: 0 }),
    dependencies.publicFauxAssistantMessage(
      'A.25 fixed turn complete.',
      { stopReason: 'stop', timestamp: 0 },
    ),
  ]);
}

type ReplayEvidence = Readonly<{
  staleNativeIndividualFrameRejections: number;
  staleNativeGroupFrameRejections: number;
  staleBrokerWaitersRemaining: number;
  staleBrokerGenerationsAborted: number;
}>;

const EMPTY_REPLAY_EVIDENCE: ReplayEvidence = Object.freeze({
  staleNativeIndividualFrameRejections: 0,
  staleNativeGroupFrameRejections: 0,
  staleBrokerWaitersRemaining: 0,
  staleBrokerGenerationsAborted: 0,
});

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('approval-matrix-replay-rejected');
  }
  return value as Record<string, unknown>;
}

function sidecarSequence(id: unknown): number {
  if (typeof id !== 'string') throw new Error('approval-matrix-replay-rejected');
  const match = /^sidecar-([1-9][0-9]*)$/.exec(id);
  const sequence = Number(match?.[1]);
  if (!Number.isSafeInteger(sequence) || sequence < 1 || sequence > 512) {
    throw new Error('approval-matrix-replay-rejected');
  }
  return sequence;
}

function alignRouter(router: SidecarRouter, correlationId: string): void {
  const target = sidecarSequence(correlationId);
  while (router.currentSequence + 1 < target) {
    const primed = router.next('event', 'a25-replay-prime', {
      eventType: 'a25.replay-prime',
    });
    if (sidecarSequence(primed.id) !== router.currentSequence) {
      throw new Error('approval-matrix-replay-rejected');
    }
  }
  if (router.currentSequence + 1 !== target) {
    throw new Error('approval-matrix-replay-rejected');
  }
}

function replayContext(
  generation: number,
  sessionId: string,
  environment: MatrixEnvironment,
) {
  return Object.freeze({
    generation,
    sessionId,
    workspaceId: environment.workspaceId,
    workspaceRevision: environment.workspaceRevision,
  });
}

async function replayOldNativeFrames(
  dependencies: A25ApprovalDependencies,
  witness: A25ApprovalWitness,
  generation: number,
  sessionId: string,
  environment: MatrixEnvironment,
): Promise<ReplayEvidence> {
  const oldIndividual = witness.loadNativeFrame('individual');
  const oldGroup = witness.loadNativeFrame('group');
  const context = replayContext(generation, sessionId, environment);
  const input = Object.freeze({ caseId: 'stale-replay', value: 'fixed' });
  const inputCanonical = dependencies.canonicaliseApprovalInput(input);
  try {
    const individualPayload = record(oldIndividual.payload);
    const individualToolCallId = individualPayload.toolCallId;
    const individualCorrelation = oldIndividual.correlationId;
    if (typeof individualToolCallId !== 'string' || typeof individualCorrelation !== 'string') {
      throw new Error('approval-matrix-replay-rejected');
    }
    const individualDescriptor = Object.freeze({
      assistantEntryId: 'a25-replacement-individual-entry',
      orderedMembers: Object.freeze([
        Object.freeze({ ordinal: 0, toolCallId: individualToolCallId, toolName: 'read' }),
      ]),
    });
    const individualCohortCanonical =
      dependencies.canonicaliseApprovalInput(individualDescriptor);
    const individualRouter = new dependencies.SidecarRouter();
    const individualWritten: ProtocolEnvelope[] = [];
    const individualBroker = new dependencies.HostRequestClient({
      router: individualRouter,
      write: (envelope) => individualWritten.push(envelope),
    });
    alignRouter(individualRouter, individualCorrelation);
    const individualPending = individualBroker.requestApproval({
      method: 'approval.request',
      schemaVersion: 2,
      ...context,
      invocationId: `invocation-${'d'.repeat(32)}`,
      toolCallId: individualToolCallId,
      toolName: 'read',
      inputDigest: inputCanonical.digest,
      input,
      cohort: Object.freeze({
        ...individualDescriptor,
        cohortDigest: individualCohortCanonical.digest,
      }),
    }).catch((error: unknown) => error);
    individualCohortCanonical.bytes.fill(0);
    if (individualWritten.length !== 1
      || individualWritten[0]?.id !== individualCorrelation) {
      throw new Error('approval-matrix-replay-rejected');
    }
    let individualConsumeError: unknown;
    try {
      individualBroker.consume(oldIndividual);
    } catch (error) {
      individualConsumeError = error;
    }
    const individualSettlement = await individualPending;
    if (!(individualConsumeError instanceof dependencies.HostRequestError)
      || individualConsumeError.code !== 'approval-response-rejected'
      || !(individualSettlement instanceof dependencies.HostRequestError)
      || !['approval-response-rejected', 'approval-unavailable']
        .includes(individualSettlement.code)
      || !individualBroker.credentialGeneration.signal.aborted
      || individualBroker.pendingApprovalCount !== 0) {
      throw new Error('approval-matrix-replay-rejected');
    }

    const groupPayload = record(oldGroup.payload);
    if (!Array.isArray(groupPayload.members) || groupPayload.members.length !== 3
      || groupPayload.generation !== 1 || context.generation !== 1
      || groupPayload.sessionId === context.sessionId) {
      throw new Error('approval-matrix-replay-rejected');
    }
    const groupMembers = groupPayload.members.map((member, ordinal) => {
      const parsed = record(member);
      const correlationId = parsed.correlationId;
      const toolCallId = parsed.toolCallId;
      if (typeof correlationId !== 'string' || typeof toolCallId !== 'string') {
        throw new Error('approval-matrix-replay-rejected');
      }
      return Object.freeze({
        ordinal,
        correlationId,
        toolCallId,
        toolName: ['read', 'grep', 'find'][ordinal] as string,
      });
    });
    const groupDescriptor = Object.freeze({
      assistantEntryId: 'a25-replacement-group-entry',
      orderedMembers: Object.freeze(groupMembers.map((member) => Object.freeze({
        ordinal: member.ordinal,
        toolCallId: member.toolCallId,
        toolName: member.toolName,
      }))),
    });
    const groupCohortCanonical = dependencies.canonicaliseApprovalInput(groupDescriptor);
    const groupCohort = Object.freeze({
      ...groupDescriptor,
      cohortDigest: groupCohortCanonical.digest,
    });
    groupCohortCanonical.bytes.fill(0);
    const groupRouter = new dependencies.SidecarRouter();
    const groupWritten: ProtocolEnvelope[] = [];
    const groupBroker = new dependencies.HostRequestClient({
      router: groupRouter,
      write: (envelope) => groupWritten.push(envelope),
    });
    const groupPending = groupMembers.map((member, ordinal) => {
      alignRouter(groupRouter, member.correlationId);
      return groupBroker.requestApproval({
        method: 'approval.request',
        schemaVersion: 2,
        ...context,
        invocationId: `invocation-${(ordinal + 224).toString(16).padStart(32, '0')}`,
        toolCallId: member.toolCallId,
        toolName: member.toolName,
        inputDigest: inputCanonical.digest,
        input,
        cohort: groupCohort,
      }).catch((error: unknown) => error);
    });
    if (groupWritten.length !== groupMembers.length
      || groupWritten.some((envelope, index) => (
        envelope.id !== groupMembers[index]?.correlationId
      ))) {
      throw new Error('approval-matrix-replay-rejected');
    }
    let groupConsumeError: unknown;
    try {
      groupBroker.consume(oldGroup);
    } catch (error) {
      groupConsumeError = error;
    }
    const groupSettlements = await Promise.all(groupPending);
    if (!(groupConsumeError instanceof dependencies.HostRequestError)
      || groupConsumeError.code !== 'approval-response-rejected'
      || groupSettlements.some((settlement) => (
        !(settlement instanceof dependencies.HostRequestError)
        || !['approval-response-rejected', 'approval-unavailable'].includes(settlement.code)
      ))
      || !groupBroker.credentialGeneration.signal.aborted
      || groupBroker.pendingApprovalCount !== 0) {
      throw new Error('approval-matrix-replay-rejected');
    }
    return Object.freeze({
      staleNativeIndividualFrameRejections: 1,
      staleNativeGroupFrameRejections: 1,
      staleBrokerWaitersRemaining:
        individualBroker.pendingApprovalCount + groupBroker.pendingApprovalCount,
      staleBrokerGenerationsAborted:
        Number(individualBroker.credentialGeneration.signal.aborted)
        + Number(groupBroker.credentialGeneration.signal.aborted),
    });
  } finally {
    inputCanonical.bytes.fill(0);
  }
}

export function createA25ApprovalFixtureFromEnvironment(
  dependencies: A25ApprovalDependencies,
): SidecarPrivateFixture | undefined {
  const environment = matrixEnvironment();
  if (!environment) return undefined;
  const witness = A25ApprovalWitness.fromControlRoot(environment.controlRoot);
  const matrixGeneration = witness.nextMatrixGeneration();
  const cases = approvalCasesForGeneration(matrixGeneration);
  return Object.freeze({
    observeIncoming(envelope, rawFrame) {
      witness.captureNativeFrame(envelope, rawFrame);
    },
    async run({ hostRequests, generation }): Promise<A25ApprovalMatrixResult> {
      dependencies.assertPublicSdk();
      const workspaceRoot = resolve(environment.controlRoot, 'workspace');
      const agentRoot = resolve(environment.controlRoot, 'agent');
      const sessionManager = dependencies.PublicSessionManager.inMemory(workspaceRoot);
      const sessionId = approvalSessionId(sessionManager.getSessionId());
      let activeCase: A25ApprovalCase | undefined;
      let readyCount = 0;
      let readyRecorded = false;
      let timeoutSettlements = new Set<string>();
      let timeoutBarrier = settlementBarrier();
      let replayEvidence = EMPTY_REPLAY_EVIDENCE;
      const observedHost: ApprovalHost = Object.freeze({
        async requestApproval(payload) {
          const grant = await hostRequests.requestApproval(payload);
          if (activeCase?.action === 'timeout') {
            if (grant.decision !== 'expired' || timeoutSettlements.has(grant.invocationId)) {
              throw new Error('approval-matrix-timeout-rejected');
            }
            timeoutSettlements.add(grant.invocationId);
            if (timeoutSettlements.size === 3) timeoutBarrier.release();
          }
          return grant;
        },
        async notifyApprovalReady(payload) {
          await hostRequests.notifyApprovalReady(payload);
          readyCount += 1;
          if (readyCount === 3 && activeCase && !readyRecorded) {
            readyRecorded = true;
            if (activeCase.action === 'stale-replay') {
              witness.replayReady(activeCase);
              await witness.waitForReplayRelease(activeCase);
              replayEvidence = await replayOldNativeFrames(
                dependencies,
                witness,
                generation,
                sessionId,
                environment,
              );
              witness.replayComplete(activeCase);
            }
            witness.caseReady(activeCase);
            if (activeCase.action === 'disconnect') {
              hostRequests.disconnect();
              process.stdin.destroy();
            }
          }
        },
        abandonApproval: (payload) => hostRequests.abandonApproval(payload),
      });
      const gate = dependencies.createApprovalGate(observedHost, Object.freeze({
        generation,
        sessionId,
        workspaceId: environment.workspaceId,
        workspaceRevision: environment.workspaceRevision,
      }));
      const definitions = createApprovalProbeDefinitions(witness);
      const decorated = Object.freeze(definitions.map(gate.decorateToolDefinition));
      const settingsManager = dependencies.PublicSettingsManager.inMemory({
        compaction: { enabled: false },
        retry: { enabled: false },
      }, { projectTrusted: false });
      const modelRuntime = await dependencies.PublicModelRuntime.create({
        credentials: {
          read: async () => undefined,
          list: async () => [],
          modify: async () => undefined,
          delete: async () => undefined,
        },
        modelsPath: null,
        allowModelNetwork: false,
      });
      const faux = dependencies.publicFauxProvider({
        api: 'a25-offline-api',
        provider: 'a25-offline-provider',
        models: [{
          id: 'a25-model',
          name: 'A.25 offline model',
          reasoning: false,
          input: ['text'],
          contextWindow: 8_192,
          maxTokens: 256,
        }],
        tokenSize: { min: 1, max: 1 },
        tokensPerSecond: 1_000,
      });
      faux.setResponses(cases.flatMap((candidate) => [
        ...responsesFor(candidate, dependencies),
      ]));
      modelRuntime.registerNativeProvider(faux.provider);
      const services = await dependencies.publicCreateAgentSessionServices({
        cwd: workspaceRoot,
        agentDir: agentRoot,
        settingsManager,
        modelRuntime,
        resourceLoaderOptions: {
          extensionFactories: [gate.extension],
          noExtensions: true,
          noSkills: true,
          noPromptTemplates: true,
          noThemes: true,
          noContextFiles: true,
          systemPrompt: '',
          appendSystemPrompt: [],
        },
      });
      const created = await dependencies.publicCreateAgentSessionFromServices({
        services,
        sessionManager,
        model: faux.getModel(),
        thinkingLevel: 'off',
        tools: definitions.map(({ name }) => name),
        customTools: [...decorated],
      });
      const session = created.session;
      gate.bindSession(session);
      witness.sessionCreated(matrixGeneration);
      try {
        for (const candidate of cases) {
          activeCase = candidate;
          readyCount = 0;
          readyRecorded = false;
          timeoutSettlements = new Set<string>();
          timeoutBarrier = settlementBarrier();
          witness.caseStarted(candidate);
          const prompt = session.prompt(`A.25 fixed approval case ${candidate.turn}.`, {
            expandPromptTemplates: false,
          });
          if (candidate.action === 'timeout') {
            await timeoutBarrier.promise;
            await new Promise<void>((resolvePromise) => setImmediate(resolvePromise));
            await session.abort();
          }
          await prompt;
        }
      } finally {
        session.dispose();
      }
      return Object.freeze({
        schemaVersion: 1 as const,
        eventType: 'approval-matrix.complete' as const,
        generation: matrixGeneration,
        turns: cases.length,
        delegateCalls: witness.delegateCalls,
        fiveArgumentViolations: witness.fiveArgumentViolations,
        ...replayEvidence,
      });
    },
  });
}
