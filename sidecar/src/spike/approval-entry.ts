import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  createA25ApprovalFixtureFromEnvironment,
  type A25ApprovalDependencies,
} from './approval-matrix.js';

function productionModule(relativePath: string): string {
  return pathToFileURL(resolve(process.cwd(), relativePath)).href;
}

const [
  runtime,
  approvalHook,
  aiPublicSdk,
  publicSdk,
  hostRequests,
  router,
  approvalCanonical,
] = await Promise.all([
  import(productionModule('dist/runtime.js')) as Promise<typeof import('../runtime.js')>,
  import(productionModule('dist/pi/approval-hook.js')) as Promise<
    typeof import('../pi/approval-hook.js')
  >,
  import(productionModule('dist/pi/ai-public-sdk.js')) as Promise<
    typeof import('../pi/ai-public-sdk.js')
  >,
  import(productionModule('dist/pi/public-sdk.js')) as Promise<
    typeof import('../pi/public-sdk.js')
  >,
  import(productionModule('dist/bridge/host-requests.js')) as Promise<
    typeof import('../bridge/host-requests.js')
  >,
  import(productionModule('dist/bridge/router.js')) as Promise<
    typeof import('../bridge/router.js')
  >,
  import(productionModule('dist/pi/approval-canonical.js')) as Promise<
    typeof import('../pi/approval-canonical.js')
  >,
]);

const dependencies: A25ApprovalDependencies = Object.freeze({
  createApprovalGate: approvalHook.createApprovalGate,
  publicFauxAssistantMessage: aiPublicSdk.publicFauxAssistantMessage,
  publicFauxProvider: aiPublicSdk.publicFauxProvider,
  publicFauxToolCall: aiPublicSdk.publicFauxToolCall,
  PublicModelRuntime: publicSdk.PublicModelRuntime,
  PublicSessionManager: publicSdk.PublicSessionManager,
  PublicSettingsManager: publicSdk.PublicSettingsManager,
  assertPublicSdk: publicSdk.assertPublicSdk,
  publicCreateAgentSessionFromServices: publicSdk.publicCreateAgentSessionFromServices,
  publicCreateAgentSessionServices: publicSdk.publicCreateAgentSessionServices,
  HostRequestClient: hostRequests.HostRequestClient,
  HostRequestError: hostRequests.HostRequestError,
  SidecarRouter: router.SidecarRouter,
  canonicaliseApprovalInput: approvalCanonical.canonicaliseApprovalInput,
});
const fixture = createA25ApprovalFixtureFromEnvironment(dependencies);
if (!fixture) throw new Error('approval-matrix-environment-rejected');
runtime.runSidecar(fixture);
