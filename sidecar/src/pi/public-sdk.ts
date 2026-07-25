import {
  AgentSession,
  AgentSessionRuntime,
  ModelRuntime,
  ProjectTrustStore,
  SessionManager,
  VERSION,
  createAgentSession,
} from '@earendil-works/pi-coding-agent';

export const REQUIRED_PUBLIC_CAPABILITIES = Object.freeze({
  AgentSession: typeof AgentSession === 'function',
  AgentSessionRuntime: typeof AgentSessionRuntime === 'function',
  ModelRuntime: typeof ModelRuntime === 'function',
  ProjectTrustStore: typeof ProjectTrustStore === 'function',
  SessionManager: typeof SessionManager === 'function',
  createAgentSession: typeof createAgentSession === 'function',
});

export function publicSdkMetadata() {
  return {
    piVersion: VERSION,
    nodeVersion: process.versions.node,
    architecture: process.arch,
    capabilities: Object.entries(REQUIRED_PUBLIC_CAPABILITIES).filter(([, available]) => available).map(([name]) => name).sort(),
  };
}

export function assertPublicSdk(): void {
  const unavailable = Object.entries(REQUIRED_PUBLIC_CAPABILITIES).filter(([, available]) => !available).map(([name]) => name);
  if (VERSION !== '0.82.0') throw new Error('Pinned Pi SDK version mismatch');
  if (unavailable.length) throw new Error(`Required public Pi capabilities unavailable: ${unavailable.join(', ')}`);
}
