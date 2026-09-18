import type { AdapterSupport } from './adapter.js';

export const PI_082_CAPABILITIES: AdapterSupport = Object.freeze({
  providers: 'supported',
  authentication: 'supported',
  workspaces: 'supported',
  sessions: 'supported',
  streaming: 'supported',
  queues: 'supported',
  compaction: 'supported',
  tools: 'supported',
  resources: 'supported',
  settings: 'supported',
  diagnostics: 'supported',
});

export const RAW_RPC_DIAGNOSTIC_ENABLED = false as const;
