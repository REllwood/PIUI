import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  PUBLIC_SESSION_VERSION,
  PublicModelRuntime,
  PublicSessionManager,
  PublicSettingsManager,
  assertPublicSdk,
  publicCreateAgentSessionFromServices,
  publicCreateAgentSessionRuntime,
  publicCreateAgentSessionServices,
  publicCreateToolDefinitions,
  publicSdkMetadata,
} from '../../src/pi/public-sdk';

describe('pinned public Pi SDK surface', () => {
  it('retains the exact version and package-root runtime factories', () => {
    expect(assertPublicSdk).not.toThrow();
    expect(publicSdkMetadata()).toMatchObject({ piVersion: '0.82.0' });
    expect(PUBLIC_SESSION_VERSION).toBeGreaterThan(0);
    for (const value of [
      PublicModelRuntime,
      PublicSessionManager,
      PublicSettingsManager,
      publicCreateAgentSessionFromServices,
      publicCreateAgentSessionRuntime,
      publicCreateAgentSessionServices,
      publicCreateToolDefinitions,
    ]) expect(value).toBeTypeOf('function');
  });

  it('keeps every adapter capability connected to a public SDK or PIUI-owned domain seam', () => {
    const source = readFileSync(resolve(import.meta.dirname, '../../src/pi/pi-082-adapter.ts'), 'utf8');
    const requiredSeams = [
      'describeProviders',
      'createOAuthInteraction',
      'PublicSessionManager',
      'PublicSettingsManager',
      'publicCreateAgentSessionServices',
      'publicCreateAgentSessionFromServices',
      'publicCreateToolDefinitions',
      'SessionOwnership',
      'TurnRegistry',
      'createApprovalGate',
      'ChangeRegistry',
      'ResourceRegistry',
      'TypedSettingsAdapter',
      'safeDiagnosticSnapshot',
    ];
    for (const seam of requiredSeams) expect(source, seam).toContain(seam);
    expect(source).toContain("thinkingLevel: 'medium'");
    expect(source).toContain("noTools: 'builtin'");
    expect(source).toContain('customTools: [...definitions]');
  });
});
