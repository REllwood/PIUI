import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: mocks.invoke }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn() }));

import {
  importNativeCredentials,
  inspectNativeCredentialImport,
} from '../../src/platform/native';

describe('credential import WebView projection', () => {
  beforeEach(() => mocks.invoke.mockReset());

  it('projects metadata only even if a hostile native response contains extra values', async () => {
    mocks.invoke.mockResolvedValueOnce({
      available: true,
      candidates: [
        {
          providerId: 'openai-codex',
          credentialType: 'subscription',
          accessToken: 'PIUI_IMPORT_CANARY',
        },
      ],
      sourcePath: '/Users/example/.pi/agent/auth.json',
    });
    const inspection = await inspectNativeCredentialImport();
    expect(inspection).toEqual({
      available: true,
      candidates: [{ providerId: 'openai-codex', credentialType: 'subscription' }],
    });
    expect(JSON.stringify(inspection)).not.toContain('PIUI_IMPORT_CANARY');
    expect(JSON.stringify(inspection)).not.toContain('/Users/');
  });

  it('sends only selected provider identifiers and accepts only an unchanged-source receipt', async () => {
    mocks.invoke.mockResolvedValueOnce({
      importedProviderIds: ['openai-codex'],
      sourceUnchanged: true,
      credential: 'PIUI_IMPORT_CANARY',
    });
    const receipt = await importNativeCredentials(['openai-codex']);
    expect(mocks.invoke).toHaveBeenCalledWith('credential_import_selected', {
      providerIds: ['openai-codex'],
    });
    expect(receipt).toEqual({
      importedProviderIds: ['openai-codex'],
      sourceUnchanged: true,
    });
    expect(JSON.stringify(receipt)).not.toContain('PIUI_IMPORT_CANARY');
  });

  it('rejects ambiguous or unacknowledged native results', async () => {
    mocks.invoke.mockResolvedValueOnce({
      importedProviderIds: ['openai-codex'],
      sourceUnchanged: false,
    });
    await expect(importNativeCredentials(['openai-codex'])).rejects.toThrow(
      'credential-import-response-invalid',
    );
    mocks.invoke.mockResolvedValueOnce({
      available: true,
      candidates: [{ providerId: 'openai-codex', credentialType: 'raw-secret' }],
    });
    await expect(inspectNativeCredentialImport()).rejects.toThrow(
      'credential-import-response-invalid',
    );
  });
});
