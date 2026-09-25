// @vitest-environment jsdom

import { act, cleanup, render, renderHook, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { defaultNativeApplicationData } from '../../platform/native';
import { ChooseProjectStep } from './ChooseProjectStep';
import { useOnboarding, type OnboardingServices } from './useOnboarding';

afterEach(cleanup);

const applicationData = {
  ...defaultNativeApplicationData,
  recentWorkspaces: [
    {
      capabilityId: 'workspace-0123456789abcdef0123456789abcdef',
      displayLabel: 'Project',
      trustState: 'untrusted' as const,
      workspaceRevision: 1,
      lastOpenedUnixMs: 1,
    },
  ],
};

function services(overrides: Partial<OnboardingServices>): OnboardingServices {
  const unused = vi.fn(() => new Promise<never>(() => undefined));
  return {
    authoriseWorkspace: unused,
    importNativeCredentials: unused,
    inspectWorkspace: unused,
    inspectNativeCredentialImport: unused,
    listProductProviders: unused,
    loadTrustedWorkspace: unused,
    nativeDiagnosticsSnapshot: unused,
    nativeHostStatus: unused,
    openWorkspaceUntrusted: unused,
    openDisclosedExternal: unused,
    presentNativeCredentialSheet: unused,
    selectWorkspaceDirectory: unused,
    startLocalHelper: unused,
    startProductAuthentication: unused,
    ...overrides,
  } as OnboardingServices;
}

describe('onboarding project trust', () => {
  it('reports a failed trust in the step instead of rejecting', async () => {
    const { result } = renderHook(() =>
      useOnboarding(
        () => undefined,
        applicationData,
        async () => undefined,
        services({ authoriseWorkspace: vi.fn().mockRejectedValue('workspace-disconnected') }),
      ),
    );
    await act(async () => {
      await expect(result.current.trustProject()).resolves.toBeUndefined();
    });
    expect(result.current.projectBusy).toBe(false);
    expect(result.current.project?.trust).toBe('untrusted');
    expect(result.current.projectError).toBe(
      'PIUI no longer has access to this project folder. Choose the project folder again to renew access.',
    );
  });

  it('shows the error as an alert beside the project controls', () => {
    render(
      <ChooseProjectStep
        project={{ id: 'workspace-a', name: 'Project', revision: 1, trust: 'untrusted' }}
        busy={false}
        error="PIUI could not trust this project."
        onChoose={async () => undefined}
        onTrust={async () => undefined}
      />,
    );
    expect(screen.getByRole('alert').textContent).toBe('PIUI could not trust this project.');
  });

  it('names the selected folder without exposing its internal capability ID', () => {
    const { container } = render(
      <ChooseProjectStep
        project={{
          id: 'workspace-0123456789abcdef0123456789abcdef',
          name: 'Project',
          revision: 1,
          trust: 'untrusted',
        }}
        busy={false}
        onChoose={async () => undefined}
        onTrust={async () => undefined}
      />,
    );
    expect(screen.getByRole('heading', { name: 'Project' })).toBeTruthy();
    expect(screen.getByText('Selected folder')).toBeTruthy();
    expect(container.textContent).not.toContain('workspace-');
    expect(container.textContent).not.toMatch(/capability workspace/iu);
  });
});
