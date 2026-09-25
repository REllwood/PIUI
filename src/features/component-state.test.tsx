// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import axe from 'axe-core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppShell } from '../app/AppShell';
import type { ProductContextValue } from '../app/ProductContext';
import { DiffView } from '../components/diff/DiffView';
import { productFixture } from '../domain/fixtures';
import { ActivityDetail } from './activity/ActivityDetail';
import { ActivityRoute } from './activity/ActivityRoute';
import { ApprovalSurface } from './approvals/ApprovalSurface';
import { DiffReview } from './changes/DiffReview';
import { CheckMacStep } from './onboarding/CheckMacStep';
import { ProductTour } from './onboarding/ProductTour';
import { ReadyStep } from './onboarding/ReadyStep';
import { AboutPanel } from './settings/AboutPanel';
import { UpdateStatus } from './updates/UpdateStatus';

const productStub = vi.hoisted(() => ({ value: null as unknown }));

vi.mock('../app/ProductContext', () => ({
  useProduct: () => productStub.value,
}));

afterEach(cleanup);

describe('async and recovery component states', () => {
  it('announces environment-check progress and disables duplicate starts', () => {
    render(<CheckMacStep status="running" checks={[]} onRun={() => undefined} />);
    const button = screen.getByRole('button', { name: 'Checking this Mac…' });
    expect(button.hasAttribute('disabled')).toBe(true);
    expect(screen.getByRole('region', { name: 'Environment checks' }).getAttribute('aria-busy'))
      .toBe('true');
  });

  it('exposes a bounded safe-report copy action after checks finish', () => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
    render(
      <CheckMacStep
        status="fail"
        checks={[
          {
            id: 'host',
            label: 'macOS and architecture',
            status: 'fail',
            detail: 'Unsupported host.',
            recovery: 'Use a supported Apple Silicon Mac.',
          },
        ]}
        onRun={() => undefined}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Copy safe report' }));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
      'macOS and architecture: fail — Unsupported host.',
    );
  });

  it('uses a textual fallback for binary diffs and suppresses unavailable copy', () => {
    render(
      <DiffView
        change={{
          id: 'change-1',
          path: 'asset.bin',
          state: 'binary',
          additions: 0,
          deletions: 0,
          before: [],
          after: [],
          undo: 'revoked',
        }}
      />,
    );
    expect(screen.getByRole('note').textContent).toContain('Binary file preview unavailable');
    expect(screen.getByRole('button', { name: 'Copy' }).hasAttribute('disabled')).toBe(true);
  });

  it('counts changed lines in natural singular and plural copy', () => {
    const change = {
      id: 'change-1',
      path: 'src/app/commands.ts',
      state: 'modified',
      additions: 1,
      deletions: 1,
      before: ["  | 'close-window';"],
      after: ["  | 'toggle-theme';"],
      undo: 'safe',
    } as const;
    const review = (additions: number, deletions: number) => (
      <DiffReview
        change={{ ...change, additions, deletions }}
        busy={false}
        onUndo={async () => undefined}
        onReveal={async () => undefined}
      />
    );
    const { rerender } = render(review(1, 1));
    const heading = () => screen.getByRole('heading', { level: 2 }).textContent;
    expect(heading()).toBe('1 addition, 1 deletion');
    rerender(review(5, 0));
    expect(heading()).toBe('5 additions, 0 deletions');
  });

  it('shows progress and disables repeated cancellation while activity cancellation waits', () => {
    render(
      <ActivityDetail
        event={{
          id: 'activity-1',
          category: 'command',
          verb: 'Running',
          target: 'local checks',
          summary: 'Checking the local project.',
          state: 'running',
          elapsed: '2s',
        }}
        onCancel={() => new Promise(() => undefined)}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Cancel safely' }));
    const waiting = screen.getByRole('button', { name: 'Cancelling safely…' });
    expect(waiting.hasAttribute('disabled')).toBe(true);
  });

  it('keeps the product tour short, keyboard-operable and skippable', () => {
    const onSkip = vi.fn();
    render(<ProductTour onSkip={onSkip} />);
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByRole('heading', { name: 'Follow the work trace' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Skip tour' }));
    expect(onSkip).toHaveBeenCalledTimes(1);
  });

  it('does not claim missing Ready prerequisites are connected or trusted', () => {
    render(<ReadyStep provider={null} project={null} />);
    expect(screen.getByText('Not connected')).toBeTruthy();
    expect(screen.getByText('Not selected')).toBeTruthy();
  });

  it('explains why updates are disabled without exposing an active control', () => {
    render(
      <UpdateStatus
        update={{
          status: 'disabled',
          endpointConfigured: false,
          publicKeyConfigured: false,
          message: 'Signed updating is not configured.',
        }}
      />,
    );
    expect(screen.getByText('Disabled safely')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Check manually' }).hasAttribute('disabled')).toBe(
      true,
    );
  });

  it('reports every clipboard refusal when copying redacted activity evidence', async () => {
    productStub.value = {
      snapshot: productFixture,
      selectedActivity: productFixture.activity[0] ?? null,
      setSelectedActivity: () => undefined,
      stop: () => Promise.resolve(),
    } as unknown as ProductContextValue;
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn().mockRejectedValue(new Error('clipboard-closed')) },
    });
    const unavailable = vi.fn();
    window.addEventListener('piui:copy-unavailable', unavailable);
    try {
      render(<ActivityRoute />);
      fireEvent.click(screen.getByRole('button', { name: /Redacted event details/ }));
      const copy = screen.getByRole('button', { name: /Copy safe JSON/ });
      await act(async () => {
        fireEvent.click(copy);
      });
      expect(unavailable).toHaveBeenCalledTimes(1);
      expect(
        screen.getByRole('button', { name: /Copy safe JSON/ }).hasAttribute('disabled'),
      ).toBe(false);
    } finally {
      window.removeEventListener('piui:copy-unavailable', unavailable);
    }
  });

  it('tells the person when copying or opening a link silently failed', async () => {
    window.matchMedia = ((query: string) => ({
      matches: false,
      media: query,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
    })) as unknown as typeof window.matchMedia;
    productStub.value = {
      snapshot: productFixture,
      route: 'conversation',
      mode: 'simple',
      settings: [],
      settingsSection: null,
      activeOperation: null,
      providerAuthNotice: null,
      diagnosticEnvironment: [],
      diagnosticLogs: [],
      selectedActivity: null,
      selectedChangeId: null,
      restoreLastProject: false,
      setRoute: () => undefined,
      setSelectedActivity: () => undefined,
      setSelectedChangeId: () => undefined,
      stop: () => Promise.resolve(),
    } as unknown as ProductContextValue;
    await act(async () => {
      render(<AppShell />);
    });
    await act(async () => {
      window.dispatchEvent(new CustomEvent('piui:copy-unavailable'));
    });
    expect(screen.getByRole('alert').textContent).toContain(
      'Copying to the clipboard is not available right now.',
    );
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(screen.queryByRole('alert')).toBe(null);
    await act(async () => {
      window.dispatchEvent(new CustomEvent('piui:external-open-failed'));
    });
    expect(screen.getByRole('alert').textContent).toContain(
      'That link could not be opened in your browser.',
    );
  });

  it('shows exactly what an approval would run as inert plain text', () => {
    const approval = productFixture.approvals[0];
    if (!approval) throw new Error('fixture approval missing');
    render(
      <ApprovalSurface
        request={{
          ...approval,
          subject: {
            label: 'Command',
            text: '**not bold** <img src=x onerror=alert(1)> rm -rf ./build‮',
            truncated: true,
          },
        }}
        offline={false}
        busy={false}
        onDecision={async () => undefined}
      />,
    );
    const command = screen.getByRole('region', { name: 'Command' });
    expect(command.tagName).toBe('PRE');
    expect(command.textContent).toBe(
      '**not bold** <img src=x onerror=alert(1)> rm -rf ./build⟨U+202E⟩',
    );
    expect(command.querySelector('*')).toBeNull();
    expect(screen.getByText(/Shortened: the full command is longer than shown here/)).toBeTruthy();
  });

  it('shows unknown versions instead of remembered release numbers', () => {
    const { rerender } = render(<AboutPanel facts={[]} />);
    expect(screen.getAllByText('Unknown')).toHaveLength(4);
    expect(screen.queryByText(/0\.1\.0|0\.82\.0|22\.23\.1|arm64/)).toBeNull();
    rerender(
      <AboutPanel
        facts={[
          { key: 'piuiVersion', value: '0.2.0', origin: 'Application bundle' },
          { key: 'architecture', value: 'arm64', origin: 'Native host' },
        ]}
      />,
    );
    expect(screen.getByText('0.2.0')).toBeTruthy();
    expect(screen.getByText('arm64 macOS')).toBeTruthy();
    expect(screen.getAllByText('Unknown')).toHaveLength(2);
  });

  it('has no serious or critical semantic accessibility violations in the setup summary', async () => {
    const { container } = render(
      <ReadyStep
        provider={{ name: 'Provider', accountLabel: 'Connected account' }}
        project={{ name: 'Project', trust: 'trusted' }}
      />,
    );
    const result = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } },
    });
    expect(
      result.violations.filter((violation) =>
        ['serious', 'critical'].includes(violation.impact ?? ''),
      ),
    ).toEqual([]);
  });
});
