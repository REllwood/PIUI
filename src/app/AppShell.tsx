import { useCallback, useEffect, useState } from 'react';
import { AnnouncementHost } from '../components/status/AnnouncementHost';
import { type AppCommandId } from './commands';
import { CommandMenu } from './CommandMenu';
import { ComposerDraftProvider } from '../features/composer/ComposerDrafts';
import { CommandRouter } from './CommandRouter';
import { isTurnActive } from '../domain/machines';
import { canCreateConversation } from '../domain/readiness';
import { MainToolbar } from './MainToolbar';
import { NavigationPlane } from './NavigationPlane';
import { useProduct, type OperationId } from './ProductContext';
import { RouteHost } from './RouteHost';
import {
  closeNativeMainWindow,
  listenForNativeMenuCommand,
  openDisclosedExternal,
  setNativeMenuEnabledState,
} from '../platform/native';
import { LoadingLabel } from '../components/primitives/LoadingLabel';

// Keyed on every operation so a new one cannot ship without its own status copy.
const OPERATION_LABELS: Readonly<Record<OperationId, string>> = {
  send: 'Sending to Pi…',
  stop: 'Stopping Pi…',
  queue: 'Queuing follow-up…',
  approval: 'Recording your decision…',
  settings: 'Saving changes…',
  diagnostics: 'Checking PIUI…',
  provider: 'Updating provider connection…',
  project: 'Updating project access…',
  update: 'Checking for updates…',
  session: 'Updating session…',
  export: 'Exporting a copy…',
  change: 'Updating file changes…',
  resource: 'Updating Pi resource…',
};

export function AppShell() {
  const product = useProduct();
  const [navigationOpen, setNavigationOpen] = useState(false);
  const [commandMenuOpen, setCommandMenuOpen] = useState(false);
  const [approvalRequest, setApprovalRequest] = useState(0);
  const [commandError, setCommandError] = useState<string | null>(null);
  const [compact, setCompact] = useState(() => window.matchMedia('(max-width: 760px)').matches);
  const closeNavigation = useCallback(() => setNavigationOpen(false), []);
  const pendingApproval = product.snapshot.approvals.find(
    (approval) => approval.state === 'awaiting' || approval.state === 'unacknowledged',
  );
  const turnRunning = isTurnActive(product.snapshot.turnStatus);
  const canCreate = canCreateConversation(product.snapshot, product.activeOperation);
  useEffect(() => {
    const query = window.matchMedia('(max-width: 760px)');
    const update = () => {
      setCompact(query.matches);
      if (!query.matches) setNavigationOpen(false);
    };
    query.addEventListener('change', update);
    return () => query.removeEventListener('change', update);
  }, []);
  const commandEnabled = useCallback(
    (command: AppCommandId) => {
      if (command === 'new-conversation') return canCreate;
      if (command === 'stop-turn') return turnRunning && product.activeOperation === null;
      if (command === 'alternate-send') return !turnRunning && canCreate;
      if (command === 'choose-project') return !turnRunning && product.activeOperation === null;
      return product.activeOperation === null;
    },
    [canCreate, product.activeOperation, turnRunning],
  );

  useEffect(() => {
    const open = (event: Event) => {
      if (!(event instanceof CustomEvent) || typeof event.detail !== 'string') return;
      void openDisclosedExternal(event.detail).catch(() => {
        window.dispatchEvent(new CustomEvent('piui:external-open-failed'));
      });
    };
    window.addEventListener('piui:open-external', open);
    return () => window.removeEventListener('piui:open-external', open);
  }, []);

  useEffect(() => {
    const copyUnavailable = () =>
      setCommandError(
        'Copying to the clipboard is not available right now. Select the text and copy it manually.',
      );
    const externalOpenFailed = () =>
      setCommandError('That link could not be opened in your browser.');
    window.addEventListener('piui:copy-unavailable', copyUnavailable);
    window.addEventListener('piui:external-open-failed', externalOpenFailed);
    return () => {
      window.removeEventListener('piui:copy-unavailable', copyUnavailable);
      window.removeEventListener('piui:external-open-failed', externalOpenFailed);
    };
  }, []);

  useEffect(() => {
    void setNativeMenuEnabledState({
      canCreate,
      canChooseProject: !turnRunning && product.activeOperation === null,
      canStop: turnRunning && product.activeOperation === null,
      canSend: !turnRunning && canCreate,
    }).catch(() => undefined);
  }, [canCreate, product.activeOperation, turnRunning]);

  const onCommand = useCallback(
    (command: AppCommandId) => {
      if (document.querySelector('dialog[open]') && (!commandMenuOpen || command === 'alternate-send')) return;
      if (!commandEnabled(command)) return;
      setCommandError(null);
      const run = (operation: Promise<unknown>) => {
        void operation.catch(() =>
          setCommandError('That action could not be completed. Please try again.'),
        );
      };
      if (command === 'open-settings') product.openSettings();
      else if (command === 'open-sessions') product.setRoute('sessions');
      else if (command === 'new-conversation') run(product.createSession());
      else if (command === 'toggle-navigation') setNavigationOpen((current) => !current);
      else if (command === 'stop-turn') run(product.stop());
      else if (command === 'alternate-send')
        document.querySelector<HTMLFormElement>('.composer')?.requestSubmit();
      else if (command === 'open-command-menu') setCommandMenuOpen(true);
      else if (command === 'choose-project')
        run(
          product.chooseProject().then((selected) => {
            if (selected) product.setRoute('conversation');
          }),
        );
      else if (command === 'close-window') run(closeNativeMainWindow());
    },
    [commandEnabled, commandMenuOpen, product],
  );

  const openSessionSearch = useCallback(() => {
    product.setRoute('sessions');
    window.requestAnimationFrame(() => {
      document.querySelector<HTMLInputElement>('#session-search')?.focus();
    });
  }, [product]);

  useEffect(() => {
    let disposed = false;
    let remove: (() => void) | undefined;
    void listenForNativeMenuCommand((command) => {
      if (!disposed) onCommand(command as AppCommandId);
    })
      .then((unlisten) => {
        if (disposed) unlisten();
        else remove = unlisten;
      })
      .catch(() => undefined);
    return () => {
      disposed = true;
      remove?.();
    };
  }, [onCommand]);

  return (
    <div className="app-shell">
      <CommandRouter onCommand={onCommand} />
      <NavigationPlane open={navigationOpen} compact={compact} onClose={closeNavigation} />
      {navigationOpen && compact ? (
        <button
          type="button"
          className="navigation-scrim"
          aria-label="Close navigation"
          onClick={() => setNavigationOpen(false)}
        />
      ) : null}
      <section className="app-main" aria-label="PIUI workspace" inert={compact && navigationOpen}>
        <MainToolbar
          onOpenNavigation={() => setNavigationOpen(true)}
          onSearch={openSessionSearch}
          onOpenCommands={() => setCommandMenuOpen(true)}
          onChooseProject={() => onCommand('choose-project')}
          onOpenApprovals={() => {
            product.setRoute('conversation');
            setApprovalRequest((current) => current + 1);
          }}
        />
        <div className="app-route-container">
          <ComposerDraftProvider>
            <RouteHost approvalRequest={approvalRequest} />
          </ComposerDraftProvider>
        </div>
      </section>
      <AnnouncementHost
        announcement={
          pendingApproval
            ? { id: pendingApproval.id, message: `Approval needed: ${pendingApproval.action}` }
            : null
        }
      />
      {commandError ? (
        <div className="global-operation-status" role="alert">
          <span>{commandError}</span>
          <button
            type="button"
            className="button button--quiet"
            onClick={() => setCommandError(null)}
          >
            Dismiss
          </button>
        </div>
      ) : null}
      {product.activeOperation ? (
        <div className="global-operation-status" role="status">
          <LoadingLabel>{OPERATION_LABELS[product.activeOperation]}</LoadingLabel>
        </div>
      ) : null}
      <CommandMenu
        open={commandMenuOpen}
        onClose={() => setCommandMenuOpen(false)}
        onCommand={onCommand}
        commandEnabled={commandEnabled}
      />
    </div>
  );
}
