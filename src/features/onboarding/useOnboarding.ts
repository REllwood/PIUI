import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  initialOnboardingState,
  reduceOnboarding,
  restoreOnboarding,
  type OnboardingEvent,
} from '../../domain/onboardingMachine';
import {
  authoriseWorkspace,
  importNativeCredentials,
  inspectWorkspace,
  inspectNativeCredentialImport,
  listProductProviders,
  loadTrustedWorkspace,
  nativeDiagnosticsSnapshot,
  nativeHostStatus,
  openWorkspaceUntrusted,
  openDisclosedExternal,
  presentNativeCredentialSheet,
  selectWorkspaceDirectory,
  startLocalHelper,
  startProductAuthentication,
  type NativeAuthNotice,
  type NativeApplicationData,
  type NativeApplicationDataUpdate,
  type NativeCredentialImportCandidate,
  type NativeDiagnosticCheck,
  type NativeProvider,
} from '../../platform/native';
import { productErrorMessage } from '../../domain/errors';

type CheckState = 'idle' | 'running' | 'pass' | 'fail' | 'offline';
type AuthState = 'idle' | 'opening' | 'waiting' | 'validated' | 'cancelled' | 'expired' | 'failed';
type ProjectChoice = Readonly<{
  id: string;
  name: string;
  revision: number;
  trust: 'untrusted' | 'trusted' | 'revoked';
}>;

export type OnboardingServices = Readonly<{
  authoriseWorkspace: typeof authoriseWorkspace;
  importNativeCredentials: typeof importNativeCredentials;
  inspectWorkspace: typeof inspectWorkspace;
  inspectNativeCredentialImport: typeof inspectNativeCredentialImport;
  listProductProviders: typeof listProductProviders;
  loadTrustedWorkspace: typeof loadTrustedWorkspace;
  nativeDiagnosticsSnapshot: typeof nativeDiagnosticsSnapshot;
  nativeHostStatus: typeof nativeHostStatus;
  openWorkspaceUntrusted: typeof openWorkspaceUntrusted;
  openDisclosedExternal: typeof openDisclosedExternal;
  presentNativeCredentialSheet: typeof presentNativeCredentialSheet;
  selectWorkspaceDirectory: typeof selectWorkspaceDirectory;
  startLocalHelper: typeof startLocalHelper;
  startProductAuthentication: typeof startProductAuthentication;
}>;

const productionOnboardingServices: OnboardingServices = Object.freeze({
  authoriseWorkspace,
  importNativeCredentials,
  inspectWorkspace,
  inspectNativeCredentialImport,
  listProductProviders,
  loadTrustedWorkspace,
  nativeDiagnosticsSnapshot,
  nativeHostStatus,
  openWorkspaceUntrusted,
  openDisclosedExternal,
  presentNativeCredentialSheet,
  selectWorkspaceDirectory,
  startLocalHelper,
  startProductAuthentication,
});

export function useOnboarding(
  onFinish: () => void,
  applicationData: NativeApplicationData,
  onPersist: (update: NativeApplicationDataUpdate) => Promise<void>,
  services: OnboardingServices = productionOnboardingServices,
) {
  const [state, setState] = useState(() =>
    restoreOnboarding(
      JSON.stringify({
        version: 1,
        completed: applicationData.onboarding.completedSteps,
        finished: applicationData.onboarding.finished,
      }),
    ),
  );
  const [checkState, setCheckState] = useState<CheckState>('idle');
  const [checkResults, setCheckResults] = useState<readonly NativeDiagnosticCheck[]>([]);
  const [authState, setAuthState] = useState<AuthState>('idle');
  const [provider, setProvider] = useState<string | null>(null);
  const [providerCatalogue, setProviderCatalogue] = useState<readonly NativeProvider[]>([]);
  const [providerSummary, setProviderSummary] = useState<Readonly<{
    name: string;
    accountLabel: string;
  }> | null>(null);
  const [authNotice, setAuthNotice] = useState<NativeAuthNotice | null>(null);
  const [project, setProject] = useState<ProjectChoice | null>(() => {
    const recent = applicationData.recentWorkspaces[0];
    return recent
      ? {
          id: recent.capabilityId,
          name: recent.displayLabel,
          revision: recent.workspaceRevision,
          trust: recent.trustState,
        }
      : null;
  });
  const [projectBusy, setProjectBusy] = useState(false);
  const [projectError, setProjectError] = useState<string | null>(null);
  const [finishing, setFinishing] = useState(false);
  const [importState, setImportState] = useState<
    'checking' | 'available' | 'unavailable' | 'importing' | 'complete' | 'failed'
  >('checking');
  const [importCandidates, setImportCandidates] = useState<
    readonly NativeCredentialImportCandidate[]
  >([]);

  useEffect(() => {
    if (
      state.finished === applicationData.onboarding.finished &&
      state.completed.length === applicationData.onboarding.completedSteps.length &&
      state.completed.every(
        (step, index) => applicationData.onboarding.completedSteps[index] === step,
      )
    )
      return;
    void onPersist((current) => ({
      ...current,
      onboarding: { completedSteps: [...state.completed], finished: state.finished },
    })).catch(() => undefined);
  }, [applicationData, onPersist, state.completed, state.finished]);

  useEffect(() => {
    let active = true;
    void services.inspectNativeCredentialImport()
      .then((inspection) => {
        if (!active) return;
        setImportCandidates(inspection.candidates);
        setImportState(
          inspection.available && inspection.candidates.length > 0 ? 'available' : 'unavailable',
        );
      })
      .catch(() => {
        if (active) setImportState('failed');
      });
    void services.listProductProviders()
      .then((providers) => {
        if (!active) return;
        setProviderCatalogue(providers);
        const connected = providers.find((candidate) => candidate.status === 'connected');
        if (connected) {
          setProvider(connected.id);
          setProviderSummary({
            name: connected.name,
            accountLabel: connected.accountLabel ?? 'Validated local credential',
          });
          setAuthState('validated');
          setState((current) => reduceOnboarding(current, { type: 'provider-connected' }));
        }
      })
      .catch(() => {
        if (active) setProviderCatalogue([]);
      });
    return () => {
      active = false;
    };
  }, [services]);

  const dispatch = useCallback(
    (event: OnboardingEvent) => setState((current) => reduceOnboarding(current, event)),
    [],
  );

  const runChecks = useCallback(async () => {
    setCheckState('running');
    setCheckResults([]);
    try {
      const [, helper] = await Promise.all([
        services.nativeHostStatus(),
        services.startLocalHelper(),
        onPersist((current) => current),
      ]);
      const snapshot = await services.nativeDiagnosticsSnapshot(navigator.onLine);
      const applicationDataCheck: NativeDiagnosticCheck = Object.freeze({
        id: 'application-data',
        label: 'Application data',
        status: 'pass',
        detail: 'PIUI confirmed an atomic non-secret application-data write.',
      });
      const results = Object.freeze([...snapshot.checks, applicationDataCheck]);
      setCheckResults(results);
      if (!helper.running || helper.failed || results.some((check) => check.status === 'fail')) {
        setCheckState('fail');
      } else if (results.some((check) => check.status === 'offline')) {
        setCheckState('offline');
      } else {
        setCheckState('pass');
      }
    } catch {
      setCheckResults(
        Object.freeze([
          {
            id: 'environment-check',
            label: 'Local environment',
            status: 'fail',
            detail: 'PIUI could not complete the local readiness checks.',
            recovery: 'Restart PIUI and run the checks again.',
          },
        ]),
      );
      setCheckState('fail');
    }
  }, [onPersist, services]);

  const connectProvider = useCallback(async (providerId: string) => {
    setProvider(providerId);
    setAuthNotice(null);
    setAuthState('opening');
    try {
      setAuthState('waiting');
      let authFailed = false;
      await services.startProductAuthentication({
        providerId,
        onStarted: () => undefined,
        onNotice: (notice) => {
          setAuthNotice(notice);
          if (notice.type === 'opening-browser') void services.openDisclosedExternal(notice.url);
          if (notice.type === 'device-code')
            void services.openDisclosedExternal(notice.verificationUri);
        },
        onFailed: () => {
          authFailed = true;
        },
      });
      if (authFailed) {
        setAuthState('failed');
        return;
      }
      const providers = await services.listProductProviders();
      const match = providers.find((candidate) => candidate.id === providerId);
      if (match?.status === 'connected') {
        setProviderCatalogue(providers);
        setProviderSummary({
          name: match.name,
          accountLabel: match.accountLabel ?? 'Validated local credential',
        });
        setAuthState('validated');
        setState((current) => reduceOnboarding(current, { type: 'provider-connected' }));
      } else {
        setAuthState('failed');
      }
    } catch {
      setAuthState('failed');
    }
  }, [services]);

  const connectApiKey = useCallback(async (providerId: string, providerLabel: string) => {
    setProvider(providerId);
    setAuthState('opening');
    try {
      const result = await services.presentNativeCredentialSheet({
        providerId,
        providerLabel,
        accountLabel: `${providerLabel} API key`,
      });
      if (result.savedState === 'cancelled') {
        setAuthState('cancelled');
        return;
      }
      setAuthState('waiting');
      const providers = await services.listProductProviders();
      const match = providers.find((candidate) => candidate.id === providerId);
      if (result.validationState === 'saved-not-validated' && match?.status === 'connected') {
        setProviderCatalogue(providers);
        setProviderSummary({
          name: match.name,
          accountLabel: result.accountLabel || 'Validated local credential',
        });
        setAuthState('validated');
        setState((current) => reduceOnboarding(current, { type: 'provider-connected' }));
      } else {
        setAuthState('failed');
      }
    } catch {
      setAuthState('failed');
    }
  }, [services]);

  const chooseProject = useCallback(async () => {
    if (projectBusy) return;
    setProjectBusy(true);
    setProjectError(null);
    try {
      const summary = await services.selectWorkspaceDirectory();
      if (summary) {
        const inspected = await services.inspectWorkspace(summary.workspaceId);
        const opened = await services.openWorkspaceUntrusted(
          inspected.workspaceId,
          inspected.revision,
        );
        setProject({
          id: opened.workspaceId,
          name: opened.displayLabel,
          revision: opened.revision,
          trust: 'untrusted',
        });
        setState((current) => reduceOnboarding(current, { type: 'project-selected' }));
      }
    } catch (error) {
      setProject(null);
      setProjectError(
        productErrorMessage(error, 'PIUI could not open that folder. Choose the project folder again.'),
      );
    } finally {
      setProjectBusy(false);
    }
  }, [projectBusy, services]);

  const trustProject = useCallback(async () => {
    if (!project || projectBusy || project.trust === 'trusted') return;
    setProjectBusy(true);
    setProjectError(null);
    try {
      const trusted = await services.authoriseWorkspace(project.id, project.revision);
      const loaded = await services.loadTrustedWorkspace(trusted.workspaceId, trusted.revision);
      setProject({
        id: loaded.workspaceId,
        name: loaded.displayLabel,
        revision: loaded.revision,
        trust: 'trusted',
      });
    } catch (error) {
      // The step shows why trust was not granted; the project stays untrusted.
      setProjectError(
        productErrorMessage(
          error,
          'PIUI could not trust this project. It stays untrusted; try again or choose another folder.',
        ),
      );
    } finally {
      setProjectBusy(false);
    }
  }, [project, projectBusy, services]);

  const importExistingCredentials = useCallback(async () => {
    if (importState === 'importing' || importCandidates.length === 0) return;
    setImportState('importing');
    try {
      await services.importNativeCredentials(
        importCandidates.map((candidate) => candidate.providerId),
      );
      setImportState('complete');
    } catch {
      setImportState('failed');
    }
  }, [importCandidates, importState, services]);

  const finish = useCallback(async () => {
    if (finishing) return;
    setFinishing(true);
    const finishedState = reduceOnboarding(state, { type: 'finish' });
    try {
      await onPersist((current) => ({
        ...current,
        onboarding: {
          completedSteps: [...finishedState.completed],
          finished: finishedState.finished,
        },
        recentWorkspaces: project
          ? [
              {
                capabilityId: project.id,
                displayLabel: project.name,
                trustState: project.trust,
                workspaceRevision: project.revision,
                lastOpenedUnixMs: Date.now(),
              },
              ...current.recentWorkspaces.filter(
                (workspace) => workspace.capabilityId !== project.id,
              ),
            ].slice(0, 32)
          : current.recentWorkspaces,
      }));
      setState(finishedState);
      onFinish();
    } finally {
      setFinishing(false);
    }
  }, [finishing, onFinish, onPersist, project, state]);

  return useMemo(
    () => ({
      state,
      dispatch,
      checkState,
      checkResults,
      runChecks,
      authState,
      authNotice,
      provider,
      providerCatalogue,
      providerSummary,
      connectProvider,
      connectApiKey,
      importState,
      importCandidates,
      importExistingCredentials,
      project,
      projectBusy,
      projectError,
      chooseProject,
      trustProject,
      finish,
      finishing,
      reset: () => setState(initialOnboardingState),
    }),
    [
      state,
      dispatch,
      checkState,
      checkResults,
      runChecks,
      authState,
      authNotice,
      provider,
      providerCatalogue,
      providerSummary,
      connectProvider,
      connectApiKey,
      importState,
      importCandidates,
      importExistingCredentials,
      project,
      projectBusy,
      projectError,
      chooseProject,
      trustProject,
      finish,
      finishing,
    ],
  );
}
