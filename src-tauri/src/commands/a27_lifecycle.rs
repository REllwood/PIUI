#![cfg(feature = "a27-lifecycle-test")]

use super::bridge::{
    BridgeState, bridge_restart_transport, bridge_start_transport, bridge_status_transport,
};
use crate::domain::approval::{
    ApprovalChoice, ApprovalRequest, ApprovalState, ApprovalSubmission, ApprovalTerminalReason,
};
use crate::protocol::approval::canonical_json_bytes;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{AppHandle, State};
use uuid::Uuid;

const A27_LOCK_DESCRIPTOR: RawFd = 3;
const MAX_JS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const RECOVERY_DEADLINE: Duration = Duration::from_secs(5);
const RECOVERY_POLL_INTERVAL: Duration = Duration::from_millis(20);
const REJECTED: &str = "A.27 lifecycle probe rejected";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum A27LifecyclePhase {
    Ready,
    Starting,
    Running,
    PreparingApproval,
    ApprovalWaiting,
    ForcingSidecarDeath,
    Recovering,
    Recovered,
    Restarting,
    AwaitingClose,
    AwaitingReopen,
    Resuming,
    ReadyToQuit,
    Quitting,
    Failed,
}

impl A27LifecyclePhase {
    fn is_busy(self) -> bool {
        matches!(
            self,
            Self::Starting
                | Self::PreparingApproval
                | Self::ForcingSidecarDeath
                | Self::Recovering
                | Self::Restarting
                | Self::AwaitingReopen
                | Self::Resuming
                | Self::Quitting
        )
    }

    fn message(self) -> &'static str {
        match self {
            Self::Ready => "Ready to verify lifecycle recovery.",
            Self::Starting => "Starting the isolated helper and checking duplicate prevention…",
            Self::Running => "Duplicate starts resolved to one helper generation.",
            Self::PreparingApproval => "Preparing one isolated waiting approval…",
            Self::ApprovalWaiting => "One approval is waiting for the current helper generation.",
            Self::ForcingSidecarDeath => "Stopping the helper unexpectedly…",
            Self::Recovering => "Detecting the failure and recovering the helper…",
            Self::Recovered => "The helper recovered and stale approval authority was rejected.",
            Self::Restarting => "Verifying an explicit helper restart…",
            Self::AwaitingClose => {
                "Explicit restart passed. Close the last window to verify cleanup."
            }
            Self::AwaitingReopen => "Waiting for the application to be reopened…",
            Self::Resuming => "Reopening the window and restoring one helper generation…",
            Self::ReadyToQuit => "Lifecycle recovery passed. Quit to verify final cleanup.",
            Self::Quitting => "Quitting and verifying process, descriptor and lock cleanup…",
            Self::Failed => "Lifecycle verification failed. No success evidence was published.",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct A27LifecycleSnapshot {
    pub schema_version: u8,
    pub phase: A27LifecyclePhase,
    pub busy: bool,
    pub message: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct A27NativeEvidence {
    schema_version: u8,
    status: &'static str,
    last_window_close_events: u64,
    reopen_events: u64,
    sidecars_after_close: u64,
    duplicate_start_requests: u64,
    duplicate_start_unique_pids: u64,
    duplicate_start_unique_generations: u64,
    forced_sidecar_deaths: u64,
    automatic_recoveries: u64,
    automatic_recovery_generation_delta: u64,
    user_restart_requests: u64,
    user_restart_generation_delta: u64,
    waiting_approvals_before_death: u64,
    generation_lost_approvals: u64,
    pending_approvals_after_recovery: u64,
    stale_approval_replay_rejections: u64,
    post_death_delegate_executions: u64,
    sidecar_generations_observed: u64,
    exit_requested_observed: bool,
    exit_observed: bool,
    graceful_quit: bool,
}

struct A27Inner {
    phase: A27LifecyclePhase,
    first_generation: Option<u64>,
    first_pid: Option<u32>,
    recovered_generation: Option<u64>,
    recovered_pid: Option<u32>,
    restarted_generation: Option<u64>,
    restarted_pid: Option<u32>,
    reopened_generation: Option<u64>,
    reopened_pid: Option<u32>,
    stale_submission: Option<ApprovalSubmission>,
    last_window_close_events: u64,
    reopen_events: u64,
    sidecars_after_close: u64,
    duplicate_start_requests: u64,
    duplicate_start_unique_pids: u64,
    duplicate_start_unique_generations: u64,
    forced_sidecar_deaths: u64,
    automatic_recoveries: u64,
    automatic_recovery_generation_delta: u64,
    user_restart_requests: u64,
    user_restart_generation_delta: u64,
    waiting_approvals_before_death: u64,
    generation_lost_approvals: u64,
    pending_approvals_after_recovery: u64,
    stale_approval_replay_rejections: u64,
    post_death_delegate_executions: u64,
    exit_requested_observed: bool,
    exit_observed: bool,
    graceful_quit: bool,
}

impl Default for A27Inner {
    fn default() -> Self {
        Self {
            phase: A27LifecyclePhase::Ready,
            first_generation: None,
            first_pid: None,
            recovered_generation: None,
            recovered_pid: None,
            restarted_generation: None,
            restarted_pid: None,
            reopened_generation: None,
            reopened_pid: None,
            stale_submission: None,
            last_window_close_events: 0,
            reopen_events: 0,
            sidecars_after_close: 0,
            duplicate_start_requests: 0,
            duplicate_start_unique_pids: 0,
            duplicate_start_unique_generations: 0,
            forced_sidecar_deaths: 0,
            automatic_recoveries: 0,
            automatic_recovery_generation_delta: 0,
            user_restart_requests: 0,
            user_restart_generation_delta: 0,
            waiting_approvals_before_death: 0,
            generation_lost_approvals: 0,
            pending_approvals_after_recovery: 0,
            stale_approval_replay_rejections: 0,
            post_death_delegate_executions: 0,
            exit_requested_observed: false,
            exit_observed: false,
            graceful_quit: false,
        }
    }
}

pub struct A27LifecycleState {
    // Retaining this file is the ownership contract. The kernel releases its
    // BSD flock when the host exits or this state is dropped.
    _ownership_lock: Option<File>,
    exit_witness: Mutex<Option<File>>,
    workspace_root: PathBuf,
    inner: Mutex<A27Inner>,
}

impl A27LifecycleState {
    pub fn from_environment() -> Result<Self, std::io::Error> {
        if std::env::var("PIUI_ARCHITECTURE_TEST_MODE").as_deref() != Ok("a27-lifecycle") {
            return Err(std::io::Error::other(REJECTED));
        }
        let workspace_root = private_directory_from_environment("PIUI_A27_WORKSPACE_ROOT")?;
        let witness_path = private_new_file_from_environment("PIUI_A27_EXIT_WITNESS_PATH")?;
        if witness_path.starts_with(&workspace_root) {
            return Err(std::io::Error::other(REJECTED));
        }
        let ownership_lock = acquire_inherited_lock(A27_LOCK_DESCRIPTOR)
            .map_err(|_| std::io::Error::other(REJECTED))?;
        let witness = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(witness_path)
            .map_err(|_| std::io::Error::other(REJECTED))?;
        validate_private_regular_descriptor(witness.as_raw_fd())
            .map_err(|_| std::io::Error::other(REJECTED))?;
        Ok(Self {
            _ownership_lock: Some(ownership_lock),
            exit_witness: Mutex::new(Some(witness)),
            workspace_root,
            inner: Mutex::new(A27Inner::default()),
        })
    }

    fn snapshot(&self) -> Result<A27LifecycleSnapshot, String> {
        let inner = self.inner.lock().map_err(|_| REJECTED.to_string())?;
        Ok(snapshot_for(inner.phase))
    }

    fn set_phase(
        &self,
        expected: &[A27LifecyclePhase],
        phase: A27LifecyclePhase,
    ) -> Result<(), String> {
        let mut inner = self.inner.lock().map_err(|_| REJECTED.to_string())?;
        if !expected.contains(&inner.phase) {
            return Err(REJECTED.into());
        }
        inner.phase = phase;
        Ok(())
    }

    fn fail(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.phase = A27LifecyclePhase::Failed;
        }
    }

    pub(crate) fn record_last_window_close(
        &self,
        sidecars_after_close: usize,
    ) -> Result<(), String> {
        let mut inner = self.inner.lock().map_err(|_| REJECTED.to_string())?;
        if inner.phase != A27LifecyclePhase::AwaitingClose
            || inner.last_window_close_events != 0
            || sidecars_after_close != 0
        {
            inner.phase = A27LifecyclePhase::Failed;
            return Err(REJECTED.into());
        }
        inner.last_window_close_events = 1;
        inner.sidecars_after_close = 0;
        inner.phase = A27LifecyclePhase::AwaitingReopen;
        Ok(())
    }

    pub(crate) fn record_reopen(&self) -> Result<(), String> {
        let mut inner = self.inner.lock().map_err(|_| REJECTED.to_string())?;
        if inner.phase != A27LifecyclePhase::AwaitingReopen || inner.reopen_events != 0 {
            return Ok(());
        }
        inner.reopen_events = 1;
        inner.phase = A27LifecyclePhase::Resuming;
        Ok(())
    }

    pub(crate) fn record_shutdown_failure(&self) {
        self.fail();
    }

    pub(crate) fn record_exit_requested(&self) -> Result<(), String> {
        let mut inner = self.inner.lock().map_err(|_| REJECTED.to_string())?;
        if inner.phase != A27LifecyclePhase::Quitting || inner.exit_requested_observed {
            inner.phase = A27LifecyclePhase::Failed;
            return Err(REJECTED.into());
        }
        inner.exit_requested_observed = true;
        Ok(())
    }

    pub(crate) fn record_exit_and_publish(&self) -> Result<(), String> {
        let evidence = {
            let mut inner = self.inner.lock().map_err(|_| REJECTED.to_string())?;
            if inner.phase != A27LifecyclePhase::Quitting
                || !inner.exit_requested_observed
                || inner.exit_observed
            {
                inner.phase = A27LifecyclePhase::Failed;
                return Err(REJECTED.into());
            }
            inner.exit_observed = true;
            inner.graceful_quit = true;
            evidence_from_inner(&inner)?
        };
        let mut witness = self
            .exit_witness
            .lock()
            .map_err(|_| REJECTED.to_string())?
            .take()
            .ok_or_else(|| REJECTED.to_string())?;
        serde_json::to_writer(&mut witness, &evidence).map_err(|_| REJECTED.to_string())?;
        witness
            .write_all(b"\n")
            .and_then(|()| witness.sync_all())
            .map_err(|_| REJECTED.to_string())
    }

    #[cfg(test)]
    fn for_test(workspace_root: PathBuf) -> Self {
        Self {
            _ownership_lock: None,
            exit_witness: Mutex::new(None),
            workspace_root,
            inner: Mutex::new(A27Inner::default()),
        }
    }
}

fn snapshot_for(phase: A27LifecyclePhase) -> A27LifecycleSnapshot {
    A27LifecycleSnapshot {
        schema_version: 1,
        phase,
        busy: phase.is_busy(),
        message: phase.message(),
    }
}

fn evidence_from_inner(inner: &A27Inner) -> Result<A27NativeEvidence, String> {
    let evidence = A27NativeEvidence {
        schema_version: 1,
        status: "pass",
        last_window_close_events: inner.last_window_close_events,
        reopen_events: inner.reopen_events,
        sidecars_after_close: inner.sidecars_after_close,
        duplicate_start_requests: inner.duplicate_start_requests,
        duplicate_start_unique_pids: inner.duplicate_start_unique_pids,
        duplicate_start_unique_generations: inner.duplicate_start_unique_generations,
        forced_sidecar_deaths: inner.forced_sidecar_deaths,
        automatic_recoveries: inner.automatic_recoveries,
        automatic_recovery_generation_delta: inner.automatic_recovery_generation_delta,
        user_restart_requests: inner.user_restart_requests,
        user_restart_generation_delta: inner.user_restart_generation_delta,
        waiting_approvals_before_death: inner.waiting_approvals_before_death,
        generation_lost_approvals: inner.generation_lost_approvals,
        pending_approvals_after_recovery: inner.pending_approvals_after_recovery,
        stale_approval_replay_rejections: inner.stale_approval_replay_rejections,
        post_death_delegate_executions: inner.post_death_delegate_executions,
        sidecar_generations_observed: [
            inner.first_generation,
            inner.recovered_generation,
            inner.restarted_generation,
            inner.reopened_generation,
        ]
        .into_iter()
        .flatten()
        .count() as u64,
        exit_requested_observed: inner.exit_requested_observed,
        exit_observed: inner.exit_observed,
        graceful_quit: inner.graceful_quit,
    };
    if evidence.last_window_close_events != 1
        || evidence.reopen_events != 1
        || evidence.sidecars_after_close != 0
        || evidence.duplicate_start_requests != 2
        || evidence.duplicate_start_unique_pids != 1
        || evidence.duplicate_start_unique_generations != 1
        || evidence.forced_sidecar_deaths != 1
        || evidence.automatic_recoveries != 1
        || evidence.automatic_recovery_generation_delta != 1
        || evidence.user_restart_requests != 1
        || evidence.user_restart_generation_delta != 1
        || evidence.waiting_approvals_before_death != 1
        || evidence.generation_lost_approvals != 1
        || evidence.pending_approvals_after_recovery != 0
        || evidence.stale_approval_replay_rejections != 1
        || evidence.post_death_delegate_executions != 0
        || evidence.sidecar_generations_observed != 4
        || !evidence.exit_requested_observed
        || !evidence.exit_observed
        || !evidence.graceful_quit
    {
        return Err(REJECTED.into());
    }
    Ok(evidence)
}

#[tauri::command]
pub fn a27_lifecycle_snapshot(
    lifecycle: State<'_, A27LifecycleState>,
) -> Result<A27LifecycleSnapshot, String> {
    lifecycle.snapshot()
}

#[tauri::command]
pub fn a27_observe_duplicate_start(
    state: State<'_, BridgeState>,
    lifecycle: State<'_, A27LifecycleState>,
) -> Result<A27LifecycleSnapshot, String> {
    lifecycle.set_phase(&[A27LifecyclePhase::Ready], A27LifecyclePhase::Starting)?;
    let result = (|| {
        let first = bridge_start_transport(state.inner())?;
        let duplicate = bridge_start_transport(state.inner())?;
        let first_generation = valid_generation(&first)?;
        let first_pid = valid_pid(&first)?;
        let duplicate_generation = valid_generation(&duplicate)?;
        let duplicate_pid = valid_pid(&duplicate)?;
        if first_generation != duplicate_generation || first_pid != duplicate_pid {
            return Err(REJECTED.into());
        }
        let mut inner = lifecycle.inner.lock().map_err(|_| REJECTED.to_string())?;
        if inner.phase != A27LifecyclePhase::Starting {
            return Err(REJECTED.into());
        }
        inner.first_generation = Some(first_generation);
        inner.first_pid = Some(first_pid);
        inner.duplicate_start_requests = 2;
        inner.duplicate_start_unique_pids = 1;
        inner.duplicate_start_unique_generations = 1;
        inner.phase = A27LifecyclePhase::Running;
        Ok(snapshot_for(inner.phase))
    })();
    if result.is_err() {
        lifecycle.fail();
    }
    result
}

#[tauri::command]
pub fn a27_prepare_waiting_approval(
    state: State<'_, BridgeState>,
    lifecycle: State<'_, A27LifecycleState>,
) -> Result<A27LifecycleSnapshot, String> {
    lifecycle.set_phase(
        &[A27LifecyclePhase::Running],
        A27LifecyclePhase::PreparingApproval,
    )?;
    let result = (|| {
        let generation = lifecycle
            .inner
            .lock()
            .map_err(|_| REJECTED.to_string())?
            .first_generation
            .ok_or_else(|| REJECTED.to_string())?;
        let submission =
            register_waiting_approval(state.inner(), &lifecycle.workspace_root, generation)?;
        let mut inner = lifecycle.inner.lock().map_err(|_| REJECTED.to_string())?;
        if inner.phase != A27LifecyclePhase::PreparingApproval {
            return Err(REJECTED.into());
        }
        inner.stale_submission = Some(submission);
        inner.waiting_approvals_before_death = 1;
        inner.phase = A27LifecyclePhase::ApprovalWaiting;
        Ok(snapshot_for(inner.phase))
    })();
    if result.is_err() {
        lifecycle.fail();
    }
    result
}

#[tauri::command]
pub fn a27_force_sidecar_death(
    state: State<'_, BridgeState>,
    lifecycle: State<'_, A27LifecycleState>,
) -> Result<A27LifecycleSnapshot, String> {
    lifecycle.set_phase(
        &[A27LifecyclePhase::ApprovalWaiting],
        A27LifecyclePhase::ForcingSidecarDeath,
    )?;
    let result = (|| {
        let expected = {
            let inner = lifecycle.inner.lock().map_err(|_| REJECTED.to_string())?;
            (
                inner.first_generation.ok_or_else(|| REJECTED.to_string())?,
                inner.first_pid.ok_or_else(|| REJECTED.to_string())?,
            )
        };
        let supervisor = state.supervisor();
        let mut supervisor = supervisor.lock().map_err(|_| REJECTED.to_string())?;
        let status = supervisor.status();
        if valid_generation(&status)? != expected.0 || valid_pid(&status)? != expected.1 {
            return Err(REJECTED.into());
        }
        // `status` was read while the supervisor still owns the unreaped
        // Child. Even if the child exits at this boundary, its PID cannot be
        // recycled before this signal and the later status call reap it.
        let signal_result = unsafe { libc::kill(expected.1 as i32, libc::SIGKILL) };
        if signal_result != 0 {
            return Err(REJECTED.into());
        }
        drop(supervisor);
        let mut inner = lifecycle.inner.lock().map_err(|_| REJECTED.to_string())?;
        inner.forced_sidecar_deaths = 1;
        inner.phase = A27LifecyclePhase::Recovering;
        Ok(snapshot_for(inner.phase))
    })();
    if result.is_err() {
        lifecycle.fail();
    }
    result
}

#[tauri::command]
pub fn a27_recover_after_death(
    state: State<'_, BridgeState>,
    lifecycle: State<'_, A27LifecycleState>,
) -> Result<A27LifecycleSnapshot, String> {
    let phase = lifecycle
        .inner
        .lock()
        .map_err(|_| REJECTED.to_string())?
        .phase;
    if phase != A27LifecyclePhase::Recovering {
        return Err(REJECTED.into());
    }
    let result = recover_after_death(state.inner(), lifecycle.inner());
    if result.is_err() {
        lifecycle.fail();
    }
    result
}

fn recover_after_death(
    state: &BridgeState,
    lifecycle: &A27LifecycleState,
) -> Result<A27LifecycleSnapshot, String> {
    let (old_generation, old_pid) = {
        let inner = lifecycle.inner.lock().map_err(|_| REJECTED.to_string())?;
        (
            inner.first_generation.ok_or_else(|| REJECTED.to_string())?,
            inner.first_pid.ok_or_else(|| REJECTED.to_string())?,
        )
    };
    let deadline = Instant::now() + RECOVERY_DEADLINE;
    let recovered = loop {
        let status = bridge_status_transport(state)?;
        let generation = valid_generation(&status)?;
        let pid = valid_pid(&status)?;
        if generation != old_generation {
            break (generation, pid);
        }
        if Instant::now() >= deadline {
            return Err(REJECTED.into());
        }
        std::thread::sleep(RECOVERY_POLL_INTERVAL);
    };
    if recovered.0.checked_sub(old_generation) != Some(1) || recovered.1 == old_pid {
        return Err(REJECTED.into());
    }

    let registry = state.approval_registry();
    let snapshot = registry.snapshot()?;
    let generation_lost = snapshot
        .records
        .iter()
        .filter(|record| {
            record.state == ApprovalState::Cancelled
                && record.terminal_reason == Some(ApprovalTerminalReason::GenerationLost)
        })
        .count();
    let pending = registry.pending()?.len();
    let stale_submission = lifecycle
        .inner
        .lock()
        .map_err(|_| REJECTED.to_string())?
        .stale_submission
        .take()
        .ok_or_else(|| REJECTED.to_string())?;
    let stale_rejected = matches!(
        registry.submit(stale_submission),
        Err(error) if error == "approval already settled"
    );
    if generation_lost != 1 || pending != 0 || !stale_rejected {
        return Err(REJECTED.into());
    }

    let mut inner = lifecycle.inner.lock().map_err(|_| REJECTED.to_string())?;
    if inner.phase != A27LifecyclePhase::Recovering {
        return Err(REJECTED.into());
    }
    inner.recovered_generation = Some(recovered.0);
    inner.recovered_pid = Some(recovered.1);
    inner.automatic_recoveries = 1;
    inner.automatic_recovery_generation_delta = 1;
    inner.generation_lost_approvals = 1;
    inner.pending_approvals_after_recovery = 0;
    inner.stale_approval_replay_rejections = 1;
    inner.post_death_delegate_executions = 0;
    inner.phase = A27LifecyclePhase::Recovered;
    Ok(snapshot_for(inner.phase))
}

#[tauri::command]
pub fn a27_user_restart(
    state: State<'_, BridgeState>,
    lifecycle: State<'_, A27LifecycleState>,
) -> Result<A27LifecycleSnapshot, String> {
    lifecycle.set_phase(
        &[A27LifecyclePhase::Recovered],
        A27LifecyclePhase::Restarting,
    )?;
    let result = (|| {
        let (previous_generation, previous_pid) = {
            let inner = lifecycle.inner.lock().map_err(|_| REJECTED.to_string())?;
            (
                inner
                    .recovered_generation
                    .ok_or_else(|| REJECTED.to_string())?,
                inner.recovered_pid.ok_or_else(|| REJECTED.to_string())?,
            )
        };
        let restarted = bridge_restart_transport(state.inner())?;
        let generation = valid_generation(&restarted)?;
        let pid = valid_pid(&restarted)?;
        if generation.checked_sub(previous_generation) != Some(1) || pid == previous_pid {
            return Err(REJECTED.into());
        }
        let mut inner = lifecycle.inner.lock().map_err(|_| REJECTED.to_string())?;
        inner.restarted_generation = Some(generation);
        inner.restarted_pid = Some(pid);
        inner.user_restart_requests = 1;
        inner.user_restart_generation_delta = 1;
        inner.phase = A27LifecyclePhase::AwaitingClose;
        Ok(snapshot_for(inner.phase))
    })();
    if result.is_err() {
        lifecycle.fail();
    }
    result
}

#[tauri::command]
pub fn a27_resume_after_reopen(
    state: State<'_, BridgeState>,
    lifecycle: State<'_, A27LifecycleState>,
) -> Result<A27LifecycleSnapshot, String> {
    let phase = lifecycle
        .inner
        .lock()
        .map_err(|_| REJECTED.to_string())?
        .phase;
    if phase == A27LifecyclePhase::ReadyToQuit {
        return lifecycle.snapshot();
    }
    if phase != A27LifecyclePhase::Resuming {
        return Err(REJECTED.into());
    }
    let result = (|| {
        let previous_generation = lifecycle
            .inner
            .lock()
            .map_err(|_| REJECTED.to_string())?
            .restarted_generation
            .ok_or_else(|| REJECTED.to_string())?;
        let reopened = bridge_start_transport(state.inner())?;
        let generation = valid_generation(&reopened)?;
        let pid = valid_pid(&reopened)?;
        if generation.checked_sub(previous_generation) != Some(1) {
            return Err(REJECTED.into());
        }
        let mut inner = lifecycle.inner.lock().map_err(|_| REJECTED.to_string())?;
        if inner.phase != A27LifecyclePhase::Resuming {
            return Err(REJECTED.into());
        }
        inner.reopened_generation = Some(generation);
        inner.reopened_pid = Some(pid);
        inner.phase = A27LifecyclePhase::ReadyToQuit;
        Ok(snapshot_for(inner.phase))
    })();
    if result.is_err() {
        lifecycle.fail();
    }
    result
}

#[tauri::command]
pub fn a27_request_quit(
    app: AppHandle,
    lifecycle: State<'_, A27LifecycleState>,
) -> Result<A27LifecycleSnapshot, String> {
    lifecycle.set_phase(
        &[A27LifecyclePhase::ReadyToQuit],
        A27LifecyclePhase::Quitting,
    )?;
    let snapshot = lifecycle.snapshot()?;
    app.exit(0);
    Ok(snapshot)
}

fn valid_generation(status: &crate::supervisor::SidecarStatus) -> Result<u64, String> {
    if !status.running || status.failed {
        return Err(REJECTED.into());
    }
    status
        .generation
        .filter(|generation| *generation > 0 && *generation <= MAX_JS_SAFE_INTEGER)
        .ok_or_else(|| REJECTED.to_string())
}

fn valid_pid(status: &crate::supervisor::SidecarStatus) -> Result<u32, String> {
    status
        .pid
        .filter(|pid| *pid > 1)
        .ok_or_else(|| REJECTED.to_string())
}

fn register_waiting_approval(
    state: &BridgeState,
    workspace_root: &Path,
    generation: u64,
) -> Result<ApprovalSubmission, String> {
    let workspace_registry = state.workspace_registry();
    let acquired = workspace_registry.acquire_selected_directory(workspace_root)?;
    workspace_registry.inspect_metadata(&acquired.workspace_id)?;
    workspace_registry.open_untrusted(&acquired.workspace_id, acquired.revision)?;
    let (trusted, _) = workspace_registry.authorise(&acquired.workspace_id, acquired.revision)?;
    let input = json!({"fixture": "bounded-read"});
    let input_digest = format!("{:x}", Sha256::digest(canonical_json_bytes(&input)?));
    let request = ApprovalRequest {
        generation,
        correlation_id: format!("sidecar-a27-{}", Uuid::new_v4().simple()),
        session_id: format!("session-{}", Uuid::new_v4().simple()),
        workspace_id: trusted.workspace_id.clone(),
        workspace_revision: trusted.revision,
        invocation_id: format!("invocation-{}", Uuid::new_v4().simple()),
        tool_call_id: None,
        tool_name: "read".into(),
        cohort: None,
        input,
        input_digest,
    };
    let view = workspace_registry.with_approval_binding(
        &trusted.workspace_id,
        trusted.revision,
        |binding| state.approval_registry().register(request, binding),
    )?;
    if view.state != ApprovalState::Awaiting {
        return Err(REJECTED.into());
    }
    Ok(ApprovalSubmission {
        approval_id: view.approval_id,
        decision_id: view.decision_id,
        scope_ids: view
            .scopes
            .into_iter()
            .map(|scope| scope.scope_id)
            .collect(),
        choice: ApprovalChoice::ApproveOnce,
    })
}

fn private_directory_from_environment(variable: &str) -> Result<PathBuf, std::io::Error> {
    let requested =
        PathBuf::from(std::env::var_os(variable).ok_or_else(|| std::io::Error::other(REJECTED))?);
    let canonical =
        std::fs::canonicalize(&requested).map_err(|_| std::io::Error::other(REJECTED))?;
    let metadata = std::fs::metadata(&canonical).map_err(|_| std::io::Error::other(REJECTED))?;
    if !requested.is_absolute()
        || requested != canonical
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(std::io::Error::other(REJECTED));
    }
    Ok(canonical)
}

fn private_new_file_from_environment(variable: &str) -> Result<PathBuf, std::io::Error> {
    let target =
        PathBuf::from(std::env::var_os(variable).ok_or_else(|| std::io::Error::other(REJECTED))?);
    if !target.is_absolute() || target.exists() {
        return Err(std::io::Error::other(REJECTED));
    }
    let parent = target
        .parent()
        .ok_or_else(|| std::io::Error::other(REJECTED))?;
    let canonical_parent =
        std::fs::canonicalize(parent).map_err(|_| std::io::Error::other(REJECTED))?;
    let metadata =
        std::fs::metadata(&canonical_parent).map_err(|_| std::io::Error::other(REJECTED))?;
    if parent != canonical_parent
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(std::io::Error::other(REJECTED));
    }
    Ok(target)
}

fn acquire_inherited_lock(descriptor: RawFd) -> Result<File, String> {
    let descriptor_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if descriptor_flags < 0 {
        return Err(REJECTED.into());
    }
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) } != 0 {
        return Err(REJECTED.into());
    }
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_uid != unsafe { libc::geteuid() }
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o777 != 0o600
    {
        return Err(REJECTED.into());
    }
    if unsafe { libc::flock(descriptor, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(REJECTED.into());
    }
    if unsafe {
        libc::fcntl(
            descriptor,
            libc::F_SETFD,
            descriptor_flags | libc::FD_CLOEXEC,
        )
    } != 0
    {
        let _ = unsafe { libc::flock(descriptor, libc::LOCK_UN) };
        return Err(REJECTED.into());
    }
    let updated_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if updated_flags < 0 || updated_flags & libc::FD_CLOEXEC == 0 {
        let _ = unsafe { libc::flock(descriptor, libc::LOCK_UN) };
        return Err(REJECTED.into());
    }
    // SAFETY: feature-gated process setup transfers sole descriptor-3
    // ownership to this state. The returned File retains the BSD flock and
    // closes the descriptor exactly once.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn validate_private_regular_descriptor(descriptor: RawFd) -> Result<(), String> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) } != 0 {
        return Err(REJECTED.into());
    }
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_uid != unsafe { libc::geteuid() }
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o777 != 0o600
    {
        Err(REJECTED.into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        A27Inner, A27LifecyclePhase, A27LifecycleState, acquire_inherited_lock,
        evidence_from_inner, register_waiting_approval,
    };
    use crate::commands::bridge::BridgeState;
    use crate::domain::approval::{ApprovalState, ApprovalTerminalReason};
    use crate::supervisor::SupervisorPaths;
    use std::fs::{self, OpenOptions};
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::PathBuf;
    use std::process::Command;
    use uuid::Uuid;

    struct FixtureDirectory(PathBuf);

    impl FixtureDirectory {
        fn new(label: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("piui-{label}-{}", Uuid::new_v4().simple()));
            fs::create_dir(&path).expect("fixture directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("fixture permissions");
            Self(path)
        }
    }

    impl Drop for FixtureDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn inert_paths() -> SupervisorPaths {
        SupervisorPaths {
            node: PathBuf::from("unused-node"),
            resource_root: PathBuf::from("unused-resources"),
            entrypoint: PathBuf::from("unused-entrypoint"),
        }
    }

    #[test]
    fn inherited_descriptor_holds_a_bsd_lock_and_is_close_on_exec() {
        let fixture = FixtureDirectory::new("a27-lock");
        let path = fixture.0.join("owner.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC)
            .open(&path)
            .expect("lock file");
        let descriptor = file.into_raw_fd();
        let owner = acquire_inherited_lock(descriptor).expect("inherited lock");
        let flags = unsafe { libc::fcntl(owner.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        let contended = Command::new("/usr/bin/lockf")
            .args(["-s", "-t", "0", "-k"])
            .arg(&path)
            .arg("/usr/bin/true")
            .status()
            .expect("lock contender");
        assert_eq!(contended.code(), Some(75));
        drop(owner);
        let released = Command::new("/usr/bin/lockf")
            .args(["-s", "-t", "0", "-k"])
            .arg(&path)
            .arg("/usr/bin/true")
            .status()
            .expect("released lock contender");
        assert!(released.success());
    }

    #[test]
    fn generation_loss_cancels_one_waiter_and_rejects_its_stale_coordinates() {
        let fixture = FixtureDirectory::new("a27-approval");
        let workspace = fixture.0.join("workspace");
        fs::create_dir(&workspace).expect("workspace");
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))
            .expect("workspace permissions");
        let bridge = BridgeState::new(inert_paths());
        let lifecycle = A27LifecycleState::for_test(workspace.clone());
        let stale = register_waiting_approval(&bridge, &workspace, 1).expect("waiting approval");
        assert_eq!(
            bridge.approval_registry().pending().expect("pending").len(),
            1
        );

        bridge
            .deactivate_generation(1)
            .expect("generation invalidation");
        let snapshot = bridge.approval_registry().snapshot().expect("snapshot");
        assert_eq!(snapshot.records.len(), 1);
        assert_eq!(snapshot.records[0].state, ApprovalState::Cancelled);
        assert_eq!(
            snapshot.records[0].terminal_reason,
            Some(ApprovalTerminalReason::GenerationLost)
        );
        assert!(matches!(
            bridge.approval_registry().submit(stale),
            Err(error) if error == "approval already settled"
        ));
        assert!(
            bridge
                .approval_registry()
                .pending()
                .expect("pending")
                .is_empty()
        );
        drop(lifecycle);
    }

    #[test]
    fn native_success_evidence_requires_the_complete_four_generation_sequence() {
        let mut incomplete = A27Inner::default();
        assert!(evidence_from_inner(&incomplete).is_err());
        incomplete.phase = A27LifecyclePhase::Quitting;
        incomplete.first_generation = Some(1);
        incomplete.recovered_generation = Some(2);
        incomplete.restarted_generation = Some(3);
        incomplete.reopened_generation = Some(4);
        incomplete.last_window_close_events = 1;
        incomplete.reopen_events = 1;
        incomplete.duplicate_start_requests = 2;
        incomplete.duplicate_start_unique_pids = 1;
        incomplete.duplicate_start_unique_generations = 1;
        incomplete.forced_sidecar_deaths = 1;
        incomplete.automatic_recoveries = 1;
        incomplete.automatic_recovery_generation_delta = 1;
        incomplete.user_restart_requests = 1;
        incomplete.user_restart_generation_delta = 1;
        incomplete.waiting_approvals_before_death = 1;
        incomplete.generation_lost_approvals = 1;
        incomplete.stale_approval_replay_rejections = 1;
        incomplete.exit_requested_observed = true;
        incomplete.exit_observed = true;
        incomplete.graceful_quit = true;
        let evidence = evidence_from_inner(&incomplete).expect("complete evidence");
        assert_eq!(evidence.sidecar_generations_observed, 4);
        assert_eq!(evidence.status, "pass");
    }
}
