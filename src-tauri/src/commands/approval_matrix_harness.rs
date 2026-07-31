use super::bridge::{BridgeState, bridge_start_transport, bridge_stop_transport};
use crate::domain::approval::{
    ApprovalChoice, ApprovalGroupSubmission, ApprovalRisk, ApprovalSnapshot, ApprovalState,
    ApprovalSubmission, ApprovalTerminalReason, ApprovalView,
};
use crate::supervisor::{
    NODE_VERSION, PI_VERSION, PROTOCOL_VERSION, SidecarStatus, SupervisorPaths,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

const NODE_ENV: &str = "PIUI_A25_NODE";
const RESOURCES_ENV: &str = "PIUI_A25_RESOURCES";
const CONTROL_ROOT_ENV: &str = "PIUI_A25_CONTROL_ROOT";
const FIXTURE_ENTRY_ENV: &str = "PIUI_A25_FIXTURE_ENTRY";
const ORDINARY_DEADLINE: Duration = Duration::from_secs(15);
const EXPIRY_DEADLINE: Duration = Duration::from_secs(130);

const CASES: [&str; 12] = [
    "routine-individual",
    "routine-group",
    "routine-deny",
    "destructive-individual",
    "destructive-repeat",
    "external-individual",
    "external-repeat",
    "routine-timeout",
    "host-disconnect",
    "transport-cutoff",
    "sidecar-death",
    "stale-replay",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalMatrixHarnessError;

impl fmt::Display for ApprovalMatrixHarnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("approval matrix harness rejected")
    }
}

impl std::error::Error for ApprovalMatrixHarnessError {}

fn rejected<T>() -> Result<T, ApprovalMatrixHarnessError> {
    Err(ApprovalMatrixHarnessError)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalMatrixEvidence {
    schema_version: u8,
    packaged_runtime_validated: bool,
    pi_public_root_sessions: u8,
    pi_prompt_turns: u8,
    approval_requests: u8,
    five_argument_delegate_calls: u8,
    five_argument_violations: u8,
    individual_approve_once_executions: u8,
    eligible_group_members: u8,
    eligible_group_executions: u8,
    deny_case_executions: u8,
    timeout_executions: u8,
    disconnect_executions: u8,
    quit_executions: u8,
    sidecar_death_executions: u8,
    destructive_approve_once_executions: u8,
    destructive_repeat_executions: u8,
    external_approve_once_executions: u8,
    external_repeat_executions: u8,
    ineligible_group_actions_exposed: u8,
    remembered_auto_approvals: u8,
    stale_individual_decision_rejections: u8,
    stale_group_decision_rejections: u8,
    fresh_bridge_state_initial_records: u8,
    fresh_bridge_state_initial_change_sequence: u8,
    fresh_bridge_state_generation_restarted_at_one: bool,
    stale_native_individual_frame_rejections: u8,
    stale_native_group_frame_rejections: u8,
    stale_broker_waiters_remaining: u8,
    stale_broker_generations_aborted: u8,
    replacement_cohort_unchanged_after_replay: bool,
    replacement_cohort_executions: u8,
    production_sidecar_excludes_approval_fixture: bool,
    approved_records: u8,
    denied_records: u8,
    expired_records: u8,
    cancelled_records: u8,
    timed_out_records: u8,
    generation_lost_records: u8,
    sidecar_generations: u8,
    unapproved_delegate_executions: u8,
    witness_inventory_exact: bool,
}

impl ApprovalMatrixEvidence {
    fn accepted() -> Self {
        Self {
            schema_version: 1,
            packaged_runtime_validated: true,
            pi_public_root_sessions: 5,
            pi_prompt_turns: 12,
            approval_requests: 36,
            five_argument_delegate_calls: 6,
            five_argument_violations: 0,
            individual_approve_once_executions: 1,
            eligible_group_members: 3,
            eligible_group_executions: 3,
            deny_case_executions: 0,
            timeout_executions: 0,
            disconnect_executions: 0,
            quit_executions: 0,
            sidecar_death_executions: 0,
            destructive_approve_once_executions: 1,
            destructive_repeat_executions: 0,
            external_approve_once_executions: 1,
            external_repeat_executions: 0,
            ineligible_group_actions_exposed: 0,
            remembered_auto_approvals: 0,
            stale_individual_decision_rejections: 1,
            stale_group_decision_rejections: 1,
            fresh_bridge_state_initial_records: 0,
            fresh_bridge_state_initial_change_sequence: 0,
            fresh_bridge_state_generation_restarted_at_one: true,
            stale_native_individual_frame_rejections: 1,
            stale_native_group_frame_rejections: 1,
            stale_broker_waiters_remaining: 0,
            stale_broker_generations_aborted: 2,
            replacement_cohort_unchanged_after_replay: true,
            replacement_cohort_executions: 0,
            production_sidecar_excludes_approval_fixture: true,
            approved_records: 6,
            denied_records: 18,
            expired_records: 3,
            cancelled_records: 9,
            timed_out_records: 3,
            generation_lost_records: 9,
            sidecar_generations: 5,
            unapproved_delegate_executions: 0,
            witness_inventory_exact: true,
        }
    }
}

struct HarnessEnvironment {
    paths: SupervisorPaths,
    control_root: PathBuf,
    witness_root: PathBuf,
    workspace_root: PathBuf,
}

#[derive(Clone)]
struct IndividualCoordinates {
    approval_id: String,
    decision_id: String,
    scope_id: String,
}

#[derive(Clone)]
struct GroupCoordinates {
    group_id: String,
    decision_id: String,
    scope_id: String,
}

pub fn run_packaged_approval_matrix_harness()
-> Result<ApprovalMatrixEvidence, ApprovalMatrixHarnessError> {
    let environment = HarnessEnvironment::from_process()?;
    let state = BridgeState::new(environment.paths.clone());
    let workspace = prepare_workspace(&state, &environment.workspace_root)?;
    unsafe {
        std::env::set_var(CONTROL_ROOT_ENV, &environment.control_root);
        std::env::set_var("PIUI_A25_WORKSPACE_ID", &workspace.0);
        std::env::set_var("PIUI_A25_WORKSPACE_REVISION", workspace.1.to_string());
    }

    let result = run_matrix(
        &state,
        &environment.paths,
        &environment.workspace_root,
        &environment.witness_root,
    );
    let stopped = bridge_stop_transport(&state).map_err(|_| ApprovalMatrixHarnessError);
    if stopped.is_err() {
        return rejected();
    }
    result
}

impl HarnessEnvironment {
    fn from_process() -> Result<Self, ApprovalMatrixHarnessError> {
        let node = required_path(NODE_ENV)?;
        let resources = required_path(RESOURCES_ENV)?;
        let control_root = required_path(CONTROL_ROOT_ENV)?;
        let fixture_entry = required_path(FIXTURE_ENTRY_ENV)?;
        let mut paths =
            SupervisorPaths::validated(node, resources).map_err(|_| ApprovalMatrixHarnessError)?;
        validate_private_directory(&control_root)?;
        validate_private_fixture(&fixture_entry, &control_root)?;
        paths.entrypoint = fixture_entry;
        validate_plan(&control_root.join("plan.json"))?;
        let witness_root = control_root.join("witness");
        let workspace_root = control_root.join("workspace");
        let agent_root = control_root.join("agent");
        for directory in [&witness_root, &workspace_root, &agent_root] {
            validate_private_directory(directory)?;
        }
        Ok(Self {
            paths,
            control_root,
            witness_root,
            workspace_root,
        })
    }
}

fn validate_private_fixture(
    path: &Path,
    control_root: &Path,
) -> Result<(), ApprovalMatrixHarnessError> {
    let item = fs::symlink_metadata(path).map_err(|_| ApprovalMatrixHarnessError)?;
    if !path.starts_with(control_root)
        || path.file_name().and_then(|name| name.to_str()) != Some("approval-entry.js")
        || item.file_type().is_symlink()
        || !item.is_file()
        || item.nlink() != 1
        || item.uid() != unsafe { libc::geteuid() }
        || item.permissions().mode() & 0o777 != 0o400
        || item.len() < 32
        || item.len() > 65_536
    {
        return rejected();
    }
    Ok(())
}

fn required_path(variable: &str) -> Result<PathBuf, ApprovalMatrixHarnessError> {
    let path = PathBuf::from(std::env::var_os(variable).ok_or(ApprovalMatrixHarnessError)?);
    if !path.is_absolute() {
        return rejected();
    }
    fs::canonicalize(&path)
        .ok()
        .filter(|canonical| canonical == &path)
        .ok_or(ApprovalMatrixHarnessError)
}

fn validate_private_directory(path: &Path) -> Result<(), ApprovalMatrixHarnessError> {
    let item = fs::symlink_metadata(path).map_err(|_| ApprovalMatrixHarnessError)?;
    let canonical = fs::canonicalize(path).map_err(|_| ApprovalMatrixHarnessError)?;
    let opened = fs::metadata(&canonical).map_err(|_| ApprovalMatrixHarnessError)?;
    if path != canonical
        || item.file_type().is_symlink()
        || !opened.is_dir()
        || item.dev() != opened.dev()
        || item.ino() != opened.ino()
        || opened.uid() != unsafe { libc::geteuid() }
        || opened.permissions().mode() & 0o777 != 0o700
    {
        return rejected();
    }
    Ok(())
}

fn validate_plan(path: &Path) -> Result<(), ApprovalMatrixHarnessError> {
    let item = fs::symlink_metadata(path).map_err(|_| ApprovalMatrixHarnessError)?;
    if item.file_type().is_symlink()
        || !item.is_file()
        || item.nlink() != 1
        || item.uid() != unsafe { libc::geteuid() }
        || item.permissions().mode() & 0o777 != 0o400
        || item.len() > 512
    {
        return rejected();
    }
    let bytes = fs::read(path).map_err(|_| ApprovalMatrixHarnessError)?;
    let expected = serde_json::json!({
        "schemaVersion": 1,
        "matrixVersion": "a25-v1",
        "generations": 5,
        "turns": 12,
        "requests": 36,
    });
    let parsed: Value = serde_json::from_slice(&bytes).map_err(|_| ApprovalMatrixHarnessError)?;
    if parsed != expected {
        return rejected();
    }
    Ok(())
}

fn prepare_workspace(
    state: &BridgeState,
    workspace_root: &Path,
) -> Result<(String, u64), ApprovalMatrixHarnessError> {
    let registry = state.workspace_registry();
    let acquired = registry
        .acquire_selected_directory(workspace_root)
        .map_err(|_| ApprovalMatrixHarnessError)?;
    registry
        .inspect_metadata(&acquired.workspace_id)
        .map_err(|_| ApprovalMatrixHarnessError)?;
    let opened = registry
        .open_untrusted(&acquired.workspace_id, acquired.revision)
        .map_err(|_| ApprovalMatrixHarnessError)?;
    let (trusted, _) = registry
        .authorise(&acquired.workspace_id, opened.revision)
        .map_err(|_| ApprovalMatrixHarnessError)?;
    if trusted.revision != 1 {
        return rejected();
    }
    Ok((trusted.workspace_id, trusted.revision))
}

fn run_matrix(
    state: &BridgeState,
    paths: &SupervisorPaths,
    workspace_root: &Path,
    witness_root: &Path,
) -> Result<ApprovalMatrixEvidence, ApprovalMatrixHarnessError> {
    let first = start_generation(state, 1)?;
    if first.pid.is_none() {
        return rejected();
    }
    settle_approve_one(
        state,
        witness_root,
        "routine-individual",
        0,
        ApprovalRisk::Routine,
        0,
    )?;
    settle_group(state, witness_root, "routine-group", 3)?;
    settle_deny(state, witness_root, "routine-deny", 6, None)?;
    settle_approve_one(
        state,
        witness_root,
        "destructive-individual",
        9,
        ApprovalRisk::Destructive,
        1,
    )?;
    settle_deny(
        state,
        witness_root,
        "destructive-repeat",
        12,
        Some(ApprovalRisk::Destructive),
    )?;
    settle_approve_one(
        state,
        witness_root,
        "external-individual",
        15,
        ApprovalRisk::External,
        1,
    )?;
    settle_deny(
        state,
        witness_root,
        "external-repeat",
        18,
        Some(ApprovalRisk::External),
    )?;
    let timeout = wait_case_ready(state, witness_root, "routine-timeout", 21)?;
    if timeout.iter().any(|view| view.group_action.is_none()) {
        return rejected();
    }
    wait_states(state, 21, ApprovalState::Expired, EXPIRY_DEADLINE)?;
    wait_matrix_event(state, 1, 8, 6, false)?;
    bridge_stop_transport(state).map_err(|_| ApprovalMatrixHarnessError)?;

    start_generation(state, 2)?;
    wait_case_ready(state, witness_root, "host-disconnect", 24)?;
    bridge_stop_transport(state).map_err(|_| ApprovalMatrixHarnessError)?;
    wait_states(state, 24, ApprovalState::Cancelled, ORDINARY_DEADLINE)?;

    start_generation(state, 3)?;
    wait_case_ready(state, witness_root, "transport-cutoff", 27)?;
    bridge_stop_transport(state).map_err(|_| ApprovalMatrixHarnessError)?;
    wait_states(state, 27, ApprovalState::Cancelled, ORDINARY_DEADLINE)?;

    let fourth = start_generation(state, 4)?;
    let fourth_records = wait_case_ready(state, witness_root, "sidecar-death", 30)?;
    let stale_individual = individual_coordinates(&fourth_records[0])?;
    let stale_group = group_coordinates(&fourth_records)?;
    let fourth_pid = fourth.pid.ok_or(ApprovalMatrixHarnessError)?;
    if unsafe { libc::kill(fourth_pid as i32, libc::SIGKILL) } != 0 {
        return rejected();
    }
    state
        .deactivate_generation(4)
        .map_err(|_| ApprovalMatrixHarnessError)?;
    bridge_stop_transport(state).map_err(|_| ApprovalMatrixHarnessError)?;
    wait_states(state, 30, ApprovalState::Cancelled, ORDINARY_DEADLINE)?;

    let fresh_state = BridgeState::new(paths.clone());
    let empty = fresh_state
        .approval_registry()
        .snapshot()
        .map_err(|_| ApprovalMatrixHarnessError)?;
    if !empty.records.is_empty() || empty.change_sequence != 0 {
        return rejected();
    }
    let fresh_workspace = prepare_workspace(&fresh_state, workspace_root)?;
    unsafe {
        std::env::set_var("PIUI_A25_WORKSPACE_ID", &fresh_workspace.0);
        std::env::set_var("PIUI_A25_WORKSPACE_REVISION", fresh_workspace.1.to_string());
    }
    let restart_result = (|| {
        start_generation(&fresh_state, 1)?;
        let replacement = wait_case_marker(
            &fresh_state,
            witness_root,
            "stale-replay",
            0,
            "replay-ready",
        )?;
        assert_no_case_delegates(witness_root, "stale-replay")?;
        let replacement_group = group_coordinates(&replacement)?;
        if replacement_group.group_id == stale_group.group_id
            || replacement[0].approval_id == stale_individual.approval_id
        {
            return rejected();
        }
        let before_replay = fresh_state
            .approval_registry()
            .snapshot()
            .map_err(|_| ApprovalMatrixHarnessError)?;
        let before_bytes = stable_snapshot_bytes(&before_replay)?;
        let stale_individual_rejected = fresh_state
            .approval_registry()
            .submit(ApprovalSubmission {
                approval_id: stale_individual.approval_id,
                decision_id: stale_individual.decision_id,
                scope_ids: vec![stale_individual.scope_id],
                choice: ApprovalChoice::ApproveOnce,
            })
            .is_err();
        let stale_group_rejected = fresh_state
            .approval_registry()
            .submit_group(ApprovalGroupSubmission {
                group_id: stale_group.group_id,
                decision_id: stale_group.decision_id,
                scope_id: stale_group.scope_id,
            })
            .is_err();
        if !stale_individual_rejected || !stale_group_rejected {
            return rejected();
        }
        let after_ui_replay = fresh_state
            .approval_registry()
            .snapshot()
            .map_err(|_| ApprovalMatrixHarnessError)?;
        if before_replay.change_sequence != after_ui_replay.change_sequence
            || before_bytes != stable_snapshot_bytes(&after_ui_replay)?
        {
            return rejected();
        }
        create_witness_marker(
            &witness_root.join("case-stale-replay.replay-release"),
            "replay-release\n",
        )?;
        let replacement_after_broker =
            wait_case_ready(&fresh_state, witness_root, "stale-replay", 0)?;
        if replacement_after_broker
            .iter()
            .map(|view| &view.approval_id)
            .ne(replacement.iter().map(|view| &view.approval_id))
            || !marker_exists(witness_root, "stale-replay", "replay-complete")?
        {
            return rejected();
        }
        let after_broker_replay = fresh_state
            .approval_registry()
            .snapshot()
            .map_err(|_| ApprovalMatrixHarnessError)?;
        if before_replay.change_sequence != after_broker_replay.change_sequence
            || before_bytes != stable_snapshot_bytes(&after_broker_replay)?
        {
            return rejected();
        }
        assert_no_case_delegates(witness_root, "stale-replay")?;
        deny_views(&fresh_state, &replacement_after_broker)?;
        wait_states(&fresh_state, 0, ApprovalState::Denied, ORDINARY_DEADLINE)?;
        wait_matrix_event(&fresh_state, 5, 1, 0, true)?;
        Ok(())
    })();
    let fresh_stopped = bridge_stop_transport(&fresh_state).map_err(|_| ApprovalMatrixHarnessError);
    if fresh_stopped.is_err() {
        return rejected();
    }
    restart_result?;

    validate_final_snapshots(state, &fresh_state)?;
    validate_witness_inventory(witness_root)?;
    Ok(ApprovalMatrixEvidence::accepted())
}

fn stable_snapshot_bytes(
    snapshot: &ApprovalSnapshot,
) -> Result<Vec<u8>, ApprovalMatrixHarnessError> {
    let mut value = serde_json::to_value(snapshot).map_err(|_| ApprovalMatrixHarnessError)?;
    let records = value
        .get_mut("records")
        .and_then(Value::as_array_mut)
        .ok_or(ApprovalMatrixHarnessError)?;
    for record in records {
        record
            .as_object_mut()
            .ok_or(ApprovalMatrixHarnessError)?
            .remove("expiresInMs")
            .ok_or(ApprovalMatrixHarnessError)?;
    }
    serde_json::to_vec(&value).map_err(|_| ApprovalMatrixHarnessError)
}

fn start_generation(
    state: &BridgeState,
    expected_generation: u64,
) -> Result<SidecarStatus, ApprovalMatrixHarnessError> {
    let status = bridge_start_transport(state).map_err(|_| ApprovalMatrixHarnessError)?;
    if !status.running
        || status.failed
        || status.generation != Some(expected_generation)
        || status.protocol_version != Some(PROTOCOL_VERSION)
        || status.node_version.as_deref() != Some(NODE_VERSION)
        || status.pi_version.as_deref() != Some(PI_VERSION)
    {
        return rejected();
    }
    Ok(status)
}

fn wait_case_ready(
    state: &BridgeState,
    witness_root: &Path,
    case_id: &str,
    offset: usize,
) -> Result<Vec<ApprovalView>, ApprovalMatrixHarnessError> {
    wait_case_marker(state, witness_root, case_id, offset, "ready")
}

fn wait_case_marker(
    state: &BridgeState,
    witness_root: &Path,
    case_id: &str,
    offset: usize,
    suffix: &str,
) -> Result<Vec<ApprovalView>, ApprovalMatrixHarnessError> {
    let deadline = Instant::now() + ORDINARY_DEADLINE;
    loop {
        let snapshot = state
            .approval_registry()
            .snapshot()
            .map_err(|_| ApprovalMatrixHarnessError)?;
        if snapshot.records.len() == offset + 3 && marker_exists(witness_root, case_id, suffix)? {
            let records = snapshot.records[offset..].to_vec();
            if records.len() == 3
                && records
                    .iter()
                    .all(|record| record.state == ApprovalState::Awaiting)
            {
                return Ok(records);
            }
            return rejected();
        }
        if snapshot.records.len() > offset + 3 || Instant::now() >= deadline {
            return rejected();
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn create_witness_marker(path: &Path, body: &str) -> Result<(), ApprovalMatrixHarnessError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path).map_err(|_| ApprovalMatrixHarnessError)?;
    file.write_all(body.as_bytes())
        .and_then(|()| file.sync_data())
        .map_err(|_| ApprovalMatrixHarnessError)
}

fn assert_no_case_delegates(
    witness_root: &Path,
    case_id: &str,
) -> Result<(), ApprovalMatrixHarnessError> {
    let prefix = format!("delegate-{case_id}-");
    for entry in fs::read_dir(witness_root).map_err(|_| ApprovalMatrixHarnessError)? {
        let name = entry
            .map_err(|_| ApprovalMatrixHarnessError)?
            .file_name()
            .into_string()
            .map_err(|_| ApprovalMatrixHarnessError)?;
        if name.starts_with(&prefix) {
            return rejected();
        }
    }
    Ok(())
}

fn marker_exists(
    witness_root: &Path,
    case_id: &str,
    suffix: &str,
) -> Result<bool, ApprovalMatrixHarnessError> {
    let path = witness_root.join(format!("case-{case_id}.{suffix}"));
    let item = match fs::symlink_metadata(&path) {
        Ok(item) => item,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return rejected(),
    };
    let expected = format!("{suffix}\n");
    if item.file_type().is_symlink()
        || !item.is_file()
        || item.nlink() != 1
        || item.uid() != unsafe { libc::geteuid() }
        || item.permissions().mode() & 0o777 != 0o600
        || fs::read(&path).map_err(|_| ApprovalMatrixHarnessError)? != expected.as_bytes()
    {
        return rejected();
    }
    Ok(true)
}

fn settle_approve_one(
    state: &BridgeState,
    witness_root: &Path,
    case_id: &str,
    offset: usize,
    approved_risk: ApprovalRisk,
    approved_member: usize,
) -> Result<(), ApprovalMatrixHarnessError> {
    let views = wait_case_ready(state, witness_root, case_id, offset)?;
    if views
        .iter()
        .filter(|view| view.risk == approved_risk)
        .count()
        != 1
        && approved_risk != ApprovalRisk::Routine
    {
        return rejected();
    }
    if views
        .iter()
        .any(|view| !matches!(view.risk, ApprovalRisk::Routine) && view.group_action.is_some())
    {
        return rejected();
    }
    let approved_index = if approved_risk == ApprovalRisk::Routine {
        approved_member
    } else {
        views
            .iter()
            .position(|view| view.risk == approved_risk)
            .ok_or(ApprovalMatrixHarnessError)?
    };
    let coordinates = individual_coordinates(&views[approved_index])?;
    for (index, view) in views.iter().enumerate() {
        submit_view(state, view, index == approved_index)?;
    }
    wait_mixed_terminal(state, offset, approved_index)?;
    state
        .approval_registry()
        .submit(ApprovalSubmission {
            approval_id: coordinates.approval_id,
            decision_id: coordinates.decision_id,
            scope_ids: vec![coordinates.scope_id],
            choice: ApprovalChoice::ApproveOnce,
        })
        .map_err(|_| ApprovalMatrixHarnessError)
}

fn settle_group(
    state: &BridgeState,
    witness_root: &Path,
    case_id: &str,
    offset: usize,
) -> Result<(), ApprovalMatrixHarnessError> {
    let views = wait_case_ready(state, witness_root, case_id, offset)?;
    let coordinates = group_coordinates(&views)?;
    submit_group(state, &coordinates)?;
    wait_states(state, offset, ApprovalState::Approved, ORDINARY_DEADLINE)?;
    submit_group(state, &coordinates)
}

fn settle_deny(
    state: &BridgeState,
    witness_root: &Path,
    case_id: &str,
    offset: usize,
    prohibited_group_risk: Option<ApprovalRisk>,
) -> Result<(), ApprovalMatrixHarnessError> {
    let views = wait_case_ready(state, witness_root, case_id, offset)?;
    if let Some(risk) = prohibited_group_risk {
        if views.iter().filter(|view| view.risk == risk).count() != 1
            || views.iter().any(|view| view.group_action.is_some())
        {
            return rejected();
        }
    }
    deny_views(state, &views)?;
    wait_states(state, offset, ApprovalState::Denied, ORDINARY_DEADLINE)
}

fn submit_view(
    state: &BridgeState,
    view: &ApprovalView,
    approve: bool,
) -> Result<(), ApprovalMatrixHarnessError> {
    let scopes = if approve {
        vec![
            view.scopes
                .first()
                .ok_or(ApprovalMatrixHarnessError)?
                .scope_id
                .clone(),
        ]
    } else {
        Vec::new()
    };
    state
        .approval_registry()
        .submit(ApprovalSubmission {
            approval_id: view.approval_id.clone(),
            decision_id: view.decision_id.clone(),
            scope_ids: scopes,
            choice: if approve {
                ApprovalChoice::ApproveOnce
            } else {
                ApprovalChoice::Deny
            },
        })
        .map_err(|_| ApprovalMatrixHarnessError)
}

fn deny_views(
    state: &BridgeState,
    views: &[ApprovalView],
) -> Result<(), ApprovalMatrixHarnessError> {
    for view in views {
        submit_view(state, view, false)?;
    }
    Ok(())
}

fn individual_coordinates(
    view: &ApprovalView,
) -> Result<IndividualCoordinates, ApprovalMatrixHarnessError> {
    Ok(IndividualCoordinates {
        approval_id: view.approval_id.clone(),
        decision_id: view.decision_id.clone(),
        scope_id: view
            .scopes
            .first()
            .ok_or(ApprovalMatrixHarnessError)?
            .scope_id
            .clone(),
    })
}

fn group_coordinates(
    views: &[ApprovalView],
) -> Result<GroupCoordinates, ApprovalMatrixHarnessError> {
    let action = views
        .first()
        .and_then(|view| view.group_action.as_ref())
        .ok_or(ApprovalMatrixHarnessError)?;
    if views.iter().any(|view| {
        view.group_action
            .as_ref()
            .is_none_or(|candidate| candidate.group_id != action.group_id)
    }) {
        return rejected();
    }
    Ok(GroupCoordinates {
        group_id: action.group_id.clone(),
        decision_id: action.decision_id.clone(),
        scope_id: action.scope_id.clone(),
    })
}

fn submit_group(
    state: &BridgeState,
    coordinates: &GroupCoordinates,
) -> Result<(), ApprovalMatrixHarnessError> {
    state
        .approval_registry()
        .submit_group(ApprovalGroupSubmission {
            group_id: coordinates.group_id.clone(),
            decision_id: coordinates.decision_id.clone(),
            scope_id: coordinates.scope_id.clone(),
        })
        .map_err(|_| ApprovalMatrixHarnessError)
}

fn wait_states(
    state: &BridgeState,
    offset: usize,
    expected: ApprovalState,
    timeout: Duration,
) -> Result<(), ApprovalMatrixHarnessError> {
    let deadline = Instant::now() + timeout;
    loop {
        let snapshot = state
            .approval_registry()
            .snapshot()
            .map_err(|_| ApprovalMatrixHarnessError)?;
        if snapshot.records.len() == offset + 3 {
            let records = &snapshot.records[offset..];
            if records.iter().all(|record| record.state == expected) {
                return Ok(());
            }
            if records.iter().any(|record| {
                matches!(
                    record.state,
                    ApprovalState::Approved
                        | ApprovalState::Denied
                        | ApprovalState::Expired
                        | ApprovalState::Cancelled
                ) && record.state != expected
            }) {
                return rejected();
            }
        }
        if snapshot.records.len() > offset + 3 || Instant::now() >= deadline {
            return rejected();
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_mixed_terminal(
    state: &BridgeState,
    offset: usize,
    approved_index: usize,
) -> Result<(), ApprovalMatrixHarnessError> {
    let deadline = Instant::now() + ORDINARY_DEADLINE;
    loop {
        let snapshot = state
            .approval_registry()
            .snapshot()
            .map_err(|_| ApprovalMatrixHarnessError)?;
        if snapshot.records.len() == offset + 3 {
            let records = &snapshot.records[offset..];
            if records.iter().enumerate().all(|(index, record)| {
                record.state
                    == if index == approved_index {
                        ApprovalState::Approved
                    } else {
                        ApprovalState::Denied
                    }
            }) {
                return Ok(());
            }
        }
        if snapshot.records.len() > offset + 3 || Instant::now() >= deadline {
            return rejected();
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_matrix_event(
    state: &BridgeState,
    generation: u64,
    turns: u64,
    delegate_calls: u64,
    replayed_native_frames: bool,
) -> Result<(), ApprovalMatrixHarnessError> {
    let deadline = Instant::now() + ORDINARY_DEADLINE;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return rejected();
        }
        let envelope = state
            .supervisor()
            .lock()
            .map_err(|_| ApprovalMatrixHarnessError)?
            .receive_envelope(remaining.min(Duration::from_millis(100)));
        let Ok(envelope) = envelope else {
            continue;
        };
        let expected_keys = [
            "schemaVersion",
            "eventType",
            "generation",
            "turns",
            "delegateCalls",
            "fiveArgumentViolations",
            "staleNativeIndividualFrameRejections",
            "staleNativeGroupFrameRejections",
            "staleBrokerWaitersRemaining",
            "staleBrokerGenerationsAborted",
        ];
        if envelope.payload.len() == expected_keys.len()
            && expected_keys
                .iter()
                .all(|key| envelope.payload.contains_key(*key))
            && envelope.payload.get("schemaVersion") == Some(&Value::from(1))
            && envelope.payload.get("eventType")
                == Some(&Value::String("approval-matrix.complete".into()))
            && envelope.payload.get("generation") == Some(&Value::from(generation))
            && envelope.payload.get("turns") == Some(&Value::from(turns))
            && envelope.payload.get("delegateCalls") == Some(&Value::from(delegate_calls))
            && envelope.payload.get("fiveArgumentViolations") == Some(&Value::from(0))
            && envelope.payload.get("staleNativeIndividualFrameRejections")
                == Some(&Value::from(u8::from(replayed_native_frames)))
            && envelope.payload.get("staleNativeGroupFrameRejections")
                == Some(&Value::from(u8::from(replayed_native_frames)))
            && envelope.payload.get("staleBrokerWaitersRemaining") == Some(&Value::from(0))
            && envelope.payload.get("staleBrokerGenerationsAborted")
                == Some(&Value::from(if replayed_native_frames { 2 } else { 0 }))
        {
            return Ok(());
        }
        return rejected();
    }
}

fn validate_final_snapshots(
    first: &BridgeState,
    replacement: &BridgeState,
) -> Result<(), ApprovalMatrixHarnessError> {
    let first_snapshot = first
        .approval_registry()
        .snapshot()
        .map_err(|_| ApprovalMatrixHarnessError)?;
    let replacement_snapshot = replacement
        .approval_registry()
        .snapshot()
        .map_err(|_| ApprovalMatrixHarnessError)?;
    if first_snapshot.records.len() != 33 || replacement_snapshot.records.len() != 3 {
        return rejected();
    }
    let mut states = BTreeMap::new();
    let mut reasons = BTreeMap::new();
    for view in first_snapshot
        .records
        .into_iter()
        .chain(replacement_snapshot.records)
    {
        *states.entry(format!("{:?}", view.state)).or_insert(0usize) += 1;
        if let Some(reason) = view.terminal_reason {
            *reasons.entry(format!("{:?}", reason)).or_insert(0usize) += 1;
        }
    }
    if states.get("Approved") != Some(&6)
        || states.get("Denied") != Some(&18)
        || states.get("Expired") != Some(&3)
        || states.get("Cancelled") != Some(&9)
        || reasons.get(&format!("{:?}", ApprovalTerminalReason::TimedOut)) != Some(&3)
        || reasons.get(&format!("{:?}", ApprovalTerminalReason::GenerationLost)) != Some(&9)
    {
        return rejected();
    }
    Ok(())
}

fn validate_witness_inventory(witness_root: &Path) -> Result<(), ApprovalMatrixHarnessError> {
    let mut expected = BTreeSet::new();
    for case_id in CASES {
        expected.insert(format!("case-{case_id}.started"));
        expected.insert(format!("case-{case_id}.ready"));
    }
    for generation in 1..=5 {
        expected.insert(format!("session-generation-{generation}.created"));
    }
    for suffix in ["replay-ready", "replay-release", "replay-complete"] {
        expected.insert(format!("case-stale-replay.{suffix}"));
    }
    expected.insert("native-old-individual.frame".to_string());
    expected.insert("native-old-group.frame".to_string());
    for (case_id, members) in [
        ("routine-individual", &[0usize][..]),
        ("routine-group", &[0usize, 1, 2][..]),
        ("destructive-individual", &[1usize][..]),
        ("external-individual", &[1usize][..]),
    ] {
        for member in members {
            expected.insert(format!("delegate-{case_id}-{member}.called"));
        }
    }
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(witness_root).map_err(|_| ApprovalMatrixHarnessError)? {
        let entry = entry.map_err(|_| ApprovalMatrixHarnessError)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ApprovalMatrixHarnessError)?;
        let item = fs::symlink_metadata(entry.path()).map_err(|_| ApprovalMatrixHarnessError)?;
        if item.file_type().is_symlink()
            || !item.is_file()
            || item.nlink() != 1
            || item.uid() != unsafe { libc::geteuid() }
            || item.permissions().mode() & 0o777 != 0o600
        {
            return rejected();
        }
        let bytes = fs::read(entry.path()).map_err(|_| ApprovalMatrixHarnessError)?;
        if name.ends_with(".frame") {
            if bytes.len() < 3
                || bytes.len() > 65_536
                || bytes.last() != Some(&b'\n')
                || bytes.contains(&b'\r')
            {
                return rejected();
            }
            let envelope: Value = serde_json::from_slice(&bytes[..bytes.len() - 1])
                .map_err(|_| ApprovalMatrixHarnessError)?;
            let expected_method = if name == "native-old-individual.frame" {
                "approval.resolve"
            } else if name == "native-old-group.frame" {
                "approval.group-commit"
            } else {
                return rejected();
            };
            if envelope.get("kind") != Some(&Value::String("host-response".into()))
                || envelope
                    .get("payload")
                    .and_then(|payload| payload.get("method"))
                    != Some(&Value::String(expected_method.into()))
            {
                return rejected();
            }
        } else {
            let body = if name.ends_with(".started") {
                b"started\n".to_vec()
            } else if name.ends_with(".ready") {
                b"ready\n".to_vec()
            } else if name.ends_with(".created") {
                b"created\n".to_vec()
            } else if name.ends_with(".called") {
                b"called\n".to_vec()
            } else if let Some(suffix) = name.split('.').next_back() {
                format!("{suffix}\n").into_bytes()
            } else {
                return rejected();
            };
            if bytes != body {
                return rejected();
            }
        }
        actual.insert(name);
    }
    if actual != expected {
        return rejected();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ApprovalMatrixEvidence;

    #[test]
    fn accepted_evidence_is_fixed_and_path_free() {
        let encoded = serde_json::to_value(ApprovalMatrixEvidence::accepted()).unwrap();
        let object = encoded.as_object().unwrap();
        assert_eq!(object.len(), 42);
        assert!(
            object
                .values()
                .all(|value| value.is_boolean() || value.is_number())
        );
        assert!(!encoded.to_string().contains('/'));
    }
}
