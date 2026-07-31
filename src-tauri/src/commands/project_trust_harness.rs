use super::bridge::{
    BridgeState, bridge_restart_transport, bridge_start_transport, bridge_stop_transport,
};
use super::workspace::{
    acquire_selected_directory, authorise_workspace, inspect_workspace, load_trusted_workspace,
    open_workspace_untrusted, revoke_workspace,
};
use crate::domain::approval::{
    ApprovalRequest, ApprovalSnapshot, ApprovalState, ApprovalTerminalReason, ApprovalView,
};
use crate::domain::workspace::{
    MetadataKind, PublicResourceState, ResourceCounts, TrustState, WorkspaceMetadata,
};
use crate::protocol::approval::canonical_json_bytes;
use crate::supervisor::{
    NODE_VERSION, PI_VERSION, PROTOCOL_VERSION, SidecarStatus, SupervisorPaths,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

const NODE_ENV: &str = "PIUI_A24_NODE";
const RESOURCES_ENV: &str = "PIUI_A24_RESOURCES";
const FIXTURE_ENV: &str = "PIUI_A24_FIXTURE";
const REPLAY_COUNT: usize = 16;
const MAX_INVENTORY_ENTRIES: usize = 64;
const MAX_INVENTORY_BYTES: u64 = 1024 * 1024;
const MAX_INVENTORY_DEPTH: usize = 8;
const CONSERVATIVE_COUNTS: ResourceCounts = ResourceCounts {
    extensions: 0,
    skills: 0,
    prompts: 0,
    themes: 0,
    packages: 0,
    truncated: true,
};

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut c_void;
    fn acl_free(object: *mut c_void) -> libc::c_int;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectTrustHarnessError;

impl fmt::Display for ProjectTrustHarnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("project trust harness rejected")
    }
}

impl std::error::Error for ProjectTrustHarnessError {}

fn rejected<T>() -> Result<T, ProjectTrustHarnessError> {
    Err(ProjectTrustHarnessError)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectTrustEvidence {
    schema_version: u8,
    packaged_runtime_validated: bool,
    metadata_inspections: u8,
    untrusted_load_rejections: u8,
    project_trust_authorisations: u8,
    sentinel_workspace_authorisations: u8,
    authorise_executions: u8,
    sidecar_generation_restarted: bool,
    sidecar_generation_restarts: u8,
    trusted_load_executions: u8,
    marker_bytes: u8,
    marker_lines: u8,
    concurrent_replay_requests: u8,
    cached_replay_results: u8,
    skill_canary_executions: u8,
    package_canary_executions: u8,
    settings_canary_loads: u8,
    ancestor_canary_loads: u8,
    project_trust_approval_policy_mutations: u8,
    approval_records_before_trust: u8,
    approval_records_after_trust: u8,
    remembered_approval_scopes: u8,
    group_approval_scopes: u8,
    blanket_approval_scopes: u8,
    approval_sentinel_unchanged_through_trusted_load: bool,
    revocations: u8,
    post_revoke_load_rejections: u8,
    stale_generation_rejections: u8,
    stale_revision_rejections: u8,
    stale_lease_rejections: u8,
    source_marker_executions: u8,
    fixture_inventory_unchanged: bool,
}

impl ProjectTrustEvidence {
    fn accepted() -> Self {
        Self {
            schema_version: 1,
            packaged_runtime_validated: true,
            metadata_inspections: 1,
            untrusted_load_rejections: 1,
            project_trust_authorisations: 1,
            sentinel_workspace_authorisations: 1,
            authorise_executions: 0,
            sidecar_generation_restarted: true,
            sidecar_generation_restarts: 2,
            trusted_load_executions: 1,
            marker_bytes: 9,
            marker_lines: 1,
            concurrent_replay_requests: REPLAY_COUNT as u8,
            cached_replay_results: REPLAY_COUNT as u8,
            skill_canary_executions: 0,
            package_canary_executions: 0,
            settings_canary_loads: 0,
            ancestor_canary_loads: 0,
            project_trust_approval_policy_mutations: 0,
            approval_records_before_trust: 0,
            approval_records_after_trust: 0,
            remembered_approval_scopes: 0,
            group_approval_scopes: 0,
            blanket_approval_scopes: 0,
            approval_sentinel_unchanged_through_trusted_load: true,
            revocations: 1,
            post_revoke_load_rejections: 1,
            stale_generation_rejections: 1,
            stale_revision_rejections: 1,
            stale_lease_rejections: 1,
            source_marker_executions: 0,
            fixture_inventory_unchanged: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FixtureInventory {
    digest: [u8; 32],
    entries: usize,
    bytes: u64,
}

struct InventoryBudget {
    entries: usize,
    bytes: u64,
}

struct SentinelDirectory {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SentinelDirectory {
    fn create(fixture: &Path) -> Result<Self, ProjectTrustHarnessError> {
        let parent = fixture.parent().ok_or(ProjectTrustHarnessError)?;
        validate_private_directory(parent)?;
        let path = parent.join(format!(
            ".piui-a24-approval-sentinel-{}",
            Uuid::new_v4().simple()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| ProjectTrustHarnessError)?;
        let metadata = fs::symlink_metadata(&path).map_err(|_| ProjectTrustHarnessError)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::getuid() }
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return rejected();
        }
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn remove(self) -> Result<(), ProjectTrustHarnessError> {
        let metadata = fs::symlink_metadata(&self.path).map_err(|_| ProjectTrustHarnessError)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || fs::read_dir(&self.path)
                .map_err(|_| ProjectTrustHarnessError)?
                .next()
                .is_some()
        {
            return rejected();
        }
        fs::remove_dir(&self.path).map_err(|_| ProjectTrustHarnessError)
    }
}

/// Executes the non-WebView A.24 native orchestration against exact paths from
/// the fixed environment contract. All externally visible failures are generic.
pub fn run_packaged_project_trust_harness() -> Result<ProjectTrustEvidence, ProjectTrustHarnessError>
{
    let node = required_environment_path(NODE_ENV)?;
    let resources = required_environment_path(RESOURCES_ENV)?;
    let fixture = required_environment_path(FIXTURE_ENV)?;
    let paths =
        SupervisorPaths::validated(node, resources).map_err(|_| ProjectTrustHarnessError)?;
    let fixture = validate_fixture_root(&fixture)?;
    let before = inventory_fixture(&fixture)?;
    source_markers_absent(&fixture)?;
    let sentinel = SentinelDirectory::create(&fixture)?;
    let state = BridgeState::new(paths);

    let probe = run_probe(&state, &fixture, &sentinel.path, &before);
    let stopped = bridge_stop_transport(&state).map_err(|_| ProjectTrustHarnessError);
    drop(state);
    let removed = sentinel.remove();

    if stopped.is_err() || removed.is_err() {
        return rejected();
    }
    probe
}

fn run_probe(
    state: &BridgeState,
    fixture: &Path,
    sentinel_root: &Path,
    before: &FixtureInventory,
) -> Result<ProjectTrustEvidence, ProjectTrustHarnessError> {
    let first_status = bridge_start_transport(state).map_err(|_| ProjectTrustHarnessError)?;
    let first_generation = authenticated_generation(&first_status)?;

    let acquired =
        acquire_selected_directory(state, fixture).map_err(|_| ProjectTrustHarnessError)?;
    let inspected =
        inspect_workspace(state, &acquired.workspace_id).map_err(|_| ProjectTrustHarnessError)?;
    validate_hostile_metadata(inspected.metadata.as_ref())?;
    let opened = open_workspace_untrusted(state, &acquired.workspace_id, acquired.revision)
        .map_err(|_| ProjectTrustHarnessError)?;
    if opened.trust_state != TrustState::Untrusted
        || load_trusted_workspace(state, &acquired.workspace_id, opened.revision).is_ok()
        || !state
            .workspace_registry()
            .snapshot_is_absent(&acquired.workspace_id)
            .map_err(|_| ProjectTrustHarnessError)?
    {
        return rejected();
    }
    source_markers_absent(fixture)?;

    let approval_before = state
        .approval_registry()
        .snapshot()
        .map_err(|_| ProjectTrustHarnessError)?;
    validate_empty_approval_policy(&approval_before)?;
    let stable_before = stable_approval_snapshot(&approval_before)?;

    let trusted = authorise_workspace(state, &acquired.workspace_id, opened.revision)
        .map_err(|_| ProjectTrustHarnessError)?;
    if trusted.revision != 1
        || trusted.trust_state != TrustState::Trusted
        || !state
            .workspace_registry()
            .snapshot_is_absent(&acquired.workspace_id)
            .map_err(|_| ProjectTrustHarnessError)?
    {
        return rejected();
    }
    source_markers_absent(fixture)?;
    let approval_after = state
        .approval_registry()
        .snapshot()
        .map_err(|_| ProjectTrustHarnessError)?;
    validate_empty_approval_policy(&approval_after)?;
    if stable_approval_snapshot(&approval_after)? != stable_before {
        return rejected();
    }
    let stale_binding = state
        .workspace_registry()
        .with_approval_binding(&acquired.workspace_id, trusted.revision, Ok)
        .map_err(|_| ProjectTrustHarnessError)?;

    let restarted = bridge_restart_transport(state).map_err(|_| ProjectTrustHarnessError)?;
    let trusted_generation = authenticated_generation(&restarted)?;
    if trusted_generation == first_generation {
        return rejected();
    }

    let sentinel_summary = acquire_selected_directory(state, sentinel_root)
        .and_then(|summary| {
            inspect_workspace(state, &summary.workspace_id)?;
            open_workspace_untrusted(state, &summary.workspace_id, summary.revision)
        })
        .and_then(|summary| authorise_workspace(state, &summary.workspace_id, summary.revision))
        .map_err(|_| ProjectTrustHarnessError)?;
    if sentinel_summary.revision != 1
        || sentinel_summary.trust_state != TrustState::Trusted
        || !state
            .workspace_registry()
            .snapshot_is_absent(&sentinel_summary.workspace_id)
            .map_err(|_| ProjectTrustHarnessError)?
    {
        return rejected();
    }
    let sentinel_view =
        register_approval_sentinel(state, &sentinel_summary.workspace_id, trusted_generation)?;
    let sentinel_before = state
        .approval_registry()
        .snapshot()
        .map_err(|_| ProjectTrustHarnessError)?;
    validate_approval_policy(&sentinel_before, &sentinel_view.approval_id)?;
    let expected_generation_loss_sequence = sentinel_before
        .change_sequence
        .checked_add(1)
        .ok_or(ProjectTrustHarnessError)?;
    let stable_approval_policy_before = stable_approval_snapshot(&sentinel_before)?;

    let loaded = load_trusted_workspace(state, &acquired.workspace_id, trusted.revision)
        .map_err(|_| ProjectTrustHarnessError)?;
    if loaded.resource_state != PublicResourceState::Loaded
        || loaded.counts != Some(CONSERVATIVE_COUNTS)
    {
        return rejected();
    }
    let observation = state
        .workspace_registry()
        .snapshot_probe_observation(&acquired.workspace_id)
        .map_err(|_| ProjectTrustHarnessError)?;
    validate_snapshot_observation(&observation)?;
    source_markers_absent(fixture)?;

    let replays = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..REPLAY_COUNT)
            .map(|_| {
                scope.spawn(|| {
                    load_trusted_workspace(state, &acquired.workspace_id, trusted.revision)
                        .is_ok_and(|summary| {
                            summary.resource_state == PublicResourceState::Loaded
                                && summary.counts == Some(CONSERVATIVE_COUNTS)
                        })
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap_or(false))
            .collect::<Vec<_>>()
    });
    if replays.len() != REPLAY_COUNT || replays.iter().any(|accepted| !accepted) {
        return rejected();
    }
    let after_replays = state
        .workspace_registry()
        .snapshot_probe_observation(&acquired.workspace_id)
        .map_err(|_| ProjectTrustHarnessError)?;
    validate_snapshot_observation(&after_replays)?;
    let sentinel_after = state
        .approval_registry()
        .snapshot()
        .map_err(|_| ProjectTrustHarnessError)?;
    validate_approval_policy(&sentinel_after, &sentinel_view.approval_id)?;
    if stable_approval_snapshot(&sentinel_after)? != stable_approval_policy_before {
        return rejected();
    }

    let stale_generation_rejected = state
        .workspace_registry()
        .begin_load(&acquired.workspace_id, trusted.revision, first_generation)
        .is_err();
    let stale_revision_rejected = state
        .workspace_registry()
        .begin_load(&acquired.workspace_id, opened.revision, trusted_generation)
        .is_err();
    if !stale_generation_rejected || !stale_revision_rejected {
        return rejected();
    }

    let revoked = revoke_workspace(state, &acquired.workspace_id, trusted.revision)
        .map_err(|_| ProjectTrustHarnessError)?;
    if revoked.revision != 2
        || revoked.trust_state != TrustState::Revoked
        || !state
            .workspace_registry()
            .snapshot_is_absent(&acquired.workspace_id)
            .map_err(|_| ProjectTrustHarnessError)?
    {
        return rejected();
    }
    let post_revoke = bridge_start_transport(state).map_err(|_| ProjectTrustHarnessError)?;
    let post_revoke_generation = authenticated_generation(&post_revoke)?;
    if post_revoke_generation == trusted_generation {
        return rejected();
    }
    let generation_loss = state
        .approval_registry()
        .snapshot()
        .map_err(|_| ProjectTrustHarnessError)?;
    validate_generation_loss_policy(
        &generation_loss,
        &sentinel_view,
        expected_generation_loss_sequence,
    )?;
    let stable_generation_loss = stable_approval_snapshot(&generation_loss)?;
    if load_trusted_workspace(state, &acquired.workspace_id, revoked.revision).is_ok() {
        return rejected();
    }
    let stale_operation_ran = AtomicBool::new(false);
    let stale_lease_rejected = state
        .workspace_registry()
        .with_valid_approval_binding(&stale_binding, || {
            stale_operation_ran.store(true, Ordering::SeqCst);
            Ok(())
        })
        .is_err();
    if !stale_lease_rejected
        || stale_operation_ran.load(Ordering::SeqCst)
        || !state
            .workspace_registry()
            .snapshot_is_absent(&acquired.workspace_id)
            .map_err(|_| ProjectTrustHarnessError)?
    {
        return rejected();
    }
    let sentinel_final = state
        .approval_registry()
        .snapshot()
        .map_err(|_| ProjectTrustHarnessError)?;
    validate_generation_loss_policy(
        &sentinel_final,
        &sentinel_view,
        expected_generation_loss_sequence,
    )?;
    if stable_approval_snapshot(&sentinel_final)? != stable_generation_loss {
        return rejected();
    }

    source_markers_absent(fixture)?;
    let after = inventory_fixture(fixture)?;
    if &after != before {
        return rejected();
    }
    Ok(ProjectTrustEvidence::accepted())
}

fn required_environment_path(name: &str) -> Result<PathBuf, ProjectTrustHarnessError> {
    let value = std::env::var_os(name).ok_or(ProjectTrustHarnessError)?;
    if value.as_bytes().is_empty() {
        return rejected();
    }
    Ok(PathBuf::from(value))
}

fn authenticated_generation(status: &SidecarStatus) -> Result<u64, ProjectTrustHarnessError> {
    if !status.running
        || status.failed
        || status.protocol_version != Some(PROTOCOL_VERSION)
        || status.node_version.as_deref() != Some(NODE_VERSION)
        || status.pi_version.as_deref() != Some(PI_VERSION)
    {
        return rejected();
    }
    status
        .generation
        .filter(|generation| *generation != 0)
        .ok_or(ProjectTrustHarnessError)
}

fn validate_hostile_metadata(
    metadata: Option<&WorkspaceMetadata>,
) -> Result<(), ProjectTrustHarnessError> {
    let metadata = metadata.ok_or(ProjectTrustHarnessError)?;
    if metadata.pi_directory != MetadataKind::Directory
        || metadata.settings != MetadataKind::File
        || metadata.extensions != MetadataKind::Directory
        || metadata.skills != MetadataKind::Directory
        || metadata.prompts != MetadataKind::Directory
        || metadata.themes != MetadataKind::Absent
        || metadata.package_manifest != MetadataKind::File
        || metadata.agents_context != MetadataKind::File
        || metadata.claude_context != MetadataKind::Absent
    {
        return rejected();
    }
    Ok(())
}

fn validate_snapshot_observation(
    observation: &crate::domain::workspace::SnapshotProbeObservation,
) -> Result<(), ProjectTrustHarnessError> {
    if observation.marker_bytes != 9
        || observation.marker_lines != 1
        || !observation.exact_marker
        || !observation.skill_canary_absent
        || !observation.package_canary_absent
        || !observation.settings_canary_absent
        || !observation.package_manifest_absent
        || !observation.ancestor_canary_absent
    {
        return rejected();
    }
    Ok(())
}

fn register_approval_sentinel(
    state: &BridgeState,
    workspace_id: &str,
    generation: u64,
) -> Result<ApprovalView, ProjectTrustHarnessError> {
    let input = json!({"path": "sentinel"});
    let canonical = canonical_json_bytes(&input).map_err(|_| ProjectTrustHarnessError)?;
    let digest = format!("{:x}", Sha256::digest(canonical));
    let request = ApprovalRequest {
        generation,
        correlation_id: "sidecar-a24-unrelated-sentinel".into(),
        session_id: format!("session-{}", Uuid::new_v4().simple()),
        workspace_id: workspace_id.to_string(),
        workspace_revision: 1,
        invocation_id: format!("invocation-{}", Uuid::new_v4().simple()),
        tool_call_id: None,
        tool_name: "read".into(),
        cohort: None,
        input,
        input_digest: digest,
    };
    state
        .workspace_registry()
        .with_approval_binding(workspace_id, 1, |binding| {
            state.approval_registry().register(request, binding)
        })
        .map_err(|_| ProjectTrustHarnessError)
}

fn stable_approval_snapshot(
    snapshot: &ApprovalSnapshot,
) -> Result<Value, ProjectTrustHarnessError> {
    let records = snapshot
        .records
        .iter()
        .map(stable_approval_view)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({
        "changeSequence": snapshot.change_sequence,
        "records": records,
    }))
}

fn stable_approval_view(view: &ApprovalView) -> Result<Value, ProjectTrustHarnessError> {
    let mut value = serde_json::to_value(view).map_err(|_| ProjectTrustHarnessError)?;
    value
        .as_object_mut()
        .ok_or(ProjectTrustHarnessError)?
        .remove("expiresInMs")
        .ok_or(ProjectTrustHarnessError)?;
    Ok(value)
}

fn validate_empty_approval_policy(
    snapshot: &ApprovalSnapshot,
) -> Result<(), ProjectTrustHarnessError> {
    if snapshot.change_sequence != 0 || !snapshot.records.is_empty() {
        return rejected();
    }
    Ok(())
}

fn validate_approval_policy(
    snapshot: &ApprovalSnapshot,
    sentinel_id: &str,
) -> Result<(), ProjectTrustHarnessError> {
    if snapshot.records.len() != 1 {
        return rejected();
    }
    let record = &snapshot.records[0];
    if record.approval_id != sentinel_id
        || record.scopes.len() != 1
        || record.scopes[0].label != "Allow this read once"
        || record.group_action.is_some()
    {
        return rejected();
    }
    Ok(())
}

fn validate_generation_loss_policy(
    snapshot: &ApprovalSnapshot,
    sentinel: &ApprovalView,
    expected_sequence: u64,
) -> Result<(), ProjectTrustHarnessError> {
    let expected_revision = sentinel
        .revision
        .checked_add(2)
        .ok_or(ProjectTrustHarnessError)?;
    if snapshot.change_sequence != expected_sequence || snapshot.records.len() != 1 {
        return rejected();
    }
    let record = &snapshot.records[0];
    if record.approval_id != sentinel.approval_id
        || record.decision_id != sentinel.decision_id
        || record.revision != expected_revision
        || record.state != ApprovalState::Cancelled
        || record.verb != sentinel.verb
        || record.target != sentinel.target
        || record.risk != sentinel.risk
        || record.scopes.len() != sentinel.scopes.len()
        || !record
            .scopes
            .iter()
            .zip(&sentinel.scopes)
            .all(|(actual, expected)| {
                actual.scope_id == expected.scope_id && actual.label == expected.label
            })
        || record.delivery_status.is_some()
        || record.group_action.is_some()
        || record.terminal_reason != Some(ApprovalTerminalReason::GenerationLost)
    {
        return rejected();
    }
    Ok(())
}

fn source_markers_absent(root: &Path) -> Result<(), ProjectTrustHarnessError> {
    for relative in [
        "import-marker.log",
        "skill-marker.log",
        "package-marker.log",
    ] {
        match fs::symlink_metadata(root.join(relative)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return rejected(),
        }
    }
    Ok(())
}

fn validate_fixture_root(root: &Path) -> Result<PathBuf, ProjectTrustHarnessError> {
    if !root.is_absolute() {
        return rejected();
    }
    let canonical = fs::canonicalize(root).map_err(|_| ProjectTrustHarnessError)?;
    if canonical != root {
        return rejected();
    }
    validate_private_directory(root)?;
    let parent = root.parent().ok_or(ProjectTrustHarnessError)?;
    validate_private_directory(parent)?;
    Ok(canonical)
}

fn validate_private_directory(path: &Path) -> Result<(), ProjectTrustHarnessError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ProjectTrustHarnessError)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::getuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return rejected();
    }
    let directory = open_directory(path, &metadata)?;
    descriptor_has_no_extended_acl(&directory)?;
    Ok(())
}

fn open_directory(path: &Path, expected: &fs::Metadata) -> Result<File, ProjectTrustHarnessError> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ProjectTrustHarnessError)?;
    let opened = directory.metadata().map_err(|_| ProjectTrustHarnessError)?;
    if !opened.is_dir()
        || opened.uid() != unsafe { libc::getuid() }
        || opened.permissions().mode() & 0o077 != 0
        || opened.dev() != expected.dev()
        || opened.ino() != expected.ino()
    {
        return rejected();
    }
    descriptor_has_no_extended_acl(&directory)?;
    Ok(directory)
}

#[cfg(target_os = "macos")]
fn descriptor_has_no_extended_acl(file: &File) -> Result<(), ProjectTrustHarnessError> {
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            rejected()
        };
    }
    let _ = unsafe { acl_free(acl) };
    rejected()
}

#[cfg(not(target_os = "macos"))]
fn descriptor_has_no_extended_acl(_file: &File) -> Result<(), ProjectTrustHarnessError> {
    rejected()
}

fn inventory_fixture(root: &Path) -> Result<FixtureInventory, ProjectTrustHarnessError> {
    let mut digest = Sha256::new();
    let mut budget = InventoryBudget {
        entries: 0,
        bytes: 0,
    };
    inventory_entry(root, root, 0, &mut budget, &mut digest)?;
    let digest: [u8; 32] = digest.finalize().into();
    Ok(FixtureInventory {
        digest,
        entries: budget.entries,
        bytes: budget.bytes,
    })
}

fn inventory_entry(
    root: &Path,
    path: &Path,
    depth: usize,
    budget: &mut InventoryBudget,
    digest: &mut Sha256,
) -> Result<(), ProjectTrustHarnessError> {
    if depth > MAX_INVENTORY_DEPTH {
        return rejected();
    }
    budget.entries = budget
        .entries
        .checked_add(1)
        .ok_or(ProjectTrustHarnessError)?;
    if budget.entries > MAX_INVENTORY_ENTRIES {
        return rejected();
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| ProjectTrustHarnessError)?;
    if metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::getuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return rejected();
    }
    let relative = path
        .strip_prefix(root)
        .map_err(|_| ProjectTrustHarnessError)?;
    let relative_bytes = relative.as_os_str().as_bytes();
    digest.update((relative_bytes.len() as u64).to_le_bytes());
    digest.update(relative_bytes);
    digest.update((metadata.permissions().mode() & 0o777).to_le_bytes());
    digest.update(metadata.dev().to_le_bytes());
    digest.update(metadata.ino().to_le_bytes());

    if metadata.is_dir() {
        digest.update(b"d");
        let identity = (metadata.dev(), metadata.ino());
        let directory = open_directory(path, &metadata)?;
        let mut entries = fs::read_dir(path)
            .map_err(|_| ProjectTrustHarnessError)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProjectTrustHarnessError)?;
        entries.sort_by(|left, right| {
            left.file_name()
                .as_bytes()
                .cmp(right.file_name().as_bytes())
        });
        for entry in entries {
            inventory_entry(root, &entry.path(), depth + 1, budget, digest)?;
        }
        descriptor_has_no_extended_acl(&directory)?;
        let opened_after = directory.metadata().map_err(|_| ProjectTrustHarnessError)?;
        let after = fs::symlink_metadata(path).map_err(|_| ProjectTrustHarnessError)?;
        if !after.is_dir()
            || after.file_type().is_symlink()
            || (after.dev(), after.ino()) != identity
            || (opened_after.dev(), opened_after.ino()) != identity
        {
            return rejected();
        }
    } else if metadata.is_file() {
        if metadata.nlink() != 1 {
            return rejected();
        }
        digest.update(b"f");
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| ProjectTrustHarnessError)?;
        let opened = file.metadata().map_err(|_| ProjectTrustHarnessError)?;
        if !opened.is_file()
            || opened.nlink() != 1
            || opened.dev() != metadata.dev()
            || opened.ino() != metadata.ino()
            || opened.len() != metadata.len()
        {
            return rejected();
        }
        descriptor_has_no_extended_acl(&file)?;
        budget.bytes = budget
            .bytes
            .checked_add(opened.len())
            .ok_or(ProjectTrustHarnessError)?;
        if budget.bytes > MAX_INVENTORY_BYTES {
            return rejected();
        }
        digest.update(opened.len().to_le_bytes());
        let mut remaining = opened.len();
        let mut buffer = [0_u8; 16 * 1024];
        while remaining > 0 {
            let requested = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| ProjectTrustHarnessError)?;
            let count = file
                .read(&mut buffer[..requested])
                .map_err(|_| ProjectTrustHarnessError)?;
            if count == 0 {
                return rejected();
            }
            digest.update(&buffer[..count]);
            remaining -= count as u64;
        }
        if file
            .read(&mut buffer[..1])
            .map_err(|_| ProjectTrustHarnessError)?
            != 0
        {
            return rejected();
        }
        let after = file.metadata().map_err(|_| ProjectTrustHarnessError)?;
        if after.dev() != opened.dev() || after.ino() != opened.ino() || after.len() != opened.len()
        {
            return rejected();
        }
        descriptor_has_no_extended_acl(&file)?;
    } else {
        return rejected();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::process::Command;

    fn private_fixture() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "piui-a24-rust-inventory-{}",
            Uuid::new_v4().simple()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join("nested"))
            .unwrap();
        let file = root.join("nested/value");
        fs::write(&file, b"fixed fixture").unwrap();
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
        root
    }

    #[test]
    fn safe_evidence_has_only_fixed_path_free_values() {
        let encoded = serde_json::to_string(&ProjectTrustEvidence::accepted()).unwrap();
        let value: Value = serde_json::from_str(&encoded).unwrap();
        let object = value.as_object().unwrap();
        let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        let mut expected = vec![
            "ancestorCanaryLoads",
            "approvalRecordsAfterTrust",
            "approvalRecordsBeforeTrust",
            "approvalSentinelUnchangedThroughTrustedLoad",
            "authoriseExecutions",
            "blanketApprovalScopes",
            "cachedReplayResults",
            "concurrentReplayRequests",
            "fixtureInventoryUnchanged",
            "groupApprovalScopes",
            "markerBytes",
            "markerLines",
            "metadataInspections",
            "packageCanaryExecutions",
            "packagedRuntimeValidated",
            "postRevokeLoadRejections",
            "projectTrustApprovalPolicyMutations",
            "projectTrustAuthorisations",
            "rememberedApprovalScopes",
            "revocations",
            "schemaVersion",
            "sentinelWorkspaceAuthorisations",
            "settingsCanaryLoads",
            "sidecarGenerationRestarted",
            "sidecarGenerationRestarts",
            "skillCanaryExecutions",
            "sourceMarkerExecutions",
            "staleGenerationRejections",
            "staleLeaseRejections",
            "staleRevisionRejections",
            "trustedLoadExecutions",
            "untrustedLoadRejections",
        ];
        expected.sort_unstable();
        assert_eq!(keys, expected);
        assert_eq!(object.get("schemaVersion"), Some(&Value::from(1)));
        assert_eq!(
            object.get("sidecarGenerationRestarted"),
            Some(&Value::Bool(true))
        );
        assert!(!encoded.contains('/') && !encoded.contains('\\'));
        assert!(!encoded.contains("workspace-") && !encoded.contains("trust-"));
        assert!(
            object
                .values()
                .all(|entry| entry.is_boolean() || entry.is_u64())
        );
    }

    #[test]
    fn fixture_inventory_detects_content_changes_and_rejects_links() {
        let root = private_fixture();
        let before = inventory_fixture(&root).unwrap();
        fs::write(root.join("nested/value"), b"changed fixture").unwrap();
        let after = inventory_fixture(&root).unwrap();
        assert_ne!(before, after);
        symlink(root.join("nested/value"), root.join("link")).unwrap();
        assert!(inventory_fixture(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fixture_inventory_rejects_extended_acls() {
        let root = private_fixture();
        let nested = root.join("nested");
        let added = Command::new("/bin/chmod")
            .arg("+a")
            .arg("everyone allow read")
            .arg(&nested)
            .status()
            .unwrap();
        assert!(added.success());
        assert!(inventory_fixture(&root).is_err());
        let cleared = Command::new("/bin/chmod")
            .arg("-N")
            .arg(&nested)
            .status()
            .unwrap();
        assert!(cleared.success());
        fs::remove_dir_all(root).unwrap();
    }
}
