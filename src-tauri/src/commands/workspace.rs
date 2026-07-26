use super::bridge::BridgeState;
use crate::domain::workspace::{LoadStart, ResourceCounts, WorkspaceSummary};
use crate::protocol::{Envelope, ProtocolKind};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::path::Path;
use std::time::Duration;
use tauri::{State, WebviewWindow};

const SCHEMA_VERSION: u8 = 1;
const WORKSPACE_TIMEOUT: Duration = Duration::from_secs(30);
const PRIVATE_REJECTED: &str = "workspace private response rejected";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFolderSelectionRequest {}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateResponse {
    schema_version: u8,
    revision: u64,
    resource_state: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SyncResponse {
    schema_version: u8,
    revision: u64,
    trust_state: String,
    resource_state: String,
    synced: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoadResponse {
    schema_version: u8,
    revision: u64,
    resource_state: String,
    counts: ResourceCounts,
    cached: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RevokeResponse {
    schema_version: u8,
    revision: u64,
    resource_state: String,
    requires_generation_stop: bool,
}

/// Internal native-selection seam. It is deliberately not a Tauri command:
/// the WebView cannot supply a project path.
pub(crate) fn acquire_selected_directory(
    state: &BridgeState,
    selected: &Path,
) -> Result<WorkspaceSummary, String> {
    state
        .workspace_registry()
        .acquire_selected_directory(selected)
}

pub(crate) fn inspect_workspace(
    state: &BridgeState,
    workspace_id: &str,
) -> Result<WorkspaceSummary, String> {
    state.workspace_registry().inspect_metadata(workspace_id)
}

pub(crate) fn open_workspace_untrusted(
    state: &BridgeState,
    workspace_id: &str,
    expected_revision: u64,
) -> Result<WorkspaceSummary, String> {
    let registry = state.workspace_registry();
    let summary = registry.open_untrusted(workspace_id, expected_revision)?;
    let generation = current_generation(state)?;
    let response = request(
        state,
        generation,
        "workspace.openUntrusted",
        Map::from_iter([
            ("schemaVersion".into(), Value::from(SCHEMA_VERSION)),
            ("workspaceId".into(), Value::from(workspace_id)),
            ("generation".into(), Value::from(generation)),
            ("revision".into(), Value::from(summary.revision)),
        ]),
    )?;
    let parsed: StateResponse = match parse_success(response) {
        Ok(parsed) => parsed,
        Err(error) => {
            let _ = state.cutoff_generation(generation);
            return Err(error);
        }
    };
    if parsed.schema_version != SCHEMA_VERSION
        || parsed.revision != summary.revision
        || parsed.resource_state != "open"
    {
        let _ = state.cutoff_generation(generation);
        return Err(PRIVATE_REJECTED.into());
    }
    Ok(summary)
}

pub(crate) fn authorise_workspace(
    state: &BridgeState,
    workspace_id: &str,
    expected_revision: u64,
) -> Result<WorkspaceSummary, String> {
    let registry = state.workspace_registry();
    let generation = current_generation(state)?;
    sync_workspace(state, workspace_id, generation)?;
    let grant = registry.reserve_authorise(workspace_id, expected_revision)?;
    let response = request(
        state,
        generation,
        "workspace.authorise",
        Map::from_iter([
            ("schemaVersion".into(), Value::from(SCHEMA_VERSION)),
            ("workspaceId".into(), Value::from(workspace_id)),
            ("generation".into(), Value::from(generation)),
            ("expectedRevision".into(), Value::from(expected_revision)),
            ("revision".into(), Value::from(grant.revision)),
            ("leaseId".into(), Value::from(grant.lease_id.clone())),
        ]),
    );
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            registry.rollback_authorise(&grant);
            state.cutoff_generation(generation)?;
            return Err(error);
        }
    };
    let parsed: StateResponse = match parse_success(response) {
        Ok(parsed) => parsed,
        Err(error) => {
            registry.rollback_authorise(&grant);
            state.cutoff_generation(generation)?;
            return Err(error);
        }
    };
    if parsed.schema_version != SCHEMA_VERSION
        || parsed.revision != grant.revision
        || parsed.resource_state != "trusted"
    {
        registry.rollback_authorise(&grant);
        state.cutoff_generation(generation)?;
        return Err(PRIVATE_REJECTED.into());
    }
    match registry.commit_authorise(&grant) {
        Ok(summary) => Ok(summary),
        Err(error) => {
            registry.rollback_authorise(&grant);
            state.cutoff_generation(generation)?;
            Err(error)
        }
    }
}

pub(crate) fn load_trusted_workspace(
    state: &BridgeState,
    workspace_id: &str,
    expected_revision: u64,
) -> Result<WorkspaceSummary, String> {
    let registry = state.workspace_registry();
    // Hold the generation authority while checking the registry shortcut. This
    // linearises cached/in-progress success against stop/restart; those paths
    // take the same supervisor→registry lock order before invalidation.
    let supervisor = state.supervisor();
    let authority = supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?;
    let generation = authority
        .current_generation()
        .ok_or_else(|| "sidecar unavailable".to_string())?;
    let existing = registry.existing_load(workspace_id, expected_revision, generation)?;
    if let Some(existing) = existing {
        return match existing {
            LoadStart::Cached(summary) | LoadStart::InProgress(summary) => Ok(summary),
            LoadStart::Dispatch(_) => Err(PRIVATE_REJECTED.into()),
        };
    }
    drop(authority);
    // A generation that does not already own this load must receive the exact
    // Rust-authoritative trust projection before dispatch can be reserved.
    sync_workspace(state, workspace_id, generation)?;
    let lease = match registry.begin_load(workspace_id, expected_revision, generation)? {
        LoadStart::Cached(summary) | LoadStart::InProgress(summary) => return Ok(summary),
        LoadStart::Dispatch(lease) => lease,
    };
    let snapshot_root = lease
        .snapshot_root
        .to_str()
        .ok_or_else(|| PRIVATE_REJECTED.to_string())?;
    let agent_root = lease
        .agent_root
        .to_str()
        .ok_or_else(|| PRIVATE_REJECTED.to_string())?;
    let response = request(
        state,
        generation,
        "workspace.loadTrusted",
        Map::from_iter([
            ("schemaVersion".into(), Value::from(SCHEMA_VERSION)),
            ("workspaceId".into(), Value::from(workspace_id)),
            ("generation".into(), Value::from(generation)),
            ("revision".into(), Value::from(expected_revision)),
            ("leaseId".into(), Value::from(lease.lease_id.clone())),
            ("snapshotRoot".into(), Value::from(snapshot_root)),
            ("agentRoot".into(), Value::from(agent_root)),
        ]),
    );
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            let _ = registry.mark_load_failed(&lease, true);
            let _ = state.cutoff_generation(generation);
            return Err(error);
        }
    };
    if let Some(error) = response.error.as_ref() {
        let preflight_rejection =
            error.category == crate::protocol::ErrorCategory::PermissionDenied;
        let _ = registry.mark_load_failed(&lease, !preflight_rejection);
        if !preflight_rejection {
            state.cutoff_generation(generation)?;
        }
        return Err(if preflight_rejection {
            "workspace resources were rejected".into()
        } else {
            "workspace execution uncertain".into()
        });
    }
    let parsed: LoadResponse = match parse_success(response) {
        Ok(parsed) => parsed,
        Err(error) => {
            let _ = registry.mark_load_failed(&lease, true);
            let _ = state.cutoff_generation(generation);
            return Err(error);
        }
    };
    if parsed.schema_version != SCHEMA_VERSION
        || parsed.revision != expected_revision
        || parsed.resource_state != "loaded"
        || parsed.cached
    {
        let _ = registry.mark_load_failed(&lease, true);
        let _ = state.cutoff_generation(generation);
        return Err(PRIVATE_REJECTED.into());
    }
    registry.complete_load(&lease, parsed.counts)
}

pub(crate) fn revoke_workspace(
    state: &BridgeState,
    workspace_id: &str,
    expected_revision: u64,
) -> Result<WorkspaceSummary, String> {
    let registry = state.workspace_registry();
    // Rust authority changes first. If any code attempt was associated with a
    // generation, that exact generation is cut off before a mirror request.
    let outcome = registry.revoke(workspace_id, expected_revision)?;
    if let Some(generation) = outcome.stop_generation {
        state.cutoff_generation(generation)?;
        return Ok(outcome.cleanup());
    }

    let Ok(generation) = current_generation(state) else {
        return Ok(outcome.cleanup());
    };
    let response = request(
        state,
        generation,
        "workspace.revoke",
        Map::from_iter([
            ("schemaVersion".into(), Value::from(SCHEMA_VERSION)),
            ("workspaceId".into(), Value::from(workspace_id)),
            ("generation".into(), Value::from(generation)),
            ("expectedRevision".into(), Value::from(expected_revision)),
            ("revision".into(), Value::from(outcome.summary.revision)),
            ("leaseId".into(), Value::from(outcome.lease_id.clone())),
        ]),
    );
    let parsed: RevokeResponse = match response.and_then(parse_success) {
        Ok(parsed) => parsed,
        Err(error) => {
            state.cutoff_generation(generation)?;
            return Err(error);
        }
    };
    if parsed.schema_version != SCHEMA_VERSION
        || parsed.revision != outcome.summary.revision
        || parsed.resource_state != "revoked"
        || parsed.requires_generation_stop
    {
        state.cutoff_generation(generation)?;
        return Err(PRIVATE_REJECTED.into());
    }
    Ok(outcome.cleanup())
}

fn sync_workspace(state: &BridgeState, workspace_id: &str, generation: u64) -> Result<(), String> {
    let sync = state.workspace_registry().sync_state(workspace_id)?;
    let trust_state = match sync.trust_state {
        crate::domain::workspace::TrustState::Untrusted => "untrusted",
        crate::domain::workspace::TrustState::Trusted => "trusted",
        crate::domain::workspace::TrustState::Revoked => "revoked",
    };
    let mut payload = Map::from_iter([
        ("schemaVersion".into(), Value::from(SCHEMA_VERSION)),
        ("workspaceId".into(), Value::from(sync.workspace_id)),
        ("generation".into(), Value::from(generation)),
        ("revision".into(), Value::from(sync.revision)),
        ("trustState".into(), Value::from(trust_state)),
    ]);
    if let Some(lease_id) = sync.lease_id {
        payload.insert("leaseId".into(), Value::from(lease_id));
    }
    let parsed: SyncResponse =
        parse_success(request(state, generation, "workspace.sync", payload)?)?;
    let compatible_resource = match trust_state {
        "untrusted" => parsed.resource_state == "open",
        "revoked" => parsed.resource_state == "revoked",
        "trusted" => matches!(
            parsed.resource_state.as_str(),
            "trusted" | "loading" | "loaded" | "failed"
        ),
        _ => false,
    };
    if parsed.schema_version != SCHEMA_VERSION
        || parsed.revision != sync.revision
        || parsed.trust_state != trust_state
        || !compatible_resource
        || !parsed.synced
    {
        return Err(PRIVATE_REJECTED.into());
    }
    Ok(())
}

fn current_generation(state: &BridgeState) -> Result<u64, String> {
    state
        .supervisor()
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?
        .current_generation()
        .ok_or_else(|| "sidecar unavailable".to_string())
}

fn request(
    state: &BridgeState,
    generation: u64,
    method: &str,
    payload: Map<String, Value>,
) -> Result<Envelope, String> {
    // Reserve the correlation and complete the generation-checked write while
    // holding the supervisor mutex, then release it before any bounded wait.
    // Revoke/stop/restart can therefore cut off a hung worker promptly.
    let supervisor = state.supervisor();
    let waiter = supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?
        .begin_workspace_request(generation, method, payload)?;
    debug_assert_eq!(waiter.generation(), generation);
    waiter.wait(WORKSPACE_TIMEOUT)
}

#[tauri::command]
pub async fn workspace_select_directory(
    window: WebviewWindow,
    state: State<'_, BridgeState>,
    _request: NativeFolderSelectionRequest,
) -> Result<Option<WorkspaceSummary>, String> {
    let selected = crate::platform::present_native_folder_picker(window)
        .await
        .map_err(|error| error.code().to_string())?;
    selected
        .map(|path| acquire_selected_directory(state.inner(), &path))
        .transpose()
}

#[tauri::command]
pub fn workspace_inspect(
    state: State<'_, BridgeState>,
    workspace_id: String,
) -> Result<WorkspaceSummary, String> {
    inspect_workspace(state.inner(), &workspace_id)
}

#[tauri::command]
pub fn workspace_open_untrusted(
    state: State<'_, BridgeState>,
    workspace_id: String,
    expected_revision: u64,
) -> Result<WorkspaceSummary, String> {
    open_workspace_untrusted(state.inner(), &workspace_id, expected_revision)
}

#[tauri::command]
pub fn workspace_authorise(
    state: State<'_, BridgeState>,
    workspace_id: String,
    expected_revision: u64,
) -> Result<WorkspaceSummary, String> {
    authorise_workspace(state.inner(), &workspace_id, expected_revision)
}

#[tauri::command]
pub fn workspace_load_trusted(
    state: State<'_, BridgeState>,
    workspace_id: String,
    expected_revision: u64,
) -> Result<WorkspaceSummary, String> {
    load_trusted_workspace(state.inner(), &workspace_id, expected_revision)
}

#[tauri::command]
pub fn workspace_revoke(
    state: State<'_, BridgeState>,
    workspace_id: String,
    expected_revision: u64,
) -> Result<WorkspaceSummary, String> {
    revoke_workspace(state.inner(), &workspace_id, expected_revision)
}

fn parse_success<T: for<'de> Deserialize<'de>>(envelope: Envelope) -> Result<T, String> {
    if envelope.kind != ProtocolKind::Response || envelope.error.is_some() {
        return Err(PRIVATE_REJECTED.into());
    }
    serde_json::from_value(Value::Object(envelope.payload)).map_err(|_| PRIVATE_REJECTED.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::bridge::{
        bridge_restart_transport, bridge_start_transport, bridge_stop_transport,
    };
    use crate::protocol::ProtocolKind;
    use crate::supervisor::SupervisorPaths;
    use std::fs;
    use uuid::Uuid;

    #[test]
    fn native_folder_selection_request_rejects_webview_paths() {
        assert!(
            serde_json::from_value::<NativeFolderSelectionRequest>(serde_json::json!({})).is_ok()
        );
        assert!(
            serde_json::from_value::<NativeFolderSelectionRequest>(serde_json::json!({
                "path": "/forged"
            }))
            .is_err()
        );
    }

    #[test]
    fn shared_workspace_response_contract_has_matching_rust_verdicts() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../packages/protocol/fixtures/workspace-contract.json"
        ))
        .unwrap();
        let validate = |payload: &Value| {
            let object = payload.as_object().unwrap().clone();
            let envelope = Envelope {
                version: 1,
                kind: ProtocolKind::Response,
                id: "sidecar-contract".into(),
                correlation_id: Some("rust-workspace-contract".into()),
                decision_id: None,
                sequence: 1,
                payload: object.clone(),
                error: None,
            };
            if object.contains_key("synced") {
                parse_success::<SyncResponse>(envelope).is_ok_and(|response| {
                    response.synced
                        && match response.trust_state.as_str() {
                            "untrusted" => response.resource_state == "open",
                            "revoked" => response.resource_state == "revoked",
                            "trusted" => matches!(
                                response.resource_state.as_str(),
                                "trusted" | "loading" | "loaded" | "failed"
                            ),
                            _ => false,
                        }
                })
            } else if object.contains_key("counts") {
                parse_success::<LoadResponse>(envelope)
                    .and_then(|response| response.counts.validate().map(|_| response))
                    .is_ok()
            } else if object.contains_key("requiresGenerationStop") {
                parse_success::<RevokeResponse>(envelope).is_ok()
            } else {
                parse_success::<StateResponse>(envelope).is_ok()
            }
        };
        for response in fixture["validResponses"].as_array().unwrap() {
            assert!(validate(response));
        }
        for response in fixture["invalidResponses"].as_array().unwrap() {
            assert!(!validate(response));
        }
    }

    #[test]
    fn response_shapes_deny_unknown_keys_and_path_bearing_payloads() {
        let envelope = Envelope {
            version: 1,
            kind: ProtocolKind::Response,
            id: "sidecar-1".into(),
            correlation_id: Some("rust-workspace-1-1".into()),
            decision_id: None,
            sequence: 1,
            payload: Map::from_iter([
                ("schemaVersion".into(), Value::from(1)),
                ("revision".into(), Value::from(1)),
                ("resourceState".into(), Value::from("trusted")),
                ("path".into(), Value::from("/private/canary")),
            ]),
            error: None,
        };
        assert!(parse_success::<StateResponse>(envelope).is_err());
    }

    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    #[test]
    #[ignore = "requires staged official Node 22.23.1 and sidecar resources"]
    fn actual_staged_workspace_path_isolated_worker_restart_replay_and_retrust() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let paths = SupervisorPaths::validated(
            manifest.join("binaries/piui-node-aarch64-apple-darwin"),
            manifest.join("resources/sidecar"),
        )
        .expect("stage the official runtime first");
        let state = BridgeState::new(paths);
        bridge_start_transport(&state).unwrap();
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/hostile-project");
        let root =
            std::env::temp_dir().join(format!("piui-a16-actual-{}", Uuid::new_v4().simple()));
        copy_tree(&source, &root);
        let summary = acquire_selected_directory(&state, &root).unwrap();
        inspect_workspace(&state, &summary.workspace_id).unwrap();
        open_workspace_untrusted(&state, &summary.workspace_id, 0).unwrap();
        assert!(load_trusted_workspace(&state, &summary.workspace_id, 0).is_err());
        authorise_workspace(&state, &summary.workspace_id, 0).unwrap();
        bridge_restart_transport(&state).unwrap();
        load_trusted_workspace(&state, &summary.workspace_id, 1).unwrap();
        assert_eq!(
            state
                .workspace_registry()
                .snapshot_marker_lines(&summary.workspace_id)
                .unwrap(),
            1
        );

        let mut replays = Vec::new();
        for _ in 0..16 {
            let replay_state = state.clone();
            let workspace_id = summary.workspace_id.clone();
            replays.push(std::thread::spawn(move || {
                load_trusted_workspace(&replay_state, &workspace_id, 1)
            }));
        }
        assert!(
            replays
                .into_iter()
                .all(|result| result.join().unwrap().is_ok())
        );
        assert_eq!(
            state
                .workspace_registry()
                .snapshot_marker_lines(&summary.workspace_id)
                .unwrap(),
            1
        );
        revoke_workspace(&state, &summary.workspace_id, 1).unwrap();
        bridge_start_transport(&state).unwrap();
        authorise_workspace(&state, &summary.workspace_id, 2).unwrap();
        load_trusted_workspace(&state, &summary.workspace_id, 3).unwrap();
        assert_eq!(
            state
                .workspace_registry()
                .snapshot_marker_lines(&summary.workspace_id)
                .unwrap(),
            1
        );
        assert!(!root.join("import-marker.log").exists());

        let hung_root =
            std::env::temp_dir().join(format!("piui-a16-hung-{}", Uuid::new_v4().simple()));
        copy_tree(&source, &hung_root);
        fs::write(
            hung_root.join(".pi/extensions/00-hang.js"),
            "while (true) {}",
        )
        .unwrap();
        let hung = acquire_selected_directory(&state, &hung_root).unwrap();
        inspect_workspace(&state, &hung.workspace_id).unwrap();
        open_workspace_untrusted(&state, &hung.workspace_id, 0).unwrap();
        authorise_workspace(&state, &hung.workspace_id, 0).unwrap();
        let loading_state = state.clone();
        let loading_id = hung.workspace_id.clone();
        let loading =
            std::thread::spawn(move || load_trusted_workspace(&loading_state, &loading_id, 1));
        std::thread::sleep(Duration::from_millis(200));
        let revoke_started = std::time::Instant::now();
        revoke_workspace(&state, &hung.workspace_id, 1).unwrap();
        assert!(revoke_started.elapsed() < Duration::from_secs(2));
        assert!(loading.join().unwrap().is_err());
        assert!(!hung_root.join("import-marker.log").exists());

        let throwing_root =
            std::env::temp_dir().join(format!("piui-a16-throwing-{}", Uuid::new_v4().simple()));
        copy_tree(&source, &throwing_root);
        fs::write(
            throwing_root.join(".pi/extensions/00-throw.js"),
            "throw new Error('project controlled')",
        )
        .unwrap();
        bridge_start_transport(&state).unwrap();
        let throwing = acquire_selected_directory(&state, &throwing_root).unwrap();
        inspect_workspace(&state, &throwing.workspace_id).unwrap();
        open_workspace_untrusted(&state, &throwing.workspace_id, 0).unwrap();
        authorise_workspace(&state, &throwing.workspace_id, 0).unwrap();
        assert!(load_trusted_workspace(&state, &throwing.workspace_id, 1).is_err());
        assert!(!throwing_root.join("import-marker.log").exists());

        let _ = bridge_stop_transport(&state);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(hung_root).unwrap();
        fs::remove_dir_all(throwing_root).unwrap();
    }
}
