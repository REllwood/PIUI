use super::bridge::{BridgeState, DeliveryAcceptance, bridge_start_transport};
use crate::platform::attachments::AttachmentRegistry;
use crate::protocol::{Envelope, ProtocolKind};
use crate::supervisor::pi_agent_dir_within;
use serde::Deserialize;
use serde_json::{Map, Value};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tauri::{AppHandle, Manager, State, WebviewWindow};

const PRODUCT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const PRODUCT_LONG_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductSessionCreateRequest {
    workspace_id: String,
    expected_revision: u64,
    title: Option<String>,
    provider_id: Option<String>,
    model_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductSessionListRequest {
    workspace_id: String,
    expected_revision: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductSessionReferenceRequest {
    session_id: String,
    expected_generation: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductSessionRenameRequest {
    session_id: String,
    expected_generation: u64,
    title: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductChangeRequest {
    session_id: String,
    expected_generation: u64,
    change_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductSettingSaveRequest {
    session_id: String,
    expected_generation: u64,
    key: String,
    value: Value,
    scope: String,
    expected_revision: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductSettingPreviewRequest {
    session_id: String,
    expected_generation: u64,
    key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductResourceSetEnabledRequest {
    session_id: String,
    expected_generation: u64,
    resource_id: String,
    enabled: bool,
    acknowledged_executable_risk: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductPackageInstallRequest {
    session_id: String,
    expected_generation: u64,
    source: String,
    scope: String,
    online: bool,
    acknowledged_executable_risk: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductPackageMutationRequest {
    session_id: String,
    expected_generation: u64,
    resource_id: String,
    operation: String,
    online: bool,
    acknowledged_executable_risk: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductTurnStartRequest {
    request_id: String,
    session_id: String,
    generation: u64,
    text: String,
    retry_previous: bool,
    attachment_capabilities: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductTurnStopRequest {
    request_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductQueueFollowUpRequest {
    session_id: String,
    expected_generation: u64,
    text: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductQueueReplaceRequest {
    session_id: String,
    expected_generation: u64,
    texts: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductAuthStartRequest {
    request_id: String,
    provider_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductProviderReferenceRequest {
    provider_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductSessionExportRequest {
    session_id: String,
    expected_generation: u64,
}

#[tauri::command]
pub async fn product_list_providers(state: State<'_, BridgeState>) -> Result<Value, String> {
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        request(&transport, "product.providers.list", Map::new())
    })
    .await
    .map_err(|_| "provider discovery worker failed".to_string())?
}

#[tauri::command]
pub async fn product_logout_provider(
    state: State<'_, BridgeState>,
    request_data: ProductProviderReferenceRequest,
) -> Result<Value, String> {
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        request(
            &transport,
            "product.provider.logout",
            Map::from_iter([
                ("schemaVersion".into(), Value::from(1)),
                ("providerId".into(), Value::from(request_data.provider_id)),
            ]),
        )
    })
    .await
    .map_err(|_| "provider logout worker failed".to_string())?
}

#[tauri::command]
pub async fn product_create_session(
    app: AppHandle,
    state: State<'_, BridgeState>,
    request_data: ProductSessionCreateRequest,
) -> Result<Value, String> {
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        let workspace = transport
            .workspace_registry()
            .execution_context(&request_data.workspace_id, request_data.expected_revision)?;
        let path = workspace
            .canonical_path
            .to_str()
            .ok_or_else(|| "workspace path unavailable".to_string())?;
        let agent_dir = pi_agent_dir(&app)?;
        request(
            &transport,
            "product.session.create",
            Map::from_iter([
                ("schemaVersion".into(), Value::from(1)),
                ("workspaceId".into(), Value::from(workspace.workspace_id)),
                ("workspaceRevision".into(), Value::from(workspace.revision)),
                ("workspacePath".into(), Value::from(path)),
                ("agentDir".into(), Value::from(agent_dir)),
                (
                    "title".into(),
                    request_data.title.map_or(Value::Null, Value::from),
                ),
                (
                    "providerId".into(),
                    request_data.provider_id.map_or(Value::Null, Value::from),
                ),
                (
                    "modelId".into(),
                    request_data.model_id.map_or(Value::Null, Value::from),
                ),
            ]),
        )
    })
    .await
    .map_err(|_| "session creation worker failed".to_string())?
}

#[tauri::command]
pub async fn product_list_sessions(
    app: AppHandle,
    state: State<'_, BridgeState>,
    request_data: ProductSessionListRequest,
) -> Result<Value, String> {
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        let workspace = transport
            .workspace_registry()
            .execution_context(&request_data.workspace_id, request_data.expected_revision)?;
        let path = workspace
            .canonical_path
            .to_str()
            .ok_or_else(|| "workspace path unavailable".to_string())?;
        let agent_dir = pi_agent_dir(&app)?;
        request(
            &transport,
            "product.sessions.list",
            Map::from_iter([
                ("schemaVersion".into(), Value::from(1)),
                ("workspaceId".into(), Value::from(workspace.workspace_id)),
                ("workspaceRevision".into(), Value::from(workspace.revision)),
                ("workspacePath".into(), Value::from(path)),
                ("agentDir".into(), Value::from(agent_dir)),
            ]),
        )
    })
    .await
    .map_err(|_| "session listing worker failed".to_string())?
}

fn pi_agent_dir(app: &AppHandle) -> Result<String, String> {
    let home = app
        .path()
        .home_dir()
        .map_err(|_| "pi-agent-directory-unavailable".to_string())?;
    pi_agent_dir_within(&home)
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| "pi-agent-directory-unavailable".to_string())
}

#[tauri::command]
pub async fn product_resume_session(
    state: State<'_, BridgeState>,
    request_data: ProductSessionReferenceRequest,
) -> Result<Value, String> {
    session_reference_request(state, "product.session.resume", request_data).await
}

#[tauri::command]
pub async fn product_fork_session(
    state: State<'_, BridgeState>,
    request_data: ProductSessionReferenceRequest,
) -> Result<Value, String> {
    session_reference_request(state, "product.session.fork", request_data).await
}

#[tauri::command]
pub async fn product_rename_session(
    state: State<'_, BridgeState>,
    request_data: ProductSessionRenameRequest,
) -> Result<Value, String> {
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        request(
            &transport,
            "product.session.rename",
            Map::from_iter([
                ("schemaVersion".into(), Value::from(1)),
                ("sessionId".into(), Value::from(request_data.session_id)),
                (
                    "expectedGeneration".into(),
                    Value::from(request_data.expected_generation),
                ),
                ("title".into(), Value::from(request_data.title)),
            ]),
        )
    })
    .await
    .map_err(|_| "session rename worker failed".to_string())?
}

#[tauri::command]
pub async fn product_inspect_session(
    state: State<'_, BridgeState>,
    request_data: ProductSessionReferenceRequest,
) -> Result<Value, String> {
    session_reference_request(state, "product.session.inspect", request_data).await
}

#[tauri::command]
pub async fn product_trash_session(
    app: AppHandle,
    state: State<'_, BridgeState>,
    request_data: ProductSessionReferenceRequest,
) -> Result<bool, String> {
    let home = app
        .path()
        .home_dir()
        .map_err(|_| "session-trash-unavailable".to_string())?;
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        let target = request(
            &transport,
            "product.session.trash-target",
            Map::from_iter([
                ("schemaVersion".into(), Value::from(1)),
                (
                    "sessionId".into(),
                    Value::from(request_data.session_id.clone()),
                ),
                (
                    "expectedGeneration".into(),
                    Value::from(request_data.expected_generation),
                ),
            ]),
        )?;
        let target = target
            .get("target")
            .and_then(Value::as_object)
            .ok_or_else(|| "session-trash-target-invalid".to_string())?;
        if target.len() != 4 {
            return Err("session-trash-target-invalid".into());
        }
        let private_path = target
            .get("privatePath")
            .and_then(Value::as_str)
            .ok_or_else(|| "session-trash-target-invalid".to_string())?;
        let expected_identity = target
            .get("identity")
            .and_then(Value::as_str)
            .ok_or_else(|| "session-trash-target-invalid".to_string())?;
        let workspace_id = target
            .get("workspaceId")
            .and_then(Value::as_str)
            .ok_or_else(|| "session-trash-target-invalid".to_string())?;
        let workspace_revision = target
            .get("workspaceRevision")
            .and_then(Value::as_u64)
            .ok_or_else(|| "session-trash-target-invalid".to_string())?;
        let _workspace = transport
            .workspace_registry()
            .execution_context(workspace_id, workspace_revision)?;
        let source = validated_session_path(private_path, &home)?;
        let current_identity = session_file_identity(&source)?;
        if current_identity != expected_identity {
            return Err("session-trash-target-changed".into());
        }
        let trash_directory = home.join(".Trash");
        let confirmation = crate::platform::trash::confirmation(
            &request_data.session_id,
            expected_identity,
            &uuid::Uuid::new_v4().simple().to_string(),
        )?;
        crate::platform::trash::move_enumerated_inactive_session(
            &source,
            &trash_directory,
            &request_data.session_id,
            &current_identity,
            &confirmation,
            false,
        )?;
        let completion = request(
            &transport,
            "product.session.trash-complete",
            Map::from_iter([
                ("schemaVersion".into(), Value::from(1)),
                ("sessionId".into(), Value::from(request_data.session_id)),
                (
                    "expectedGeneration".into(),
                    Value::from(request_data.expected_generation),
                ),
            ]),
        );
        let confirmed = completion
            .ok()
            .and_then(|completion| completion.get("acknowledged").and_then(Value::as_bool))
            .unwrap_or(false);
        if !confirmed {
            eprintln!("PIUI session Trash catalogue confirmation deferred");
        }
        Ok(true)
    })
    .await
    .map_err(|_| "session trash worker failed".to_string())?
}

fn validated_session_path(value: &str, home: &Path) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if !path.is_absolute() || value.len() > 4_096 || value.chars().any(char::is_control) {
        return Err("session-trash-target-invalid".into());
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| "session-trash-target-invalid".to_string())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("session-trash-target-invalid".into());
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| "session-trash-target-invalid".to_string())?;
    let session_root = session_root_within(home);
    let canonical_root = session_root
        .canonicalize()
        .map_err(|_| "session-trash-target-invalid".to_string())?;
    if !canonical.starts_with(&canonical_root)
        || canonical.extension().and_then(|value| value.to_str()) != Some("jsonl")
    {
        return Err("session-trash-target-invalid".into());
    }
    Ok(canonical)
}

fn session_root_within(home: &Path) -> PathBuf {
    pi_agent_dir_within(home).join("sessions")
}

#[cfg(unix)]
fn session_file_identity(path: &Path) -> Result<String, String> {
    let metadata =
        std::fs::metadata(path).map_err(|_| "session-trash-target-invalid".to_string())?;
    Ok(format!(
        "{}:{}:{}:{}",
        metadata.dev(),
        metadata.ino(),
        metadata.size(),
        i128::from(metadata.mtime()) * 1_000_000_000_i128 + i128::from(metadata.mtime_nsec())
    ))
}

#[cfg(not(unix))]
fn session_file_identity(_path: &Path) -> Result<String, String> {
    Err("session-trash-unavailable".into())
}

#[tauri::command]
pub async fn product_compact_session(
    state: State<'_, BridgeState>,
    request_data: ProductSessionReferenceRequest,
) -> Result<Value, String> {
    session_reference_request(state, "product.session.compact", request_data).await
}

#[tauri::command]
pub async fn product_list_changes(
    state: State<'_, BridgeState>,
    request_data: ProductSessionReferenceRequest,
) -> Result<Value, String> {
    session_reference_request(state, "product.changes.list", request_data).await
}

#[tauri::command]
pub async fn product_undo_change(
    state: State<'_, BridgeState>,
    request_data: ProductChangeRequest,
) -> Result<Value, String> {
    change_request(state, "product.change.undo", request_data).await
}

#[tauri::command]
pub async fn product_reveal_change(
    state: State<'_, BridgeState>,
    request_data: ProductChangeRequest,
) -> Result<(), String> {
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        let response = request(
            &transport,
            "product.change.target",
            change_payload(request_data),
        )?;
        let target = response
            .get("target")
            .and_then(Value::as_object)
            .ok_or_else(|| "change-target-invalid".to_string())?;
        if target.len() != 3 {
            return Err("change-target-invalid".into());
        }
        let workspace_id = target
            .get("workspaceId")
            .and_then(Value::as_str)
            .ok_or_else(|| "change-target-invalid".to_string())?;
        let workspace_revision = target
            .get("workspaceRevision")
            .and_then(Value::as_u64)
            .ok_or_else(|| "change-target-invalid".to_string())?;
        let private_path = target
            .get("privatePath")
            .and_then(Value::as_str)
            .ok_or_else(|| "change-target-invalid".to_string())?;
        let workspace = transport
            .workspace_registry()
            .execution_context(workspace_id, workspace_revision)?;
        let path = crate::platform::finder::capability_backed_path(
            &workspace.canonical_path,
            std::path::Path::new(private_path),
        )?;
        crate::platform::finder::reveal(&path)
    })
    .await
    .map_err(|_| "change reveal worker failed".to_string())?
}

#[tauri::command]
pub async fn product_list_settings(
    state: State<'_, BridgeState>,
    request_data: ProductSessionReferenceRequest,
) -> Result<Value, String> {
    session_reference_request(state, "product.settings.list", request_data).await
}

#[tauri::command]
pub async fn product_list_resources(
    state: State<'_, BridgeState>,
    request_data: ProductSessionReferenceRequest,
) -> Result<Value, String> {
    session_reference_request(state, "product.resources.list", request_data).await
}

#[tauri::command]
pub async fn product_set_resource_enabled(
    state: State<'_, BridgeState>,
    request_data: ProductResourceSetEnabledRequest,
) -> Result<Value, String> {
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        request(
            &transport,
            "product.resource.set-enabled",
            Map::from_iter([
                ("schemaVersion".into(), Value::from(1)),
                ("sessionId".into(), Value::from(request_data.session_id)),
                (
                    "expectedGeneration".into(),
                    Value::from(request_data.expected_generation),
                ),
                ("resourceId".into(), Value::from(request_data.resource_id)),
                ("enabled".into(), Value::from(request_data.enabled)),
                (
                    "acknowledgedExecutableRisk".into(),
                    Value::from(request_data.acknowledged_executable_risk),
                ),
            ]),
        )
    })
    .await
    .map_err(|_| "resource lifecycle worker failed".to_string())?
}

#[tauri::command]
pub async fn product_install_package(
    state: State<'_, BridgeState>,
    request_data: ProductPackageInstallRequest,
) -> Result<Value, String> {
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        request(
            &transport,
            "product.package.install",
            Map::from_iter([
                ("schemaVersion".into(), Value::from(1)),
                ("sessionId".into(), Value::from(request_data.session_id)),
                (
                    "expectedGeneration".into(),
                    Value::from(request_data.expected_generation),
                ),
                ("source".into(), Value::from(request_data.source)),
                ("scope".into(), Value::from(request_data.scope)),
                ("online".into(), Value::from(request_data.online)),
                (
                    "acknowledgedExecutableRisk".into(),
                    Value::from(request_data.acknowledged_executable_risk),
                ),
            ]),
        )
    })
    .await
    .map_err(|_| "package installation worker failed".to_string())?
}

#[tauri::command]
pub async fn product_mutate_package(
    state: State<'_, BridgeState>,
    request_data: ProductPackageMutationRequest,
) -> Result<Value, String> {
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        request(
            &transport,
            "product.package.mutate",
            Map::from_iter([
                ("schemaVersion".into(), Value::from(1)),
                ("sessionId".into(), Value::from(request_data.session_id)),
                (
                    "expectedGeneration".into(),
                    Value::from(request_data.expected_generation),
                ),
                ("resourceId".into(), Value::from(request_data.resource_id)),
                ("operation".into(), Value::from(request_data.operation)),
                ("online".into(), Value::from(request_data.online)),
                (
                    "acknowledgedExecutableRisk".into(),
                    Value::from(request_data.acknowledged_executable_risk),
                ),
            ]),
        )
    })
    .await
    .map_err(|_| "package lifecycle worker failed".to_string())?
}

#[tauri::command]
pub async fn product_save_setting(
    state: State<'_, BridgeState>,
    request_data: ProductSettingSaveRequest,
) -> Result<Value, String> {
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        request(
            &transport,
            "product.setting.save",
            Map::from_iter([
                ("schemaVersion".into(), Value::from(1)),
                ("sessionId".into(), Value::from(request_data.session_id)),
                (
                    "expectedGeneration".into(),
                    Value::from(request_data.expected_generation),
                ),
                ("key".into(), Value::from(request_data.key)),
                ("value".into(), request_data.value),
                ("scope".into(), Value::from(request_data.scope)),
                (
                    "expectedRevision".into(),
                    Value::from(request_data.expected_revision),
                ),
            ]),
        )
    })
    .await
    .map_err(|_| "setting save worker failed".to_string())?
}

#[tauri::command]
pub async fn product_preview_setting_reset(
    state: State<'_, BridgeState>,
    request_data: ProductSettingPreviewRequest,
) -> Result<Value, String> {
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        request(
            &transport,
            "product.setting.reset-preview",
            Map::from_iter([
                ("schemaVersion".into(), Value::from(1)),
                ("sessionId".into(), Value::from(request_data.session_id)),
                (
                    "expectedGeneration".into(),
                    Value::from(request_data.expected_generation),
                ),
                ("key".into(), Value::from(request_data.key)),
            ]),
        )
    })
    .await
    .map_err(|_| "setting reset preview worker failed".to_string())?
}

#[tauri::command]
pub async fn product_queue_follow_up(
    state: State<'_, BridgeState>,
    request_data: ProductQueueFollowUpRequest,
) -> Result<Value, String> {
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        request(
            &transport,
            "product.queue.followup",
            Map::from_iter([
                ("schemaVersion".into(), Value::from(1)),
                ("sessionId".into(), Value::from(request_data.session_id)),
                (
                    "expectedGeneration".into(),
                    Value::from(request_data.expected_generation),
                ),
                ("text".into(), Value::from(request_data.text)),
            ]),
        )
    })
    .await
    .map_err(|_| "queue worker failed".to_string())?
}

#[tauri::command]
pub async fn product_replace_follow_up_queue(
    state: State<'_, BridgeState>,
    request_data: ProductQueueReplaceRequest,
) -> Result<Value, String> {
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        request(
            &transport,
            "product.queue.replace",
            Map::from_iter([
                ("schemaVersion".into(), Value::from(1)),
                ("sessionId".into(), Value::from(request_data.session_id)),
                (
                    "expectedGeneration".into(),
                    Value::from(request_data.expected_generation),
                ),
                (
                    "texts".into(),
                    Value::Array(request_data.texts.into_iter().map(Value::from).collect()),
                ),
            ]),
        )
    })
    .await
    .map_err(|_| "queue replacement worker failed".to_string())?
}

#[tauri::command]
pub async fn product_auth_start(
    app: AppHandle,
    state: State<'_, BridgeState>,
    request_data: ProductAuthStartRequest,
) -> Result<(), String> {
    let transport = state.inner().clone();
    transport.initialise_event_output(app)?;
    let envelope = Envelope {
        version: 1,
        kind: ProtocolKind::Request,
        id: request_data.request_id,
        correlation_id: None,
        decision_id: None,
        sequence: 1,
        payload: Map::from_iter([
            ("method".into(), Value::from("product.auth.start")),
            ("schemaVersion".into(), Value::from(1)),
            ("providerId".into(), Value::from(request_data.provider_id)),
            ("authMethod".into(), Value::from("subscription")),
        ]),
        error: None,
    };
    tauri::async_runtime::spawn_blocking(move || {
        super::stream::run_stream_transport_receipted(&transport, envelope, |generation, event| {
            if event.kind == ProtocolKind::Ack {
                transport
                    .enqueue_ack_event(generation, event)
                    .map(DeliveryAcceptance::Receipt)
            } else {
                transport
                    .enqueue_event(generation, event)
                    .map(|()| DeliveryAcceptance::Immediate)
            }
        })
    })
    .await
    .map_err(|_| "authentication worker failed".to_string())?
}

#[tauri::command]
pub async fn product_session_export(
    window: WebviewWindow,
    state: State<'_, BridgeState>,
    request_data: ProductSessionExportRequest,
) -> Result<bool, String> {
    let Some(destination) =
        crate::platform::present_native_export_picker(window, "PIUI-session.jsonl".into())
            .await
            .map_err(|error| error.code().to_string())?
    else {
        return Ok(false);
    };
    let path = destination
        .to_str()
        .ok_or_else(|| "session-export-destination-invalid".to_string())?
        .to_owned();
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        let result = request(
            &transport,
            "product.session.export",
            Map::from_iter([
                ("schemaVersion".into(), Value::from(1)),
                ("sessionId".into(), Value::from(request_data.session_id)),
                (
                    "expectedGeneration".into(),
                    Value::from(request_data.expected_generation),
                ),
                ("privatePath".into(), Value::from(path)),
            ]),
        )?;
        result
            .get("exported")
            .and_then(Value::as_bool)
            .filter(|exported| *exported)
            .map(|_| true)
            .ok_or_else(|| "session-export-failed".to_string())
    })
    .await
    .map_err(|_| "session export worker failed".to_string())?
}

async fn session_reference_request(
    state: State<'_, BridgeState>,
    method: &'static str,
    request_data: ProductSessionReferenceRequest,
) -> Result<Value, String> {
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        request(
            &transport,
            method,
            Map::from_iter([
                ("schemaVersion".into(), Value::from(1)),
                ("sessionId".into(), Value::from(request_data.session_id)),
                (
                    "expectedGeneration".into(),
                    Value::from(request_data.expected_generation),
                ),
            ]),
        )
    })
    .await
    .map_err(|_| "session operation worker failed".to_string())?
}

async fn change_request(
    state: State<'_, BridgeState>,
    method: &'static str,
    request_data: ProductChangeRequest,
) -> Result<Value, String> {
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        request(&transport, method, change_payload(request_data))
    })
    .await
    .map_err(|_| "change operation worker failed".to_string())?
}

fn change_payload(request_data: ProductChangeRequest) -> Map<String, Value> {
    Map::from_iter([
        ("schemaVersion".into(), Value::from(1)),
        ("sessionId".into(), Value::from(request_data.session_id)),
        (
            "expectedGeneration".into(),
            Value::from(request_data.expected_generation),
        ),
        ("changeId".into(), Value::from(request_data.change_id)),
    ])
}

#[tauri::command]
pub async fn product_turn_start(
    app: AppHandle,
    state: State<'_, BridgeState>,
    attachments: State<'_, AttachmentRegistry>,
    request_data: ProductTurnStartRequest,
) -> Result<(), String> {
    let transport = state.inner().clone();
    transport.initialise_event_output(app)?;
    if request_data.attachment_capabilities.len() > 8 {
        return Err("attachment-count-unsupported".into());
    }
    let attachment_payload = request_data
        .attachment_capabilities
        .iter()
        .map(|capability_id| {
            let (view, path) = attachments.transport_descriptor(capability_id)?;
            let path = path
                .to_str()
                .ok_or_else(|| "attachment-path-unavailable".to_string())?;
            Ok(Value::Object(Map::from_iter([
                ("capabilityId".into(), Value::from(view.capability_id)),
                ("mime".into(), Value::from(view.mime)),
                ("byteLength".into(), Value::from(view.byte_length)),
                ("privatePath".into(), Value::from(path)),
            ])))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let envelope = Envelope {
        version: 1,
        kind: ProtocolKind::Request,
        id: request_data.request_id,
        correlation_id: None,
        decision_id: None,
        sequence: 1,
        payload: Map::from_iter([
            ("method".into(), Value::from("product.turn.start")),
            ("schemaVersion".into(), Value::from(1)),
            ("sessionId".into(), Value::from(request_data.session_id)),
            ("generation".into(), Value::from(request_data.generation)),
            ("text".into(), Value::from(request_data.text)),
            (
                "retryPrevious".into(),
                Value::from(request_data.retry_previous),
            ),
            ("attachments".into(), Value::Array(attachment_payload)),
        ]),
        error: None,
    };
    // Everything up to and including writing the request is awaited, so a
    // turn that cannot start rejects this command. The turn itself runs on
    // after the command returns; if it fails later the interface receives a
    // `stream.failed` terminal instead of waiting for one that never comes.
    let starting = transport.clone();
    let opened = tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&starting)?;
        super::stream::open_stream(&starting, envelope)
    })
    .await
    .map_err(|_| "turn start worker failed".to_string())??;
    tauri::async_runtime::spawn_blocking(move || {
        let result = super::stream::drive_stream_transport_receipted(
            opened,
            super::stream::FailureNotice::Project,
            |generation, event| {
                if event.kind == ProtocolKind::Ack {
                    transport
                        .enqueue_ack_event(generation, event)
                        .map(DeliveryAcceptance::Receipt)
                } else {
                    transport
                        .enqueue_event(generation, event)
                        .map(|()| DeliveryAcceptance::Immediate)
                }
            },
        );
        if let Err(reason) = result {
            // Fixed host strings only; no payload or path reaches the log.
            eprintln!("PIUI product turn ended early reason={reason}");
        }
    });
    Ok(())
}

#[tauri::command]
pub async fn product_turn_stop(
    state: State<'_, BridgeState>,
    request_data: ProductTurnStopRequest,
) -> Result<(), String> {
    let cancellation = Envelope {
        version: 1,
        kind: ProtocolKind::Cancel,
        id: format!("web-stop-{}", uuid::Uuid::new_v4().simple()),
        correlation_id: Some(request_data.request_id),
        decision_id: None,
        sequence: 1,
        payload: Map::new(),
        error: None,
    };
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        super::stream::cancel_stream_transport(&transport, cancellation)
    })
    .await
    .map_err(|_| "turn stop worker failed".to_string())?
}

#[tauri::command]
pub async fn product_diagnostics(state: State<'_, BridgeState>) -> Result<Value, String> {
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        bridge_start_transport(&transport)?;
        request(&transport, "product.diagnostics", Map::new())
    })
    .await
    .map_err(|_| "diagnostics worker failed".to_string())?
}

fn request(
    state: &BridgeState,
    method: &str,
    payload: Map<String, Value>,
) -> Result<Value, String> {
    let supervisor = state.supervisor();
    let generation = supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?
        .current_generation()
        .ok_or_else(|| "sidecar unavailable".to_string())?;
    let waiter = supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?
        .begin_product_request(generation, method, payload)?;
    debug_assert_eq!(waiter.generation(), generation);
    let envelope = waiter.wait(product_request_timeout(method))?;
    if let Some(error) = envelope.error.as_ref() {
        return Err(product_error_code(&error.message));
    }
    Ok(Value::Object(envelope.payload))
}

/// Compaction is a model call and package operations may reach the network,
/// so they get longer than the default budget. A waiter that still times out
/// leaves the sidecar running; its late response is discarded.
fn product_request_timeout(method: &str) -> Duration {
    match method {
        "product.session.compact" | "product.package.install" | "product.package.mutate" => {
            PRODUCT_LONG_REQUEST_TIMEOUT
        }
        _ => PRODUCT_REQUEST_TIMEOUT,
    }
}

/// The sidecar reports product failures as stable kebab-case codes the
/// interface can explain. Anything else could carry paths or provider text,
/// so it collapses to one generic code before reaching the WebView.
fn product_error_code(message: &str) -> String {
    let bytes = message.as_bytes();
    let code_shaped = (3..=64).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
    if code_shaped {
        message.to_owned()
    } else {
        "product-operation-failed".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_error_codes_reach_the_interface_only_when_code_shaped() {
        for code in [
            "session-generation-stale",
            "provider-auth-required",
            "abc",
            "model2-unavailable",
            &format!("a{}", "b".repeat(63)),
        ] {
            assert_eq!(product_error_code(code), code);
        }
        for rejected in [
            "",
            "ab",
            "Session-stale",
            "1session",
            "-session",
            "session stale",
            "session_stale",
            "/Users/someone/.pi/agent/auth.json",
            "failed: ENOENT",
            "sessión-stale",
            &format!("a{}", "b".repeat(64)),
        ] {
            assert_eq!(
                product_error_code(rejected),
                "product-operation-failed",
                "{rejected:?} must not reach the interface"
            );
        }
    }

    #[test]
    fn model_and_network_product_calls_outlive_the_default_budget() {
        assert_eq!(
            product_request_timeout("product.session.compact"),
            PRODUCT_LONG_REQUEST_TIMEOUT
        );
        assert_eq!(
            product_request_timeout("product.package.install"),
            PRODUCT_LONG_REQUEST_TIMEOUT
        );
        assert_eq!(
            product_request_timeout("product.sessions.list"),
            PRODUCT_REQUEST_TIMEOUT
        );
        assert!(PRODUCT_LONG_REQUEST_TIMEOUT >= Duration::from_secs(300));
    }

    #[test]
    fn session_trash_root_is_the_shared_pi_agent_directory() {
        let home = Path::new("/Users/example");
        assert_eq!(
            session_root_within(home),
            Path::new("/Users/example/.pi/agent/sessions")
        );
    }
}
