use crate::commands::bridge::{BridgeState, bridge_observe_status};
use crate::diagnostics::checks::{CheckStatus, DiagnosticCheck, local_checks};
use crate::diagnostics::environment::{EnvironmentFact, safe_environment};
use crate::storage::atomic_file::{read_json, write_json};
use crate::storage::onboarding::validate_onboarding;
use crate::storage::schema::{ApplicationData, WindowRecord};
use crate::supervisor::{NODE_VERSION, PI_VERSION};
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{State, WebviewWindow};

pub struct AppStorageState {
    path: PathBuf,
    access: Mutex<()>,
}

impl AppStorageState {
    pub fn new(application_data_directory: PathBuf) -> Self {
        Self {
            path: application_data_directory.join("application-data-v1.json"),
            access: Mutex::new(()),
        }
    }

    pub fn persist_window(&self, window: WindowRecord) -> Result<(), String> {
        let _access = self
            .access
            .lock()
            .map_err(|_| "application-data-unavailable")?;
        let mut data = if self.path.exists() {
            read_json::<ApplicationData>(&self.path)?
        } else {
            ApplicationData::default()
        };
        data.window = Some(window);
        data.validate()?;
        validate_onboarding(&data.onboarding)?;
        write_json(&self.path, &data)
    }
}

#[tauri::command]
pub fn app_state_load(state: State<'_, AppStorageState>) -> Result<ApplicationData, String> {
    let _access = state
        .access
        .lock()
        .map_err(|_| "application-data-unavailable")?;
    let data = if state.path.exists() {
        read_json::<ApplicationData>(&state.path)?
    } else {
        ApplicationData::default()
    };
    data.validate()?;
    validate_onboarding(&data.onboarding)?;
    Ok(data)
}

#[tauri::command]
pub fn app_state_save(
    state: State<'_, AppStorageState>,
    data: ApplicationData,
) -> Result<ApplicationData, String> {
    data.validate()?;
    validate_onboarding(&data.onboarding)?;
    let _access = state
        .access
        .lock()
        .map_err(|_| "application-data-unavailable")?;
    write_json(&state.path, &data)?;
    Ok(data)
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsSnapshot {
    checks: Vec<DiagnosticCheck>,
    environment: Vec<EnvironmentFact>,
    logs: Vec<String>,
    /// The recorded generation-fatal reason, verbatim. It is a fixed host
    /// string, so the interface can name it without any redaction of its own.
    helper_failure: Option<String>,
}

fn build_diagnostics_snapshot(
    bridge: &BridgeState,
    network_available: bool,
) -> Result<DiagnosticsSnapshot, String> {
    let status = bridge_observe_status(bridge)?;
    let logs = bridge
        .supervisor()
        .lock()
        .map_err(|_| "diagnostic-log-unavailable".to_string())?
        .diagnostics();
    let mut checks = local_checks(network_available);
    if let Some(sidecar) = checks.iter_mut().find(|check| check.id == "sidecar") {
        sidecar.status = if status.running && !status.failed {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        };
        sidecar.detail = if status.running && !status.failed {
            format!("Bundled Pi {PI_VERSION} is ready on Node {NODE_VERSION}.")
        } else {
            // The recorded reason is a fixed host string with no path or
            // payload in it, so naming it here keeps an exported report able
            // to explain the failure instead of only reporting it.
            match status.failure.as_deref() {
                Some(reason) => {
                    format!("The bundled local Pi helper is unavailable ({reason}).")
                }
                None => "The bundled local Pi helper is unavailable.".into(),
            }
        };
        sidecar.recovery = (!status.running || status.failed)
            .then(|| "Review and confirm a local helper restart.".into());
    }
    let mut environment = safe_environment();
    environment.push(EnvironmentFact {
        key: "piVersion",
        value: PI_VERSION.into(),
        origin: "bundled-sidecar",
    });
    environment.push(EnvironmentFact {
        key: "nodeVersion",
        value: NODE_VERSION.into(),
        origin: "bundled-runtime",
    });
    Ok(DiagnosticsSnapshot {
        checks,
        environment,
        logs: logs.into_iter().take(2_000).collect(),
        helper_failure: status.failure,
    })
}

#[tauri::command]
pub fn diagnostics_snapshot(
    state: State<'_, BridgeState>,
    network_available: bool,
) -> Result<DiagnosticsSnapshot, String> {
    build_diagnostics_snapshot(state.inner(), network_available)
}

#[tauri::command]
pub async fn diagnostics_export(
    window: WebviewWindow,
    state: State<'_, BridgeState>,
    network_available: bool,
) -> Result<bool, String> {
    let Some(destination) =
        crate::platform::present_native_export_picker(window, "PIUI-diagnostics.json".into())
            .await
            .map_err(|error| error.code().to_string())?
    else {
        return Ok(false);
    };
    let snapshot = build_diagnostics_snapshot(state.inner(), network_available)?;
    let bytes = serde_json::to_vec_pretty(&snapshot)
        .map_err(|_| "diagnostics-export-serialisation-failed".to_string())?;
    tauri::async_runtime::spawn_blocking(move || {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(destination)
            .map_err(|_| "diagnostics-export-write-failed".to_string())?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| "diagnostics-export-write-failed".to_string())
    })
    .await
    .map_err(|_| "diagnostics-export-worker-failed".to_string())??;
    Ok(true)
}

#[tauri::command]
pub fn update_status() -> crate::domain::update_state::UpdateState {
    crate::updates::UpdateConfiguration::default().state()
}
