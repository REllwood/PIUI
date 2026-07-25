use crate::supervisor::{SidecarStatus, SidecarSupervisor, SupervisorPaths};
use std::sync::{Arc, Mutex};
use tauri::State;

pub struct BridgeState {
    supervisor: Arc<Mutex<SidecarSupervisor>>,
    paths: SupervisorPaths,
}

impl BridgeState {
    pub fn new(paths: SupervisorPaths) -> Self {
        Self {
            supervisor: Arc::new(Mutex::new(SidecarSupervisor::default())),
            paths,
        }
    }

    pub(crate) fn supervisor(&self) -> Arc<Mutex<SidecarSupervisor>> {
        Arc::clone(&self.supervisor)
    }

    pub(crate) fn paths(&self) -> SupervisorPaths {
        self.paths.clone()
    }
}

#[tauri::command]
pub fn sidecar_start(state: State<'_, BridgeState>) -> Result<SidecarStatus, String> {
    state
        .supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?
        .start(&state.paths)
}

#[tauri::command]
pub fn sidecar_status(state: State<'_, BridgeState>) -> Result<SidecarStatus, String> {
    Ok(state
        .supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?
        .status())
}

#[tauri::command]
pub fn sidecar_stop(state: State<'_, BridgeState>) -> Result<(), String> {
    state
        .supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?
        .stop()
}
