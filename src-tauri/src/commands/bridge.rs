use crate::protocol::{Envelope, ProtocolKind};
use crate::supervisor::{SidecarStatus, SidecarSupervisor, SupervisorPaths};
use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    mpsc::{Receiver, SyncSender, sync_channel},
};
use tauri::State;

pub struct BridgeState {
    supervisor: Arc<Mutex<SidecarSupervisor>>,
    paths: SupervisorPaths,
    acknowledgement_waiters: Arc<Mutex<HashMap<String, SyncSender<bool>>>>,
}

impl BridgeState {
    pub fn new(paths: SupervisorPaths) -> Self {
        Self {
            supervisor: Arc::new(Mutex::new(SidecarSupervisor::default())),
            paths,
            acknowledgement_waiters: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn supervisor(&self) -> Arc<Mutex<SidecarSupervisor>> {
        Arc::clone(&self.supervisor)
    }

    pub(crate) fn paths(&self) -> SupervisorPaths {
        self.paths.clone()
    }

    pub(crate) fn register_acknowledgement(
        &self,
        envelope_id: String,
    ) -> Result<Receiver<bool>, String> {
        let (sender, receiver) = sync_channel(1);
        let mut waiters = self
            .acknowledgement_waiters
            .lock()
            .map_err(|_| "acknowledgement state unavailable".to_string())?;
        match waiters.entry(envelope_id) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(sender);
                Ok(receiver)
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                Err("acknowledgement already pending".into())
            }
        }
    }

    pub(crate) fn acknowledgement_waiters(&self) -> Arc<Mutex<HashMap<String, SyncSender<bool>>>> {
        Arc::clone(&self.acknowledgement_waiters)
    }

    pub(crate) fn remove_acknowledgement(&self, envelope_id: &str) {
        if let Ok(mut waiters) = self.acknowledgement_waiters.lock() {
            waiters.remove(envelope_id);
        }
    }
}

#[tauri::command]
pub fn sidecar_start(state: State<'_, BridgeState>) -> Result<SidecarStatus, String> {
    let mut supervisor = state
        .supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?;
    let status = supervisor.status();
    if status.running {
        Ok(status)
    } else {
        supervisor.start(&state.paths)
    }
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
pub fn bridge_send(state: State<'_, BridgeState>, envelope: Envelope) -> Result<(), String> {
    if envelope.kind != ProtocolKind::Request
        || envelope
            .payload
            .get("method")
            .and_then(serde_json::Value::as_str)
            != Some("snapshot")
    {
        return Err("bridge request is not permitted".into());
    }
    state
        .supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?
        .send_envelope(&envelope)
}

#[tauri::command]
pub fn sidecar_stop(state: State<'_, BridgeState>) -> Result<(), String> {
    state
        .supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?
        .stop()
}

#[cfg(test)]
mod tests {
    use super::BridgeState;
    use crate::supervisor::SupervisorPaths;

    #[test]
    fn duplicate_acknowledgement_registration_preserves_the_original_waiter() {
        let paths = SupervisorPaths::development().unwrap();
        let state = BridgeState::new(paths);
        let original = state
            .register_acknowledgement("cancel-1".into())
            .unwrap();
        assert!(
            state
                .register_acknowledgement("cancel-1".into())
                .is_err()
        );
        let sender = state
            .acknowledgement_waiters
            .lock()
            .unwrap()
            .remove("cancel-1")
            .unwrap();
        sender.try_send(true).unwrap();
        assert_eq!(original.recv().unwrap(), true);
    }
}
