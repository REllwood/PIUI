use super::ack_settlement::AckSettlement;
use super::event_output::{EventOutputQueue, EventReceipt};
use super::projector::{PublicOperationClass, WebViewProjector};
use crate::domain::approval::ApprovalRegistry;
use crate::domain::workspace::WorkspaceRegistry;
use crate::protocol::{Envelope, ProtocolKind, validate_envelope};
use crate::supervisor::{
    NODE_VERSION, PI_VERSION, PROTOCOL_VERSION, RestartController, SidecarStatus,
    SidecarSupervisor, SupervisorPaths,
};
use serde_json::Value;
use std::sync::{Arc, Mutex, mpsc::Receiver};
use tauri::{AppHandle, State};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcknowledgementAbandonment {
    Won,
    AlreadySettled,
}

pub(crate) enum DeliveryAcceptance {
    Immediate,
    Receipt(EventReceipt),
}

#[derive(Clone)]
pub struct BridgeState {
    supervisor: Arc<Mutex<SidecarSupervisor>>,
    restart: Arc<Mutex<RestartController>>,
    paths: SupervisorPaths,
    acknowledgement_settlement: AckSettlement,
    projector: Arc<WebViewProjector>,
    event_output: Arc<EventOutputQueue>,
    approval_registry: Arc<ApprovalRegistry>,
    workspace_registry: Arc<WorkspaceRegistry>,
}

impl BridgeState {
    pub fn new(paths: SupervisorPaths) -> Self {
        let approval_registry = Arc::new(ApprovalRegistry::default());
        let workspace_registry = Arc::new(WorkspaceRegistry::default());
        Self {
            supervisor: Arc::new(Mutex::new(SidecarSupervisor::with_registries(
                Arc::clone(&approval_registry),
                Arc::clone(&workspace_registry),
            ))),
            restart: Arc::new(Mutex::new(RestartController::default())),
            paths,
            acknowledgement_settlement: AckSettlement::default(),
            projector: Arc::new(WebViewProjector::default()),
            event_output: Arc::new(EventOutputQueue::default()),
            approval_registry,
            workspace_registry,
        }
    }

    pub(crate) fn initialise_event_output(&self, app: AppHandle) -> Result<(), String> {
        self.event_output
            .initialise(app, Arc::clone(&self.projector))
    }

    pub(crate) fn enqueue_event(&self, generation: u64, envelope: &Envelope) -> Result<(), String> {
        self.event_output.enqueue(generation, envelope)
    }

    pub(crate) fn enqueue_ack_event(
        &self,
        generation: u64,
        envelope: &Envelope,
    ) -> Result<EventReceipt, String> {
        self.event_output.enqueue_ack_with_receipt(
            generation,
            envelope,
            self.acknowledgement_settlement.clone(),
        )
    }

    pub(crate) fn supervisor(&self) -> Arc<Mutex<SidecarSupervisor>> {
        Arc::clone(&self.supervisor)
    }

    pub(crate) fn register_acknowledgement(
        &self,
        envelope_id: String,
    ) -> Result<Receiver<bool>, String> {
        self.acknowledgement_settlement.register(envelope_id)
    }

    pub(crate) fn remove_acknowledgement(&self, envelope_id: &str) {
        let _ = self.acknowledgement_settlement.remove_pending(envelope_id);
    }

    pub(crate) fn acknowledgement_is_pending(&self, envelope_id: &str) -> bool {
        self.acknowledgement_settlement.is_pending(envelope_id)
    }

    pub(crate) fn activate_generation(&self, generation: u64) -> Result<(), String> {
        self.projector.activate_generation(generation)?;
        Ok(())
    }

    pub(crate) fn deactivate_generation(&self, generation: u64) -> Result<(), String> {
        self.projector.deactivate_generation(generation)?;
        self.workspace_registry.invalidate_generation(generation);
        self.approval_registry.invalidate_generation(generation);
        Ok(())
    }

    pub(crate) fn approval_registry(&self) -> Arc<ApprovalRegistry> {
        Arc::clone(&self.approval_registry)
    }

    pub(crate) fn workspace_registry(&self) -> Arc<WorkspaceRegistry> {
        Arc::clone(&self.workspace_registry)
    }

    pub(crate) fn abandon_acknowledgement(
        &self,
        envelope_id: &str,
        generation: u64,
    ) -> AcknowledgementAbandonment {
        let mut removed = false;
        let _ = self.projector.abandon_public_origin_with_action(
            envelope_id,
            generation,
            PublicOperationClass::Cancellation,
            || {
                removed = self.acknowledgement_settlement.remove_pending(envelope_id);
            },
        );
        if removed {
            AcknowledgementAbandonment::Won
        } else {
            AcknowledgementAbandonment::AlreadySettled
        }
    }

    pub(crate) fn cutoff_generation(&self, generation: u64) -> Result<(), String> {
        let mut supervisor = self
            .supervisor
            .lock()
            .map_err(|_| "sidecar state unavailable".to_string())?;
        self.deactivate_generation(generation)?;
        if supervisor.current_generation() == Some(generation) {
            supervisor.stop()?;
        }
        Ok(())
    }

    fn activate_running_status(&self, status: &SidecarStatus) -> Result<(), String> {
        if status.running {
            let generation = status
                .generation
                .ok_or_else(|| "sidecar generation unavailable".to_string())?;
            self.activate_generation(generation)?;
        }
        Ok(())
    }

    /// Projector delivery runs without supervisor, restart, acknowledgement
    /// or projector locks. Concurrent/re-entrant attempts fail promptly.
    pub(crate) fn project_and_deliver<F, T>(
        &self,
        generation: u64,
        envelope: &Envelope,
        deliver: F,
    ) -> Result<T, String>
    where
        F: FnOnce(&Envelope) -> Result<T, String>,
    {
        self.projector
            .project_and_deliver(generation, envelope, deliver)
    }

    pub(crate) fn project_ack_and_deliver<F>(
        &self,
        generation: u64,
        envelope: &Envelope,
        deliver: F,
    ) -> Result<DeliveryAcceptance, String>
    where
        F: FnOnce(&Envelope) -> Result<DeliveryAcceptance, String>,
    {
        let correlation = envelope
            .correlation_id
            .as_deref()
            .ok_or_else(|| "WebView projection rejected".to_string())?;
        let accepted = envelope
            .payload
            .get("accepted")
            .and_then(Value::as_bool)
            .ok_or_else(|| "WebView projection rejected".to_string())?;
        self.projector.project_and_deliver_authorised(
            generation,
            envelope,
            || self.acknowledgement_is_pending(correlation),
            deliver,
            |delivery| match delivery {
                DeliveryAcceptance::Immediate => (
                    true,
                    self.acknowledgement_settlement
                        .settle(correlation, accepted),
                ),
                DeliveryAcceptance::Receipt(_) => (false, Ok(())),
            },
        )
    }

    pub(crate) fn register_public_origin(
        &self,
        id: &str,
        generation: u64,
        class: PublicOperationClass,
    ) -> Result<(), String> {
        self.projector.register_public_origin(id, generation, class)
    }

    pub(crate) fn abandon_public_origin(
        &self,
        id: &str,
        generation: u64,
        class: PublicOperationClass,
    ) {
        self.projector.abandon_public_origin(id, generation, class);
    }

    pub(crate) fn authenticate_ack(
        &self,
        generation: u64,
        envelope: &Envelope,
    ) -> Result<bool, String> {
        let correlation = envelope.correlation_id.as_deref().unwrap_or_default();
        self.projector.authenticate_ack(
            generation,
            envelope,
            self.acknowledgement_is_pending(correlation),
        )
    }

    fn raw_sequence_for(&self, generation: u64, ui_sequence: u64) -> Result<u64, String> {
        self.projector.raw_sequence_for(generation, ui_sequence)
    }
}

pub fn bridge_start_transport(state: &BridgeState) -> Result<SidecarStatus, String> {
    let mut supervisor = state
        .supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?;
    let previous_generation = supervisor.current_generation();
    let observed = supervisor.status();
    if observed.failed
        && let Some(generation) = previous_generation
    {
        state.deactivate_generation(generation)?;
    }
    let status = if observed.running {
        observed
    } else if observed.failed {
        state
            .restart
            .lock()
            .map_err(|_| "restart state unavailable".to_string())?
            .automatic_restart(&mut supervisor, &state.paths)?
    } else {
        supervisor.start(&state.paths)?
    };
    state.activate_running_status(&status)?;
    Ok(status)
}

const PACKAGED_AUTHENTICATED_READY: &str =
    "PIUI_A21_AUTHENTICATED_SIDECAR_READY protocol=1 node=22.23.1 pi=0.82.0";

fn packaged_readiness_line(status: &SidecarStatus) -> Option<&'static str> {
    (status.running
        && !status.failed
        && status.protocol_version == Some(PROTOCOL_VERSION)
        && status.node_version.as_deref() == Some(NODE_VERSION)
        && status.pi_version.as_deref() == Some(PI_VERSION))
    .then_some(PACKAGED_AUTHENTICATED_READY)
}

#[tauri::command]
pub fn sidecar_start(state: State<'_, BridgeState>) -> Result<SidecarStatus, String> {
    let status = bridge_start_transport(state.inner())?;
    if let Some(line) = packaged_readiness_line(&status) {
        eprintln!("{line}");
    }
    Ok(status)
}

pub fn bridge_status_transport(state: &BridgeState) -> Result<SidecarStatus, String> {
    let mut supervisor = state
        .supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?;
    let previous_generation = supervisor.current_generation();
    let observed = supervisor.status();
    if observed.failed
        && let Some(generation) = previous_generation
    {
        state.deactivate_generation(generation)?;
    }
    let status = if observed.failed {
        state
            .restart
            .lock()
            .map_err(|_| "restart state unavailable".to_string())?
            .automatic_restart(&mut supervisor, &state.paths)?
    } else {
        observed
    };
    state.activate_running_status(&status)?;
    Ok(status)
}

#[tauri::command]
pub fn sidecar_status(state: State<'_, BridgeState>) -> Result<SidecarStatus, String> {
    bridge_status_transport(state.inner())
}

pub fn bridge_restart_transport(state: &BridgeState) -> Result<SidecarStatus, String> {
    let mut supervisor = state
        .supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?;
    if let Some(generation) = supervisor.current_generation() {
        state.deactivate_generation(generation)?;
    }
    let status = state
        .restart
        .lock()
        .map_err(|_| "restart state unavailable".to_string())?
        .user_restart(&mut supervisor, &state.paths)?;
    state.activate_running_status(&status)?;
    Ok(status)
}

#[tauri::command]
pub fn sidecar_restart(state: State<'_, BridgeState>) -> Result<SidecarStatus, String> {
    bridge_restart_transport(state.inner())
}

pub fn bridge_send_transport(state: &BridgeState, envelope: &Envelope) -> Result<(), String> {
    let ui_after_sequence = validate_snapshot_request(envelope)?;

    // Lock order is deliberately non-nested: observe generation, release the
    // supervisor, translate under the projector, release it, then reacquire
    // the supervisor for a generation-checked send.
    let generation = state
        .supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?
        .current_generation()
        .ok_or_else(|| "sidecar unavailable".to_string())?;
    state.activate_generation(generation)?;
    let raw_after_sequence = state.raw_sequence_for(generation, ui_after_sequence)?;
    let outbound = rewrite_snapshot_after_sequence(envelope, raw_after_sequence)?;
    state.register_public_origin(&envelope.id, generation, PublicOperationClass::Snapshot)?;
    let result = state
        .supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())
        .and_then(|mut supervisor| supervisor.send_for_generation(generation, &outbound));
    if result.is_err() {
        state.abandon_public_origin(&envelope.id, generation, PublicOperationClass::Snapshot);
        let _ = state.cutoff_generation(generation);
    }
    result
}

fn validate_snapshot_request(envelope: &Envelope) -> Result<u64, String> {
    if validate_envelope(envelope).is_err()
        || envelope.kind != ProtocolKind::Request
        || envelope.correlation_id.is_some()
        || envelope.decision_id.is_some()
        || envelope.error.is_some()
        || envelope.payload.len() != 2
        || envelope.payload.get("method").and_then(Value::as_str) != Some("snapshot")
    {
        return Err("bridge request is not permitted".into());
    }
    envelope
        .payload
        .get("afterSequence")
        .and_then(Value::as_u64)
        .filter(|sequence| *sequence <= 9_007_199_254_740_991)
        .ok_or_else(|| "bridge request is not permitted".to_string())
}

fn rewrite_snapshot_after_sequence(
    envelope: &Envelope,
    raw_after_sequence: u64,
) -> Result<Envelope, String> {
    validate_snapshot_request(envelope)?;
    let mut outbound = envelope.clone();
    outbound
        .payload
        .insert("afterSequence".into(), Value::from(raw_after_sequence));
    Ok(outbound)
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn bridge_abandon_snapshot_transport_for_test(
    state: &BridgeState,
    id: &str,
) -> Result<(), String> {
    let generation = state
        .supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?
        .current_generation()
        .ok_or_else(|| "sidecar unavailable".to_string())?;
    state.activate_generation(generation)?;
    state.abandon_public_origin(id, generation, PublicOperationClass::Snapshot);
    Ok(())
}

#[tauri::command]
pub fn bridge_send(state: State<'_, BridgeState>, envelope: Envelope) -> Result<(), String> {
    bridge_send_transport(state.inner(), &envelope)
}

pub fn bridge_stop_transport(state: &BridgeState) -> Result<(), String> {
    let mut supervisor = state
        .supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?;
    if let Some(generation) = supervisor.current_generation() {
        state.deactivate_generation(generation)?;
    }
    supervisor.stop()
}

#[tauri::command]
pub fn sidecar_stop(state: State<'_, BridgeState>) -> Result<(), String> {
    bridge_stop_transport(state.inner())
}

#[cfg(test)]
mod tests {
    use super::{
        BridgeState, packaged_readiness_line, rewrite_snapshot_after_sequence,
        validate_snapshot_request,
    };
    use crate::protocol::Envelope;
    use crate::supervisor::{SidecarStatus, SupervisorPaths};
    use serde_json::json;
    use std::path::PathBuf;

    fn inert_paths() -> SupervisorPaths {
        SupervisorPaths {
            node: PathBuf::from("unused-node"),
            resource_root: PathBuf::from("unused-resources"),
            entrypoint: PathBuf::from("unused-entrypoint"),
        }
    }

    fn snapshot_request(after_sequence: u64, outer_sequence: u64) -> Envelope {
        serde_json::from_value(json!({
            "version": 1,
            "kind": "request",
            "id": "web-snapshot-1",
            "sequence": outer_sequence,
            "payload": {"method": "snapshot", "afterSequence": after_sequence}
        }))
        .unwrap()
    }

    #[test]
    fn packaged_readiness_requires_the_exact_authenticated_pins() {
        let ready = SidecarStatus {
            running: true,
            failed: false,
            failure: None,
            generation: Some(1),
            pid: Some(2),
            protocol_version: Some(1),
            node_version: Some("22.23.1".into()),
            pi_version: Some("0.82.0".into()),
        };
        assert_eq!(
            packaged_readiness_line(&ready),
            Some("PIUI_A21_AUTHENTICATED_SIDECAR_READY protocol=1 node=22.23.1 pi=0.82.0")
        );
        let mut stale = ready;
        stale.pi_version = Some("0.81.0".into());
        assert_eq!(packaged_readiness_line(&stale), None);
    }

    #[test]
    fn duplicate_acknowledgement_registration_preserves_the_original_waiter() {
        let state = BridgeState::new(inert_paths());
        let original = state.register_acknowledgement("cancel-1".into()).unwrap();
        assert!(state.register_acknowledgement("cancel-1".into()).is_err());
        state
            .acknowledgement_settlement
            .settle("cancel-1", true)
            .unwrap();
        assert!(original.recv().unwrap());
    }

    #[test]
    fn failed_restart_without_replacement_keeps_old_generation_inactive() {
        let state = BridgeState::new(inert_paths());
        state.activate_generation(1).unwrap();
        state.deactivate_generation(1).unwrap();
        assert!(state.activate_generation(1).is_err());
        assert!(
            state
                .register_public_origin(
                    "web-stale-after-failed-restart",
                    1,
                    super::PublicOperationClass::Stream,
                )
                .is_err()
        );
        state.activate_generation(2).unwrap();
        state
            .register_public_origin(
                "web-replacement-after-failure",
                2,
                super::PublicOperationClass::Stream,
            )
            .unwrap();
    }

    #[test]
    fn snapshot_request_rewrites_only_mapped_after_sequence() {
        let request = snapshot_request(77, 9_000);
        assert_eq!(validate_snapshot_request(&request), Ok(77));
        let outbound = rewrite_snapshot_after_sequence(&request, 12).unwrap();
        assert_eq!(outbound.sequence, 9_000);
        assert_eq!(outbound.payload["afterSequence"], 12);
        assert_eq!(outbound.payload["method"], "snapshot");
        assert_eq!(outbound.id, request.id);

        let mut smuggled = request.clone();
        smuggled
            .payload
            .insert("rawSequence".into(), serde_json::Value::from(123_456));
        assert!(validate_snapshot_request(&smuggled).is_err());

        let mut correlated = request;
        correlated.correlation_id = Some("raw-correlation".into());
        assert!(validate_snapshot_request(&correlated).is_err());

        let workspace_attempt: Envelope = serde_json::from_value(json!({
            "version":1,"kind":"request","id":"web-workspace-forged","sequence":1,
            "payload":{"method":"workspace.loadTrusted","schemaVersion":1,
                "workspaceId":"workspace-0123456789abcdef0123456789abcdef",
                "generation":1,"revision":1,
                "leaseId":"trust-0123456789abcdef0123456789abcdef",
                "snapshotRoot":"/private/canary","agentRoot":"/private/agent"}
        }))
        .unwrap();
        assert!(validate_snapshot_request(&workspace_attempt).is_err());
    }
}
