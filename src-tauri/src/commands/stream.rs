use crate::commands::bridge::BridgeState;
use crate::protocol::{Envelope, ProtocolKind};
use crate::supervisor::{SidecarSupervisor, SupervisorPaths};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc::SyncSender};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, State};

const STREAM_EVENT: &str = "piui://stream-probe";

#[tauri::command]
pub async fn stream_probe(
    app: AppHandle,
    state: State<'_, BridgeState>,
    request: Envelope,
) -> Result<(), String> {
    validate_stream_request(&request)?;
    let supervisor = state.supervisor();
    let paths = state.paths();
    let waiters = state.acknowledgement_waiters();

    tauri::async_runtime::spawn_blocking(move || {
        run_stream(supervisor, paths, request, |envelope| {
            resolve_acknowledgement(&waiters, envelope);
            app.emit(STREAM_EVENT, envelope)
                .map_err(|_| "stream event delivery failed".to_string())
        })
    })
    .await
    .map_err(|_| "stream worker failed".to_string())?
}

#[tauri::command]
pub fn cancel_stream(state: State<'_, BridgeState>, cancellation: Envelope) -> Result<(), String> {
    validate_cancellation(&cancellation)?;
    let cancellation_id = cancellation.id.clone();
    let receiver = state.register_acknowledgement(cancellation_id.clone())?;
    if let Err(error) = state
        .supervisor()
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?
        .send_envelope(&cancellation)
    {
        state.remove_acknowledgement(&cancellation_id);
        return Err(error);
    }
    match receiver.recv_timeout(Duration::from_secs(1)) {
        Ok(true) => Ok(()),
        Ok(false) => Err("sidecar did not accept cancellation".into()),
        Err(_) => {
            state.remove_acknowledgement(&cancellation_id);
            Err("cancellation acknowledgement timed out".into())
        }
    }
}

pub fn run_stream<F>(
    supervisor: Arc<Mutex<SidecarSupervisor>>,
    paths: SupervisorPaths,
    request: Envelope,
    mut deliver: F,
) -> Result<(), String>
where
    F: FnMut(&Envelope) -> Result<(), String>,
{
    validate_stream_request(&request)?;
    {
        let mut supervisor = supervisor
            .lock()
            .map_err(|_| "sidecar state unavailable".to_string())?;
        if !supervisor.status().running {
            supervisor.start(&paths)?;
        }
        supervisor.send_envelope(&request)?;
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let result = supervisor
            .lock()
            .map_err(|_| "sidecar state unavailable".to_string())?
            .receive_envelope(Duration::from_millis(100));
        let envelope = match result {
            Ok(envelope) => envelope,
            Err(error) if error == "sidecar receive timed out" && Instant::now() < deadline => {
                continue;
            }
            Err(error) => return Err(error),
        };

        let is_stream_event = envelope.kind == ProtocolKind::Event
            && envelope.correlation_id.as_deref() == Some(request.id.as_str());
        let is_acknowledgement = envelope.kind == ProtocolKind::Ack;
        let is_snapshot = envelope.kind == ProtocolKind::Response
            && envelope
                .payload
                .get("snapshot")
                .is_some_and(serde_json::Value::is_object);
        if !is_stream_event && !is_acknowledgement && !is_snapshot {
            continue;
        }
        deliver(&envelope)?;
        if is_stream_event
            && matches!(
                envelope
                    .payload
                    .get("terminal")
                    .and_then(serde_json::Value::as_str),
                Some("complete" | "cancelled")
            )
        {
            return Ok(());
        }
    }
}

fn resolve_acknowledgement(
    waiters: &Arc<Mutex<HashMap<String, SyncSender<bool>>>>,
    envelope: &Envelope,
) {
    if envelope.kind != ProtocolKind::Ack {
        return;
    }
    let Some(correlation) = envelope.correlation_id.as_deref() else {
        return;
    };
    let sender = waiters
        .lock()
        .ok()
        .and_then(|mut waiters| waiters.remove(correlation));
    if let Some(sender) = sender {
        let accepted = envelope
            .payload
            .get("accepted")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let _ = sender.try_send(accepted);
    }
}

fn validate_stream_request(request: &Envelope) -> Result<(), String> {
    if request.kind != ProtocolKind::Request
        || request
            .payload
            .get("method")
            .and_then(serde_json::Value::as_str)
            != Some("stream.fixture")
        || !valid_id(&request.id)
    {
        return Err("stream request invalid".into());
    }
    Ok(())
}

fn validate_cancellation(cancellation: &Envelope) -> Result<(), String> {
    if cancellation.kind != ProtocolKind::Cancel
        || cancellation
            .correlation_id
            .as_deref()
            .is_none_or(|correlation_id| !valid_id(correlation_id))
        || !valid_id(&cancellation.id)
    {
        return Err("cancellation request invalid".into());
    }
    Ok(())
}

fn valid_id(request_id: &str) -> bool {
    !request_id.is_empty()
        && request_id.len() <= 128
        && request_id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
}

#[cfg(test)]
mod tests {
    use super::{validate_cancellation, validate_stream_request};
    use crate::protocol::Envelope;

    fn envelope(value: serde_json::Value) -> Envelope {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn stream_and_cancellation_requests_are_bounded() {
        let request = envelope(serde_json::json!({
            "version":1,"kind":"request","id":"stream-probe-1","sequence":1,
            "payload":{"method":"stream.fixture"}
        }));
        let cancellation = envelope(serde_json::json!({
            "version":1,"kind":"cancel","id":"cancel-1","correlationId":"stream-probe-1",
            "sequence":2,"payload":{}
        }));
        assert!(validate_stream_request(&request).is_ok());
        assert!(validate_cancellation(&cancellation).is_ok());

        let bad_request = envelope(serde_json::json!({
            "version":1,"kind":"request","id":"stream-probe-1","sequence":1,
            "payload":{"method":"arbitrary"}
        }));
        assert!(validate_stream_request(&bad_request).is_err());

        let bad_correlation = envelope(serde_json::json!({
            "version":1,"kind":"cancel","id":"cancel-1","correlationId":"bad correlation",
            "sequence":2,"payload":{}
        }));
        assert!(validate_cancellation(&bad_correlation).is_err());
    }
}
