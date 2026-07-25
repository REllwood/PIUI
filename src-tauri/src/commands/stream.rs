use crate::commands::bridge::BridgeState;
use crate::protocol::Envelope;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, State};

const STREAM_EVENT: &str = "piui://stream-probe";

#[tauri::command]
pub async fn stream_probe(
    app: AppHandle,
    state: State<'_, BridgeState>,
    request_id: String,
) -> Result<(), String> {
    validate_request_id(&request_id)?;
    let supervisor = state.supervisor();
    let paths = state.paths();

    tauri::async_runtime::spawn_blocking(move || {
        {
            let mut supervisor = supervisor
                .lock()
                .map_err(|_| "sidecar state unavailable".to_string())?;
            if !supervisor.status().running {
                supervisor.start(&paths)?;
            }
            let request: Envelope = serde_json::from_value(serde_json::json!({
                "version": 1,
                "kind": "request",
                "id": request_id,
                "sequence": 1,
                "payload": { "method": "stream.fixture" }
            }))
            .map_err(|_| "stream request invalid".to_string())?;
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
            let terminal = envelope
                .payload
                .get("terminal")
                .and_then(serde_json::Value::as_str)
                .is_some();
            app.emit(STREAM_EVENT, &envelope)
                .map_err(|_| "stream event delivery failed".to_string())?;
            if terminal {
                return Ok(());
            }
        }
    })
    .await
    .map_err(|_| "stream worker failed".to_string())?
}

#[tauri::command]
pub fn cancel_stream(
    state: State<'_, BridgeState>,
    request_id: String,
) -> Result<(), String> {
    validate_request_id(&request_id)?;
    let cancellation: Envelope = serde_json::from_value(serde_json::json!({
        "version": 1,
        "kind": "cancel",
        "id": format!("cancel-{request_id}"),
        "correlationId": request_id,
        "sequence": 2,
        "payload": {}
    }))
    .map_err(|_| "cancellation request invalid".to_string())?;
    state
        .supervisor()
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?
        .send_envelope(&cancellation)
}

fn validate_request_id(request_id: &str) -> Result<(), String> {
    if request_id.is_empty()
        || request_id.len() > 80
        || !request_id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
    {
        return Err("stream request identifier invalid".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_request_id;

    #[test]
    fn stream_request_ids_are_bounded() {
        assert!(validate_request_id("stream-probe-1").is_ok());
        assert!(validate_request_id("").is_err());
        assert!(validate_request_id("-bad").is_err());
        assert!(validate_request_id(&"a".repeat(81)).is_err());
    }
}
