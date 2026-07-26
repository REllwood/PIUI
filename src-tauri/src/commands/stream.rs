use crate::commands::bridge::{
    AcknowledgementAbandonment, BridgeState, DeliveryAcceptance, bridge_start_transport,
};
use crate::commands::projector::{PROJECTION_REJECTED, PublicOperationClass};
use crate::protocol::{Envelope, ProtocolKind, validate_envelope};
use std::time::{Duration, Instant};
use tauri::{AppHandle, State};
const STREAM_DEADLINE: Duration = Duration::from_secs(5);
const MAX_STREAM_EVENTS: u64 = 4_096;
const MAX_STREAM_DELTA_UTF16: u64 = 262_144;
const STREAM_DEADLINE_EXCEEDED: &str = "sidecar stream deadline exceeded";
const STREAM_LIMIT_EXCEEDED: &str = "sidecar stream limit exceeded";

#[derive(Default)]
struct StreamBudget {
    events: u64,
    delta_utf16: u64,
}

impl StreamBudget {
    fn observe(&mut self, envelope: &Envelope) -> Result<(), String> {
        self.events = self
            .events
            .checked_add(1)
            .filter(|value| *value <= MAX_STREAM_EVENTS)
            .ok_or_else(|| STREAM_LIMIT_EXCEEDED.to_string())?;
        let mut units = 0_u64;
        if envelope
            .payload
            .get("eventType")
            .and_then(serde_json::Value::as_str)
            == Some("stream.delta")
        {
            units = envelope
                .payload
                .get("text")
                .and_then(serde_json::Value::as_str)
                .map(|text| text.encode_utf16().count() as u64)
                .ok_or_else(|| STREAM_LIMIT_EXCEEDED.to_string())?;
        } else if envelope.kind == ProtocolKind::Response
            && let Some(streams) = envelope
                .payload
                .get("snapshot")
                .and_then(serde_json::Value::as_object)
                .and_then(|snapshot| snapshot.get("state"))
                .and_then(serde_json::Value::as_object)
                .and_then(|state| state.get("streams"))
                .and_then(serde_json::Value::as_object)
        {
            for stream in streams.values() {
                let text_units = stream
                    .as_object()
                    .and_then(|stream| stream.get("text"))
                    .and_then(serde_json::Value::as_str)
                    .map(|text| text.encode_utf16().count() as u64)
                    .ok_or_else(|| STREAM_LIMIT_EXCEEDED.to_string())?;
                units = units
                    .checked_add(text_units)
                    .ok_or_else(|| STREAM_LIMIT_EXCEEDED.to_string())?;
            }
        }
        self.delta_utf16 = self
            .delta_utf16
            .checked_add(units)
            .filter(|value| *value <= MAX_STREAM_DELTA_UTF16)
            .ok_or_else(|| STREAM_LIMIT_EXCEEDED.to_string())?;
        Ok(())
    }
}

#[tauri::command]
pub async fn stream_probe(
    app: AppHandle,
    state: State<'_, BridgeState>,
    request: Envelope,
) -> Result<(), String> {
    let transport = state.inner().clone();
    transport.initialise_event_output(app)?;
    tauri::async_runtime::spawn_blocking(move || {
        run_stream_transport_receipted(&transport, request, |generation, envelope| {
            if envelope.kind == ProtocolKind::Ack {
                transport
                    .enqueue_ack_event(generation, envelope)
                    .map(DeliveryAcceptance::Receipt)
            } else {
                transport
                    .enqueue_event(generation, envelope)
                    .map(|()| DeliveryAcceptance::Immediate)
            }
        })
    })
    .await
    .map_err(|_| "stream worker failed".to_string())?
}

#[tauri::command]
pub fn cancel_stream(state: State<'_, BridgeState>, cancellation: Envelope) -> Result<(), String> {
    cancel_stream_transport(state.inner(), cancellation)
}

pub fn cancel_stream_transport(state: &BridgeState, cancellation: Envelope) -> Result<(), String> {
    validate_cancellation(&cancellation)?;
    let cancellation_id = cancellation.id.clone();
    let generation = state
        .supervisor()
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?
        .current_generation()
        .ok_or_else(|| "sidecar unavailable".to_string())?;
    state.activate_generation(generation)?;
    let receiver = state.register_acknowledgement(cancellation_id.clone())?;
    if let Err(error) = state.register_public_origin(
        &cancellation_id,
        generation,
        PublicOperationClass::Cancellation,
    ) {
        state.remove_acknowledgement(&cancellation_id);
        return Err(error);
    }
    let send_result = state
        .supervisor()
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())
        .and_then(|mut supervisor| supervisor.send_for_generation(generation, &cancellation));
    if let Err(error) = send_result {
        state.abandon_acknowledgement(&cancellation_id, generation);
        let _ = state.cutoff_generation(generation);
        return Err(error);
    }
    match receiver.recv_timeout(Duration::from_secs(1)) {
        Ok(true) => Ok(()),
        Ok(false) => Err("sidecar did not accept cancellation".into()),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            finish_timed_out_acknowledgement(state, generation, &cancellation_id, &receiver)
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err("cancellation acknowledgement timed out".into())
        }
    }
}

fn finish_timed_out_acknowledgement(
    state: &BridgeState,
    generation: u64,
    cancellation_id: &str,
    receiver: &std::sync::mpsc::Receiver<bool>,
) -> Result<(), String> {
    match state.abandon_acknowledgement(cancellation_id, generation) {
        AcknowledgementAbandonment::Won => Err("cancellation acknowledgement timed out".into()),
        AcknowledgementAbandonment::AlreadySettled => {
            match receiver.recv_timeout(Duration::from_millis(25)) {
                Ok(true) => Ok(()),
                Ok(false) => Err("sidecar did not accept cancellation".into()),
                Err(_) => Err("cancellation acknowledgement unavailable".into()),
            }
        }
    }
}

pub fn run_stream_transport<F>(
    state: &BridgeState,
    request: Envelope,
    mut deliver: F,
) -> Result<(), String>
where
    F: FnMut(&Envelope) -> Result<(), String>,
{
    run_stream_transport_receipted(state, request, |_, envelope| {
        deliver(envelope).map(|()| DeliveryAcceptance::Immediate)
    })
}

fn run_stream_transport_receipted<F>(
    state: &BridgeState,
    request: Envelope,
    mut deliver: F,
) -> Result<(), String>
where
    F: FnMut(u64, &Envelope) -> Result<DeliveryAcceptance, String>,
{
    bridge_start_transport(state)?;
    run_stream(state, request, |generation, envelope, remaining| {
        project_stream_delivery(state, generation, envelope, remaining, |safe| {
            deliver(generation, safe)
        })
    })
}

fn project_stream_delivery<F>(
    state: &BridgeState,
    generation: u64,
    envelope: &Envelope,
    remaining: Duration,
    deliver: F,
) -> Result<(), String>
where
    F: FnOnce(&Envelope) -> Result<DeliveryAcceptance, String>,
{
    if envelope.kind == ProtocolKind::Ack {
        match state.authenticate_ack(generation, envelope) {
            Ok(_) => {}
            Err(error) if error == PROJECTION_REJECTED => return Ok(()),
            Err(error) => return Err(error),
        }
        let delivery = match state.project_ack_and_deliver(generation, envelope, deliver) {
            Ok(delivery) => delivery,
            Err(error) if error == PROJECTION_REJECTED => return Ok(()),
            Err(error) => return Err(error),
        };
        return match delivery {
            DeliveryAcceptance::Receipt(receipt) => match receipt.recv_timeout(remaining) {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) if error == PROJECTION_REJECTED => Ok(()),
                Ok(Err(error)) => Err(error),
                Err(_) => Err(STREAM_DEADLINE_EXCEEDED.into()),
            },
            DeliveryAcceptance::Immediate => Ok(()),
        };
    }
    match state.project_and_deliver(generation, envelope, deliver) {
        Err(error) if error == PROJECTION_REJECTED => {
            let terminal = envelope.kind == ProtocolKind::Event
                && envelope
                    .payload
                    .get("terminal")
                    .and_then(serde_json::Value::as_str)
                    .is_some();
            if terminal {
                Err("stream terminal projection failed".into())
            } else {
                Ok(())
            }
        }
        Ok(_) => Ok(()),
        Err(error) => Err(error),
    }
}

struct StreamOriginGuard<'a> {
    state: &'a BridgeState,
    id: &'a str,
    generation: u64,
    armed: bool,
}

impl StreamOriginGuard<'_> {
    fn complete(mut self) {
        self.armed = false;
    }
}

impl Drop for StreamOriginGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.state.abandon_public_origin(
                self.id,
                self.generation,
                PublicOperationClass::Stream,
            );
        }
    }
}

fn run_stream<F>(state: &BridgeState, request: Envelope, mut deliver: F) -> Result<(), String>
where
    F: FnMut(u64, &Envelope, Duration) -> Result<(), String>,
{
    validate_stream_request(&request)?;
    let supervisor = state.supervisor();
    let (previous_generation, status) = {
        let mut supervisor = supervisor
            .lock()
            .map_err(|_| "sidecar state unavailable".to_string())?;
        let previous_generation = supervisor.current_generation();
        (previous_generation, supervisor.status())
    };
    if !status.running || status.failed {
        if let Some(generation) = previous_generation {
            let _ = state.cutoff_generation(generation);
        }
        return Err("sidecar unavailable".into());
    }
    let generation = status
        .generation
        .ok_or_else(|| "sidecar generation unavailable".to_string())?;
    state.activate_generation(generation)?;
    state.register_public_origin(&request.id, generation, PublicOperationClass::Stream)?;
    let guard = StreamOriginGuard {
        state,
        id: &request.id,
        generation,
        armed: true,
    };
    let send_result = supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?
        .send_for_generation(generation, &request);
    if let Err(error) = send_result {
        let _ = state.cutoff_generation(generation);
        return Err(error);
    }

    let result = run_stream_loop(
        generation,
        &request.id,
        Instant::now() + STREAM_DEADLINE,
        |timeout| {
            supervisor
                .lock()
                .map_err(|_| "sidecar state unavailable".to_string())?
                .receive_for_generation(generation, timeout)
        },
        &mut deliver,
    );
    if result.is_ok() {
        guard.complete();
    } else {
        let _ = state.cutoff_generation(generation);
    }
    result
}

fn run_stream_loop<R, D>(
    generation: u64,
    request_id: &str,
    deadline: Instant,
    mut receive: R,
    mut deliver: D,
) -> Result<(), String>
where
    R: FnMut(Duration) -> Result<Envelope, String>,
    D: FnMut(u64, &Envelope, Duration) -> Result<(), String>,
{
    let mut budget = StreamBudget::default();
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(STREAM_DEADLINE_EXCEEDED.into());
        }
        let receive_timeout = deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(100));
        let envelope = match receive(receive_timeout) {
            Ok(envelope) => {
                if Instant::now() >= deadline {
                    return Err(STREAM_DEADLINE_EXCEEDED.into());
                }
                envelope
            }
            Err(error) if error == "sidecar receive timed out" => {
                if Instant::now() >= deadline {
                    return Err(STREAM_DEADLINE_EXCEEDED.into());
                }
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(error) => return Err(error),
        };

        let is_stream_event = envelope.kind == ProtocolKind::Event
            && envelope.correlation_id.as_deref() == Some(request_id);
        let is_acknowledgement = envelope.kind == ProtocolKind::Ack;
        let is_snapshot = envelope.kind == ProtocolKind::Response
            && envelope
                .payload
                .get("snapshot")
                .is_some_and(serde_json::Value::is_object);
        if !is_stream_event && !is_acknowledgement && !is_snapshot {
            continue;
        }
        budget.observe(&envelope)?;
        if Instant::now() >= deadline {
            return Err(STREAM_DEADLINE_EXCEEDED.into());
        }
        deliver(
            generation,
            &envelope,
            deadline.saturating_duration_since(Instant::now()),
        )?;
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
        std::thread::yield_now();
    }
}

fn validate_stream_request(request: &Envelope) -> Result<(), String> {
    if validate_envelope(request).is_err()
        || request.kind != ProtocolKind::Request
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
    if validate_envelope(cancellation).is_err()
        || cancellation.kind != ProtocolKind::Cancel
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
    request_id.starts_with("web-")
        && !request_id.is_empty()
        && request_id.len() <= 128
        && request_id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
}

#[cfg(test)]
mod tests {
    use super::{
        AcknowledgementAbandonment, DeliveryAcceptance, MAX_STREAM_DELTA_UTF16, MAX_STREAM_EVENTS,
        PublicOperationClass, STREAM_LIMIT_EXCEEDED, StreamBudget,
        finish_timed_out_acknowledgement, project_stream_delivery, run_stream_loop,
        validate_cancellation, validate_stream_request,
    };
    use crate::commands::bridge::BridgeState;
    use crate::protocol::Envelope;
    use crate::supervisor::SupervisorPaths;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    fn envelope(value: serde_json::Value) -> Envelope {
        serde_json::from_value(value).unwrap()
    }

    fn inert_paths() -> SupervisorPaths {
        SupervisorPaths {
            node: PathBuf::from("unused-node"),
            resource_root: PathBuf::from("unused-resources"),
            entrypoint: PathBuf::from("unused-entrypoint"),
        }
    }

    #[test]
    fn stream_and_cancellation_requests_are_bounded() {
        let request = envelope(serde_json::json!({
            "version":1,"kind":"request","id":"web-stream-probe-1","sequence":1,
            "payload":{"method":"stream.fixture"}
        }));
        let cancellation = envelope(serde_json::json!({
            "version":1,"kind":"cancel","id":"web-cancel-1","correlationId":"web-stream-probe-1",
            "sequence":2,"payload":{}
        }));
        assert!(validate_stream_request(&request).is_ok());
        assert!(validate_cancellation(&cancellation).is_ok());

        let bad_request = envelope(serde_json::json!({
            "version":1,"kind":"request","id":"web-stream-probe-1","sequence":1,
            "payload":{"method":"arbitrary"}
        }));
        assert!(validate_stream_request(&bad_request).is_err());

        let bad_correlation = envelope(serde_json::json!({
            "version":1,"kind":"cancel","id":"cancel-1","correlationId":"bad correlation",
            "sequence":2,"payload":{}
        }));
        assert!(validate_cancellation(&bad_correlation).is_err());
    }

    #[test]
    fn uninterrupted_stream_events_and_utf16_deltas_have_fixed_aggregate_bounds() {
        let maximum_delta = envelope(serde_json::json!({
            "version":1,"kind":"event","id":"sidecar-delta","correlationId":"stream-probe-1",
            "sequence":1,"payload":{"eventType":"stream.delta","text":"x".repeat(8_192)}
        }));
        let mut text_budget = StreamBudget::default();
        for _ in 0..(MAX_STREAM_DELTA_UTF16 / 8_192) {
            assert!(text_budget.observe(&maximum_delta).is_ok());
        }
        assert_eq!(
            text_budget.observe(&maximum_delta),
            Err(STREAM_LIMIT_EXCEEDED.into())
        );

        let empty_delta = envelope(serde_json::json!({
            "version":1,"kind":"event","id":"sidecar-empty","correlationId":"stream-probe-1",
            "sequence":1,"payload":{"eventType":"stream.delta","text":""}
        }));
        let mut event_budget = StreamBudget::default();
        for _ in 0..MAX_STREAM_EVENTS {
            assert!(event_budget.observe(&empty_delta).is_ok());
        }
        assert_eq!(
            event_budget.observe(&empty_delta),
            Err(STREAM_LIMIT_EXCEEDED.into())
        );

        let mut overflow_budget = StreamBudget {
            events: 0,
            delta_utf16: u64::MAX,
        };
        assert_eq!(
            overflow_budget.observe(&maximum_delta),
            Err(STREAM_LIMIT_EXCEEDED.into())
        );
    }

    #[test]
    fn actual_run_loop_bounds_uninterrupted_ack_and_repeated_snapshot_delivery() {
        let mut ack_index = 0_u64;
        let mut delivered_acks = 0_u64;
        let ack_result = run_stream_loop(
            1,
            "web-stream-probe-1",
            Instant::now() + Duration::from_secs(2),
            |_| {
                ack_index += 1;
                Ok(envelope(serde_json::json!({
                    "version":1,"kind":"ack","id":format!("sidecar-ack-{ack_index}"),
                    "correlationId":format!("web-cancel-{ack_index}"),"sequence":ack_index,
                    "payload":{"accepted":true}
                })))
            },
            |_, _, _| {
                delivered_acks += 1;
                Ok(())
            },
        );
        assert_eq!(ack_result, Err(STREAM_LIMIT_EXCEEDED.into()));
        assert_eq!(delivered_acks, MAX_STREAM_EVENTS);

        let streams = (0..32)
            .map(|index| {
                (
                    format!("web-stream-{index}"),
                    serde_json::json!({"text":"x".repeat(8_192)}),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let snapshot = envelope(serde_json::json!({
            "version":1,"kind":"response","id":"sidecar-snapshot","correlationId":"web-snapshot-1",
            "sequence":1,"payload":{"snapshot":{"sequence":1,"state":{"status":"ready","streams":streams}}}
        }));
        let mut delivered_snapshots = 0;
        let snapshot_result = run_stream_loop(
            1,
            "web-stream-probe-1",
            Instant::now() + Duration::from_secs(2),
            |_| Ok(snapshot.clone()),
            |_, _, _| {
                delivered_snapshots += 1;
                Ok(())
            },
        );
        assert_eq!(snapshot_result, Err(STREAM_LIMIT_EXCEEDED.into()));
        assert_eq!(delivered_snapshots, 1);
    }

    #[test]
    fn acknowledgement_settles_only_after_exact_projection_and_successful_delivery() {
        let state = BridgeState::new(inert_paths());
        state.activate_generation(1).unwrap();
        let receiver = state
            .register_acknowledgement("web-cancel-auth-1".into())
            .unwrap();
        state
            .register_public_origin("web-cancel-auth-1", 1, PublicOperationClass::Cancellation)
            .unwrap();
        let mut ack = envelope(serde_json::json!({
            "version":1,"kind":"ack","id":"sidecar-ack-1",
            "correlationId":"web-cancel-auth-1","sequence":1,
            "payload":{"accepted":true}
        }));
        ack.payload.insert("extra".into(), serde_json::json!(true));
        assert!(
            project_stream_delivery(&state, 1, &ack, Duration::from_secs(1), |_| Ok(
                DeliveryAcceptance::Immediate
            ),)
            .is_ok()
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        ack.payload.remove("extra");
        assert!(
            project_stream_delivery(&state, 1, &ack, Duration::from_secs(1), |_| Err(
                "test delivery failed".into()
            ),)
            .is_err()
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        assert!(
            project_stream_delivery(&state, 1, &ack, Duration::from_secs(1), |_| Ok(
                DeliveryAcceptance::Immediate
            ),)
            .is_ok()
        );
        assert_eq!(receiver.recv_timeout(Duration::from_secs(1)), Ok(true));
        assert!(
            state
                .register_public_origin("web-cancel-auth-1", 1, PublicOperationClass::Cancellation,)
                .is_err()
        );
    }

    #[test]
    fn failed_ack_emit_receipt_never_settles_native_waiter() {
        let state = BridgeState::new(inert_paths());
        state.activate_generation(1).unwrap();
        let receiver = state
            .register_acknowledgement("web-cancel-emit-fail".into())
            .unwrap();
        state
            .register_public_origin(
                "web-cancel-emit-fail",
                1,
                PublicOperationClass::Cancellation,
            )
            .unwrap();
        let ack = envelope(serde_json::json!({
            "version":1,"kind":"ack","id":"sidecar-emit-fail",
            "correlationId":"web-cancel-emit-fail","sequence":1,
            "payload":{"accepted":true}
        }));
        assert_eq!(
            project_stream_delivery(&state, 1, &ack, Duration::from_secs(1), |_| {
                let (sender, receipt) = std::sync::mpsc::sync_channel(1);
                sender
                    .try_send(Err("stream event output unavailable".into()))
                    .unwrap();
                Ok(DeliveryAcceptance::Receipt(receipt))
            },),
            Err("stream event output unavailable".into())
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert_eq!(
            state.abandon_acknowledgement("web-cancel-emit-fail", 1),
            AcknowledgementAbandonment::Won
        );
    }

    #[test]
    fn timeout_gap_consumes_ack_that_settled_before_abandonment_won() {
        let state = BridgeState::new(inert_paths());
        state.activate_generation(1).unwrap();
        let receiver = state
            .register_acknowledgement("web-cancel-gap-1".into())
            .unwrap();
        state
            .register_public_origin("web-cancel-gap-1", 1, PublicOperationClass::Cancellation)
            .unwrap();
        let ack = envelope(serde_json::json!({
            "version":1,"kind":"ack","id":"sidecar-gap-1",
            "correlationId":"web-cancel-gap-1","sequence":1,
            "payload":{"accepted":true}
        }));
        project_stream_delivery(&state, 1, &ack, Duration::from_secs(1), |_| {
            Ok(DeliveryAcceptance::Immediate)
        })
        .unwrap();
        assert_eq!(
            finish_timed_out_acknowledgement(&state, 1, "web-cancel-gap-1", &receiver,),
            Ok(())
        );
    }

    #[test]
    fn acknowledgement_delivery_and_timeout_abandonment_have_one_gate_winner() {
        let state = BridgeState::new(inert_paths());
        state.activate_generation(1).unwrap();
        let receiver = state
            .register_acknowledgement("web-cancel-race-1".into())
            .unwrap();
        state
            .register_public_origin("web-cancel-race-1", 1, PublicOperationClass::Cancellation)
            .unwrap();
        let ack = envelope(serde_json::json!({
            "version":1,"kind":"ack","id":"sidecar-ack-race-1",
            "correlationId":"web-cancel-race-1","sequence":1,
            "payload":{"accepted":true}
        }));
        let entered = std::sync::Arc::new(std::sync::Barrier::new(2));
        let release = std::sync::Arc::new(std::sync::Barrier::new(2));
        let delivery_state = state.clone();
        let delivery_entered = std::sync::Arc::clone(&entered);
        let delivery_release = std::sync::Arc::clone(&release);
        let delivery = std::thread::spawn(move || {
            project_stream_delivery(&delivery_state, 1, &ack, Duration::from_secs(1), |_| {
                delivery_entered.wait();
                delivery_release.wait();
                Ok(DeliveryAcceptance::Immediate)
            })
        });
        entered.wait();
        let timeout_state = state.clone();
        let (timeout_sender, timeout_receiver) = std::sync::mpsc::channel();
        let timeout = std::thread::spawn(move || {
            let outcome = timeout_state.abandon_acknowledgement("web-cancel-race-1", 1);
            timeout_sender.send(outcome).unwrap();
        });
        assert!(matches!(
            timeout_receiver.recv_timeout(Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        release.wait();
        delivery.join().unwrap().unwrap();
        assert_eq!(
            timeout_receiver.recv_timeout(Duration::from_secs(1)),
            Ok(AcknowledgementAbandonment::AlreadySettled)
        );
        timeout.join().unwrap();
        assert_eq!(receiver.recv_timeout(Duration::from_secs(1)), Ok(true));

        let late_receiver = state
            .register_acknowledgement("web-cancel-timeout-first".into())
            .unwrap();
        state
            .register_public_origin(
                "web-cancel-timeout-first",
                1,
                PublicOperationClass::Cancellation,
            )
            .unwrap();
        state.abandon_acknowledgement("web-cancel-timeout-first", 1);
        let late_ack = envelope(serde_json::json!({
            "version":1,"kind":"ack","id":"sidecar-ack-race-2",
            "correlationId":"web-cancel-timeout-first","sequence":2,
            "payload":{"accepted":true}
        }));
        let mut delivered = false;
        assert!(
            project_stream_delivery(&state, 1, &late_ack, Duration::from_secs(1), |_| {
                delivered = true;
                Ok(DeliveryAcceptance::Immediate)
            },)
            .is_ok()
        );
        assert!(!delivered);
        assert!(matches!(
            late_receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn private_host_kinds_never_reach_stream_delivery() {
        let state = BridgeState::new(inert_paths());
        for kind in ["host-request", "host-response"] {
            let private = envelope(serde_json::json!({
                "version": 1,
                "kind": kind,
                "id": format!("private-{kind}"),
                "correlationId": "cancel-1",
                "sequence": 17,
                "payload": {
                    "method": "credential.set",
                    "providerId": "provider",
                    "credential": {"type": "api_key", "key": "runtime-canary"},
                    "snapshot": {"sequence": 17, "state": {"tool": "unsafe"}}
                }
            }));
            let mut deliveries = 0;
            assert!(
                project_stream_delivery(&state, 1, &private, Duration::from_secs(1), |_| {
                    deliveries += 1;
                    Ok(DeliveryAcceptance::Immediate)
                },)
                .is_ok()
            );
            assert_eq!(deliveries, 0);
        }
    }
}
