use crate::commands::bridge::{
    AcknowledgementAbandonment, BridgeState, DeliveryAcceptance, bridge_start_transport,
};
use crate::commands::event_output::EVENT_OUTPUT_BUSY;
use crate::commands::projector::{
    PROJECTION_BUSY, PROJECTION_REJECTED, PublicOperationClass, STREAM_ORIGIN_TTL,
};
use crate::protocol::{Envelope, ErrorCategory, ProtocolKind, validate_envelope};
use crate::supervisor::{PublicRoute, RECEIVE_TIMED_OUT, TEST_METHODS_ENABLED};
use std::time::{Duration, Instant};
use tauri::{AppHandle, State};
const STREAM_DEADLINE: Duration = Duration::from_secs(5);
const PRODUCT_STREAM_DEADLINE: Duration = Duration::from_secs(900);
// Fixture and probe streams keep the original tight budgets. A real agent
// turn (long answers, many tool calls) needs far more before it is treated
// as runaway output.
const MAX_STREAM_EVENTS: u64 = 4_096;
const MAX_STREAM_DELTA_UTF16: u64 = 262_144;
const MAX_PRODUCT_STREAM_EVENTS: u64 = 65_536;
const MAX_PRODUCT_STREAM_DELTA_UTF16: u64 = 8_388_608;
const STREAM_DEADLINE_EXCEEDED: &str = "sidecar stream deadline exceeded";
const STREAM_LIMIT_EXCEEDED: &str = "sidecar stream limit exceeded";
const SYNTHESISED_STREAM_TERMINAL_ID: &str = "host-synthesised-stream-terminal";
// A busy projector or a momentarily full WebView queue is back-pressure,
// not a fault; delivery waits this long for it to clear.
const BUSY_DELIVERY_WINDOW: Duration = Duration::from_secs(5);
const BUSY_DELIVERY_MAX_BACKOFF: Duration = Duration::from_millis(10);
const FAILURE_NOTICE_RECEIPT_TIMEOUT: Duration = Duration::from_secs(1);

// A stream's projection origin must outlive its longest deadline, or a
// quiet turn (a long tool run) would have its later events dropped.
const _: () = assert!(PRODUCT_STREAM_DEADLINE.as_secs() < STREAM_ORIGIN_TTL.as_secs());

struct StreamBudget {
    events: u64,
    delta_utf16: u64,
    max_events: u64,
    max_delta_utf16: u64,
}

impl StreamBudget {
    fn fixture() -> Self {
        Self::with_limits(MAX_STREAM_EVENTS, MAX_STREAM_DELTA_UTF16)
    }

    fn product() -> Self {
        Self::with_limits(MAX_PRODUCT_STREAM_EVENTS, MAX_PRODUCT_STREAM_DELTA_UTF16)
    }

    fn with_limits(max_events: u64, max_delta_utf16: u64) -> Self {
        Self {
            events: 0,
            delta_utf16: 0,
            max_events,
            max_delta_utf16,
        }
    }

    fn observe(&mut self, envelope: &Envelope) -> Result<(), String> {
        let max_events = self.max_events;
        self.events = self
            .events
            .checked_add(1)
            .filter(|value| *value <= max_events)
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
        let max_delta_utf16 = self.max_delta_utf16;
        self.delta_utf16 = self
            .delta_utf16
            .checked_add(units)
            .filter(|value| *value <= max_delta_utf16)
            .ok_or_else(|| STREAM_LIMIT_EXCEEDED.to_string())?;
        Ok(())
    }
}

fn is_product_stream(request: &Envelope) -> bool {
    request
        .payload
        .get("method")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|method| matches!(method, "product.turn.start" | "product.auth.start"))
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

/// Waits up to a second for the sidecar's acknowledgement, so it runs off
/// the main thread.
#[tauri::command]
pub async fn cancel_stream(
    state: State<'_, BridgeState>,
    cancellation: Envelope,
) -> Result<(), String> {
    let transport = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || cancel_stream_transport(&transport, cancellation))
        .await
        .map_err(|_| "cancellation worker failed".to_string())?
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
        .and_then(|mut supervisor| {
            // The acknowledgement belongs to the stream being cancelled; if
            // that stream has already finished, any listener may project it.
            if let Some(stream_id) = cancellation.correlation_id.as_deref() {
                supervisor.route_acknowledgement(generation, &cancellation_id, stream_id);
            }
            supervisor.send_for_generation(generation, &cancellation)
        });
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

pub(crate) fn run_stream_transport_receipted<F>(
    state: &BridgeState,
    request: Envelope,
    deliver: F,
) -> Result<(), String>
where
    F: FnMut(u64, &Envelope) -> Result<DeliveryAcceptance, String>,
{
    bridge_start_transport(state)?;
    let opened = open_stream(state, request)?;
    drive_stream_transport_receipted(opened, FailureNotice::None, deliver)
}

/// How a stream that fails after it started tells the interface.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureNotice {
    /// The caller learns of the failure from the returned error.
    None,
    /// Nothing awaits the stream, so a `stream.failed` terminal is projected
    /// to the WebView before the generation is cut off.
    Project,
}

pub(crate) fn drive_stream_transport_receipted<F>(
    opened: OpenedStream,
    notice: FailureNotice,
    mut deliver: F,
) -> Result<(), String>
where
    F: FnMut(u64, &Envelope) -> Result<DeliveryAcceptance, String>,
{
    let state = opened.state.clone();
    drive_stream(opened, notice, |generation, envelope, remaining| {
        project_stream_delivery(&state, generation, envelope, remaining, |safe| {
            deliver(generation, safe)
        })
    })
}

fn is_busy(error: &str) -> bool {
    error == PROJECTION_BUSY || error == EVENT_OUTPUT_BUSY
}

/// Projects one envelope, waiting out transient back-pressure. A busy
/// projector or a full WebView queue leaves nothing reserved or committed,
/// so a retry is exact; only lasting congestion becomes a failure.
fn project_stream_delivery<F>(
    state: &BridgeState,
    generation: u64,
    envelope: &Envelope,
    remaining: Duration,
    mut deliver: F,
) -> Result<(), String>
where
    F: FnMut(&Envelope) -> Result<DeliveryAcceptance, String>,
{
    let started = Instant::now();
    let give_up = started + remaining.min(BUSY_DELIVERY_WINDOW);
    let mut backoff = Duration::from_millis(1);
    loop {
        let remaining = remaining.saturating_sub(started.elapsed());
        match project_stream_delivery_once(state, generation, envelope, remaining, &mut deliver) {
            Err(error) if is_busy(&error) && Instant::now() < give_up => {
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(BUSY_DELIVERY_MAX_BACKOFF);
            }
            outcome => return outcome,
        }
    }
}

fn project_stream_delivery_once<F>(
    state: &BridgeState,
    generation: u64,
    envelope: &Envelope,
    remaining: Duration,
    deliver: &mut F,
) -> Result<(), String>
where
    F: FnMut(&Envelope) -> Result<DeliveryAcceptance, String>,
{
    if envelope.kind == ProtocolKind::Ack {
        match state.authenticate_ack(generation, envelope) {
            Ok(_) => {}
            Err(error) if error == PROJECTION_REJECTED => return Ok(()),
            Err(error) => return Err(error),
        }
        let delivery = match state.project_ack_and_deliver(generation, envelope, &mut *deliver) {
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
    match state.project_and_deliver(generation, envelope, &mut *deliver) {
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

/// A stream whose request has been written and whose events are routed to
/// its own mailbox. Dropping it without completing retires its origin.
pub(crate) struct OpenedStream {
    state: BridgeState,
    request_id: String,
    generation: u64,
    route: PublicRoute,
    deadline: Instant,
    budget: StreamBudget,
    completed: bool,
}

impl OpenedStream {
    fn complete(mut self) {
        self.completed = true;
    }
}

impl Drop for OpenedStream {
    fn drop(&mut self) {
        if !self.completed {
            self.state.abandon_public_origin(
                &self.request_id,
                self.generation,
                PublicOperationClass::Stream,
            );
        }
    }
}

/// Registers the stream's origin and mailbox, then writes its request. The
/// mailbox exists before the write, so no event can arrive unrouted.
pub(crate) fn open_stream(state: &BridgeState, request: Envelope) -> Result<OpenedStream, String> {
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
    let route = match supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())
        .and_then(|supervisor| supervisor.open_public_route(generation, &request.id))
    {
        Ok(route) => route,
        Err(error) => {
            state.abandon_public_origin(&request.id, generation, PublicOperationClass::Stream);
            return Err(error);
        }
    };
    let product = is_product_stream(&request);
    let opened = OpenedStream {
        state: state.clone(),
        request_id: request.id.clone(),
        generation,
        route,
        deadline: Instant::now()
            + if product {
                PRODUCT_STREAM_DEADLINE
            } else {
                STREAM_DEADLINE
            },
        budget: if product {
            StreamBudget::product()
        } else {
            StreamBudget::fixture()
        },
        completed: false,
    };
    let send_result = supervisor
        .lock()
        .map_err(|_| "sidecar state unavailable".to_string())?
        .send_for_generation(generation, &request);
    if let Err(error) = send_result {
        let _ = state.cutoff_generation(generation);
        return Err(error);
    }
    Ok(opened)
}

/// Reads the stream's own mailbox until its terminal. It never holds the
/// supervisor lock while waiting, so other commands and streams proceed.
fn drive_stream<F>(
    opened: OpenedStream,
    notice: FailureNotice,
    mut deliver: F,
) -> Result<(), String>
where
    F: FnMut(u64, &Envelope, Duration) -> Result<(), String>,
{
    let generation = opened.generation;
    let budget = StreamBudget::with_limits(opened.budget.max_events, opened.budget.max_delta_utf16);
    let result = run_stream_loop(
        generation,
        &opened.request_id,
        opened.deadline,
        budget,
        |timeout| opened.route.receive(timeout),
        &mut deliver,
    );
    if result.is_ok() {
        opened.complete();
    } else {
        if notice == FailureNotice::Project
            && let Err(error) = &result
        {
            project_failure_notice(&opened, error);
        }
        let _ = opened.state.cutoff_generation(generation);
    }
    result
}

/// Best effort: tells the interface that a turn nobody is awaiting ended,
/// and waits for that event to be emitted before the generation is cut off.
fn project_failure_notice(opened: &OpenedStream, error: &str) {
    let code = match error {
        STREAM_DEADLINE_EXCEEDED => "host-stream-deadline-exceeded",
        STREAM_LIMIT_EXCEEDED => "host-stream-limit-exceeded",
        _ => "host-stream-interrupted",
    };
    let terminal = Envelope {
        version: 1,
        kind: ProtocolKind::Event,
        id: SYNTHESISED_STREAM_TERMINAL_ID.to_owned(),
        correlation_id: Some(opened.request_id.clone()),
        decision_id: None,
        sequence: 0,
        payload: serde_json::Map::from_iter([
            ("eventType".into(), serde_json::Value::from("stream.failed")),
            ("terminal".into(), serde_json::Value::from("failed")),
            ("code".into(), serde_json::Value::from(code)),
        ]),
        error: None,
    };
    let state = &opened.state;
    let receipt = state.project_and_deliver(opened.generation, &terminal, |safe| {
        state.enqueue_event_with_receipt(opened.generation, safe)
    });
    if let Ok(receipt) = receipt {
        let _ = receipt.recv_timeout(FAILURE_NOTICE_RECEIPT_TIMEOUT);
    }
}

fn run_stream_loop<R, D>(
    generation: u64,
    request_id: &str,
    deadline: Instant,
    mut budget: StreamBudget,
    mut receive: R,
    mut deliver: D,
) -> Result<(), String>
where
    R: FnMut(Duration) -> Result<Envelope, String>,
    D: FnMut(u64, &Envelope, Duration) -> Result<(), String>,
{
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
            Err(error) if error == RECEIVE_TIMED_OUT => {
                if Instant::now() >= deadline {
                    return Err(STREAM_DEADLINE_EXCEEDED.into());
                }
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
        let is_stream_response = envelope.kind == ProtocolKind::Response
            && !is_snapshot
            && envelope.correlation_id.as_deref() == Some(request_id);
        if is_stream_response {
            // The sidecar answered a stream request with a plain response, so the stream
            // will never carry its own terminal. Synthesise the terminal failure the
            // WebView already understands rather than waiting out the deadline.
            let terminal = synthesise_stream_failure(&envelope, request_id);
            budget.observe(&terminal)?;
            deliver(
                generation,
                &terminal,
                deadline.saturating_duration_since(Instant::now()),
            )?;
            return Ok(());
        }
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
                Some("complete" | "cancelled" | "failed")
            )
        {
            return Ok(());
        }
    }
}

fn synthesise_stream_failure(response: &Envelope, request_id: &str) -> Envelope {
    let code = response
        .error
        .as_ref()
        .map_or("provider-stream-unavailable", |error| {
            match error.category {
                ErrorCategory::InvalidRequest => "provider-stream-invalid-request",
                ErrorCategory::UnsupportedVersion => "provider-stream-unsupported-version",
                ErrorCategory::Unavailable => "provider-stream-unavailable",
                ErrorCategory::Cancelled => "provider-stream-cancelled",
                ErrorCategory::Timeout => "provider-stream-timeout",
                ErrorCategory::PermissionDenied => "provider-stream-permission-denied",
                ErrorCategory::Conflict => "provider-stream-conflict",
                ErrorCategory::Internal => "provider-stream-internal",
            }
        });
    Envelope {
        version: 1,
        kind: ProtocolKind::Event,
        id: SYNTHESISED_STREAM_TERMINAL_ID.to_owned(),
        correlation_id: Some(request_id.to_owned()),
        decision_id: None,
        sequence: response.sequence,
        payload: serde_json::Map::from_iter([
            ("eventType".into(), serde_json::Value::from("stream.failed")),
            ("terminal".into(), serde_json::Value::from("failed")),
            ("code".into(), serde_json::Value::from(code)),
        ]),
        error: None,
    }
}

fn validate_stream_request(request: &Envelope) -> Result<(), String> {
    let method = request
        .payload
        .get("method")
        .and_then(serde_json::Value::as_str);
    let permitted_payload = match method {
        // Fixture streams exist only where the sidecar also enables its test
        // methods, so a release build cannot drive them.
        Some("stream.fixture") => TEST_METHODS_ENABLED && request.payload.len() == 1,
        Some("product.turn.start") => {
            crate::protocol::product::validate_product_turn_request(&request.payload).is_ok()
        }
        Some("product.auth.start") => {
            crate::protocol::product::validate_product_auth_request(&request.payload).is_ok()
        }
        _ => false,
    };
    if validate_envelope(request).is_err()
        || request.kind != ProtocolKind::Request
        || !permitted_payload
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
        AcknowledgementAbandonment, DeliveryAcceptance, EVENT_OUTPUT_BUSY,
        MAX_PRODUCT_STREAM_DELTA_UTF16, MAX_PRODUCT_STREAM_EVENTS, MAX_STREAM_DELTA_UTF16,
        MAX_STREAM_EVENTS, PROJECTION_BUSY, PublicOperationClass, STREAM_DEADLINE_EXCEEDED,
        STREAM_LIMIT_EXCEEDED, StreamBudget, finish_timed_out_acknowledgement, is_product_stream,
        project_stream_delivery, run_stream_loop, synthesise_stream_failure, validate_cancellation,
        validate_stream_request,
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
        assert_eq!(
            validate_stream_request(&request).is_ok(),
            crate::supervisor::TEST_METHODS_ENABLED
        );
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
        let mut text_budget = StreamBudget::fixture();
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
        let mut event_budget = StreamBudget::fixture();
        for _ in 0..MAX_STREAM_EVENTS {
            assert!(event_budget.observe(&empty_delta).is_ok());
        }
        assert_eq!(
            event_budget.observe(&empty_delta),
            Err(STREAM_LIMIT_EXCEEDED.into())
        );

        let mut overflow_budget = StreamBudget::product();
        overflow_budget.delta_utf16 = u64::MAX;
        assert_eq!(
            overflow_budget.observe(&maximum_delta),
            Err(STREAM_LIMIT_EXCEEDED.into())
        );
    }

    #[test]
    fn product_turns_get_long_turn_budgets_while_fixtures_stay_tight() {
        let turn = envelope(serde_json::json!({
            "version":1,"kind":"request","id":"web-turn-1","sequence":1,
            "payload":{"method":"product.turn.start"}
        }));
        let fixture = envelope(serde_json::json!({
            "version":1,"kind":"request","id":"web-stream-1","sequence":1,
            "payload":{"method":"stream.fixture"}
        }));
        assert!(is_product_stream(&turn));
        assert!(!is_product_stream(&fixture));

        // A long answer runs far past the fixture ceiling of 262,144 units
        // before a product turn's own budget ends it.
        let large_delta = envelope(serde_json::json!({
            "version":1,"kind":"event","id":"sidecar-delta","correlationId":"web-turn-1",
            "sequence":1,"payload":{"eventType":"stream.delta","text":"x".repeat(8_192)}
        }));
        let mut product = StreamBudget::product();
        for _ in 0..(MAX_PRODUCT_STREAM_DELTA_UTF16 / 8_192) {
            product.observe(&large_delta).unwrap();
        }
        assert_eq!(
            product.observe(&large_delta),
            Err(STREAM_LIMIT_EXCEEDED.into())
        );
        let mut fixture_budget = StreamBudget::fixture();
        for _ in 0..(MAX_STREAM_DELTA_UTF16 / 8_192) {
            fixture_budget.observe(&large_delta).unwrap();
        }
        assert!(fixture_budget.observe(&large_delta).is_err());

        let empty_delta = envelope(serde_json::json!({
            "version":1,"kind":"event","id":"sidecar-empty","correlationId":"web-turn-1",
            "sequence":1,"payload":{"eventType":"stream.delta","text":""}
        }));
        let mut events = StreamBudget::product();
        for _ in 0..MAX_PRODUCT_STREAM_EVENTS {
            events.observe(&empty_delta).unwrap();
        }
        assert_eq!(
            events.observe(&empty_delta),
            Err(STREAM_LIMIT_EXCEEDED.into())
        );
        assert_eq!(MAX_PRODUCT_STREAM_EVENTS, 65_536);
        assert_eq!(MAX_PRODUCT_STREAM_DELTA_UTF16, 8_388_608);
    }

    fn busy_rig() -> (BridgeState, Envelope) {
        let state = BridgeState::new(inert_paths());
        state.activate_generation(1).unwrap();
        state
            .register_public_origin("web-stream-busy", 1, PublicOperationClass::Stream)
            .unwrap();
        let delta = envelope(serde_json::json!({
            "version":1,"kind":"event","id":"sidecar-busy-1","correlationId":"web-stream-busy",
            "sequence":1,"payload":{"eventType":"stream.delta","text":"hello"}
        }));
        (state, delta)
    }

    #[test]
    fn a_momentarily_full_webview_queue_is_retried_not_fatal() {
        let (state, delta) = busy_rig();
        let mut attempts = 0;
        project_stream_delivery(&state, 1, &delta, Duration::from_secs(5), |_| {
            attempts += 1;
            if attempts < 4 {
                Err(EVENT_OUTPUT_BUSY.into())
            } else {
                Ok(DeliveryAcceptance::Immediate)
            }
        })
        .expect("back-pressure clears and the event is delivered");
        assert_eq!(attempts, 4);

        // Congestion that outlasts the stream's remaining time still fails.
        let started = Instant::now();
        assert_eq!(
            project_stream_delivery(&state, 1, &delta, Duration::from_millis(50), |_| Err(
                EVENT_OUTPUT_BUSY.into()
            )),
            Err(EVENT_OUTPUT_BUSY.into())
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_busy_projector_makes_a_second_stream_wait_instead_of_failing() {
        let (state, delta) = busy_rig();
        state
            .register_public_origin("web-stream-other", 1, PublicOperationClass::Stream)
            .unwrap();
        let other = envelope(serde_json::json!({
            "version":1,"kind":"event","id":"sidecar-other-1","correlationId":"web-stream-other",
            "sequence":2,"payload":{"eventType":"stream.delta","text":"concurrent"}
        }));
        let entered = std::sync::Arc::new(std::sync::Barrier::new(2));
        let holder_state = state.clone();
        let holder_entered = std::sync::Arc::clone(&entered);
        let holder = std::thread::spawn(move || {
            holder_state.project_and_deliver(1, &other, |_| {
                holder_entered.wait();
                std::thread::sleep(Duration::from_millis(50));
                Ok(())
            })
        });
        entered.wait();
        // The gate is held right now; the old code returned this as fatal.
        assert_eq!(
            state.project_and_deliver(1, &delta, |_| Ok(())),
            Err(PROJECTION_BUSY.into())
        );
        let mut delivered = false;
        project_stream_delivery(&state, 1, &delta, Duration::from_secs(5), |_| {
            delivered = true;
            Ok(DeliveryAcceptance::Immediate)
        })
        .expect("the second stream waits for the projector");
        assert!(delivered);
        holder.join().unwrap().unwrap();
    }

    #[test]
    fn actual_run_loop_bounds_uninterrupted_ack_and_repeated_snapshot_delivery() {
        let mut ack_index = 0_u64;
        let mut delivered_acks = 0_u64;
        let ack_result = run_stream_loop(
            1,
            "web-stream-probe-1",
            Instant::now() + Duration::from_secs(2),
            StreamBudget::fixture(),
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
            StreamBudget::fixture(),
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
    fn stream_correlated_responses_terminate_the_stream_with_a_mapped_failure() {
        for (category, code) in [
            ("invalid-request", "provider-stream-invalid-request"),
            ("unsupported-version", "provider-stream-unsupported-version"),
            ("unavailable", "provider-stream-unavailable"),
            ("cancelled", "provider-stream-cancelled"),
            ("timeout", "provider-stream-timeout"),
            ("permission-denied", "provider-stream-permission-denied"),
            ("conflict", "provider-stream-conflict"),
            ("internal", "provider-stream-internal"),
        ] {
            let response = envelope(serde_json::json!({
                "version":1,"kind":"response","id":"sidecar-1",
                "correlationId":"web-auth-driver-0001","sequence":1,"payload":{},
                "error":{"category":category,"message":"Product operation failed","retryable":true}
            }));
            let terminal = synthesise_stream_failure(&response, "web-auth-driver-0001");
            assert_eq!(terminal.kind, super::ProtocolKind::Event);
            assert_eq!(
                terminal.correlation_id.as_deref(),
                Some("web-auth-driver-0001")
            );
            assert!(terminal.error.is_none());
            assert_eq!(
                terminal
                    .payload
                    .get("eventType")
                    .and_then(serde_json::Value::as_str),
                Some("stream.failed")
            );
            assert_eq!(
                terminal
                    .payload
                    .get("terminal")
                    .and_then(serde_json::Value::as_str),
                Some("failed")
            );
            assert_eq!(
                terminal
                    .payload
                    .get("code")
                    .and_then(serde_json::Value::as_str),
                Some(code)
            );
        }

        // A success response for a stream correlation is still a protocol break.
        let success = envelope(serde_json::json!({
            "version":1,"kind":"response","id":"sidecar-2",
            "correlationId":"web-auth-driver-0001","sequence":2,"payload":{"ok":true}
        }));
        assert_eq!(
            synthesise_stream_failure(&success, "web-auth-driver-0001")
                .payload
                .get("code")
                .and_then(serde_json::Value::as_str),
            Some("provider-stream-unavailable")
        );

        // The run loop must stop on that response instead of waiting out the deadline.
        let error_response = envelope(serde_json::json!({
            "version":1,"kind":"response","id":"sidecar-1",
            "correlationId":"web-auth-driver-0001","sequence":1,"payload":{},
            "error":{"category":"unavailable","message":"Product operation failed","retryable":true}
        }));
        let mut delivered = Vec::new();
        let started = Instant::now();
        let result = run_stream_loop(
            1,
            "web-auth-driver-0001",
            started + Duration::from_secs(60),
            StreamBudget::product(),
            |_| Ok(error_response.clone()),
            |_, envelope, _| {
                delivered.push(envelope.clone());
                Ok(())
            },
        );
        assert_eq!(result, Ok(()));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(delivered.len(), 1);
        assert_eq!(
            delivered[0]
                .payload
                .get("code")
                .and_then(serde_json::Value::as_str),
            Some("provider-stream-unavailable")
        );

        // Responses correlated elsewhere still pass by without terminating the stream.
        let unrelated = envelope(serde_json::json!({
            "version":1,"kind":"response","id":"sidecar-3",
            "correlationId":"web-other-0001","sequence":3,"payload":{}
        }));
        let mut unrelated_deliveries = 0;
        assert_eq!(
            run_stream_loop(
                1,
                "web-auth-driver-0001",
                Instant::now() + Duration::from_millis(250),
                StreamBudget::product(),
                |_| Ok(unrelated.clone()),
                |_, _, _| {
                    unrelated_deliveries += 1;
                    Ok(())
                },
            ),
            Err(STREAM_DEADLINE_EXCEEDED.into())
        );
        assert_eq!(unrelated_deliveries, 0);
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
