use super::process::{
    APPROVAL_WRITE_MAX_DURATION, GenerationWriter, ProductDelivery, ProductWaiters,
    WorkspaceWaiters,
};
use super::public_router::PublicRouter;
use super::router::{SequenceOutcome, SequenceRouter};
use super::stdio::{GenerationControl, RawFrame, fail_generation};
use crate::credentials::CredentialProxy;
use crate::credentials::proxy::discard_private_envelope;
use crate::domain::approval::{
    ApprovalAbandonRequest, ApprovalCohort, ApprovalCohortMember, ApprovalReadyRequest,
    ApprovalRegistry, ApprovalRequest,
};
use crate::domain::workspace::WorkspaceRegistry;
use crate::protocol::{
    AUTHENTICATED_INTERNAL_SNAPSHOT_CORRELATION, Envelope, ProtocolDecoder, ProtocolKind,
};
use serde_json::Value;
use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex, MutexGuard, TryLockError,
    atomic::{AtomicUsize, Ordering},
    mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub(super) const RAW_QUEUE_CAPACITY: usize = 32;
pub(super) const PUBLIC_QUEUE_CAPACITY: usize = 256;
const PRIVATE_QUEUE_CAPACITY: usize = 128;
// Coordinators block on their own signals; this is only a safety net.
const COORDINATOR_IDLE_WAIT: Duration = Duration::from_secs(1);
// The sidecar abandons a credential request it has not heard back on within
// 120 s and treats a later reply as fatal. Every request is answered before
// this budget, measured from when it was decoded, even if storage hangs.
pub(super) const CREDENTIAL_REPLY_BUDGET: Duration = Duration::from_secs(100);

struct WorkPermit(Arc<AtomicUsize>);

impl Drop for WorkPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct PrivateWork {
    request: Option<Envelope>,
    permit: Option<WorkPermit>,
    reply_deadline: Instant,
}

impl PrivateWork {
    fn new(request: Envelope, permit: WorkPermit) -> Self {
        Self {
            request: Some(request),
            permit: Some(permit),
            reply_deadline: Instant::now() + CREDENTIAL_REPLY_BUDGET,
        }
    }

    fn take(&mut self) -> (Envelope, WorkPermit) {
        (
            self.request.take().expect("private request owned"),
            self.permit.take().expect("private permit owned"),
        )
    }
}

impl Drop for PrivateWork {
    fn drop(&mut self) {
        if let Some(request) = self.request.take() {
            discard_private_envelope(request);
        }
        // The optional permit releases through its ordinary Drop.
    }
}

struct CompletedWork {
    pending: crate::credentials::proxy::PendingHostResponse,
    _permit: WorkPermit,
}

/// Everything the credential coordinator waits for arrives on one channel,
/// so it can block rather than poll.
enum CoordinatorEvent {
    Work(PrivateWork),
    Completed(u64, CompletedWork),
    Wake,
}

/// The one repository operation in flight: its token, the correlation of
/// the request it answers, and the latest moment its answer may be sent.
struct RunningOperation {
    token: u64,
    correlation_id: Zeroizing<String>,
    reply_deadline: Instant,
}

#[derive(Clone)]
struct SnapshotRequest {
    id: String,
    after_sequence: u64,
}

pub(super) struct DispatcherHandles {
    pub dispatcher: JoinHandle<()>,
    // The coordinator always remains drainable. Only its one separate
    // repository operation thread may be detached if storage never returns.
    pub credential_coordinator: JoinHandle<()>,
    pub approval_coordinator: JoinHandle<()>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn start_dispatcher(
    generation: u64,
    decoder: ProtocolDecoder,
    raw_receiver: Receiver<RawFrame>,
    public: Arc<PublicRouter>,
    workspace_waiters: Arc<WorkspaceWaiters>,
    product_waiters: Arc<ProductWaiters>,
    proxy: CredentialProxy,
    approval_registry: Arc<ApprovalRegistry>,
    workspace_registry: Arc<WorkspaceRegistry>,
    writer: Arc<Mutex<GenerationWriter>>,
    control: Arc<GenerationControl>,
    diagnostics: Arc<Mutex<VecDeque<String>>>,
    handshake_sequence: u64,
) -> DispatcherHandles {
    // Room for every permitted request plus one completion and one wake.
    let (private_sender, private_receiver) = sync_channel(PRIVATE_QUEUE_CAPACITY + 2);
    let outstanding = Arc::new(AtomicUsize::new(0));
    let coordinator_writer = Arc::clone(&writer);
    let coordinator_control = Arc::clone(&control);
    let coordinator_events = private_sender.clone();
    let credential_coordinator = thread::spawn(move || {
        credential_coordinator_loop(
            generation,
            private_receiver,
            coordinator_events,
            proxy,
            coordinator_writer,
            coordinator_control,
        );
    });

    let approval_writer = Arc::clone(&writer);
    let approval_control = Arc::clone(&control);
    let approval_registry_for_coordinator = Arc::clone(&approval_registry);
    let approval_workspace_for_coordinator = Arc::clone(&workspace_registry);
    let approval_coordinator = thread::spawn(move || {
        approval_coordinator_loop(
            generation,
            approval_registry_for_coordinator,
            approval_workspace_for_coordinator,
            approval_writer,
            approval_control,
        );
    });

    let dispatcher_writer = Arc::clone(&writer);
    let dispatcher_control = Arc::clone(&control);
    let dispatcher = thread::spawn(move || {
        dispatch_loop(
            generation,
            decoder,
            raw_receiver,
            public,
            workspace_waiters,
            product_waiters,
            approval_registry,
            workspace_registry,
            private_sender,
            outstanding,
            dispatcher_writer,
            dispatcher_control,
            diagnostics,
            handshake_sequence,
        );
    });

    DispatcherHandles {
        dispatcher,
        credential_coordinator,
        approval_coordinator,
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_loop(
    generation: u64,
    mut decoder: ProtocolDecoder,
    raw_receiver: Receiver<RawFrame>,
    public: Arc<PublicRouter>,
    workspace_waiters: Arc<WorkspaceWaiters>,
    product_waiters: Arc<ProductWaiters>,
    approval_registry: Arc<ApprovalRegistry>,
    workspace_registry: Arc<WorkspaceRegistry>,
    private_sender: SyncSender<CoordinatorEvent>,
    outstanding: Arc<AtomicUsize>,
    writer: Arc<Mutex<GenerationWriter>>,
    control: Arc<GenerationControl>,
    diagnostics: Arc<Mutex<VecDeque<String>>>,
    handshake_sequence: u64,
) {
    let mut router = SequenceRouter::default();
    router.apply_snapshot(handshake_sequence);
    let mut snapshot_request: Option<SnapshotRequest> = None;

    while control.is_active() {
        let frame = match raw_receiver.recv() {
            Ok(frame) => frame,
            Err(_) if !control.is_active() => return,
            Err(_) => {
                fatal("sidecar raw response channel closed", &control, &public);
                return;
            }
        };
        let line = match frame {
            RawFrame::Line(line) => line,
            RawFrame::Failure(message) => {
                public.fail(&message);
                return;
            }
        };
        #[cfg(feature = "a23-credential-test")]
        if writer
            .lock()
            .map_err(|_| "A.23 raw capture unavailable".to_string())
            .and_then(|writer| writer.capture_a23_inbound_frame(&line))
            .is_err()
        {
            fatal("A.23 raw capture unavailable", &control, &public);
            return;
        }
        let envelope = match decoder.decode(&line) {
            Ok(envelope) => envelope,
            Err(_) => {
                fatal("sidecar stdout protocol violation", &control, &public);
                return;
            }
        };

        if forbidden_inbound_identifier(&envelope.id)
            || envelope
                .correlation_id
                .as_deref()
                .is_some_and(forbidden_inbound_identifier)
        {
            if matches!(
                envelope.kind,
                ProtocolKind::HostRequest | ProtocolKind::HostResponse
            ) {
                discard_private_envelope(envelope);
            }
            fatal("sidecar identifier namespace invalid", &control, &public);
            return;
        }

        if envelope.kind == ProtocolKind::HostResponse {
            discard_private_envelope(envelope);
            fatal(
                "sidecar private response direction invalid",
                &control,
                &public,
            );
            return;
        }

        if let Some(request) = snapshot_request.as_ref()
            && envelope.correlation_id.as_deref() == Some(request.id.as_str())
        {
            if !valid_snapshot(&envelope, request.after_sequence)
                || !router.apply_correlated_snapshot(&envelope)
            {
                if envelope.kind == ProtocolKind::HostRequest {
                    discard_private_envelope(envelope);
                }
                fatal("sidecar snapshot invalid", &control, &public);
                return;
            }
            snapshot_request = None;
            let mut authenticated = envelope;
            authenticated.correlation_id = Some(AUTHENTICATED_INTERNAL_SNAPSHOT_CORRELATION.into());
            if !send_public(authenticated, &public) {
                fatal("sidecar public response queue overflow", &control, &public);
                return;
            }
            continue;
        }

        let private = envelope.kind == ProtocolKind::HostRequest;
        match router.observe(&envelope) {
            SequenceOutcome::Accepted => {}
            SequenceOutcome::Duplicate | SequenceOutcome::Stale if !private => continue,
            SequenceOutcome::Gap if !private => {
                if router.take_resynchronisation() {
                    let after_sequence = router.last_sequence().unwrap_or(0);
                    let request_id = writer.lock().ok().and_then(|mut writer| {
                        writer
                            .write_snapshot_request(generation, after_sequence)
                            .ok()
                    });
                    let Some(request_id) = request_id else {
                        fatal("sidecar snapshot request failed", &control, &public);
                        return;
                    };
                    snapshot_request = Some(SnapshotRequest {
                        id: request_id,
                        after_sequence,
                    });
                }
                continue;
            }
            _ => {
                discard_private_envelope(envelope);
                fatal("sidecar private sequence invalid", &control, &public);
                return;
            }
        }

        if envelope
            .correlation_id
            .as_deref()
            .is_some_and(|correlation| correlation.starts_with("rust-workspace-"))
        {
            if envelope.kind != ProtocolKind::Response {
                fatal("sidecar workspace response invalid", &control, &public);
                return;
            }
            if workspace_waiters.deliver(generation, envelope).is_err() {
                fatal("sidecar workspace response unavailable", &control, &public);
                return;
            }
            continue;
        }

        if envelope
            .correlation_id
            .as_deref()
            .is_some_and(|correlation| correlation.starts_with("rust-product-"))
        {
            if envelope.kind != ProtocolKind::Response {
                fatal("sidecar product response invalid", &control, &public);
                return;
            }
            match product_waiters.deliver(generation, envelope) {
                Ok(ProductDelivery::Delivered) => {}
                Ok(ProductDelivery::LateDiscarded) => record_diagnostic(
                    &diagnostics,
                    "A product response arrived after its request timed out and was discarded.",
                ),
                Ok(ProductDelivery::NotProduct) | Err(_) => {
                    fatal("sidecar product response unavailable", &control, &public);
                    return;
                }
            }
            continue;
        }

        if private {
            let method = envelope.payload.get("method").and_then(Value::as_str);
            if method == Some("approval.request") {
                let request = parse_approval_request(generation, &envelope);
                let private_envelope = envelope;
                match request.and_then(|request| {
                    let workspace_id = request.workspace_id.clone();
                    let workspace_revision = request.workspace_revision;
                    workspace_registry.with_approval_binding(
                        &workspace_id,
                        workspace_revision,
                        |binding| approval_registry.register(request, binding).map(|_| ()),
                    )
                }) {
                    Ok(()) => discard_private_envelope(private_envelope),
                    Err(_) => {
                        discard_private_envelope(private_envelope);
                        fatal("sidecar approval request invalid", &control, &public);
                        return;
                    }
                }
                continue;
            }
            if method == Some("approval.ready") {
                let result = parse_approval_ready(generation, &envelope)
                    .and_then(|request| approval_registry.mark_ready(request))
                    .and_then(|ack| {
                        writer
                            .lock()
                            .map_err(|_| "sidecar writer unavailable".to_string())
                            .and_then(|mut writer| writer.write_approval_ready_ack(generation, ack))
                    });
                discard_private_envelope(envelope);
                if result.is_err() {
                    fatal("sidecar approval ready invalid", &control, &public);
                    return;
                }
                continue;
            }
            if method == Some("approval.abandon") {
                let result = parse_approval_abandon(generation, &envelope)
                    .and_then(|request| approval_registry.abandon(request))
                    .and_then(|ack| {
                        writer
                            .lock()
                            .map_err(|_| "sidecar writer unavailable".to_string())
                            .and_then(|mut writer| {
                                writer.write_approval_abandon_ack(generation, ack)
                            })
                    });
                discard_private_envelope(envelope);
                if result.is_err() {
                    fatal("sidecar approval abandon invalid", &control, &public);
                    return;
                }
                continue;
            }
            if !method.is_some_and(|method| method.starts_with("credential.")) {
                discard_private_envelope(envelope);
                fatal("sidecar private method invalid", &control, &public);
                return;
            }
            let Some(permit) = reserve_private_work(&outstanding) else {
                discard_private_envelope(envelope);
                fatal("sidecar credential queue unavailable", &control, &public);
                return;
            };
            if !control.is_active() {
                discard_private_envelope(envelope);
                drop(permit);
                return;
            }
            match private_sender
                .try_send(CoordinatorEvent::Work(PrivateWork::new(envelope, permit)))
            {
                Ok(()) => {}
                Err(TrySendError::Full(work)) | Err(TrySendError::Disconnected(work)) => {
                    drop(work);
                    fatal("sidecar credential queue unavailable", &control, &public);
                    return;
                }
            }
            continue;
        }

        if envelope.kind == ProtocolKind::Event
            && envelope.payload.get("eventType") == Some(&Value::String("unknown-event".into()))
        {
            record_diagnostic(
                &diagnostics,
                "Unknown sidecar event was redacted and withheld from the interface.",
            );
            continue;
        }

        if !send_public(envelope, &public) {
            fatal("sidecar public response queue overflow", &control, &public);
            return;
        }
    }
}

fn record_diagnostic(diagnostics: &Mutex<VecDeque<String>>, message: &str) {
    let mut diagnostics = diagnostics
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if diagnostics.len() == 64 {
        diagnostics.pop_front();
    }
    diagnostics.push_back(message.into());
}

fn reserve_private_work(outstanding: &Arc<AtomicUsize>) -> Option<WorkPermit> {
    outstanding
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < PRIVATE_QUEUE_CAPACITY).then_some(count + 1)
        })
        .ok()
        .map(|_| WorkPermit(Arc::clone(outstanding)))
}

fn parse_approval_request(generation: u64, envelope: &Envelope) -> Result<ApprovalRequest, String> {
    crate::protocol::approval::validate_approval_request(&envelope.payload)?;
    let payload = &envelope.payload;
    let request_generation = payload
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(|| "approval request rejected".to_string())?;
    if request_generation != generation {
        return Err("approval request rejected".into());
    }
    Ok(ApprovalRequest {
        generation,
        correlation_id: envelope.id.clone(),
        session_id: payload
            .get("sessionId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        workspace_id: payload
            .get("workspaceId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        workspace_revision: payload
            .get("workspaceRevision")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        invocation_id: payload
            .get("invocationId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        tool_call_id: payload
            .get("toolCallId")
            .and_then(Value::as_str)
            .map(str::to_string),
        tool_name: payload
            .get("toolName")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        cohort: payload
            .get("cohort")
            .and_then(Value::as_object)
            .map(|cohort| ApprovalCohort {
                assistant_entry_id: cohort
                    .get("assistantEntryId")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                cohort_digest: cohort
                    .get("cohortDigest")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                ordered_members: cohort
                    .get("orderedMembers")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|member| {
                        let member = member.as_object();
                        ApprovalCohortMember {
                            ordinal: member
                                .and_then(|member| member.get("ordinal"))
                                .and_then(Value::as_u64)
                                .unwrap_or(usize::MAX as u64)
                                as usize,
                            tool_call_id: member
                                .and_then(|member| member.get("toolCallId"))
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                            tool_name: member
                                .and_then(|member| member.get("toolName"))
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                        }
                    })
                    .collect(),
            }),
        input: payload
            .get("input")
            .cloned()
            .ok_or_else(|| "approval request rejected".to_string())?,
        input_digest: payload
            .get("inputDigest")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

fn parse_approval_ready(
    generation: u64,
    envelope: &Envelope,
) -> Result<ApprovalReadyRequest, String> {
    crate::protocol::approval::validate_approval_ready(&envelope.payload)?;
    let payload = &envelope.payload;
    if payload.get("generation").and_then(Value::as_u64) != Some(generation) {
        return Err("approval ready rejected".into());
    }
    Ok(ApprovalReadyRequest {
        generation,
        correlation_id: envelope.id.clone(),
        invocation_id: payload
            .get("invocationId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        tool_call_id: payload
            .get("toolCallId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        input_digest: payload
            .get("inputDigest")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        cohort_digest: payload
            .get("cohortDigest")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

fn parse_approval_abandon(
    generation: u64,
    envelope: &Envelope,
) -> Result<ApprovalAbandonRequest, String> {
    crate::protocol::approval::validate_approval_abandon(&envelope.payload)?;
    let payload = &envelope.payload;
    if payload.get("generation").and_then(Value::as_u64) != Some(generation) {
        return Err("approval abandon rejected".into());
    }
    Ok(ApprovalAbandonRequest {
        generation,
        correlation_id: envelope.id.clone(),
        session_id: payload
            .get("sessionId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        workspace_id: payload
            .get("workspaceId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        workspace_revision: payload
            .get("workspaceRevision")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        assistant_entry_id: payload
            .get("assistantEntryId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        cohort_digest: payload
            .get("cohortDigest")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

fn approval_absolute_deadline(remaining: Duration) -> Result<Instant, String> {
    Instant::now()
        .checked_add(remaining.min(APPROVAL_WRITE_MAX_DURATION))
        .filter(|deadline| Instant::now() < *deadline)
        .ok_or_else(|| "sidecar approval write timed out".to_string())
}

fn lock_writer_until(
    writer: &Mutex<GenerationWriter>,
    absolute_deadline: Instant,
) -> Result<MutexGuard<'_, GenerationWriter>, String> {
    loop {
        if Instant::now() >= absolute_deadline {
            return Err("sidecar approval write timed out".into());
        }
        match writer.try_lock() {
            Ok(guard) => {
                if Instant::now() >= absolute_deadline {
                    drop(guard);
                    return Err("sidecar approval write timed out".into());
                }
                return Ok(guard);
            }
            Err(TryLockError::WouldBlock) => {
                let remaining = absolute_deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err("sidecar approval write timed out".into());
                }
                thread::sleep(remaining.min(Duration::from_millis(1)));
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err("sidecar writer unavailable".into());
            }
        }
    }
}

fn approval_coordinator_loop(
    generation: u64,
    registry: Arc<ApprovalRegistry>,
    workspace_registry: Arc<WorkspaceRegistry>,
    writer: Arc<Mutex<GenerationWriter>>,
    control: Arc<GenerationControl>,
) {
    // Jobs are still taken in the same order; only the idle wait changed
    // from polling to blocking until a decision, an expiry or the end of
    // the generation can have produced one.
    let waker_registry = Arc::clone(&registry);
    control.on_deactivate(Box::new(move || waker_registry.wake_coordinators()));
    while control.is_active() {
        let observed = registry.work_epoch();
        match registry.take_group_response_job(generation) {
            Ok(Some(job)) => {
                let response_token = job.response_token.clone();
                let binding = job.binding.clone();
                let result = workspace_registry.with_valid_approval_binding(&binding, || {
                    registry.complete_group_response(&response_token, |remaining_lifetime| {
                        let absolute_deadline = approval_absolute_deadline(remaining_lifetime)?;
                        let mut writer = lock_writer_until(&writer, absolute_deadline)?;
                        writer.write_group_approval_response(generation, job, absolute_deadline)
                    })
                });
                if result.is_err() {
                    control.invalidate("sidecar group approval response failed");
                    break;
                }
                continue;
            }
            Ok(None) => {}
            Err(_) => {
                control.invalidate("approval state unavailable");
                break;
            }
        }
        match registry.take_response_job(generation) {
            Ok(Some(job)) => {
                let response_token = job.response_token.clone();
                let binding = job.binding.clone();
                let approved = job.decision == "approved";
                let mut writer_attempted = false;
                let complete = || {
                    registry.complete_response(&response_token, |remaining_lifetime| {
                        writer_attempted = true;
                        let absolute_deadline = approval_absolute_deadline(remaining_lifetime)?;
                        let mut writer = lock_writer_until(&writer, absolute_deadline)?;
                        writer.write_approval_response(generation, job, absolute_deadline)
                    })
                };
                let result = if approved {
                    workspace_registry.with_valid_approval_binding(&binding, complete)
                } else {
                    complete()
                };
                if result.is_err() {
                    registry.cancel_response(&response_token);
                    if writer_attempted {
                        control.invalidate("sidecar approval response failed");
                        break;
                    }
                }
            }
            Ok(None) if control.is_active() => {
                registry.wait_for_work(observed, COORDINATOR_IDLE_WAIT);
            }
            Ok(None) => {}
            Err(_) => {
                control.invalidate("approval state unavailable");
                break;
            }
        }
    }
    registry.invalidate_generation(generation);
}

fn credential_coordinator_loop(
    generation: u64,
    events: Receiver<CoordinatorEvent>,
    events_sender: SyncSender<CoordinatorEvent>,
    proxy: CredentialProxy,
    writer: Arc<Mutex<GenerationWriter>>,
    control: Arc<GenerationControl>,
) {
    // The end of the generation wakes a blocked wait at once. The waker only
    // queues an event, so it is safe from whatever context invalidates.
    let waker = events_sender.clone();
    control.on_deactivate(Box::new(move || {
        let _ = waker.try_send(CoordinatorEvent::Wake);
    }));
    let mut buffered = VecDeque::with_capacity(PRIVATE_QUEUE_CAPACITY);
    let mut running: Option<RunningOperation> = None;
    let mut next_token = 0_u64;

    loop {
        if !control.is_active() {
            cancel_buffered_work(&proxy, &mut buffered);
            while let Ok(event) = events.try_recv() {
                if let CoordinatorEvent::Work(work) = event {
                    cancel_private_work(&proxy, work);
                }
            }
            return;
        }

        // Answer anything that has run out of time before the sidecar gives
        // up on it. A request still queued is cancelled without running; an
        // operation still inside storage is detached and its eventual
        // result is dropped.
        let now = Instant::now();
        if let Some(operation) = running.take_if(|operation| now >= operation.reply_deadline) {
            let pending = crate::credentials::proxy::PendingHostResponse::unavailable(
                operation.correlation_id.to_string(),
            );
            if !write_private_reply(generation, &writer, &control, pending) {
                return;
            }
        }
        while buffered
            .front()
            .is_some_and(|work: &PrivateWork| now >= work.reply_deadline)
        {
            let mut work = buffered.pop_front().expect("expired work present");
            let (request, permit) = work.take();
            let written =
                write_private_reply(generation, &writer, &control, proxy.cancel_request(request));
            drop(permit);
            if !written {
                return;
            }
        }

        if running.is_none()
            && let Some(work) = buffered.pop_front()
        {
            next_token = next_token.wrapping_add(1);
            let token = next_token;
            let correlation_id = Zeroizing::new(
                work.request
                    .as_ref()
                    .map(|request| request.id.clone())
                    .unwrap_or_default(),
            );
            let reply_deadline = work.reply_deadline;
            let operation_proxy = proxy.clone();
            let operation_sender = events_sender.clone();
            let mut candidate = Some(work);
            let promoted = control.authorised_attempt(|| {
                let mut work = candidate.take().expect("promotion candidate owned");
                thread::spawn(move || {
                    let (request, permit) = work.take();
                    let pending = operation_proxy.try_execute_request(request);
                    let _ = operation_sender.send(CoordinatorEvent::Completed(
                        token,
                        CompletedWork {
                            pending,
                            _permit: permit,
                        },
                    ));
                });
            });
            match promoted {
                Ok(()) => {
                    running = Some(RunningOperation {
                        token,
                        correlation_id,
                        reply_deadline,
                    });
                }
                Err(()) => {
                    if let Some(work) = candidate.take() {
                        cancel_private_work(&proxy, work);
                    }
                }
            }
            continue;
        }

        let next_deadline = running
            .as_ref()
            .map(|operation| operation.reply_deadline)
            .into_iter()
            .chain(buffered.front().map(|work| work.reply_deadline))
            .min();
        let wait = next_deadline.map_or(COORDINATOR_IDLE_WAIT, |deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .min(COORDINATOR_IDLE_WAIT)
        });
        match events.recv_timeout(wait) {
            Ok(CoordinatorEvent::Work(work)) => buffered.push_back(work),
            Ok(CoordinatorEvent::Completed(token, completed)) => {
                if running
                    .as_ref()
                    .is_none_or(|operation| operation.token != token)
                {
                    // Already answered as unavailable; this late result must
                    // never become a second reply.
                    drop(completed);
                    continue;
                }
                running = None;
                if !control.is_active() {
                    drop(completed);
                    continue;
                }
                let CompletedWork { pending, _permit } = completed;
                let written = write_private_reply(generation, &writer, &control, pending);
                drop(_permit);
                if !written {
                    return;
                }
            }
            Ok(CoordinatorEvent::Wake) | Err(RecvTimeoutError::Timeout) => {}
            // The coordinator holds a sender itself, so this cannot occur
            // while it runs; treat it as the end of the generation.
            Err(RecvTimeoutError::Disconnected) => {
                cancel_buffered_work(&proxy, &mut buffered);
                return;
            }
        }
    }
}

/// Writes one credential reply. `false` means the generation has ended and
/// the coordinator must stop.
fn write_private_reply(
    generation: u64,
    writer: &Mutex<GenerationWriter>,
    control: &Arc<GenerationControl>,
    pending: crate::credentials::proxy::PendingHostResponse,
) -> bool {
    let result = writer
        .lock()
        .map_err(|_| "sidecar writer unavailable".to_string())
        .and_then(|mut writer| writer.write_private_response(generation, pending));
    if result.is_err() && control.is_active() {
        fail_generation("sidecar private response write failed", control, None);
        return false;
    }
    // A write refused because the generation already ended is not a new
    // failure; the next pass cancels what remains.
    true
}

fn cancel_buffered_work(proxy: &CredentialProxy, buffered: &mut VecDeque<PrivateWork>) {
    while let Some(work) = buffered.pop_front() {
        cancel_private_work(proxy, work);
    }
}

fn cancel_private_work(proxy: &CredentialProxy, mut work: PrivateWork) {
    let (request, permit) = work.take();
    drop(proxy.cancel_request(request));
    drop(permit);
}

fn forbidden_inbound_identifier(value: &str) -> bool {
    value.starts_with("ui-") || value == AUTHENTICATED_INTERNAL_SNAPSHOT_CORRELATION
}

fn valid_snapshot(envelope: &Envelope, after_sequence: u64) -> bool {
    let Some(snapshot) = envelope.payload.get("snapshot").and_then(Value::as_object) else {
        return false;
    };
    envelope.kind == ProtocolKind::Response
        && snapshot
            .get("sequence")
            .and_then(Value::as_u64)
            .is_some_and(|sequence| sequence >= after_sequence && sequence <= envelope.sequence)
        && snapshot.get("state").is_some_and(Value::is_object)
}

fn send_public(envelope: Envelope, public: &PublicRouter) -> bool {
    debug_assert!(!matches!(
        envelope.kind,
        ProtocolKind::HostRequest | ProtocolKind::HostResponse
    ));
    public.route(envelope)
}

fn fatal(message: &str, control: &Arc<GenerationControl>, public: &PublicRouter) {
    fail_generation(message, control, None);
    public.fail(message);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::validate_envelope;
    use crate::supervisor::process::NonblockingSink;
    use crate::supervisor::public_router::PublicMessage;
    use std::io::Error;
    use std::sync::mpsc::SyncSender;
    use std::sync::mpsc::TryRecvError;
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    #[derive(Clone, Default)]
    struct SharedSink(Arc<Mutex<Vec<u8>>>);

    impl NonblockingSink for SharedSink {
        fn try_write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn wait_writable(&mut self, _timeout: Duration) -> std::io::Result<bool> {
            Ok(true)
        }
    }

    #[test]
    fn contended_writer_mutex_cannot_restart_individual_or_group_deadlines() {
        use crate::domain::approval::{
            ApprovalResponseJob, GroupApprovalMemberJob, GroupApprovalResponseJob,
        };
        use crate::domain::workspace::WorkspaceApprovalBinding;

        for group in [false, true] {
            let failure = Arc::new(Mutex::new(None));
            let control = Arc::new(GenerationControl::new(i32::MAX, failure));
            let sink = SharedSink::default();
            let writer = Arc::new(Mutex::new(GenerationWriter::with_sink_for_test(
                1,
                Box::new(sink.clone()),
                Arc::clone(&control),
            )));
            let held = writer.lock().unwrap();
            let (minted_sender, minted_receiver) = sync_channel(1);
            let marker = Arc::new(AtomicUsize::new(0));
            let attempted_marker = Arc::clone(&marker);
            let attempted_writer = Arc::clone(&writer);
            let attempted_control = Arc::clone(&control);
            let attempt = thread::spawn(move || {
                let absolute_deadline = Instant::now() + Duration::from_millis(10);
                minted_sender.send(()).unwrap();
                let result = lock_writer_until(&attempted_writer, absolute_deadline).and_then(
                    |mut writer| {
                        if group {
                            writer.write_group_approval_response(
                                1,
                                GroupApprovalResponseJob {
                                    response_token: format!("response-{:032x}", 1),
                                    binding: WorkspaceApprovalBinding::for_test(
                                        format!("workspace-{:032x}", 2),
                                        1,
                                    ),
                                    generation: 1,
                                    session_id: format!("session-{:032x}", 1),
                                    workspace_id: format!("workspace-{:032x}", 2),
                                    workspace_revision: 1,
                                    assistant_entry_id: "assistant-entry-contended".into(),
                                    group_id: format!("group-{:032x}", 3),
                                    decision_id: format!("decision-{:032x}", 4),
                                    transaction_id: format!("transaction-{:032x}", 5),
                                    cohort_digest: "a".repeat(64),
                                    members: (0..2)
                                        .map(|index| GroupApprovalMemberJob {
                                            correlation_id: format!("sidecar-contended-{index}"),
                                            approval_id: format!("approval-{:032x}", index + 10),
                                            decision_id: format!("decision-{:032x}", index + 20),
                                            invocation_id: format!(
                                                "invocation-{:032x}",
                                                index + 30
                                            ),
                                            tool_call_id: format!("tool-call-{}", index + 1),
                                            input_digest: "b".repeat(64),
                                            scope_id: format!("scope-{:032x}", index + 40),
                                        })
                                        .collect(),
                                },
                                absolute_deadline,
                            )
                        } else {
                            writer.write_approval_response(
                                1,
                                ApprovalResponseJob {
                                    response_token: format!("response-{:032x}", 1),
                                    binding: WorkspaceApprovalBinding::for_test(
                                        format!("workspace-{:032x}", 2),
                                        1,
                                    ),
                                    correlation_id: "sidecar-contended-individual".into(),
                                    decision_id: format!("decision-{:032x}", 4),
                                    approval_id: format!("approval-{:032x}", 3),
                                    transaction_id: format!("transaction-{:032x}", 5),
                                    invocation_id: format!("invocation-{:032x}", 6),
                                    tool_call_id: Some("tool-call-1".into()),
                                    cohort_digest: Some("a".repeat(64)),
                                    input_digest: "b".repeat(64),
                                    decision: "approved",
                                    scope_ids: vec![format!("scope-{:032x}", 7)],
                                },
                                absolute_deadline,
                            )
                        }
                    },
                );
                if result.is_ok() {
                    attempted_marker.fetch_add(1, Ordering::SeqCst);
                } else {
                    attempted_control.invalidate("sidecar approval response failed");
                }
                result
            });
            minted_receiver.recv().unwrap();
            thread::sleep(Duration::from_millis(20));
            drop(held);
            assert_eq!(
                attempt.join().unwrap().unwrap_err(),
                "sidecar approval write timed out"
            );
            assert!(
                sink.0.lock().unwrap().is_empty(),
                "no body or LF may be written"
            );
            assert_eq!(marker.load(Ordering::SeqCst), 0, "no delegate marker");
            assert!(!control.is_active());
        }
    }

    struct Rig {
        raw: SyncSender<RawFrame>,
        public: Arc<PublicRouter>,
        workspace: Receiver<PublicMessage>,
        control: Arc<GenerationControl>,
        failure: crate::supervisor::stdio::FailureSignal,
        writer: Arc<Mutex<GenerationWriter>>,
        approval_registry: Arc<ApprovalRegistry>,
        workspace_registry: Arc<WorkspaceRegistry>,
        product_waiters: Arc<ProductWaiters>,
        diagnostics: Arc<Mutex<VecDeque<String>>>,
        sink: SharedSink,
        handles: DispatcherHandles,
    }

    impl Rig {
        fn new(proxy: CredentialProxy) -> Self {
            let sink = SharedSink::default();
            let failure = Arc::new(Mutex::new(None));
            let control = Arc::new(GenerationControl::new(i32::MAX, Arc::clone(&failure)));
            let writer = Arc::new(Mutex::new(GenerationWriter::with_sink_for_test(
                1,
                Box::new(sink.clone()),
                Arc::clone(&control),
            )));
            let (raw, raw_receiver) = sync_channel(RAW_QUEUE_CAPACITY);
            let public = Arc::new(PublicRouter::new(PUBLIC_QUEUE_CAPACITY));
            let workspace_waiters = Arc::new(WorkspaceWaiters::new());
            let (workspace_sender, workspace) = sync_channel(1);
            workspace_waiters
                .register("rust-workspace-1-1", 1, workspace_sender)
                .unwrap();
            let mut decoder = ProtocolDecoder::default();
            decoder.decode(&line(serde_json::json!({
                "version":1,"kind":"handshake","id":"handshake-test","sequence":0,
                "payload":{"protocolVersion":1,"desktopVersion":"0.1.0","piVersion":"0.82.0","nodeVersion":"22.23.1","nonce":"dispatcher-test-nonce","architecture":"arm64","capabilities":["streaming","cancellation","snapshot-resync"]}
            }))).unwrap();
            let approval_registry = Arc::new(ApprovalRegistry::default());
            let workspace_registry = Arc::new(WorkspaceRegistry::default());
            let product_waiters = Arc::new(ProductWaiters::new());
            let diagnostics = Arc::new(Mutex::new(VecDeque::new()));
            let handles = start_dispatcher(
                1,
                decoder,
                raw_receiver,
                Arc::clone(&public),
                workspace_waiters,
                Arc::clone(&product_waiters),
                proxy,
                Arc::clone(&approval_registry),
                Arc::clone(&workspace_registry),
                Arc::clone(&writer),
                Arc::clone(&control),
                Arc::clone(&diagnostics),
                0,
            );
            Self {
                raw,
                public,
                workspace,
                control,
                failure,
                writer,
                approval_registry,
                workspace_registry,
                product_waiters,
                diagnostics,
                sink,
                handles,
            }
        }

        fn send(&self, value: Value) -> Result<(), ()> {
            self.raw.send(RawFrame::Line(line(value))).map_err(|_| ())
        }

        fn wait_for_lines(&self, count: usize) -> Vec<Envelope> {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let bytes = self.sink.0.lock().unwrap().clone();
                if bytes.iter().filter(|byte| **byte == b'\n').count() >= count {
                    let mut decoder = ProtocolDecoder::default();
                    return bytes
                        .split_inclusive(|byte| *byte == b'\n')
                        .filter(|line| line.last() == Some(&b'\n'))
                        .map(|line| decoder.decode(line).unwrap())
                        .collect();
                }
                assert!(Instant::now() < deadline, "writer output timed out");
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        fn shutdown(self) {
            self.control.deactivate();
            drop(self.raw);
            let _ = self.handles.dispatcher.join();
            let _ = self.handles.credential_coordinator.join();
            let _ = self.handles.approval_coordinator.join();
        }
    }

    fn line(value: Value) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(serde_json::to_vec(&value).unwrap());
        bytes.push(b'\n');
        bytes
    }

    fn host(sequence: u64, id: &str, payload: Value) -> Value {
        serde_json::json!({
            "version":1,"kind":"host-request","id":id,"sequence":sequence,
            "payload":payload
        })
    }

    fn event(sequence: u64, id: &str) -> Value {
        serde_json::json!({
            "version":1,"kind":"event","id":id,"sequence":sequence,
            "payload":{"eventType":"sidecar.status","status":"ready"}
        })
    }

    fn list_request(sequence: u64, id: &str) -> Envelope {
        serde_json::from_value(host(
            sequence,
            id,
            serde_json::json!({"method":"credential.list"}),
        ))
        .unwrap()
    }

    #[test]
    fn continuously_handles_private_round_trip_without_public_receiver() {
        let proxy = CredentialProxy::in_memory_for_dispatcher_test();
        let rig = Rig::new(proxy);
        let canary = format!(
            "runtime-dispatcher-canary-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        );
        rig.send(host(
            1,
            "set-1",
            serde_json::json!({
                "method":"credential.set","providerId":"test-provider",
                "credential":{"type":"api_key","key":canary}
            }),
        ))
        .unwrap();
        rig.send(host(
            2,
            "get-1",
            serde_json::json!({"method":"credential.get","providerId":"test-provider"}),
        ))
        .unwrap();
        rig.send(host(
            3,
            "list-1",
            serde_json::json!({"method":"credential.list"}),
        ))
        .unwrap();
        rig.send(host(
            4,
            "remove-1",
            serde_json::json!({"method":"credential.remove","providerId":"test-provider"}),
        ))
        .unwrap();

        let mut responses = rig.wait_for_lines(4);
        assert!(responses.iter().all(|response| {
            response.kind == ProtocolKind::HostResponse && validate_envelope(response).is_ok()
        }));
        let get = responses
            .iter()
            .find(|response| response.correlation_id.as_deref() == Some("get-1"))
            .unwrap();
        assert!(
            get.payload
                .get("credential")
                .and_then(Value::as_object)
                .and_then(|credential| credential.get("key"))
                .and_then(Value::as_str)
                .is_some_and(|key| key == canary),
            "private dispatcher get did not return the runtime canary"
        );
        let list = responses
            .iter()
            .find(|response| response.correlation_id.as_deref() == Some("list-1"))
            .unwrap();
        assert!(list.payload.get("credential").is_none());
        assert_eq!(list.payload["entries"].as_array().map(Vec::len), Some(1));
        assert!(matches!(
            rig.public.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        let request: Envelope = serde_json::from_value(serde_json::json!({
            "version":1,"kind":"request","id":"web-public-snapshot","sequence":999,
            "payload":{"method":"snapshot","afterSequence":0}
        }))
        .unwrap();
        {
            let mut writer = rig.writer.lock().unwrap();
            writer.write_public(1, &request).unwrap();
            writer.write_snapshot_request(1, 4).unwrap();
        }
        responses = rig.wait_for_lines(6);
        assert_eq!(
            responses
                .iter()
                .map(|envelope| envelope.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5, 6]
        );
        rig.shutdown();
    }

    #[test]
    fn public_progresses_while_private_work_is_held_and_shutdown_cancels_queued_mutation() {
        let (proxy, gate) = CredentialProxy::in_memory_with_dispatcher_gate_for_test();
        let inspection_proxy = proxy.clone();
        let rig = Rig::new(proxy);
        rig.send(host(
            1,
            "held-set",
            serde_json::json!({
                "method":"credential.set","providerId":"committed-provider",
                "credential":{"type":"api_key","key":"held-runtime-value"}
            }),
        ))
        .unwrap();
        gate.wait_until_entered();
        rig.send(event(2, "public-during-held")).unwrap();
        let first_public = rig
            .public
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(first_public.id, "public-during-held");
        rig.send(host(
            3,
            "queued-set",
            serde_json::json!({
                "method":"credential.set","providerId":"must-not-run",
                "credential":{"type":"api_key","key":"queued-runtime-value"}
            }),
        ))
        .unwrap();
        rig.send(event(4, "public-after-queued")).unwrap();
        let second_public = rig
            .public
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(second_public.id, "public-after-queued");

        rig.control.deactivate();
        gate.release();
        std::thread::sleep(Duration::from_millis(30));
        assert!(rig.sink.0.lock().unwrap().is_empty());

        let response = inspection_proxy
            .dispatch(
                list_request(1, "inspection-list"),
                "inspection-response".into(),
                1,
            )
            .unwrap()
            .into_lf_json()
            .unwrap();
        let mut decoder = ProtocolDecoder::default();
        let response = decoder.decode(&response).unwrap();
        let entries = response.payload["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["providerId"], "committed-provider");
        assert!(
            entries
                .iter()
                .all(|entry| entry["providerId"] != "must-not-run")
        );
        rig.shutdown();
    }

    #[test]
    fn private_queue_overflow_is_fatal_and_queued_mutations_are_not_replayed() {
        let (proxy, gate) = CredentialProxy::in_memory_with_dispatcher_gate_for_test();
        let inspection_proxy = proxy.clone();
        let rig = Rig::new(proxy);
        rig.send(host(
            1,
            "overflow-held-set",
            serde_json::json!({
                "method":"credential.set","providerId":"overflow-committed",
                "credential":{"type":"api_key","key":"overflow-held-value"}
            }),
        ))
        .unwrap();
        gate.wait_until_entered();

        for index in 0..=PRIVATE_QUEUE_CAPACITY {
            if rig
                .send(host(
                    index as u64 + 2,
                    &format!("overflow-queued-{index}"),
                    serde_json::json!({
                        "method":"credential.set",
                        "providerId":format!("overflow-must-not-run-{index}"),
                        "credential":{"type":"api_key","key":"overflow-queued-value"}
                    }),
                ))
                .is_err()
            {
                break;
            }
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while rig.control.is_active() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!rig.control.is_active());
        assert_eq!(
            rig.failure.lock().unwrap().as_deref(),
            Some("sidecar credential queue unavailable")
        );
        gate.release();
        assert!(rig.sink.0.lock().unwrap().is_empty());
        rig.shutdown();

        let response = inspection_proxy
            .dispatch(
                list_request(1, "overflow-inspection-list"),
                "overflow-inspection-response".into(),
                1,
            )
            .unwrap()
            .into_lf_json()
            .unwrap();
        let mut decoder = ProtocolDecoder::default();
        let response = decoder.decode(&response).unwrap();
        let entries = response.payload["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["providerId"], "overflow-committed");
    }

    #[test]
    fn reserved_internal_ids_cannot_collide_with_public_or_private_writes() {
        let proxy = CredentialProxy::in_memory_for_dispatcher_test();
        let rig = Rig::new(proxy.clone());
        let reserved_request: Envelope = serde_json::from_value(serde_json::json!({
            "version":1,"kind":"request","id":"rust-snapshot-1-1","sequence":1,
            "payload":{"method":"snapshot","afterSequence":0}
        }))
        .unwrap();
        let reserved_correlation: Envelope = serde_json::from_value(serde_json::json!({
            "version":1,"kind":"cancel","id":"web-public-cancel","correlationId":"rust-host-response-1-1","sequence":2,
            "payload":{}
        }))
        .unwrap();
        let reserved_ui: Envelope = serde_json::from_value(serde_json::json!({
            "version":1,"kind":"request","id":"ui-envelope-1","sequence":3,
            "payload":{"method":"snapshot","afterSequence":0}
        }))
        .unwrap();
        let synthetic_sidecar: Envelope = serde_json::from_value(serde_json::json!({
            "version":1,"kind":"request","id":"sidecar-37","sequence":4,
            "payload":{"method":"snapshot","afterSequence":0}
        }))
        .unwrap();
        let ordinary: Envelope = serde_json::from_value(serde_json::json!({
            "version":1,"kind":"request","id":"web-public-request","sequence":99,
            "payload":{"method":"snapshot","afterSequence":0}
        }))
        .unwrap();
        {
            let mut writer = rig.writer.lock().unwrap();
            assert_eq!(
                writer.write_public(1, &reserved_request).unwrap_err(),
                "sidecar request is not permitted"
            );
            assert_eq!(
                writer.write_public(1, &reserved_correlation).unwrap_err(),
                "sidecar request is not permitted"
            );
            assert_eq!(
                writer.write_public(1, &reserved_ui).unwrap_err(),
                "sidecar request is not permitted"
            );
            assert_eq!(
                writer.write_public(1, &synthetic_sidecar).unwrap_err(),
                "sidecar request is not permitted"
            );
            assert!(rig.sink.0.lock().unwrap().is_empty());
            writer.write_public(1, &ordinary).unwrap();
            writer.write_snapshot_request(1, 0).unwrap();
            let pending = proxy.try_execute_request(list_request(1, "private-list"));
            writer.write_private_response(1, pending).unwrap();
        }
        let envelopes = rig.wait_for_lines(3);
        assert_eq!(
            envelopes
                .iter()
                .map(|envelope| envelope.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        let ids = envelopes
            .iter()
            .map(|envelope| envelope.id.as_str())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains("web-public-request"));
        assert!(ids.iter().filter(|id| id.starts_with("rust-")).count() == 2);
        rig.shutdown();
    }

    #[test]
    fn snapshot_repair_covers_hidden_boundary_and_repeated_correlation_is_duplicate() {
        let rig = Rig::new(CredentialProxy::in_memory_for_dispatcher_test());
        rig.send(host(
            1,
            "hidden-list",
            serde_json::json!({"method":"credential.list"}),
        ))
        .unwrap();
        rig.send(event(3, "gapped-public")).unwrap();
        let outbound = rig.wait_for_lines(2);
        let snapshot_id = outbound
            .iter()
            .find(|envelope| {
                envelope.kind == ProtocolKind::Request
                    && envelope.payload.get("method") == Some(&Value::String("snapshot".into()))
            })
            .map(|envelope| envelope.id.clone())
            .expect("snapshot request written");
        rig.send(serde_json::json!({
            "version":1,"kind":"response","id":"snapshot-response","correlationId":snapshot_id,
            "sequence":4,"payload":{"snapshot":{"sequence":1,"state":{}}}
        }))
        .unwrap();
        let snapshot = rig
            .public
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.id, "snapshot-response");
        assert_eq!(
            snapshot.correlation_id.as_deref(),
            Some(AUTHENTICATED_INTERNAL_SNAPSHOT_CORRELATION)
        );
        let correlation = snapshot_id.clone();
        rig.send(serde_json::json!({
            "version":1,"kind":"response","id":"snapshot-repeat","correlationId":correlation,
            "sequence":5,"payload":{}
        }))
        .unwrap();
        rig.send(event(6, "after-repeated-snapshot")).unwrap();
        let after = rig
            .public
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(after.id, "after-repeated-snapshot");
        assert!(matches!(
            rig.public.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        rig.shutdown();

        let stale = Rig::new(CredentialProxy::in_memory_for_dispatcher_test());
        stale
            .send(host(
                1,
                "stale-hidden-list",
                serde_json::json!({"method":"credential.list"}),
            ))
            .unwrap();
        stale.send(event(3, "stale-gap")).unwrap();
        let outbound = stale.wait_for_lines(2);
        let snapshot_id = outbound
            .iter()
            .find(|envelope| {
                envelope.payload.get("method") == Some(&Value::String("snapshot".into()))
            })
            .map(|envelope| envelope.id.clone())
            .unwrap();
        stale
            .send(serde_json::json!({
                "version":1,"kind":"response","id":"stale-snapshot","correlationId":snapshot_id,
                "sequence":4,"payload":{"snapshot":{"sequence":0,"state":{}}}
            }))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while stale.control.is_active() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!stale.control.is_active());
        assert_eq!(
            stale.failure.lock().unwrap().as_deref(),
            Some("sidecar snapshot invalid")
        );
        stale.shutdown();
    }

    #[test]
    fn forged_authenticated_marker_and_ui_namespace_are_generation_fatal() {
        for forged in [
            serde_json::json!({
                "version":1,"kind":"event","id":"sidecar-forged-marker","sequence":1,
                "correlationId":AUTHENTICATED_INTERNAL_SNAPSHOT_CORRELATION,
                "payload":{"eventType":"sidecar.status","status":"ready"}
            }),
            serde_json::json!({
                "version":1,"kind":"event","id":"ui-envelope-9","sequence":1,
                "payload":{"eventType":"sidecar.status","status":"ready"}
            }),
            serde_json::json!({
                "version":1,"kind":"event","id":"sidecar-forged-ui","sequence":1,
                "correlationId":"ui-internal-9",
                "payload":{"eventType":"sidecar.status","status":"ready"}
            }),
        ] {
            let rig = Rig::new(CredentialProxy::in_memory_for_dispatcher_test());
            rig.send(forged).unwrap();
            let deadline = Instant::now() + Duration::from_secs(1);
            while rig.control.is_active() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(!rig.control.is_active());
            assert_eq!(
                rig.failure.lock().unwrap().as_deref(),
                Some("sidecar identifier namespace invalid")
            );
            rig.shutdown();
        }
    }

    #[test]
    fn workspace_correlations_are_continuously_consumed_without_public_projection() {
        let rig = Rig::new(CredentialProxy::in_memory_for_dispatcher_test());
        rig.send(serde_json::json!({
            "version":1,"kind":"response","id":"sidecar-workspace-1",
            "correlationId":"rust-workspace-1-1","sequence":1,
            "payload":{"schemaVersion":1,"revision":1,"resourceState":"trusted"}
        }))
        .unwrap();
        let response = rig
            .workspace
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(
            response.correlation_id.as_deref(),
            Some("rust-workspace-1-1")
        );
        assert!(matches!(rig.public.try_recv(), Err(TryRecvError::Empty)));
        rig.shutdown();
    }

    #[test]
    fn an_abandon_for_a_cohort_the_host_already_cleaned_up_is_acknowledged() {
        let rig = Rig::new(CredentialProxy::in_memory_for_dispatcher_test());
        rig.send(host(
            1,
            "sidecar-abandon-unknown-1",
            serde_json::json!({
                "method":"approval.abandon","schemaVersion":2,"generation":1,
                "sessionId":format!("session-{:032x}", 1),
                "workspaceId":format!("workspace-{:032x}", 2),
                "workspaceRevision":1,
                "assistantEntryId":"assistant-entry-gone",
                "cohortDigest":"c".repeat(64),
                "reason":"pi-abort"
            }),
        ))
        .unwrap();
        let written = rig.wait_for_lines(1);
        assert_eq!(written[0].kind, ProtocolKind::HostResponse);
        assert_eq!(
            written[0].correlation_id.as_deref(),
            Some("sidecar-abandon-unknown-1")
        );
        assert_eq!(written[0].payload["method"], "approval.abandon-ack");
        assert_eq!(written[0].payload["cohortDigest"], "c".repeat(64));
        assert_eq!(written[0].payload["cancelled"], true);
        assert!(
            rig.control.is_active(),
            "a racing abandon must not be fatal"
        );

        // A malformed abandon is still a protocol violation.
        rig.send(host(
            2,
            "sidecar-abandon-malformed-1",
            serde_json::json!({
                "method":"approval.abandon","schemaVersion":2,"generation":1,
                "sessionId":format!("session-{:032x}", 1),
                "workspaceId":format!("workspace-{:032x}", 2),
                "workspaceRevision":1,
                "assistantEntryId":"assistant-entry-gone",
                "cohortDigest":"c".repeat(64),
                "reason":"not-a-reason"
            }),
        ))
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while rig.control.is_active() {
            assert!(Instant::now() < deadline, "malformed abandon was accepted");
            std::thread::sleep(Duration::from_millis(5));
        }
        rig.shutdown();
    }

    #[test]
    fn a_late_product_response_is_discarded_without_ending_the_generation() {
        let rig = Rig::new(CredentialProxy::in_memory_for_dispatcher_test());
        let (sender, receiver) = sync_channel(1);
        rig.product_waiters
            .register("rust-product-1-7", 1, sender)
            .unwrap();
        // The command gave up waiting, exactly as the waiter's Drop does.
        drop(receiver);
        rig.product_waiters.retire("rust-product-1-7");
        rig.send(serde_json::json!({
            "version":1,"kind":"response","id":"sidecar-late-product",
            "correlationId":"rust-product-1-7","sequence":1,
            "payload":{"schemaVersion":1,"compacted":true}
        }))
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while rig.diagnostics.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline, "late response not recorded");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(rig.control.is_active(), "a late answer must not be fatal");
        assert!(rig.failure.lock().unwrap().is_none());
        assert!(
            rig.diagnostics.lock().unwrap()[0].contains("after its request timed out"),
            "{:?}",
            rig.diagnostics.lock().unwrap()
        );

        // A correlation that was never issued is still a protocol violation.
        rig.send(serde_json::json!({
            "version":1,"kind":"response","id":"sidecar-unknown-product",
            "correlationId":"rust-product-1-8","sequence":2,
            "payload":{"schemaVersion":1,"compacted":true}
        }))
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while rig.control.is_active() {
            assert!(Instant::now() < deadline, "unknown response was accepted");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            rig.failure.lock().unwrap().as_deref(),
            Some("sidecar product response unavailable")
        );
        rig.shutdown();
    }

    #[test]
    fn shutdown_drains_queued_canaries_when_executing_repository_never_returns() {
        let (proxy, gate) = CredentialProxy::in_memory_with_dispatcher_gate_for_test();
        let replacement_proxy = proxy.clone();
        let rig = Rig::new(proxy);
        rig.send(host(
            1,
            "never-returning-set",
            serde_json::json!({
                "method":"credential.set","providerId":"never-returning",
                "credential":{"type":"api_key","key":"executing-value"}
            }),
        ))
        .unwrap();
        gate.wait_until_entered();
        let queued_canary = format!("queued-drain-canary-{}", std::process::id());
        let queued_bytes = queued_canary.len() * 3;
        let before = crate::credentials::proxy::private_zeroised_bytes_for_test();
        for index in 0..3 {
            rig.send(host(
                index + 2,
                &format!("queued-never-{index}"),
                serde_json::json!({
                    "method":"credential.set","providerId":format!("queued-never-provider-{index}"),
                    "credential":{"type":"api_key","key":queued_canary}
                }),
            ))
            .unwrap();
        }
        rig.send(event(5, "queued-drain-barrier")).unwrap();
        let barrier = rig
            .public
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(barrier.id, "queued-drain-barrier");
        rig.control.deactivate();
        rig.shutdown();
        assert!(
            crate::credentials::proxy::private_zeroised_bytes_for_test() >= before + queued_bytes
        );

        let started = Instant::now();
        let unavailable = replacement_proxy
            .try_execute_request(list_request(1, "replacement-list"))
            .bind("replacement-response".into(), 1)
            .unwrap()
            .into_lf_json()
            .unwrap();
        assert!(started.elapsed() < Duration::from_millis(100));
        let mut decoder = ProtocolDecoder::default();
        let unavailable = decoder.decode(&unavailable).unwrap();
        assert_eq!(
            unavailable.error.as_ref().map(|error| error.category),
            Some(crate::protocol::ErrorCategory::Unavailable)
        );
        // Deliberately do not release the gate: only this one executing test
        // operation remains detached; all queued envelopes were erased.
    }

    #[test]
    fn promotion_loses_to_invalidation_and_cancels_without_repository_start() {
        let proxy = CredentialProxy::in_memory_for_dispatcher_test();
        let inspection_proxy = proxy.clone();
        let failure = Arc::new(Mutex::new(None));
        let control = Arc::new(GenerationControl::new(i32::MAX, failure));
        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let hook_reached = Arc::clone(&reached);
        let hook_release = Arc::clone(&release);
        control.set_authorisation_hook(Some(Arc::new(move || {
            hook_reached.wait();
            hook_release.wait();
        })));
        let sink = SharedSink::default();
        let writer = Arc::new(Mutex::new(GenerationWriter::with_sink_for_test(
            1,
            Box::new(sink),
            Arc::clone(&control),
        )));
        let (sender, receiver) = sync_channel(PRIVATE_QUEUE_CAPACITY);
        let outstanding = Arc::new(AtomicUsize::new(0));
        let canary = format!("promotion-race-canary-{}", std::process::id());
        let canary_len = canary.len();
        let before = crate::credentials::proxy::private_zeroised_bytes_for_test();
        let request: Envelope = serde_json::from_value(host(
            1,
            "promotion-race-set",
            serde_json::json!({
                "method":"credential.set","providerId":"must-not-promote",
                "credential":{"type":"api_key","key":canary}
            }),
        ))
        .unwrap();
        sender
            .send(CoordinatorEvent::Work(PrivateWork::new(
                request,
                reserve_private_work(&outstanding).unwrap(),
            )))
            .unwrap();
        let coordinator_control = Arc::clone(&control);
        let coordinator = thread::spawn(move || {
            credential_coordinator_loop(1, receiver, sender, proxy, writer, coordinator_control)
        });
        reached.wait();
        assert!(control.deactivate());
        release.wait();
        coordinator.join().unwrap();
        assert_eq!(outstanding.load(Ordering::Acquire), 0);
        assert!(
            crate::credentials::proxy::private_zeroised_bytes_for_test() >= before + canary_len
        );

        let listed = inspection_proxy
            .dispatch(
                list_request(1, "promotion-inspection"),
                "promotion-inspection-response".into(),
                1,
            )
            .unwrap()
            .into_lf_json()
            .unwrap();
        let mut decoder = ProtocolDecoder::default();
        let listed = decoder.decode(&listed).unwrap();
        assert_eq!(listed.payload["entries"].as_array().map(Vec::len), Some(0));
    }

    fn coordinator_rig(
        proxy: CredentialProxy,
    ) -> (
        Arc<GenerationControl>,
        SharedSink,
        SyncSender<CoordinatorEvent>,
        Arc<AtomicUsize>,
        JoinHandle<()>,
    ) {
        let control = Arc::new(GenerationControl::new(i32::MAX, Arc::new(Mutex::new(None))));
        let sink = SharedSink::default();
        let writer = Arc::new(Mutex::new(GenerationWriter::with_sink_for_test(
            1,
            Box::new(sink.clone()),
            Arc::clone(&control),
        )));
        let (sender, receiver) = sync_channel(PRIVATE_QUEUE_CAPACITY + 2);
        let coordinator_sender = sender.clone();
        let coordinator_control = Arc::clone(&control);
        let coordinator = thread::spawn(move || {
            credential_coordinator_loop(
                1,
                receiver,
                coordinator_sender,
                proxy,
                writer,
                coordinator_control,
            )
        });
        (
            control,
            sink,
            sender,
            Arc::new(AtomicUsize::new(0)),
            coordinator,
        )
    }

    fn written_replies(sink: &SharedSink) -> Vec<Envelope> {
        let bytes = sink.0.lock().unwrap().clone();
        let mut decoder = ProtocolDecoder::default();
        bytes
            .split_inclusive(|byte| *byte == b'\n')
            .map(|line| decoder.decode(line).unwrap())
            .collect()
    }

    #[test]
    fn a_credential_request_stuck_in_storage_is_answered_before_the_sidecar_gives_up() {
        assert!(CREDENTIAL_REPLY_BUDGET < Duration::from_secs(120));
        let (proxy, gate) = CredentialProxy::in_memory_with_dispatcher_gate_for_test();
        let (control, sink, sender, outstanding, coordinator) = coordinator_rig(proxy);
        let short_budget = |id: &str, provider: &str| {
            let request: Envelope = serde_json::from_value(host(
                1,
                id,
                serde_json::json!({
                    "method":"credential.set","providerId":provider,
                    "credential":{"type":"api_key","key":"stuck-value"}
                }),
            ))
            .unwrap();
            let mut work = PrivateWork::new(request, reserve_private_work(&outstanding).unwrap());
            work.reply_deadline = Instant::now() + Duration::from_millis(80);
            CoordinatorEvent::Work(work)
        };
        sender
            .send(short_budget("stuck-set", "stuck-provider"))
            .unwrap();
        gate.wait_until_entered();
        // Queued behind the stuck operation; its own budget also runs out.
        sender
            .send(short_budget("queued-set", "queued-provider"))
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        while written_replies(&sink).len() < 2 {
            assert!(
                Instant::now() < deadline,
                "stuck requests were not answered"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let replies = written_replies(&sink);
        let by_correlation = |id: &str| {
            replies
                .iter()
                .find(|reply| reply.correlation_id.as_deref() == Some(id))
                .unwrap_or_else(|| panic!("no reply for {id}"))
        };
        assert_eq!(
            by_correlation("stuck-set")
                .error
                .as_ref()
                .map(|error| error.category),
            Some(crate::protocol::ErrorCategory::Unavailable)
        );
        assert!(by_correlation("queued-set").error.is_some());
        assert!(
            control.is_active(),
            "an honest failure keeps the generation"
        );

        // The stuck operation eventually finishes; its late result must not
        // become a second reply.
        gate.release();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(written_replies(&sink).len(), 2);
        assert_eq!(outstanding.load(Ordering::Acquire), 0);
        control.deactivate();
        coordinator.join().unwrap();
    }

    #[test]
    fn an_idle_credential_coordinator_stops_as_soon_as_the_generation_ends() {
        let (control, _sink, _sender, _outstanding, coordinator) =
            coordinator_rig(CredentialProxy::in_memory_for_dispatcher_test());
        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        assert!(control.deactivate());
        coordinator.join().unwrap();
        // Far below the idle safety-net wait: the deactivation woke it.
        assert!(started.elapsed() < COORDINATOR_IDLE_WAIT / 2);
    }

    #[test]
    fn private_work_drop_erases_late_enqueue_after_final_empty_drain() {
        let outstanding = Arc::new(AtomicUsize::new(0));
        let (sender, receiver) = sync_channel(1);
        let (drained_sender, drained_receiver) = sync_channel(1);
        let (release_sender, release_receiver) = sync_channel(1);
        let consumer = thread::spawn(move || {
            assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
            drained_sender.send(()).unwrap();
            release_receiver.recv().unwrap();
            drop(receiver);
        });
        drained_receiver.recv().unwrap();
        let canary = format!("late-channel-canary-{}", std::process::id());
        let canary_len = canary.len();
        let before = crate::credentials::proxy::private_zeroised_bytes_for_test();
        let request: Envelope = serde_json::from_value(host(
            1,
            "late-channel-set",
            serde_json::json!({
                "method":"credential.set","providerId":"late-provider",
                "credential":{"type":"api_key","key":canary}
            }),
        ))
        .unwrap();
        sender
            .send(PrivateWork::new(
                request,
                reserve_private_work(&outstanding).unwrap(),
            ))
            .unwrap();
        release_sender.send(()).unwrap();
        consumer.join().unwrap();
        assert_eq!(outstanding.load(Ordering::Acquire), 0);
        assert!(
            crate::credentials::proxy::private_zeroised_bytes_for_test() >= before + canary_len
        );
    }

    #[test]
    fn malformed_input_and_private_output_failure_are_generation_fatal_and_not_retried() {
        let rig = Rig::new(CredentialProxy::in_memory_for_dispatcher_test());
        rig.raw
            .send(RawFrame::Line(Zeroizing::new(b"not-json\n".to_vec())))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while rig.control.is_active() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!rig.control.is_active());
        assert_eq!(
            rig.failure.lock().unwrap().as_deref(),
            Some("sidecar stdout protocol violation")
        );
        rig.shutdown();

        #[derive(Clone)]
        struct FailingSink(Arc<std::sync::atomic::AtomicUsize>);
        impl NonblockingSink for FailingSink {
            fn try_write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Err(Error::other("expected test write failure"))
            }
            fn wait_writable(&mut self, _timeout: Duration) -> std::io::Result<bool> {
                Ok(true)
            }
        }

        let failure = Arc::new(Mutex::new(None));
        let control = Arc::new(GenerationControl::new(i32::MAX, Arc::clone(&failure)));
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let writer = Arc::new(Mutex::new(GenerationWriter::with_sink_for_test(
            1,
            Box::new(FailingSink(Arc::clone(&attempts))),
            Arc::clone(&control),
        )));
        let (raw, raw_receiver) = sync_channel(RAW_QUEUE_CAPACITY);
        let public = Arc::new(PublicRouter::new(PUBLIC_QUEUE_CAPACITY));
        let workspace_waiters = Arc::new(WorkspaceWaiters::new());
        let handles = start_dispatcher(
            1,
            ProtocolDecoder::default(),
            raw_receiver,
            public,
            workspace_waiters,
            Arc::new(ProductWaiters::new()),
            CredentialProxy::in_memory_for_dispatcher_test(),
            Arc::new(ApprovalRegistry::default()),
            Arc::new(WorkspaceRegistry::default()),
            writer,
            Arc::clone(&control),
            Arc::new(Mutex::new(VecDeque::new())),
            0,
        );
        raw.send(RawFrame::Line(line(host(
            1,
            "list-write-failure",
            serde_json::json!({"method":"credential.list"}),
        ))))
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while control.is_active() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!control.is_active());
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        drop(raw);
        let _ = handles.dispatcher.join();
        let _ = handles.credential_coordinator.join();
        let _ = handles.approval_coordinator.join();
    }

    #[test]
    fn approval_request_is_private_and_exact_decision_writes_once() {
        let rig = Rig::new(CredentialProxy::in_memory_for_dispatcher_test());
        let root =
            std::env::temp_dir().join(format!("piui-approval-dispatch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let acquired = rig
            .workspace_registry
            .acquire_selected_directory(&root)
            .unwrap();
        rig.workspace_registry
            .inspect_metadata(&acquired.workspace_id)
            .unwrap();
        rig.workspace_registry
            .open_untrusted(&acquired.workspace_id, 0)
            .unwrap();
        let (trusted, _) = rig
            .workspace_registry
            .authorise(&acquired.workspace_id, 0)
            .unwrap();
        let request_id = "sidecar-1".to_string();
        rig.send(host(
            1,
            &request_id,
            serde_json::json!({
                "method":"approval.request", "schemaVersion":1, "generation":1,
                "sessionId":format!("session-{}", "1".repeat(32)),
                "workspaceId":trusted.workspace_id, "workspaceRevision":trusted.revision,
                "invocationId":format!("invocation-{}", "3".repeat(32)), "toolName":"write",
                "inputDigest":"a594cdfbde86ad0642102bbb9cbf64d0dfed9418951e891a3930373cd916b5cf",
                "input":{"path":"private/canary","content":"safe"}
            }),
        ))
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let view = loop {
            let pending = rig.approval_registry.pending().unwrap();
            if let Some(view) = pending.into_iter().next() {
                break view;
            }
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        };
        assert!(rig.public.try_recv().is_err());
        rig.approval_registry
            .submit(crate::domain::approval::ApprovalSubmission {
                approval_id: view.approval_id.clone(),
                decision_id: view.decision_id.clone(),
                scope_ids: vec![view.scopes[0].scope_id.clone()],
                choice: crate::domain::approval::ApprovalChoice::ApproveOnce,
            })
            .unwrap();
        let responses = rig.wait_for_lines(1);
        assert_eq!(responses.len(), 1);
        let response = &responses[0];
        assert_eq!(response.kind, ProtocolKind::HostResponse);
        assert_eq!(
            response.correlation_id.as_deref(),
            Some(request_id.as_str())
        );
        assert_eq!(
            response.decision_id.as_deref(),
            Some(view.decision_id.as_str())
        );
        assert_eq!(
            response.payload.get("decision"),
            Some(&Value::String("approved".into()))
        );
        let encoded = serde_json::to_string(response).unwrap();
        assert!(!encoded.contains("private/canary"));
        rig.shutdown();
        let _ = std::fs::remove_dir_all(root);
    }
}
