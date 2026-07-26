use super::process::{GenerationWriter, WorkspaceWaiters};
use super::router::{SequenceOutcome, SequenceRouter};
use super::stdio::{GenerationControl, RawFrame, fail_generation};
use crate::credentials::CredentialProxy;
use crate::credentials::proxy::discard_private_envelope;
use crate::domain::approval::{ApprovalRegistry, ApprovalRequest};
use crate::protocol::{
    AUTHENTICATED_INTERNAL_SNAPSHOT_CORRELATION, Envelope, ProtocolDecoder, ProtocolKind,
};
use serde_json::Value;
use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub(super) const RAW_QUEUE_CAPACITY: usize = 32;
pub(super) const PUBLIC_QUEUE_CAPACITY: usize = 256;
const PRIVATE_QUEUE_CAPACITY: usize = 128;

type PublicMessage = Result<Envelope, String>;

struct WorkPermit(Arc<AtomicUsize>);

impl Drop for WorkPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct PrivateWork {
    request: Option<Envelope>,
    permit: Option<WorkPermit>,
}

impl PrivateWork {
    fn new(request: Envelope, permit: WorkPermit) -> Self {
        Self {
            request: Some(request),
            permit: Some(permit),
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
    public_sender: SyncSender<PublicMessage>,
    workspace_waiters: Arc<WorkspaceWaiters>,
    proxy: CredentialProxy,
    approval_registry: Arc<ApprovalRegistry>,
    writer: Arc<Mutex<GenerationWriter>>,
    control: Arc<GenerationControl>,
    diagnostics: Arc<Mutex<VecDeque<String>>>,
    handshake_sequence: u64,
) -> DispatcherHandles {
    let (private_sender, private_receiver) = sync_channel(PRIVATE_QUEUE_CAPACITY);
    let outstanding = Arc::new(AtomicUsize::new(0));
    let coordinator_writer = Arc::clone(&writer);
    let coordinator_control = Arc::clone(&control);
    let credential_coordinator = thread::spawn(move || {
        credential_coordinator_loop(
            generation,
            private_receiver,
            proxy,
            coordinator_writer,
            coordinator_control,
        );
    });

    let approval_writer = Arc::clone(&writer);
    let approval_control = Arc::clone(&control);
    let approval_registry_for_coordinator = Arc::clone(&approval_registry);
    let approval_coordinator = thread::spawn(move || {
        approval_coordinator_loop(
            generation,
            approval_registry_for_coordinator,
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
            public_sender,
            workspace_waiters,
            approval_registry,
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
    public_sender: SyncSender<PublicMessage>,
    workspace_waiters: Arc<WorkspaceWaiters>,
    approval_registry: Arc<ApprovalRegistry>,
    private_sender: SyncSender<PrivateWork>,
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
                fatal(
                    "sidecar raw response channel closed",
                    &control,
                    &public_sender,
                );
                return;
            }
        };
        let line = match frame {
            RawFrame::Line(line) => line,
            RawFrame::Failure(message) => {
                let _ = public_sender.try_send(Err(message));
                return;
            }
        };
        let envelope = match decoder.decode(&line) {
            Ok(envelope) => envelope,
            Err(_) => {
                fatal(
                    "sidecar stdout protocol violation",
                    &control,
                    &public_sender,
                );
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
            fatal(
                "sidecar identifier namespace invalid",
                &control,
                &public_sender,
            );
            return;
        }

        if envelope.kind == ProtocolKind::HostResponse {
            discard_private_envelope(envelope);
            fatal(
                "sidecar private response direction invalid",
                &control,
                &public_sender,
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
                fatal("sidecar snapshot invalid", &control, &public_sender);
                return;
            }
            snapshot_request = None;
            let mut authenticated = envelope;
            authenticated.correlation_id = Some(AUTHENTICATED_INTERNAL_SNAPSHOT_CORRELATION.into());
            if !send_public(authenticated, &public_sender) {
                fatal(
                    "sidecar public response queue overflow",
                    &control,
                    &public_sender,
                );
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
                        fatal("sidecar snapshot request failed", &control, &public_sender);
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
                fatal("sidecar private sequence invalid", &control, &public_sender);
                return;
            }
        }

        if envelope
            .correlation_id
            .as_deref()
            .is_some_and(|correlation| correlation.starts_with("rust-workspace-"))
        {
            if envelope.kind != ProtocolKind::Response {
                fatal(
                    "sidecar workspace response invalid",
                    &control,
                    &public_sender,
                );
                return;
            }
            if workspace_waiters.deliver(generation, envelope).is_err() {
                fatal(
                    "sidecar workspace response unavailable",
                    &control,
                    &public_sender,
                );
                return;
            }
            continue;
        }

        if private {
            let method = envelope.payload.get("method").and_then(Value::as_str);
            if method == Some("approval.request") {
                let request = parse_approval_request(generation, &envelope);
                let private_envelope = envelope;
                match request.and_then(|request| approval_registry.register(request).map(|_| ())) {
                    Ok(()) => discard_private_envelope(private_envelope),
                    Err(_) => {
                        discard_private_envelope(private_envelope);
                        fatal("sidecar approval request invalid", &control, &public_sender);
                        return;
                    }
                }
                continue;
            }
            if !method.is_some_and(|method| method.starts_with("credential.")) {
                discard_private_envelope(envelope);
                fatal("sidecar private method invalid", &control, &public_sender);
                return;
            }
            let Some(permit) = reserve_private_work(&outstanding) else {
                discard_private_envelope(envelope);
                fatal(
                    "sidecar credential queue unavailable",
                    &control,
                    &public_sender,
                );
                return;
            };
            if !control.is_active() {
                discard_private_envelope(envelope);
                drop(permit);
                return;
            }
            match private_sender.try_send(PrivateWork::new(envelope, permit)) {
                Ok(()) => {}
                Err(TrySendError::Full(work)) | Err(TrySendError::Disconnected(work)) => {
                    drop(work);
                    fatal(
                        "sidecar credential queue unavailable",
                        &control,
                        &public_sender,
                    );
                    return;
                }
            }
            continue;
        }

        if envelope.kind == ProtocolKind::Event
            && envelope.payload.get("eventType") == Some(&Value::String("unknown-event".into()))
        {
            if let Ok(mut diagnostics) = diagnostics.lock() {
                if diagnostics.len() == 64 {
                    diagnostics.pop_front();
                }
                diagnostics.push_back(
                    "Unknown sidecar event was redacted and withheld from the interface.".into(),
                );
            }
            continue;
        }

        if !send_public(envelope, &public_sender) {
            fatal(
                "sidecar public response queue overflow",
                &control,
                &public_sender,
            );
            return;
        }
    }
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
        tool_name: payload
            .get("toolName")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        group_id: payload
            .get("groupId")
            .and_then(Value::as_str)
            .map(str::to_string),
        input: payload
            .get("input")
            .cloned()
            .ok_or_else(|| "approval request rejected".to_string())?,
    })
}

fn approval_coordinator_loop(
    generation: u64,
    registry: Arc<ApprovalRegistry>,
    writer: Arc<Mutex<GenerationWriter>>,
    control: Arc<GenerationControl>,
) {
    while control.is_active() {
        match registry.take_response_job(generation) {
            Ok(Some(job)) => {
                let result = writer
                    .lock()
                    .map_err(|_| "sidecar writer unavailable".to_string())
                    .and_then(|mut writer| writer.write_approval_response(generation, job));
                if result.is_err() {
                    control.invalidate("sidecar approval response failed");
                    return;
                }
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                control.invalidate("approval state unavailable");
                return;
            }
        }
    }
    registry.invalidate_generation(generation);
}

fn credential_coordinator_loop(
    generation: u64,
    private_receiver: Receiver<PrivateWork>,
    proxy: CredentialProxy,
    writer: Arc<Mutex<GenerationWriter>>,
    control: Arc<GenerationControl>,
) {
    let (completion_sender, completion_receiver) = sync_channel::<CompletedWork>(1);
    let mut buffered = VecDeque::with_capacity(PRIVATE_QUEUE_CAPACITY);
    let mut operation_running = false;

    loop {
        if !control.is_active() {
            cancel_buffered_work(&proxy, &mut buffered);
            while let Ok(work) = private_receiver.try_recv() {
                cancel_private_work(&proxy, work);
            }
            return;
        }

        if operation_running {
            match completion_receiver.try_recv() {
                Ok(completed) => {
                    operation_running = false;
                    if !control.is_active() {
                        drop(completed);
                        continue;
                    }
                    let CompletedWork { pending, _permit } = completed;
                    let result = writer
                        .lock()
                        .map_err(|_| "sidecar writer unavailable".to_string())
                        .and_then(|mut writer| writer.write_private_response(generation, pending));
                    drop(_permit);
                    if result.is_err() && control.is_active() {
                        fail_generation("sidecar private response write failed", &control, None);
                        return;
                    }
                    continue;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    fail_generation("sidecar credential worker unavailable", &control, None);
                    return;
                }
            }
        }

        while buffered.len() < PRIVATE_QUEUE_CAPACITY {
            match private_receiver.try_recv() {
                Ok(work) => buffered.push_back(work),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) if buffered.is_empty() && !operation_running => {
                    return;
                }
                Err(TryRecvError::Disconnected) => break,
            }
        }

        if !operation_running && let Some(work) = buffered.pop_front() {
            let operation_proxy = proxy.clone();
            let operation_sender = completion_sender.clone();
            let mut candidate = Some(work);
            let promoted = control.authorised_attempt(|| {
                let mut work = candidate.take().expect("promotion candidate owned");
                operation_running = true;
                thread::spawn(move || {
                    let (request, permit) = work.take();
                    let pending = operation_proxy.try_execute_request(request);
                    let _ = operation_sender.send(CompletedWork {
                        pending,
                        _permit: permit,
                    });
                });
            });
            if promoted.is_err()
                && let Some(work) = candidate.take()
            {
                cancel_private_work(&proxy, work);
            }
            continue;
        }

        match private_receiver.recv_timeout(Duration::from_millis(10)) {
            Ok(work) => buffered.push_back(work),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
                if buffered.is_empty() && !operation_running =>
            {
                return;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
        }
    }
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

fn send_public(envelope: Envelope, sender: &SyncSender<PublicMessage>) -> bool {
    debug_assert!(!matches!(
        envelope.kind,
        ProtocolKind::HostRequest | ProtocolKind::HostResponse
    ));
    match sender.try_send(Ok(envelope)) {
        Ok(()) => true,
        Err(TrySendError::Full(message)) | Err(TrySendError::Disconnected(message)) => {
            drop(message);
            false
        }
    }
}

fn fatal(
    message: &str,
    control: &Arc<GenerationControl>,
    public_sender: &SyncSender<PublicMessage>,
) {
    fail_generation(message, control, None);
    let _ = public_sender.try_send(Err(message.to_string()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::validate_envelope;
    use crate::supervisor::process::NonblockingSink;
    use std::io::Error;
    use std::sync::mpsc::SyncSender;
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

    struct Rig {
        raw: SyncSender<RawFrame>,
        public: Receiver<PublicMessage>,
        workspace: Receiver<PublicMessage>,
        control: Arc<GenerationControl>,
        failure: crate::supervisor::stdio::FailureSignal,
        writer: Arc<Mutex<GenerationWriter>>,
        approval_registry: Arc<ApprovalRegistry>,
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
            let (public_sender, public) = sync_channel(PUBLIC_QUEUE_CAPACITY);
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
            let handles = start_dispatcher(
                1,
                decoder,
                raw_receiver,
                public_sender,
                workspace_waiters,
                proxy,
                Arc::clone(&approval_registry),
                Arc::clone(&writer),
                Arc::clone(&control),
                Arc::new(Mutex::new(VecDeque::new())),
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
            .send(PrivateWork::new(
                request,
                reserve_private_work(&outstanding).unwrap(),
            ))
            .unwrap();
        drop(sender);
        let coordinator_control = Arc::clone(&control);
        let coordinator = thread::spawn(move || {
            credential_coordinator_loop(1, receiver, proxy, writer, coordinator_control)
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
        let (public_sender, _public) = sync_channel(PUBLIC_QUEUE_CAPACITY);
        let workspace_waiters = Arc::new(WorkspaceWaiters::new());
        let handles = start_dispatcher(
            1,
            ProtocolDecoder::default(),
            raw_receiver,
            public_sender,
            workspace_waiters,
            CredentialProxy::in_memory_for_dispatcher_test(),
            Arc::new(ApprovalRegistry::default()),
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
        let request_id = "sidecar-1".to_string();
        rig.send(host(
            1,
            &request_id,
            serde_json::json!({
                "method":"approval.request", "schemaVersion":1, "generation":1,
                "sessionId":format!("session-{}", "1".repeat(32)),
                "workspaceId":format!("workspace-{}", "2".repeat(32)), "workspaceRevision":1,
                "invocationId":format!("invocation-{}", "3".repeat(32)), "toolName":"write",
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
    }
}
