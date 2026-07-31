use super::dispatcher::{
    DispatcherHandles, PUBLIC_QUEUE_CAPACITY, RAW_QUEUE_CAPACITY, start_dispatcher,
};
use super::handshake::{HandshakeExpectation, protocol_architecture, validate_handshake};
use super::redact::StderrRedactor;
use super::stdio::{
    AttemptAuthorisationError, FailureSignal, GenerationControl, RawFrame, stderr_reader,
    stdout_reader,
};
use crate::credentials::CredentialProxy;
use crate::credentials::proxy::{PendingHostResponse, discard_private_envelope};
use crate::domain::approval::ApprovalRegistry;
use crate::domain::workspace::WorkspaceRegistry;
use crate::protocol::{Envelope, ProtocolDecoder, ProtocolKind, validate_envelope};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{
    Arc, Mutex,
    mpsc::{self, Receiver, SyncSender, sync_channel},
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const MAX_JS_SAFE_SEQUENCE: u64 = 9_007_199_254_740_991;
const MAX_WORKSPACE_WAITERS: usize = 32;

#[cfg(feature = "a23-credential-test")]
const A23_RAW_CAPTURE_MAX_BYTES: usize = 262_144;
#[cfg(feature = "a23-credential-test")]
const A23_RAW_CAPTURE_MAX_FRAMES: usize = 32;

#[cfg(feature = "a23-credential-test")]
#[derive(Clone)]
struct A23RawCapture {
    output: Arc<Mutex<A23RawCaptureOutput>>,
}

#[cfg(feature = "a23-credential-test")]
struct A23RawCaptureOutput {
    file: std::fs::File,
    bytes: usize,
    frames: usize,
}

#[cfg(feature = "a23-credential-test")]
impl A23RawCapture {
    fn from_environment() -> Result<Self, String> {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let target = a23_private_target("PIUI_A23_CAPTURE_PATH")?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(target)
            .map_err(|_| "A.23 raw capture unavailable".to_string())?;
        let header = b"PIUI-A23-RAW-V1\n";
        file.write_all(header)
            .and_then(|()| file.sync_data())
            .map_err(|_| "A.23 raw capture unavailable".to_string())?;
        Ok(Self {
            output: Arc::new(Mutex::new(A23RawCaptureOutput {
                file,
                bytes: header.len(),
                frames: 0,
            })),
        })
    }

    fn record_sidecar_frame(&self, raw: &[u8]) -> Result<(), String> {
        self.record(b'S', raw)
    }

    fn record_host_response(&self, raw: &[u8]) -> Result<(), String> {
        self.record(b'H', raw)
    }

    fn record(&self, direction: u8, raw: &[u8]) -> Result<(), String> {
        use std::io::Write;

        if !matches!(direction, b'S' | b'H') || raw.is_empty() || !raw.ends_with(b"\n") {
            return Err("A.23 raw capture rejected".into());
        }
        let header = format!("{} {}\n", direction as char, raw.len());
        let mut output = self
            .output
            .lock()
            .map_err(|_| "A.23 raw capture unavailable".to_string())?;
        let next_frames = output
            .frames
            .checked_add(1)
            .filter(|frames| *frames <= A23_RAW_CAPTURE_MAX_FRAMES)
            .ok_or_else(|| "A.23 raw capture limit".to_string())?;
        let next_bytes = output
            .bytes
            .checked_add(header.len())
            .and_then(|bytes| bytes.checked_add(raw.len()))
            .filter(|bytes| *bytes <= A23_RAW_CAPTURE_MAX_BYTES)
            .ok_or_else(|| "A.23 raw capture limit".to_string())?;
        output
            .file
            .write_all(header.as_bytes())
            .and_then(|()| output.file.write_all(raw))
            .and_then(|()| output.file.sync_data())
            .map_err(|_| "A.23 raw capture unavailable".to_string())?;
        output.frames = next_frames;
        output.bytes = next_bytes;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SupervisorPaths {
    pub node: PathBuf,
    pub resource_root: PathBuf,
    pub entrypoint: PathBuf,
}

impl SupervisorPaths {
    #[cfg(debug_assertions)]
    pub fn development() -> Result<Self, String> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        Self::validated(
            root.join("binaries/piui-node-aarch64-apple-darwin"),
            root.join("resources/sidecar"),
        )
    }

    pub fn from_app(app: &tauri::AppHandle) -> Result<Self, String> {
        #[cfg(debug_assertions)]
        {
            let _ = app;
            return Self::development();
        }
        #[cfg(not(debug_assertions))]
        {
            use tauri::Manager;
            let executable = std::env::current_exe()
                .map_err(|_| "packaged executable path unavailable".to_string())?;
            let executable_dir = executable
                .parent()
                .ok_or_else(|| "packaged executable directory unavailable".to_string())?;
            let resource_dir = app
                .path()
                .resource_dir()
                .map_err(|_| "packaged resource directory unavailable".to_string())?;
            Self::from_bundle_layout(executable_dir, &resource_dir)
        }
    }

    pub fn from_bundle_layout(executable_dir: &Path, resource_dir: &Path) -> Result<Self, String> {
        let executable_boundary = fs::canonicalize(executable_dir)
            .map_err(|_| "packaged executable directory unavailable".to_string())?;
        let resource_boundary = fs::canonicalize(resource_dir)
            .map_err(|_| "packaged resource directory unavailable".to_string())?;
        let paths = Self::validated(
            executable_boundary.join("piui-node"),
            resource_boundary.join("resources/sidecar"),
        )?;
        if paths.node.parent() != Some(executable_boundary.as_path())
            || !paths.resource_root.starts_with(&resource_boundary)
        {
            return Err("packaged sidecar path escaped its bundle boundary".into());
        }
        Ok(paths)
    }

    pub fn validated(node: PathBuf, resource_root: PathBuf) -> Result<Self, String> {
        let node = fs::canonicalize(node)
            .map_err(|_| "bundled Node executable unavailable".to_string())?;
        let resource_root = fs::canonicalize(resource_root)
            .map_err(|_| "bundled sidecar resources unavailable".to_string())?;
        let entrypoint = fs::canonicalize(resource_root.join("dist/index.js"))
            .map_err(|_| "bundled sidecar entrypoint unavailable".to_string())?;
        if !node.is_file()
            || !entrypoint.starts_with(&resource_root)
            || !resource_root.join("manifest.json").is_file()
        {
            return Err("sidecar resource boundary invalid".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(&node)
                .map_err(|_| "bundled Node metadata unavailable".to_string())?
                .permissions()
                .mode()
                & 0o111
                == 0
            {
                return Err("bundled Node executable is not executable".into());
            }
        }
        Ok(Self {
            node,
            resource_root,
            entrypoint,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SidecarStatus {
    pub running: bool,
    pub failed: bool,
    pub failure: Option<String>,
    pub generation: Option<u64>,
    pub pid: Option<u32>,
    pub protocol_version: Option<u64>,
    pub node_version: Option<String>,
    pub pi_version: Option<String>,
}

pub(super) const APPROVAL_WRITE_MAX_DURATION: Duration = Duration::from_millis(250);
const WRITE_POLL_SLICE: Duration = Duration::from_millis(20);
const RESERVED_INTERNAL_ID_PREFIX: &str = "rust-";
const RESERVED_UI_ID_PREFIX: &str = "ui-";

fn valid_public_wire_id(id: &str) -> bool {
    id.starts_with("web-")
        && !id.starts_with(RESERVED_INTERNAL_ID_PREFIX)
        && !id.starts_with(RESERVED_UI_ID_PREFIX)
}

pub(super) trait NonblockingSink: Send {
    fn try_write(&mut self, bytes: &[u8]) -> io::Result<usize>;
    fn wait_writable(&mut self, timeout: Duration) -> io::Result<bool>;
}

struct ChildStdinSink {
    descriptor: std::os::fd::RawFd,
}

impl ChildStdinSink {
    fn new(stdin: &ChildStdin) -> Result<Self, String> {
        let descriptor = stdin.as_raw_fd();
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err("sidecar stdin configuration failed".into());
        }
        Ok(Self { descriptor })
    }
}

impl NonblockingSink for ChildStdinSink {
    fn try_write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = unsafe { libc::write(self.descriptor, bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(written as usize)
        }
    }

    fn wait_writable(&mut self, timeout: Duration) -> io::Result<bool> {
        let mut descriptor = libc::pollfd {
            fd: self.descriptor,
            events: libc::POLLOUT,
            revents: 0,
        };
        let milliseconds = timeout.as_millis().clamp(1, i32::MAX as u128) as i32;
        let result = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result > 0)
        }
    }
}

/// Sole per-generation stdin and outbound raw-sequence authority.
pub(super) struct GenerationWriter {
    generation: u64,
    sink: Box<dyn NonblockingSink>,
    outbound_sequence: u64,
    internal_request_counter: u64,
    control: Arc<GenerationControl>,
    #[cfg(feature = "a23-credential-test")]
    a23_capture: Option<A23RawCapture>,
}

impl GenerationWriter {
    fn new(
        generation: u64,
        stdin: ChildStdin,
        control: Arc<GenerationControl>,
        #[cfg(feature = "a23-credential-test")] a23_capture: A23RawCapture,
    ) -> Result<Self, String> {
        let sink = ChildStdinSink::new(&stdin)?;
        control.attach_stdin(stdin)?;
        Ok(Self {
            generation,
            sink: Box::new(sink),
            outbound_sequence: 0,
            internal_request_counter: 0,
            control,
            #[cfg(feature = "a23-credential-test")]
            a23_capture: Some(a23_capture),
        })
    }

    #[cfg(test)]
    pub(super) fn with_sink_for_test(
        generation: u64,
        sink: Box<dyn NonblockingSink>,
        control: Arc<GenerationControl>,
    ) -> Self {
        Self {
            generation,
            sink,
            outbound_sequence: 0,
            internal_request_counter: 0,
            control,
            #[cfg(feature = "a23-credential-test")]
            a23_capture: None,
        }
    }

    fn ensure_active(&self, expected_generation: u64) -> Result<(), String> {
        if self.generation != expected_generation || !self.control.is_active() {
            Err("stale sidecar generation".into())
        } else {
            Ok(())
        }
    }

    fn next_sequence(&mut self) -> Result<u64, String> {
        let next = self
            .outbound_sequence
            .checked_add(1)
            .filter(|value| *value <= MAX_JS_SAFE_SEQUENCE)
            .ok_or_else(|| "sidecar outbound sequence exhausted".to_string())?;
        self.outbound_sequence = next;
        Ok(next)
    }

    fn next_internal_coordinates(&mut self, label: &str) -> Result<(String, u64), String> {
        self.internal_request_counter = self
            .internal_request_counter
            .checked_add(1)
            .ok_or_else(|| "sidecar request identity exhausted".to_string())?;
        let sequence = self.next_sequence()?;
        Ok((
            format!(
                "rust-{label}-{}-{}",
                self.generation, self.internal_request_counter
            ),
            sequence,
        ))
    }

    pub(super) fn write_public(
        &mut self,
        expected_generation: u64,
        envelope: &Envelope,
    ) -> Result<(), String> {
        self.ensure_active(expected_generation)?;
        if validate_envelope(envelope).is_err()
            || !matches!(envelope.kind, ProtocolKind::Request | ProtocolKind::Cancel)
            || !valid_public_wire_id(&envelope.id)
            || envelope
                .correlation_id
                .as_deref()
                .is_some_and(|id| !valid_public_wire_id(id))
        {
            return Err("sidecar request is not permitted".into());
        }
        let mut outbound = envelope.clone();
        outbound.sequence = self.next_sequence()?;
        let mut bytes = Zeroizing::new(
            serde_json::to_vec(&outbound)
                .map_err(|_| "sidecar request encoding failed".to_string())?,
        );
        bytes.push(b'\n');
        self.write_bytes(bytes)
    }

    pub(super) fn write_snapshot_request(
        &mut self,
        expected_generation: u64,
        after_sequence: u64,
    ) -> Result<String, String> {
        let mut payload = Map::new();
        payload.insert("afterSequence".into(), Value::from(after_sequence));
        self.write_internal_request(expected_generation, "snapshot", payload)
    }

    fn write_internal_request(
        &mut self,
        expected_generation: u64,
        method: &str,
        payload: Map<String, Value>,
    ) -> Result<String, String> {
        self.write_internal_request_with_label(expected_generation, method, method, payload)
    }

    fn write_internal_request_with_label(
        &mut self,
        expected_generation: u64,
        label: &str,
        method: &str,
        mut payload: Map<String, Value>,
    ) -> Result<String, String> {
        self.ensure_active(expected_generation)?;
        let (id, sequence) = self.next_internal_coordinates(label)?;
        payload.insert("method".into(), Value::String(method.into()));
        let envelope = Envelope {
            version: 1,
            kind: ProtocolKind::Request,
            id: id.clone(),
            correlation_id: None,
            decision_id: None,
            sequence,
            payload,
            error: None,
        };
        validate_envelope(&envelope).map_err(|_| "internal sidecar request invalid".to_string())?;
        let mut bytes = Zeroizing::new(
            serde_json::to_vec(&envelope)
                .map_err(|_| "internal sidecar request invalid".to_string())?,
        );
        bytes.push(b'\n');
        self.write_bytes(bytes)?;
        Ok(id)
    }

    pub(super) fn write_workspace_request<F>(
        &mut self,
        expected_generation: u64,
        method: &str,
        payload: Map<String, Value>,
        register: F,
    ) -> Result<String, String>
    where
        F: FnOnce(&str) -> Result<(), String>,
    {
        crate::protocol::workspace::validate_workspace_request(method, &payload)?;
        if !matches!(
            method,
            "workspace.openUntrusted"
                | "workspace.authorise"
                | "workspace.loadTrusted"
                | "workspace.revoke"
                | "workspace.sync"
        ) {
            return Err("workspace request is not permitted".into());
        }
        self.ensure_active(expected_generation)?;
        let (id, sequence) = self.next_internal_coordinates("workspace")?;
        let mut payload = payload;
        payload.insert("method".into(), Value::String(method.into()));
        let envelope = Envelope {
            version: 1,
            kind: ProtocolKind::Request,
            id: id.clone(),
            correlation_id: None,
            decision_id: None,
            sequence,
            payload,
            error: None,
        };
        validate_envelope(&envelope).map_err(|_| "internal sidecar request invalid".to_string())?;
        register(&id)?;
        let mut bytes = Zeroizing::new(
            serde_json::to_vec(&envelope)
                .map_err(|_| "internal sidecar request invalid".to_string())?,
        );
        bytes.push(b'\n');
        self.write_bytes(bytes)?;
        Ok(id)
    }

    pub(super) fn write_approval_response(
        &mut self,
        expected_generation: u64,
        job: crate::domain::approval::ApprovalResponseJob,
        absolute_deadline: Instant,
    ) -> Result<(), String> {
        self.ensure_before_deadline(absolute_deadline)?;
        self.ensure_active(expected_generation)?;
        let (id, sequence) = self.next_internal_coordinates("approval-response")?;
        self.ensure_before_deadline(absolute_deadline)?;
        let mut payload = Map::new();
        if let (Some(tool_call_id), Some(cohort_digest)) = (&job.tool_call_id, &job.cohort_digest) {
            payload.insert("schemaVersion".into(), Value::from(2));
            payload.insert("method".into(), Value::String("approval.resolve".into()));
            payload.insert(
                "transactionId".into(),
                Value::String(job.transaction_id.clone()),
            );
            payload.insert("toolCallId".into(), Value::String(tool_call_id.clone()));
            payload.insert("cohortDigest".into(), Value::String(cohort_digest.clone()));
        } else {
            payload.insert("schemaVersion".into(), Value::from(1));
        }
        payload.insert("approvalId".into(), Value::String(job.approval_id.clone()));
        payload.insert(
            "invocationId".into(),
            Value::String(job.invocation_id.clone()),
        );
        payload.insert(
            "inputDigest".into(),
            Value::String(job.input_digest.clone()),
        );
        payload.insert("decision".into(), Value::String(job.decision.into()));
        payload.insert(
            "scopeIds".into(),
            Value::Array(job.scope_ids.iter().cloned().map(Value::String).collect()),
        );
        self.ensure_before_deadline(absolute_deadline)?;
        crate::protocol::approval::validate_approval_response(&job.decision_id, &payload)?;
        self.ensure_before_deadline(absolute_deadline)?;
        let response = Envelope {
            version: 1,
            kind: ProtocolKind::HostResponse,
            id,
            correlation_id: Some(job.correlation_id.clone()),
            decision_id: Some(job.decision_id.clone()),
            sequence,
            payload,
            error: None,
        };
        validate_envelope(&response)
            .map_err(|_| "approval response encoding failed".to_string())?;
        self.ensure_before_deadline(absolute_deadline)?;
        let encoded = serde_json::to_vec(&response)
            .map_err(|_| "approval response encoding failed".to_string());
        discard_private_envelope(response);
        let bytes = Zeroizing::new(encoded?);
        self.ensure_before_deadline(absolute_deadline)?;
        self.write_approval_frame(bytes, absolute_deadline)
    }

    pub(super) fn write_approval_ready_ack(
        &mut self,
        expected_generation: u64,
        ack: crate::domain::approval::ApprovalReadyAck,
    ) -> Result<(), String> {
        let payload = Map::from_iter([
            ("schemaVersion".into(), Value::from(2)),
            ("method".into(), Value::String("approval.ready-ack".into())),
            ("invocationId".into(), Value::String(ack.invocation_id)),
            ("accepted".into(), Value::Bool(true)),
        ]);
        self.write_approval_control_response(expected_generation, ack.correlation_id, payload)
    }

    pub(super) fn write_approval_abandon_ack(
        &mut self,
        expected_generation: u64,
        ack: crate::domain::approval::ApprovalAbandonAck,
    ) -> Result<(), String> {
        let payload = Map::from_iter([
            ("schemaVersion".into(), Value::from(2)),
            (
                "method".into(),
                Value::String("approval.abandon-ack".into()),
            ),
            ("cohortDigest".into(), Value::String(ack.cohort_digest)),
            ("cancelled".into(), Value::Bool(true)),
        ]);
        self.write_approval_control_response(expected_generation, ack.correlation_id, payload)
    }

    fn write_approval_control_response(
        &mut self,
        expected_generation: u64,
        correlation_id: String,
        payload: Map<String, Value>,
    ) -> Result<(), String> {
        self.ensure_active(expected_generation)?;
        let (id, sequence) = self.next_internal_coordinates("approval-control")?;
        let response = Envelope {
            version: 1,
            kind: ProtocolKind::HostResponse,
            id,
            correlation_id: Some(correlation_id),
            decision_id: None,
            sequence,
            payload,
            error: None,
        };
        validate_envelope(&response)
            .map_err(|_| "approval response encoding failed".to_string())?;
        let encoded = serde_json::to_vec(&response)
            .map_err(|_| "approval response encoding failed".to_string());
        discard_private_envelope(response);
        let mut bytes = Zeroizing::new(encoded?);
        bytes.push(b'\n');
        self.write_bytes(bytes)
    }

    pub(super) fn write_group_approval_response(
        &mut self,
        expected_generation: u64,
        job: crate::domain::approval::GroupApprovalResponseJob,
        absolute_deadline: Instant,
    ) -> Result<(), String> {
        self.ensure_before_deadline(absolute_deadline)?;
        self.ensure_active(expected_generation)?;
        let (id, sequence) = self.next_internal_coordinates("approval-group")?;
        self.ensure_before_deadline(absolute_deadline)?;
        let correlation_id = job
            .members
            .first()
            .map(|member| member.correlation_id.clone())
            .ok_or_else(|| "approval group response encoding failed".to_string())?;
        let members = job
            .members
            .iter()
            .map(|member| {
                Value::Object(Map::from_iter([
                    (
                        "correlationId".into(),
                        Value::String(member.correlation_id.clone()),
                    ),
                    (
                        "approvalId".into(),
                        Value::String(member.approval_id.clone()),
                    ),
                    (
                        "decisionId".into(),
                        Value::String(member.decision_id.clone()),
                    ),
                    (
                        "invocationId".into(),
                        Value::String(member.invocation_id.clone()),
                    ),
                    (
                        "toolCallId".into(),
                        Value::String(member.tool_call_id.clone()),
                    ),
                    (
                        "inputDigest".into(),
                        Value::String(member.input_digest.clone()),
                    ),
                    ("scopeId".into(), Value::String(member.scope_id.clone())),
                ]))
            })
            .collect();
        self.ensure_before_deadline(absolute_deadline)?;
        let payload = Map::from_iter([
            ("schemaVersion".into(), Value::from(2)),
            (
                "method".into(),
                Value::String("approval.group-commit".into()),
            ),
            ("generation".into(), Value::from(job.generation)),
            ("sessionId".into(), Value::String(job.session_id.clone())),
            (
                "workspaceId".into(),
                Value::String(job.workspace_id.clone()),
            ),
            (
                "workspaceRevision".into(),
                Value::from(job.workspace_revision),
            ),
            (
                "assistantEntryId".into(),
                Value::String(job.assistant_entry_id.clone()),
            ),
            ("groupId".into(), Value::String(job.group_id.clone())),
            (
                "transactionId".into(),
                Value::String(job.transaction_id.clone()),
            ),
            (
                "cohortDigest".into(),
                Value::String(job.cohort_digest.clone()),
            ),
            ("decision".into(), Value::String("approved".into())),
            ("members".into(), Value::Array(members)),
        ]);
        self.ensure_before_deadline(absolute_deadline)?;
        crate::protocol::approval::validate_group_response(&job.decision_id, &payload)?;
        self.ensure_before_deadline(absolute_deadline)?;
        let response = Envelope {
            version: 1,
            kind: ProtocolKind::HostResponse,
            id,
            correlation_id: Some(correlation_id),
            decision_id: Some(job.decision_id.clone()),
            sequence,
            payload,
            error: None,
        };
        validate_envelope(&response)
            .map_err(|_| "approval group response encoding failed".to_string())?;
        self.ensure_before_deadline(absolute_deadline)?;
        let encoded = serde_json::to_vec(&response)
            .map_err(|_| "approval group response encoding failed".to_string());
        discard_private_envelope(response);
        let bytes = Zeroizing::new(encoded?);
        self.ensure_before_deadline(absolute_deadline)?;
        self.write_approval_frame(bytes, absolute_deadline)
    }

    pub(super) fn write_private_response(
        &mut self,
        expected_generation: u64,
        pending: PendingHostResponse,
    ) -> Result<(), String> {
        self.ensure_active(expected_generation)?;
        let (id, sequence) = self.next_internal_coordinates("host-response")?;
        let response = pending
            .bind(id, sequence)
            .map_err(|_| "sidecar private response encoding failed".to_string())?;
        let bytes = response
            .into_lf_json()
            .map_err(|_| "sidecar private response encoding failed".to_string())?;
        #[cfg(feature = "a23-credential-test")]
        let capture_bytes = Zeroizing::new(bytes.as_slice().to_vec());
        self.write_bytes(bytes)?;
        #[cfg(feature = "a23-credential-test")]
        match self.a23_capture.as_ref() {
            Some(capture) => capture.record_host_response(&capture_bytes)?,
            None => {
                // `with_sink_for_test` deliberately has no file-backed capture.
                // Every non-test A.23 writer is constructed with one and must
                // continue to fail closed if that invariant is ever broken.
                #[cfg(not(test))]
                return Err("A.23 raw capture unavailable".into());
            }
        }
        Ok(())
    }

    #[cfg(feature = "a23-credential-test")]
    pub(super) fn capture_a23_inbound_frame(&self, raw: &[u8]) -> Result<(), String> {
        match self.a23_capture.as_ref() {
            Some(capture) => capture.record_sidecar_frame(raw),
            None => {
                // This branch exists only for `with_sink_for_test`; release
                // A.23 processes must retain their file-backed evidence sink.
                #[cfg(test)]
                return Ok(());
                #[cfg(not(test))]
                return Err("A.23 raw capture unavailable".into());
            }
        }
    }

    fn write_bytes(&mut self, bytes: Zeroizing<Vec<u8>>) -> Result<(), String> {
        let deadline = Instant::now()
            .checked_add(APPROVAL_WRITE_MAX_DURATION)
            .ok_or_else(|| "sidecar write timed out".to_string())?;
        self.write_slice_until(&bytes, deadline)
    }

    fn ensure_before_deadline(&self, deadline: Instant) -> Result<(), String> {
        if Instant::now() >= deadline {
            self.control.invalidate("sidecar write timed out");
            Err("sidecar write timed out".into())
        } else {
            Ok(())
        }
    }

    fn write_approval_frame(
        &mut self,
        body: Zeroizing<Vec<u8>>,
        absolute_deadline: Instant,
    ) -> Result<(), String> {
        self.ensure_before_deadline(absolute_deadline)?;
        self.write_slice_until(&body, absolute_deadline)?;
        // The LF is the approval publication point. It is a separate write and
        // is never attempted after the one dispatcher-minted deadline.
        self.ensure_before_deadline(absolute_deadline)?;
        self.write_slice_until(b"\n", absolute_deadline)
    }

    fn write_slice_until(&mut self, bytes: &[u8], deadline: Instant) -> Result<(), String> {
        let mut offset = 0;
        while offset < bytes.len() {
            self.ensure_before_deadline(deadline)?;
            let attempt = self
                .control
                .authorised_attempt_before(deadline, || self.sink.try_write(&bytes[offset..]));
            let result = match attempt {
                Ok(result) => result,
                Err(AttemptAuthorisationError::Inactive) => {
                    return Err("stale sidecar generation".into());
                }
                Err(AttemptAuthorisationError::DeadlineElapsed) => {
                    self.control.invalidate("sidecar write timed out");
                    return Err("sidecar write timed out".into());
                }
            };
            match result {
                Ok(0) => {
                    self.control.invalidate("sidecar write failed");
                    return Err("sidecar write failed".into());
                }
                Ok(written) => offset += written,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        continue;
                    }
                    match self.sink.wait_writable(remaining.min(WRITE_POLL_SLICE)) {
                        Ok(_) => {}
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => {
                            self.control.invalidate("sidecar write failed");
                            return Err("sidecar write failed".into());
                        }
                    }
                }
                Err(_) => {
                    self.control.invalidate("sidecar write failed");
                    return Err("sidecar write failed".into());
                }
            }
        }
        Ok(())
    }
}

pub(super) struct WorkspaceWaiters {
    pending: Mutex<HashMap<String, (u64, SyncSender<Result<Envelope, String>>)>>,
}

impl WorkspaceWaiters {
    pub(super) fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::with_capacity(MAX_WORKSPACE_WAITERS)),
        }
    }

    pub(super) fn register(
        &self,
        id: &str,
        generation: u64,
        sender: SyncSender<Result<Envelope, String>>,
    ) -> Result<(), String> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| "workspace waiter unavailable".to_string())?;
        if pending.len() >= MAX_WORKSPACE_WAITERS || pending.contains_key(id) {
            return Err("workspace waiter unavailable".into());
        }
        pending.insert(id.to_string(), (generation, sender));
        Ok(())
    }

    pub(super) fn deliver(&self, generation: u64, envelope: Envelope) -> Result<bool, String> {
        let Some(correlation) = envelope.correlation_id.as_deref() else {
            return Ok(false);
        };
        if !correlation.starts_with("rust-workspace-") {
            return Ok(false);
        }
        let waiter = self
            .pending
            .lock()
            .map_err(|_| "workspace waiter unavailable".to_string())?
            .remove(correlation);
        let Some((expected_generation, sender)) = waiter else {
            return Err("workspace response correlation unavailable".into());
        };
        if expected_generation != generation {
            return Err("stale workspace response".into());
        }
        sender
            .try_send(Ok(envelope))
            .map_err(|_| "workspace waiter unavailable".to_string())?;
        Ok(true)
    }

    fn cancel(&self, id: &str) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(id);
        }
    }
}

pub(crate) struct WorkspaceWaiter {
    id: String,
    generation: u64,
    receiver: Receiver<Result<Envelope, String>>,
    waiters: Arc<WorkspaceWaiters>,
    control: Arc<GenerationControl>,
}

impl WorkspaceWaiter {
    pub(crate) fn wait(mut self, timeout: Duration) -> Result<Envelope, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if !self.control.is_active() {
                return Err("workspace execution uncertain".into());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.control.invalidate("workspace response uncertain");
                return Err("workspace execution uncertain".into());
            }
            match self
                .receiver
                .recv_timeout(remaining.min(Duration::from_millis(10)))
            {
                Ok(Ok(response)) => {
                    if response.kind != ProtocolKind::Response
                        || response.correlation_id.as_deref() != Some(self.id.as_str())
                    {
                        self.control.invalidate("workspace response invalid");
                        return Err("workspace execution uncertain".into());
                    }
                    self.waiters.cancel(&self.id);
                    self.id.clear();
                    return Ok(response);
                }
                Ok(Err(error)) => return Err(error),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("workspace execution uncertain".into());
                }
            }
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}

impl Drop for WorkspaceWaiter {
    fn drop(&mut self) {
        if !self.id.is_empty() {
            self.waiters.cancel(&self.id);
        }
    }
}

struct RunningSidecar {
    generation: u64,
    child: Child,
    writer: Arc<Mutex<GenerationWriter>>,
    messages: Receiver<Result<Envelope, String>>,
    workspace_waiters: Arc<WorkspaceWaiters>,
    stdout: Option<JoinHandle<()>>,
    stderr: Option<JoinHandle<()>>,
    dispatcher: Option<JoinHandle<()>>,
    credential_coordinator: Option<JoinHandle<()>>,
    approval_coordinator: Option<JoinHandle<()>>,
    control: Arc<GenerationControl>,
    diagnostics: Arc<Mutex<VecDeque<String>>>,
    failure: FailureSignal,
    handshake: Envelope,
}

pub struct SidecarSupervisor {
    running: Option<RunningSidecar>,
    last_failure: Option<String>,
    generation: u64,
    credential_proxy: CredentialProxy,
    approval_registry: Arc<ApprovalRegistry>,
    workspace_registry: Arc<WorkspaceRegistry>,
}

impl Default for SidecarSupervisor {
    fn default() -> Self {
        Self {
            running: None,
            last_failure: None,
            generation: 0,
            credential_proxy: CredentialProxy::default(),
            approval_registry: Arc::new(ApprovalRegistry::default()),
            workspace_registry: Arc::new(WorkspaceRegistry::default()),
        }
    }
}

impl SidecarSupervisor {
    #[cfg(test)]
    pub(crate) fn with_registries(
        approval_registry: Arc<ApprovalRegistry>,
        workspace_registry: Arc<WorkspaceRegistry>,
    ) -> Self {
        Self::with_registries_and_credentials(
            approval_registry,
            workspace_registry,
            CredentialProxy::default(),
        )
    }

    pub(crate) fn with_registries_and_credentials(
        approval_registry: Arc<ApprovalRegistry>,
        workspace_registry: Arc<WorkspaceRegistry>,
        credential_proxy: CredentialProxy,
    ) -> Self {
        Self {
            running: None,
            last_failure: None,
            generation: 0,
            credential_proxy,
            approval_registry,
            workspace_registry,
        }
    }

    pub fn start(&mut self, paths: &SupervisorPaths) -> Result<SidecarStatus, String> {
        if self.status().running {
            return Err("sidecar is already running".into());
        }
        self.running = None;
        self.last_failure = None;
        let nonce = format!("piui-{:016x}-{:08x}", std::process::id(), nonce_counter());
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| "sidecar generation exhausted".to_string())?;
        let mut command = Command::new(&paths.node);
        command
            .arg(&paths.entrypoint)
            .current_dir(&paths.resource_root)
            .env_clear()
            // Keep dependency-level home discovery inside the sealed sidecar
            // resources. Project loaders receive their own agent-root HOME.
            .env("HOME", &paths.resource_root)
            .env("CFFIXED_USER_HOME", &paths.resource_root)
            .env("NODE_ENV", "production")
            .env("PIUI_DESKTOP_VERSION", env!("CARGO_PKG_VERSION"))
            .env("PIUI_HANDSHAKE_NONCE", &nonce)
            .env("PIUI_OWN_PROCESS_GROUP", "1")
            .env("PIUI_SUPERVISOR_GENERATION", next_generation.to_string())
            .env("PI_OFFLINE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        configure_architecture_test_sidecar(&mut command)?;
        let mut child = command
            .spawn()
            .map_err(|_| "sidecar spawn failed".to_string())?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "sidecar stdin unavailable".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "sidecar stdout unavailable".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "sidecar stderr unavailable".to_string())?;
        let (raw_sender, raw_receiver) = mpsc::sync_channel(RAW_QUEUE_CAPACITY);
        let diagnostics = Arc::new(Mutex::new(VecDeque::with_capacity(64)));
        let failure: FailureSignal = Arc::new(Mutex::new(None));
        let process_group = child.id() as i32;
        let control = Arc::new(GenerationControl::new(process_group, Arc::clone(&failure)));
        let stdout_handle = stdout_reader(stdout, raw_sender, Arc::clone(&control));
        let stderr_handle = stderr_reader(
            stderr,
            Arc::clone(&diagnostics),
            StderrRedactor::for_current_user(),
        );
        let mut decoder = ProtocolDecoder::default();
        let handshake = match raw_receiver.recv_timeout(Duration::from_secs(10)) {
            Ok(RawFrame::Line(line)) => decoder
                .decode(&line)
                .map_err(|_| "sidecar stdout protocol violation".to_string()),
            Ok(RawFrame::Failure(error)) => Err(error),
            Err(_) => Err("sidecar handshake timed out".to_string()),
        };
        let handshake = match handshake.and_then(accept_first_protocol_envelope) {
            Ok(envelope) => envelope,
            Err(error) => {
                return self.abort_start(child, process_group, control, error);
            }
        };
        if let Err(error) = validate_handshake(
            &handshake,
            &HandshakeExpectation {
                nonce: &nonce,
                desktop_version: env!("CARGO_PKG_VERSION"),
                architecture: protocol_architecture(),
            },
        ) {
            return self.abort_start(child, process_group, control, error);
        }

        self.generation = next_generation;
        let generation = next_generation;
        #[cfg(feature = "a23-credential-test")]
        let a23_capture = match A23RawCapture::from_environment() {
            Ok(capture) => capture,
            Err(error) => return self.abort_start(child, process_group, control, error),
        };
        #[cfg(not(feature = "a23-credential-test"))]
        let writer_result = GenerationWriter::new(generation, stdin, Arc::clone(&control));
        #[cfg(feature = "a23-credential-test")]
        let writer_result =
            GenerationWriter::new(generation, stdin, Arc::clone(&control), a23_capture);
        let writer = match writer_result {
            Ok(writer) => Arc::new(Mutex::new(writer)),
            Err(error) => {
                return self.abort_start(child, process_group, control, error);
            }
        };
        let (public_sender, public_receiver) = mpsc::sync_channel(PUBLIC_QUEUE_CAPACITY);
        let workspace_waiters = Arc::new(WorkspaceWaiters::new());
        let DispatcherHandles {
            dispatcher,
            credential_coordinator,
            approval_coordinator,
        } = start_dispatcher(
            generation,
            decoder,
            raw_receiver,
            public_sender,
            Arc::clone(&workspace_waiters),
            self.credential_proxy.clone(),
            Arc::clone(&self.approval_registry),
            Arc::clone(&self.workspace_registry),
            Arc::clone(&writer),
            Arc::clone(&control),
            Arc::clone(&diagnostics),
            handshake.sequence,
        );
        self.running = Some(RunningSidecar {
            generation,
            child,
            writer,
            messages: public_receiver,
            workspace_waiters,
            stdout: Some(stdout_handle),
            stderr: Some(stderr_handle),
            dispatcher: Some(dispatcher),
            credential_coordinator: Some(credential_coordinator),
            approval_coordinator: Some(approval_coordinator),
            control,
            diagnostics,
            failure,
            handshake,
        });
        let status = self.status();
        if status.failed {
            Err(status
                .failure
                .unwrap_or_else(|| "sidecar failed during start".into()))
        } else {
            Ok(status)
        }
    }

    fn abort_start(
        &mut self,
        mut child: Child,
        process_group: i32,
        control: Arc<GenerationControl>,
        error: String,
    ) -> Result<SidecarStatus, String> {
        control.deactivate();
        self.last_failure = Some(error.clone());
        let _ = terminate_group(&mut child, process_group);
        Err(error)
    }

    pub fn status(&mut self) -> SidecarStatus {
        let observed_failure = self.running.as_ref().and_then(|running| {
            running
                .failure
                .lock()
                .ok()
                .and_then(|failure| failure.clone())
        });
        if let Some(failure) = observed_failure {
            if let Some(mut running) = self.running.take() {
                running.control.deactivate();
                let process_group = running.child.id() as i32;
                let _ = terminate_group(&mut running.child, process_group);
                join_transport_threads(&mut running);
            }
            self.last_failure = Some(failure);
            return stopped_status(self.last_failure.clone());
        }
        let Some(running) = self.running.as_mut() else {
            return stopped_status(self.last_failure.clone());
        };
        if let Some(exit) = running.child.try_wait().ok().flatten() {
            let mut running = self.running.take().expect("running sidecar exists");
            running.control.deactivate();
            let process_group = running.child.id() as i32;
            let _ = terminate_group(&mut running.child, process_group);
            join_transport_threads(&mut running);
            self.last_failure = Some(match exit.code() {
                Some(code) => format!("sidecar exited unexpectedly (code {code})"),
                None => "sidecar exited unexpectedly (signal)".into(),
            });
            return stopped_status(self.last_failure.clone());
        }
        SidecarStatus {
            running: true,
            failed: false,
            failure: None,
            generation: Some(running.generation),
            pid: Some(running.child.id()),
            protocol_version: running
                .handshake
                .payload
                .get("protocolVersion")
                .and_then(Value::as_u64),
            node_version: running
                .handshake
                .payload
                .get("nodeVersion")
                .and_then(Value::as_str)
                .map(str::to_owned),
            pi_version: running
                .handshake
                .payload
                .get("piVersion")
                .and_then(Value::as_str)
                .map(str::to_owned),
        }
    }

    pub fn current_generation(&self) -> Option<u64> {
        self.running.as_ref().map(|running| running.generation)
    }

    pub fn send_for_generation(
        &mut self,
        generation: u64,
        envelope: &Envelope,
    ) -> Result<(), String> {
        if self.current_generation() != Some(generation) {
            return Err("stale sidecar generation".into());
        }
        self.send_envelope(envelope)
    }

    pub fn receive_for_generation(
        &mut self,
        generation: u64,
        timeout: Duration,
    ) -> Result<Envelope, String> {
        if self.current_generation() != Some(generation) {
            return Err("stale sidecar generation".into());
        }
        let envelope = self.receive_envelope(timeout)?;
        if self.current_generation() != Some(generation) {
            return Err("stale sidecar generation".into());
        }
        Ok(envelope)
    }

    pub fn request_status(&mut self) -> Result<Envelope, String> {
        let status = self.status();
        if !status.running {
            return Err(status
                .failure
                .unwrap_or_else(|| "sidecar is not running".into()));
        }
        let generation = status
            .generation
            .ok_or_else(|| "sidecar generation unavailable".to_string())?;
        let request_id = {
            let running = self.running.as_ref().expect("running status has sidecar");
            running
                .writer
                .lock()
                .map_err(|_| "sidecar writer unavailable".to_string())?
                .write_internal_request(generation, "status", Map::new())?
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let envelope =
                self.receive_envelope(deadline.saturating_duration_since(Instant::now()))?;
            if envelope.kind == ProtocolKind::Response
                && envelope.correlation_id.as_deref() == Some(request_id.as_str())
            {
                return Ok(envelope);
            }
        }
    }

    pub(crate) fn begin_workspace_request(
        &mut self,
        generation: u64,
        method: &str,
        payload: Map<String, Value>,
    ) -> Result<WorkspaceWaiter, String> {
        if self.current_generation() != Some(generation) {
            return Err("stale sidecar generation".into());
        }
        let running = self
            .running
            .as_ref()
            .ok_or_else(|| "sidecar unavailable".to_string())?;
        let (sender, receiver) = sync_channel(1);
        let waiters = Arc::clone(&running.workspace_waiters);
        let control = Arc::clone(&running.control);
        let mut registered = None;
        let request_id = running
            .writer
            .lock()
            .map_err(|_| "sidecar writer unavailable".to_string())?
            .write_workspace_request(generation, method, payload, |id| {
                waiters.register(id, generation, sender)?;
                registered = Some(id.to_string());
                Ok(())
            });
        let request_id = match request_id {
            Ok(id) => id,
            Err(error) => {
                if let Some(id) = registered.as_deref() {
                    waiters.cancel(id);
                }
                return Err(error);
            }
        };
        Ok(WorkspaceWaiter {
            id: request_id,
            generation,
            receiver,
            waiters,
            control,
        })
    }

    pub fn send_envelope(&mut self, envelope: &Envelope) -> Result<(), String> {
        let status = self.status();
        if !status.running {
            return Err(status
                .failure
                .unwrap_or_else(|| "sidecar is not running".into()));
        }
        let generation = status
            .generation
            .ok_or_else(|| "sidecar generation unavailable".to_string())?;
        let running = self.running.as_ref().expect("running status has sidecar");
        let result = running
            .writer
            .lock()
            .map_err(|_| "sidecar writer unavailable".to_string())?
            .write_public(generation, envelope);
        result
    }

    pub fn receive_envelope(&mut self, timeout: Duration) -> Result<Envelope, String> {
        let status = self.status();
        if !status.running {
            return Err(status
                .failure
                .unwrap_or_else(|| "sidecar is not running".into()));
        }
        let running = self.running.as_ref().expect("running status has sidecar");
        match running.messages.recv_timeout(timeout) {
            Ok(Ok(envelope)) => Ok(envelope),
            Ok(Err(error)) => Err(error),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                Err("sidecar receive timed out".into())
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err("sidecar response channel closed".into())
            }
        }
    }

    pub fn stop(&mut self) -> Result<(), String> {
        let Some(mut running) = self.running.take() else {
            return Ok(());
        };
        if let Ok(failure) = running.failure.lock()
            && failure.is_some()
        {
            self.last_failure = failure.clone();
        }
        running.control.deactivate();
        let process_group = running.child.id() as i32;
        let graceful_deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < graceful_deadline {
            if running
                .child
                .try_wait()
                .map_err(|_| "sidecar wait failed".to_string())?
                .is_some()
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let result = terminate_group(&mut running.child, process_group);
        join_transport_threads(&mut running);
        // The coordinator is always drainable and joins within a bounded
        // interval. Only its separate, already-running repository operation
        // may remain detached if synchronous storage never returns.
        if let Some(handle) = running.credential_coordinator.take() {
            let _ = handle.join();
        }
        if let Some(handle) = running.approval_coordinator.take() {
            let _ = handle.join();
        }
        result
    }

    pub fn diagnostics(&self) -> Vec<String> {
        self.running
            .as_ref()
            .map(|running| {
                running
                    .diagnostics
                    .lock()
                    .expect("diagnostic ring poisoned")
                    .iter()
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(not(any(feature = "a23-credential-test", feature = "a25-approval-test")))]
fn configure_architecture_test_sidecar(_command: &mut Command) -> Result<(), String> {
    Ok(())
}

#[cfg(feature = "a23-credential-test")]
fn a23_private_target(variable: &str) -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt;

    let target = PathBuf::from(
        std::env::var_os(variable)
            .ok_or_else(|| "A.23 private capture target unavailable".to_string())?,
    );
    if !target.is_absolute() || target.exists() {
        return Err("A.23 private capture target invalid".into());
    }
    let parent = target
        .parent()
        .ok_or_else(|| "A.23 private capture target invalid".to_string())?;
    let parent = fs::canonicalize(parent)
        .map_err(|_| "A.23 private capture boundary unavailable".to_string())?;
    if target.parent() != Some(parent.as_path()) {
        return Err("A.23 private capture target invalid".into());
    }
    let metadata = fs::metadata(&parent)
        .map_err(|_| "A.23 private capture boundary unavailable".to_string())?;
    if !metadata.is_dir()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err("A.23 private capture boundary invalid".into());
    }
    Ok(target)
}

#[cfg(all(feature = "a23-credential-test", not(feature = "a25-approval-test")))]
fn configure_architecture_test_sidecar(command: &mut Command) -> Result<(), String> {
    let capture = a23_private_target("PIUI_A23_CAPTURE_PATH")?;
    let result = a23_private_target("PIUI_A23_RESULT_PATH")?;
    let trigger = a23_private_target("PIUI_A23_TRIGGER_PATH")?;
    if capture == result || capture == trigger || result == trigger {
        return Err("A.23 private targets overlap".into());
    }
    command
        .env("PIUI_A23_TEST_MODE", "1")
        .env("PIUI_A23_PROVIDER_ID", "a23.fixture-provider")
        .env("PIUI_A23_RESULT_PATH", result)
        .env("PIUI_A23_TRIGGER_PATH", trigger);
    Ok(())
}

#[cfg(all(feature = "a25-approval-test", not(feature = "a23-credential-test")))]
fn configure_architecture_test_sidecar(command: &mut Command) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let control_root = PathBuf::from(
        std::env::var_os("PIUI_A25_CONTROL_ROOT")
            .ok_or_else(|| "A.25 control root unavailable".to_string())?,
    );
    let workspace_id = std::env::var("PIUI_A25_WORKSPACE_ID")
        .map_err(|_| "A.25 workspace unavailable".to_string())?;
    let workspace_revision = std::env::var("PIUI_A25_WORKSPACE_REVISION")
        .map_err(|_| "A.25 workspace unavailable".to_string())?;
    let canonical =
        fs::canonicalize(&control_root).map_err(|_| "A.25 control root unavailable".to_string())?;
    let metadata =
        fs::metadata(&canonical).map_err(|_| "A.25 control root unavailable".to_string())?;
    let valid_workspace = workspace_id
        .strip_prefix("workspace-")
        .is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        });
    let valid_revision = workspace_revision
        .parse::<u64>()
        .is_ok_and(|revision| revision > 0 && revision <= 9_007_199_254_740_991);
    if !control_root.is_absolute()
        || control_root != canonical
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
        || !valid_workspace
        || !valid_revision
    {
        return Err("A.25 architecture test environment rejected".into());
    }
    command
        .env("PIUI_A25_TEST_MODE", "1")
        .env("PIUI_A25_CONTROL_ROOT", canonical)
        .env("PIUI_A25_WORKSPACE_ID", workspace_id)
        .env("PIUI_A25_WORKSPACE_REVISION", workspace_revision);
    Ok(())
}

#[cfg(all(feature = "a23-credential-test", feature = "a25-approval-test"))]
fn configure_architecture_test_sidecar(_command: &mut Command) -> Result<(), String> {
    Err("A.23 and A.25 architecture test features cannot overlap".into())
}

impl Drop for SidecarSupervisor {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn join_transport_threads(running: &mut RunningSidecar) {
    if let Some(handle) = running.stdout.take() {
        let _ = handle.join();
    }
    if let Some(handle) = running.dispatcher.take() {
        let _ = handle.join();
    }
    if let Some(handle) = running.credential_coordinator.take() {
        let _ = handle.join();
    }
    if let Some(handle) = running.approval_coordinator.take() {
        let _ = handle.join();
    }
    if let Some(handle) = running.stderr.take() {
        let _ = handle.join();
    }
}

fn accept_first_protocol_envelope(envelope: Envelope) -> Result<Envelope, String> {
    if envelope.kind == ProtocolKind::Handshake {
        return Ok(envelope);
    }
    if matches!(
        envelope.kind,
        ProtocolKind::HostRequest | ProtocolKind::HostResponse
    ) {
        crate::credentials::proxy::discard_private_envelope(envelope);
    }
    Err("sidecar handshake was not the first protocol envelope".into())
}

fn nonce_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn stopped_status(failure: Option<String>) -> SidecarStatus {
    SidecarStatus {
        running: false,
        failed: failure.is_some(),
        failure,
        generation: None,
        pid: None,
        protocol_version: None,
        node_version: None,
        pi_version: None,
    }
}

fn terminate_group(child: &mut Child, process_group: i32) -> Result<(), String> {
    signal_group(process_group, libc::SIGTERM);
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        let _ = child.try_wait();
        if !group_is_alive(process_group) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    signal_group(process_group, libc::SIGKILL);
    child
        .wait()
        .map(|_| ())
        .map_err(|_| "sidecar termination failed".into())
}

fn signal_group(process_group: i32, signal: i32) {
    unsafe {
        libc::kill(-process_group, signal);
    }
}

fn group_is_alive(process_group: i32) -> bool {
    let result = unsafe { libc::kill(-process_group, 0) };
    if result == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::proxy::private_zeroised_bytes_for_test;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct NeverWritableSink {
        control: Arc<GenerationControl>,
        entered: mpsc::SyncSender<()>,
        attempts_after_invalidation: Arc<AtomicUsize>,
    }

    impl NonblockingSink for NeverWritableSink {
        fn try_write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            if !self.control.is_active() {
                self.attempts_after_invalidation
                    .fetch_add(1, Ordering::Relaxed);
            }
            let _ = self.entered.try_send(());
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }

        fn wait_writable(&mut self, timeout: Duration) -> io::Result<bool> {
            std::thread::sleep(timeout);
            Ok(false)
        }
    }

    #[test]
    fn transition_gate_invalidates_a_waiting_write_without_late_attempts() {
        let failure = Arc::new(Mutex::new(None));
        let control = Arc::new(GenerationControl::new(i32::MAX, failure));
        let (entered_sender, entered_receiver) = mpsc::sync_channel(1);
        let attempts_after_invalidation = Arc::new(AtomicUsize::new(0));
        let mut writer = GenerationWriter::with_sink_for_test(
            1,
            Box::new(NeverWritableSink {
                control: Arc::clone(&control),
                entered: entered_sender,
                attempts_after_invalidation: Arc::clone(&attempts_after_invalidation),
            }),
            Arc::clone(&control),
        );
        let request: Envelope = serde_json::from_value(serde_json::json!({
            "version":1,"kind":"request","id":"web-bounded-public","sequence":9,
            "payload":{"method":"snapshot","afterSequence":0}
        }))
        .unwrap();
        let writer_thread = std::thread::spawn(move || writer.write_public(1, &request));
        entered_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("nonblocking write attempted");
        let invalidation_started = Instant::now();
        assert!(control.deactivate());
        assert!(invalidation_started.elapsed() < Duration::from_millis(50));
        assert_eq!(
            writer_thread.join().unwrap().unwrap_err(),
            "stale sidecar generation"
        );
        assert_eq!(attempts_after_invalidation.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn approval_write_respects_a_real_short_remaining_budget() {
        let failure = Arc::new(Mutex::new(None));
        let control = Arc::new(GenerationControl::new(i32::MAX, failure));
        let (entered_sender, _entered_receiver) = mpsc::sync_channel(1);
        let mut writer = GenerationWriter::with_sink_for_test(
            1,
            Box::new(NeverWritableSink {
                control: Arc::clone(&control),
                entered: entered_sender,
                attempts_after_invalidation: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::clone(&control),
        );
        let started = Instant::now();
        assert_eq!(
            writer
                .write_approval_frame(
                    Zeroizing::new(b"approval-short-budget".to_vec()),
                    Instant::now() + Duration::from_millis(5),
                )
                .unwrap_err(),
            "sidecar write timed out"
        );
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(!control.is_active());
    }

    #[derive(Clone, Copy)]
    enum ApprovalBarrierPoint {
        BodyContinuation,
        FinalLf,
    }

    struct ApprovalBarrierSink {
        point: ApprovalBarrierPoint,
        writes: usize,
        bytes: Arc<Mutex<Vec<u8>>>,
        sink_attempts: Arc<AtomicUsize>,
        marker: Arc<AtomicUsize>,
    }

    impl NonblockingSink for ApprovalBarrierSink {
        fn try_write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.sink_attempts.fetch_add(1, Ordering::SeqCst);
            let written = if self.writes == 0
                && matches!(self.point, ApprovalBarrierPoint::BodyContinuation)
            {
                1.min(bytes.len())
            } else {
                bytes.len()
            };
            self.writes += 1;
            let written_bytes = &bytes[..written];
            if written_bytes.contains(&b'\n') {
                self.marker.fetch_add(1, Ordering::SeqCst);
            }
            self.bytes.lock().unwrap().extend_from_slice(written_bytes);
            Ok(written)
        }

        fn wait_writable(&mut self, _timeout: Duration) -> io::Result<bool> {
            Ok(true)
        }
    }

    #[test]
    fn approval_deadline_is_rechecked_inside_transition_gate_for_body_and_lf() {
        use crate::domain::approval::{
            ApprovalResponseJob, GroupApprovalMemberJob, GroupApprovalResponseJob,
        };
        use crate::domain::workspace::WorkspaceApprovalBinding;

        for group in [false, true] {
            for point in [
                ApprovalBarrierPoint::BodyContinuation,
                ApprovalBarrierPoint::FinalLf,
            ] {
                let failure = Arc::new(Mutex::new(None));
                let control = Arc::new(GenerationControl::new(i32::MAX, failure));
                let bytes = Arc::new(Mutex::new(Vec::new()));
                let sink_attempts = Arc::new(AtomicUsize::new(0));
                let marker = Arc::new(AtomicUsize::new(0));
                let mut writer = GenerationWriter::with_sink_for_test(
                    1,
                    Box::new(ApprovalBarrierSink {
                        point,
                        writes: 0,
                        bytes: Arc::clone(&bytes),
                        sink_attempts: Arc::clone(&sink_attempts),
                        marker: Arc::clone(&marker),
                    }),
                    Arc::clone(&control),
                );
                let (paused_sender, paused_receiver) = mpsc::sync_channel(1);
                let (release_sender, release_receiver) = mpsc::sync_channel(1);
                let release_receiver = Arc::new(Mutex::new(release_receiver));
                let hook_calls = Arc::new(AtomicUsize::new(0));
                control.set_authorisation_hook(Some(Arc::new({
                    let hook_calls = Arc::clone(&hook_calls);
                    let release_receiver = Arc::clone(&release_receiver);
                    move || {
                        if hook_calls.fetch_add(1, Ordering::SeqCst) == 1 {
                            paused_sender.send(()).unwrap();
                            release_receiver.lock().unwrap().recv().unwrap();
                        }
                    }
                })));
                let absolute_deadline = Instant::now() + Duration::from_millis(100);
                let attempt = std::thread::spawn(move || {
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
                                assistant_entry_id: "assistant-entry-barrier".into(),
                                group_id: format!("group-{:032x}", 3),
                                decision_id: format!("decision-{:032x}", 4),
                                transaction_id: format!("transaction-{:032x}", 5),
                                cohort_digest: "a".repeat(64),
                                members: (0..2)
                                    .map(|index| GroupApprovalMemberJob {
                                        correlation_id: format!("sidecar-barrier-{index}"),
                                        approval_id: format!("approval-{:032x}", index + 10),
                                        decision_id: format!("decision-{:032x}", index + 20),
                                        invocation_id: format!("invocation-{:032x}", index + 30),
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
                                correlation_id: "sidecar-barrier-individual".into(),
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
                });
                paused_receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("write paused before transition-gated attempt");
                while Instant::now() < absolute_deadline {
                    std::thread::sleep(Duration::from_millis(1));
                }
                release_sender.send(()).unwrap();
                assert_eq!(
                    attempt.join().unwrap().unwrap_err(),
                    "sidecar write timed out"
                );
                let captured = bytes.lock().unwrap();
                assert!(!captured.is_empty(), "approval body must make progress");
                assert!(!captured.contains(&b'\n'), "final LF must be absent");
                if matches!(point, ApprovalBarrierPoint::FinalLf) {
                    serde_json::from_slice::<Value>(&captured)
                        .expect("complete JSON body reached the LF publication barrier");
                }
                assert_eq!(sink_attempts.load(Ordering::SeqCst), 1);
                assert_eq!(marker.load(Ordering::SeqCst), 0, "no complete frame marker");
                assert!(!control.is_active(), "generation must be invalidated");
            }
        }
    }

    #[test]
    #[ignore = "requires the authorised pre-staged Node runtime; no staging in test"]
    fn staged_approval_sigkill_cancels_every_old_member_without_delegate_replay() {
        use crate::domain::approval::{
            ApprovalChoice, ApprovalGroupSubmission, ApprovalState, ApprovalSubmission,
            ApprovalTerminalReason,
        };
        use sha2::{Digest, Sha256};

        struct FixtureDirectory(PathBuf);
        impl Drop for FixtureDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        let fixture_directory = FixtureDirectory(std::env::temp_dir().join(format!(
            "piui-a18-approval-sigkill-{}",
            uuid::Uuid::new_v4().simple()
        )));
        let fixture_root = &fixture_directory.0;
        let workspace_root = fixture_root.join("workspace");
        let resources = fixture_root.join("sidecar");
        let dist = resources.join("dist");
        fs::create_dir_all(&workspace_root).unwrap();
        fs::create_dir_all(&dist).unwrap();
        fs::write(resources.join("manifest.json"), b"{}\n").unwrap();
        let marker = fixture_root.join("delegate-marker");

        let workspace_registry = Arc::new(WorkspaceRegistry::default());
        let acquired = workspace_registry
            .acquire_selected_directory(&workspace_root)
            .unwrap();
        workspace_registry
            .inspect_metadata(&acquired.workspace_id)
            .unwrap();
        workspace_registry
            .open_untrusted(&acquired.workspace_id, 0)
            .unwrap();
        let (trusted, _) = workspace_registry
            .authorise(&acquired.workspace_id, 0)
            .unwrap();
        assert_eq!(trusted.revision, 1);

        let script = r#"
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const markerPath = __MARKER__;
const workspaceId = __WORKSPACE__;
const generation = Number(process.env.PIUI_SUPERVISOR_GENERATION);
const sessionId = `session-${generation.toString(16).padStart(32, '0')}`;
const assistantEntryId = `assistant-entry-fixture-${generation}`;
const tools = ['read', 'grep', 'find'];
const orderedMembers = tools.map((toolName, ordinal) => ({
  ordinal, toolCallId: `fixture-call-${ordinal + 1}`, toolName,
}));
const digest = (value) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const cohortDigest = digest({ assistantEntryId, orderedMembers });
let sequence = 0;
const send = (kind, id, payload, extra = {}) => process.stdout.write(`${JSON.stringify({
  version: 1, kind, id, sequence: sequence++, payload, ...extra,
})}\n`);
send('handshake', 'sidecar-handshake', {
  nonce: process.env.PIUI_HANDSHAKE_NONCE,
  desktopVersion: process.env.PIUI_DESKTOP_VERSION,
  protocolVersion: 1,
  nodeVersion: '22.23.1',
  piVersion: '0.82.0',
  architecture: process.arch === 'arm64' ? 'arm64' : process.arch,
  capabilities: ['cancel', 'status', 'stream', 'host-credentials', 'workspace-trust-v1'],
});
for (let ordinal = 0; ordinal < tools.length; ordinal += 1) {
  const input = { value: `safe-${ordinal + 1}` };
  send('host-request', `sidecar-approval-${ordinal + 1}`, {
    method: 'approval.request', schemaVersion: 2, generation, sessionId, workspaceId,
    workspaceRevision: 1,
    invocationId: `invocation-${(generation * 100 + ordinal + 1).toString(16).padStart(32, '0')}`,
    toolCallId: orderedMembers[ordinal].toolCallId, toolName: tools[ordinal],
    inputDigest: digest(input), input,
    cohort: { assistantEntryId, cohortDigest, orderedMembers },
  });
}
for (let ordinal = 0; ordinal < tools.length; ordinal += 1) {
  const input = { value: `safe-${ordinal + 1}` };
  send('host-request', `sidecar-ready-${ordinal + 1}`, {
    method: 'approval.ready', schemaVersion: 2, generation,
    invocationId: `invocation-${(generation * 100 + ordinal + 1).toString(16).padStart(32, '0')}`,
    toolCallId: orderedMembers[ordinal].toolCallId,
    inputDigest: digest(input), cohortDigest,
  });
}
let buffered = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffered += chunk;
  for (;;) {
    const lf = buffered.indexOf('\n');
    if (lf < 0) break;
    const line = buffered.slice(0, lf);
    buffered = buffered.slice(lf + 1);
    if (!line) continue;
    const frame = JSON.parse(line);
    if (frame?.payload?.decision === 'approved'
      || frame?.payload?.method === 'approval.group-commit') {
      fs.appendFileSync(markerPath, 'delegate\n', { encoding: 'utf8', mode: 0o600 });
    }
  }
});
process.stdin.resume();
"#
        .replace("__MARKER__", &serde_json::to_string(&marker).unwrap())
        .replace(
            "__WORKSPACE__",
            &serde_json::to_string(&acquired.workspace_id).unwrap(),
        );
        fs::write(dist.join("index.js"), script).unwrap();
        let node =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("binaries/piui-node-aarch64-apple-darwin");
        let paths = SupervisorPaths::validated(node, resources.clone()).unwrap();

        let approval_registry = Arc::new(ApprovalRegistry::default());
        let mut supervisor = SidecarSupervisor::with_registries(
            Arc::clone(&approval_registry),
            Arc::clone(&workspace_registry),
        );
        let first = supervisor.start(&paths).unwrap();
        let old_generation = first.generation.unwrap();
        let old_pid = first.pid.unwrap() as i32;
        let deadline = Instant::now() + Duration::from_secs(3);
        let old_views = loop {
            let pending = approval_registry.pending().unwrap();
            if pending.len() == 3 && pending.iter().all(|view| view.group_action.is_some()) {
                break pending;
            }
            assert!(
                Instant::now() < deadline,
                "approval cohort did not become ready"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        let old_group = old_views[0].group_action.clone().unwrap();
        let old_individual_submission = ApprovalSubmission {
            approval_id: old_views[0].approval_id.clone(),
            decision_id: old_views[0].decision_id.clone(),
            scope_ids: old_views[0]
                .scopes
                .iter()
                .map(|scope| scope.scope_id.clone())
                .collect(),
            choice: ApprovalChoice::ApproveOnce,
        };
        let old_group_submission = ApprovalGroupSubmission {
            group_id: old_group.group_id.clone(),
            decision_id: old_group.decision_id.clone(),
            scope_id: old_group.scope_id.clone(),
        };
        let old_session_id = format!("session-{old_generation:032x}");
        let old_assistant_entry_id = format!("assistant-entry-fixture-{old_generation}");
        let old_tools = ["read", "grep", "find"];
        let old_descriptor = serde_json::json!({
            "assistantEntryId": old_assistant_entry_id,
            "orderedMembers": old_tools.iter().enumerate().map(|(ordinal, tool_name)| {
                serde_json::json!({
                    "ordinal": ordinal,
                    "toolCallId": format!("fixture-call-{}", ordinal + 1),
                    "toolName": tool_name,
                })
            }).collect::<Vec<_>>(),
        });
        let old_cohort_digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&old_descriptor).unwrap())
        );
        let old_input_digests: Vec<String> = (0..old_tools.len())
            .map(|index| {
                format!(
                    "{:x}",
                    Sha256::digest(
                        serde_json::to_vec(&serde_json::json!({
                            "value": format!("safe-{}", index + 1)
                        }))
                        .unwrap()
                    )
                )
            })
            .collect();
        let old_individual_payload = serde_json::json!({
            "schemaVersion": 2,
            "method": "approval.resolve",
            "approvalId": old_views[0].approval_id,
            "transactionId": format!("transaction-{:032x}", 1),
            "invocationId": format!("invocation-{:032x}", old_generation * 100 + 1),
            "toolCallId": "fixture-call-1",
            "inputDigest": old_input_digests[0],
            "cohortDigest": old_cohort_digest,
            "decision": "approved",
            "scopeIds": old_views[0].scopes.iter().map(|scope| scope.scope_id.clone()).collect::<Vec<_>>(),
        });
        let old_individual_payload = old_individual_payload.as_object().unwrap().clone();
        crate::protocol::approval::validate_approval_response(
            &old_views[0].decision_id,
            &old_individual_payload,
        )
        .unwrap();
        let old_individual_frame = Envelope {
            version: 1,
            kind: ProtocolKind::HostResponse,
            id: "rust-old-private-individual".into(),
            correlation_id: Some("sidecar-approval-1".into()),
            decision_id: Some(old_views[0].decision_id.clone()),
            sequence: 1,
            payload: old_individual_payload,
            error: None,
        };
        validate_envelope(&old_individual_frame).unwrap();

        let old_group_members = old_views
            .iter()
            .enumerate()
            .map(|(index, view)| {
                serde_json::json!({
                    "correlationId": format!("sidecar-approval-{}", index + 1),
                    "approvalId": view.approval_id,
                    "decisionId": view.decision_id,
                    "invocationId": format!("invocation-{:032x}", old_generation * 100 + index as u64 + 1),
                    "toolCallId": format!("fixture-call-{}", index + 1),
                    "inputDigest": old_input_digests[index],
                    "scopeId": view.scopes[0].scope_id,
                })
            })
            .collect::<Vec<_>>();
        let old_group_payload = serde_json::json!({
            "schemaVersion": 2,
            "method": "approval.group-commit",
            "generation": old_generation,
            "sessionId": old_session_id,
            "workspaceId": acquired.workspace_id,
            "workspaceRevision": 1,
            "assistantEntryId": old_assistant_entry_id,
            "groupId": old_group.group_id,
            "transactionId": format!("transaction-{:032x}", 2),
            "cohortDigest": old_cohort_digest,
            "decision": "approved",
            "members": old_group_members,
        });
        let old_group_payload = old_group_payload.as_object().unwrap().clone();
        crate::protocol::approval::validate_group_response(
            &old_group.decision_id,
            &old_group_payload,
        )
        .unwrap();
        let old_group_frame = Envelope {
            version: 1,
            kind: ProtocolKind::HostResponse,
            id: "rust-old-private-group".into(),
            correlation_id: Some("sidecar-approval-1".into()),
            decision_id: Some(old_group.decision_id.clone()),
            sequence: 2,
            payload: old_group_payload,
            error: None,
        };
        validate_envelope(&old_group_frame).unwrap();
        assert!(!marker.exists());

        assert_eq!(unsafe { libc::kill(old_pid, libc::SIGKILL) }, 0);
        let _ = supervisor.receive_for_generation(old_generation, Duration::from_secs(1));
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let _ = supervisor.status();
            let snapshot = approval_registry.snapshot().unwrap();
            if snapshot.records.len() == 3
                && snapshot.records.iter().all(|view| {
                    view.state == ApprovalState::Cancelled
                        && view.terminal_reason == Some(ApprovalTerminalReason::GenerationLost)
                })
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "old approvals were not cancelled"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!marker.exists());

        let replacement = supervisor.start(&paths).unwrap();
        let replacement_generation = replacement.generation.unwrap();
        assert!(replacement_generation > old_generation);
        let deadline = Instant::now() + Duration::from_secs(3);
        let replacement_views = loop {
            let pending = approval_registry.pending().unwrap();
            if pending.len() == 3 && pending.iter().all(|view| view.group_action.is_some()) {
                break pending;
            }
            assert!(Instant::now() < deadline, "replacement cohort unavailable");
            std::thread::sleep(Duration::from_millis(5));
        };
        let replacement_before: Vec<_> = replacement_views
            .iter()
            .map(|view| {
                (
                    view.approval_id.clone(),
                    view.decision_id.clone(),
                    view.revision,
                    view.state,
                    view.scopes
                        .iter()
                        .map(|scope| scope.scope_id.clone())
                        .collect::<Vec<_>>(),
                    view.group_action.as_ref().map(|group| {
                        (
                            group.group_id.clone(),
                            group.decision_id.clone(),
                            group.scope_id.clone(),
                        )
                    }),
                )
            })
            .collect();

        assert_eq!(
            approval_registry
                .submit(old_individual_submission)
                .unwrap_err(),
            "approval already settled"
        );
        assert_eq!(
            approval_registry
                .submit_group(old_group_submission)
                .unwrap_err(),
            "approval group rejected"
        );
        for old_frame in [&old_individual_frame, &old_group_frame] {
            assert_eq!(
                supervisor
                    .send_for_generation(replacement_generation, old_frame)
                    .unwrap_err(),
                "sidecar request is not permitted"
            );
        }
        let replacement_after: Vec<_> = approval_registry
            .pending()
            .unwrap()
            .iter()
            .map(|view| {
                (
                    view.approval_id.clone(),
                    view.decision_id.clone(),
                    view.revision,
                    view.state,
                    view.scopes
                        .iter()
                        .map(|scope| scope.scope_id.clone())
                        .collect::<Vec<_>>(),
                    view.group_action.as_ref().map(|group| {
                        (
                            group.group_id.clone(),
                            group.decision_id.clone(),
                            group.scope_id.clone(),
                        )
                    }),
                )
            })
            .collect();
        assert_eq!(replacement_after, replacement_before);
        assert!(!marker.exists());
        supervisor.stop().unwrap();
        assert!(!marker.exists());
    }

    #[test]
    fn workspace_wait_does_not_hold_supervisor_control_and_observes_prompt_cutoff() {
        let failure = Arc::new(Mutex::new(None));
        let control = Arc::new(GenerationControl::new(i32::MAX, failure));
        let waiters = Arc::new(WorkspaceWaiters::new());
        let (sender, receiver) = sync_channel(1);
        waiters
            .register("rust-workspace-hung-1", 1, sender)
            .unwrap();
        let waiter = WorkspaceWaiter {
            id: "rust-workspace-hung-1".into(),
            generation: 1,
            receiver,
            waiters,
            control: Arc::clone(&control),
        };
        let started = Instant::now();
        let waiting = std::thread::spawn(move || waiter.wait(Duration::from_secs(30)));
        std::thread::sleep(Duration::from_millis(20));
        assert!(control.deactivate());
        assert_eq!(
            waiting.join().unwrap().unwrap_err(),
            "workspace execution uncertain"
        );
        assert!(started.elapsed() < Duration::from_millis(150));
    }

    #[test]
    fn private_first_envelope_is_recursively_erased_before_startup_rejection() {
        let canary = format!("startup-private-canary-{}", std::process::id());
        let canary_len = canary.len();
        let envelope: Envelope = serde_json::from_value(serde_json::json!({
            "version":1,"kind":"host-request","id":"startup-private","sequence":0,
            "payload":{"method":"credential.set","providerId":"provider",
                "credential":{"type":"api_key","key":canary}}
        }))
        .unwrap();
        let before = private_zeroised_bytes_for_test();
        assert_eq!(
            accept_first_protocol_envelope(envelope).unwrap_err(),
            "sidecar handshake was not the first protocol envelope"
        );
        assert!(private_zeroised_bytes_for_test() >= before + canary_len);
    }
}
