use super::dispatcher::{
    DispatcherHandles, PUBLIC_QUEUE_CAPACITY, RAW_QUEUE_CAPACITY, start_dispatcher,
};
use super::handshake::{HandshakeExpectation, protocol_architecture, validate_handshake};
use super::redact::StderrRedactor;
use super::stdio::{FailureSignal, GenerationControl, RawFrame, stderr_reader, stdout_reader};
use crate::credentials::CredentialProxy;
use crate::credentials::proxy::{PendingHostResponse, discard_private_envelope};
use crate::domain::approval::ApprovalRegistry;
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

const WRITE_DEADLINE: Duration = Duration::from_millis(250);
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
}

impl GenerationWriter {
    fn new(
        generation: u64,
        stdin: ChildStdin,
        control: Arc<GenerationControl>,
    ) -> Result<Self, String> {
        let sink = ChildStdinSink::new(&stdin)?;
        control.attach_stdin(stdin)?;
        Ok(Self {
            generation,
            sink: Box::new(sink),
            outbound_sequence: 0,
            internal_request_counter: 0,
            control,
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
    ) -> Result<(), String> {
        self.ensure_active(expected_generation)?;
        let (id, sequence) = self.next_internal_coordinates("approval-response")?;
        let mut payload = Map::new();
        payload.insert("schemaVersion".into(), Value::from(1));
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
        crate::protocol::approval::validate_approval_response(&job.decision_id, &payload)?;
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
        let encoded = serde_json::to_vec(&response)
            .map_err(|_| "approval response encoding failed".to_string());
        discard_private_envelope(response);
        let mut bytes = Zeroizing::new(encoded?);
        bytes.push(b'\n');
        self.write_bytes(bytes)
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
        self.write_bytes(bytes)
    }

    fn write_bytes(&mut self, bytes: Zeroizing<Vec<u8>>) -> Result<(), String> {
        let deadline = Instant::now() + WRITE_DEADLINE;
        let mut offset = 0;
        while offset < bytes.len() {
            if Instant::now() >= deadline {
                self.control.invalidate("sidecar write timed out");
                return Err("sidecar write timed out".into());
            }
            let attempt = self
                .control
                .authorised_attempt(|| self.sink.try_write(&bytes[offset..]));
            let result = match attempt {
                Ok(result) => result,
                Err(()) => return Err("stale sidecar generation".into()),
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
}

impl Default for SidecarSupervisor {
    fn default() -> Self {
        Self {
            running: None,
            last_failure: None,
            generation: 0,
            credential_proxy: CredentialProxy::default(),
            approval_registry: Arc::new(ApprovalRegistry::default()),
        }
    }
}

impl SidecarSupervisor {
    pub(crate) fn with_approval_registry(approval_registry: Arc<ApprovalRegistry>) -> Self {
        Self {
            running: None,
            last_failure: None,
            generation: 0,
            credential_proxy: CredentialProxy::default(),
            approval_registry,
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
        let writer = match GenerationWriter::new(generation, stdin, Arc::clone(&control)) {
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
