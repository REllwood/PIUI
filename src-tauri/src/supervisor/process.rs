use super::handshake::{HandshakeExpectation, protocol_architecture, validate_handshake};
use super::redact::StderrRedactor;
use super::router::{SequenceOutcome, SequenceRouter};
use super::stdio::{FailureSignal, stderr_reader, stdout_reader};
use crate::protocol::{Envelope, ProtocolKind};
use serde::Serialize;
use serde_json::Value;
use std::collections::VecDeque;
use std::fs;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{
    Arc, Mutex,
    mpsc::{self, Receiver},
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

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
    pub pid: Option<u32>,
    pub protocol_version: Option<u64>,
    pub node_version: Option<String>,
    pub pi_version: Option<String>,
}

struct RunningSidecar {
    child: Child,
    stdin: Option<ChildStdin>,
    messages: Receiver<Result<Envelope, String>>,
    _stdout: JoinHandle<()>,
    _stderr: JoinHandle<()>,
    diagnostics: Arc<Mutex<VecDeque<String>>>,
    failure: FailureSignal,
    handshake: Envelope,
    router: SequenceRouter,
    outbound_sequence: u64,
    internal_request_counter: u64,
    snapshot_request: Option<String>,
}

impl RunningSidecar {
    fn write_envelope(&mut self, envelope: &Envelope) -> Result<(), String> {
        self.outbound_sequence = self.outbound_sequence.max(envelope.sequence);
        let bytes = serde_json::to_vec(envelope)
            .map_err(|_| "sidecar request encoding failed".to_string())?;
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| "sidecar stdin closed".to_string())?;
        stdin
            .write_all(&bytes)
            .and_then(|_| stdin.write_all(b"\n"))
            .and_then(|_| stdin.flush())
            .map_err(|_| "sidecar write failed".to_string())
    }

    fn internal_request(
        &mut self,
        method: &str,
        payload: serde_json::Map<String, Value>,
    ) -> Result<Envelope, String> {
        self.internal_request_counter += 1;
        self.outbound_sequence += 1;
        let mut payload = payload;
        payload.insert("method".into(), Value::String(method.into()));
        serde_json::from_value(serde_json::json!({
            "version": 1,
            "kind": "request",
            "id": format!("rust-{method}-{}", self.internal_request_counter),
            "sequence": self.outbound_sequence,
            "payload": payload,
        }))
        .map_err(|_| "internal sidecar request invalid".to_string())
    }
}

#[derive(Default)]
pub struct SidecarSupervisor {
    running: Option<RunningSidecar>,
    last_failure: Option<String>,
}

impl SidecarSupervisor {
    pub fn start(&mut self, paths: &SupervisorPaths) -> Result<SidecarStatus, String> {
        if self.status().running {
            return Err("sidecar is already running".into());
        }
        self.running = None;
        self.last_failure = None;
        let nonce = format!("piui-{:016x}-{:08x}", std::process::id(), nonce_counter());
        let mut command = Command::new(&paths.node);
        command
            .arg(&paths.entrypoint)
            .current_dir(&paths.resource_root)
            .env_clear()
            .env("NODE_ENV", "production")
            .env("PIUI_DESKTOP_VERSION", env!("CARGO_PKG_VERSION"))
            .env("PIUI_HANDSHAKE_NONCE", &nonce)
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
        let (sender, receiver) = mpsc::channel();
        let diagnostics = Arc::new(Mutex::new(VecDeque::with_capacity(64)));
        let failure: FailureSignal = Arc::new(Mutex::new(None));
        let process_group = child.id() as i32;
        let stdout_handle = stdout_reader(stdout, sender, process_group, failure.clone());
        let stderr_handle = stderr_reader(
            stderr,
            diagnostics.clone(),
            StderrRedactor::for_current_user(),
        );
        let handshake = match receiver.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(envelope)) if envelope.kind == ProtocolKind::Handshake => envelope,
            Ok(Err(error)) => {
                self.last_failure = Some(error.clone());
                let _ = terminate_group(&mut child);
                return Err(error);
            }
            Ok(Ok(_)) => {
                let error = "sidecar handshake was not the first protocol envelope".to_string();
                self.last_failure = Some(error.clone());
                let _ = terminate_group(&mut child);
                return Err(error);
            }
            Err(_) => {
                let error = "sidecar handshake timed out".to_string();
                self.last_failure = Some(error.clone());
                let _ = terminate_group(&mut child);
                return Err(error);
            }
        };
        validate_handshake(
            &handshake,
            &HandshakeExpectation {
                nonce: &nonce,
                desktop_version: env!("CARGO_PKG_VERSION"),
                architecture: protocol_architecture(),
            },
        )
        .map_err(|error| {
            self.last_failure = Some(error.clone());
            let _ = terminate_group(&mut child);
            error
        })?;
        let mut router = SequenceRouter::default();
        router.apply_snapshot(handshake.sequence);
        self.running = Some(RunningSidecar {
            child,
            stdin: Some(stdin),
            messages: receiver,
            _stdout: stdout_handle,
            _stderr: stderr_handle,
            diagnostics,
            failure,
            handshake,
            router,
            outbound_sequence: 0,
            internal_request_counter: 0,
            snapshot_request: None,
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
                let _ = running.child.wait();
            }
            self.last_failure = Some(failure);
            return stopped_status(self.last_failure.clone());
        }
        let Some(running) = self.running.as_mut() else {
            return stopped_status(self.last_failure.clone());
        };
        if let Some(exit) = running.child.try_wait().ok().flatten() {
            self.running = None;
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

    pub fn request_status(&mut self) -> Result<Envelope, String> {
        let status = self.status();
        if !status.running {
            return Err(status
                .failure
                .unwrap_or_else(|| "sidecar is not running".into()));
        }
        let request = {
            let running = self.running.as_mut().expect("running status has sidecar");
            running.internal_request("status", serde_json::Map::new())?
        };
        let request_id = request.id.clone();
        self.send_envelope(&request)?;
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

    pub fn send_envelope(&mut self, envelope: &Envelope) -> Result<(), String> {
        let status = self.status();
        if !status.running {
            return Err(status
                .failure
                .unwrap_or_else(|| "sidecar is not running".into()));
        }
        self.running
            .as_mut()
            .expect("running status has sidecar")
            .write_envelope(envelope)
    }

    pub fn receive_envelope(&mut self, timeout: Duration) -> Result<Envelope, String> {
        let status = self.status();
        if !status.running {
            return Err(status
                .failure
                .unwrap_or_else(|| "sidecar is not running".into()));
        }
        let deadline = Instant::now() + timeout;
        let running = self.running.as_mut().expect("running status has sidecar");
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("sidecar receive timed out".into());
            }
            let envelope = match running.messages.recv_timeout(remaining) {
                Ok(Ok(envelope)) => envelope,
                Ok(Err(error)) => return Err(error),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    return Err("sidecar receive timed out".into());
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("sidecar response channel closed".into());
                }
            };

            if running
                .snapshot_request
                .as_deref()
                .is_some_and(|request_id| envelope.correlation_id.as_deref() == Some(request_id))
            {
                let snapshot = envelope
                    .payload
                    .get("snapshot")
                    .and_then(Value::as_object)
                    .ok_or_else(|| "sidecar snapshot invalid".to_string())?;
                let snapshot_sequence = snapshot
                    .get("sequence")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "sidecar snapshot invalid".to_string())?;
                if envelope.kind != ProtocolKind::Response
                    || snapshot_sequence > envelope.sequence
                    || !snapshot.get("state").is_some_and(Value::is_object)
                    || !running.router.apply_snapshot(envelope.sequence)
                {
                    return Err("sidecar snapshot invalid".into());
                }
                running.snapshot_request = None;
                return Ok(envelope);
            }

            match running.router.observe(&envelope) {
                SequenceOutcome::Accepted => return Ok(envelope),
                SequenceOutcome::Duplicate | SequenceOutcome::Stale => continue,
                SequenceOutcome::Gap => {
                    if running.router.take_resynchronisation() {
                        let mut payload = serde_json::Map::new();
                        payload.insert(
                            "afterSequence".into(),
                            Value::from(running.router.last_sequence().unwrap_or(0)),
                        );
                        let request = running.internal_request("snapshot", payload)?;
                        running.snapshot_request = Some(request.id.clone());
                        running.write_envelope(&request)?;
                    }
                }
            }
        }
    }

    pub fn stop(&mut self) -> Result<(), String> {
        let Some(mut running) = self.running.take() else {
            return Ok(());
        };
        if let Ok(failure) = running.failure.lock() {
            if failure.is_some() {
                self.last_failure = failure.clone();
            }
        }
        running.stdin.take();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if running
                .child
                .try_wait()
                .map_err(|_| "sidecar wait failed".to_string())?
                .is_some()
            {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        terminate_group(&mut running.child)
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
        pid: None,
        protocol_version: None,
        node_version: None,
        pi_version: None,
    }
}
fn terminate_group(child: &mut Child) -> Result<(), String> {
    let pid = child.id() as i32;
    unsafe {
        libc::kill(-pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    child
        .wait()
        .map(|_| ())
        .map_err(|_| "sidecar termination failed".into())
}
