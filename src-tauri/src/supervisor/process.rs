use super::handshake::{HandshakeExpectation, validate_handshake};
use super::redact::StderrRedactor;
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
                architecture: std::env::consts::ARCH,
            },
        )
        .map_err(|error| {
            self.last_failure = Some(error.clone());
            let _ = terminate_group(&mut child);
            error
        })?;
        self.running = Some(RunningSidecar {
            child,
            stdin: Some(stdin),
            messages: receiver,
            _stdout: stdout_handle,
            _stderr: stderr_handle,
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
        if running.child.try_wait().ok().flatten().is_some() {
            self.running = None;
            self.last_failure = Some("sidecar exited unexpectedly".into());
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
        let running = self.running.as_mut().expect("running status has sidecar");
        let request = serde_json::json!({"version":1,"kind":"request","id":"rust-status","sequence":1,"payload":{"method":"status"}});
        let bytes = format!("{}\n", request);
        running
            .stdin
            .as_mut()
            .ok_or_else(|| "sidecar stdin closed".to_string())?
            .write_all(bytes.as_bytes())
            .map_err(|_| "sidecar write failed".to_string())?;
        match running.messages.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(envelope)) if envelope.kind == ProtocolKind::Response => Ok(envelope),
            Ok(Err(error)) => {
                self.last_failure = Some(error.clone());
                self.stop()?;
                Err(error)
            }
            _ => Err("sidecar response timed out".into()),
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
