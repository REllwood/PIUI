use piui_lib::supervisor::{SidecarSupervisor, SupervisorPaths};
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn lifecycle_normal_parent_pipe_eof_exits_the_real_sidecar() {
    let paths = SupervisorPaths::development().expect("development sidecar paths");
    let mut child = Command::new(&paths.node)
        .arg(&paths.entrypoint)
        .current_dir(&paths.resource_root)
        .env_clear()
        .env("NODE_ENV", "production")
        .env("PIUI_DESKTOP_VERSION", "0.1.0")
        .env("PIUI_HANDSHAKE_NONCE", "parent-pipe-test-0001")
        .env("PIUI_OWN_PROCESS_GROUP", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("sidecar spawn");
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .expect("handshake read");
    let handshake: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(handshake["kind"], "handshake");

    drop(child.stdin.take());
    let status = wait_for_status(&mut child, Duration::from_secs(2)).expect("sidecar exits");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn lifecycle_normal_parent_pipe_eof_cleans_owned_descendants() {
    let paths = SupervisorPaths::development().expect("development sidecar paths");
    let root = temporary_fixture("parent-loss-descendants");
    let lifecycle = paths.resource_root.join("dist/lifecycle.js");
    let script_path = root.join("probe.mjs");
    fs::write(&script_path, lifecycle_probe_script(&lifecycle)).unwrap();
    let mut child = Command::new(&paths.node)
        .arg(&script_path)
        .current_dir(&root)
        .env_clear()
        .env("PIUI_OWN_PROCESS_GROUP", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("lifecycle probe spawn");
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready, "ready\n");
    let descendant_pid: i32 = fs::read_to_string(root.join("descendant.pid"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(process_is_alive(descendant_pid));

    drop(child.stdin.take());
    let status = wait_for_status(&mut child, Duration::from_secs(2)).expect("probe exits");
    assert_eq!(status.code(), Some(0));
    assert!(wait_until_gone(descendant_pid, Duration::from_secs(2)));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn lifecycle_normal_destroyed_input_preserves_failure_status_and_cleans_descendants() {
    let paths = SupervisorPaths::development().expect("development sidecar paths");
    let root = temporary_fixture("destroyed-input-descendants");
    let script_path = root.join("probe.mjs");
    fs::write(
        &script_path,
        lifecycle_probe_script(&paths.resource_root.join("dist/lifecycle.js")),
    )
    .unwrap();
    let mut child = Command::new(&paths.node)
        .arg(&script_path)
        .current_dir(&root)
        .env_clear()
        .env("PIUI_OWN_PROCESS_GROUP", "1")
        .env("PROBE_DESTROY_INPUT", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("failure lifecycle probe spawn");
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready, "ready\n");
    let descendant_pid: i32 = fs::read_to_string(root.join("descendant.pid"))
        .unwrap()
        .parse()
        .unwrap();

    let status = wait_for_status(&mut child, Duration::from_secs(2)).expect("failure probe exits");
    assert_eq!(status.code(), Some(65));
    assert!(wait_until_gone(descendant_pid, Duration::from_secs(2)));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn lifecycle_normal_stop_cleans_the_owned_group_and_preserves_an_unrelated_process() {
    let development = SupervisorPaths::development().expect("development runtime");
    let root = temporary_fixture("normal-stop");
    fs::write(root.join("manifest.json"), "{}\n").unwrap();
    fs::create_dir_all(root.join("dist")).unwrap();
    fs::write(
        root.join("dist/index.js"),
        r#"
const fs = require('node:fs');
const { spawn } = require('node:child_process');
const descendant = spawn('/bin/sh', ['-c', "trap '' TERM; while :; do sleep 1; done"], { stdio: 'ignore' });
fs.writeFileSync('descendant.pid', String(descendant.pid));
process.stdout.write(`${JSON.stringify({
  version: 1, kind: 'handshake', id: 'sidecar-handshake', sequence: 0,
  payload: {
    nonce: process.env.PIUI_HANDSHAKE_NONCE,
    desktopVersion: process.env.PIUI_DESKTOP_VERSION,
    protocolVersion: 1,
    nodeVersion: process.versions.node,
    piVersion: '0.82.0', architecture: 'arm64',
    capabilities: [
      'cancel', 'status', 'stream', 'host-credentials', 'workspace-trust-v1',
      'AgentSession', 'AgentSessionRuntime', 'ModelRuntime', 'ProjectTrustStore',
      'SessionManager', 'createAgentSession'
    ]
  }
})}\n`);
process.stdin.resume();
const keepAlive = setInterval(() => undefined, 60000);
process.stdin.on('end', () => { clearInterval(keepAlive); process.exit(0); });
"#,
    )
    .unwrap();
    let paths = SupervisorPaths::validated(development.node, root.clone()).unwrap();
    let mut unrelated = Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("unrelated sentinel");
    let unrelated_pid = unrelated.id() as i32;

    let mut supervisor = SidecarSupervisor::default();
    let status = supervisor.start(&paths).expect("fixture starts");
    let descendant_file = root.join("descendant.pid");
    let deadline = Instant::now() + Duration::from_secs(2);
    while !descendant_file.is_file() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let descendant_pid: i32 = fs::read_to_string(&descendant_file)
        .expect("descendant pid file")
        .parse()
        .unwrap();
    assert!(process_is_alive(descendant_pid));

    supervisor.stop().expect("normal group stop");
    assert!(wait_until_gone(descendant_pid, Duration::from_secs(2)));
    assert!(wait_until_gone(
        status.pid.expect("sidecar pid") as i32,
        Duration::from_secs(1)
    ));
    assert!(process_is_alive(unrelated_pid));

    let _ = unrelated.kill();
    let _ = unrelated.wait();
    fs::remove_dir_all(root).unwrap();
}

fn lifecycle_probe_script(lifecycle: &std::path::Path) -> String {
    let lifecycle_json = serde_json::to_string(lifecycle.to_str().unwrap()).unwrap();
    format!(
        r#"
import fs from 'node:fs';
import {{ spawn }} from 'node:child_process';
import {{ pathToFileURL }} from 'node:url';
const {{ installParentPipeLifecycle }} = await import(pathToFileURL({lifecycle_json}).href);
const descendant = spawn('/bin/sh', ['-c', "trap '' TERM; while :; do sleep 1; done"], {{ stdio: 'ignore' }});
fs.writeFileSync('descendant.pid', String(descendant.pid));
process.stdout.write('ready\n');
installParentPipeLifecycle(new Map());
if (process.env.PROBE_DESTROY_INPUT === '1') {{
  setTimeout(() => {{ process.exitCode = 65; process.stdin.destroy(); }}, 20);
}}
"#
    )
}

fn temporary_fixture(label: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "piui-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn wait_for_status(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().ok().flatten() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

fn wait_until_gone(pid: i32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !process_is_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

fn process_is_alive(pid: i32) -> bool {
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}
