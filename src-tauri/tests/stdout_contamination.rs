use piui_lib::supervisor::{SidecarSupervisor, SupervisorPaths};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn fixture_root(name: &str, script: &str) -> (PathBuf, SupervisorPaths) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("piui-{name}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(root.join("dist")).unwrap();
    fs::write(root.join("dist/index.js"), script).unwrap();
    fs::write(root.join("manifest.json"), b"{}\n").unwrap();
    let node =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("binaries/piui-node-aarch64-apple-darwin");
    let paths = SupervisorPaths::validated(node, root.clone()).unwrap();
    (root, paths)
}

fn is_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[test]
fn contamination_after_handshake_kills_group_without_another_request() {
    let script = r#"
const handshake={version:1,kind:'handshake',id:'handshake',sequence:0,payload:{nonce:process.env.PIUI_HANDSHAKE_NONCE,desktopVersion:process.env.PIUI_DESKTOP_VERSION,protocolVersion:1,nodeVersion:process.versions.node,piVersion:'0.82.0',architecture:process.arch,capabilities:['cancel','status','stream','host-credentials','workspace-trust-v1']}};
process.stdout.write(JSON.stringify(handshake)+'\n');
setTimeout(()=>process.stdout.write('not-json contamination\n'),50);
setInterval(()=>{},1000);
"#;
    let (root, paths) = fixture_root("contamination-after", script);
    let mut supervisor = SidecarSupervisor::default();
    let started = supervisor.start(&paths).expect("valid handshake starts");
    let pid = started.pid.unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let failed = loop {
        let status = supervisor.status();
        if status.failed {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "contamination was not observed continuously"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert!(!failed.running);
    assert!(
        failed
            .failure
            .as_deref()
            .unwrap_or_default()
            .contains("stdout")
    );
    assert!(!is_alive(pid), "contaminated process group survived");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn runtime_stderr_is_redacted_before_diagnostics_storage() {
    let script = r#"
process.stderr.write('Authorization: Bearer raw-header token=raw-token https://example.test/?api_key=raw-query /Users/private-person/secret.txt\n');
const handshake={version:1,kind:'handshake',id:'handshake',sequence:0,payload:{nonce:process.env.PIUI_HANDSHAKE_NONCE,desktopVersion:process.env.PIUI_DESKTOP_VERSION,protocolVersion:1,nodeVersion:process.versions.node,piVersion:'0.82.0',architecture:process.arch,capabilities:['cancel','status','stream','host-credentials','workspace-trust-v1']}};
process.stdout.write(JSON.stringify(handshake)+'\n');
process.stdin.resume();
"#;
    let (root, paths) = fixture_root("stderr-redaction", script);
    let mut supervisor = SidecarSupervisor::default();
    supervisor.start(&paths).expect("sidecar starts");
    let deadline = Instant::now() + Duration::from_secs(2);
    let diagnostics = loop {
        let diagnostics = supervisor.diagnostics();
        if !diagnostics.is_empty() {
            break diagnostics.join(" ");
        }
        assert!(
            Instant::now() < deadline,
            "stderr diagnostic was not captured"
        );
        thread::sleep(Duration::from_millis(20));
    };
    for value in [
        "raw-header",
        "raw-token",
        "raw-query",
        "private-person",
        "secret.txt",
    ] {
        assert!(
            !diagnostics.contains(value),
            "stderr pipeline leaked {value}: {diagnostics}"
        );
    }
    supervisor.stop().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn contamination_before_handshake_fails_start_and_kills_child() {
    let script = "process.stdout.write('startup contamination\\n'); setInterval(()=>{},1000);\n";
    let (root, paths) = fixture_root("contamination-before", script);
    let mut supervisor = SidecarSupervisor::default();
    let error = supervisor
        .start(&paths)
        .expect_err("contamination must fail start");
    assert!(error.contains("stdout"));
    assert!(supervisor.status().failed);
    fs::remove_dir_all(root).unwrap();
}
