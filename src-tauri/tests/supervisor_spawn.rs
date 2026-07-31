#![cfg(debug_assertions)]

use piui_lib::supervisor::{SidecarSupervisor, SupervisorPaths};
use std::process::Command;

#[test]
fn supervisor_spawn_has_one_child_valid_pipes_no_listener_and_clean_stop() {
    let paths = SupervisorPaths::development().expect("bundled paths");
    let mut supervisor = SidecarSupervisor::default();
    let status = supervisor.start(&paths).expect("sidecar starts");
    assert!(status.running);
    assert_eq!(status.node_version.as_deref(), Some("22.23.1"));
    assert_eq!(status.pi_version.as_deref(), Some("0.82.0"));
    let response = supervisor.request_status().unwrap_or_else(|error| {
        let status = supervisor.status();
        let diagnostics = supervisor.diagnostics();
        panic!("valid status response: {error}; status={status:?}; diagnostics={diagnostics:?}")
    });
    assert_eq!(
        response
            .payload
            .get("status")
            .and_then(|value| value.as_str()),
        Some("ready")
    );
    assert!(
        supervisor.start(&paths).is_err(),
        "second child must be rejected"
    );
    let pid = status.pid.expect("child PID");
    let listeners = Command::new("lsof")
        .args(["-Pan", "-p", &pid.to_string(), "-iTCP", "-sTCP:LISTEN"])
        .output()
        .expect("lsof available");
    assert!(listeners.stdout.is_empty(), "sidecar opened a TCP listener");
    assert!(
        supervisor.diagnostics().is_empty(),
        "unexpected sidecar diagnostic"
    );
    supervisor.stop().expect("clean stop");
    assert!(!supervisor.status().running);
    let gone = Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .expect("kill probe");
    assert!(!gone.success(), "sidecar process survived stop");
}
