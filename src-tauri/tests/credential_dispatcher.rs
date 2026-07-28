use piui_lib::protocol::Envelope;
use piui_lib::supervisor::{SidecarSupervisor, SupervisorPaths};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

#[test]
fn stop_is_bounded_when_handshaken_child_never_reads_stdin() {
    let root = std::env::temp_dir().join(format!(
        "piui-credential-dispatcher-backpressure-{}-{}",
        std::process::id(),
        unique_counter()
    ));
    let resources = root.join("resources");
    fs::create_dir_all(resources.join("dist")).unwrap();
    fs::write(resources.join("manifest.json"), "{}\n").unwrap();
    fs::write(resources.join("dist/index.js"), "// fixture\n").unwrap();
    let node = root.join("fixture-node");
    fs::write(
        &node,
        r#"#!/bin/sh
printf '{"version":1,"kind":"handshake","id":"fixture-handshake","sequence":0,"payload":{"nonce":"%s","desktopVersion":"%s","protocolVersion":1,"nodeVersion":"22.23.1","piVersion":"0.82.0","architecture":"arm64","capabilities":["cancel","status","stream","host-credentials","workspace-trust-v1"]}}\n' "$PIUI_HANDSHAKE_NONCE" "$PIUI_DESKTOP_VERSION"
/bin/sleep 30
"#,
    )
    .unwrap();
    fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();

    let paths = SupervisorPaths::validated(node, resources).unwrap();
    let supervisor = Arc::new(Mutex::new(SidecarSupervisor::default()));
    supervisor.lock().unwrap().start(&paths).unwrap();
    let request: Envelope = serde_json::from_value(serde_json::json!({
        "version":1,"kind":"request","id":"web-backpressure-request","sequence":1,
        "payload":{"method":"snapshot","afterSequence":0,"padding":"x".repeat(500_000)}
    }))
    .unwrap();

    let writer_supervisor = Arc::clone(&supervisor);
    let (started_sender, started_receiver) = mpsc::sync_channel(1);
    let writer = std::thread::spawn(move || {
        let mut supervisor = writer_supervisor.lock().unwrap();
        started_sender.send(()).unwrap();
        supervisor.send_envelope(&request)
    });
    started_receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("backpressured write started");

    let stop_started = Instant::now();
    let stop_result = supervisor.lock().unwrap().stop();
    let elapsed = stop_started.elapsed();
    let write_result = writer.join().unwrap();
    assert!(write_result.is_err());
    assert!(stop_result.is_ok());
    assert!(
        elapsed < Duration::from_secs(2),
        "bounded stop exceeded its deadline"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn unexpected_leader_exit_terminates_same_group_descendant_before_status_returns() {
    let root = std::env::temp_dir().join(format!(
        "piui-credential-dispatcher-leader-exit-{}-{}",
        std::process::id(),
        unique_counter()
    ));
    let resources = root.join("resources");
    fs::create_dir_all(resources.join("dist")).unwrap();
    fs::write(resources.join("manifest.json"), "{}\n").unwrap();
    let entrypoint = resources.join("dist/index.js");
    fs::write(&entrypoint, "// fixture\n").unwrap();
    let descendant_path = resources.join("dist/index.js.descendant.pid");
    let node = root.join("fixture-node");
    fs::write(
        &node,
        r#"#!/bin/sh
printf '{"version":1,"kind":"handshake","id":"fixture-handshake","sequence":0,"payload":{"nonce":"%s","desktopVersion":"%s","protocolVersion":1,"nodeVersion":"22.23.1","piVersion":"0.82.0","architecture":"arm64","capabilities":["cancel","status","stream","host-credentials","workspace-trust-v1"]}}\n' "$PIUI_HANDSHAKE_NONCE" "$PIUI_DESKTOP_VERSION"
/bin/sleep 30 &
echo "$!" > "$1.descendant.pid"
/bin/sleep 0.2
exit 7
"#,
    )
    .unwrap();
    fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();

    let paths = SupervisorPaths::validated(node, resources).unwrap();
    let mut supervisor = SidecarSupervisor::default();
    supervisor.start(&paths).unwrap();
    let pid_deadline = Instant::now() + Duration::from_secs(1);
    while !descendant_path.is_file() && Instant::now() < pid_deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let descendant: i32 = fs::read_to_string(&descendant_path)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    let status_deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        let call_started = Instant::now();
        let status = supervisor.status();
        assert!(
            call_started.elapsed() < Duration::from_secs(1),
            "leader-exit status call exceeded its bound"
        );
        if !status.running {
            break status;
        }
        assert!(Instant::now() < status_deadline);
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(status.failed);
    assert_eq!(
        status.failure.as_deref(),
        Some("sidecar exited unexpectedly (code 7)")
    );

    let death_deadline = Instant::now() + Duration::from_secs(1);
    while process_is_alive(descendant) && Instant::now() < death_deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!process_is_alive(descendant));
    let _ = fs::remove_dir_all(root);
}

fn process_is_alive(pid: i32) -> bool {
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

fn unique_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
