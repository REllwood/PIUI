#![cfg(debug_assertions)]

use piui_lib::protocol::Envelope;
use piui_lib::supervisor::{
    RESTART_HALTED_REPORT, RestartController, SidecarSupervisor, SupervisorPaths,
};
use std::time::{Duration, Instant};

#[test]
fn lifecycle_crash_restarts_with_new_generations_then_halts_and_allows_user_recovery() {
    let paths = SupervisorPaths::development().expect("development sidecar paths");
    let mut supervisor = SidecarSupervisor::default();
    let first = supervisor.start(&paths).expect("initial sidecar starts");
    let mut generation = first.generation.expect("initial generation");
    let mut old_pids = vec![first.pid.expect("initial pid") as i32];
    let mut restart = RestartController::new(3, Duration::from_millis(5), Duration::from_secs(60));

    for attempt in 1..=3 {
        crash_generation(&mut supervisor, generation, attempt);
        let recovered = restart
            .automatic_restart(&mut supervisor, &paths)
            .expect("bounded automatic restart");
        let next_generation = recovered.generation.expect("recovered generation");
        assert!(next_generation > generation);
        assert_eq!(restart.attempt_count(), attempt as usize);
        assert_eq!(
            supervisor
                .send_for_generation(generation, &status_request("web-stale", 1))
                .unwrap_err(),
            "stale sidecar generation"
        );
        generation = next_generation;
        old_pids.push(recovered.pid.expect("recovered pid") as i32);
    }

    crash_generation(&mut supervisor, generation, 4);
    let halted = restart
        .automatic_restart(&mut supervisor, &paths)
        .expect_err("crash loop must halt");
    assert_eq!(halted, RESTART_HALTED_REPORT);
    assert!(restart.is_halted());
    assert!(!halted.contains('/'));
    assert!(!halted.contains("code 70"));

    let user_recovered = restart
        .user_restart(&mut supervisor, &paths)
        .expect("user restart resets the cut-off");
    assert!(!restart.is_halted());
    assert_eq!(restart.attempt_count(), 0);
    let user_generation = user_recovered.generation.expect("user generation");
    assert!(user_generation > generation);
    let response = supervisor
        .request_status()
        .expect("one active reader answers");
    assert_eq!(response.payload["status"], "ready");
    assert_eq!(
        supervisor
            .receive_for_generation(user_generation, Duration::from_millis(50))
            .unwrap_err(),
        "sidecar receive timed out"
    );

    supervisor.stop().unwrap();
    for pid in old_pids {
        assert!(wait_until_gone(pid, Duration::from_secs(1)));
    }
}

fn crash_generation(supervisor: &mut SidecarSupervisor, generation: u64, attempt: u64) {
    let request: Envelope = serde_json::from_value(serde_json::json!({
        "version": 1,
        "kind": "request",
        "id": format!("web-crash-{attempt}"),
        "sequence": 1,
        "payload": {"method": "spike.crash"}
    }))
    .unwrap();
    supervisor
        .send_for_generation(generation, &request)
        .expect("crash request sent");
    let _ = supervisor.receive_for_generation(generation, Duration::from_secs(1));
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let status = supervisor.status();
        if status.failed {
            assert!(!status.running);
            break;
        }
        assert!(Instant::now() < deadline, "sidecar crash was not observed");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn status_request(id: &str, sequence: u64) -> Envelope {
    serde_json::from_value(serde_json::json!({
        "version": 1,
        "kind": "request",
        "id": id,
        "sequence": sequence,
        "payload": {"method": "status"}
    }))
    .unwrap()
}

fn wait_until_gone(pid: i32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let alive = unsafe { libc::kill(pid, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH);
        if !alive {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}
