use piui_lib::commands::bridge::{
    BridgeState, bridge_abandon_snapshot_transport_for_test, bridge_restart_transport,
    bridge_send_transport, bridge_stop_transport,
};
use piui_lib::commands::stream::{cancel_stream_transport, run_stream_transport};
use piui_lib::protocol::{Envelope, ProtocolKind};
use piui_lib::supervisor::SupervisorPaths;
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[test]
fn real_stream_projection_hides_raw_gaps_and_translates_only_current_ui_coordinates() {
    let root = temporary_fixture_root();
    fs::create_dir_all(root.join("dist")).unwrap();
    fs::write(root.join("manifest.json"), "{}\n").unwrap();
    fs::write(root.join("dist/index.js"), FIXTURE).unwrap();
    let node = find_program("node").expect("test Node executable");
    let paths = SupervisorPaths::validated(node, root.clone()).unwrap();
    let state = BridgeState::new(paths);
    let stream_request: Envelope = serde_json::from_value(serde_json::json!({
        "version":1,"kind":"request","id":"web-stream-actual-1","sequence":777,
        "payload":{"method":"stream.fixture"}
    }))
    .unwrap();
    let stream_state = state.clone();
    let (delivery_sender, delivery_receiver) = mpsc::channel::<Envelope>();
    let (result_sender, result_receiver) = mpsc::channel();
    let stream = std::thread::spawn(move || {
        let result = run_stream_transport(&stream_state, stream_request, |envelope| {
            delivery_sender
                .send(envelope.clone())
                .map_err(|_| "test delivery unavailable".to_string())
        });
        let _ = result_sender.send(result.clone());
        result
    });

    let first = delivery_receiver
        .recv_timeout(Duration::from_secs(3))
        .unwrap_or_else(|error| {
            panic!(
                "first projected delta unavailable: {error:?}; stream={:?}",
                result_receiver.recv_timeout(Duration::from_secs(1))
            )
        });
    let second = delivery_receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("second projected delta after withheld event");
    assert_eq!([first.sequence, second.sequence], [1, 2]);
    assert_eq!(
        [first.id.as_str(), second.id.as_str()],
        ["ui-envelope-1", "ui-envelope-2"]
    );
    assert_eq!(first.correlation_id.as_deref(), Some("web-stream-actual-1"));
    assert_eq!(
        second.correlation_id.as_deref(),
        Some("web-stream-actual-1")
    );
    assert_eq!(first.payload["text"], "A");
    assert_eq!(second.payload["text"], "B");

    let current_snapshot_request = snapshot_request("web-snapshot-current", 2);
    bridge_send_transport(&state, &current_snapshot_request).expect("current UI mapping sends");

    let mut delivered = vec![first, second];
    loop {
        let envelope = delivery_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("projected snapshot/bulk event");
        let terminal = envelope.payload.get("terminal").is_some();
        delivered.push(envelope);
        if terminal {
            break;
        }
    }
    stream.join().unwrap().unwrap();

    assert!(delivered.len() > 1_024);
    for (index, envelope) in delivered.iter().enumerate() {
        assert_eq!(envelope.sequence, index as u64 + 1);
        assert!(matches!(
            envelope.kind,
            ProtocolKind::Event | ProtocolKind::Response | ProtocolKind::Ack
        ));
        let encoded = serde_json::to_string(envelope).unwrap();
        for forbidden in [
            "rawSequence",
            "afterSequence",
            "credential",
            "token",
            "secret",
            "private-payload-value",
            "sidecar-",
            "rust-",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }
    let projected_snapshot = &delivered[2];
    assert_eq!(projected_snapshot.id, "ui-envelope-3");
    assert_eq!(
        projected_snapshot.correlation_id.as_deref(),
        Some("web-snapshot-current")
    );
    assert_eq!(projected_snapshot.payload["snapshot"]["sequence"], 3);
    assert_eq!(projected_snapshot.sequence, 3);

    let capture = wait_for_lines(&root.join("captured-input.jsonl"), 2);
    let snapshot_input: Value = serde_json::from_str(&capture[1]).unwrap();
    assert_eq!(snapshot_input["payload"]["afterSequence"], 3);
    let before_rejected_sends = capture.len();

    // UI sequence 1 has been evicted by the actual projected stream. It must
    // fail before the running fixture observes any outbound request.
    assert!(bridge_send_transport(&state, &snapshot_request("web-snapshot-evicted", 1)).is_err());
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        read_lines(&root.join("captured-input.jsonl")).len(),
        before_rejected_sends
    );

    let last_ui_sequence = delivered.last().unwrap().sequence;
    bridge_restart_transport(&state).expect("fixture restart");
    assert!(
        bridge_send_transport(
            &state,
            &snapshot_request("web-snapshot-stale-generation", last_ui_sequence),
        )
        .is_err()
    );
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        read_lines(&root.join("captured-input.jsonl")).len(),
        before_rejected_sends
    );

    bridge_stop_transport(&state).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn internal_snapshot_identifiers_are_replaced_on_the_real_process_path() {
    let root = temporary_fixture_root();
    fs::create_dir_all(root.join("dist")).unwrap();
    fs::write(root.join("manifest.json"), "{}\n").unwrap();
    fs::write(root.join("dist/index.js"), INTERNAL_SNAPSHOT_FIXTURE).unwrap();
    let paths = SupervisorPaths::validated(find_program("node").unwrap(), root.clone()).unwrap();
    let state = BridgeState::new(paths);
    let request: Envelope = serde_json::from_value(serde_json::json!({
        "version":1,"kind":"request","id":"web-stream-internal-1","sequence":1,
        "payload":{"method":"stream.fixture"}
    }))
    .unwrap();
    let state_for_stream = state.clone();
    let (sender, receiver) = mpsc::channel();
    let stream = std::thread::spawn(move || {
        run_stream_transport(&state_for_stream, request, |envelope| {
            sender
                .send(envelope.clone())
                .map_err(|_| "test delivery unavailable".to_string())
        })
    });
    let mut delivered = Vec::new();
    loop {
        let envelope = receiver.recv_timeout(Duration::from_secs(3)).unwrap();
        let terminal = envelope.payload.get("terminal").is_some();
        delivered.push(envelope);
        if terminal {
            break;
        }
    }
    stream.join().unwrap().unwrap();
    assert_eq!(delivered.len(), 3);
    assert!(
        delivered
            .iter()
            .all(|value| value.kind != ProtocolKind::Ack)
    );
    assert_eq!(delivered[2].payload["terminal"], "complete");
    assert_eq!(
        delivered
            .iter()
            .map(|value| value.sequence)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert_eq!(
        delivered
            .iter()
            .map(|value| value.id.as_str())
            .collect::<Vec<_>>(),
        ["ui-envelope-1", "ui-envelope-2", "ui-envelope-3"]
    );
    assert_eq!(
        delivered[0].correlation_id.as_deref(),
        Some("web-stream-internal-1")
    );
    assert_eq!(
        delivered[1].correlation_id.as_deref(),
        Some("ui-internal-2")
    );
    assert_eq!(
        delivered[2].correlation_id.as_deref(),
        Some("web-stream-internal-1")
    );
    let encoded = serde_json::to_string(&delivered).unwrap();
    assert!(!encoded.contains("sidecar-"));
    assert!(!encoded.contains("rust-"));
    assert!(!encoded.contains("snapshot-1-"));
    let captured = wait_for_lines(&root.join("captured-input.jsonl"), 2);
    let internal: Value = serde_json::from_str(&captured[1]).unwrap();
    assert!(
        internal["id"]
            .as_str()
            .unwrap()
            .starts_with("rust-snapshot-")
    );
    bridge_stop_transport(&state).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn child_exit_between_start_and_stream_registration_deactivates_without_delivery() {
    let root = temporary_fixture_root();
    fs::create_dir_all(root.join("dist")).unwrap();
    fs::write(root.join("manifest.json"), "{}\n").unwrap();
    fs::write(root.join("dist/index.js"), EXIT_AFTER_HANDSHAKE_FIXTURE).unwrap();
    let paths = SupervisorPaths::validated(find_program("node").unwrap(), root.clone()).unwrap();
    let state = BridgeState::new(paths);
    let request: Envelope = serde_json::from_value(serde_json::json!({
        "version":1,"kind":"request","id":"web-stream-exit-gap-1","sequence":1,
        "payload":{"method":"stream.fixture"}
    }))
    .unwrap();
    let mut delivered = 0;
    assert!(
        run_stream_transport(&state, request, |_| {
            delivered += 1;
            Ok(())
        })
        .is_err()
    );
    assert_eq!(delivered, 0);
    bridge_stop_transport(&state).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn real_child_forged_marker_and_ui_namespace_produce_zero_projection() {
    for mode in ["marker", "ui"] {
        let root = temporary_fixture_root();
        fs::create_dir_all(root.join("dist")).unwrap();
        fs::write(root.join("manifest.json"), "{}\n").unwrap();
        fs::write(
            root.join("dist/index.js"),
            FORGED_IDENTIFIER_FIXTURE.replace("__MODE__", mode),
        )
        .unwrap();
        let paths =
            SupervisorPaths::validated(find_program("node").unwrap(), root.clone()).unwrap();
        let state = BridgeState::new(paths);
        let request: Envelope = serde_json::from_value(serde_json::json!({
            "version":1,"kind":"request","id":format!("web-stream-forged-{mode}"),"sequence":1,
            "payload":{"method":"stream.fixture"}
        }))
        .unwrap();
        let mut delivered = 0;
        assert!(
            run_stream_transport(&state, request, |_| {
                delivered += 1;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(delivered, 0);
        bridge_stop_transport(&state).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn real_child_ack_and_snapshot_floods_stop_at_aggregate_limits() {
    for (name, fixture) in [
        ("ack", ACK_FLOOD_FIXTURE),
        ("snapshot", SNAPSHOT_FLOOD_FIXTURE),
    ] {
        let root = temporary_fixture_root();
        fs::create_dir_all(root.join("dist")).unwrap();
        fs::write(root.join("manifest.json"), "{}\n").unwrap();
        fs::write(root.join("dist/index.js"), fixture).unwrap();
        let paths =
            SupervisorPaths::validated(find_program("node").unwrap(), root.clone()).unwrap();
        let state = BridgeState::new(paths);
        let request: Envelope = serde_json::from_value(serde_json::json!({
            "version":1,"kind":"request","id":format!("web-stream-{name}-flood"),"sequence":1,
            "payload":{"method":"stream.fixture"}
        }))
        .unwrap();
        let mut delivered = 0;
        assert_eq!(
            run_stream_transport(&state, request, |_| {
                delivered += 1;
                Ok(())
            }),
            Err("sidecar stream limit exceeded".into())
        );
        assert_eq!(delivered, 0);
        bridge_stop_transport(&state).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn real_child_recovers_after_more_than_replay_window_abandonments_and_rejects_late_cache() {
    let root = temporary_fixture_root();
    fs::create_dir_all(root.join("dist")).unwrap();
    fs::write(root.join("manifest.json"), "{}\n").unwrap();
    fs::write(root.join("dist/index.js"), ORIGIN_STRESS_FIXTURE).unwrap();
    let paths = SupervisorPaths::validated(find_program("node").unwrap(), root.clone()).unwrap();
    let state = BridgeState::new(paths);
    let request: Envelope = serde_json::from_value(serde_json::json!({
        "version":1,"kind":"request","id":"web-stream-origin-stress-1","sequence":1,
        "payload":{"method":"stream.fixture"}
    }))
    .unwrap();
    let state_for_stream = state.clone();
    let (sender, receiver) = mpsc::channel();
    let stream = std::thread::spawn(move || {
        run_stream_transport(&state_for_stream, request, |envelope| {
            sender
                .send(envelope.clone())
                .map_err(|_| "test delivery unavailable".to_string())
        })
    });
    let initial = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(initial.sequence, 1);

    for index in 0..600 {
        let id = format!("web-snapshot-abandoned-{index}");
        bridge_send_transport(&state, &snapshot_request(&id, 1)).unwrap();
        bridge_abandon_snapshot_transport_for_test(&state, &id).unwrap();
    }
    bridge_send_transport(&state, &snapshot_request("web-snapshot-unknown-map", 1)).unwrap();
    bridge_send_transport(&state, &snapshot_request("web-snapshot-healthy", 1)).unwrap();

    let snapshot = receiver.recv_timeout(Duration::from_secs(3)).unwrap();
    let terminal = receiver.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!(snapshot.sequence, 2);
    assert_eq!(
        snapshot.correlation_id.as_deref(),
        Some("web-snapshot-healthy")
    );
    assert_eq!(terminal.sequence, 3);
    assert_eq!(terminal.payload["terminal"], "complete");
    assert!(matches!(
        receiver.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty | std::sync::mpsc::TryRecvError::Disconnected)
    ));
    stream.join().unwrap().unwrap();
    assert!(wait_for_lines(&root.join("captured-input.jsonl"), 603).len() >= 603);
    bridge_stop_transport(&state).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn malformed_process_ack_does_not_settle_native_cancellation_or_suppress_terminal() {
    let root = temporary_fixture_root();
    fs::create_dir_all(root.join("dist")).unwrap();
    fs::write(root.join("manifest.json"), "{}\n").unwrap();
    fs::write(root.join("dist/index.js"), MALFORMED_ACK_FIXTURE).unwrap();
    let paths = SupervisorPaths::validated(find_program("node").unwrap(), root.clone()).unwrap();
    let state = BridgeState::new(paths);
    let request: Envelope = serde_json::from_value(serde_json::json!({
        "version":1,"kind":"request","id":"web-stream-ack-proof-1","sequence":1,
        "payload":{"method":"stream.fixture"}
    }))
    .unwrap();
    let state_for_stream = state.clone();
    let (sender, receiver) = mpsc::channel();
    let stream = std::thread::spawn(move || {
        run_stream_transport(&state_for_stream, request, |envelope| {
            sender
                .send(envelope.clone())
                .map_err(|_| "test delivery unavailable".to_string())
        })
    });
    let delta = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(delta.payload["text"], "ready");
    let cancellation: Envelope = serde_json::from_value(serde_json::json!({
        "version":1,"kind":"cancel","id":"web-cancel-ack-proof-1",
        "correlationId":"web-stream-ack-proof-1","sequence":2,"payload":{}
    }))
    .unwrap();
    assert_eq!(
        cancel_stream_transport(&state, cancellation),
        Err("cancellation acknowledgement timed out".into())
    );
    let terminal = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(terminal.payload["terminal"], "complete");
    assert!(matches!(
        receiver.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty | std::sync::mpsc::TryRecvError::Disconnected)
    ));
    stream.join().unwrap().unwrap();
    bridge_stop_transport(&state).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn real_harness_queue_captures_only_projected_consecutive_envelopes() {
    let root = temporary_fixture_root();
    fs::create_dir_all(root.join("dist")).unwrap();
    fs::write(root.join("manifest.json"), "{}\n").unwrap();
    fs::write(root.join("dist/index.js"), FIXTURE).unwrap();
    let node = find_program("node").expect("test Node executable");
    let mut child = Command::new(env!("CARGO_BIN_EXE_stream-harness"))
        .env("PIUI_HARNESS_TEST_NODE", node)
        .env("PIUI_HARNESS_TEST_RESOURCES", &root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("stream harness starts");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    writeln!(
        stdin,
        "{}",
        serde_json::to_string(&serde_json::json!({
            "version":1,"kind":"request","id":"web-stream-actual-1","sequence":88,
            "payload":{"method":"stream.fixture"}
        }))
        .unwrap()
    )
    .unwrap();
    stdin.flush().unwrap();

    let first = read_envelope_line(&mut stdout);
    let second = read_envelope_line(&mut stdout);
    assert_eq!([first.sequence, second.sequence], [1, 2]);
    assert_eq!(
        [first.id.as_str(), second.id.as_str()],
        ["ui-envelope-1", "ui-envelope-2"]
    );
    assert_eq!(first.correlation_id.as_deref(), Some("web-stream-actual-1"));
    assert_eq!(
        second.correlation_id.as_deref(),
        Some("web-stream-actual-1")
    );
    writeln!(
        stdin,
        "{}",
        serde_json::to_string(&snapshot_request("web-harness-snapshot", 2)).unwrap()
    )
    .unwrap();
    stdin.flush().unwrap();

    let mut delivered = vec![first, second];
    loop {
        let envelope = read_envelope_line(&mut stdout);
        let terminal = envelope.payload.get("terminal").is_some();
        delivered.push(envelope);
        if terminal {
            break;
        }
    }
    drop(stdin);
    let status = child.wait().unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success());
    assert!(stderr.is_empty());
    for (index, envelope) in delivered.iter().enumerate() {
        assert_eq!(envelope.sequence, index as u64 + 1);
        assert!(matches!(
            envelope.kind,
            ProtocolKind::Event | ProtocolKind::Response | ProtocolKind::Ack
        ));
        let encoded = serde_json::to_string(envelope).unwrap();
        assert!(!encoded.contains("rawSequence"));
        assert!(!encoded.contains("afterSequence"));
        assert!(!encoded.contains("credential"));
        assert!(!encoded.contains("sidecar-"));
        assert!(!encoded.contains("rust-"));
    }
    assert_eq!(delivered[2].id, "ui-envelope-3");
    assert_eq!(
        delivered[2].correlation_id.as_deref(),
        Some("web-harness-snapshot")
    );
    assert_eq!(delivered[2].payload["snapshot"]["sequence"], 3);
    assert_eq!(
        serde_json::from_str::<Value>(&wait_for_lines(&root.join("captured-input.jsonl"), 2)[1])
            .unwrap()["payload"]["afterSequence"],
        3
    );
    fs::remove_dir_all(root).unwrap();
}

fn read_envelope_line(reader: &mut BufReader<impl Read>) -> Envelope {
    let mut line = String::new();
    assert!(
        reader.read_line(&mut line).unwrap() > 0,
        "harness stdout closed"
    );
    serde_json::from_str(&line).unwrap()
}

fn snapshot_request(id: &str, after_sequence: u64) -> Envelope {
    serde_json::from_value(serde_json::json!({
        "version":1,"kind":"request","id":id,"sequence":999999,
        "payload":{"method":"snapshot","afterSequence":after_sequence}
    }))
    .unwrap()
}

fn find_program(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn temporary_fixture_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "piui-webview-projection-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn wait_for_lines(path: &Path, minimum: usize) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let lines = read_lines(path);
        if lines.len() >= minimum {
            return lines;
        }
        assert!(Instant::now() < deadline, "fixture capture timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn read_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

const EXIT_AFTER_HANDSHAKE_FIXTURE: &str = r#"
const handshake = {version:1,kind:'handshake',id:'sidecar-handshake',sequence:0,payload:{
  nonce:process.env.PIUI_HANDSHAKE_NONCE,desktopVersion:process.env.PIUI_DESKTOP_VERSION,
  protocolVersion:1,nodeVersion:'22.23.1',piVersion:'0.82.0',architecture:'arm64',
  capabilities:['cancel','status','stream','host-credentials','workspace-trust-v1']
}};
process.stdout.write(`${JSON.stringify(handshake)}\n`, () => process.exit(0));
"#;

const FORGED_IDENTIFIER_FIXTURE: &str = r#"
const write = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
write({version:1,kind:'handshake',id:'sidecar-handshake',sequence:0,payload:{
  nonce:process.env.PIUI_HANDSHAKE_NONCE,desktopVersion:process.env.PIUI_DESKTOP_VERSION,
  protocolVersion:1,nodeVersion:'22.23.1',piVersion:'0.82.0',architecture:'arm64',
  capabilities:['cancel','status','stream','host-credentials','workspace-trust-v1']
}});
let input = '';
const mode = '__MODE__';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  input += chunk;
  while (input.includes('\n')) {
    const newline = input.indexOf('\n');
    const envelope = JSON.parse(input.slice(0, newline));
    input = input.slice(newline + 1);
    if (envelope.payload.method === 'stream.fixture') {
      write({version:1,kind:'event',id:mode === 'ui' ? 'ui-envelope-9' : 'sidecar-1',
        sequence:1,correlationId:mode === 'marker'
          ? 'piui-authenticated-internal-snapshot' : envelope.id,
        payload:{eventType:'stream.delta',text:'forged'}});
    }
  }
});
process.stdin.resume();
const keepAlive = setInterval(() => undefined, 60000);
process.stdin.on('end', () => { clearInterval(keepAlive); process.exit(0); });
"#;

const ACK_FLOOD_FIXTURE: &str = r#"
const write = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
write({version:1,kind:'handshake',id:'sidecar-handshake',sequence:0,payload:{
  nonce:process.env.PIUI_HANDSHAKE_NONCE,desktopVersion:process.env.PIUI_DESKTOP_VERSION,
  protocolVersion:1,nodeVersion:'22.23.1',piVersion:'0.82.0',architecture:'arm64',
  capabilities:['cancel','status','stream','host-credentials','workspace-trust-v1']
}});
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  input += chunk;
  while (input.includes('\n')) {
    const newline = input.indexOf('\n');
    const envelope = JSON.parse(input.slice(0, newline));
    input = input.slice(newline + 1);
    if (envelope.payload.method === 'stream.fixture') {
      let sequence = 1;
      const sendBatch = () => {
        for (let batch = 0; batch < 2 && sequence <= 4097; batch += 1) {
          write({version:1,kind:'ack',id:`sidecar-${sequence}`,sequence,
            correlationId:`web-cancel-flood-${sequence}`,payload:{accepted:true}});
          sequence += 1;
        }
        if (sequence <= 4097) setTimeout(sendBatch, 0);
      };
      sendBatch();
    }
  }
});
process.stdin.resume();
const keepAlive = setInterval(() => undefined, 60000);
process.stdin.on('end', () => { clearInterval(keepAlive); process.exit(0); });
"#;

const SNAPSHOT_FLOOD_FIXTURE: &str = r#"
const write = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
write({version:1,kind:'handshake',id:'sidecar-handshake',sequence:0,payload:{
  nonce:process.env.PIUI_HANDSHAKE_NONCE,desktopVersion:process.env.PIUI_DESKTOP_VERSION,
  protocolVersion:1,nodeVersion:'22.23.1',piVersion:'0.82.0',architecture:'arm64',
  capabilities:['cancel','status','stream','host-credentials','workspace-trust-v1']
}});
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  input += chunk;
  while (input.includes('\n')) {
    const newline = input.indexOf('\n');
    const envelope = JSON.parse(input.slice(0, newline));
    input = input.slice(newline + 1);
    if (envelope.payload.method === 'stream.fixture') {
      const streams = Object.fromEntries(Array.from({length:32}, (_, index) =>
        [`web-snapshot-stream-${index}`, {text:'x'.repeat(8192)}]));
      write({version:1,kind:'response',id:'sidecar-1',sequence:1,
        correlationId:'web-snapshot-flood-1',payload:{snapshot:{sequence:1,
        state:{status:'ready',streams}}}});
      write({version:1,kind:'response',id:'sidecar-2',sequence:2,
        correlationId:'web-snapshot-flood-2',payload:{snapshot:{sequence:2,
        state:{status:'ready',streams}}}});
    }
  }
});
process.stdin.resume();
const keepAlive = setInterval(() => undefined, 60000);
process.stdin.on('end', () => { clearInterval(keepAlive); process.exit(0); });
"#;

const ORIGIN_STRESS_FIXTURE: &str = r#"
const fs = require('node:fs');
const write = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
write({version:1,kind:'handshake',id:'sidecar-handshake',sequence:0,payload:{
  nonce:process.env.PIUI_HANDSHAKE_NONCE,desktopVersion:process.env.PIUI_DESKTOP_VERSION,
  protocolVersion:1,nodeVersion:'22.23.1',piVersion:'0.82.0',architecture:'arm64',
  capabilities:['cancel','status','stream','host-credentials','workspace-trust-v1']
}});
let input = '';
let streamId = '';
let sequence = 1;
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  input += chunk;
  while (input.includes('\n')) {
    const newline = input.indexOf('\n');
    const envelope = JSON.parse(input.slice(0, newline));
    input = input.slice(newline + 1);
    fs.appendFileSync('captured-input.jsonl', `${JSON.stringify(envelope)}\n`);
    if (envelope.payload.method === 'stream.fixture') {
      streamId = envelope.id;
      write({version:1,kind:'event',id:`sidecar-${sequence}`,sequence:sequence++,
        correlationId:streamId,payload:{eventType:'stream.delta',text:'ready'}});
    } else if (envelope.id === 'web-snapshot-unknown-map') {
      write({version:1,kind:'response',id:`sidecar-${sequence}`,sequence:sequence++,
        correlationId:envelope.id,payload:{snapshot:{sequence:sequence-2,state:{status:'ready',
        streams:{'web-unknown-stream':{text:'forged'}}}}}});
    } else if (envelope.id === 'web-snapshot-healthy') {
      write({version:1,kind:'response',id:`sidecar-${sequence}`,sequence:sequence++,
        correlationId:'web-snapshot-abandoned-0',payload:{snapshot:{sequence:sequence-2,
        state:{status:'ready',streams:{[streamId]:{text:'late-cache'}}}}}});
      write({version:1,kind:'response',id:`sidecar-${sequence}`,sequence:sequence++,
        correlationId:envelope.id,payload:{snapshot:{sequence:sequence-2,
        state:{status:'ready',streams:{[streamId]:{text:'healthy'}}}}}});
      write({version:1,kind:'event',id:`sidecar-${sequence}`,sequence:sequence++,
        correlationId:streamId,payload:{eventType:'stream.complete',terminal:'complete'}});
    }
  }
});
process.stdin.resume();
const keepAlive = setInterval(() => undefined, 60000);
process.stdin.on('end', () => { clearInterval(keepAlive); process.exit(0); });
"#;

const MALFORMED_ACK_FIXTURE: &str = r#"
const write = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
write({version:1,kind:'handshake',id:'sidecar-handshake',sequence:0,payload:{
  nonce:process.env.PIUI_HANDSHAKE_NONCE,desktopVersion:process.env.PIUI_DESKTOP_VERSION,
  protocolVersion:1,nodeVersion:'22.23.1',piVersion:'0.82.0',architecture:'arm64',
  capabilities:['cancel','status','stream','host-credentials','workspace-trust-v1']
}});
let input = '';
let streamId = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  input += chunk;
  while (input.includes('\n')) {
    const newline = input.indexOf('\n');
    const envelope = JSON.parse(input.slice(0, newline));
    input = input.slice(newline + 1);
    if (envelope.payload.method === 'stream.fixture') {
      streamId = envelope.id;
      write({version:1,kind:'event',id:'sidecar-1',sequence:1,correlationId:streamId,
        payload:{eventType:'stream.delta',text:'ready'}});
    } else if (envelope.kind === 'cancel') {
      write({version:1,kind:'ack',id:'sidecar-2',sequence:2,correlationId:envelope.id,
        payload:{accepted:true,extra:true}});
      setTimeout(() => write({version:1,kind:'event',id:'sidecar-3',sequence:3,
        correlationId:streamId,payload:{eventType:'stream.complete',terminal:'complete'}}), 1100);
    }
  }
});
process.stdin.resume();
const keepAlive = setInterval(() => undefined, 60000);
process.stdin.on('end', () => { clearInterval(keepAlive); process.exit(0); });
"#;

const INTERNAL_SNAPSHOT_FIXTURE: &str = r#"
const fs = require('node:fs');
const write = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
write({
  version:1, kind:'handshake', id:'sidecar-handshake', sequence:0,
  payload:{
    nonce:process.env.PIUI_HANDSHAKE_NONCE,
    desktopVersion:process.env.PIUI_DESKTOP_VERSION,
    protocolVersion:1, nodeVersion:'22.23.1', piVersion:'0.82.0', architecture:'arm64',
    capabilities:['cancel','status','stream','host-credentials','workspace-trust-v1']
  }
});
let input = '';
let streamId = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  input += chunk;
  while (input.includes('\n')) {
    const newline = input.indexOf('\n');
    const line = input.slice(0, newline);
    input = input.slice(newline + 1);
    const envelope = JSON.parse(line);
    fs.appendFileSync('captured-input.jsonl', `${JSON.stringify(envelope)}\n`);
    if (envelope.payload.method === 'stream.fixture') {
      streamId = envelope.id;
      write({version:1,kind:'event',id:'sidecar-1',sequence:1,correlationId:streamId,
        payload:{eventType:'stream.delta',text:'safe'}});
      write({version:1,kind:'event',id:'sidecar-3',sequence:3,correlationId:streamId,
        payload:{eventType:'stream.delta',text:'withheld-gap'}});
    } else if (envelope.payload.method === 'snapshot') {
      write({version:1,kind:'response',id:'sidecar-4',sequence:4,correlationId:envelope.id,
        payload:{snapshot:{sequence:3,state:{status:'ready',streams:{[streamId]:{text:'safe'}}}}}});
      write({version:1,kind:'ack',id:'sidecar-5',sequence:5,correlationId:streamId,
        payload:{accepted:true}});
      write({version:1,kind:'event',id:'sidecar-6',sequence:6,correlationId:streamId,
        payload:{eventType:'stream.complete',terminal:'complete'}});
    }
  }
});
process.stdin.resume();
const keepAlive = setInterval(() => undefined, 60000);
process.stdin.on('end', () => { clearInterval(keepAlive); process.exit(0); });
"#;

const FIXTURE: &str = r#"
const fs = require('node:fs');
const write = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
let sequence = 1;
let streamId = '';
let bulkStarted = false;
write({
  version: 1,
  kind: 'handshake',
  id: 'sidecar-handshake',
  sequence: 0,
  payload: {
    nonce: process.env.PIUI_HANDSHAKE_NONCE,
    desktopVersion: process.env.PIUI_DESKTOP_VERSION,
    protocolVersion: 1,
    nodeVersion: '22.23.1',
    piVersion: '0.82.0',
    architecture: 'arm64',
    capabilities: [
      'cancel', 'status', 'stream', 'host-credentials', 'workspace-trust-v1', 'AgentSession',
      'AgentSessionRuntime', 'ModelRuntime', 'ProjectTrustStore',
      'SessionManager', 'createAgentSession'
    ]
  }
});
const event = (payload, correlationId = streamId) => write({
  version: 1, kind: 'event', id: `sidecar-${sequence}`, sequence: sequence++,
  correlationId, payload
});
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  input += chunk;
  while (input.includes('\n')) {
    const newline = input.indexOf('\n');
    const line = input.slice(0, newline);
    input = input.slice(newline + 1);
    const envelope = JSON.parse(line);
    fs.appendFileSync('captured-input.jsonl', `${JSON.stringify(envelope)}\n`);
    if (envelope.payload.method === 'stream.fixture') {
      streamId = envelope.id;
      event({eventType:'stream.delta', text:'A'});
      event({eventType:'future.safe-event', detail:{ordinary:'withheld'}});
      event({eventType:'stream.delta', text:'B'});
    } else if (envelope.payload.method === 'snapshot' && !bulkStarted) {
      const snapshotSequence = sequence - 1;
      write({
        version:1, kind:'response', id:`sidecar-${sequence}`, sequence:sequence++,
        correlationId:envelope.id,
        payload:{snapshot:{sequence:snapshotSequence,state:{
          status:'ready', streams:{[streamId]:{text:'AB'}}
        }}}
      });
      bulkStarted = true;
      let count = 0;
      const timer = setInterval(() => {
        if (count < 1025) {
          event({eventType:'stream.delta', text:''});
          count += 1;
          return;
        }
        clearInterval(timer);
        event({eventType:'stream.complete', terminal:'complete'});
      }, 1);
    }
  }
});
process.stdin.resume();
const keepAlive = setInterval(() => undefined, 60000);
process.stdin.on('end', () => { clearInterval(keepAlive); process.exit(0); });
"#;
