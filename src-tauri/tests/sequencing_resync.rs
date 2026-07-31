#![cfg(debug_assertions)]

use piui_lib::protocol::Envelope;
use piui_lib::supervisor::{SidecarSupervisor, SupervisorPaths};
use std::fs;
use std::time::Duration;

#[test]
fn gap_requests_one_snapshot_from_the_last_accepted_sequence() {
    let development = SupervisorPaths::development().expect("development runtime");
    let root = std::env::temp_dir().join(format!(
        "piui-sequencing-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(root.join("dist")).unwrap();
    fs::write(root.join("manifest.json"), "{}\n").unwrap();
    fs::write(
        root.join("dist/index.js"),
        r#"
const write = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
write({
  version: 1,
  kind: 'handshake',
  id: 'sidecar-handshake',
  sequence: 0,
  payload: {
    nonce: process.env.PIUI_HANDSHAKE_NONCE,
    desktopVersion: process.env.PIUI_DESKTOP_VERSION,
    protocolVersion: 1,
    nodeVersion: process.versions.node,
    piVersion: '0.82.0',
    architecture: 'arm64',
    capabilities: [
      'cancel', 'status', 'stream', 'host-credentials', 'workspace-trust-v1', 'AgentSession',
      'AgentSessionRuntime', 'ModelRuntime', 'ProjectTrustStore',
      'SessionManager', 'createAgentSession'
    ]
  }
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
    if (envelope.payload.method === 'trigger-gap') {
      write({version:1, kind:'event', id:'state-1', sequence:1,
        correlationId:envelope.id, payload:{eventType:'sidecar.status', value:'accepted'}});
      write({version:1, kind:'event', id:'state-3', sequence:3,
        correlationId:envelope.id, payload:{eventType:'sidecar.status', value:'must-not-apply'}});
    } else if (envelope.payload.method === 'snapshot') {
      write({version:1, kind:'response', id:'snapshot-response', sequence:4,
        correlationId:envelope.id, payload:{snapshot:{sequence:3,
          state:{afterSequence:envelope.payload.afterSequence, value:'authoritative'}}}});
      write({version:1, kind:'event', id:'state-5', sequence:5,
        payload:{eventType:'sidecar.status', value:'after-snapshot'}});
      write({version:1, kind:'event', id:'future-6', sequence:6,
        payload:{eventType:'future.private.event', ordinaryField:'private-payload-value'}});
      write({version:1, kind:'event', id:'state-7', sequence:7,
        payload:{eventType:'sidecar.status', value:'after-redaction'}});
    }
  }
});
process.stdin.resume();
const keepAlive = setInterval(() => undefined, 60000);
process.stdin.on('end', () => { clearInterval(keepAlive); process.exit(0); });
"#,
    )
    .unwrap();

    let paths = SupervisorPaths::validated(development.node, root.clone()).unwrap();
    let mut supervisor = SidecarSupervisor::default();
    supervisor.start(&paths).expect("fixture starts");
    let request: Envelope = serde_json::from_value(serde_json::json!({
        "version": 1,
        "kind": "request",
        "id": "web-trigger-1",
        "sequence": 1,
        "payload": {"method": "trigger-gap"}
    }))
    .unwrap();
    supervisor.send_envelope(&request).unwrap();

    let accepted = supervisor
        .receive_envelope(Duration::from_secs(2))
        .expect("first event");
    assert_eq!(accepted.sequence, 1);
    let snapshot = supervisor
        .receive_envelope(Duration::from_secs(2))
        .expect("authoritative snapshot");
    assert_eq!(snapshot.sequence, 4);
    assert_eq!(
        snapshot.payload["snapshot"]["state"]["afterSequence"],
        serde_json::json!(1),
        "resynchronisation must start from the last accepted sequence"
    );
    let after_snapshot = supervisor
        .receive_envelope(Duration::from_secs(2))
        .expect("post-snapshot event");
    assert_eq!(after_snapshot.sequence, 5);
    assert_eq!(after_snapshot.payload["value"], "after-snapshot");
    let after_redaction = supervisor
        .receive_envelope(Duration::from_secs(2))
        .expect("unknown event is withheld");
    assert_eq!(after_redaction.sequence, 7);
    assert_eq!(after_redaction.payload["value"], "after-redaction");
    let diagnostics = supervisor.diagnostics().join("\n");
    assert!(diagnostics.contains("redacted and withheld"));
    assert!(!diagnostics.contains("future.private.event"));
    assert!(!diagnostics.contains("private-payload-value"));

    supervisor.stop().unwrap();
    fs::remove_dir_all(root).unwrap();
}
