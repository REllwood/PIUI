use piui_lib::protocol::{MAX_LINE_BYTES, ProtocolDecoder};
use serde_json::{Value, json};

fn event(id: &str, payload: Value) -> Vec<u8> {
    let envelope = json!({
        "version": 1,
        "kind": "event",
        "id": id,
        "sequence": 1,
        "payload": payload,
    });
    format!("{envelope}\n").into_bytes()
}

#[test]
fn malformed_framing_and_utf8_are_rejected_without_advancing_state() {
    let valid = event(
        "framing-state",
        json!({"eventType": "sidecar.status", "status": "ready"}),
    );
    let mut missing_lf = valid.clone();
    missing_lf.pop();
    let mut crlf = valid.clone();
    crlf.pop();
    crlf.extend_from_slice(b"\r\n");
    let multiple = [valid.as_slice(), valid.as_slice()].concat();
    let invalid_utf8 = vec![b'{', b'"', b'x', b'"', b':', 0xc3, b'(', b'}', b'\n'];
    let cases = [
        (Vec::new(), "line limit exceeded"),
        (missing_lf, "input must be LF-delimited"),
        (crlf, "input must be LF-delimited"),
        (multiple, "invalid JSON"),
        (invalid_utf8, "invalid UTF-8"),
        (b"{\"version\":1,}\n".to_vec(), "invalid JSON"),
    ];

    let mut decoder = ProtocolDecoder::default();
    for (bytes, expected) in cases {
        assert_eq!(decoder.decode(&bytes).unwrap_err().0, expected);
    }
    assert!(
        decoder.decode(&valid).is_ok(),
        "rejected input advanced the duplicate window"
    );
}

#[test]
fn line_payload_and_json_depth_limits_are_bounded() {
    let mut oversized_line = vec![b' '; MAX_LINE_BYTES + 1];
    *oversized_line.last_mut().expect("non-empty line") = b'\n';
    assert_eq!(
        ProtocolDecoder::default()
            .decode(&oversized_line)
            .unwrap_err()
            .0,
        "line limit exceeded"
    );

    let oversized_payload = event(
        "oversized-payload",
        json!({"eventType": "sidecar.status", "detail": "x".repeat(524_288)}),
    );
    assert!(oversized_payload.len() < MAX_LINE_BYTES);
    assert_eq!(
        ProtocolDecoder::default()
            .decode(&oversized_payload)
            .unwrap_err()
            .0,
        "payload limit exceeded"
    );

    let mut nested = json!({"terminal": true});
    for _ in 0..=32 {
        nested = json!({"child": nested});
    }
    let excessive_depth = event(
        "excessive-depth",
        json!({"eventType": "future.deep-event", "nested": nested}),
    );
    assert_eq!(
        ProtocolDecoder::default()
            .decode(&excessive_depth)
            .unwrap_err()
            .0,
        "depth limit exceeded"
    );
}

#[test]
fn unknown_events_are_redacted_and_secret_shaped_diagnostics_are_rejected() {
    let event_type = format!("future.{}", "x".repeat(121));
    let mut payload = serde_json::Map::from_iter([
        ("eventType".to_string(), Value::String(event_type)),
        (
            "apiToken".to_string(),
            Value::String("must-not-survive".to_string()),
        ),
    ]);
    for index in 0..40 {
        payload.insert(format!("safeKey{index:02}"), Value::from(index));
    }
    let secret = event("secret-unknown", Value::Object(payload.clone()));
    assert_eq!(
        ProtocolDecoder::default().decode(&secret).unwrap_err().0,
        "secret-shaped diagnostic field"
    );

    payload.remove("apiToken");
    let decoded = ProtocolDecoder::default()
        .decode(&event("bounded-unknown", Value::Object(payload)))
        .expect("bounded unknown event accepted");
    assert_eq!(decoded.payload["eventType"], "unknown-event");
    assert_eq!(decoded.payload["redacted"], true);
    assert_eq!(
        decoded.payload["originalEventType"]
            .as_str()
            .expect("original type")
            .chars()
            .count(),
        128
    );
    assert_eq!(
        decoded.payload["keys"]
            .as_array()
            .expect("diagnostic keys")
            .len(),
        32
    );
    assert!(
        !serde_json::to_string(&decoded.payload)
            .expect("diagnostic serialises")
            .contains("must-not-survive")
    );
}

#[test]
fn deterministic_mutation_corpus_fails_closed() {
    let valid = json!({
        "version": 1,
        "kind": "event",
        "id": "mutation-base",
        "sequence": 1,
        "payload": {"eventType": "sidecar.status", "status": "ready"},
    });
    let mutations = [
        {
            let mut value = valid.clone();
            value["version"] = json!(2);
            value
        },
        {
            let mut value = valid.clone();
            value["kind"] = json!("notification");
            value
        },
        {
            let mut value = valid.clone();
            value["id"] = json!("");
            value
        },
        {
            let mut value = valid.clone();
            value["id"] = json!("../escape");
            value
        },
        {
            let mut value = valid.clone();
            value["sequence"] = json!(-1);
            value
        },
        {
            let mut value = valid.clone();
            value["sequence"] = json!(1.25);
            value
        },
        {
            let mut value = valid.clone();
            value["payload"] = json!([]);
            value
        },
        {
            let mut value = valid.clone();
            value["payload"] = json!({});
            value
        },
        {
            let mut value = valid.clone();
            value["unexpected"] = json!(true);
            value
        },
        json!(null),
        json!([]),
        json!("event"),
    ];

    for mutation in mutations {
        let bytes = format!("{mutation}\n").into_bytes();
        assert!(ProtocolDecoder::default().decode(&bytes).is_err());
    }
    assert!(
        ProtocolDecoder::default()
            .decode(format!("{valid}\n").as_bytes())
            .is_ok()
    );
}
