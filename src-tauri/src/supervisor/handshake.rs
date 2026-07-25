use crate::protocol::{Envelope, ProtocolKind};
use serde_json::Value;
use std::collections::HashSet;

pub const PROTOCOL_VERSION: u64 = 1;
pub const NODE_VERSION: &str = "22.23.1";
pub const PI_VERSION: &str = "0.82.0";
pub const REQUIRED_CAPABILITIES: [&str; 4] = ["cancel", "status", "stream", "host-credentials"];

pub fn protocol_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        architecture => architecture,
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeExpectation<'a> {
    pub nonce: &'a str,
    pub desktop_version: &'a str,
    pub architecture: &'a str,
}

pub fn validate_handshake(
    envelope: &Envelope,
    expected: &HandshakeExpectation<'_>,
) -> Result<(), String> {
    if envelope.kind != ProtocolKind::Handshake
        || text(envelope, "nonce") != Some(expected.nonce)
        || text(envelope, "desktopVersion") != Some(expected.desktop_version)
        || number(envelope, "protocolVersion") != Some(PROTOCOL_VERSION)
        || text(envelope, "nodeVersion") != Some(NODE_VERSION)
        || text(envelope, "piVersion") != Some(PI_VERSION)
        || text(envelope, "architecture") != Some(expected.architecture)
    {
        return Err("incompatible-sidecar".into());
    }
    let capabilities = envelope
        .payload
        .get("capabilities")
        .and_then(Value::as_array)
        .ok_or_else(|| "incompatible-sidecar".to_string())?
        .iter()
        .filter_map(Value::as_str)
        .collect::<HashSet<_>>();
    if REQUIRED_CAPABILITIES
        .iter()
        .any(|capability| !capabilities.contains(capability))
    {
        return Err("incompatible-sidecar".into());
    }
    Ok(())
}

fn text<'a>(envelope: &'a Envelope, field: &str) -> Option<&'a str> {
    envelope.payload.get(field).and_then(Value::as_str)
}
fn number(envelope: &Envelope, field: &str) -> Option<u64> {
    envelope.payload.get(field).and_then(Value::as_u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Envelope {
        serde_json::from_value(json!({
          "version":1,"kind":"handshake","id":"h","sequence":0,
          "payload":{"nonce":"0123456789abcdef","desktopVersion":"0.1.0","protocolVersion":1,
          "nodeVersion":"22.23.1","piVersion":"0.82.0","architecture":"arm64",
          "capabilities":["cancel","status","stream","host-credentials"]}
        }))
        .unwrap()
    }

    #[test]
    fn accepts_the_canonical_architecture_and_rejects_mismatches() {
        let expected = HandshakeExpectation {
            nonce: "0123456789abcdef",
            desktop_version: "0.1.0",
            architecture: "arm64",
        };
        assert!(validate_handshake(&fixture(), &expected).is_ok());

        for (field, value) in [
            ("nonce", json!("wrong")),
            ("protocolVersion", json!(2)),
            ("piVersion", json!("0.83.0")),
            ("architecture", json!("x64")),
        ] {
            let mut changed = fixture();
            changed.payload.insert(field.into(), value);
            assert_eq!(
                validate_handshake(&changed, &expected),
                Err("incompatible-sidecar".into())
            );
        }

        let mut missing_capability = fixture();
        missing_capability
            .payload
            .insert("capabilities".into(), json!(["cancel", "status", "stream"]));
        assert_eq!(
            validate_handshake(&missing_capability, &expected),
            Err("incompatible-sidecar".into())
        );
    }

    #[test]
    fn maps_rust_target_names_to_protocol_names() {
        assert!(matches!(protocol_architecture(), "arm64" | "x64"));
    }
}
