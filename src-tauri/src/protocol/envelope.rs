use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fmt::{Display, Formatter};

pub const MAX_LINE_BYTES: usize = 1_048_576;
const MAX_PAYLOAD_BYTES: usize = 524_288;
const MAX_DEPTH: usize = 32;
const MAX_PENDING_IDS: usize = 4_096;
const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;
const MAX_PAYLOAD_PROPERTIES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolKind {
    Handshake,
    Request,
    Response,
    Event,
    HostRequest,
    HostResponse,
    Cancel,
    Ack,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Envelope {
    pub version: u8,
    pub kind: ProtocolKind,
    pub id: String,
    #[serde(default)]
    pub correlation_id: Option<String>,
    #[serde(default)]
    pub decision_id: Option<String>,
    pub sequence: u64,
    pub payload: Map<String, Value>,
    #[serde(default)]
    pub error: Option<EnvelopeError>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvelopeError {
    pub category: ErrorCategory,
    pub message: String,
    #[serde(default)]
    pub retryable: Option<bool>,
    #[serde(default)]
    pub diagnostic_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCategory {
    InvalidRequest,
    UnsupportedVersion,
    Unavailable,
    Cancelled,
    Timeout,
    PermissionDenied,
    Conflict,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError(pub &'static str);

impl Display for ProtocolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for ProtocolError {}

#[derive(Default)]
pub struct ProtocolDecoder {
    seen_ids: HashSet<String>,
}

impl ProtocolDecoder {
    pub fn decode(&mut self, bytes: &[u8]) -> Result<Envelope, ProtocolError> {
        if bytes.is_empty() || bytes.len() > MAX_LINE_BYTES {
            return Err(ProtocolError("line limit exceeded"));
        }
        if bytes.last() != Some(&b'\n') || bytes.contains(&b'\r') {
            return Err(ProtocolError("input must be LF-delimited"));
        }
        let text = std::str::from_utf8(&bytes[..bytes.len() - 1])
            .map_err(|_| ProtocolError("invalid UTF-8"))?;
        let value: Value = serde_json::from_str(text).map_err(|_| ProtocolError("invalid JSON"))?;
        if json_depth(&value, 0) > MAX_DEPTH {
            return Err(ProtocolError("depth limit exceeded"));
        }
        validate_raw_envelope(&value)?;
        let mut envelope: Envelope =
            serde_json::from_value(value).map_err(|_| ProtocolError("schema mismatch"))?;
        validate_envelope(&envelope)?;
        if self.seen_ids.len() >= MAX_PENDING_IDS {
            return Err(ProtocolError("pending ID limit exceeded"));
        }
        if !self.seen_ids.insert(envelope.id.clone()) {
            return Err(ProtocolError("duplicate envelope ID"));
        }
        if envelope.kind == ProtocolKind::Event {
            let event_type = envelope
                .payload
                .get("eventType")
                .and_then(Value::as_str)
                .ok_or(ProtocolError("event type missing"))?;
            if contains_secret_key(&Value::Object(envelope.payload.clone())) {
                return Err(ProtocolError("secret-shaped diagnostic field"));
            }
            if !matches!(
                event_type,
                "sidecar.status"
                    | "stream.delta"
                    | "stream.complete"
                    | "stream.cancelled"
                    | "tool.activity"
            ) {
                let keys = envelope
                    .payload
                    .keys()
                    .filter(|key| !is_secret_key(key))
                    .take(32)
                    .cloned()
                    .map(Value::String)
                    .collect();
                envelope.payload = Map::from_iter([
                    ("eventType".into(), Value::String("unknown-event".into())),
                    (
                        "originalEventType".into(),
                        Value::String(event_type.chars().take(128).collect()),
                    ),
                    ("redacted".into(), Value::Bool(true)),
                    ("keys".into(), Value::Array(keys)),
                ]);
            }
        }
        Ok(envelope)
    }
}

fn validate_raw_envelope(value: &Value) -> Result<(), ProtocolError> {
    let object = value
        .as_object()
        .ok_or(ProtocolError("envelope must be an object"))?;
    for optional_id in ["correlationId", "decisionId"] {
        if let Some(value) = object.get(optional_id) {
            if !value.is_string() {
                return Err(ProtocolError("optional ID must be a string"));
            }
        }
    }
    if let Some(error) = object.get("error") {
        if !error.is_object() {
            return Err(ProtocolError("error must be an object"));
        }
        let error = error.as_object().expect("checked object");
        if let Some(retryable) = error.get("retryable") {
            if !retryable.is_boolean() {
                return Err(ProtocolError("retryable must be boolean"));
            }
        }
        if let Some(diagnostic_id) = error.get("diagnosticId") {
            if !diagnostic_id.is_string() {
                return Err(ProtocolError("diagnostic ID must be a string"));
            }
        }
    }
    Ok(())
}

fn validate_envelope(envelope: &Envelope) -> Result<(), ProtocolError> {
    if envelope.version != 1 {
        return Err(ProtocolError("unsupported version"));
    }
    if envelope.sequence > MAX_SEQUENCE {
        return Err(ProtocolError("sequence exceeds JavaScript safe integer"));
    }
    validate_id(&envelope.id, "invalid ID")?;
    if let Some(id) = &envelope.correlation_id {
        validate_id(id, "invalid correlation ID")?;
    }
    if let Some(id) = &envelope.decision_id {
        validate_id(id, "invalid decision ID")?;
    }
    if matches!(
        envelope.kind,
        ProtocolKind::Response
            | ProtocolKind::HostResponse
            | ProtocolKind::Cancel
            | ProtocolKind::Ack
    ) && envelope.correlation_id.is_none()
    {
        return Err(ProtocolError("correlation ID required"));
    }
    if envelope.payload.len() > MAX_PAYLOAD_PROPERTIES {
        return Err(ProtocolError("payload property limit exceeded"));
    }
    let payload_bytes = serde_json::to_vec(&envelope.payload)
        .map_err(|_| ProtocolError("payload encoding failed"))?
        .len();
    if payload_bytes > MAX_PAYLOAD_BYTES {
        return Err(ProtocolError("payload limit exceeded"));
    }
    if let Some(error) = &envelope.error {
        validate_error(error)?;
    }
    match envelope.kind {
        ProtocolKind::Handshake => validate_handshake(&envelope.payload),
        ProtocolKind::Request | ProtocolKind::HostRequest => {
            let method = envelope
                .payload
                .get("method")
                .and_then(Value::as_str)
                .ok_or(ProtocolError("method required"))?;
            if method.chars().count() > 96 {
                Err(ProtocolError("method too long"))
            } else {
                Ok(())
            }
        }
        ProtocolKind::Event => {
            let event_type = envelope
                .payload
                .get("eventType")
                .and_then(Value::as_str)
                .ok_or(ProtocolError("event type required"))?;
            if event_type.chars().count() > 128 {
                Err(ProtocolError("event type too long"))
            } else {
                Ok(())
            }
        }
        ProtocolKind::Cancel if envelope.payload.len() > 1 => {
            Err(ProtocolError("cancel payload property limit exceeded"))
        }
        _ => Ok(()),
    }
}

fn validate_error(error: &EnvelopeError) -> Result<(), ProtocolError> {
    let message_length = error.message.chars().count();
    if message_length == 0 || message_length > 512 {
        return Err(ProtocolError("invalid error message"));
    }
    if let Some(id) = &error.diagnostic_id {
        validate_id(id, "invalid diagnostic ID")?;
    }
    Ok(())
}

fn validate_handshake(payload: &Map<String, Value>) -> Result<(), ProtocolError> {
    const REQUIRED: [&str; 7] = [
        "nonce",
        "desktopVersion",
        "protocolVersion",
        "nodeVersion",
        "piVersion",
        "architecture",
        "capabilities",
    ];
    if payload.len() != REQUIRED.len() || REQUIRED.iter().any(|key| !payload.contains_key(*key)) {
        return Err(ProtocolError("handshake fields mismatch"));
    }
    let nonce = payload
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or(ProtocolError("nonce required"))?;
    if !(16..=128).contains(&nonce.chars().count()) {
        return Err(ProtocolError("invalid handshake nonce"));
    }
    let desktop = payload
        .get("desktopVersion")
        .and_then(Value::as_str)
        .ok_or(ProtocolError("desktop version required"))?;
    if desktop.chars().count() > 64 {
        return Err(ProtocolError("desktop version too long"));
    }
    if payload.get("protocolVersion") != Some(&Value::from(1))
        || payload.get("piVersion") != Some(&Value::from("0.82.0"))
        || payload.get("architecture") != Some(&Value::from("arm64"))
    {
        return Err(ProtocolError("handshake version or architecture mismatch"));
    }
    let node = payload
        .get("nodeVersion")
        .and_then(Value::as_str)
        .ok_or(ProtocolError("node version required"))?;
    if !node.starts_with("22.") {
        return Err(ProtocolError("node version mismatch"));
    }
    let capabilities = payload
        .get("capabilities")
        .and_then(Value::as_array)
        .ok_or(ProtocolError("capabilities required"))?;
    if capabilities.len() > 64 {
        return Err(ProtocolError("capability count exceeded"));
    }
    let mut unique = HashSet::new();
    for capability in capabilities {
        let capability = capability
            .as_str()
            .ok_or(ProtocolError("capability must be a string"))?;
        if capability.chars().count() > 64 || !unique.insert(capability) {
            return Err(ProtocolError("invalid or duplicate capability"));
        }
    }
    Ok(())
}

fn validate_id(id: &str, message: &'static str) -> Result<(), ProtocolError> {
    if id.is_empty() || id.len() > 128 || !valid_id(id) {
        Err(ProtocolError(message))
    } else {
        Ok(())
    }
}

fn valid_id(id: &str) -> bool {
    id.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
    })
}
fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase().replace(['_', '-'], "");
    [
        "secret",
        "token",
        "password",
        "apikey",
        "authorization",
        "credential",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}
fn contains_secret_key(value: &Value) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(key, value)| is_secret_key(key) || contains_secret_key(value)),
        Value::Array(values) => values.iter().any(contains_secret_key),
        _ => false,
    }
}
fn json_depth(value: &Value, level: usize) -> usize {
    if level > MAX_DEPTH {
        return level;
    }
    match value {
        Value::Object(map) => map
            .values()
            .map(|child| json_depth(child, level + 1))
            .max()
            .unwrap_or(level),
        Value::Array(values) => values
            .iter()
            .map(|child| json_depth(child, level + 1))
            .max()
            .unwrap_or(level),
        _ => level,
    }
}
