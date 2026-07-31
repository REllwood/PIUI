use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashSet, VecDeque};
use std::fmt::{Debug, Display, Formatter};
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

pub const MAX_LINE_BYTES: usize = 1_048_576;
const MAX_PAYLOAD_BYTES: usize = 524_288;
const MAX_DEPTH: usize = 32;
// A credential is validated with depth zero at `payload.credential`; the
// private envelope and payload wrappers consume exactly two additional levels.
const PRIVATE_HOST_REQUEST_MAX_DEPTH: usize = MAX_DEPTH + 2;
const MAX_RECENT_IDS: usize = 4_096;
const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;
const MAX_PAYLOAD_PROPERTIES: usize = 128;

#[cfg(test)]
static PRIVATE_DECODE_ZEROISED_BYTES: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
fn private_decode_zeroised_bytes() -> usize {
    PRIVATE_DECODE_ZEROISED_BYTES.load(Ordering::Relaxed)
}

fn zeroise_private_string(value: &mut String) {
    #[cfg(test)]
    PRIVATE_DECODE_ZEROISED_BYTES.fetch_add(value.len(), Ordering::Relaxed);
    value.zeroize();
}

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

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Envelope {
    pub version: u8,
    pub kind: ProtocolKind,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    pub sequence: u64,
    pub payload: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<EnvelopeError>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvelopeError {
    pub category: ErrorCategory,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_id: Option<String>,
}

impl Debug for Envelope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("Envelope");
        debug
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field("id", &self.id)
            .field("correlation_id", &self.correlation_id)
            .field("decision_id", &self.decision_id)
            .field("sequence", &self.sequence);
        if matches!(
            self.kind,
            ProtocolKind::HostRequest | ProtocolKind::HostResponse
        ) {
            debug.field("payload", &"<redacted private payload>").field(
                "error",
                &self.error.as_ref().map(|_| "<redacted private error>"),
            );
        } else {
            debug
                .field("payload", &self.payload)
                .field("error", &self.error);
        }
        debug.finish()
    }
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
    seen_order: VecDeque<String>,
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
        let raw: Value = serde_json::from_str(text).map_err(|_| ProtocolError("invalid JSON"))?;
        let raw = RawEnvelopeGuard::new(raw);
        let private_kind = raw.private_kind();
        let depth_limit = if private_kind == Some(ProtocolKind::HostRequest) {
            PRIVATE_HOST_REQUEST_MAX_DEPTH
        } else {
            MAX_DEPTH
        };
        if json_depth(raw.value(), 0) > depth_limit {
            return Err(ProtocolError("depth limit exceeded"));
        }
        validate_raw_envelope(raw.value())?;

        // Once a private kind is identified, avoid serde's fallible
        // Value-to-typed clone/deserialisation path. Strictly validate all
        // fields first, then move the already-parsed allocations into the
        // envelope. Both raw and decoded guards recursively erase strings on
        // every subsequent failure.
        let mut decoded = if private_kind.is_some() {
            DecodedEnvelope::Private(decode_private_envelope(raw)?)
        } else {
            DecodedEnvelope::Ordinary(
                serde_json::from_value(raw.into_value())
                    .map_err(|_| ProtocolError("schema mismatch"))?,
            )
        };
        let envelope = decoded.envelope_mut();
        validate_envelope(envelope)?;
        if !self.seen_ids.insert(envelope.id.clone()) {
            return Err(ProtocolError("duplicate envelope ID"));
        }
        self.seen_order.push_back(envelope.id.clone());
        if self.seen_order.len() > MAX_RECENT_IDS
            && let Some(oldest) = self.seen_order.pop_front()
        {
            self.seen_ids.remove(&oldest);
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
            let known_event = matches!(
                event_type,
                "sidecar.status"
                    | "stream.delta"
                    | "stream.complete"
                    | "stream.cancelled"
                    | "tool.activity"
            ) || cfg!(feature = "a25-approval-test")
                && event_type == "approval-matrix.complete";
            if !known_event {
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
        Ok(decoded.into_envelope())
    }
}

struct RawEnvelopeGuard(Value);

impl RawEnvelopeGuard {
    fn new(value: Value) -> Self {
        Self(value)
    }

    fn value(&self) -> &Value {
        &self.0
    }

    fn private_kind(&self) -> Option<ProtocolKind> {
        match self.0.get("kind").and_then(Value::as_str) {
            Some("host-request") => Some(ProtocolKind::HostRequest),
            Some("host-response") => Some(ProtocolKind::HostResponse),
            _ => None,
        }
    }

    fn into_value(mut self) -> Value {
        std::mem::take(&mut self.0)
    }
}

impl Drop for RawEnvelopeGuard {
    fn drop(&mut self) {
        zeroise_json_value(&mut self.0);
    }
}

enum DecodedEnvelope {
    Ordinary(Envelope),
    Private(DecodedPrivateEnvelope),
}

impl DecodedEnvelope {
    fn envelope_mut(&mut self) -> &mut Envelope {
        match self {
            Self::Ordinary(envelope) => envelope,
            Self::Private(envelope) => &mut envelope.0,
        }
    }

    fn into_envelope(self) -> Envelope {
        match self {
            Self::Ordinary(envelope) => envelope,
            Self::Private(mut envelope) => std::mem::replace(&mut envelope.0, empty_envelope()),
        }
    }
}

struct DecodedPrivateEnvelope(Envelope);

impl Drop for DecodedPrivateEnvelope {
    fn drop(&mut self) {
        zeroise_envelope_strings(&mut self.0);
    }
}

fn decode_private_envelope(
    mut raw: RawEnvelopeGuard,
) -> Result<DecodedPrivateEnvelope, ProtocolError> {
    validate_private_raw_schema(raw.value())?;
    let mut object = match std::mem::take(&mut raw.0) {
        Value::Object(object) => object,
        _ => unreachable!("private raw schema checked object"),
    };
    let kind = match take_raw_string(&mut object, "kind").as_str() {
        "host-request" => ProtocolKind::HostRequest,
        "host-response" => ProtocolKind::HostResponse,
        _ => unreachable!("private raw schema checked kind"),
    };
    let error = object.remove("error").map(|value| {
        let Value::Object(mut error) = value else {
            unreachable!("private error checked");
        };
        EnvelopeError {
            category: parse_error_category(&take_raw_string(&mut error, "category"))
                .expect("private category checked"),
            message: take_raw_string(&mut error, "message"),
            retryable: error.remove("retryable").map(|value| match value {
                Value::Bool(value) => value,
                _ => unreachable!("private retryable checked"),
            }),
            diagnostic_id: take_optional_raw_string(&mut error, "diagnosticId"),
        }
    });
    let envelope = Envelope {
        version: take_raw_unsigned_integer(&mut object, "version", u8::MAX as u64)
            .expect("private version checked") as u8,
        kind,
        id: take_raw_string(&mut object, "id"),
        correlation_id: take_optional_raw_string(&mut object, "correlationId"),
        decision_id: take_optional_raw_string(&mut object, "decisionId"),
        sequence: take_raw_unsigned_integer(&mut object, "sequence", MAX_SEQUENCE)
            .expect("private sequence checked"),
        payload: match object.remove("payload").expect("private payload checked") {
            Value::Object(payload) => payload,
            _ => unreachable!("private payload checked"),
        },
        error,
    };
    Ok(DecodedPrivateEnvelope(envelope))
}

fn validate_private_raw_schema(value: &Value) -> Result<(), ProtocolError> {
    let object = value
        .as_object()
        .ok_or(ProtocolError("envelope must be an object"))?;
    const ALLOWED: [&str; 8] = [
        "version",
        "kind",
        "id",
        "correlationId",
        "decisionId",
        "sequence",
        "payload",
        "error",
    ];
    if object.keys().any(|key| !ALLOWED.contains(&key.as_str()))
        || !["version", "kind", "id", "sequence", "payload"]
            .iter()
            .all(|key| object.contains_key(*key))
        || raw_unsigned_integer(object.get("version"), u8::MAX as u64).is_none()
        || !matches!(
            object.get("kind").and_then(Value::as_str),
            Some("host-request" | "host-response")
        )
        || !object.get("id").is_some_and(Value::is_string)
        || raw_unsigned_integer(object.get("sequence"), MAX_SEQUENCE).is_none()
        || !object.get("payload").is_some_and(Value::is_object)
    {
        return Err(ProtocolError("schema mismatch"));
    }
    for optional in ["correlationId", "decisionId"] {
        if object.get(optional).is_some_and(|value| !value.is_string()) {
            return Err(ProtocolError("schema mismatch"));
        }
    }
    if let Some(error) = object.get("error") {
        let error = error.as_object().ok_or(ProtocolError("schema mismatch"))?;
        if error.keys().any(|key| {
            !["category", "message", "retryable", "diagnosticId"].contains(&key.as_str())
        }) || !error.get("category").is_some_and(Value::is_string)
            || !error.get("message").is_some_and(Value::is_string)
            || parse_error_category(
                error
                    .get("category")
                    .and_then(Value::as_str)
                    .expect("checked category string"),
            )
            .is_none()
            || error
                .get("retryable")
                .is_some_and(|value| !value.is_boolean())
            || error
                .get("diagnosticId")
                .is_some_and(|value| !value.is_string())
        {
            return Err(ProtocolError("schema mismatch"));
        }
    }
    Ok(())
}

fn raw_unsigned_integer(value: Option<&Value>, maximum: u64) -> Option<u64> {
    let number = value?.as_number()?;
    if let Some(value) = number.as_u64() {
        return (value <= maximum).then_some(value);
    }
    if let Some(value) = number.as_i64() {
        return (value >= 0 && value as u64 <= maximum).then_some(value as u64);
    }
    number.as_f64().and_then(|value| {
        (value.is_finite() && value >= 0.0 && value.fract() == 0.0 && value <= maximum as f64)
            .then_some(value as u64)
    })
}

fn take_raw_unsigned_integer(
    object: &mut Map<String, Value>,
    key: &str,
    maximum: u64,
) -> Option<u64> {
    let value = object.remove(key)?;
    raw_unsigned_integer(Some(&value), maximum)
}

fn take_raw_string(object: &mut Map<String, Value>, key: &str) -> String {
    match object.remove(key).expect("private string checked") {
        Value::String(value) => value,
        _ => unreachable!("private string checked"),
    }
}

fn take_optional_raw_string(object: &mut Map<String, Value>, key: &str) -> Option<String> {
    object.remove(key).map(|value| match value {
        Value::String(value) => value,
        _ => unreachable!("private optional string checked"),
    })
}

fn parse_error_category(category: &str) -> Option<ErrorCategory> {
    Some(match category {
        "invalid-request" => ErrorCategory::InvalidRequest,
        "unsupported-version" => ErrorCategory::UnsupportedVersion,
        "unavailable" => ErrorCategory::Unavailable,
        "cancelled" => ErrorCategory::Cancelled,
        "timeout" => ErrorCategory::Timeout,
        "permission-denied" => ErrorCategory::PermissionDenied,
        "conflict" => ErrorCategory::Conflict,
        "internal" => ErrorCategory::Internal,
        _ => return None,
    })
}

fn empty_envelope() -> Envelope {
    Envelope {
        version: 0,
        kind: ProtocolKind::HostRequest,
        id: String::new(),
        correlation_id: None,
        decision_id: None,
        sequence: 0,
        payload: Map::new(),
        error: None,
    }
}

fn zeroise_envelope_strings(envelope: &mut Envelope) {
    zeroise_private_string(&mut envelope.id);
    if let Some(value) = envelope.correlation_id.as_mut() {
        zeroise_private_string(value);
    }
    envelope.correlation_id = None;
    if let Some(value) = envelope.decision_id.as_mut() {
        zeroise_private_string(value);
    }
    envelope.decision_id = None;
    let payload = std::mem::take(&mut envelope.payload);
    zeroise_json_map(payload);
    if let Some(error) = envelope.error.as_mut() {
        zeroise_private_string(&mut error.message);
        if let Some(value) = error.diagnostic_id.as_mut() {
            zeroise_private_string(value);
        }
        error.diagnostic_id = None;
    }
    envelope.error = None;
}

fn zeroise_json_map(map: Map<String, Value>) {
    for (mut key, mut value) in map {
        zeroise_private_string(&mut key);
        zeroise_json_value(&mut value);
    }
}

fn zeroise_json_value(value: &mut Value) {
    match value {
        Value::String(text) => zeroise_private_string(text),
        Value::Array(values) => {
            for value in &mut *values {
                zeroise_json_value(value);
            }
            values.clear();
        }
        Value::Object(map) => zeroise_json_map(std::mem::take(map)),
        _ => {}
    }
    *value = Value::Null;
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

pub fn validate_envelope(envelope: &Envelope) -> Result<(), ProtocolError> {
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
        match envelope.kind {
            ProtocolKind::Ack => {}
            ProtocolKind::HostResponse
                if id.strip_prefix("decision-").is_some_and(|suffix| {
                    suffix.len() == 32
                        && suffix
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                }) => {}
            _ => return Err(ProtocolError("decision ID not permitted")),
        }
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
    let payload_bytes = Zeroizing::new(
        serde_json::to_vec(&envelope.payload)
            .map_err(|_| ProtocolError("payload encoding failed"))?,
    )
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

#[cfg(test)]
mod tests {
    use super::{Envelope, ProtocolKind};
    use serde_json::{Map, Value};
    use uuid::Uuid;

    #[test]
    fn absent_optional_fields_are_omitted_from_the_wire_shape() {
        let mut payload = Map::new();
        payload.insert("method".into(), Value::String("status".into()));
        let envelope = Envelope {
            version: 1,
            kind: ProtocolKind::Request,
            id: "rust-status-1".into(),
            correlation_id: None,
            decision_id: None,
            sequence: 1,
            payload,
            error: None,
        };
        let value = serde_json::to_value(envelope).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "version": 1,
                "kind": "request",
                "id": "rust-status-1",
                "sequence": 1,
                "payload": {"method": "status"}
            })
        );
    }

    #[test]
    fn private_decode_failures_recursively_zeroise_parsed_raw_and_decoded_strings() {
        let canary = format!("private-decode-{}", Uuid::new_v4().simple());
        let cases = [
            format!(
                "{{\"version\":1,\"kind\":\"host-request\",\"id\":\"private-raw-schema\",\"sequence\":1,\"payload\":{{\"method\":\"credential.set\",\"credential\":{{\"key\":\"{canary}\"}}}},\"unknown\":true}}\n"
            ),
            format!(
                "{{\"version\":1,\"kind\":\"host-request\",\"id\":\"private-type-schema\",\"sequence\":1.5,\"payload\":{{\"method\":\"credential.set\",\"credential\":{{\"key\":\"{canary}\"}}}}}}\n"
            ),
            format!(
                "{{\"version\":2,\"kind\":\"host-request\",\"id\":\"private-envelope-validation\",\"sequence\":1,\"payload\":{{\"method\":\"credential.set\",\"credential\":{{\"key\":\"{canary}\"}}}}}}\n"
            ),
        ];
        for line in cases {
            let before = super::private_decode_zeroised_bytes();
            assert!(
                super::ProtocolDecoder::default()
                    .decode(line.as_bytes())
                    .is_err()
            );
            assert!(super::private_decode_zeroised_bytes() >= before + canary.len());
        }
    }

    #[test]
    fn duplicate_window_is_bounded_without_exhausting_long_lived_streams() {
        let mut decoder = super::ProtocolDecoder::default();
        for sequence in 1..=4_100_u64 {
            let line = format!(
                "{{\"version\":1,\"kind\":\"event\",\"id\":\"event-{sequence}\",\"sequence\":{sequence},\"payload\":{{\"eventType\":\"sidecar.status\"}}}}\n"
            );
            decoder.decode(line.as_bytes()).unwrap();
        }
        let recent = b"{\"version\":1,\"kind\":\"event\",\"id\":\"event-4100\",\"sequence\":4101,\"payload\":{\"eventType\":\"sidecar.status\"}}\n";
        assert_eq!(
            decoder.decode(recent).unwrap_err().to_string(),
            "duplicate envelope ID"
        );
    }

    #[test]
    fn approval_matrix_event_is_visible_only_in_the_a25_twin() {
        let line = b"{\"version\":1,\"kind\":\"event\",\"id\":\"sidecar-a25-result\",\"sequence\":1,\"payload\":{\"schemaVersion\":1,\"eventType\":\"approval-matrix.complete\",\"generation\":1,\"turns\":8,\"delegateCalls\":6,\"fiveArgumentViolations\":0}}\n";
        let decoded = super::ProtocolDecoder::default().decode(line).unwrap();
        if cfg!(feature = "a25-approval-test") {
            assert_eq!(
                decoded.payload.get("eventType"),
                Some(&Value::String("approval-matrix.complete".into()))
            );
            assert_eq!(decoded.payload.get("delegateCalls"), Some(&Value::from(6)));
        } else {
            assert_eq!(
                decoded.payload.get("eventType"),
                Some(&Value::String("unknown-event".into()))
            );
            assert_eq!(decoded.payload.get("redacted"), Some(&Value::Bool(true)));
        }
    }
}
