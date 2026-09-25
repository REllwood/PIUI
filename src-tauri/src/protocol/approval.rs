use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const MAX_JS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
// Shared with the sidecar's canonicaliser and approval.schema.json. Real
// `write` and `edit` calls carry whole files, so the bound is sized for them
// while still fitting a complete approval request inside one envelope payload.
pub(crate) const MAX_APPROVAL_INPUT_BYTES: usize = 393_216;
pub(crate) const MAX_APPROVAL_INPUT_DEPTH: usize = 16;
pub(crate) const MAX_APPROVAL_INPUT_NODES: usize = 4_096;

pub(crate) fn validate_approval_request(payload: &Map<String, Value>) -> Result<(), String> {
    let legacy = payload.get("schemaVersion") == Some(&Value::from(1));
    let mut expected = if legacy {
        vec![
            "method",
            "schemaVersion",
            "generation",
            "sessionId",
            "workspaceId",
            "workspaceRevision",
            "invocationId",
            "toolName",
            "inputDigest",
            "input",
        ]
    } else {
        vec![
            "method",
            "schemaVersion",
            "generation",
            "sessionId",
            "workspaceId",
            "workspaceRevision",
            "invocationId",
            "toolCallId",
            "toolName",
            "inputDigest",
            "input",
            "cohort",
        ]
    };
    if legacy && payload.contains_key("groupId") {
        expected.push("groupId");
    }
    if payload.len() != expected.len()
        || !expected.iter().all(|key| payload.contains_key(*key))
        || payload.get("method") != Some(&Value::String("approval.request".into()))
        || !matches!(payload.get("schemaVersion"), Some(value) if value == &Value::from(1) || value == &Value::from(2))
        || integer(payload, "generation").is_none_or(|value| value == 0)
        || integer(payload, "workspaceRevision").is_none()
        || !valid_id(payload, "sessionId", "session-")
        || !valid_id(payload, "workspaceId", "workspace-")
        || !valid_id(payload, "invocationId", "invocation-")
        || payload
            .get("groupId")
            .is_some_and(|_| !valid_id(payload, "groupId", "group-"))
        || payload
            .get("toolName")
            .and_then(Value::as_str)
            .is_none_or(|value| !valid_approval_tool_name(value))
        || payload.get("input").is_none_or(|value| !value.is_object())
    {
        return Err("approval request rejected".into());
    }
    if !legacy {
        validate_cohort_request(payload)?;
    }
    let canonical = canonical_json_bytes(&payload["input"])?;
    let digest = format!("{:x}", Sha256::digest(&canonical));
    if payload.get("inputDigest").and_then(Value::as_str) != Some(digest.as_str()) {
        return Err("approval request rejected".into());
    }
    Ok(())
}

fn validate_cohort_request(payload: &Map<String, Value>) -> Result<(), String> {
    let tool_call_id = payload
        .get("toolCallId")
        .and_then(Value::as_str)
        .ok_or_else(|| "approval request rejected".to_string())?;
    if !valid_wire_coordinate(tool_call_id) {
        return Err("approval request rejected".into());
    }
    let cohort = payload
        .get("cohort")
        .and_then(Value::as_object)
        .ok_or_else(|| "approval request rejected".to_string())?;
    if cohort.len() != 3
        || !["assistantEntryId", "cohortDigest", "orderedMembers"]
            .iter()
            .all(|key| cohort.contains_key(*key))
        || cohort
            .get("assistantEntryId")
            .and_then(Value::as_str)
            .is_none_or(|value| !valid_wire_coordinate(value))
        || cohort
            .get("cohortDigest")
            .and_then(Value::as_str)
            .is_none_or(|value| !valid_digest(value))
    {
        return Err("approval request rejected".into());
    }
    let members = cohort
        .get("orderedMembers")
        .and_then(Value::as_array)
        .filter(|members| !members.is_empty() && members.len() <= 32)
        .ok_or_else(|| "approval request rejected".to_string())?;
    let mut seen = std::collections::HashSet::new();
    let mut matches = 0;
    for (index, member) in members.iter().enumerate() {
        let member = member
            .as_object()
            .ok_or_else(|| "approval request rejected".to_string())?;
        if member.len() != 3
            || !["ordinal", "toolCallId", "toolName"]
                .iter()
                .all(|key| member.contains_key(*key))
            || member.get("ordinal").and_then(Value::as_u64) != Some(index as u64)
            || member
                .get("toolCallId")
                .and_then(Value::as_str)
                .is_none_or(|value| !valid_wire_coordinate(value) || !seen.insert(value))
            || member
                .get("toolName")
                .and_then(Value::as_str)
                .is_none_or(|value| !valid_approval_tool_name(value))
        {
            return Err("approval request rejected".into());
        }
        if member.get("toolCallId").and_then(Value::as_str) == Some(tool_call_id)
            && member.get("toolName").and_then(Value::as_str)
                == payload.get("toolName").and_then(Value::as_str)
        {
            matches += 1;
        }
    }
    let descriptor = serde_json::json!({"assistantEntryId": cohort["assistantEntryId"], "orderedMembers": members});
    let digest = format!("{:x}", Sha256::digest(canonical_json_bytes(&descriptor)?));
    if matches != 1 || cohort.get("cohortDigest").and_then(Value::as_str) != Some(digest.as_str()) {
        return Err("approval request rejected".into());
    }
    Ok(())
}

pub(crate) fn validate_approval_ready(payload: &Map<String, Value>) -> Result<(), String> {
    if payload.len() != 7
        || ![
            "method",
            "schemaVersion",
            "generation",
            "invocationId",
            "toolCallId",
            "inputDigest",
            "cohortDigest",
        ]
        .iter()
        .all(|key| payload.contains_key(*key))
        || payload.get("method") != Some(&Value::String("approval.ready".into()))
        || payload.get("schemaVersion") != Some(&Value::from(2))
        || integer(payload, "generation").is_none_or(|value| value == 0)
        || !valid_id(payload, "invocationId", "invocation-")
        || payload
            .get("toolCallId")
            .and_then(Value::as_str)
            .is_none_or(|value| !valid_wire_coordinate(value))
        || payload
            .get("inputDigest")
            .and_then(Value::as_str)
            .is_none_or(|value| !valid_digest(value))
        || payload
            .get("cohortDigest")
            .and_then(Value::as_str)
            .is_none_or(|value| !valid_digest(value))
    {
        Err("approval ready rejected".into())
    } else {
        Ok(())
    }
}

pub(crate) fn validate_approval_abandon(payload: &Map<String, Value>) -> Result<(), String> {
    if payload.len() != 9
        || ![
            "method",
            "schemaVersion",
            "generation",
            "sessionId",
            "workspaceId",
            "workspaceRevision",
            "assistantEntryId",
            "cohortDigest",
            "reason",
        ]
        .iter()
        .all(|key| payload.contains_key(*key))
        || payload.get("method") != Some(&Value::String("approval.abandon".into()))
        || payload.get("schemaVersion") != Some(&Value::from(2))
        || integer(payload, "generation").is_none_or(|value| value == 0)
        || !valid_id(payload, "sessionId", "session-")
        || !valid_id(payload, "workspaceId", "workspace-")
        || integer(payload, "workspaceRevision").is_none()
        || payload
            .get("assistantEntryId")
            .and_then(Value::as_str)
            .is_none_or(|value| !valid_wire_coordinate(value))
        || payload
            .get("cohortDigest")
            .and_then(Value::as_str)
            .is_none_or(|value| !valid_digest(value))
        || payload
            .get("reason")
            .and_then(Value::as_str)
            .is_none_or(|value| {
                !matches!(
                    value,
                    "pi-abort"
                        | "definition-change"
                        | "digest-change"
                        | "extension-error"
                        | "session-shutdown"
                )
            })
    {
        Err("approval abandon rejected".into())
    } else {
        Ok(())
    }
}

pub(crate) fn validate_approval_response(
    decision_id: &str,
    payload: &Map<String, Value>,
) -> Result<(), String> {
    if !prefixed(decision_id, "decision-") {
        return Err("approval response rejected".into());
    }
    let legacy = payload.get("schemaVersion") == Some(&Value::from(1));
    let expected = if legacy {
        &[
            "schemaVersion",
            "approvalId",
            "invocationId",
            "inputDigest",
            "decision",
            "scopeIds",
        ][..]
    } else {
        &[
            "schemaVersion",
            "method",
            "approvalId",
            "transactionId",
            "invocationId",
            "toolCallId",
            "inputDigest",
            "cohortDigest",
            "decision",
            "scopeIds",
        ][..]
    };
    if payload.len() != expected.len()
        || !expected.iter().all(|key| payload.contains_key(*key))
        || (!legacy
            && (payload.get("schemaVersion") != Some(&Value::from(2))
                || payload.get("method") != Some(&Value::String("approval.resolve".into()))
                || !valid_id(payload, "transactionId", "transaction-")
                || payload
                    .get("toolCallId")
                    .and_then(Value::as_str)
                    .is_none_or(|value| !valid_wire_coordinate(value))
                || payload
                    .get("cohortDigest")
                    .and_then(Value::as_str)
                    .is_none_or(|value| !valid_digest(value))))
        || !valid_id(payload, "approvalId", "approval-")
        || !valid_id(payload, "invocationId", "invocation-")
        || payload
            .get("inputDigest")
            .and_then(Value::as_str)
            .is_none_or(|value| !valid_digest(value))
    {
        return Err("approval response rejected".into());
    }
    let decision = payload
        .get("decision")
        .and_then(Value::as_str)
        .ok_or_else(|| "approval response rejected".to_string())?;
    let scopes = payload
        .get("scopeIds")
        .and_then(Value::as_array)
        .ok_or_else(|| "approval response rejected".to_string())?;
    if !matches!(decision, "approved" | "denied" | "expired" | "cancelled")
        || scopes.len() > 1
        || !scopes.iter().all(|value| {
            value
                .as_str()
                .is_some_and(|value| prefixed(value, "scope-"))
        })
        || (decision == "approved") != (scopes.len() == 1)
    {
        return Err("approval response rejected".into());
    }
    Ok(())
}

pub(crate) fn validate_group_response(
    decision_id: &str,
    payload: &Map<String, Value>,
) -> Result<(), String> {
    if !prefixed(decision_id, "decision-")
        || payload.len() != 12
        || ![
            "schemaVersion",
            "method",
            "generation",
            "sessionId",
            "workspaceId",
            "workspaceRevision",
            "assistantEntryId",
            "groupId",
            "transactionId",
            "cohortDigest",
            "decision",
            "members",
        ]
        .iter()
        .all(|key| payload.contains_key(*key))
        || payload.get("schemaVersion") != Some(&Value::from(2))
        || payload.get("method") != Some(&Value::String("approval.group-commit".into()))
        || integer(payload, "generation").is_none_or(|value| value == 0)
        || !valid_id(payload, "sessionId", "session-")
        || !valid_id(payload, "workspaceId", "workspace-")
        || integer(payload, "workspaceRevision").is_none()
        || payload
            .get("assistantEntryId")
            .and_then(Value::as_str)
            .is_none_or(|value| !valid_wire_coordinate(value))
        || !valid_id(payload, "groupId", "group-")
        || !valid_id(payload, "transactionId", "transaction-")
        || payload
            .get("cohortDigest")
            .and_then(Value::as_str)
            .is_none_or(|value| !valid_digest(value))
        || payload.get("decision") != Some(&Value::String("approved".into()))
    {
        return Err("approval group response rejected".into());
    }
    let members = payload
        .get("members")
        .and_then(Value::as_array)
        .filter(|members| members.len() >= 2 && members.len() <= 32)
        .ok_or_else(|| "approval group response rejected".to_string())?;
    let mut correlations = std::collections::HashSet::new();
    let mut approvals = std::collections::HashSet::new();
    let mut decisions = std::collections::HashSet::new();
    let mut scopes = std::collections::HashSet::new();
    for member in members {
        let member = member
            .as_object()
            .ok_or_else(|| "approval group response rejected".to_string())?;
        if member.len() != 7
            || ![
                "correlationId",
                "approvalId",
                "decisionId",
                "invocationId",
                "toolCallId",
                "inputDigest",
                "scopeId",
            ]
            .iter()
            .all(|key| member.contains_key(*key))
            || member
                .get("correlationId")
                .and_then(Value::as_str)
                .is_none_or(|value| !valid_wire_coordinate(value) || !correlations.insert(value))
            || member
                .get("approvalId")
                .and_then(Value::as_str)
                .is_none_or(|value| !prefixed(value, "approval-") || !approvals.insert(value))
            || member
                .get("decisionId")
                .and_then(Value::as_str)
                .is_none_or(|value| !prefixed(value, "decision-") || !decisions.insert(value))
            || member
                .get("invocationId")
                .and_then(Value::as_str)
                .is_none_or(|value| !prefixed(value, "invocation-"))
            || member
                .get("toolCallId")
                .and_then(Value::as_str)
                .is_none_or(|value| !valid_wire_coordinate(value))
            || member
                .get("inputDigest")
                .and_then(Value::as_str)
                .is_none_or(|value| !valid_digest(value))
            || member
                .get("scopeId")
                .and_then(Value::as_str)
                .is_none_or(|value| !prefixed(value, "scope-") || !scopes.insert(value))
        {
            return Err("approval group response rejected".into());
        }
    }
    Ok(())
}

pub(crate) fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    fn append(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
        if output.len().saturating_add(bytes.len()) > MAX_APPROVAL_INPUT_BYTES {
            return Err("approval input rejected".into());
        }
        output.extend_from_slice(bytes);
        Ok(())
    }

    fn quoted(value: &str, output: &mut Vec<u8>) -> Result<(), String> {
        append(output, b"\"")?;
        for character in value.chars() {
            match character {
                '"' => append(output, b"\\\"")?,
                '\\' => append(output, b"\\\\")?,
                '\u{0008}' => append(output, b"\\b")?,
                '\u{000c}' => append(output, b"\\f")?,
                '\n' => append(output, b"\\n")?,
                '\r' => append(output, b"\\r")?,
                '\t' => append(output, b"\\t")?,
                character if (character as u32) <= 0x1f => {
                    let escape = format!("\\u{:04x}", character as u32);
                    append(output, escape.as_bytes())?;
                }
                character => {
                    let mut encoded = [0u8; 4];
                    append(output, character.encode_utf8(&mut encoded).as_bytes())?;
                }
            }
        }
        append(output, b"\"")
    }

    fn emit(
        value: &Value,
        depth: usize,
        nodes: &mut usize,
        output: &mut Vec<u8>,
    ) -> Result<(), String> {
        if depth > MAX_APPROVAL_INPUT_DEPTH || *nodes >= MAX_APPROVAL_INPUT_NODES {
            return Err("approval input rejected".into());
        }
        *nodes += 1;
        match value {
            Value::Null => append(output, b"null"),
            Value::Bool(true) => append(output, b"true"),
            Value::Bool(false) => append(output, b"false"),
            Value::String(value) => quoted(value, output),
            Value::Number(number) => {
                let encoded = if let Some(value) = number.as_i64() {
                    if value.unsigned_abs() > MAX_JS_SAFE_INTEGER {
                        return Err("approval input rejected".into());
                    }
                    value.to_string()
                } else if let Some(value) = number.as_u64() {
                    if value > MAX_JS_SAFE_INTEGER {
                        return Err("approval input rejected".into());
                    }
                    value.to_string()
                } else {
                    return Err("approval input rejected".into());
                };
                append(output, encoded.as_bytes())
            }
            Value::Array(values) => {
                append(output, b"[")?;
                for (index, entry) in values.iter().enumerate() {
                    if index > 0 {
                        append(output, b",")?;
                    }
                    emit(entry, depth + 1, nodes, output)?;
                }
                append(output, b"]")
            }
            Value::Object(values) => {
                let mut keys: Vec<&str> = values.keys().map(String::as_str).collect();
                keys.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
                append(output, b"{")?;
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        append(output, b",")?;
                    }
                    quoted(key, output)?;
                    append(output, b":")?;
                    emit(&values[key], depth + 1, nodes, output)?;
                }
                append(output, b"}")
            }
        }
    }

    let mut nodes = 0usize;
    let mut output = Vec::new();
    emit(value, 0, &mut nodes, &mut output)?;
    Ok(output)
}

pub(crate) fn valid_approval_tool_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=96).contains(&bytes.len())
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn integer(payload: &Map<String, Value>, key: &str) -> Option<u64> {
    payload
        .get(key)
        .and_then(Value::as_u64)
        .filter(|value| *value <= MAX_JS_SAFE_INTEGER)
}
fn valid_id(payload: &Map<String, Value>, key: &str, prefix: &str) -> bool {
    payload
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| prefixed(value, prefix))
}
fn prefixed(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn valid_wire_coordinate(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_approval_contract_has_matching_rust_verdicts_and_canonical_bytes() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../packages/protocol/fixtures/approval-contract.json"
        ))
        .unwrap();
        for (field, expected) in [("validRequests", true), ("invalidRequests", false)] {
            for request in fixture[field].as_array().unwrap() {
                assert_eq!(
                    validate_approval_request(request.as_object().unwrap()).is_ok(),
                    expected,
                    "cross-language verdict differed: {request}"
                );
            }
        }
        let base_request = fixture["validRequests"][1].as_object().unwrap();
        for (field, expected) in [("valid", true), ("invalid", false)] {
            for tool_name in fixture["toolNameCases"][field].as_array().unwrap() {
                let tool_name = tool_name.as_str().unwrap();
                assert_eq!(
                    valid_approval_tool_name(tool_name),
                    expected,
                    "tool name verdict differed: {tool_name:?}"
                );
                let mut request = base_request.clone();
                request.insert("toolName".into(), Value::String(tool_name.into()));
                assert_eq!(
                    validate_approval_request(&request).is_ok(),
                    expected,
                    "request tool name verdict differed: {tool_name:?}"
                );
            }
        }
        for (field, expected) in [("validResponses", true), ("invalidResponses", false)] {
            for response in fixture[field].as_array().unwrap() {
                let object = response.as_object().unwrap();
                assert_eq!(
                    validate_approval_response(
                        object["decisionId"].as_str().unwrap(),
                        object["payload"].as_object().unwrap()
                    )
                    .is_ok(),
                    expected,
                    "cross-language response verdict differed: {response}"
                );
            }
        }
        for case in fixture["canonicalCases"].as_array().unwrap() {
            let parsed: Value = serde_json::from_str(case["jsonText"].as_str().unwrap()).unwrap();
            let bytes = canonical_json_bytes(&parsed).unwrap();
            assert_eq!(std::str::from_utf8(&bytes).unwrap(), case["canonical"]);
            assert_eq!(format!("{:x}", Sha256::digest(&bytes)), case["sha256"]);
        }
        for case in fixture["canonicalRejections"].as_array().unwrap() {
            let parsed = serde_json::from_str::<Value>(case["jsonText"].as_str().unwrap());
            assert!(
                parsed.is_err() || canonical_json_bytes(&parsed.unwrap()).is_err(),
                "accepted {}",
                case["name"]
            );
        }
    }

    #[test]
    fn canonical_bounds_are_exact() {
        let mut depth = Value::from(0);
        for _ in 0..15 {
            depth = Value::Array(vec![depth]);
        }
        let depth = serde_json::json!({"v": depth});
        assert!(canonical_json_bytes(&depth).is_ok());
        let mut too_deep = depth["v"].clone();
        too_deep = Value::Array(vec![too_deep]);
        assert!(canonical_json_bytes(&serde_json::json!({"v": too_deep})).is_err());

        // The object and array count as two of the 4,096 nodes.
        assert!(canonical_json_bytes(&serde_json::json!({"v": vec![0; 4_094]})).is_ok());
        assert!(canonical_json_bytes(&serde_json::json!({"v": vec![0; 4_095]})).is_err());
        // `{"v":"` and `"}` frame the string with eight bytes.
        assert_eq!(
            canonical_json_bytes(&serde_json::json!({"v": "x".repeat(393_208)}))
                .unwrap()
                .len(),
            393_216
        );
        assert!(canonical_json_bytes(&serde_json::json!({"v": "x".repeat(393_209)})).is_err());
        // Multi-byte characters count as UTF-8 bytes, not characters.
        assert!(canonical_json_bytes(&serde_json::json!({"v": "é".repeat(196_604)})).is_ok());
        assert!(canonical_json_bytes(&serde_json::json!({"v": "é".repeat(196_605)})).is_err());
    }

    fn maximal_approval_request() -> Map<String, Value> {
        // A whole-file write at the canonical byte bound, with the largest
        // cohort the protocol admits.
        let input = serde_json::json!({
            "content": "x".repeat(393_216 - r#"{"content":"","path":"src/generated.rs"}"#.len()),
            "path": "src/generated.rs"
        });
        let canonical = canonical_json_bytes(&input).unwrap();
        assert_eq!(canonical.len(), MAX_APPROVAL_INPUT_BYTES);
        let members = (0..32)
            .map(|ordinal| {
                serde_json::json!({
                    "ordinal": ordinal,
                    "toolCallId": format!("tool-call-{ordinal:0>100}"),
                    "toolName": if ordinal == 0 { "write" } else { "read" }
                })
            })
            .collect::<Vec<_>>();
        let assistant_entry_id = "a".repeat(128);
        let descriptor = serde_json::json!({
            "assistantEntryId": assistant_entry_id,
            "orderedMembers": members
        });
        let cohort_digest = format!(
            "{:x}",
            Sha256::digest(canonical_json_bytes(&descriptor).unwrap())
        );
        serde_json::json!({
            "method": "approval.request",
            "schemaVersion": 2,
            "generation": 9_007_199_254_740_991_u64,
            "sessionId": format!("session-{}", "a".repeat(32)),
            "workspaceId": format!("workspace-{}", "b".repeat(32)),
            "workspaceRevision": 9_007_199_254_740_991_u64,
            "invocationId": format!("invocation-{}", "c".repeat(32)),
            "toolCallId": format!("tool-call-{:0>100}", 0),
            "toolName": "write",
            "inputDigest": format!("{:x}", Sha256::digest(&canonical)),
            "input": input,
            "cohort": {
                "assistantEntryId": assistant_entry_id,
                "cohortDigest": cohort_digest,
                "orderedMembers": members
            }
        })
        .as_object()
        .unwrap()
        .clone()
    }

    #[test]
    fn a_maximal_approval_request_fits_the_envelope_and_payload_limits() {
        let payload = maximal_approval_request();
        validate_approval_request(&payload).unwrap();
        let line = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "kind": "host-request",
            "id": format!("sidecar-{}", "d".repeat(120)),
            "sequence": 9_007_199_254_740_991_u64,
            "payload": payload
        }))
        .unwrap();
        let mut line = line;
        line.push(b'\n');
        let decoded = crate::protocol::ProtocolDecoder::default()
            .decode(&line)
            .expect("a maximal approval request must pass envelope validation");
        crate::credentials::proxy::discard_private_envelope(decoded);

        let mut deeper = maximal_approval_request();
        let mut nested = Value::from(0);
        for _ in 0..16 {
            nested = Value::Array(vec![nested]);
        }
        deeper.insert("input".into(), serde_json::json!({"v": nested}));
        let digest = format!(
            "{:x}",
            Sha256::digest(canonical_json_bytes(&deeper["input"]).unwrap_or_default())
        );
        deeper.insert("inputDigest".into(), Value::String(digest));
        assert!(validate_approval_request(&deeper).is_err());
    }
}
