use serde_json::{Map, Value};

const MAX_JS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub(crate) fn validate_approval_request(payload: &Map<String, Value>) -> Result<(), String> {
    let mut expected = vec![
        "method",
        "schemaVersion",
        "generation",
        "sessionId",
        "workspaceId",
        "workspaceRevision",
        "invocationId",
        "toolName",
        "input",
    ];
    if payload.contains_key("groupId") {
        expected.push("groupId");
    }
    if payload.len() != expected.len()
        || !expected.iter().all(|key| payload.contains_key(*key))
        || payload.get("method") != Some(&Value::String("approval.request".into()))
        || payload.get("schemaVersion") != Some(&Value::from(1))
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
            .is_none_or(|value| {
                value.is_empty() || value.len() > 96 || value.chars().any(char::is_control)
            })
        || !payload.contains_key("input")
    {
        return Err("approval request rejected".into());
    }
    Ok(())
}

pub(crate) fn validate_approval_response(
    decision_id: &str,
    payload: &Map<String, Value>,
) -> Result<(), String> {
    if !prefixed(decision_id, "decision-")
        || payload.len() != 6
        || ![
            "schemaVersion",
            "approvalId",
            "invocationId",
            "inputDigest",
            "decision",
            "scopeIds",
        ]
        .iter()
        .all(|key| payload.contains_key(*key))
        || payload.get("schemaVersion") != Some(&Value::from(1))
        || !valid_id(payload, "approvalId", "approval-")
        || !valid_id(payload, "invocationId", "invocation-")
        || payload
            .get("inputDigest")
            .and_then(Value::as_str)
            .is_none_or(|value| {
                value.len() != 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_approval_contract_has_matching_rust_request_verdicts() {
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
    }
}
