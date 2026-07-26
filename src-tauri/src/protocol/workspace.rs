use serde_json::{Map, Value};
use std::path::Path;

const MAX_JS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_PATH_BYTES: usize = 4_096;

pub(crate) fn validate_workspace_request(
    method: &str,
    payload: &Map<String, Value>,
) -> Result<(), String> {
    let common = payload.get("schemaVersion") == Some(&Value::from(1))
        && payload
            .get("workspaceId")
            .and_then(Value::as_str)
            .is_some_and(|value| valid_prefixed_hex(value, "workspace-"))
        && integer(payload, "generation").is_some()
        && integer(payload, "revision").is_some();
    if !common {
        return Err("workspace request rejected".into());
    }
    match method {
        "workspace.sync" => {
            let state = payload.get("trustState").and_then(Value::as_str);
            let keys: &[&str] = if state == Some("trusted") {
                &[
                    "schemaVersion",
                    "workspaceId",
                    "generation",
                    "revision",
                    "trustState",
                    "leaseId",
                ]
            } else {
                &[
                    "schemaVersion",
                    "workspaceId",
                    "generation",
                    "revision",
                    "trustState",
                ]
            };
            if !exact_keys(payload, keys)
                || !matches!(state, Some("untrusted" | "trusted" | "revoked"))
                || (state == Some("trusted") && !valid_lease(payload))
            {
                return Err("workspace request rejected".into());
            }
        }
        "workspace.openUntrusted" => {
            if !exact_keys(
                payload,
                &["schemaVersion", "workspaceId", "generation", "revision"],
            ) {
                return Err("workspace request rejected".into());
            }
        }
        "workspace.authorise" | "workspace.revoke" => {
            if !exact_keys(
                payload,
                &[
                    "schemaVersion",
                    "workspaceId",
                    "generation",
                    "expectedRevision",
                    "revision",
                    "leaseId",
                ],
            ) || !valid_lease(payload)
            {
                return Err("workspace request rejected".into());
            }
            let expected = integer(payload, "expectedRevision")
                .ok_or_else(|| "workspace request rejected".to_string())?;
            if integer(payload, "revision") != expected.checked_add(1) {
                return Err("workspace request rejected".into());
            }
        }
        "workspace.loadTrusted" => {
            if !exact_keys(
                payload,
                &[
                    "schemaVersion",
                    "workspaceId",
                    "generation",
                    "revision",
                    "leaseId",
                    "snapshotRoot",
                    "agentRoot",
                ],
            ) || !valid_lease(payload)
                || !valid_path(payload.get("snapshotRoot"))
                || !valid_path(payload.get("agentRoot"))
            {
                return Err("workspace request rejected".into());
            }
        }
        _ => return Err("workspace request rejected".into()),
    }
    Ok(())
}

fn integer(payload: &Map<String, Value>, key: &str) -> Option<u64> {
    payload
        .get(key)
        .and_then(Value::as_u64)
        .filter(|value| *value <= MAX_JS_SAFE_INTEGER)
}

fn exact_keys(payload: &Map<String, Value>, keys: &[&str]) -> bool {
    payload.len() == keys.len() && keys.iter().all(|key| payload.contains_key(*key))
}

fn valid_lease(payload: &Map<String, Value>) -> bool {
    payload
        .get("leaseId")
        .and_then(Value::as_str)
        .is_some_and(|value| valid_prefixed_hex(value, "trust-"))
}

fn valid_prefixed_hex(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn valid_path(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|value| {
        Path::new(value).is_absolute()
            && !value.is_empty()
            && value.len() <= MAX_PATH_BYTES
            && !value.chars().any(char::is_control)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_workspace_contract_has_matching_rust_request_verdicts() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../packages/protocol/fixtures/workspace-contract.json"
        ))
        .unwrap();
        for (field, expected) in [("validRequests", true), ("invalidRequests", false)] {
            for request in fixture[field].as_array().unwrap() {
                let mut payload = request.as_object().unwrap().clone();
                let method = payload
                    .remove("method")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string();
                assert_eq!(
                    validate_workspace_request(&method, &payload).is_ok(),
                    expected,
                    "cross-language verdict differed for {method}"
                );
            }
        }
    }
}
