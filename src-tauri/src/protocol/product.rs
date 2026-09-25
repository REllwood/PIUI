use serde_json::{Map, Value};
use std::path::Path;

const MAX_JS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_TEXT_BYTES: usize = 262_144;

pub(crate) fn validate_product_request(
    method: &str,
    payload: &Map<String, Value>,
) -> Result<(), String> {
    let valid = match method {
        "product.providers.list" | "product.diagnostics" => payload.is_empty(),
        "product.provider.logout" => {
            exact_keys(payload, &["schemaVersion", "providerId"])
                && payload.get("schemaVersion") == Some(&Value::from(1))
                && bounded_optional_identifier(payload, "providerId", 128)
                && payload
                    .get("providerId")
                    .is_some_and(|value| !value.is_null())
        }
        "product.session.create" => {
            exact_keys(
                payload,
                &[
                    "schemaVersion",
                    "workspaceId",
                    "workspaceRevision",
                    "workspacePath",
                    "agentDir",
                    "title",
                    "providerId",
                    "modelId",
                ],
            ) && payload.get("schemaVersion") == Some(&Value::from(1))
                && valid_prefixed_hex(payload, "workspaceId", "workspace-")
                && integer(payload, "workspaceRevision").is_some()
                && valid_path(payload.get("workspacePath"))
                && valid_path(payload.get("agentDir"))
                && bounded_optional_text(payload, "title", 160)
                && bounded_optional_identifier(payload, "providerId", 128)
                && bounded_optional_identifier(payload, "modelId", 256)
        }
        "product.sessions.list" => {
            exact_keys(
                payload,
                &[
                    "schemaVersion",
                    "workspaceId",
                    "workspaceRevision",
                    "workspacePath",
                    "agentDir",
                ],
            ) && payload.get("schemaVersion") == Some(&Value::from(1))
                && valid_prefixed_hex(payload, "workspaceId", "workspace-")
                && integer(payload, "workspaceRevision").is_some()
                && valid_path(payload.get("workspacePath"))
                && valid_path(payload.get("agentDir"))
        }
        "product.session.resume"
        | "product.session.fork"
        | "product.session.inspect"
        | "product.session.compact"
        | "product.session.trash-target"
        | "product.session.trash-complete"
        | "product.changes.list"
        | "product.settings.list"
        | "product.resources.list" => {
            exact_keys(
                payload,
                &["schemaVersion", "sessionId", "expectedGeneration"],
            ) && payload.get("schemaVersion") == Some(&Value::from(1))
                && valid_prefixed_hex(payload, "sessionId", "session-")
                && integer(payload, "expectedGeneration").is_some_and(|value| value > 0)
        }
        "product.resource.set-enabled" => {
            exact_keys(
                payload,
                &[
                    "schemaVersion",
                    "sessionId",
                    "expectedGeneration",
                    "resourceId",
                    "enabled",
                    "acknowledgedExecutableRisk",
                ],
            ) && payload.get("schemaVersion") == Some(&Value::from(1))
                && valid_prefixed_hex(payload, "sessionId", "session-")
                && integer(payload, "expectedGeneration").is_some_and(|value| value > 0)
                && valid_prefixed_hex(payload, "resourceId", "resource-")
                && payload.get("enabled").and_then(Value::as_bool).is_some()
                && payload
                    .get("acknowledgedExecutableRisk")
                    .and_then(Value::as_bool)
                    .is_some()
        }
        // Mirrors `assertProductRequest` in sidecar/src/pi/product-router.ts:
        // the source is at most 256 UTF-16 units without control characters.
        "product.package.install" => {
            exact_keys(
                payload,
                &[
                    "schemaVersion",
                    "sessionId",
                    "expectedGeneration",
                    "source",
                    "scope",
                    "online",
                    "acknowledgedExecutableRisk",
                ],
            ) && payload.get("schemaVersion") == Some(&Value::from(1))
                && valid_prefixed_hex(payload, "sessionId", "session-")
                && integer(payload, "expectedGeneration").is_some_and(|value| value > 0)
                && payload
                    .get("source")
                    .and_then(Value::as_str)
                    .is_some_and(|source| {
                        source.encode_utf16().count() <= 256 && !source.chars().any(char::is_control)
                    })
                && matches!(
                    payload.get("scope").and_then(Value::as_str),
                    Some("global" | "project")
                )
                && payload.get("online").and_then(Value::as_bool).is_some()
                && payload
                    .get("acknowledgedExecutableRisk")
                    .and_then(Value::as_bool)
                    .is_some()
        }
        "product.package.mutate" => {
            exact_keys(
                payload,
                &[
                    "schemaVersion",
                    "sessionId",
                    "expectedGeneration",
                    "resourceId",
                    "operation",
                    "online",
                    "acknowledgedExecutableRisk",
                ],
            ) && payload.get("schemaVersion") == Some(&Value::from(1))
                && valid_prefixed_hex(payload, "sessionId", "session-")
                && integer(payload, "expectedGeneration").is_some_and(|value| value > 0)
                && valid_prefixed_hex(payload, "resourceId", "resource-")
                && matches!(
                    payload.get("operation").and_then(Value::as_str),
                    Some("update" | "remove")
                )
                && payload.get("online").and_then(Value::as_bool).is_some()
                && payload
                    .get("acknowledgedExecutableRisk")
                    .and_then(Value::as_bool)
                    .is_some()
        }
        "product.setting.save" => {
            exact_keys(
                payload,
                &[
                    "schemaVersion",
                    "sessionId",
                    "expectedGeneration",
                    "key",
                    "value",
                    "scope",
                    "expectedRevision",
                ],
            ) && payload.get("schemaVersion") == Some(&Value::from(1))
                && valid_prefixed_hex(payload, "sessionId", "session-")
                && integer(payload, "expectedGeneration").is_some_and(|value| value > 0)
                && valid_setting_key(payload.get("key"))
                && matches!(
                    payload.get("scope").and_then(Value::as_str),
                    Some("global" | "project")
                )
                && integer(payload, "expectedRevision").is_some()
                && payload
                    .get("value")
                    .and_then(|value| serde_json::to_vec(value).ok())
                    .is_some_and(|bytes| bytes.len() <= 16_384)
        }
        "product.setting.reset-preview" => {
            exact_keys(
                payload,
                &["schemaVersion", "sessionId", "expectedGeneration", "key"],
            ) && payload.get("schemaVersion") == Some(&Value::from(1))
                && valid_prefixed_hex(payload, "sessionId", "session-")
                && integer(payload, "expectedGeneration").is_some_and(|value| value > 0)
                && valid_setting_key(payload.get("key"))
        }
        "product.change.undo" | "product.change.target" => {
            exact_keys(
                payload,
                &[
                    "schemaVersion",
                    "sessionId",
                    "expectedGeneration",
                    "changeId",
                ],
            ) && payload.get("schemaVersion") == Some(&Value::from(1))
                && valid_prefixed_hex(payload, "sessionId", "session-")
                && integer(payload, "expectedGeneration").is_some_and(|value| value > 0)
                && valid_prefixed_hex(payload, "changeId", "change-")
        }
        "product.session.rename" => {
            exact_keys(
                payload,
                &["schemaVersion", "sessionId", "expectedGeneration", "title"],
            ) && payload.get("schemaVersion") == Some(&Value::from(1))
                && valid_prefixed_hex(payload, "sessionId", "session-")
                && integer(payload, "expectedGeneration").is_some_and(|value| value > 0)
                && payload
                    .get("title")
                    .and_then(Value::as_str)
                    .is_some_and(|title| {
                        !title.trim().is_empty()
                            && title.chars().count() <= 160
                            && !title.chars().any(char::is_control)
                    })
        }
        "product.queue.followup" => {
            exact_keys(
                payload,
                &["schemaVersion", "sessionId", "expectedGeneration", "text"],
            ) && payload.get("schemaVersion") == Some(&Value::from(1))
                && valid_prefixed_hex(payload, "sessionId", "session-")
                && integer(payload, "expectedGeneration").is_some_and(|value| value > 0)
                && payload
                    .get("text")
                    .and_then(Value::as_str)
                    .is_some_and(|text| {
                        !text.trim().is_empty()
                            && text.len() <= MAX_TEXT_BYTES
                            && !text.chars().any(|character| character == '\0')
                    })
        }
        "product.queue.replace" => {
            exact_keys(
                payload,
                &["schemaVersion", "sessionId", "expectedGeneration", "texts"],
            ) && payload.get("schemaVersion") == Some(&Value::from(1))
                && valid_prefixed_hex(payload, "sessionId", "session-")
                && integer(payload, "expectedGeneration").is_some_and(|value| value > 0)
                && payload
                    .get("texts")
                    .and_then(Value::as_array)
                    .is_some_and(|texts| {
                        texts.len() <= 64
                            && texts.iter().all(|text| {
                                text.as_str().is_some_and(|text| {
                                    !text.trim().is_empty()
                                        && text.len() <= MAX_TEXT_BYTES
                                        && !text.chars().any(|character| character == '\0')
                                })
                            })
                    })
        }
        "product.session.export" => {
            exact_keys(
                payload,
                &[
                    "schemaVersion",
                    "sessionId",
                    "expectedGeneration",
                    "privatePath",
                ],
            ) && payload.get("schemaVersion") == Some(&Value::from(1))
                && valid_prefixed_hex(payload, "sessionId", "session-")
                && integer(payload, "expectedGeneration").is_some_and(|value| value > 0)
                && valid_path(payload.get("privatePath"))
        }
        _ => false,
    };
    valid
        .then_some(())
        .ok_or_else(|| "product request rejected".to_string())
}

pub(crate) fn validate_product_turn_request(payload: &Map<String, Value>) -> Result<(), String> {
    let valid = exact_keys(
        payload,
        &[
            "method",
            "schemaVersion",
            "sessionId",
            "generation",
            "text",
            "retryPrevious",
            "attachments",
        ],
    ) && payload.get("method") == Some(&Value::String("product.turn.start".into()))
        && payload.get("schemaVersion") == Some(&Value::from(1))
        && valid_prefixed_hex(payload, "sessionId", "session-")
        && integer(payload, "generation").is_some_and(|value| value > 0)
        && payload
            .get("text")
            .and_then(Value::as_str)
            .is_some_and(|text| {
                !text.trim().is_empty()
                    && text.len() <= MAX_TEXT_BYTES
                    && !text.chars().any(|character| character == '\0')
            })
        && payload
            .get("retryPrevious")
            .and_then(Value::as_bool)
            .is_some()
        && payload
            .get("attachments")
            .and_then(Value::as_array)
            .is_some_and(|items| items.len() <= 8 && items.iter().all(valid_attachment));
    valid
        .then_some(())
        .ok_or_else(|| "product turn request rejected".to_string())
}

pub(crate) fn validate_product_auth_request(payload: &Map<String, Value>) -> Result<(), String> {
    let valid = exact_keys(
        payload,
        &["method", "schemaVersion", "providerId", "authMethod"],
    ) && payload.get("method") == Some(&Value::String("product.auth.start".into()))
        && payload.get("schemaVersion") == Some(&Value::from(1))
        && bounded_optional_identifier(payload, "providerId", 128)
        && payload
            .get("providerId")
            .is_some_and(|value| !value.is_null())
        && payload.get("authMethod") == Some(&Value::String("subscription".into()));
    valid
        .then_some(())
        .ok_or_else(|| "product auth request rejected".to_string())
}

fn valid_attachment(value: &Value) -> bool {
    let Some(item) = value.as_object() else {
        return false;
    };
    exact_keys(item, &["capabilityId", "mime", "byteLength", "privatePath"])
        && valid_prefixed_hex(item, "capabilityId", "attachment-")
        && matches!(
            item.get("mime").and_then(Value::as_str),
            Some("image/png" | "image/jpeg" | "image/webp")
        )
        && integer(item, "byteLength")
            .is_some_and(|length| length > 0 && length <= 20 * 1024 * 1024)
        && valid_path(item.get("privatePath"))
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

fn valid_prefixed_hex(payload: &Map<String, Value>, key: &str, prefix: &str) -> bool {
    payload
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix(prefix))
        .is_some_and(|suffix| {
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

fn valid_setting_key(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|key| {
        !key.is_empty()
            && key.len() <= 128
            && key.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index > 0 && matches!(byte, b'.' | b'-'))
            })
            && key.as_bytes()[0].is_ascii_lowercase()
    })
}

fn bounded_optional_text(payload: &Map<String, Value>, key: &str, maximum: usize) -> bool {
    payload.get(key).is_some_and(|value| {
        value.is_null()
            || value.as_str().is_some_and(|text| {
                !text.is_empty()
                    && text.chars().count() <= maximum
                    && !text.chars().any(char::is_control)
            })
    })
}

fn bounded_optional_identifier(payload: &Map<String, Value>, key: &str, maximum: usize) -> bool {
    payload.get(key).is_some_and(|value| {
        value.is_null()
            || value.as_str().is_some_and(|identifier| {
                !identifier.is_empty()
                    && identifier.len() <= maximum
                    && identifier.bytes().enumerate().all(|(index, byte)| {
                        byte.is_ascii_alphanumeric()
                            || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
                    })
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_requests_are_exact_and_path_bearing_only_on_the_private_boundary() {
        let create = serde_json::json!({
            "schemaVersion": 1,
            "workspaceId": "workspace-0123456789abcdef0123456789abcdef",
            "workspaceRevision": 1,
            "workspacePath": "/private/tmp/project",
            "agentDir": "/private/tmp/agent",
            "title": "New conversation",
            "providerId": null,
            "modelId": null
        });
        assert!(
            validate_product_request(
                "product.session.create",
                create.as_object().expect("object")
            )
            .is_ok()
        );
        let mut smuggled = create.as_object().expect("object").clone();
        smuggled.insert("credential".into(), Value::String("forbidden".into()));
        assert!(validate_product_request("product.session.create", &smuggled).is_err());
    }

    fn package_install(source: &str) -> Map<String, Value> {
        serde_json::json!({
            "schemaVersion": 1,
            "sessionId": "session-0123456789abcdef0123456789abcdef",
            "expectedGeneration": 3,
            "source": source,
            "scope": "project",
            "online": false,
            "acknowledgedExecutableRisk": true
        })
        .as_object()
        .expect("object")
        .clone()
    }

    fn package_mutation() -> Map<String, Value> {
        serde_json::json!({
            "schemaVersion": 1,
            "sessionId": "session-0123456789abcdef0123456789abcdef",
            "expectedGeneration": 3,
            "resourceId": "resource-0123456789abcdef0123456789abcdef",
            "operation": "update",
            "online": true,
            "acknowledgedExecutableRisk": false
        })
        .as_object()
        .expect("object")
        .clone()
    }

    #[test]
    fn package_install_matches_the_sidecar_router_contract() {
        let install = "product.package.install";
        assert!(validate_product_request(install, &package_install("npm:@scope/pkg")).is_ok());
        assert!(validate_product_request(install, &package_install("")).is_ok());
        assert!(validate_product_request(install, &package_install(&"x".repeat(256))).is_ok());
        // 128 astral characters are 256 UTF-16 units, as the sidecar counts.
        assert!(validate_product_request(install, &package_install(&"😀".repeat(128))).is_ok());
        assert!(validate_product_request(install, &package_install(&"x".repeat(257))).is_err());
        assert!(validate_product_request(install, &package_install(&"😀".repeat(129))).is_err());
        assert!(validate_product_request(install, &package_install("npm:pkg\n")).is_err());
        assert!(validate_product_request(install, &package_install("npm:pkg\u{85}")).is_err());

        let mut global = package_install("npm:pkg");
        global.insert("scope".into(), Value::from("global"));
        assert!(validate_product_request(install, &global).is_ok());
        let mut wrong_scope = package_install("npm:pkg");
        wrong_scope.insert("scope".into(), Value::from("user"));
        assert!(validate_product_request(install, &wrong_scope).is_err());
        let mut stale = package_install("npm:pkg");
        stale.insert("expectedGeneration".into(), Value::from(0));
        assert!(validate_product_request(install, &stale).is_err());
        let mut untyped = package_install("npm:pkg");
        untyped.insert("online".into(), Value::from("yes"));
        assert!(validate_product_request(install, &untyped).is_err());
        let mut smuggled = package_install("npm:pkg");
        smuggled.insert("path".into(), Value::from("/private/tmp"));
        assert!(validate_product_request(install, &smuggled).is_err());
    }

    #[test]
    fn package_mutation_matches_the_sidecar_router_contract() {
        let mutate = "product.package.mutate";
        assert!(validate_product_request(mutate, &package_mutation()).is_ok());
        let mut remove = package_mutation();
        remove.insert("operation".into(), Value::from("remove"));
        assert!(validate_product_request(mutate, &remove).is_ok());
        let mut install = package_mutation();
        install.insert("operation".into(), Value::from("install"));
        assert!(validate_product_request(mutate, &install).is_err());
        let mut resource = package_mutation();
        resource.insert("resourceId".into(), Value::from("resource-XYZ"));
        assert!(validate_product_request(mutate, &resource).is_err());
        let mut missing = package_mutation();
        missing.remove("acknowledgedExecutableRisk");
        assert!(validate_product_request(mutate, &missing).is_err());
    }
}
