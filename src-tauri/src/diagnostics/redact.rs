use regex::Regex;
use serde_json::Value;

pub fn redact_text(value: &str) -> String {
    let credential = Regex::new(
        r"(?i)(authorization|api[_-]?key|cookie|set-cookie|token|secret|password|client[_-]?secret)\s*[:=]\s*[^,;\r\n]*",
    )
    .expect("static credential redaction pattern");
    let bearer =
        Regex::new(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+").expect("static bearer redaction pattern");
    let home = Regex::new(r"/Users/[^/\s]+/?").expect("static home redaction pattern");
    let query = Regex::new(r"(?i)([?&](?:code|state|token|key)=)[^&\s]+")
        .expect("static query redaction pattern");
    let result = credential.replace_all(value, "$1=[redacted]");
    let result = bearer.replace_all(&result, "Bearer [redacted]");
    let result = home.replace_all(&result, "/Users/[home]/");
    query
        .replace_all(&result, "$1[redacted]")
        .chars()
        .take(131_072)
        .collect()
}

pub fn redact_json(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, child) in object.iter_mut() {
                if [
                    "password",
                    "secret",
                    "token",
                    "credential",
                    "authorization",
                    "apikey",
                ]
                .iter()
                .any(|forbidden| key.to_ascii_lowercase().contains(forbidden))
                {
                    *child = Value::String("[redacted]".into());
                } else {
                    redact_json(child);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_json),
        Value::String(text) => *text = redact_text(text),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{redact_json, redact_text};

    #[test]
    fn text_redaction_removes_headers_queries_and_home_paths() {
        let canaries = [
            "PIUI_AUTH_CANARY",
            "PIUI_COOKIE_CANARY",
            "PIUI_QUERY_CANARY",
            "piuicanaryuser",
        ];
        let output = redact_text(
            "Authorization: Bearer PIUI_AUTH_CANARY; Cookie=session=PIUI_COOKIE_CANARY; callback=https://example.test/?code=PIUI_QUERY_CANARY /Users/piuicanaryuser/Documents/project",
        );
        for canary in canaries {
            assert!(!output.contains(canary), "redaction leaked {canary}");
        }
        assert!(output.contains("[redacted]"));
        assert!(output.contains("/Users/[home]/"));
    }

    #[test]
    fn structured_redaction_preserves_safe_evidence_only() {
        let mut value = serde_json::json!({
            "code": "provider-offline",
            "nested": {
                "accessToken": "PIUI_STRUCTURED_CANARY",
                "detail": "Retry is available"
            }
        });
        redact_json(&mut value);
        let output = value.to_string();
        assert!(!output.contains("PIUI_STRUCTURED_CANARY"));
        assert!(output.contains("provider-offline"));
        assert!(output.contains("Retry is available"));
    }
}
