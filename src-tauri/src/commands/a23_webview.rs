use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::State;

const SNAPSHOT_SCHEMA_VERSION: u8 = 1;
const SNAPSHOT_SCOPE: &str = "credential-probe-webview-surfaces";
const MAX_SNAPSHOT_BYTES: usize = 262_144;
const MAX_COMMANDS: usize = 256;
const MAX_APP_EVENTS: usize = 128;
const MAX_FORM_CONTROLS: usize = 256;
const MAX_STORAGE_ENTRIES: usize = 256;
const MAX_VALUE_DEPTH: usize = 16;
const MAX_VALUE_NODES: usize = 8_192;
const MAX_STRING_BYTES: usize = 131_072;
const STREAM_EVENT: &str = "piui://stream-probe";

#[derive(Default)]
pub struct A23WebViewSnapshotState {
    claimed: AtomicBool,
}

impl A23WebViewSnapshotState {
    fn claim_once(&self) -> Result<(), String> {
        self.claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| "a23-webview-snapshot-already-captured".to_string())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct A23WebViewSnapshot {
    schema_version: u8,
    scope: String,
    coverage: A23Coverage,
    document: A23Document,
    storage: A23Storage,
    commands: Vec<A23CommandObservation>,
    app_events: Vec<A23AppEventObservation>,
    submission: A23SubmissionObservation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct A23Coverage {
    arbitrary_javascript_heap: String,
    document: String,
    storage: String,
    commands: String,
    app_events: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct A23Document {
    outer_html: String,
    inner_text: String,
    text_content: String,
    visibility_state: String,
    url: String,
    form_controls: Vec<A23FormControl>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct A23FormControl {
    index: u32,
    tag: String,
    input_type: String,
    name: String,
    value: String,
    checked: bool,
    selected_values: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct A23Storage {
    local: Vec<A23StorageEntry>,
    session: Vec<A23StorageEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct A23StorageEntry {
    key: String,
    value: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct A23CommandObservation {
    sequence: u32,
    command: String,
    input: Value,
    result: Value,
    error: Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct A23AppEventObservation {
    sequence: u32,
    event: String,
    payload: Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct A23SubmissionObservation {
    command: String,
    input: String,
    result: String,
    error: Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct A23WebViewSnapshotReceipt {
    schema_version: u8,
    state: &'static str,
}

#[tauri::command]
pub fn credential_webview_snapshot(
    state: State<'_, A23WebViewSnapshotState>,
    snapshot: A23WebViewSnapshot,
) -> Result<A23WebViewSnapshotReceipt, String> {
    state.claim_once()?;
    let bytes = encode_snapshot(&snapshot)?;
    write_snapshot(bytes)?;
    Ok(A23WebViewSnapshotReceipt {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        state: "captured",
    })
}

fn encode_snapshot(snapshot: &A23WebViewSnapshot) -> Result<Vec<u8>, String> {
    validate_snapshot(snapshot)?;
    let mut bytes =
        serde_json::to_vec(snapshot).map_err(|_| "a23-webview-snapshot-rejected".to_string())?;
    if bytes.len() >= MAX_SNAPSHOT_BYTES {
        bytes.fill(0);
        return Err("a23-webview-snapshot-rejected".into());
    }
    bytes.push(b'\n');
    Ok(bytes)
}

fn validate_snapshot(snapshot: &A23WebViewSnapshot) -> Result<(), String> {
    if snapshot.schema_version != SNAPSHOT_SCHEMA_VERSION
        || snapshot.scope != SNAPSHOT_SCOPE
        || snapshot.coverage.arbitrary_javascript_heap != "not-claimed"
        || snapshot.coverage.document != "outer-html-inner-text-text-content-form-controls"
        || snapshot.coverage.storage != "local-and-session-storage"
        || snapshot.coverage.commands != "credential-probe-invoke-inputs-results-errors"
        || snapshot.coverage.app_events != [STREAM_EVENT]
        || snapshot.document.outer_html.len() > MAX_STRING_BYTES
        || snapshot.document.inner_text.len() > MAX_STRING_BYTES
        || snapshot.document.text_content.len() > MAX_STRING_BYTES
        || snapshot.document.url.len() > 4_096
        || snapshot.document.visibility_state.len() > 32
        || snapshot.document.form_controls.len() > MAX_FORM_CONTROLS
        || snapshot.storage.local.len() > MAX_STORAGE_ENTRIES
        || snapshot.storage.session.len() > MAX_STORAGE_ENTRIES
        || snapshot.commands.len() < 3
        || snapshot.commands.len() > MAX_COMMANDS
        || snapshot.app_events.len() > MAX_APP_EVENTS
        || snapshot.submission.command != "credential_webview_snapshot"
        || snapshot.submission.input != "all-other-fields-in-this-record"
        || snapshot.submission.result != "file-created-before-command-response"
        || !snapshot.submission.error.is_null()
    {
        return Err("a23-webview-snapshot-rejected".into());
    }

    for (index, control) in snapshot.document.form_controls.iter().enumerate() {
        if control.index as usize != index
            || control.tag.len() > 32
            || control.input_type.len() > 64
            || control.name.len() > 1_024
            || control.value.len() > MAX_STRING_BYTES
            || control.selected_values.len() > MAX_FORM_CONTROLS
            || control
                .selected_values
                .iter()
                .any(|value| value.len() > MAX_STRING_BYTES)
        {
            return Err("a23-webview-snapshot-rejected".into());
        }
    }
    for entry in snapshot
        .storage
        .local
        .iter()
        .chain(snapshot.storage.session.iter())
    {
        if entry.key.len() > 4_096 || entry.value.len() > MAX_STRING_BYTES {
            return Err("a23-webview-snapshot-rejected".into());
        }
    }

    let mut expected_sequence = 1_u32;
    let mut nodes = 0_usize;
    for (index, observation) in snapshot.commands.iter().enumerate() {
        let command_is_expected = match index {
            0 => observation.command == "sidecar_start",
            1 => observation.command == "present_credential_sheet",
            _ => observation.command == "credential_lifecycle_status",
        };
        if observation.sequence != expected_sequence
            || !command_is_expected
            || observation.result.is_null()
            || !observation.error.is_null()
        {
            return Err("a23-webview-snapshot-rejected".into());
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| "a23-webview-snapshot-rejected".to_string())?;
        validate_value(&observation.input, 0, &mut nodes)?;
        validate_value(&observation.result, 0, &mut nodes)?;
        validate_value(&observation.error, 0, &mut nodes)?;
    }
    if snapshot
        .commands
        .last()
        .and_then(|observation| observation.result.get("state"))
        .and_then(Value::as_str)
        != Some("passed")
    {
        return Err("a23-webview-snapshot-rejected".into());
    }
    expected_sequence = 1;
    for observation in &snapshot.app_events {
        if observation.sequence != expected_sequence || observation.event != STREAM_EVENT {
            return Err("a23-webview-snapshot-rejected".into());
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| "a23-webview-snapshot-rejected".to_string())?;
        validate_value(&observation.payload, 0, &mut nodes)?;
    }
    Ok(())
}

fn validate_value(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), String> {
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| "a23-webview-snapshot-rejected".to_string())?;
    if depth > MAX_VALUE_DEPTH || *nodes > MAX_VALUE_NODES {
        return Err("a23-webview-snapshot-rejected".into());
    }
    match value {
        Value::String(value) if value.len() > MAX_STRING_BYTES => {
            Err("a23-webview-snapshot-rejected".into())
        }
        Value::Array(values) => {
            for value in values {
                validate_value(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for (key, value) in values {
                if key.len() > 4_096 {
                    return Err("a23-webview-snapshot-rejected".into());
                }
                validate_value(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(not(feature = "a23-credential-test"))]
fn write_snapshot(mut bytes: Vec<u8>) -> Result<(), String> {
    bytes.fill(0);
    Err("a23-webview-snapshot-not-enabled".into())
}

#[cfg(feature = "a23-credential-test")]
fn write_snapshot(mut bytes: Vec<u8>) -> Result<(), String> {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::PathBuf;

    let result = (|| {
        let target = PathBuf::from(
            std::env::var_os("PIUI_A23_WEBVIEW_SNAPSHOT_PATH")
                .ok_or_else(|| "a23-webview-snapshot-path-unavailable".to_string())?,
        );
        if !target.is_absolute()
            || target.file_name().and_then(|name| name.to_str()) != Some("webview-snapshot.json")
            || target.exists()
        {
            return Err("a23-webview-snapshot-path-invalid".into());
        }
        let lifecycle_result = PathBuf::from(
            std::env::var_os("PIUI_A23_RESULT_PATH")
                .ok_or_else(|| "a23-webview-snapshot-path-unavailable".to_string())?,
        );
        if lifecycle_result.parent() != target.parent() {
            return Err("a23-webview-snapshot-path-invalid".into());
        }
        let parent = target
            .parent()
            .ok_or_else(|| "a23-webview-snapshot-path-invalid".to_string())?;
        let canonical_parent = fs::canonicalize(parent)
            .map_err(|_| "a23-webview-snapshot-path-invalid".to_string())?;
        if target.parent() != Some(canonical_parent.as_path()) {
            return Err("a23-webview-snapshot-path-invalid".into());
        }
        let metadata = fs::metadata(&canonical_parent)
            .map_err(|_| "a23-webview-snapshot-path-invalid".to_string())?;
        if !metadata.is_dir()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err("a23-webview-snapshot-path-invalid".into());
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&target)
            .map_err(|_| "a23-webview-snapshot-write-failed".to_string())?;
        output
            .write_all(&bytes)
            .and_then(|()| output.sync_all())
            .map_err(|_| "a23-webview-snapshot-write-failed".to_string())
    })();
    bytes.fill(0);
    result
}

#[cfg(test)]
mod tests {
    use super::{A23WebViewSnapshot, A23WebViewSnapshotState, MAX_SNAPSHOT_BYTES, encode_snapshot};

    fn snapshot_json(inner_text: &str) -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": 1,
            "scope": "credential-probe-webview-surfaces",
            "coverage": {
                "arbitraryJavascriptHeap": "not-claimed",
                "document": "outer-html-inner-text-text-content-form-controls",
                "storage": "local-and-session-storage",
                "commands": "credential-probe-invoke-inputs-results-errors",
                "appEvents": ["piui://stream-probe"]
            },
            "document": {
                "outerHtml": "<html><body>fixture</body></html>",
                "innerText": inner_text,
                "textContent": "fixture",
                "visibilityState": "visible",
                "url": "index.html?spike=credential",
                "formControls": []
            },
            "storage": { "local": [], "session": [] },
            "commands": [
                {
                    "sequence": 1,
                    "command": "sidecar_start",
                    "input": { "type": "undefined" },
                    "result": { "running": true },
                    "error": null
                },
                {
                    "sequence": 2,
                    "command": "present_credential_sheet",
                    "input": { "request": { "providerId": "a23.fixture-provider" } },
                    "result": { "savedState": "saved" },
                    "error": null
                },
                {
                    "sequence": 3,
                    "command": "credential_lifecycle_status",
                    "input": { "type": "undefined" },
                    "result": { "state": "passed" },
                    "error": null
                }
            ],
            "appEvents": [{
                "sequence": 1,
                "event": "piui://stream-probe",
                "payload": { "fixture": true }
            }],
            "submission": {
                "command": "credential_webview_snapshot",
                "input": "all-other-fields-in-this-record",
                "result": "file-created-before-command-response",
                "error": null
            }
        })
    }

    #[test]
    fn raw_canary_is_preserved_for_external_scanning() {
        let snapshot: A23WebViewSnapshot =
            serde_json::from_value(snapshot_json("PIUI_A23_CANARY_MUST_REMAIN_RAW")).unwrap();
        let bytes = encode_snapshot(&snapshot).unwrap();
        assert!(
            bytes
                .windows(b"PIUI_A23_CANARY_MUST_REMAIN_RAW".len())
                .any(|window| window == b"PIUI_A23_CANARY_MUST_REMAIN_RAW")
        );
    }

    #[test]
    fn schema_bounds_and_unknown_fields_fail_closed() {
        let mut unknown = snapshot_json("fixture");
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<A23WebViewSnapshot>(unknown).is_err());

        let oversized = "x".repeat(MAX_SNAPSHOT_BYTES);
        let snapshot: A23WebViewSnapshot =
            serde_json::from_value(snapshot_json(&oversized)).unwrap();
        assert!(encode_snapshot(&snapshot).is_err());
    }

    #[test]
    fn snapshot_state_is_one_shot() {
        let state = A23WebViewSnapshotState::default();
        assert!(state.claim_once().is_ok());
        assert!(state.claim_once().is_err());
    }
}
