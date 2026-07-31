use crate::protocol::Envelope;
use serde::Serialize;
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::ipc::InvokeBody;

const MAX_EVIDENCE_BYTES: usize = 262_144;
const MAX_RECORDS: usize = 512;
const NATIVE_EVIDENCE_FILE: &str = "native-boundary.jsonl";

struct EvidenceOutput {
    file: File,
    bytes: usize,
    records: usize,
}

#[derive(Clone)]
pub struct A23NativeEvidenceState {
    output: Arc<Mutex<EvidenceOutput>>,
}

impl A23NativeEvidenceState {
    pub fn from_environment() -> Result<Self, std::io::Error> {
        let target = private_target()?;
        let run_nonce = std::env::var("PIUI_A23_RUN_NONCE")
            .map_err(|_| std::io::Error::other("A.23 native evidence nonce unavailable"))?;
        if run_nonce.len() != 32 || !run_nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(std::io::Error::other("A.23 native evidence nonce invalid"));
        }
        let executable = std::env::current_exe()
            .and_then(fs::canonicalize)
            .map_err(|_| std::io::Error::other("A.23 executable identity unavailable"))?;
        let executable_metadata = fs::metadata(executable)
            .map_err(|_| std::io::Error::other("A.23 executable identity unavailable"))?;
        if !executable_metadata.is_file()
            || executable_metadata.uid() != unsafe { libc::geteuid() }
            || executable_metadata.nlink() != 1
        {
            return Err(std::io::Error::other("A.23 executable identity invalid"));
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(target)
            .map_err(|_| std::io::Error::other("A.23 native evidence unavailable"))?;
        let state = Self {
            output: Arc::new(Mutex::new(EvidenceOutput {
                file,
                bytes: 0,
                records: 0,
            })),
        };
        state
            .append(json!({
                "schemaVersion": 1,
                "record": "header",
                "runNonce": run_nonce,
                "processId": std::process::id(),
                "executable": {
                    "device": executable_metadata.dev(),
                    "inode": executable_metadata.ino(),
                    "bytes": executable_metadata.size()
                },
                "coverage": {
                    "invokeInputs": "all-native-handler-entries",
                    "invokeResults": "closed-a23-command-set",
                    "rustEvents": "webview-queue-admission",
                    "documentDom": "not-claimed",
                    "webStorage": "not-claimed",
                    "arbitraryJavascriptHeap": "not-claimed"
                }
            }))
            .map_err(std::io::Error::other)?;
        Ok(state)
    }

    pub fn record_invoke_entry(&self, command: &str, body: &InvokeBody) -> Result<(), String> {
        let input = match body {
            InvokeBody::Json(value) => value.clone(),
            InvokeBody::Raw(_) => return Err("a23-native-evidence-rejected".into()),
        };
        self.append(json!({
            "schemaVersion": 1,
            "record": "invoke-entry",
            "command": command,
            "input": input
        }))
    }

    pub fn record_invoke_result<T: Serialize>(
        &self,
        command: &str,
        result: &T,
    ) -> Result<(), String> {
        let result =
            serde_json::to_value(result).map_err(|_| "a23-native-evidence-rejected".to_string())?;
        self.append(json!({
            "schemaVersion": 1,
            "record": "invoke-result",
            "command": command,
            "result": result
        }))
    }

    pub fn record_invoke_error(&self, command: &str, code: &str) -> Result<(), String> {
        self.append(json!({
            "schemaVersion": 1,
            "record": "invoke-error",
            "command": command,
            "error": code
        }))
    }

    pub fn record_rust_event(&self, envelope: &Envelope) -> Result<(), String> {
        let bytes =
            serde_json::to_vec(envelope).map_err(|_| "a23-native-evidence-rejected".to_string())?;
        let bytes_utf8 =
            String::from_utf8(bytes).map_err(|_| "a23-native-evidence-rejected".to_string())?;
        self.append(json!({
            "schemaVersion": 1,
            "record": "rust-event",
            "event": "piui://stream-probe",
            "boundary": "webview-queue-admission",
            "bytesUtf8": bytes_utf8
        }))
    }

    fn append(&self, mut value: Value) -> Result<(), String> {
        let mut output = self
            .output
            .lock()
            .map_err(|_| "a23-native-evidence-unavailable".to_string())?;
        let next_sequence = output
            .records
            .checked_add(1)
            .filter(|sequence| *sequence <= MAX_RECORDS)
            .ok_or_else(|| "a23-native-evidence-limit".to_string())?;
        value
            .as_object_mut()
            .ok_or_else(|| "a23-native-evidence-rejected".to_string())?
            .insert("sequence".into(), Value::from(next_sequence));
        let mut bytes =
            serde_json::to_vec(&value).map_err(|_| "a23-native-evidence-rejected".to_string())?;
        bytes.push(b'\n');
        let next_bytes = output
            .bytes
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_EVIDENCE_BYTES)
            .ok_or_else(|| "a23-native-evidence-limit".to_string())?;
        let result = output
            .file
            .write_all(&bytes)
            .and_then(|()| output.file.sync_data())
            .map_err(|_| "a23-native-evidence-unavailable".to_string());
        bytes.fill(0);
        result?;
        output.records = next_sequence;
        output.bytes = next_bytes;
        Ok(())
    }
}

fn private_target() -> Result<PathBuf, std::io::Error> {
    let target = PathBuf::from(
        std::env::var_os("PIUI_A23_NATIVE_EVIDENCE_PATH")
            .ok_or_else(|| std::io::Error::other("A.23 native evidence path unavailable"))?,
    );
    if !target.is_absolute()
        || target.file_name().and_then(|name| name.to_str()) != Some(NATIVE_EVIDENCE_FILE)
        || target.exists()
    {
        return Err(std::io::Error::other("A.23 native evidence path invalid"));
    }
    let parent = target
        .parent()
        .ok_or_else(|| std::io::Error::other("A.23 native evidence path invalid"))?;
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|_| std::io::Error::other("A.23 native evidence path invalid"))?;
    if target.parent() != Some(canonical_parent.as_path()) {
        return Err(std::io::Error::other("A.23 native evidence path invalid"));
    }
    let metadata = fs::metadata(canonical_parent)
        .map_err(|_| std::io::Error::other("A.23 native evidence path invalid"))?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(std::io::Error::other("A.23 native evidence path invalid"));
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::{MAX_EVIDENCE_BYTES, MAX_RECORDS, NATIVE_EVIDENCE_FILE};

    #[test]
    fn native_boundary_is_bounded_and_has_a_fixed_private_target() {
        assert_eq!(MAX_EVIDENCE_BYTES, 262_144);
        assert_eq!(MAX_RECORDS, 512);
        assert_eq!(NATIVE_EVIDENCE_FILE, "native-boundary.jsonl");
    }
}
