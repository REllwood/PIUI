use super::CredentialProxy;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::Zeroize;

const MAX_SOURCE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportCandidate {
    pub provider_id: String,
    pub credential_type: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportInspection {
    pub available: bool,
    pub candidates: Vec<ImportCandidate>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReceipt {
    pub imported_provider_ids: Vec<String>,
    pub source_unchanged: bool,
}

pub fn inspect(path: &Path) -> Result<ImportInspection, String> {
    if !path.exists() {
        return Ok(ImportInspection {
            available: false,
            candidates: Vec::new(),
        });
    }
    let mut bytes = read_restricted(path)?;
    let result = parse_candidates(&bytes);
    bytes.zeroize();
    result.map(|candidates| ImportInspection {
        available: true,
        candidates,
    })
}

pub fn import_selected(
    path: &Path,
    provider_ids: Vec<String>,
    proxy: &CredentialProxy,
) -> Result<ImportReceipt, String> {
    if provider_ids.is_empty() || provider_ids.len() > 32 {
        return Err("credential-import-selection-invalid".into());
    }
    let selected: HashSet<_> = provider_ids.iter().cloned().collect();
    if selected.len() != provider_ids.len() {
        return Err("credential-import-selection-invalid".into());
    }
    let mut bytes = read_restricted(path)?;
    let before = Sha256::digest(&bytes);
    let mut parsed: Value = serde_json::from_slice(&bytes)
        .map_err(|_| "credential-import-source-invalid".to_string())?;
    bytes.zeroize();
    let mut source = parsed
        .as_object_mut()
        .map(std::mem::take)
        .ok_or_else(|| "credential-import-source-invalid".to_string())?;
    zeroise_json(&mut parsed);
    if source.len() > 256
        || !selected
            .iter()
            .all(|provider_id| source.contains_key(provider_id))
    {
        return Err("credential-import-selection-invalid".into());
    }
    let mut imported = Vec::with_capacity(provider_ids.len());
    for provider_id in provider_ids {
        let credential = source
            .remove(&provider_id)
            .ok_or_else(|| "credential-import-selection-invalid".to_string())?;
        proxy
            .import_credential(&provider_id, credential)
            .map_err(str::to_owned)?;
        imported.push(provider_id);
    }
    for value in source.values_mut() {
        zeroise_json(value);
    }
    let mut after_bytes = read_restricted(path)?;
    let after = Sha256::digest(&after_bytes);
    after_bytes.zeroize();
    if before.as_slice() != after.as_slice() {
        return Err("credential-import-source-changed".into());
    }
    Ok(ImportReceipt {
        imported_provider_ids: imported,
        source_unchanged: true,
    })
}

fn parse_candidates(bytes: &[u8]) -> Result<Vec<ImportCandidate>, String> {
    let mut value: Value = serde_json::from_slice(bytes)
        .map_err(|_| "credential-import-source-invalid".to_string())?;
    let result = (|| {
        let source = value
            .as_object()
            .ok_or_else(|| "credential-import-source-invalid".to_string())?;
        if source.len() > 256 {
            return Err("credential-import-source-invalid".into());
        }
        let mut candidates = Vec::new();
        for (provider_id, credential) in source {
            if provider_id.is_empty()
                || provider_id.len() > 128
                || !provider_id.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_alphanumeric()
                        || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
                })
            {
                return Err("credential-import-source-invalid".into());
            }
            let credential_type = match credential
                .as_object()
                .and_then(|record| record.get("type"))
                .and_then(Value::as_str)
            {
                Some("api_key") => "api-key",
                Some("oauth") => "subscription",
                _ => return Err("credential-import-source-invalid".into()),
            };
            candidates.push(ImportCandidate {
                provider_id: provider_id.clone(),
                credential_type,
            });
        }
        candidates.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
        Ok(candidates)
    })();
    zeroise_json(&mut value);
    result
}

fn read_restricted(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| "credential-import-source-unavailable".to_string())?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_SOURCE_BYTES
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err("credential-import-source-permissions".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "credential-import-source-unavailable".to_string())?;
    let opened = file
        .metadata()
        .map_err(|_| "credential-import-source-unavailable".to_string())?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err("credential-import-source-changed".into());
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "credential-import-source-unavailable".to_string())?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        bytes.zeroize();
        return Err("credential-import-source-invalid".into());
    }
    Ok(bytes)
}

fn zeroise_json(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(zeroise_json),
        Value::Object(record) => record.values_mut().for_each(zeroise_json),
        _ => {}
    }
    *value = Value::Null;
}

#[cfg(test)]
mod tests {
    use super::{import_selected, inspect};
    use crate::credentials::CredentialProxy;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    fn fixture_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "piui-credential-import-{}-{}-{label}.json",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn write_private_fixture(label: &str, content: &str) -> PathBuf {
        let path = fixture_path(label);
        fs::write(&path, content).expect("credential import fixture should be written");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("credential import fixture should be private");
        path
    }

    #[test]
    fn inspection_returns_metadata_without_secret_values() {
        let canary = "PIUI_IMPORT_SECRET_CANARY_9472";
        let source = write_private_fixture(
            "inspect",
            &format!(
                r#"{{"openai-codex":{{"type":"oauth","access":"{canary}","refresh":"refresh-canary","expires":4102444800000}},"anthropic":{{"type":"api_key","key":"api-canary"}}}}"#
            ),
        );
        let inspection = inspect(&source).expect("private source should be inspectable");
        let projected = serde_json::to_string(&inspection).expect("inspection should serialise");
        assert!(inspection.available);
        assert_eq!(inspection.candidates.len(), 2);
        assert!(!projected.contains(canary));
        assert!(!projected.contains("refresh-canary"));
        assert!(!projected.contains("api-canary"));
    }

    #[test]
    fn selected_import_preserves_source_and_uses_serialised_repository() {
        let source_bytes = br#"{"openai-codex":{"type":"oauth","access":"access-canary","refresh":"refresh-canary","expires":4102444800000}}"#;
        let source = write_private_fixture(
            "selected",
            std::str::from_utf8(source_bytes).expect("fixture is UTF-8"),
        );
        let proxy = CredentialProxy::in_memory_for_dispatcher_test();
        let receipt = import_selected(&source, vec!["openai-codex".into()], &proxy)
            .expect("selected credential should import");
        assert_eq!(receipt.imported_provider_ids, ["openai-codex"]);
        assert!(receipt.source_unchanged);
        assert_eq!(
            fs::read(&source).expect("source remains readable"),
            source_bytes
        );
        let debug = format!("{proxy:?}");
        assert!(!debug.contains("access-canary"));
        assert!(!debug.contains("refresh-canary"));
    }

    #[test]
    fn import_rejects_permissive_permissions_and_unsupported_shapes() {
        let permissive = write_private_fixture(
            "permissions",
            r#"{"provider":{"type":"api_key","key":"secret"}}"#,
        );
        fs::set_permissions(&permissive, fs::Permissions::from_mode(0o644))
            .expect("fixture permissions should change");
        assert_eq!(
            inspect(&permissive).err().as_deref(),
            Some("credential-import-source-permissions")
        );

        let unsupported = write_private_fixture(
            "unsupported",
            r#"{"provider":{"type":"unknown","value":"secret"}}"#,
        );
        assert_eq!(
            inspect(&unsupported).err().as_deref(),
            Some("credential-import-source-invalid")
        );
    }
}
