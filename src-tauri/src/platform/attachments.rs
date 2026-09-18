use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

const MAX_ATTACHMENT_BYTES: u64 = 20 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentView {
    pub capability_id: String,
    pub file_label: String,
    pub mime: &'static str,
    pub byte_length: u64,
}

struct AttachmentRecord {
    file: File,
    canonical_path: PathBuf,
    expires_at: Instant,
    view: AttachmentView,
}

#[derive(Default)]
pub struct AttachmentRegistry {
    records: Mutex<HashMap<String, AttachmentRecord>>,
}

impl AttachmentRegistry {
    pub fn register_selected(&self, path: &Path) -> Result<AttachmentView, String> {
        let canonical_path = path
            .canonicalize()
            .map_err(|_| "attachment-unavailable".to_string())?;
        let extension = canonical_path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let mime = match extension.as_str() {
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "webp" => "image/webp",
            _ => return Err("attachment-type-unsupported".into()),
        };
        let file = File::open(&canonical_path).map_err(|_| "attachment-unavailable")?;
        let length = file.metadata().map_err(|_| "attachment-unavailable")?.len();
        if length == 0 || length > MAX_ATTACHMENT_BYTES {
            return Err("attachment-size-unsupported".into());
        }
        let capability_id = format!("attachment-{}", Uuid::new_v4().simple());
        let view = AttachmentView {
            capability_id: capability_id.clone(),
            file_label: canonical_path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("Selected image")
                .chars()
                .take(160)
                .collect(),
            mime,
            byte_length: length,
        };
        let record = AttachmentRecord {
            file,
            canonical_path,
            expires_at: Instant::now() + Duration::from_secs(300),
            view: view.clone(),
        };
        let mut records = self
            .records
            .lock()
            .map_err(|_| "attachment-registry-unavailable")?;
        if records.len() >= 32 {
            return Err("attachment-capacity-unavailable".into());
        }
        records.insert(capability_id, record);
        Ok(view)
    }

    pub fn validate(&self, capability_id: &str) -> Result<AttachmentView, String> {
        let records = self
            .records
            .lock()
            .map_err(|_| "attachment-registry-unavailable")?;
        let record = records
            .get(capability_id)
            .ok_or("attachment-capability-expired")?;
        if record.expires_at <= Instant::now() {
            return Err("attachment-capability-expired".into());
        }
        let _ = record
            .file
            .metadata()
            .map_err(|_| "attachment-unavailable")?;
        Ok(record.view.clone())
    }

    pub fn remove(&self, capability_id: &str) -> Result<bool, String> {
        Ok(self
            .records
            .lock()
            .map_err(|_| "attachment-registry-unavailable")?
            .remove(capability_id)
            .is_some())
    }

    pub(crate) fn transport_descriptor(
        &self,
        capability_id: &str,
    ) -> Result<(AttachmentView, PathBuf), String> {
        let records = self
            .records
            .lock()
            .map_err(|_| "attachment-registry-unavailable")?;
        let record = records
            .get(capability_id)
            .ok_or("attachment-capability-expired")?;
        if record.expires_at <= Instant::now() {
            return Err("attachment-capability-expired".into());
        }
        let metadata = record
            .file
            .metadata()
            .map_err(|_| "attachment-unavailable")?;
        if metadata.len() != record.view.byte_length {
            return Err("attachment-changed-after-selection".into());
        }
        Ok((record.view.clone(), record.canonical_path.clone()))
    }
}
