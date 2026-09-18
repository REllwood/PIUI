use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use uuid::Uuid;

const MAX_APPLICATION_DATA_BYTES: u64 = 4 * 1024 * 1024;

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|_| "application-data-encode-failed")?;
    if bytes.len() as u64 > MAX_APPLICATION_DATA_BYTES {
        return Err("application-data-too-large".into());
    }
    write_atomic(path, &bytes)
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let mut file = File::open(path).map_err(|_| "application-data-unavailable")?;
    let metadata = file
        .metadata()
        .map_err(|_| "application-data-unavailable")?;
    if !metadata.is_file() || metadata.len() > MAX_APPLICATION_DATA_BYTES {
        return Err("application-data-invalid".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| "application-data-unavailable")?;
    serde_json::from_slice(&bytes).map_err(|_| "application-data-corrupt".into())
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("application-data-path-invalid")?;
    fs::create_dir_all(parent).map_err(|_| "application-data-directory-unavailable")?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|_| "application-data-permissions-unavailable")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("application-data-path-invalid")?;
    let temporary = parent.join(format!(
        ".{file_name}.{}.temporary",
        Uuid::new_v4().simple()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| "application-data-temporary-unavailable")?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| "application-data-write-failed")?;
        fs::rename(&temporary, path).map_err(|_| "application-data-rename-failed")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "application-data-directory-sync-failed")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
