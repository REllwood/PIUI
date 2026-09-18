use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashConfirmation {
    session_id: String,
    identity: String,
    token: String,
}

pub fn confirmation(
    session_id: &str,
    identity: &str,
    nonce: &str,
) -> Result<TrashConfirmation, String> {
    if session_id.is_empty() || identity.is_empty() || nonce.len() < 32 {
        return Err("trash-confirmation-invalid".into());
    }
    let token = format!(
        "{:x}",
        Sha256::digest(format!("{session_id}\0{identity}\0{nonce}").as_bytes())
    );
    Ok(TrashConfirmation {
        session_id: session_id.into(),
        identity: identity.into(),
        token,
    })
}

pub fn move_enumerated_inactive_session(
    source: &Path,
    trash_directory: &Path,
    session_id: &str,
    current_identity: &str,
    expected: &TrashConfirmation,
    active: bool,
) -> Result<PathBuf, String> {
    if active
        || expected.session_id != session_id
        || expected.identity != current_identity
        || !source.is_absolute()
        || !trash_directory.is_absolute()
    {
        return Err("trash-request-rejected".into());
    }
    let target_name = source.file_name().ok_or("trash-request-rejected")?;
    let target = trash_directory.join(format!(
        "{}.{}",
        target_name.to_string_lossy(),
        &expected.token[..12]
    ));
    if target.exists() {
        return Err("trash-target-conflict".into());
    }
    fs::rename(source, &target).map_err(|_| "trash-move-failed")?;
    Ok(target)
}
