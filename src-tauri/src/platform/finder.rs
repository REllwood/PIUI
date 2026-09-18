use std::path::{Path, PathBuf};
use std::process::Command;

pub fn capability_backed_path(root: &Path, candidate: &Path) -> Result<PathBuf, String> {
    let canonical_root = root
        .canonicalize()
        .map_err(|_| "finder-capability-unavailable")?;
    let canonical_candidate = candidate
        .canonicalize()
        .map_err(|_| "finder-target-unavailable")?;
    if !canonical_candidate.starts_with(&canonical_root) {
        return Err("finder-target-rejected".into());
    }
    Ok(canonical_candidate)
}

#[cfg(target_os = "macos")]
pub fn reveal(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("finder-target-rejected".into());
    }
    let status = Command::new("/usr/bin/open")
        .arg("-R")
        .arg("--")
        .arg(path)
        .status()
        .map_err(|_| "finder-reveal-failed")?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| "finder-reveal-failed".into())
}
