pub mod atomic_file;
pub mod onboarding;
pub mod schema;
pub mod session_index;

use std::path::{Path, PathBuf};

pub fn application_data_root(base: &Path) -> Result<PathBuf, String> {
    if !base.is_absolute() {
        return Err("application-data-root-invalid".into());
    }
    Ok(base.join("PIUI"))
}
