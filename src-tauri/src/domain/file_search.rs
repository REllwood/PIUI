use std::path::{Component, Path};

pub fn validate_workspace_relative_path(value: &str) -> Result<&Path, String> {
    if value.is_empty() || value.len() > 4_096 {
        return Err("workspace-path-invalid".into());
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("workspace-path-invalid".into());
    }
    Ok(path)
}
