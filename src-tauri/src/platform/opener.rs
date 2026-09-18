use regex::Regex;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosedExternalUrl(String);

impl DisclosedExternalUrl {
    pub fn parse(value: &str) -> Result<Self, String> {
        if value.len() > 2_048
            || !value.is_ascii()
            || value.contains('@')
            || value.chars().any(char::is_whitespace)
        {
            return Err("external-url-rejected".into());
        }
        let pattern = Regex::new(r"^https?://[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::[0-9]{1,5})?(?:/[^\x00-\x1f\x7f]*)?$")
            .expect("static external URL pattern");
        if !pattern.is_match(value) {
            return Err("external-url-rejected".into());
        }
        Ok(Self(value.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(target_os = "macos")]
pub fn open_external(target: &DisclosedExternalUrl) -> Result<(), String> {
    let status = Command::new("/usr/bin/open")
        .arg("--")
        .arg(target.as_str())
        .status()
        .map_err(|_| "external-open-failed")?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| "external-open-failed".into())
}
