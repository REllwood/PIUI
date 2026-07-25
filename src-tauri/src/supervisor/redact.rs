use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct StderrRedactor {
    home: Option<PathBuf>,
}

impl StderrRedactor {
    pub fn for_current_user() -> Self {
        Self {
            home: std::env::var_os("HOME").map(PathBuf::from),
        }
    }

    pub fn with_home(home: impl Into<PathBuf>) -> Self {
        Self {
            home: Some(home.into()),
        }
    }

    pub fn redact(&self, input: &str) -> String {
        // Redact while line boundaries still exist so a personal path with
        // spaces cannot consume a following diagnostic line.
        let mut text = input.to_owned();
        if let Some(home) = self.home.as_deref().and_then(Path::to_str) {
            if !home.is_empty() {
                text = text.replace(home, "<home>");
            }
        }
        text = user_path_regex()
            .replace_all(&text, "<user-path>")
            .into_owned();
        text = user_info_regex()
            .replace_all(&text, "://[redacted]@")
            .into_owned();
        text = query_regex()
            .replace_all(&text, "$1[redacted]")
            .into_owned();
        text = header_regex()
            .replace_all(&text, "$1: [redacted]")
            .into_owned();
        text = value_regex()
            .replace_all(&text, "$1=[redacted]")
            .into_owned();
        text = text.replace(['\r', '\n'], " ");
        text.chars().take(512).collect()
    }
}

fn header_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r#"(?i)\b(authorization|proxy-authorization|x-api-key|api-key|cookie|set-cookie)\s*[:=]\s*(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+(?:\s+[^\s,;]+)?)"#).unwrap())
}
fn value_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r#"(?i)\b(access[_-]?token|refresh[_-]?token|token|secret|password|credential|api[_-]?key)\b\s*[:=]\s*(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;&]+)"#).unwrap())
}
fn query_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"(?i)([?&](?:access[_-]?token|refresh[_-]?token|token|secret|password|credential|api[_-]?key)=)[^&\s]+").unwrap())
}
fn user_info_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"://[^/\s:@]+:[^/\s@]+@").unwrap())
}
fn user_path_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"(?i)(?:file://)?/(?:Users|home)/[^/\s\"']+(?:/[^\"'\r\n,;|)>\]}]*)?"#)
            .unwrap()
    })
}
