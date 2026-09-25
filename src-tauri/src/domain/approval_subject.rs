//! The human-readable subject of an approval: the command, file or address a
//! tool call is asking about. It is derived only from the canonical tool
//! input Rust has already validated, and shaped so that no absolute path
//! outside the workspace or home directory, no control character and no
//! recognisable secret reaches the WebView.

use serde::Serialize;
use serde_json::Value;
use std::path::{Component, Path, PathBuf};

pub(crate) const MAX_SUBJECT_UTF16: usize = 2_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalSubjectView {
    pub label: &'static str,
    pub text: String,
    pub truncated: bool,
}

/// Host-only locations used to shorten paths for display.
pub(crate) struct SubjectContext<'a> {
    pub workspace_root: &'a Path,
    pub home: Option<&'a Path>,
}

/// Argument names follow the pinned Pi 0.82.0 tool schemas
/// (`dist/core/tools/*.js`); `file_path` is Pi's accepted legacy alias.
pub(crate) fn derive_subject(
    tool: &str,
    input: &Value,
    context: &SubjectContext<'_>,
) -> Option<ApprovalSubjectView> {
    let input = input.as_object()?;
    let text = |key: &str| input.get(key).and_then(Value::as_str);
    let (label, raw) = match tool {
        "bash" => ("Command", text("command")?.to_owned()),
        "read" | "edit" | "write" => (
            "File",
            display_path(text("path").or_else(|| text("file_path"))?, context),
        ),
        "ls" => ("Folder", display_path(text("path").unwrap_or("."), context)),
        "grep" | "find" => {
            let pattern = text("pattern")?;
            match text("path") {
                Some(path) => (
                    "Pattern",
                    format!("{pattern} in {}", display_path(path, context)),
                ),
                None => ("Pattern", pattern.to_owned()),
            }
        }
        "web_fetch" => ("Address", text("url")?.to_owned()),
        "web_search" => ("Search", text("query")?.to_owned()),
        _ => return None,
    };
    Some(finish(label, &raw, context))
}

fn finish(label: &'static str, raw: &str, context: &SubjectContext<'_>) -> ApprovalSubjectView {
    let visible = raw
        .chars()
        .map(|character| {
            if character.is_control() && !matches!(character, '\n' | '\t') {
                '\u{FFFD}'
            } else {
                character
            }
        })
        .collect::<String>();
    let visible = match context.home.and_then(Path::to_str) {
        Some(home) => abbreviate_home(&visible, home),
        None => visible,
    };
    // Redaction runs on the whole text so a secret straddling the display cut
    // is still recognised; the cut then bounds whatever redaction produced.
    let redacted = crate::diagnostics::redact::redact_text(&visible);
    let (text, truncated) = truncate_utf16(&redacted, MAX_SUBJECT_UTF16);
    ApprovalSubjectView {
        label,
        text,
        truncated,
    }
}

fn truncate_utf16(text: &str, limit: usize) -> (String, bool) {
    let mut units = 0;
    for (index, character) in text.char_indices() {
        units += character.len_utf16();
        if units > limit {
            return (text[..index].to_owned(), true);
        }
    }
    (text.to_owned(), false)
}

/// Replaces the user's home directory with `~` wherever it appears as a
/// whole path prefix, the way a shell would print it.
fn abbreviate_home(text: &str, home: &str) -> String {
    let home = home.trim_end_matches('/');
    if home.is_empty() {
        return text.to_owned();
    }
    let mut output = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find(home) {
        let after = &rest[index + home.len()..];
        let boundary = after
            .chars()
            .next()
            .is_none_or(|next| !(next.is_alphanumeric() || matches!(next, '.' | '_' | '-')));
        output.push_str(&rest[..index]);
        output.push_str(if boundary { "~" } else { home });
        rest = after;
    }
    output.push_str(rest);
    output
}

/// Shows a tool path relative to the workspace or home directory. Relative
/// input is already relative to the workspace, so it is shown unchanged.
/// Any other absolute location is reduced to its final name.
fn display_path(raw: &str, context: &SubjectContext<'_>) -> String {
    let raw = raw.strip_prefix('@').unwrap_or(raw);
    if raw == "~" || raw.starts_with("~/") {
        return raw.to_owned();
    }
    let path = Path::new(raw);
    if !path.is_absolute() {
        return raw.to_owned();
    }
    let normalised = lexical_normalise(path);
    let candidates = [normalised.clone(), macos_private_alias(&normalised)];
    let root = lexical_normalise(context.workspace_root);
    for candidate in &candidates {
        if let Ok(relative) = candidate.strip_prefix(&root) {
            return if relative.as_os_str().is_empty() {
                ".".to_owned()
            } else {
                relative.to_string_lossy().into_owned()
            };
        }
    }
    if let Some(home) = context.home.map(lexical_normalise) {
        for candidate in &candidates {
            if let Ok(relative) = candidate.strip_prefix(&home) {
                return if relative.as_os_str().is_empty() {
                    "~".to_owned()
                } else {
                    format!("~/{}", relative.to_string_lossy())
                };
            }
        }
    }
    match normalised.file_name() {
        Some(name) => format!("…/{}", name.to_string_lossy()),
        None => "…".to_owned(),
    }
}

/// Resolves `.` and `..` without touching the filesystem, so a path cannot
/// appear inside the workspace merely by starting with its root.
fn lexical_normalise(path: &Path) -> PathBuf {
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => output.push(Component::RootDir.as_os_str()),
            Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                output.pop();
            }
            Component::Normal(part) => output.push(part),
        }
    }
    output
}

/// macOS exposes `/tmp`, `/var` and `/etc` through `/private`, and the
/// workspace root is stored canonically.
fn macos_private_alias(path: &Path) -> PathBuf {
    for alias in ["/tmp", "/var", "/etc"] {
        if path.starts_with(alias) {
            return Path::new("/private").join(path.strip_prefix("/").unwrap_or(path));
        }
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn context() -> SubjectContext<'static> {
        SubjectContext {
            workspace_root: Path::new("/Users/example/Code/project"),
            home: Some(Path::new("/Users/example")),
        }
    }

    fn subject(tool: &str, input: Value) -> Option<ApprovalSubjectView> {
        derive_subject(tool, &input, &context())
    }

    fn expect(tool: &str, input: Value, label: &str, text: &str) {
        let view = subject(tool, input).unwrap_or_else(|| panic!("{tool} has a subject"));
        assert_eq!((view.label, view.text.as_str()), (label, text), "{tool}");
        assert!(!view.truncated);
    }

    #[test]
    fn each_tool_maps_its_primary_argument_to_a_labelled_subject() {
        expect(
            "bash",
            json!({"command": "cargo test"}),
            "Command",
            "cargo test",
        );
        expect(
            "read",
            json!({"path": "src/main.rs"}),
            "File",
            "src/main.rs",
        );
        expect(
            "edit",
            json!({"path": "/Users/example/Code/project/src/lib.rs", "edits": []}),
            "File",
            "src/lib.rs",
        );
        expect(
            "write",
            json!({"file_path": "notes.txt", "content": "x"}),
            "File",
            "notes.txt",
        );
        expect("ls", json!({}), "Folder", ".");
        expect(
            "ls",
            json!({"path": "/Users/example/Code/project"}),
            "Folder",
            ".",
        );
        expect("grep", json!({"pattern": "TODO"}), "Pattern", "TODO");
        expect(
            "grep",
            json!({"pattern": "fn main", "path": "src"}),
            "Pattern",
            "fn main in src",
        );
        expect(
            "find",
            json!({"pattern": "*.rs", "path": "/Users/example/Code/project/crates"}),
            "Pattern",
            "*.rs in crates",
        );
        expect(
            "web_fetch",
            json!({"url": "https://example.com/docs"}),
            "Address",
            "https://example.com/docs",
        );
        expect(
            "web_search",
            json!({"query": "tauri menus"}),
            "Search",
            "tauri menus",
        );
    }

    #[test]
    fn unknown_tools_and_missing_arguments_have_no_subject() {
        assert_eq!(subject("mcp_tool", json!({"command": "rm -rf /"})), None);
        assert_eq!(subject("delete", json!({"path": "src"})), None);
        assert_eq!(subject("bash", json!({"cmd": "ls"})), None);
        assert_eq!(subject("read", json!({"path": 7})), None);
        assert_eq!(subject("grep", json!({"path": "src"})), None);
        assert_eq!(subject("bash", json!(["command"])), None);
    }

    #[test]
    fn paths_are_relative_to_the_workspace_or_home_and_never_otherwise_absolute() {
        let cases = [
            ("/Users/example/Code/project/src/a.rs", "src/a.rs"),
            (
                "/Users/example/Code/project/../other/secret.txt",
                "~/Code/other/secret.txt",
            ),
            (
                "/Users/example/Code/projectile/x.rs",
                "~/Code/projectile/x.rs",
            ),
            ("/Users/example/.ssh/id_ed25519", "~/.ssh/id_ed25519"),
            ("/Users/example", "~"),
            ("~/Downloads/file.zip", "~/Downloads/file.zip"),
            ("@src/app.ts", "src/app.ts"),
            ("../sibling/file", "../sibling/file"),
            ("/etc/passwd", "…/passwd"),
            ("/Users/someone-else/private/diary.md", "…/diary.md"),
            ("/Volumes/Backup/../../opt/tool", "…/tool"),
            ("/", "…"),
        ];
        for (raw, shown) in cases {
            expect("read", json!({"path": raw}), "File", shown);
        }
        let temporary = SubjectContext {
            workspace_root: Path::new("/private/tmp/workspace"),
            home: None,
        };
        let view =
            derive_subject("read", &json!({"path": "/tmp/workspace/a.txt"}), &temporary).unwrap();
        assert_eq!(view.text, "a.txt");
        let view = derive_subject("read", &json!({"path": "/Users/x/file"}), &temporary).unwrap();
        assert_eq!(view.text, "…/file");
    }

    #[test]
    fn free_text_abbreviates_home_and_redacts_secrets() {
        expect(
            "bash",
            json!({"command": "cat /Users/example/.zshrc /Users/examples/x"}),
            "Command",
            "cat ~/.zshrc /Users/[home]/x",
        );
        let view = subject(
            "bash",
            json!({"command": "curl -H 'Authorization: Bearer sk-live-PIUICANARY' https://api.test"}),
        )
        .unwrap();
        assert!(!view.text.contains("PIUICANARY"), "{}", view.text);
        let view = subject(
            "bash",
            json!({"command": "GITHUB_TOKEN=ghp_PIUICANARY make release"}),
        )
        .unwrap();
        assert!(!view.text.contains("PIUICANARY"), "{}", view.text);
        let view = subject(
            "web_fetch",
            json!({"url": "https://user:PIUICANARY@example.com/a?token=PIUICANARY2&page=1"}),
        )
        .unwrap();
        assert!(!view.text.contains("PIUICANARY"), "{}", view.text);
        assert!(view.text.contains("example.com"));
    }

    #[test]
    fn control_characters_are_replaced_but_newlines_and_tabs_survive() {
        expect(
            "bash",
            json!({"command": "echo a\tb\nprintf '\u{1b}[31m'\r\u{7f}\u{85}"}),
            "Command",
            "echo a\tb\nprintf '\u{FFFD}[31m'\u{FFFD}\u{FFFD}\u{FFFD}",
        );
    }

    #[test]
    fn long_text_is_cut_on_a_code_point_boundary_at_two_thousand_units() {
        let exact = "x".repeat(MAX_SUBJECT_UTF16);
        let view = subject("bash", json!({"command": exact})).unwrap();
        assert_eq!(view.text.encode_utf16().count(), MAX_SUBJECT_UTF16);
        assert!(!view.truncated);

        let over = "x".repeat(MAX_SUBJECT_UTF16 + 1);
        let view = subject("bash", json!({"command": over})).unwrap();
        assert_eq!(view.text.encode_utf16().count(), MAX_SUBJECT_UTF16);
        assert!(view.truncated);

        // 1,999 units then an astral character that would need two more.
        let astral = format!("{}😀tail", "x".repeat(MAX_SUBJECT_UTF16 - 1));
        let view = subject("bash", json!({"command": astral})).unwrap();
        assert_eq!(view.text, "x".repeat(MAX_SUBJECT_UTF16 - 1));
        assert!(view.truncated);

        let huge = "y".repeat(393_000);
        let view = subject("write", json!({"path": huge, "content": ""})).unwrap();
        assert_eq!(view.text.encode_utf16().count(), MAX_SUBJECT_UTF16);
        assert!(view.truncated);
    }
}
