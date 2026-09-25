//! Resolves the `PATH` the user's login shell would give a terminal.
//!
//! A macOS app launched from Finder inherits launchd's minimal `PATH`, so
//! tools the agent runs (Homebrew, nvm, cargo) would otherwise be missing.
//! The login shell is asked once per app run; anything slow, noisy or
//! malformed falls back to a fixed system list.

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) const FALLBACK_PATH: &str =
    "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
const LOGIN_SHELL_TIMEOUT: Duration = Duration::from_secs(3);
const START_SENTINEL: &str = "__PIUI_LOGIN_PATH_START__";
const END_SENTINEL: &str = "__PIUI_LOGIN_PATH_END__";
const MAX_SHELL_OUTPUT_BYTES: usize = 65_536;
const MAX_PATH_BYTES: usize = 16_384;
const MAX_PATH_ENTRIES: usize = 256;

/// The user's login-shell `PATH`, resolved at most once per process.
pub(crate) fn user_login_path() -> &'static str {
    static RESOLVED: OnceLock<String> = OnceLock::new();
    RESOLVED.get_or_init(|| {
        std::env::var_os("SHELL")
            .and_then(|shell| resolve_with_shell(Path::new(&shell), LOGIN_SHELL_TIMEOUT))
            .unwrap_or_else(|| FALLBACK_PATH.to_owned())
    })
}

fn resolve_with_shell(shell: &Path, timeout: Duration) -> Option<String> {
    if !shell.is_absolute() || !shell.is_file() {
        return None;
    }
    let script = format!("printf '%s%s%s' '{START_SENTINEL}' \"$PATH\" '{END_SENTINEL}'");
    let mut child = Command::new(shell)
        .args(["-l", "-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        // Its own group, so a profile that starts background jobs cannot
        // outlive the timeout.
        .process_group(0)
        .spawn()
        .ok()?;
    let group = child.id() as i32;
    let mut stdout = child.stdout.take()?;
    // Drain on a separate thread so a chatty profile cannot fill the pipe and
    // stall the shell. The capture is handed over as soon as the closing
    // sentinel arrives, because a background job started by the profile may
    // keep the pipe open long after the shell itself has exited.
    let (captured_sender, captured_receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut captured = Vec::new();
        let mut chunk = [0_u8; 4_096];
        let mut sent = false;
        loop {
            match stdout.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(read) if !sent => {
                    let room = MAX_SHELL_OUTPUT_BYTES.saturating_sub(captured.len());
                    captured.extend_from_slice(&chunk[..read.min(room)]);
                    if captured
                        .windows(END_SENTINEL.len())
                        .any(|window| window == END_SENTINEL.as_bytes())
                    {
                        sent = captured_sender
                            .try_send(std::mem::take(&mut captured))
                            .is_ok();
                    }
                }
                Ok(_) => {}
            }
        }
        if !sent {
            let _ = captured_sender.try_send(captured);
        }
    });
    let deadline = Instant::now() + timeout;
    let succeeded = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                // Still unreaped, so the group ID cannot have been reused.
                unsafe {
                    libc::kill(-group, libc::SIGKILL);
                }
                let _ = child.wait();
                break false;
            }
        }
    };
    if !succeeded {
        return None;
    }
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(100));
    let output = captured_receiver.recv_timeout(remaining).ok()?;
    extract_path(&String::from_utf8(output).ok()?)
}

fn extract_path(output: &str) -> Option<String> {
    let start = output.rfind(START_SENTINEL)? + START_SENTINEL.len();
    let end = start + output[start..].find(END_SENTINEL)?;
    let path = &output[start..end];
    valid_path_list(path).then(|| path.to_owned())
}

fn valid_path_list(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_BYTES
        && path.split(':').count() <= MAX_PATH_ENTRIES
        && path
            .split(':')
            .all(|entry| entry.starts_with('/') && !entry.chars().any(char::is_control))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_output_yields_only_absolute_directory_lists() {
        assert_eq!(
            extract_path(&format!(
                "motd noise\n{START_SENTINEL}/opt/homebrew/bin:/usr/bin{END_SENTINEL}"
            ))
            .as_deref(),
            Some("/opt/homebrew/bin:/usr/bin")
        );
        for rejected in [
            format!("{START_SENTINEL}{END_SENTINEL}"),
            format!("{START_SENTINEL}relative/bin:/usr/bin{END_SENTINEL}"),
            format!("{START_SENTINEL}/usr/bin::/bin{END_SENTINEL}"),
            format!("{START_SENTINEL}/usr/bin\n/bin{END_SENTINEL}"),
            format!("{START_SENTINEL}/usr/bin"),
            "no sentinel at all".to_owned(),
        ] {
            assert_eq!(extract_path(&rejected), None, "{rejected:?}");
        }
        assert!(valid_path_list(FALLBACK_PATH));
    }

    #[test]
    fn login_shell_path_is_read_between_sentinels() {
        let resolved = resolve_with_shell(Path::new("/bin/sh"), Duration::from_secs(3))
            .expect("the system shell reports a PATH");
        assert!(valid_path_list(&resolved), "{resolved:?}");
    }

    #[test]
    fn a_hanging_login_shell_times_out_and_is_killed() {
        let directory = std::env::temp_dir().join(format!(
            "piui-login-shell-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let shell = directory.join("slow-shell");
        std::fs::write(&shell, "#!/bin/sh\nsleep 30\n").unwrap();
        std::fs::set_permissions(&shell, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        let started = Instant::now();
        assert_eq!(resolve_with_shell(&shell, Duration::from_millis(200)), None);
        assert!(started.elapsed() < Duration::from_secs(2));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn missing_or_relative_shells_fall_back() {
        assert_eq!(
            resolve_with_shell(Path::new("sh"), Duration::from_secs(1)),
            None
        );
        assert_eq!(
            resolve_with_shell(Path::new("/nonexistent/piui-shell"), Duration::from_secs(1)),
            None
        );
        assert!(valid_path_list(user_login_path()));
    }
}
