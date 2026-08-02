#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(not(feature = "a23-credential-test"))]
    if production_arguments_request_a23_maintenance(std::env::args_os()) {
        std::process::exit(1);
    }
    #[cfg(feature = "a23-credential-test")]
    {
        let mut input = std::io::stdin().lock();
        let mut output = std::io::stdout().lock();
        match piui_lib::a23_credential_maintenance::run_main_arguments(
            std::env::args_os(),
            &mut input,
            &mut output,
        ) {
            piui_lib::a23_credential_maintenance::MainAction::Continue => {}
            piui_lib::a23_credential_maintenance::MainAction::ExitSuccess => return,
            piui_lib::a23_credential_maintenance::MainAction::ExitFailure(code) => {
                let stderr = std::io::stderr();
                let mut stderr = stderr.lock();
                match write_a23_maintenance_failure(&mut stderr, code) {
                    Ok(()) => std::process::exit(1),
                    Err(error) => exit_after_a23_stderr_failure(error),
                }
            }
        }
    }
    piui_lib::run();
}

#[cfg(feature = "a23-credential-test")]
fn write_a23_maintenance_failure<W: std::io::Write>(
    stderr: &mut W,
    code: piui_lib::a23_credential_maintenance::MaintenanceFailureCode,
) -> Result<(), std::io::Error> {
    stderr.write_all(code.stderr_line())?;
    stderr.flush()
}

#[cfg(feature = "a23-credential-test")]
fn exit_after_a23_stderr_failure(error: std::io::Error) -> ! {
    drop(error);
    std::process::exit(1)
}

#[cfg(not(feature = "a23-credential-test"))]
fn production_arguments_request_a23_maintenance<I>(arguments: I) -> bool
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    const RESERVED: [&str; 3] = [
        "--a23-cleanup",
        "--a23-seed-cleanup-fixture",
        "--a23-inspect-cleanup-fixture",
    ];
    arguments
        .into_iter()
        .skip(1)
        .any(|argument| RESERVED.iter().any(|reserved| argument == *reserved))
}

#[cfg(all(test, feature = "a23-credential-test"))]
mod a23_credential_test_mode_tests {
    use super::write_a23_maintenance_failure;
    use piui_lib::a23_credential_maintenance::MaintenanceFailureCode;
    use std::io::{Error, Write};

    #[derive(Default)]
    struct RecordingWriter {
        bytes: Vec<u8>,
        writes: usize,
        flushes: usize,
    }

    impl Write for RecordingWriter {
        fn write(&mut self, buffer: &[u8]) -> Result<usize, Error> {
            self.writes += 1;
            self.bytes.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> Result<(), Error> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn maintenance_failure_is_one_static_flushed_stderr_line() {
        let mut stderr = RecordingWriter::default();
        assert!(write_a23_maintenance_failure(&mut stderr, MaintenanceFailureCode::Input).is_ok());
        assert_eq!(stderr.bytes, b"A23_MAINTENANCE_FAILURE=input\n");
        assert_eq!(stderr.writes, 1);
        assert_eq!(stderr.flushes, 1);
    }
}

#[cfg(all(test, not(feature = "a23-credential-test")))]
mod tests {
    use super::production_arguments_request_a23_maintenance;
    use std::ffi::OsString;

    #[test]
    fn production_rejects_every_reserved_a23_maintenance_argument() {
        for reserved in [
            "--a23-cleanup",
            "--a23-seed-cleanup-fixture",
            "--a23-inspect-cleanup-fixture",
        ] {
            assert!(production_arguments_request_a23_maintenance([
                OsString::from("piui"),
                OsString::from(reserved),
            ]));
            assert!(production_arguments_request_a23_maintenance([
                OsString::from("piui"),
                OsString::from("--ordinary"),
                OsString::from(reserved),
            ]));
        }
        assert!(!production_arguments_request_a23_maintenance([
            OsString::from("piui"),
            OsString::from("--ordinary"),
        ]));
    }
}
