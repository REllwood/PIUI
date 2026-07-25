use super::redact::StderrRedactor;
use crate::protocol::{Envelope, MAX_LINE_BYTES, ProtocolDecoder};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};
use std::process::{ChildStderr, ChildStdout};
use std::sync::{Arc, Mutex, mpsc::Sender};
use std::thread::{self, JoinHandle};

pub(super) type FailureSignal = Arc<Mutex<Option<String>>>;

pub(super) fn stdout_reader(
    stdout: ChildStdout,
    sender: Sender<Result<Envelope, String>>,
    process_group: i32,
    failure: FailureSignal,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::with_capacity(16 * 1024, stdout);
        let mut decoder = ProtocolDecoder::default();
        loop {
            let mut line = Vec::with_capacity(4096);
            let read = (&mut reader)
                .take((MAX_LINE_BYTES + 1) as u64)
                .read_until(b'\n', &mut line);
            match read {
                Ok(0) => {
                    fail_contaminated_stdout(
                        "sidecar stdout closed unexpectedly",
                        process_group,
                        &failure,
                        &sender,
                    );
                    return;
                }
                Ok(_) if line.len() > MAX_LINE_BYTES || line.last() != Some(&b'\n') => {
                    fail_contaminated_stdout(
                        "sidecar stdout contamination or limit violation",
                        process_group,
                        &failure,
                        &sender,
                    );
                    return;
                }
                Ok(_) => match decoder.decode(&line) {
                    Ok(envelope) => {
                        if sender.send(Ok(envelope)).is_err() {
                            return;
                        }
                    }
                    Err(_) => {
                        fail_contaminated_stdout(
                            "sidecar stdout protocol violation",
                            process_group,
                            &failure,
                            &sender,
                        );
                        return;
                    }
                },
                Err(_) => {
                    fail_contaminated_stdout(
                        "sidecar stdout read failed",
                        process_group,
                        &failure,
                        &sender,
                    );
                    return;
                }
            }
        }
    })
}

fn fail_contaminated_stdout(
    message: &str,
    process_group: i32,
    failure: &FailureSignal,
    sender: &Sender<Result<Envelope, String>>,
) {
    if let Ok(mut state) = failure.lock() {
        if state.is_none() {
            *state = Some(message.to_string());
        }
    }
    // The child is PIUI-owned and was placed in its own process group before
    // any protocol byte was read. Contamination invalidates the authority
    // boundary, so terminate the complete group immediately.
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
    let _ = sender.send(Err(message.to_string()));
}

pub(super) fn stderr_reader(
    stderr: ChildStderr,
    diagnostics: Arc<Mutex<VecDeque<String>>>,
    redactor: StderrRedactor,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::with_capacity(8 * 1024, stderr);
        loop {
            let mut fragment = Vec::with_capacity(1024);
            let read = (&mut reader).take(16_384).read_until(b'\n', &mut fragment);
            let count = match read {
                Ok(count) => count,
                Err(_) => return,
            };
            if count == 0 {
                return;
            }
            let text = redactor.redact(&String::from_utf8_lossy(&fragment));
            if text.is_empty() {
                continue;
            }
            let mut ring = diagnostics.lock().expect("diagnostic ring poisoned");
            if ring.len() == 64 {
                ring.pop_front();
            }
            ring.push_back(text);
        }
    })
}
