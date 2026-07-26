use super::redact::StderrRedactor;
use crate::protocol::MAX_LINE_BYTES;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};
use std::process::{ChildStderr, ChildStdin, ChildStdout};
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicBool, Ordering},
    mpsc::{SyncSender, TrySendError},
};
use std::thread::{self, JoinHandle};
use zeroize::Zeroizing;

pub(super) type FailureSignal = Arc<Mutex<Option<String>>>;

/// One linearisation point for generation write attempts and invalidation.
/// A write attempt may hold the shared gate only around one nonblocking sink
/// call. Fatal/stop takes the exclusive gate, marks the generation inactive,
/// then signals independently; no later write attempt can be authorised.
pub(super) struct GenerationControl {
    transition: RwLock<()>,
    active: AtomicBool,
    process_group: i32,
    failure: FailureSignal,
    stdin: Mutex<Option<ChildStdin>>,
    #[cfg(test)]
    authorisation_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl GenerationControl {
    pub(super) fn new(process_group: i32, failure: FailureSignal) -> Self {
        Self {
            transition: RwLock::new(()),
            active: AtomicBool::new(true),
            process_group,
            failure,
            stdin: Mutex::new(None),
            #[cfg(test)]
            authorisation_hook: Mutex::new(None),
        }
    }

    pub(super) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub(super) fn attach_stdin(&self, stdin: ChildStdin) -> Result<(), String> {
        let _gate = self
            .transition
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.active.load(Ordering::Acquire) {
            return Err("stale sidecar generation".into());
        }
        let mut owned = self
            .stdin
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if owned.is_some() {
            return Err("sidecar stdin already attached".into());
        }
        *owned = Some(stdin);
        Ok(())
    }

    pub(super) fn authorised_attempt<T>(&self, attempt: impl FnOnce() -> T) -> Result<T, ()> {
        #[cfg(test)]
        if let Some(hook) = self
            .authorisation_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            hook();
        }
        let _gate = self
            .transition
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.active.load(Ordering::Acquire) {
            return Err(());
        }
        Ok(attempt())
    }

    #[cfg(test)]
    pub(super) fn set_authorisation_hook(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self
            .authorisation_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    pub(super) fn invalidate(&self, message: &str) -> bool {
        let transitioned = {
            let _gate = self
                .transition
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let transitioned = self.active.swap(false, Ordering::AcqRel);
            if transitioned {
                self.close_stdin();
            }
            transitioned
        };
        if !transitioned {
            return false;
        }
        if let Ok(mut state) = self.failure.lock()
            && state.is_none()
        {
            *state = Some(message.to_string());
        }
        unsafe {
            libc::kill(-self.process_group, libc::SIGKILL);
        }
        true
    }

    pub(super) fn deactivate(&self) -> bool {
        let _gate = self
            .transition
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let transitioned = self.active.swap(false, Ordering::AcqRel);
        if transitioned {
            self.close_stdin();
        }
        transitioned
    }

    fn close_stdin(&self) {
        self.stdin
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
}

pub(super) enum RawFrame {
    Line(Zeroizing<Vec<u8>>),
    Failure(String),
}

/// The sole OS-level stdout consumer. It performs only bounded LF framing;
/// decoding and routing stay on the continuous dispatcher so decoder duplicate
/// history is never split between command receivers.
pub(super) fn stdout_reader(
    stdout: ChildStdout,
    sender: SyncSender<RawFrame>,
    control: Arc<GenerationControl>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::with_capacity(16 * 1024, stdout);
        loop {
            let mut line = Zeroizing::new(Vec::with_capacity(4096));
            let read = (&mut reader)
                .take((MAX_LINE_BYTES + 1) as u64)
                .read_until(b'\n', &mut line);
            match read {
                Ok(0) if !control.is_active() => return,
                Ok(0) => {
                    fail_generation(
                        "sidecar stdout closed unexpectedly",
                        &control,
                        Some(&sender),
                    );
                    return;
                }
                Ok(_) if line.len() > MAX_LINE_BYTES || line.last() != Some(&b'\n') => {
                    fail_generation(
                        "sidecar stdout contamination or limit violation",
                        &control,
                        Some(&sender),
                    );
                    return;
                }
                Ok(_) => match sender.try_send(RawFrame::Line(line)) {
                    Ok(()) => {}
                    Err(TrySendError::Full(frame)) => {
                        drop(frame);
                        fail_generation("sidecar stdout queue overflow", &control, Some(&sender));
                        return;
                    }
                    Err(TrySendError::Disconnected(frame)) => {
                        drop(frame);
                        return;
                    }
                },
                Err(_) if !control.is_active() => return,
                Err(_) => {
                    fail_generation("sidecar stdout read failed", &control, Some(&sender));
                    return;
                }
            }
        }
    })
}

pub(super) fn fail_generation(
    message: &str,
    control: &Arc<GenerationControl>,
    sender: Option<&SyncSender<RawFrame>>,
) {
    if !control.invalidate(message) {
        return;
    }
    if let Some(sender) = sender {
        let _ = sender.try_send(RawFrame::Failure(message.to_string()));
    }
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
