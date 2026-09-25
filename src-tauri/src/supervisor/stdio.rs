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
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub(super) type FailureSignal = Arc<Mutex<Option<String>>>;
pub(super) type DeactivationWaker = Box<dyn FnOnce() + Send>;

pub(super) enum AttemptAuthorisationError {
    Inactive,
    DeadlineElapsed,
}

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
    // Coordinators block instead of polling, so the end of a generation has
    // to wake them. `None` once the wakers have run.
    wakers: Mutex<Option<Vec<DeactivationWaker>>>,
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
            wakers: Mutex::new(Some(Vec::new())),
            #[cfg(test)]
            authorisation_hook: Mutex::new(None),
        }
    }

    pub(super) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// Runs `waker` once this generation stops being active, or at once if
    /// it already has.
    pub(super) fn on_deactivate(&self, waker: DeactivationWaker) {
        let mut wakers = self
            .wakers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(pending) = wakers.as_mut()
            && self.is_active()
        {
            pending.push(waker);
            return;
        }
        drop(wakers);
        waker();
    }

    fn run_wakers(&self) {
        let wakers = self
            .wakers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        for waker in wakers.into_iter().flatten() {
            waker();
        }
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
        self.run_authorisation_hook();
        let _gate = self
            .transition
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.active.load(Ordering::Acquire) {
            return Err(());
        }
        Ok(attempt())
    }

    /// Authorises one sink attempt for this generation only while both the
    /// generation and its absolute deadline remain live. The checks and sink
    /// call share the transition read gate, so neither expiry nor generation
    /// invalidation has a stale check-to-attempt window.
    pub(super) fn authorised_attempt_before<T>(
        &self,
        absolute_deadline: Instant,
        attempt: impl FnOnce() -> T,
    ) -> Result<T, AttemptAuthorisationError> {
        self.run_authorisation_hook();
        let _gate = self
            .transition
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.active.load(Ordering::Acquire) {
            return Err(AttemptAuthorisationError::Inactive);
        }
        if Instant::now() >= absolute_deadline {
            return Err(AttemptAuthorisationError::DeadlineElapsed);
        }
        Ok(attempt())
    }

    fn run_authorisation_hook(&self) {
        #[cfg(test)]
        if let Some(hook) = self
            .authorisation_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            hook();
        }
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
        // One choke point for every generation-fatal reason, including
        // `fail_generation` and the dispatcher's `fatal`. Reasons are fixed
        // host strings, so no path or payload can reach the log.
        report_sidecar_failure(message);
        unsafe {
            libc::kill(-self.process_group, libc::SIGKILL);
        }
        self.run_wakers();
        true
    }

    pub(super) fn deactivate(&self) -> bool {
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
        if transitioned {
            self.run_wakers();
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

/// Records one generation-fatal reason on stderr so a packaged run can be
/// explained without a debugger. Only fixed host reason strings are emitted;
/// paths, identifiers and payloads are never included.
pub(crate) fn report_sidecar_failure(reason: &str) {
    eprintln!("PIUI_SIDECAR_FAILURE reason={reason}");
}

pub(super) enum RawFrame {
    Line(Zeroizing<Vec<u8>>),
    Failure(String),
}

/// How long the reader may wait for the dispatcher to take one frame before the
/// dispatcher is treated as wedged rather than merely behind.
pub(super) const RAW_QUEUE_STALL_DEADLINE: Duration = Duration::from_secs(5);
const RAW_QUEUE_STALL_SLICE: Duration = Duration::from_millis(1);

pub(super) enum RawAdmission {
    /// The dispatcher stopped receiving, so this generation has already ended.
    Retired,
    /// The dispatcher accepted nothing for the whole deadline.
    Stalled,
}

/// Hands one framed line to the dispatcher, waiting for room rather than
/// discarding it.
///
/// The sidecar legitimately answers a single request with a burst far larger
/// than the queue: the first `product.providers.list` alone emits one
/// credential probe per provider, several hundred frames in one flush. A full
/// queue therefore means the one dispatcher thread is momentarily behind the
/// reader, not that the generation is unsound, so the reader waits and lets the
/// operating system pipe be the outer buffer. Nothing is buffered beyond the
/// queue's existing bound, and a dispatcher that accepts nothing for the whole
/// deadline is still fatal.
pub(super) fn admit_raw_frame(
    frame: RawFrame,
    sender: &SyncSender<RawFrame>,
    control: &Arc<GenerationControl>,
    stall_deadline: Duration,
) -> Result<(), RawAdmission> {
    let expiry = Instant::now() + stall_deadline;
    let mut pending = frame;
    loop {
        match sender.try_send(pending) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Disconnected(held)) => {
                drop(held);
                return Err(RawAdmission::Retired);
            }
            Err(TrySendError::Full(held)) => {
                if !control.is_active() {
                    drop(held);
                    return Err(RawAdmission::Retired);
                }
                if Instant::now() >= expiry {
                    drop(held);
                    return Err(RawAdmission::Stalled);
                }
                pending = held;
                thread::sleep(RAW_QUEUE_STALL_SLICE);
            }
        }
    }
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
                Ok(_) => match admit_raw_frame(
                    RawFrame::Line(line),
                    &sender,
                    &control,
                    RAW_QUEUE_STALL_DEADLINE,
                ) {
                    Ok(()) => {}
                    Err(RawAdmission::Retired) => return,
                    Err(RawAdmission::Stalled) => {
                        fail_generation("sidecar stdout dispatch stalled", &control, Some(&sender));
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
            // Diagnostics are best-effort text; a panic elsewhere while the
            // ring was held must not take the stderr drain down with it.
            let mut ring = diagnostics
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if ring.len() == 64 {
                ring.pop_front();
            }
            ring.push_back(text);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::dispatcher::RAW_QUEUE_CAPACITY;
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc::sync_channel;

    /// Every control in these tests owns a real, dedicated process group, so an
    /// invalidation can only ever signal that one child and never the test
    /// runner's own group.
    fn grouped_child() -> (Child, Arc<GenerationControl>) {
        let child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("grouped child spawns");
        let control = Arc::new(GenerationControl::new(
            child.id() as i32,
            Arc::new(Mutex::new(None)),
        ));
        (child, control)
    }

    fn line(index: usize) -> RawFrame {
        RawFrame::Line(Zeroizing::new(format!("{index}\n").into_bytes()))
    }

    /// The boot burst the sidecar emits for one `product.providers.list` is far
    /// larger than the queue. A full queue must make the reader wait for the
    /// dispatcher rather than end the generation under it.
    #[test]
    fn a_full_raw_queue_waits_for_the_dispatcher_instead_of_ending_the_generation() {
        let (mut child, control) = grouped_child();
        let (sender, receiver) = sync_channel(RAW_QUEUE_CAPACITY);
        for index in 0..RAW_QUEUE_CAPACITY {
            assert!(sender.try_send(line(index)).is_ok(), "queue accepts");
        }
        // The dispatcher only reaches the next frame once the reader is already
        // waiting, which is exactly the ordering that used to be fatal.
        let drain = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            receiver.recv().expect("dispatcher takes one frame");
            receiver
        });
        let admitted = admit_raw_frame(
            line(RAW_QUEUE_CAPACITY),
            &sender,
            &control,
            RAW_QUEUE_STALL_DEADLINE,
        );
        assert!(admitted.is_ok());
        assert!(control.is_active());
        drop(drain.join().expect("drain thread"));
        control.deactivate();
        let _ = child.kill();
        let _ = child.wait();
    }

    /// The bound itself is unchanged: a dispatcher that accepts nothing for the
    /// whole deadline still ends the generation.
    #[test]
    fn a_dispatcher_that_never_drains_still_ends_the_generation() {
        let (mut child, control) = grouped_child();
        let (sender, receiver) = sync_channel(RAW_QUEUE_CAPACITY);
        for index in 0..RAW_QUEUE_CAPACITY {
            assert!(sender.try_send(line(index)).is_ok(), "queue accepts");
        }
        let admitted = admit_raw_frame(
            line(RAW_QUEUE_CAPACITY),
            &sender,
            &control,
            Duration::from_millis(40),
        );
        assert!(matches!(admitted, Err(RawAdmission::Stalled)));
        assert!(control.is_active());
        drop(receiver);
        control.deactivate();
        let _ = child.kill();
        let _ = child.wait();
    }

    /// A panic elsewhere while the diagnostic ring was held poisons it. The
    /// stderr drain must keep recording rather than panic and stop draining,
    /// which would eventually block the sidecar on a full stderr pipe.
    #[test]
    fn a_poisoned_diagnostic_ring_keeps_draining_stderr() {
        let ring = Arc::new(Mutex::new(VecDeque::new()));
        let poisoner = Arc::clone(&ring);
        let _ = thread::spawn(move || {
            let _held = poisoner.lock().unwrap();
            panic!("poison the diagnostic ring");
        })
        .join();
        assert!(ring.is_poisoned());
        let mut child = Command::new("/bin/sh")
            .args([
                "-c",
                "echo first diagnostic >&2; echo second diagnostic >&2",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("stderr child spawns");
        let stderr = child.stderr.take().expect("child stderr");
        let handle = stderr_reader(
            stderr,
            Arc::clone(&ring),
            StderrRedactor::with_home("/nonexistent-piui-home"),
        );
        handle
            .join()
            .expect("stderr drain survives a poisoned ring");
        let _ = child.wait();
        let lines = ring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 2, "both diagnostics recorded: {lines:?}");
    }

    /// End to end over a real pipe: one flush many times the queue's size must
    /// arrive whole and in order while the dispatcher is behind.
    #[test]
    fn a_boot_sized_flush_survives_a_dispatcher_that_starts_late() {
        const FRAMES: usize = RAW_QUEUE_CAPACITY * 16;
        let (mut child, control) = grouped_child();
        let mut stdin = child.stdin.take().expect("child stdin");
        let stdout = child.stdout.take().expect("child stdout");
        let (sender, receiver) = sync_channel(RAW_QUEUE_CAPACITY);
        // The writer hands the pipe back rather than closing it, so no end of
        // input can retire the generation while the frames are being checked.
        let writer = thread::spawn(move || {
            let padding = "p".repeat(1_024);
            for index in 0..FRAMES {
                writeln!(stdin, "{index}:{padding}").expect("burst is written");
            }
            stdin.flush().expect("burst is flushed");
            stdin
        });
        let handle = stdout_reader(stdout, sender, Arc::clone(&control));
        // Nothing drains yet, so the pipe and the queue both fill and the
        // reader is left waiting on a dispatcher that has not started.
        thread::sleep(Duration::from_millis(100));
        let mut observed = Vec::with_capacity(FRAMES);
        while observed.len() < FRAMES {
            match receiver
                .recv_timeout(Duration::from_secs(20))
                .expect("frame arrives")
            {
                RawFrame::Line(frame) => {
                    let text = String::from_utf8_lossy(&frame).to_string();
                    let index = text.split(':').next().expect("frame index").to_owned();
                    observed.push(index.parse::<usize>().expect("frame index parses"));
                }
                RawFrame::Failure(reason) => panic!("unexpected generation failure: {reason}"),
            }
        }
        assert_eq!(observed, (0..FRAMES).collect::<Vec<_>>());
        assert!(control.is_active());
        let stdin = writer.join().expect("writer thread");
        control.deactivate();
        drop(stdin);
        drop(receiver);
        let _ = child.wait();
        handle.join().expect("reader thread");
    }
}
