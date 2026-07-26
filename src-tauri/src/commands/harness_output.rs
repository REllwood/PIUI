use crate::protocol::Envelope;
use std::io;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{SyncSender, TrySendError, sync_channel},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const OUTPUT_QUEUE_CAPACITY: usize = 64;
const OUTPUT_DEADLINE: Duration = Duration::from_millis(250);
const OUTPUT_POLL_SLICE_MS: i32 = 20;
const OUTPUT_UNAVAILABLE: &str = "harness output unavailable";

trait OutputSink: Send {
    fn write_frame(&mut self, frame: &[u8]) -> Result<(), ()>;
}

/// Bounded, one-way harness output commit boundary. A projector delivery is
/// successful once its reconstructed safe envelope enters this queue. The
/// single writer thread owns encoding and serial stdout writes; a later output
/// failure is terminal and cannot cause the committed UI sequence to be reused.
pub struct HarnessOutputQueue {
    sender: Option<SyncSender<Envelope>>,
    terminal: Arc<AtomicBool>,
    writer: Option<JoinHandle<()>>,
}

impl HarnessOutputQueue {
    pub fn stdout() -> Result<Self, String> {
        let sink = NonblockingStdoutSink::new()?;
        Ok(Self::with_sink(OUTPUT_QUEUE_CAPACITY, Box::new(sink)))
    }

    pub fn enqueue(&self, envelope: &Envelope) -> Result<(), String> {
        if self.terminal.load(Ordering::Acquire) {
            return Err(OUTPUT_UNAVAILABLE.into());
        }
        let Some(sender) = self.sender.as_ref() else {
            return Err(OUTPUT_UNAVAILABLE.into());
        };
        match sender.try_send(envelope.clone()) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                Err(OUTPUT_UNAVAILABLE.into())
            }
        }
    }

    pub fn close(mut self) -> Result<(), String> {
        self.sender.take();
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
        if self.terminal.load(Ordering::Acquire) {
            Err(OUTPUT_UNAVAILABLE.into())
        } else {
            Ok(())
        }
    }

    fn with_sink(capacity: usize, mut sink: Box<dyn OutputSink>) -> Self {
        let (sender, receiver) = sync_channel::<Envelope>(capacity);
        let terminal = Arc::new(AtomicBool::new(false));
        let writer_terminal = Arc::clone(&terminal);
        let writer = thread::spawn(move || {
            while let Ok(envelope) = receiver.recv() {
                let mut frame = match serde_json::to_vec(&envelope) {
                    Ok(frame) => Zeroizing::new(frame),
                    Err(_) => {
                        writer_terminal.store(true, Ordering::Release);
                        return;
                    }
                };
                frame.push(b'\n');
                if sink.write_frame(&frame).is_err() {
                    writer_terminal.store(true, Ordering::Release);
                    return;
                }
            }
        });
        Self {
            sender: Some(sender),
            terminal,
            writer: Some(writer),
        }
    }
}

impl Drop for HarnessOutputQueue {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

struct NonblockingStdoutSink {
    fd: i32,
    original_flags: i32,
}

impl NonblockingStdoutSink {
    fn new() -> Result<Self, String> {
        let fd = libc::STDOUT_FILENO;
        let original_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if original_flags < 0
            || unsafe { libc::fcntl(fd, libc::F_SETFL, original_flags | libc::O_NONBLOCK) } < 0
        {
            return Err(OUTPUT_UNAVAILABLE.into());
        }
        Ok(Self { fd, original_flags })
    }
}

impl OutputSink for NonblockingStdoutSink {
    fn write_frame(&mut self, frame: &[u8]) -> Result<(), ()> {
        let deadline = Instant::now() + OUTPUT_DEADLINE;
        let mut offset = 0;
        while offset < frame.len() {
            if Instant::now() >= deadline {
                return Err(());
            }
            let written = unsafe {
                libc::write(
                    self.fd,
                    frame[offset..].as_ptr().cast(),
                    frame.len() - offset,
                )
            };
            if written > 0 {
                offset += written as usize;
                continue;
            }
            if written == 0 {
                return Err(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::WouldBlock {
                return Err(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let timeout = i32::try_from(remaining.as_millis())
                .unwrap_or(i32::MAX)
                .clamp(1, OUTPUT_POLL_SLICE_MS);
            let mut descriptor = libc::pollfd {
                fd: self.fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let polled = unsafe { libc::poll(&mut descriptor, 1, timeout) };
            if polled < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(());
            }
        }
        Ok(())
    }
}

impl Drop for NonblockingStdoutSink {
    fn drop(&mut self) {
        unsafe {
            libc::fcntl(self.fd, libc::F_SETFL, self.original_flags);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ProtocolKind;
    use serde_json::{Map, Value};
    use std::sync::{Barrier, Mutex};

    fn envelope(sequence: u64) -> Envelope {
        let mut payload = Map::new();
        payload.insert("eventType".into(), Value::String("stream.delta".into()));
        payload.insert("text".into(), Value::String("safe".into()));
        Envelope {
            version: 1,
            kind: ProtocolKind::Event,
            id: format!("sidecar-{sequence}"),
            correlation_id: Some("web-stream-1".into()),
            decision_id: None,
            sequence,
            payload,
            error: None,
        }
    }

    struct BlockingSink {
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
    }

    impl OutputSink for BlockingSink {
        fn write_frame(&mut self, _frame: &[u8]) -> Result<(), ()> {
            self.entered.wait();
            self.release.wait();
            Ok(())
        }
    }

    struct FailingSink {
        attempts: Arc<Mutex<usize>>,
    }

    impl OutputSink for FailingSink {
        fn write_frame(&mut self, _frame: &[u8]) -> Result<(), ()> {
            *self.attempts.lock().unwrap() += 1;
            Err(())
        }
    }

    #[test]
    fn full_queue_fails_before_exposure_and_drains_cleanly() {
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let queue = HarnessOutputQueue::with_sink(
            1,
            Box::new(BlockingSink {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            }),
        );
        queue.enqueue(&envelope(1)).unwrap();
        entered.wait();
        queue.enqueue(&envelope(2)).unwrap();
        assert_eq!(queue.enqueue(&envelope(3)), Err(OUTPUT_UNAVAILABLE.into()));
        release.wait();
        // The sink blocks for every item, so release the second accepted frame.
        entered.wait();
        release.wait();
        assert!(queue.close().is_ok());
    }

    #[test]
    fn writer_failure_is_terminal_after_the_irreversible_enqueue_commit() {
        let attempts = Arc::new(Mutex::new(0));
        let queue = HarnessOutputQueue::with_sink(
            1,
            Box::new(FailingSink {
                attempts: Arc::clone(&attempts),
            }),
        );
        queue.enqueue(&envelope(1)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while !queue.terminal.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(queue.terminal.load(Ordering::Acquire));
        assert_eq!(queue.enqueue(&envelope(2)), Err(OUTPUT_UNAVAILABLE.into()));
        assert_eq!(*attempts.lock().unwrap(), 1);
        assert!(queue.close().is_err());
    }
}
