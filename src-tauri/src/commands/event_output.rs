use super::ack_settlement::AckSettlement;
use super::projector::WebViewProjector;
use crate::protocol::Envelope;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
};
use tauri::{AppHandle, Emitter};

const EVENT_QUEUE_CAPACITY: usize = 64;
const EVENT_OUTPUT_UNAVAILABLE: &str = "stream event output unavailable";
const STREAM_EVENT: &str = "piui://stream-probe";

pub(crate) type EventReceipt = Receiver<Result<(), String>>;

trait EventSink: Send + 'static {
    fn emit(&mut self, envelope: &Envelope) -> Result<(), ()>;
}

struct AppEventSink {
    app: AppHandle,
}

impl EventSink for AppEventSink {
    fn emit(&mut self, envelope: &Envelope) -> Result<(), ()> {
        // Pinned Tauri 2.11.5 contract: this is only serialisation and WebView
        // eval scheduling. It does not execute a JavaScript callback inline.
        self.app.emit(STREAM_EVENT, envelope).map_err(|_| ())
    }
}

struct AckRecord {
    correlation: String,
    accepted: bool,
    settlement: AckSettlement,
}

struct EventRecord {
    generation: u64,
    envelope: Envelope,
    receipt: Option<SyncSender<Result<(), String>>>,
    acknowledgement: Option<AckRecord>,
}

enum EventOutputState {
    Uninitialised,
    Running {
        sender: SyncSender<EventRecord>,
        terminal: Arc<AtomicBool>,
    },
}

/// Application-lifetime bounded WebView event acceptance boundary.
///
/// Projection commits only on nonblocking `try_send`. The sole worker owns
/// the fixed trusted Tauri emitter. Immediately before emission it enters the
/// projector delivery gate and reauthenticates generation plus committed UI
/// coordinate, so deactivation returning is a hard no-later-emission boundary.
pub(crate) struct EventOutputQueue {
    state: Mutex<EventOutputState>,
}

impl Default for EventOutputQueue {
    fn default() -> Self {
        Self {
            state: Mutex::new(EventOutputState::Uninitialised),
        }
    }
}

impl EventOutputQueue {
    pub(crate) fn initialise(
        &self,
        app: AppHandle,
        projector: Arc<WebViewProjector>,
    ) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EVENT_OUTPUT_UNAVAILABLE.to_string())?;
        if matches!(*state, EventOutputState::Running { .. }) {
            return Ok(());
        }
        *state = spawn_worker(
            EVENT_QUEUE_CAPACITY,
            Box::new(AppEventSink { app }),
            projector,
        );
        Ok(())
    }

    pub(crate) fn enqueue(&self, generation: u64, envelope: &Envelope) -> Result<(), String> {
        self.enqueue_record(EventRecord {
            generation,
            envelope: envelope.clone(),
            receipt: None,
            acknowledgement: None,
        })
    }

    pub(crate) fn enqueue_ack_with_receipt(
        &self,
        generation: u64,
        envelope: &Envelope,
        settlement: AckSettlement,
    ) -> Result<EventReceipt, String> {
        let correlation = envelope
            .correlation_id
            .clone()
            .ok_or_else(|| EVENT_OUTPUT_UNAVAILABLE.to_string())?;
        let accepted = envelope
            .payload
            .get("accepted")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| EVENT_OUTPUT_UNAVAILABLE.to_string())?;
        let (sender, receiver) = sync_channel(1);
        self.enqueue_record(EventRecord {
            generation,
            envelope: envelope.clone(),
            receipt: Some(sender),
            acknowledgement: Some(AckRecord {
                correlation,
                accepted,
                settlement,
            }),
        })?;
        Ok(receiver)
    }

    #[cfg(test)]
    fn enqueue_with_receipt(
        &self,
        generation: u64,
        envelope: &Envelope,
    ) -> Result<EventReceipt, String> {
        let (sender, receiver) = sync_channel(1);
        self.enqueue_record(EventRecord {
            generation,
            envelope: envelope.clone(),
            receipt: Some(sender),
            acknowledgement: None,
        })?;
        Ok(receiver)
    }

    fn enqueue_record(&self, record: EventRecord) -> Result<(), String> {
        let state = self
            .state
            .lock()
            .map_err(|_| EVENT_OUTPUT_UNAVAILABLE.to_string())?;
        let EventOutputState::Running { sender, terminal } = &*state else {
            return Err(EVENT_OUTPUT_UNAVAILABLE.into());
        };
        if terminal.load(Ordering::Acquire) {
            return Err(EVENT_OUTPUT_UNAVAILABLE.into());
        }
        match sender.try_send(record) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                Err(EVENT_OUTPUT_UNAVAILABLE.into())
            }
        }
    }

    #[cfg(test)]
    fn with_sink(
        capacity: usize,
        sink: Box<dyn EventSink>,
        projector: Arc<WebViewProjector>,
    ) -> Self {
        Self {
            state: Mutex::new(spawn_worker(capacity, sink, projector)),
        }
    }
}

fn spawn_worker(
    capacity: usize,
    mut sink: Box<dyn EventSink>,
    projector: Arc<WebViewProjector>,
) -> EventOutputState {
    let (sender, receiver) = sync_channel::<EventRecord>(capacity);
    let terminal = Arc::new(AtomicBool::new(false));
    let worker_terminal = Arc::clone(&terminal);
    std::thread::spawn(move || {
        while let Ok(record) = receiver.recv() {
            let mut sink_failed = false;
            let emit = || match sink.emit(&record.envelope) {
                Ok(()) => Ok(()),
                Err(()) => {
                    sink_failed = true;
                    Err(EVENT_OUTPUT_UNAVAILABLE.into())
                }
            };
            let result = if let Some(acknowledgement) = &record.acknowledgement {
                projector.emit_ack_if_active(
                    record.generation,
                    &record.envelope,
                    &acknowledgement.correlation,
                    || {
                        acknowledgement
                            .settlement
                            .is_pending(&acknowledgement.correlation)
                    },
                    emit,
                    || {
                        acknowledgement
                            .settlement
                            .settle(&acknowledgement.correlation, acknowledgement.accepted)
                    },
                )
            } else {
                projector.emit_if_active(record.generation, &record.envelope, emit)
            };
            if let Some(receipt) = record.receipt {
                let _ = receipt.try_send(result.clone());
            }
            if sink_failed {
                worker_terminal.store(true, Ordering::Release);
                return;
            }
            // Stale/deactivated records fail their receipt and are dropped;
            // they do not poison the application-lifetime queue.
        }
    });
    EventOutputState::Running { sender, terminal }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::projector::PublicOperationClass;
    use crate::protocol::ProtocolKind;
    use serde_json::{Map, Value};
    use std::sync::Barrier;
    use std::time::{Duration, Instant};

    fn raw_envelope(sequence: u64) -> Envelope {
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

    fn committed(projector: &WebViewProjector, raw_sequence: u64) -> Envelope {
        let mut safe = None;
        projector
            .project_and_deliver(1, &raw_envelope(raw_sequence), |envelope| {
                safe = Some(envelope.clone());
                Ok(())
            })
            .unwrap();
        safe.unwrap()
    }

    fn committed_ack(
        projector: &WebViewProjector,
        settlement: &AckSettlement,
    ) -> (Envelope, std::sync::mpsc::Receiver<bool>) {
        let correlation = "web-cancel-atomic-1";
        let receiver = settlement.register(correlation.into()).unwrap();
        projector
            .register_public_origin(correlation, 1, PublicOperationClass::Cancellation)
            .unwrap();
        let mut payload = Map::new();
        payload.insert("accepted".into(), Value::Bool(true));
        let raw = Envelope {
            version: 1,
            kind: ProtocolKind::Ack,
            id: "sidecar-ack-atomic-1".into(),
            correlation_id: Some(correlation.into()),
            decision_id: None,
            sequence: 2,
            payload,
            error: None,
        };
        let safe = projector
            .project_and_deliver_authorised(
                1,
                &raw,
                || settlement.is_pending(correlation),
                |envelope| Ok(envelope.clone()),
                |_| (false, Ok(())),
            )
            .unwrap();
        (safe, receiver)
    }

    fn projector() -> Arc<WebViewProjector> {
        let projector = Arc::new(WebViewProjector::default());
        projector.activate_generation(1).unwrap();
        projector
            .register_public_origin("web-stream-1", 1, PublicOperationClass::Stream)
            .unwrap();
        projector
    }

    struct BlockingSink {
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
        calls: Arc<Mutex<usize>>,
    }

    impl EventSink for BlockingSink {
        fn emit(&mut self, _envelope: &Envelope) -> Result<(), ()> {
            *self.calls.lock().unwrap() += 1;
            self.entered.wait();
            self.release.wait();
            Ok(())
        }
    }

    struct FailingSink;

    impl EventSink for FailingSink {
        fn emit(&mut self, _envelope: &Envelope) -> Result<(), ()> {
            Err(())
        }
    }

    #[test]
    fn deactivation_waits_for_linearised_sink_and_stale_records_never_emit_after_return() {
        let projector = projector();
        let safe = committed(&projector, 1);
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let calls = Arc::new(Mutex::new(0));
        let queue = EventOutputQueue::with_sink(
            2,
            Box::new(BlockingSink {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                calls: Arc::clone(&calls),
            }),
            Arc::clone(&projector),
        );
        let first = queue.enqueue_with_receipt(1, &safe).unwrap();
        entered.wait();
        let deactivating = Arc::clone(&projector);
        let (done_sender, done_receiver) = std::sync::mpsc::channel();
        let deactivation = std::thread::spawn(move || {
            deactivating.deactivate_generation(1).unwrap();
            done_sender.send(()).unwrap();
        });
        assert!(matches!(
            done_receiver.recv_timeout(Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        release.wait();
        assert_eq!(first.recv_timeout(Duration::from_secs(1)), Ok(Ok(())));
        done_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        deactivation.join().unwrap();
        let stale = queue.enqueue_with_receipt(1, &safe).unwrap();
        assert!(stale.recv_timeout(Duration::from_secs(1)).unwrap().is_err());
        assert_eq!(*calls.lock().unwrap(), 1);
    }

    #[test]
    fn successful_ack_sink_settles_before_competing_deactivation_returns() {
        let projector = projector();
        let settlement = AckSettlement::default();
        let (safe, native_receiver) = committed_ack(&projector, &settlement);
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let calls = Arc::new(Mutex::new(0));
        let queue = EventOutputQueue::with_sink(
            1,
            Box::new(BlockingSink {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                calls: Arc::clone(&calls),
            }),
            Arc::clone(&projector),
        );
        let receipt = queue
            .enqueue_ack_with_receipt(1, &safe, settlement.clone())
            .unwrap();
        entered.wait();
        let deactivating = Arc::clone(&projector);
        let (done_sender, done_receiver) = std::sync::mpsc::channel();
        let deactivation = std::thread::spawn(move || {
            deactivating.deactivate_generation(1).unwrap();
            done_sender.send(()).unwrap();
        });
        assert!(matches!(
            done_receiver.recv_timeout(Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        release.wait();
        assert_eq!(receipt.recv_timeout(Duration::from_secs(1)), Ok(Ok(())));
        assert_eq!(
            native_receiver.recv_timeout(Duration::from_secs(1)),
            Ok(true)
        );
        done_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        deactivation.join().unwrap();
        assert_eq!(*calls.lock().unwrap(), 1);
        assert!(!settlement.is_pending("web-cancel-atomic-1"));
    }

    #[test]
    fn stalled_sink_leaves_enqueue_bounded_and_full_queue_fails_closed() {
        let projector = projector();
        let safe = committed(&projector, 1);
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let queue = EventOutputQueue::with_sink(
            1,
            Box::new(BlockingSink {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                calls: Arc::new(Mutex::new(0)),
            }),
            projector,
        );
        queue.enqueue(1, &safe).unwrap();
        entered.wait();
        queue.enqueue(1, &safe).unwrap();
        let started = Instant::now();
        assert_eq!(
            queue.enqueue(1, &safe),
            Err(EVENT_OUTPUT_UNAVAILABLE.into())
        );
        assert!(started.elapsed() < Duration::from_millis(100));
        release.wait();
    }

    #[test]
    fn emitter_failure_is_terminal_and_receipt_reports_failure() {
        let projector = projector();
        let safe = committed(&projector, 1);
        let queue = EventOutputQueue::with_sink(1, Box::new(FailingSink), projector);
        let receipt = queue.enqueue_with_receipt(1, &safe).unwrap();
        assert!(
            receipt
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .is_err()
        );
        let deadline = Instant::now() + Duration::from_secs(1);
        while queue.enqueue(1, &safe).is_ok() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            queue.enqueue(1, &safe),
            Err(EVENT_OUTPUT_UNAVAILABLE.into())
        );
    }

    #[test]
    fn uninitialised_queue_fails_closed() {
        assert_eq!(
            EventOutputQueue::default().enqueue(1, &raw_envelope(1)),
            Err(EVENT_OUTPUT_UNAVAILABLE.into())
        );
    }
}
