//! Routes public sidecar messages to the stream that is waiting for them.
//!
//! Every stream reads its own bounded mailbox, keyed by the request ID the
//! sidecar echoes as `correlationId`, so concurrent streams never consume or
//! discard each other's events. Acknowledgements and snapshots are shared
//! work that any live stream may project; they go to the cancelled stream
//! when known, otherwise to the oldest live stream. Everything else, and
//! anything that arrives while no stream is listening, uses the general
//! queue that status requests and harnesses read.

use super::stdio::GenerationControl;
use crate::protocol::{Envelope, ProtocolKind};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::mpsc::{
    Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError, sync_channel,
};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::Duration;

pub(super) type PublicMessage = Result<Envelope, String>;

const MAX_ROUTES: usize = 64;
const MAX_ALIASES: usize = 64;
pub(crate) const RECEIVE_TIMED_OUT: &str = "sidecar receive timed out";
const RESPONSE_CHANNEL_CLOSED: &str = "sidecar response channel closed";
const STALE_GENERATION: &str = "stale sidecar generation";

#[derive(Default)]
struct RouteTable {
    // Registration order, so shared work always has one deterministic owner.
    routes: Vec<(String, SyncSender<PublicMessage>)>,
    aliases: HashMap<String, String>,
}

impl RouteTable {
    fn route(&self, id: &str) -> Option<&SyncSender<PublicMessage>> {
        self.routes
            .iter()
            .find(|(route_id, _)| route_id == id)
            .map(|(_, sender)| sender)
    }
}

pub(crate) struct PublicRouter {
    capacity: usize,
    table: Mutex<RouteTable>,
    general_sender: SyncSender<PublicMessage>,
    general_receiver: Mutex<Receiver<PublicMessage>>,
}

impl PublicRouter {
    pub(super) fn new(capacity: usize) -> Self {
        let (general_sender, general_receiver) = sync_channel(capacity);
        Self {
            capacity,
            table: Mutex::new(RouteTable::default()),
            general_sender,
            general_receiver: Mutex::new(general_receiver),
        }
    }

    fn table(&self) -> MutexGuard<'_, RouteTable> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Accepts one decoded public envelope without blocking. `false` means
    /// its destination is full, which the dispatcher treats as fatal exactly
    /// as it did for the single shared queue.
    pub(super) fn route(&self, envelope: Envelope) -> bool {
        let mut table = self.table();
        let correlation = envelope.correlation_id.clone();
        let mut target = correlation
            .as_deref()
            .and_then(|id| table.route(id).cloned());
        if target.is_none()
            && let Some(alias) = correlation.as_deref()
            && envelope.kind == ProtocolKind::Ack
            && let Some(stream) = table.aliases.remove(alias)
        {
            target = table.route(&stream).cloned();
        }
        if target.is_none() && shared_work(&envelope) {
            target = table.routes.first().map(|(_, sender)| sender.clone());
        }
        drop(table);
        let sender = target.as_ref().unwrap_or(&self.general_sender);
        match sender.try_send(Ok(envelope)) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
        }
    }

    /// Tells every waiting reader why the generation ended.
    pub(super) fn fail(&self, message: &str) {
        let table = self.table();
        for (_, sender) in &table.routes {
            let _ = sender.try_send(Err(message.to_owned()));
        }
        let _ = self.general_sender.try_send(Err(message.to_owned()));
    }

    fn register(&self, id: &str) -> Result<Receiver<PublicMessage>, String> {
        let mut table = self.table();
        if table.routes.len() >= MAX_ROUTES || table.route(id).is_some() {
            return Err("sidecar stream route unavailable".into());
        }
        let (sender, receiver) = sync_channel(self.capacity);
        table.routes.push((id.to_owned(), sender));
        Ok(receiver)
    }

    fn unregister(&self, id: &str) {
        let mut table = self.table();
        table.routes.retain(|(route_id, _)| route_id != id);
        table.aliases.retain(|_, stream| stream != id);
    }

    /// Sends the acknowledgement for `alias` to the stream it cancels.
    pub(super) fn alias(&self, alias: &str, stream: &str) -> bool {
        let mut table = self.table();
        if table.route(stream).is_none()
            || table.aliases.len() >= MAX_ALIASES
            || table.aliases.contains_key(alias)
        {
            return false;
        }
        table.aliases.insert(alias.to_owned(), stream.to_owned());
        true
    }

    fn general(&self) -> MutexGuard<'_, Receiver<PublicMessage>> {
        self.general_receiver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<PublicMessage, RecvTimeoutError> {
        self.general().recv_timeout(timeout)
    }

    #[cfg(test)]
    pub(super) fn try_recv(&self) -> Result<PublicMessage, TryRecvError> {
        self.general().try_recv()
    }

    /// Takes one queued general message if no other reader holds the queue.
    fn try_take_general(&self) -> Option<PublicMessage> {
        match self.general_receiver.try_lock() {
            Ok(receiver) => receiver.try_recv().ok(),
            Err(TryLockError::Poisoned(receiver)) => receiver.into_inner().try_recv().ok(),
            Err(TryLockError::WouldBlock) => None,
        }
    }
}

fn shared_work(envelope: &Envelope) -> bool {
    envelope.kind == ProtocolKind::Ack
        || envelope.kind == ProtocolKind::Response
            && envelope
                .payload
                .get("snapshot")
                .is_some_and(Value::is_object)
}

/// One stream's mailbox. Dropping it stops routing to the stream.
pub(crate) struct PublicRoute {
    id: String,
    receiver: Receiver<PublicMessage>,
    router: Arc<PublicRouter>,
    control: Arc<GenerationControl>,
}

impl PublicRoute {
    pub(super) fn open(
        router: &Arc<PublicRouter>,
        control: &Arc<GenerationControl>,
        id: &str,
    ) -> Result<Self, String> {
        Ok(Self {
            id: id.to_owned(),
            receiver: router.register(id)?,
            router: Arc::clone(router),
            control: Arc::clone(control),
        })
    }

    /// Waits for this stream's next message without holding any supervisor
    /// lock. Messages queued while no stream was listening are drained here
    /// too, so the general queue cannot silently fill.
    pub(crate) fn receive(&self, timeout: Duration) -> Result<Envelope, String> {
        if !self.control.is_active() {
            return Err(self.ending_reason());
        }
        if let Some(message) = self.router.try_take_general() {
            return message;
        }
        match self.receiver.recv_timeout(timeout) {
            Ok(message) => message,
            Err(RecvTimeoutError::Timeout) if self.control.is_active() => {
                Err(RECEIVE_TIMED_OUT.into())
            }
            Err(RecvTimeoutError::Timeout) => Err(self.ending_reason()),
            Err(RecvTimeoutError::Disconnected) => Err(RESPONSE_CHANNEL_CLOSED.into()),
        }
    }

    fn ending_reason(&self) -> String {
        loop {
            match self.receiver.try_recv() {
                Ok(Err(reason)) => return reason,
                Ok(Ok(_)) => {}
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => {
                    return STALE_GENERATION.into();
                }
            }
        }
    }
}

impl Drop for PublicRoute {
    fn drop(&mut self) {
        self.router.unregister(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control() -> Arc<GenerationControl> {
        Arc::new(GenerationControl::new(i32::MAX, Arc::new(Mutex::new(None))))
    }

    fn event(id: &str, correlation: &str) -> Envelope {
        serde_json::from_value(serde_json::json!({
            "version":1,"kind":"event","id":id,"correlationId":correlation,"sequence":1,
            "payload":{"eventType":"stream.delta","text":id}
        }))
        .unwrap()
    }

    fn ack(id: &str, correlation: &str) -> Envelope {
        serde_json::from_value(serde_json::json!({
            "version":1,"kind":"ack","id":id,"correlationId":correlation,"sequence":1,
            "payload":{"accepted":true}
        }))
        .unwrap()
    }

    fn received_ids(route: &PublicRoute) -> Vec<String> {
        let mut ids = Vec::new();
        while let Ok(envelope) = route.receive(Duration::from_millis(5)) {
            ids.push(envelope.id);
        }
        ids
    }

    #[test]
    fn concurrent_streams_each_receive_only_their_own_events() {
        let router = Arc::new(PublicRouter::new(16));
        let control = control();
        let first = PublicRoute::open(&router, &control, "web-turn-a").unwrap();
        let second = PublicRoute::open(&router, &control, "web-turn-b").unwrap();
        for (id, correlation) in [
            ("sidecar-1", "web-turn-a"),
            ("sidecar-2", "web-turn-b"),
            ("sidecar-3", "web-turn-b"),
            ("sidecar-4", "web-turn-a"),
        ] {
            assert!(router.route(event(id, correlation)));
        }
        // The second stream reads first; it must not swallow the first's work.
        assert_eq!(received_ids(&second), ["sidecar-2", "sidecar-3"]);
        assert_eq!(received_ids(&first), ["sidecar-1", "sidecar-4"]);
    }

    #[test]
    fn shared_work_reaches_the_cancelled_stream_or_the_oldest_listener() {
        let router = Arc::new(PublicRouter::new(16));
        let control = control();
        let first = PublicRoute::open(&router, &control, "web-turn-a").unwrap();
        let second = PublicRoute::open(&router, &control, "web-turn-b").unwrap();
        assert!(router.alias("web-stop-b", "web-turn-b"));
        assert!(router.route(ack("sidecar-ack-b", "web-stop-b")));
        assert!(router.route(ack("sidecar-ack-unknown", "web-stop-unknown")));
        assert_eq!(received_ids(&second), ["sidecar-ack-b"]);
        assert_eq!(received_ids(&first), ["sidecar-ack-unknown"]);
    }

    #[test]
    fn unrouted_messages_use_the_general_queue_and_are_drained_by_listeners() {
        let router = Arc::new(PublicRouter::new(16));
        let control = control();
        assert!(router.route(event("sidecar-orphan", "web-finished")));
        assert!(matches!(router.try_recv(), Ok(Ok(envelope)) if envelope.id == "sidecar-orphan"));
        assert!(router.route(event("sidecar-late", "web-finished")));
        let listener = PublicRoute::open(&router, &control, "web-turn-a").unwrap();
        assert_eq!(received_ids(&listener), ["sidecar-late"]);
        drop(listener);
        assert!(router.route(event("sidecar-after-close", "web-turn-a")));
        assert!(
            matches!(router.try_recv(), Ok(Ok(envelope)) if envelope.id == "sidecar-after-close")
        );
    }

    #[test]
    fn failure_reaches_every_listener_and_an_inactive_generation_stops_waiting() {
        let router = Arc::new(PublicRouter::new(16));
        let control = control();
        let first = PublicRoute::open(&router, &control, "web-turn-a").unwrap();
        let second = PublicRoute::open(&router, &control, "web-turn-b").unwrap();
        router.fail("sidecar stdout closed unexpectedly");
        control.deactivate();
        for route in [&first, &second] {
            assert_eq!(
                route.receive(Duration::from_secs(5)).unwrap_err(),
                "sidecar stdout closed unexpectedly"
            );
        }
        let started = std::time::Instant::now();
        assert_eq!(
            first.receive(Duration::from_secs(5)).unwrap_err(),
            STALE_GENERATION
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_full_mailbox_is_reported_and_routes_are_bounded_and_unique() {
        let router = Arc::new(PublicRouter::new(1));
        let control = control();
        let route = PublicRoute::open(&router, &control, "web-turn-a").unwrap();
        assert!(PublicRoute::open(&router, &control, "web-turn-a").is_err());
        assert!(router.route(event("sidecar-1", "web-turn-a")));
        assert!(!router.route(event("sidecar-2", "web-turn-a")));
        drop(route);
        let mut routes = Vec::new();
        for index in 0..MAX_ROUTES {
            routes.push(PublicRoute::open(&router, &control, &format!("web-{index}")).unwrap());
        }
        assert!(PublicRoute::open(&router, &control, "web-overflow").is_err());
    }
}
