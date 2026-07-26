use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    mpsc::{Receiver, SyncSender, sync_channel},
};

const ACK_STATE_UNAVAILABLE: &str = "acknowledgement state unavailable";
const ACK_DELIVERY_UNAVAILABLE: &str = "acknowledgement delivery unavailable";
const ACK_CAPACITY_EXCEEDED: &str = "acknowledgement capacity exceeded";
const MAX_PENDING_ACKNOWLEDGEMENTS: usize = 512;

/// Narrow shared authority for native cancellation waiter registration,
/// abandonment, and durable settlement. It exposes no supervisor or bridge
/// state and is safe to pass to the sole event-output worker. Pending map
/// admission is atomically capped at the public-origin capacity; its retained
/// allocation therefore cannot grow beyond that bounded high-water mark.
#[derive(Clone, Default)]
pub(crate) struct AckSettlement {
    waiters: Arc<Mutex<HashMap<String, SyncSender<bool>>>>,
}

impl AckSettlement {
    pub(crate) fn register(&self, id: String) -> Result<Receiver<bool>, String> {
        let (sender, receiver) = sync_channel(1);
        let mut waiters = self
            .waiters
            .lock()
            .map_err(|_| ACK_STATE_UNAVAILABLE.to_string())?;
        if waiters.contains_key(&id) {
            return Err("acknowledgement already pending".into());
        }
        if waiters.len() >= MAX_PENDING_ACKNOWLEDGEMENTS {
            return Err(ACK_CAPACITY_EXCEEDED.into());
        }
        waiters.insert(id, sender);
        Ok(receiver)
    }

    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        self.waiters.lock().map_or(0, |waiters| waiters.len())
    }

    pub(crate) fn is_pending(&self, id: &str) -> bool {
        self.waiters
            .lock()
            .is_ok_and(|waiters| waiters.contains_key(id))
    }

    pub(crate) fn remove_pending(&self, id: &str) -> bool {
        self.waiters
            .lock()
            .is_ok_and(|mut waiters| waiters.remove(id).is_some())
    }

    /// Removes the map entry before sending. A disconnected receiver still
    /// leaves no ambiguous pending entry and is reported fail-closed.
    pub(crate) fn settle(&self, id: &str, accepted: bool) -> Result<(), String> {
        let sender = self
            .waiters
            .lock()
            .map_err(|_| ACK_STATE_UNAVAILABLE.to_string())?
            .remove(id)
            .ok_or_else(|| ACK_DELIVERY_UNAVAILABLE.to_string())?;
        sender
            .try_send(accepted)
            .map_err(|_| ACK_DELIVERY_UNAVAILABLE.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Barrier,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn sequential_capacity_rejects_513th_and_removal_admits_one_fresh_waiter() {
        let settlement = AckSettlement::default();
        let mut receivers = Vec::with_capacity(MAX_PENDING_ACKNOWLEDGEMENTS);
        for index in 0..MAX_PENDING_ACKNOWLEDGEMENTS {
            receivers.push(
                settlement
                    .register(format!("web-capacity-{index}"))
                    .unwrap(),
            );
        }
        assert_eq!(settlement.pending_len(), MAX_PENDING_ACKNOWLEDGEMENTS);
        assert_eq!(
            settlement.register("web-capacity-overflow".into()).err(),
            Some(ACK_CAPACITY_EXCEEDED.into())
        );
        assert!(settlement.is_pending("web-capacity-0"));
        assert!(settlement.is_pending("web-capacity-511"));
        assert_eq!(
            settlement.register("web-capacity-0".into()).err(),
            Some("acknowledgement already pending".into())
        );
        assert!(settlement.is_pending("web-capacity-0"));

        assert!(settlement.remove_pending("web-capacity-256"));
        let fresh = settlement.register("web-capacity-fresh".into()).unwrap();
        assert_eq!(settlement.pending_len(), MAX_PENDING_ACKNOWLEDGEMENTS);
        assert!(settlement.is_pending("web-capacity-fresh"));
        assert!(settlement.is_pending("web-capacity-0"));
        assert!(settlement.is_pending("web-capacity-511"));
        drop(fresh);
        drop(receivers);
    }

    #[test]
    fn concurrent_saturation_never_observes_more_than_fixed_capacity() {
        const WORKERS: usize = 32;
        const ATTEMPTS_PER_WORKER: usize = 32;
        let settlement = AckSettlement::default();
        let start = Arc::new(Barrier::new(WORKERS + 1));
        let maximum_observed = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::with_capacity(WORKERS);
        for worker in 0..WORKERS {
            let settlement = settlement.clone();
            let start = Arc::clone(&start);
            let maximum_observed = Arc::clone(&maximum_observed);
            workers.push(std::thread::spawn(move || {
                start.wait();
                for attempt in 0..ATTEMPTS_PER_WORKER {
                    let _ = settlement.register(format!("web-concurrent-{worker}-{attempt}"));
                    maximum_observed.fetch_max(settlement.pending_len(), Ordering::SeqCst);
                }
            }));
        }
        start.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(settlement.pending_len(), MAX_PENDING_ACKNOWLEDGEMENTS);
        assert!(maximum_observed.load(Ordering::SeqCst) <= MAX_PENDING_ACKNOWLEDGEMENTS);
        assert_eq!(
            settlement.register("web-concurrent-overflow".into()).err(),
            Some(ACK_CAPACITY_EXCEEDED.into())
        );
    }
}
