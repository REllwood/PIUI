use crate::protocol::{Envelope, ProtocolKind};
use std::collections::{HashSet, VecDeque};

const MAX_ACKNOWLEDGEMENTS: usize = 512;

#[derive(Debug, PartialEq, Eq)]
pub enum SequenceOutcome {
    Accepted,
    Duplicate,
    Stale,
    Gap,
}

#[derive(Default)]
pub struct SequenceRouter {
    last_sequence: Option<u64>,
    acknowledgements: HashSet<String>,
    acknowledgement_order: VecDeque<String>,
    resynchronisation_needed: bool,
    resynchronisation_issued: bool,
}

impl SequenceRouter {
    pub fn observe(&mut self, envelope: &Envelope) -> SequenceOutcome {
        let outcome = match self.last_sequence {
            Some(last) if envelope.sequence < last => SequenceOutcome::Stale,
            Some(last) if envelope.sequence == last => SequenceOutcome::Duplicate,
            Some(last) if envelope.sequence != last + 1 => {
                self.resynchronisation_needed = true;
                SequenceOutcome::Gap
            }
            _ => SequenceOutcome::Accepted,
        };
        if outcome != SequenceOutcome::Accepted {
            return outcome;
        }

        if matches!(envelope.kind, ProtocolKind::Ack | ProtocolKind::Response)
            && let Some(correlation) = envelope.correlation_id.as_ref()
        {
            if !self.acknowledgements.insert(correlation.clone()) {
                self.last_sequence = Some(envelope.sequence);
                return SequenceOutcome::Duplicate;
            }
            self.acknowledgement_order.push_back(correlation.clone());
            if self.acknowledgement_order.len() > MAX_ACKNOWLEDGEMENTS
                && let Some(oldest) = self.acknowledgement_order.pop_front()
            {
                self.acknowledgements.remove(&oldest);
            }
        }

        self.last_sequence = Some(envelope.sequence);
        SequenceOutcome::Accepted
    }

    pub fn last_sequence(&self) -> Option<u64> {
        self.last_sequence
    }

    pub fn take_resynchronisation(&mut self) -> bool {
        if !self.resynchronisation_needed || self.resynchronisation_issued {
            return false;
        }
        self.resynchronisation_issued = true;
        true
    }

    pub fn apply_snapshot(&mut self, sequence: u64) -> bool {
        if self.last_sequence.is_some_and(|last| sequence < last) {
            return false;
        }
        self.last_sequence = Some(sequence);
        self.resynchronisation_needed = false;
        self.resynchronisation_issued = false;
        true
    }

    /// Accepts one correlated snapshot response across the gap it repairs and
    /// records its correlation in the same bounded duplicate history used by
    /// ordinary responses. A later response with the same correlation is then
    /// classified as duplicate even when it has a fresh envelope ID.
    pub fn apply_correlated_snapshot(&mut self, envelope: &Envelope) -> bool {
        if envelope.kind != ProtocolKind::Response
            || envelope.correlation_id.is_none()
            || self
                .last_sequence
                .is_some_and(|last| envelope.sequence <= last)
        {
            return false;
        }
        let correlation = envelope
            .correlation_id
            .as_ref()
            .expect("correlation checked");
        if !self.acknowledgements.insert(correlation.clone()) {
            return false;
        }
        self.acknowledgement_order.push_back(correlation.clone());
        if self.acknowledgement_order.len() > MAX_ACKNOWLEDGEMENTS
            && let Some(oldest) = self.acknowledgement_order.pop_front()
        {
            self.acknowledgements.remove(&oldest);
        }
        self.last_sequence = Some(envelope.sequence);
        self.resynchronisation_needed = false;
        self.resynchronisation_issued = false;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(kind: &str, id: &str, sequence: u64, correlation: Option<&str>) -> Envelope {
        serde_json::from_value(serde_json::json!({
            "version": 1,
            "kind": kind,
            "id": id,
            "sequence": sequence,
            "payload": if kind == "event" {
                serde_json::json!({"eventType": "sidecar.status"})
            } else {
                serde_json::json!({})
            },
            "correlationId": correlation,
        }))
        .unwrap()
    }

    #[test]
    fn gaps_do_not_advance_and_request_one_resynchronisation() {
        let mut router = SequenceRouter::default();
        assert_eq!(
            router.observe(&envelope("event", "e-1", 1, None)),
            SequenceOutcome::Accepted
        );
        assert_eq!(
            router.observe(&envelope("event", "e-3", 3, None)),
            SequenceOutcome::Gap
        );
        assert_eq!(router.last_sequence(), Some(1));
        assert!(router.take_resynchronisation());
        assert!(!router.take_resynchronisation());
        assert_eq!(
            router.observe(&envelope("event", "e-3-repeat", 3, None)),
            SequenceOutcome::Gap
        );
        assert!(!router.take_resynchronisation());
        assert!(router.apply_snapshot(3));
        assert_eq!(
            router.observe(&envelope("event", "e-4", 4, None)),
            SequenceOutcome::Accepted
        );
        assert!(!router.apply_snapshot(2));
    }

    #[test]
    fn correlated_snapshot_crosses_gap_and_registers_duplicate_history_once() {
        let mut router = SequenceRouter::default();
        assert_eq!(
            router.observe(&envelope("event", "public-1", 1, None)),
            SequenceOutcome::Accepted
        );
        assert_eq!(
            router.observe(&envelope("event", "public-3", 3, None)),
            SequenceOutcome::Gap
        );
        let snapshot = envelope("response", "snapshot-4", 4, Some("rust-snapshot-1"));
        assert!(router.apply_correlated_snapshot(&snapshot));
        assert_eq!(router.last_sequence(), Some(4));
        assert!(!router.apply_correlated_snapshot(&snapshot));
        assert_eq!(
            router.observe(&envelope(
                "response",
                "snapshot-repeat-5",
                5,
                Some("rust-snapshot-1"),
            )),
            SequenceOutcome::Duplicate
        );
        assert_eq!(router.last_sequence(), Some(5));
    }

    #[test]
    fn shared_stream_correlation_is_not_treated_as_duplicate_acknowledgement() {
        let mut router = SequenceRouter::default();
        assert_eq!(
            router.observe(&envelope("event", "chunk-1", 1, Some("request-1"))),
            SequenceOutcome::Accepted
        );
        assert_eq!(
            router.observe(&envelope("event", "chunk-2", 2, Some("request-1"))),
            SequenceOutcome::Accepted
        );
        assert_eq!(
            router.observe(&envelope("ack", "ack-1", 3, Some("request-1"))),
            SequenceOutcome::Accepted
        );
        assert_eq!(
            router.observe(&envelope("ack", "ack-2", 4, Some("request-1"))),
            SequenceOutcome::Duplicate
        );
    }
}
