use crate::protocol::Envelope;
use std::collections::{HashSet, VecDeque};

#[derive(Debug, PartialEq, Eq)]
pub enum SequenceOutcome { Accepted, Duplicate, Stale, Gap }

#[derive(Default)]
pub struct SequenceRouter {
    last_sequence: Option<u64>,
    acknowledgements: HashSet<String>,
    acknowledgement_order: VecDeque<String>,
    resynchronisation_pending: bool,
}

impl SequenceRouter {
    pub fn observe(&mut self, envelope: &Envelope) -> SequenceOutcome {
        if let Some(correlation) = envelope.correlation_id.as_ref() {
            if !self.acknowledgements.insert(correlation.clone()) { return SequenceOutcome::Duplicate; }
            self.acknowledgement_order.push_back(correlation.clone());
            if self.acknowledgement_order.len() > 512 { if let Some(old) = self.acknowledgement_order.pop_front() { self.acknowledgements.remove(&old); } }
        }
        match self.last_sequence {
            Some(last) if envelope.sequence < last => SequenceOutcome::Stale,
            Some(last) if envelope.sequence == last => SequenceOutcome::Duplicate,
            Some(last) if envelope.sequence != last + 1 => { self.resynchronisation_pending = true; SequenceOutcome::Gap }
            _ => { self.last_sequence = Some(envelope.sequence); SequenceOutcome::Accepted }
        }
    }
    pub fn take_resynchronisation(&mut self) -> bool { std::mem::take(&mut self.resynchronisation_pending) }
    pub fn apply_snapshot(&mut self, sequence: u64) { if self.last_sequence.is_none_or(|last| sequence >= last) { self.last_sequence = Some(sequence); self.resynchronisation_pending = false; } }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(sequence: u64) -> Envelope { serde_json::from_value(serde_json::json!({"version":1,"kind":"event","id":format!("e-{sequence}"),"sequence":sequence,"payload":{"eventType":"sidecar.status"}})).unwrap() }
    #[test] fn gaps_do_not_advance_state() { let mut router=SequenceRouter::default(); assert_eq!(router.observe(&event(1)),SequenceOutcome::Accepted); assert_eq!(router.observe(&event(3)),SequenceOutcome::Gap); assert!(router.take_resynchronisation()); router.apply_snapshot(3); assert_eq!(router.observe(&event(4)),SequenceOutcome::Accepted); }
}
