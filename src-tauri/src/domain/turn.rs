use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TurnState {
    Sending,
    Streaming,
    ToolRunning,
    StopRequested,
    Stopped,
    CancelTooLate,
    Failed,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnRecord {
    pub request_id: String,
    pub session_id: String,
    pub generation: u64,
    pub state: TurnState,
    pub sequence: u64,
    pub retained_text: String,
}

#[derive(Default)]
pub struct TurnRegistry {
    active: Mutex<HashMap<String, TurnRecord>>,
    terminals: Mutex<VecDeque<String>>,
}

impl TurnRegistry {
    pub fn begin(
        &self,
        request_id: String,
        session_id: String,
        generation: u64,
    ) -> Result<TurnRecord, String> {
        let mut active = self.active.lock().map_err(|_| "turn-state-unavailable")?;
        if active.contains_key(&request_id) {
            return Err("turn-request-duplicate".into());
        }
        let record = TurnRecord {
            request_id: request_id.clone(),
            session_id,
            generation,
            state: TurnState::Sending,
            sequence: 1,
            retained_text: String::new(),
        };
        active.insert(request_id, record.clone());
        Ok(record)
    }

    pub fn transition(
        &self,
        request_id: &str,
        next: TurnState,
        text: Option<&str>,
    ) -> Result<TurnRecord, String> {
        let mut active = self.active.lock().map_err(|_| "turn-state-unavailable")?;
        let record = active.get_mut(request_id).ok_or("turn-request-unknown")?;
        if !valid_transition(record.state, next) {
            return Err("turn-transition-invalid".into());
        }
        record.state = next;
        record.sequence = record
            .sequence
            .checked_add(1)
            .ok_or("turn-sequence-exhausted")?;
        if let Some(chunk) = text {
            let remaining = 4 * 1024 * 1024usize - record.retained_text.len().min(4 * 1024 * 1024);
            record
                .retained_text
                .push_str(&chunk.chars().take(remaining).collect::<String>());
        }
        let result = record.clone();
        if matches!(
            next,
            TurnState::Stopped | TurnState::Failed | TurnState::Complete
        ) {
            active.remove(request_id);
            let mut terminals = self
                .terminals
                .lock()
                .map_err(|_| "turn-state-unavailable")?;
            terminals.push_back(request_id.into());
            while terminals.len() > 512 {
                terminals.pop_front();
            }
        }
        Ok(result)
    }
}

fn valid_transition(current: TurnState, next: TurnState) -> bool {
    matches!(
        (current, next),
        (
            TurnState::Sending,
            TurnState::Streaming | TurnState::Failed | TurnState::StopRequested
        ) | (
            TurnState::Streaming,
            TurnState::ToolRunning
                | TurnState::StopRequested
                | TurnState::Failed
                | TurnState::Complete
        ) | (
            TurnState::ToolRunning,
            TurnState::Streaming
                | TurnState::StopRequested
                | TurnState::Failed
                | TurnState::Complete
        ) | (
            TurnState::StopRequested,
            TurnState::Stopped | TurnState::CancelTooLate | TurnState::Failed
        ) | (
            TurnState::CancelTooLate,
            TurnState::Streaming | TurnState::ToolRunning | TurnState::Failed | TurnState::Complete
        )
    )
}
