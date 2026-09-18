use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionState {
    pub id: String,
    pub workspace_id: String,
    pub generation: u64,
    pub title: String,
    pub writable: bool,
    pub parent_id: Option<String>,
}

#[derive(Default)]
pub struct SessionRegistry {
    records: Mutex<HashMap<String, SessionState>>,
    active: Mutex<Option<String>>,
}

impl SessionRegistry {
    pub fn create(&self, workspace_id: String, title: String) -> Result<SessionState, String> {
        let id = format!("session-{}", Uuid::new_v4().simple());
        let session = SessionState {
            id: id.clone(),
            workspace_id,
            generation: 1,
            title: title.chars().take(160).collect(),
            writable: true,
            parent_id: None,
        };
        self.replace_active(session)
    }

    pub fn resume(&self, id: &str, expected_generation: u64) -> Result<SessionState, String> {
        let record = self
            .records
            .lock()
            .map_err(|_| "session-state-unavailable")?
            .get(id)
            .cloned()
            .ok_or("session-unknown")?;
        if record.generation != expected_generation {
            return Err("session-generation-stale".into());
        }
        self.replace_active(SessionState {
            generation: record.generation + 1,
            writable: true,
            ..record
        })
    }

    pub fn fork(&self, id: &str, expected_generation: u64) -> Result<SessionState, String> {
        let parent = self
            .records
            .lock()
            .map_err(|_| "session-state-unavailable")?
            .get(id)
            .cloned()
            .ok_or("session-unknown")?;
        if parent.generation != expected_generation {
            return Err("session-generation-stale".into());
        }
        let fork = SessionState {
            id: format!("session-{}", Uuid::new_v4().simple()),
            workspace_id: parent.workspace_id,
            generation: 1,
            title: format!("{} — branch", parent.title),
            writable: true,
            parent_id: Some(parent.id),
        };
        self.replace_active(fork)
    }

    fn replace_active(&self, session: SessionState) -> Result<SessionState, String> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| "session-state-unavailable")?;
        let mut active = self
            .active
            .lock()
            .map_err(|_| "session-state-unavailable")?;
        if let Some(previous_id) = active.as_ref()
            && let Some(previous) = records.get_mut(previous_id)
        {
            previous.writable = false;
        }
        records.insert(session.id.clone(), session.clone());
        *active = Some(session.id.clone());
        Ok(session)
    }
}
