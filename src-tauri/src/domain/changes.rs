use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeSummary {
    pub capability_id: String,
    pub path_label: String,
    pub additions: u32,
    pub deletions: u32,
    pub binary: bool,
    pub truncated: bool,
    pub undo_generation: Option<u64>,
}

impl ChangeSummary {
    pub fn validate(&self) -> Result<(), String> {
        if self.capability_id.is_empty()
            || self.capability_id.len() > 128
            || self.path_label.chars().count() > 512
            || self.additions.saturating_add(self.deletions) > 1_000_000
        {
            Err("change-summary-invalid".into())
        } else {
            Ok(())
        }
    }

    pub fn revoke_undo(&mut self) {
        self.undo_generation = None;
    }
    pub fn can_undo(&self, current_generation: u64) -> bool {
        self.undo_generation == Some(current_generation)
    }
}
