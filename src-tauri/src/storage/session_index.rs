use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionIndexRecord {
    pub session_id: String,
    pub title: String,
    pub project_label: String,
    pub status: String,
    pub branch: Option<String>,
    pub modified_unix_ms: u64,
}

#[derive(Default)]
pub struct SessionIndex {
    records: BTreeMap<String, SessionIndexRecord>,
}

impl SessionIndex {
    pub fn rebuild(records: impl IntoIterator<Item = SessionIndexRecord>) -> Result<Self, String> {
        let mut index = Self::default();
        for record in records {
            if record.session_id.is_empty()
                || record.session_id.len() > 160
                || record.title.chars().count() > 200
                || index
                    .records
                    .insert(record.session_id.clone(), record)
                    .is_some()
            {
                return Err("session-index-invalid".into());
            }
        }
        Ok(index)
    }

    pub fn search(&self, query: &str) -> Vec<SessionIndexRecord> {
        let query = query.to_lowercase();
        let mut results: Vec<_> = self
            .records
            .values()
            .filter(|record| {
                format!(
                    "{} {} {} {}",
                    record.title,
                    record.project_label,
                    record.status,
                    record.branch.as_deref().unwrap_or_default()
                )
                .to_lowercase()
                .contains(&query)
            })
            .cloned()
            .collect();
        results.sort_by_key(|record| std::cmp::Reverse(record.modified_unix_ms));
        results
    }
}
