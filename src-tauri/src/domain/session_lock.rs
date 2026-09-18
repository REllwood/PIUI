use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionLock {
    pub session_id: String,
    pub owner_pid: u32,
    pub owner_start_time: u64,
    pub generation: u64,
    pub file_device: u64,
    pub file_inode: u64,
}

impl SessionLock {
    pub fn may_replace(&self, observed_owner_start_time: Option<u64>) -> bool {
        observed_owner_start_time != Some(self.owner_start_time)
    }

    pub fn owns(&self, pid: u32, start_time: u64, generation: u64) -> bool {
        self.owner_pid == pid
            && self.owner_start_time == start_time
            && self.generation == generation
    }
}
