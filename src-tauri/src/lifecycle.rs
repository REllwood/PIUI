use std::collections::HashSet;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEvent {
    Started,
    WindowClosed,
    Reopened,
    SidecarCrashed,
    Restarted,
    UpdateRelaunch,
    QuitRequested,
    Exited,
}

#[derive(Default)]
pub struct LifecycleState {
    generation: Mutex<u64>,
    waiting_approvals: Mutex<HashSet<String>>,
}

impl LifecycleState {
    pub fn begin_generation(&self) -> Result<u64, String> {
        let mut generation = self
            .generation
            .lock()
            .map_err(|_| "lifecycle-unavailable")?;
        *generation = generation
            .checked_add(1)
            .ok_or("lifecycle-generation-exhausted")?;
        Ok(*generation)
    }

    pub fn register_waiting_approval(&self, id: String) -> Result<(), String> {
        self.waiting_approvals
            .lock()
            .map_err(|_| "lifecycle-unavailable")?
            .insert(id);
        Ok(())
    }

    pub fn fail_waiting_closed(&self) -> Result<Vec<String>, String> {
        let mut waiting = self
            .waiting_approvals
            .lock()
            .map_err(|_| "lifecycle-unavailable")?;
        let mut denied: Vec<_> = waiting.drain().collect();
        denied.sort();
        Ok(denied)
    }
}
