use super::bridge::BridgeState;
use crate::domain::approval::{ApprovalSubmission, ApprovalView};
use tauri::State;

#[tauri::command]
pub fn approval_pending(state: State<'_, BridgeState>) -> Result<Vec<ApprovalView>, String> {
    state.approval_registry().pending()
}

#[tauri::command]
pub fn approval_submit(
    state: State<'_, BridgeState>,
    submission: ApprovalSubmission,
) -> Result<(), String> {
    state.approval_registry().submit(submission)
}
