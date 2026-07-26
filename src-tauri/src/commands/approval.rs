use super::bridge::BridgeState;
use crate::domain::approval::{
    ApprovalGroupSubmission, ApprovalSnapshot, ApprovalSubmission, ApprovalView,
};
use tauri::State;

#[tauri::command]
pub fn approval_pending(state: State<'_, BridgeState>) -> Result<Vec<ApprovalView>, String> {
    state.approval_registry().pending()
}

#[tauri::command]
pub fn approval_snapshot(state: State<'_, BridgeState>) -> Result<ApprovalSnapshot, String> {
    state.approval_registry().snapshot()
}

#[tauri::command]
pub fn approval_submit(
    state: State<'_, BridgeState>,
    submission: ApprovalSubmission,
) -> Result<(), String> {
    state.approval_registry().submit(submission)
}

/// The WebView supplies only Rust-minted opaque group coordinates. Membership,
/// workspace authority, risk and private correlations never cross this command.
#[tauri::command]
pub fn approval_submit_group(
    state: State<'_, BridgeState>,
    submission: ApprovalGroupSubmission,
) -> Result<(), String> {
    state.approval_registry().submit_group(submission)
}
