use crate::platform::attachments::{AttachmentRegistry, AttachmentView};
use crate::platform::opener::DisclosedExternalUrl;
use crate::storage::schema::WindowRecord;
use tauri::{AppHandle, State, WebviewWindow};

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotificationRequest {
    kind: String,
    context_label: String,
}

fn require_main_window(window: &WebviewWindow) -> Result<(), String> {
    if window.label() != "main" {
        return Err("window-operation-rejected".into());
    }
    Ok(())
}

pub fn current_window_record(window: &WebviewWindow) -> Result<WindowRecord, String> {
    require_main_window(window)?;
    let scale_factor = window
        .scale_factor()
        .map_err(|_| "window-state-unavailable")?;
    let size = window
        .inner_size()
        .map_err(|_| "window-state-unavailable")?
        .to_logical::<f64>(scale_factor);
    let maximised = window
        .is_maximized()
        .map_err(|_| "window-state-unavailable")?;
    let record = WindowRecord {
        width: size.width,
        height: size.height,
        maximised,
    };
    if !record.width.is_finite()
        || !record.height.is_finite()
        || !(680.0..=8_192.0).contains(&record.width)
        || !(560.0..=8_192.0).contains(&record.height)
    {
        return Err("window-state-invalid".into());
    }
    Ok(record)
}

#[tauri::command]
pub fn open_disclosed_external(target: String) -> Result<(), String> {
    let target = DisclosedExternalUrl::parse(&target)?;
    #[cfg(target_os = "macos")]
    {
        crate::platform::opener::open_external(&target)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = target;
        Err("external-open-unsupported".into())
    }
}

#[tauri::command]
pub async fn attachment_select(
    window: WebviewWindow,
    registry: State<'_, AttachmentRegistry>,
) -> Result<Option<AttachmentView>, String> {
    let selected = crate::platform::present_native_attachment_picker(window)
        .await
        .map_err(|error| error.code().to_string())?;
    selected
        .map(|path| registry.register_selected(&path))
        .transpose()
}

#[tauri::command]
pub fn attachment_remove(
    registry: State<'_, AttachmentRegistry>,
    capability_id: String,
) -> Result<(), String> {
    if !capability_id.starts_with("attachment-") || capability_id.len() != 43 {
        return Err("attachment-capability-invalid".into());
    }
    registry.remove(&capability_id).map(|_| ())
}

#[tauri::command]
pub fn close_main_window(window: WebviewWindow) -> Result<(), String> {
    require_main_window(&window)?;
    window.close().map_err(|_| "window-close-failed".into())
}

#[tauri::command]
pub fn notification_send(
    app: AppHandle,
    window: WebviewWindow,
    request: NotificationRequest,
) -> Result<bool, String> {
    require_main_window(&window)?;
    if request.context_label.len() > 512 {
        return Err("notification-context-invalid".into());
    }
    let kind = match request.kind.as_str() {
        "approval-waiting" => crate::platform::notifications::NotificationKind::ApprovalWaiting,
        "work-complete" => crate::platform::notifications::NotificationKind::WorkComplete,
        _ => return Err("notification-kind-invalid".into()),
    };
    crate::platform::notifications::send(&app, kind, &request.context_label)
}

#[tauri::command]
pub fn window_current_state(window: WebviewWindow) -> Result<WindowRecord, String> {
    current_window_record(&window)
}

#[tauri::command]
pub fn window_apply_state(
    window: WebviewWindow,
    window_state: WindowRecord,
) -> Result<WindowRecord, String> {
    require_main_window(&window)?;
    if !window_state.width.is_finite()
        || !window_state.height.is_finite()
        || !(680.0..=8_192.0).contains(&window_state.width)
        || !(560.0..=8_192.0).contains(&window_state.height)
    {
        return Err("window-state-invalid".into());
    }
    if window_state.maximised {
        window.maximize().map_err(|_| "window-state-apply-failed")?;
    } else {
        window
            .unmaximize()
            .map_err(|_| "window-state-apply-failed")?;
        window
            .set_size(tauri::LogicalSize::new(
                window_state.width,
                window_state.height,
            ))
            .map_err(|_| "window-state-apply-failed")?;
    }
    current_window_record(&window)
}
