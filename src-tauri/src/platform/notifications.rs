use serde::Serialize;
use tauri::{AppHandle, Manager};
use tauri_plugin_notification::NotificationExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotificationKind {
    ApprovalWaiting,
    WorkComplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafeNotification {
    pub kind: NotificationKind,
    pub title: &'static str,
    pub body: String,
    pub opens_piui_only: bool,
}

pub fn notification(
    kind: NotificationKind,
    context_label: &str,
    app_is_active: bool,
) -> Option<SafeNotification> {
    if app_is_active {
        return None;
    }
    let body_label: String = context_label.chars().take(120).collect();
    Some(match kind {
        NotificationKind::ApprovalWaiting => SafeNotification {
            kind,
            title: "PIUI needs your review",
            body: format!("A local action is waiting in {body_label}. Open PIUI to decide."),
            opens_piui_only: true,
        },
        NotificationKind::WorkComplete => SafeNotification {
            kind,
            title: "PIUI finished the current work",
            body: format!("{body_label} is ready to review."),
            opens_piui_only: true,
        },
    })
}

pub fn send(app: &AppHandle, kind: NotificationKind, context_label: &str) -> Result<bool, String> {
    let Some(window) = app.get_webview_window("main") else {
        return Err("notification-window-unavailable".into());
    };
    let active = window
        .is_focused()
        .map_err(|_| "notification-window-state-unavailable")?;
    let safe_label = sanitise_context_label(context_label);
    let Some(notification) = notification(kind, &safe_label, active) else {
        return Ok(false);
    };
    app.notification()
        .builder()
        .title(notification.title)
        .body(notification.body)
        .auto_cancel()
        .show()
        .map_err(|_| "notification-send-failed")?;
    Ok(true)
}

fn sanitise_context_label(value: &str) -> String {
    let clean: String = value
        .chars()
        .filter(|character| !character.is_control())
        .take(120)
        .collect::<String>()
        .trim()
        .to_owned();
    if clean.is_empty() {
        "the current project".into()
    } else {
        clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_application_suppresses_notifications() {
        assert!(notification(NotificationKind::WorkComplete, "Project", true).is_none());
    }

    #[test]
    fn approval_notification_never_contains_a_decision() {
        let value = notification(NotificationKind::ApprovalWaiting, "Project", false)
            .expect("inactive application should produce an intent");
        assert!(value.opens_piui_only);
        assert!(!value.body.to_ascii_lowercase().contains("approve"));
        assert!(!value.body.to_ascii_lowercase().contains("deny"));
    }

    #[test]
    fn context_labels_are_bounded_and_single_line() {
        let value = sanitise_context_label(&format!("{}\nsecret", "x".repeat(200)));
        assert!(value.chars().count() <= 120);
        assert!(!value.contains('\n'));
    }
}
