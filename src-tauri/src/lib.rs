use serde::Serialize;

pub mod commands;
pub mod credentials;
pub mod platform;
pub mod protocol;
pub mod supervisor;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HostStatus {
    status: &'static str,
    architecture: &'static str,
    transport: &'static str,
    listener: bool,
}

#[tauri::command]
fn host_status() -> HostStatus {
    HostStatus {
        status: "ready",
        architecture: std::env::consts::ARCH,
        transport: "inherited-stdio",
        listener: false,
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .setup(|app| {
            use tauri::Manager;
            let paths = supervisor::SupervisorPaths::from_app(app.handle())
                .map_err(std::io::Error::other)?;
            app.manage(commands::bridge::BridgeState::new(paths));
            app.manage(commands::credentials::CredentialSheetState::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            host_status,
            commands::bridge::sidecar_start,
            commands::bridge::sidecar_status,
            commands::bridge::sidecar_restart,
            commands::bridge::sidecar_stop,
            commands::bridge::bridge_send,
            commands::credentials::present_credential_sheet,
            commands::stream::stream_probe,
            commands::stream::cancel_stream,
        ])
        .build(tauri::generate_context!())
        .expect("PIUI failed to build its native host");

    app.run(|app_handle, event| match event {
        tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit => {
            stop_managed_sidecar(app_handle);
        }
        tauri::RunEvent::WindowEvent {
            event: tauri::WindowEvent::Destroyed,
            ..
        } => {
            use tauri::Manager;
            if should_stop_after_window_destroy(app_handle.webview_windows().len()) {
                stop_managed_sidecar(app_handle);
            }
        }
        _ => {}
    });
}

fn should_stop_after_window_destroy(remaining_windows: usize) -> bool {
    remaining_windows == 0
}

fn stop_managed_sidecar(app_handle: &tauri::AppHandle) {
    use tauri::Manager;
    if let Some(state) = app_handle.try_state::<commands::bridge::BridgeState>() {
        let _ = commands::bridge::bridge_stop_transport(state.inner());
    }
}

#[cfg(test)]
mod tests {
    use super::{host_status, should_stop_after_window_destroy};

    #[test]
    fn status_is_local_and_listener_free() {
        let status = host_status();
        assert_eq!(status.status, "ready");
        assert_eq!(status.transport, "inherited-stdio");
        assert!(!status.listener);
    }

    #[test]
    fn only_the_destroyed_final_window_stops_background_transport() {
        assert!(should_stop_after_window_destroy(0));
        assert!(!should_stop_after_window_destroy(1));
        assert!(!should_stop_after_window_destroy(2));
    }
}
