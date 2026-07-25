use serde::Serialize;

pub mod commands;
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
    tauri::Builder::default()
        .setup(|app| {
            use tauri::Manager;
            let paths = supervisor::SupervisorPaths::from_app(app.handle())
                .map_err(std::io::Error::other)?;
            app.manage(commands::bridge::BridgeState::new(paths));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            host_status,
            commands::bridge::sidecar_start,
            commands::bridge::sidecar_status,
            commands::bridge::sidecar_stop,
            commands::bridge::bridge_send,
            commands::stream::stream_probe,
            commands::stream::cancel_stream,
        ])
        .run(tauri::generate_context!())
        .expect("PIUI failed to start its native host");
}

#[cfg(test)]
mod tests {
    use super::host_status;

    #[test]
    fn status_is_local_and_listener_free() {
        let status = host_status();
        assert_eq!(status.status, "ready");
        assert_eq!(status.transport, "inherited-stdio");
        assert!(!status.listener);
    }
}
