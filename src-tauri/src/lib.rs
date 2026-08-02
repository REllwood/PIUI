use serde::Serialize;

#[cfg(feature = "a23-credential-test")]
#[doc(hidden)]
pub mod a23_credential_maintenance;
pub mod commands;
pub mod credentials;
pub mod domain;
pub mod platform;
pub mod protocol;
pub mod security;
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

#[cfg(feature = "architecture-test")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArchitectureTestMode {
    Markdown,
    Lifecycle,
    Accessibility,
}

#[cfg(all(feature = "architecture-test", target_os = "macos"))]
#[derive(Clone, Debug)]
struct ArchitectureTestActivation {
    mode: ArchitectureTestMode,
    _nonce: String,
    port: u16,
}

#[cfg(feature = "architecture-test")]
struct ArchitectureTestRuntime {
    mode: ArchitectureTestMode,
}

#[cfg(all(feature = "architecture-test", target_os = "macos"))]
fn architecture_test_activation() -> Result<Option<ArchitectureTestActivation>, std::io::Error> {
    let mode = architecture_environment_value("PIUI_ARCHITECTURE_TEST_MODE")?;
    let nonce = architecture_environment_value("PIUI_ARCHITECTURE_TEST_NONCE")?;
    let port = architecture_environment_value("PIUI_ARCHITECTURE_TEST_PORT")?;
    parse_architecture_test_activation(mode, nonce, port)
}

#[cfg(all(feature = "architecture-test", target_os = "macos"))]
fn parse_architecture_test_activation(
    mode: Option<String>,
    nonce: Option<String>,
    port: Option<String>,
) -> Result<Option<ArchitectureTestActivation>, std::io::Error> {
    let (mode, nonce, port) = match (mode, nonce, port) {
        (None, None, None) => return Ok(None),
        (Some(mode), Some(nonce), Some(port)) => (mode, nonce, port),
        _ => return Err(architecture_activation_error()),
    };
    let mode = match mode.as_str() {
        "a26-markdown" => ArchitectureTestMode::Markdown,
        "a27-lifecycle" if cfg!(feature = "a27-lifecycle-test") => ArchitectureTestMode::Lifecycle,
        "a28-accessibility" => ArchitectureTestMode::Accessibility,
        _ => return Err(architecture_activation_error()),
    };
    if nonce.len() != 64
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(architecture_activation_error());
    }
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(architecture_activation_error());
    }
    let parsed_port = port
        .parse::<u16>()
        .map_err(|_| architecture_activation_error())?;
    if parsed_port.to_string() != port || !(49_152..=65_535).contains(&parsed_port) {
        return Err(architecture_activation_error());
    }
    Ok(Some(ArchitectureTestActivation {
        mode,
        _nonce: nonce,
        port: parsed_port,
    }))
}

#[cfg(all(feature = "architecture-test", target_os = "macos"))]
fn architecture_environment_value(name: &str) -> Result<Option<String>, std::io::Error> {
    std::env::var_os(name)
        .map(|value| {
            value
                .into_string()
                .map_err(|_| architecture_activation_error())
        })
        .transpose()
}

#[cfg(all(feature = "architecture-test", target_os = "macos"))]
fn architecture_activation_error() -> std::io::Error {
    std::io::Error::other("architecture test activation rejected")
}

#[cfg(all(feature = "architecture-test", target_os = "macos"))]
fn register_architecture_driver(
    builder: tauri::Builder<tauri::Wry>,
    port: u16,
) -> tauri::Builder<tauri::Wry> {
    builder.plugin(tauri_plugin_wdio_webdriver::init_with_port(port))
}

fn register_a26_asset_protocol(
    builder: tauri::Builder<tauri::Wry>,
    assets: std::sync::Arc<domain::assets::OpaqueAssetRegistry>,
) -> tauri::Builder<tauri::Wry> {
    builder.register_uri_scheme_protocol("piui-raster", move |context, request| {
        use tauri::http::{HeaderValue, Response, StatusCode, header};

        let path_and_query = request
            .uri()
            .path_and_query()
            .map_or_else(|| request.uri().path(), |value| value.as_str());
        let resolved = assets.resolve_request(
            context.webview_label(),
            request.method().as_str(),
            path_and_query,
        );
        let Some(asset) = resolved else {
            let mut response = Response::new(Vec::new());
            *response.status_mut() = StatusCode::NOT_FOUND;
            return response;
        };

        let mut response = Response::new(asset.bytes.to_vec());
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(asset.mime.as_str()),
        );
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, max-age=0"),
        );
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("inline"),
        );
        headers.insert(
            header::HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        );
        if let Ok(length) = HeaderValue::from_str(&response.body().len().to_string()) {
            response
                .headers_mut()
                .insert(header::CONTENT_LENGTH, length);
        } else {
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response.body_mut().clear();
        }
        response
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(all(feature = "architecture-test", target_os = "macos"))]
    let architecture_activation = match architecture_test_activation() {
        Ok(activation) => activation,
        Err(_) => panic!("architecture test activation rejected"),
    };
    #[cfg(all(feature = "architecture-test", target_os = "macos"))]
    let architecture_activation_for_setup = architecture_activation.clone();
    let a26_assets = std::sync::Arc::new(domain::assets::OpaqueAssetRegistry::default());

    let app = tauri::Builder::default().plugin(security::navigation::init());
    #[cfg(all(feature = "architecture-test", target_os = "macos"))]
    let app = match architecture_activation.as_ref() {
        Some(activation) => register_architecture_driver(app, activation.port),
        None => app,
    };
    let app = register_a26_asset_protocol(app, std::sync::Arc::clone(&a26_assets));
    let app = app.setup(move |app| {
        use tauri::Manager;
        let paths =
            supervisor::SupervisorPaths::from_app(app.handle()).map_err(std::io::Error::other)?;
        let credential_proxy = app_credential_proxy()?;
        #[cfg(not(feature = "a23-credential-test"))]
        app.manage(commands::bridge::BridgeState::new_with_credentials(
            paths,
            credential_proxy.clone(),
        ));
        #[cfg(feature = "a23-credential-test")]
        let a23_evidence =
            commands::a23_native_evidence::A23NativeEvidenceState::from_environment()?;
        #[cfg(feature = "a23-credential-test")]
        app.manage(commands::bridge::BridgeState::new_with_credentials_and_a23(
            paths,
            credential_proxy.clone(),
            a23_evidence.clone(),
        ));
        #[cfg(not(feature = "a23-credential-test"))]
        app.manage(commands::credentials::CredentialSheetState::new(
            credential_proxy,
        ));
        #[cfg(feature = "a23-credential-test")]
        app.manage(
            commands::credentials::CredentialSheetState::new_with_a23_secret(
                credential_proxy,
                read_a23_canary_descriptor()?,
            ),
        );
        #[cfg(feature = "a23-credential-test")]
        app.manage(a23_evidence);
        #[cfg(all(feature = "architecture-test", target_os = "macos"))]
        if let Some(activation) = architecture_activation_for_setup.as_ref() {
            app.manage(ArchitectureTestRuntime {
                mode: activation.mode,
            });
            match activation.mode {
                ArchitectureTestMode::Markdown => {
                    app.manage(commands::a26_markdown::A26MarkdownState::new(
                        std::sync::Arc::clone(&a26_assets),
                    ));
                }
                ArchitectureTestMode::Lifecycle => {
                    #[cfg(feature = "a27-lifecycle-test")]
                    app.manage(commands::a27_lifecycle::A27LifecycleState::from_environment()?);
                    #[cfg(not(feature = "a27-lifecycle-test"))]
                    return Err(architecture_activation_error().into());
                }
                ArchitectureTestMode::Accessibility => {}
            }
        }
        Ok(())
    });
    let generated_handler: fn(tauri::ipc::Invoke<tauri::Wry>) -> bool = tauri::generate_handler![
        host_status,
        commands::bridge::sidecar_start,
        commands::bridge::sidecar_status,
        commands::bridge::sidecar_restart,
        commands::bridge::sidecar_stop,
        commands::bridge::bridge_send,
        commands::credentials::present_credential_sheet,
        #[cfg(feature = "a23-credential-test")]
        commands::credentials::credential_lifecycle_status,
        commands::approval::approval_pending,
        commands::approval::approval_snapshot,
        commands::approval::approval_submit,
        commands::approval::approval_submit_group,
        commands::workspace::workspace_select_directory,
        commands::workspace::workspace_inspect,
        commands::workspace::workspace_open_untrusted,
        commands::workspace::workspace_authorise,
        commands::workspace::workspace_load_trusted,
        commands::workspace::workspace_revoke,
        commands::stream::stream_probe,
        commands::stream::cancel_stream,
        #[cfg(feature = "a27-lifecycle-test")]
        commands::a27_lifecycle::a27_lifecycle_snapshot,
        #[cfg(feature = "a27-lifecycle-test")]
        commands::a27_lifecycle::a27_observe_duplicate_start,
        #[cfg(feature = "a27-lifecycle-test")]
        commands::a27_lifecycle::a27_prepare_waiting_approval,
        #[cfg(feature = "a27-lifecycle-test")]
        commands::a27_lifecycle::a27_force_sidecar_death,
        #[cfg(feature = "a27-lifecycle-test")]
        commands::a27_lifecycle::a27_recover_after_death,
        #[cfg(feature = "a27-lifecycle-test")]
        commands::a27_lifecycle::a27_user_restart,
        #[cfg(feature = "a27-lifecycle-test")]
        commands::a27_lifecycle::a27_resume_after_reopen,
        #[cfg(feature = "a27-lifecycle-test")]
        commands::a27_lifecycle::a27_request_quit,
    ];
    #[cfg(feature = "architecture-test")]
    let a26_generated_handler: fn(tauri::ipc::Invoke<tauri::Wry>) -> bool = tauri::generate_handler![
        commands::a26_markdown::a26_markdown_prepare,
        commands::a26_markdown::a26_markdown_evidence,
    ];
    #[cfg(feature = "a27-lifecycle-test")]
    let a27_generated_handler: fn(tauri::ipc::Invoke<tauri::Wry>) -> bool = tauri::generate_handler![
        commands::a27_lifecycle::a27_lifecycle_snapshot,
        commands::a27_lifecycle::a27_observe_duplicate_start,
        commands::a27_lifecycle::a27_prepare_waiting_approval,
        commands::a27_lifecycle::a27_force_sidecar_death,
        commands::a27_lifecycle::a27_recover_after_death,
        commands::a27_lifecycle::a27_user_restart,
        commands::a27_lifecycle::a27_resume_after_reopen,
        commands::a27_lifecycle::a27_request_quit,
    ];
    let app = app.invoke_handler(move |invoke: tauri::ipc::Invoke<tauri::Wry>| {
        #[cfg(feature = "a23-credential-test")]
        {
            use tauri::Manager;
            let recorded = invoke
                .message
                .webview_ref()
                .app_handle()
                .try_state::<commands::a23_native_evidence::A23NativeEvidenceState>()
                .ok_or_else(|| "a23-native-evidence-unavailable".to_string())
                .and_then(|state| {
                    state.record_invoke_entry(invoke.message.command(), invoke.message.payload())
                });
            if recorded.is_err() {
                invoke.resolver.reject("a23-native-evidence-unavailable");
                return true;
            }
        }
        #[cfg(feature = "architecture-test")]
        {
            use tauri::Manager;
            let app_handle = invoke.message.webview_ref().app_handle();
            let runtime = app_handle.try_state::<ArchitectureTestRuntime>();
            if matches!(
                runtime.as_ref().map(|runtime| runtime.mode),
                Some(ArchitectureTestMode::Markdown)
            ) {
                let Some(state) =
                    app_handle.try_state::<commands::a26_markdown::A26MarkdownState>()
                else {
                    invoke.resolver.reject("a26-markdown-invoke-rejected");
                    return true;
                };
                let label = invoke.message.webview_ref().label();
                let command = invoke.message.command();
                let accepted = state.record_invoke_entry(label, command, invoke.message.payload());
                if !accepted {
                    invoke.resolver.reject("a26-markdown-invoke-rejected");
                    return true;
                }
                return a26_generated_handler(invoke);
            }
            #[cfg(feature = "a27-lifecycle-test")]
            if matches!(
                runtime.as_ref().map(|runtime| runtime.mode),
                Some(ArchitectureTestMode::Lifecycle)
            ) {
                let command = invoke.message.command();
                let accepted = invoke.message.webview_ref().label() == "main"
                    && architecture_invoke_payload_is_empty(invoke.message.payload())
                    && matches!(
                        command,
                        "a27_lifecycle_snapshot"
                            | "a27_observe_duplicate_start"
                            | "a27_prepare_waiting_approval"
                            | "a27_force_sidecar_death"
                            | "a27_recover_after_death"
                            | "a27_user_restart"
                            | "a27_resume_after_reopen"
                            | "a27_request_quit"
                    );
                if !accepted {
                    invoke.resolver.reject("a27-lifecycle-invoke-rejected");
                    return true;
                }
                return a27_generated_handler(invoke);
            }
            if matches!(
                runtime.as_ref().map(|runtime| runtime.mode),
                Some(ArchitectureTestMode::Accessibility)
            ) {
                invoke.resolver.reject("a28-accessibility-invoke-rejected");
                return true;
            }
        }
        generated_handler(invoke)
    });
    #[cfg(all(feature = "architecture-test", target_os = "macos"))]
    let mut context = tauri::generate_context!();
    #[cfg(not(all(feature = "architecture-test", target_os = "macos")))]
    let context = tauri::generate_context!();
    #[cfg(all(feature = "architecture-test", target_os = "macos"))]
    if let Some(activation) = architecture_activation.as_ref() {
        let route = match activation.mode {
            ArchitectureTestMode::Markdown => "index.html?spike=markdown-packaged",
            ArchitectureTestMode::Lifecycle => "index.html?spike=lifecycle-packaged",
            ArchitectureTestMode::Accessibility => "index.html?spike=accessibility-packaged",
        };
        let main_window = context
            .config_mut()
            .app
            .windows
            .iter_mut()
            .find(|window| window.label == "main")
            .unwrap_or_else(|| panic!("architecture test main window unavailable"));
        main_window.url = tauri::WebviewUrl::App(route.into());
    }
    let app = app
        .build(context)
        .expect("PIUI failed to build its native host");

    app.run(|app_handle, event| match event {
        tauri::RunEvent::ExitRequested { api, .. } => {
            if stop_managed_sidecar(app_handle).is_err()
                || record_a27_exit_requested(app_handle).is_err()
            {
                api.prevent_exit();
                record_a27_shutdown_failure(app_handle);
            }
        }
        tauri::RunEvent::Exit => {
            if stop_managed_sidecar(app_handle).is_err()
                || publish_a27_exit_evidence(app_handle).is_err()
            {
                record_a27_shutdown_failure(app_handle);
                eprintln!("PIUI could not complete native shutdown");
            }
        }
        tauri::RunEvent::WindowEvent {
            event: tauri::WindowEvent::Destroyed,
            ..
        } => {
            use tauri::Manager;
            if should_stop_after_window_destroy(app_handle.webview_windows().len()) {
                let stopped = stop_managed_sidecar(app_handle);
                let recorded = match stopped {
                    Ok(()) => record_a27_last_window_close(app_handle),
                    Err(error) => Err(error),
                };
                if recorded.is_err() {
                    record_a27_shutdown_failure(app_handle);
                    if restore_main_window(app_handle).is_err() {
                        eprintln!("PIUI could not restore its main window");
                    }
                }
            }
        }
        #[cfg(target_os = "macos")]
        tauri::RunEvent::Reopen { .. } => {
            if record_a27_reopen(app_handle).is_err() {
                record_a27_shutdown_failure(app_handle);
            }
            if restore_main_window(app_handle).is_err() {
                record_a27_shutdown_failure(app_handle);
                eprintln!("PIUI could not restore its main window");
            }
        }
        _ => {}
    });
}

#[cfg(feature = "architecture-test")]
fn architecture_invoke_payload_is_empty(payload: &tauri::ipc::InvokeBody) -> bool {
    matches!(
        payload,
        tauri::ipc::InvokeBody::Json(serde_json::Value::Object(arguments))
            if arguments.is_empty()
    )
}

#[cfg(not(feature = "a23-credential-test"))]
fn app_credential_proxy() -> Result<credentials::CredentialProxy, std::io::Error> {
    Ok(credentials::CredentialProxy::default())
}

#[cfg(feature = "a23-credential-test")]
fn read_a23_canary_descriptor() -> Result<credentials::SecretMaterial, std::io::Error> {
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::FromRawFd;
    use zeroize::Zeroize;

    const A23_CANARY_FD: i32 = 6;
    let descriptor_flags = unsafe { libc::fcntl(A23_CANARY_FD, libc::F_GETFD) };
    if descriptor_flags < 0 {
        return Err(std::io::Error::other("A.23 canary descriptor unavailable"));
    }
    // SAFETY: The feature-only runner gives the host sole ownership of fixed
    // descriptor 6. Constructing File transfers that ownership and closes it
    // immediately after this one bounded read.
    let file = unsafe { File::from_raw_fd(A23_CANARY_FD) };
    let metadata = file
        .metadata()
        .map_err(|_| std::io::Error::other("A.23 canary descriptor invalid"))?;
    if !valid_a23_canary_descriptor(&metadata) {
        return Err(std::io::Error::other("A.23 canary descriptor invalid"));
    }
    let mut bytes = Vec::with_capacity(58);
    file.take(58)
        .read_to_end(&mut bytes)
        .map_err(|_| std::io::Error::other("A.23 canary descriptor unreadable"))?;
    let valid = bytes.len() == 57
        && bytes.starts_with(b"PIUI_A23_")
        && bytes[9..].iter().all(u8::is_ascii_hexdigit);
    if !valid {
        bytes.zeroize();
        return Err(std::io::Error::other("A.23 canary descriptor invalid"));
    }
    credentials::SecretMaterial::new(bytes)
        .map_err(|_| std::io::Error::other("A.23 canary descriptor invalid"))
}

#[cfg(feature = "a23-credential-test")]
fn valid_a23_canary_descriptor(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    (metadata.file_type().is_fifo() || metadata.file_type().is_socket())
        && metadata.uid() == unsafe { libc::geteuid() }
}

#[cfg(feature = "a23-credential-test")]
fn app_credential_proxy() -> Result<credentials::CredentialProxy, std::io::Error> {
    let namespace = std::env::var("PIUI_A23_TEST_NAMESPACE")
        .map_err(|_| std::io::Error::other("A.23 isolated namespace unavailable"))?;
    if !a23_credential_maintenance::valid_a23_namespace(&namespace) {
        return Err(std::io::Error::other("A.23 isolated namespace invalid"));
    }
    let repository = credentials::KeychainRepository::for_tests(&namespace)
        .map_err(|_| std::io::Error::other("A.23 isolated namespace invalid"))?;
    Ok(credentials::CredentialProxy::new(repository))
}

fn should_stop_after_window_destroy(remaining_windows: usize) -> bool {
    remaining_windows == 0
}

fn stop_managed_sidecar(app_handle: &tauri::AppHandle) -> Result<(), String> {
    use tauri::Manager;
    if let Some(state) = app_handle.try_state::<commands::bridge::BridgeState>() {
        commands::bridge::bridge_stop_transport(state.inner())?;
    }
    Ok(())
}

fn restore_main_window(app_handle: &tauri::AppHandle) -> Result<(), String> {
    use tauri::Manager;

    if let Some(window) = app_handle.get_webview_window("main") {
        window
            .show()
            .and_then(|()| window.set_focus())
            .map_err(|_| "main window restoration failed".to_string())?;
        return Ok(());
    }
    let config = app_handle
        .config()
        .app
        .windows
        .iter()
        .find(|config| config.label == "main")
        .cloned()
        .ok_or_else(|| "main window restoration failed".to_string())?;
    let window = tauri::WebviewWindowBuilder::from_config(app_handle, &config)
        .and_then(tauri::WebviewWindowBuilder::build)
        .map_err(|_| "main window restoration failed".to_string())?;
    window
        .show()
        .and_then(|()| window.set_focus())
        .map_err(|_| "main window restoration failed".to_string())
}

fn record_a27_last_window_close(app_handle: &tauri::AppHandle) -> Result<(), String> {
    #[cfg(feature = "a27-lifecycle-test")]
    {
        use tauri::Manager;
        if let Some(lifecycle) =
            app_handle.try_state::<commands::a27_lifecycle::A27LifecycleState>()
        {
            lifecycle.record_last_window_close(0)?;
        }
    }
    #[cfg(not(feature = "a27-lifecycle-test"))]
    let _ = app_handle;
    Ok(())
}

fn record_a27_reopen(app_handle: &tauri::AppHandle) -> Result<(), String> {
    #[cfg(feature = "a27-lifecycle-test")]
    {
        use tauri::Manager;
        if let Some(lifecycle) =
            app_handle.try_state::<commands::a27_lifecycle::A27LifecycleState>()
        {
            lifecycle.record_reopen()?;
        }
    }
    #[cfg(not(feature = "a27-lifecycle-test"))]
    let _ = app_handle;
    Ok(())
}

fn record_a27_exit_requested(app_handle: &tauri::AppHandle) -> Result<(), String> {
    #[cfg(feature = "a27-lifecycle-test")]
    {
        use tauri::Manager;
        if let Some(lifecycle) =
            app_handle.try_state::<commands::a27_lifecycle::A27LifecycleState>()
        {
            lifecycle.record_exit_requested()?;
        }
    }
    #[cfg(not(feature = "a27-lifecycle-test"))]
    let _ = app_handle;
    Ok(())
}

fn publish_a27_exit_evidence(app_handle: &tauri::AppHandle) -> Result<(), String> {
    #[cfg(feature = "a27-lifecycle-test")]
    {
        use tauri::Manager;
        if let Some(lifecycle) =
            app_handle.try_state::<commands::a27_lifecycle::A27LifecycleState>()
        {
            lifecycle.record_exit_and_publish()?;
        }
    }
    #[cfg(not(feature = "a27-lifecycle-test"))]
    let _ = app_handle;
    Ok(())
}

fn record_a27_shutdown_failure(app_handle: &tauri::AppHandle) {
    #[cfg(feature = "a27-lifecycle-test")]
    {
        use tauri::Manager;
        if let Some(lifecycle) =
            app_handle.try_state::<commands::a27_lifecycle::A27LifecycleState>()
        {
            lifecycle.record_shutdown_failure();
        }
    }
    #[cfg(not(feature = "a27-lifecycle-test"))]
    let _ = app_handle;
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

    #[cfg(all(
        feature = "architecture-test",
        feature = "a27-lifecycle-test",
        target_os = "macos"
    ))]
    #[test]
    fn architecture_driver_activation_is_atomic_canonical_and_mode_bounded() {
        use super::{ArchitectureTestMode, parse_architecture_test_activation};

        assert!(
            parse_architecture_test_activation(None, None, None)
                .expect("dormant activation")
                .is_none()
        );
        for (mode, expected) in [
            ("a26-markdown", ArchitectureTestMode::Markdown),
            ("a27-lifecycle", ArchitectureTestMode::Lifecycle),
            ("a28-accessibility", ArchitectureTestMode::Accessibility),
        ] {
            let activation = parse_architecture_test_activation(
                Some(mode.to_string()),
                Some("a".repeat(64)),
                Some("49152".to_string()),
            )
            .expect("valid activation")
            .expect("active architecture mode");
            assert_eq!(activation.mode, expected);
            assert_eq!(activation.port, 49_152);
        }
        for malformed in [
            (Some("a26-markdown".into()), None, None),
            (
                Some("a26-markdown".into()),
                Some("A".repeat(64)),
                Some("49152".into()),
            ),
            (
                Some("a26-markdown".into()),
                Some("a".repeat(64)),
                Some("049152".into()),
            ),
            (
                Some("a26-markdown".into()),
                Some("a".repeat(64)),
                Some("49151".into()),
            ),
            (
                Some("unknown".into()),
                Some("a".repeat(64)),
                Some("49152".into()),
            ),
        ] {
            assert!(
                parse_architecture_test_activation(malformed.0, malformed.1, malformed.2).is_err()
            );
        }
    }

    #[cfg(feature = "a23-credential-test")]
    #[test]
    fn a23_canary_descriptor_rejects_regular_files() {
        let executable = std::env::current_exe().unwrap();
        let metadata = std::fs::metadata(executable).unwrap();
        assert!(!super::valid_a23_canary_descriptor(&metadata));
    }
}
