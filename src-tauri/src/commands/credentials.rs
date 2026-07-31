use crate::credentials::{CredentialMetadata, CredentialProxy, KeychainRepository, SecretMaterial};
use crate::platform::{
    CREDENTIAL_SHEET_BUSY, CredentialSheetDecision, CredentialSheetRequest, CredentialSheetResult,
    INVALID_CREDENTIAL_INPUT, present_native_credential_sheet,
};
#[cfg(feature = "a23-credential-test")]
use std::sync::Mutex;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tauri::{AppHandle, State, WebviewWindow};

const MAX_PROVIDER_LABEL_CHARS: usize = 80;

#[cfg(feature = "a23-credential-test")]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialLifecycleStatus {
    state: &'static str,
}

#[derive(Clone)]
pub struct CredentialSheetState {
    active: Arc<AtomicBool>,
    credential_proxy: CredentialProxy,
    #[cfg(feature = "a23-credential-test")]
    a23_secret: Arc<Mutex<Option<SecretMaterial>>>,
}

impl CredentialSheetState {
    pub fn new(credential_proxy: CredentialProxy) -> Self {
        Self {
            active: Arc::new(AtomicBool::new(false)),
            credential_proxy,
            #[cfg(feature = "a23-credential-test")]
            a23_secret: Arc::new(Mutex::new(None)),
        }
    }

    #[cfg(feature = "a23-credential-test")]
    pub fn new_with_a23_secret(credential_proxy: CredentialProxy, secret: SecretMaterial) -> Self {
        Self {
            active: Arc::new(AtomicBool::new(false)),
            credential_proxy,
            a23_secret: Arc::new(Mutex::new(Some(secret))),
        }
    }

    #[cfg(feature = "a23-credential-test")]
    fn take_a23_secret(&self) -> Result<SecretMaterial, String> {
        self.a23_secret
            .lock()
            .map_err(|_| "credential-store-unavailable".to_string())?
            .take()
            .ok_or_else(|| "credential-store-unavailable".to_string())
    }

    fn try_acquire(&self) -> Result<CredentialSheetPermit, String> {
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| CREDENTIAL_SHEET_BUSY.to_string())?;
        Ok(CredentialSheetPermit {
            active: Arc::clone(&self.active),
        })
    }
}

struct CredentialSheetPermit {
    active: Arc<AtomicBool>,
}

impl Drop for CredentialSheetPermit {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

#[tauri::command]
pub async fn present_credential_sheet(
    _app: AppHandle,
    window: WebviewWindow,
    state: State<'_, CredentialSheetState>,
    request: CredentialSheetRequest,
) -> Result<CredentialSheetResult, String> {
    let result = present_credential_sheet_inner(window, state.inner(), request).await;
    #[cfg(feature = "a23-credential-test")]
    {
        let recorded = record_a23_command_result(&_app, "present_credential_sheet", &result);
        if result.is_err() || recorded.is_err() {
            make_a23_native_failure_observable(&_app);
        }
        recorded?;
    }
    result
}

async fn present_credential_sheet_inner(
    window: WebviewWindow,
    state: &CredentialSheetState,
    request: CredentialSheetRequest,
) -> Result<CredentialSheetResult, String> {
    let provider_id = crate::credentials::proxy::normalise_provider_id(&request.provider_id)?;
    let provider_label = normalise_provider_label(&request.provider_label)?;
    let account_label = KeychainRepository::normalise_account_label(&request.account_label)
        .map_err(|error| error.code().to_string())?;
    let _permit = state.try_acquire()?;

    #[cfg(feature = "a23-credential-test")]
    let sheet = {
        if provider_id != "a23.fixture-provider" {
            return Err(INVALID_CREDENTIAL_INPUT.to_string());
        }
        present_native_credential_sheet(window, provider_label, state.take_a23_secret()?)
    };
    #[cfg(not(feature = "a23-credential-test"))]
    let sheet = present_native_credential_sheet(window, provider_label);
    let decision = sheet.await.map_err(|error| error.code().to_string())?;
    let result = match prepare_credential_completion(decision, account_label) {
        CredentialCompletion::Complete(result) => Ok(result),
        CredentialCompletion::Persist {
            account_label,
            secret,
        } => {
            let credential_proxy = state.credential_proxy.clone();
            tauri::async_runtime::spawn_blocking(move || {
                credential_proxy
                    .store_native_api_key(&provider_id, &account_label, secret)
                    .and_then(|credential_reference| {
                        signal_a23_credential_saved()?;
                        Ok(CredentialSheetResult::saved(
                            credential_reference,
                            account_label,
                        ))
                    })
                    .map_err(str::to_owned)
            })
            .await
            .map_err(|_| "keychain-unavailable".to_string())?
        }
    };
    result
}

#[cfg(feature = "a23-credential-test")]
fn make_a23_native_failure_observable(app: &AppHandle) {
    if publish_a23_native_failure().is_ok() {
        return;
    }
    use tauri::Manager;
    let stopped = app
        .try_state::<super::bridge::BridgeState>()
        .ok_or_else(|| "sidecar state unavailable".to_string())
        .and_then(|state| super::bridge::bridge_stop_transport(state.inner()));
    if stopped.is_err() {
        app.exit(70);
    }
}

#[cfg(not(feature = "a23-credential-test"))]
fn signal_a23_credential_saved() -> Result<(), &'static str> {
    Ok(())
}

#[cfg(feature = "a23-credential-test")]
fn publish_a23_native_failure() -> Result<(), &'static str> {
    let target = std::path::PathBuf::from(
        std::env::var_os("PIUI_A23_RESULT_PATH").ok_or("credential-store-unavailable")?,
    );
    publish_a23_native_failure_to(&target)
}

#[cfg(feature = "a23-credential-test")]
fn publish_a23_native_failure_to(target: &std::path::Path) -> Result<(), &'static str> {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    if !target.is_absolute()
        || target.file_name().and_then(|name| name.to_str()) != Some("lifecycle-result.json")
        || target.exists()
    {
        return Err("credential-store-unavailable");
    }
    let parent = target.parent().ok_or("credential-store-unavailable")?;
    let canonical_parent = fs::canonicalize(parent).map_err(|_| "credential-store-unavailable")?;
    let parent_metadata =
        fs::metadata(&canonical_parent).map_err(|_| "credential-store-unavailable")?;
    if parent != canonical_parent
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != unsafe { libc::geteuid() }
        || parent_metadata.mode() & 0o077 != 0
    {
        return Err("credential-store-unavailable");
    }
    let pending = canonical_parent.join("lifecycle-result.json.native-pending");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&pending)
        .map_err(|_| "credential-store-unavailable")?;
    file.write_all(b"{\"schemaVersion\":1,\"status\":\"fail\"}\n")
        .and_then(|()| file.sync_all())
        .map_err(|_| "credential-store-unavailable")?;
    drop(file);
    fs::hard_link(&pending, target).map_err(|_| "credential-store-unavailable")?;
    fs::remove_file(&pending).map_err(|_| "credential-store-unavailable")?;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(canonical_parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "credential-store-unavailable")
}

#[cfg(feature = "a23-credential-test")]
#[tauri::command]
pub fn credential_lifecycle_status(app: AppHandle) -> Result<CredentialLifecycleStatus, String> {
    let result = CredentialLifecycleStatus {
        state: a23_lifecycle_state(),
    };
    let recorded: Result<CredentialLifecycleStatus, String> = Ok(result);
    record_a23_command_result(&app, "credential_lifecycle_status", &recorded)?;
    recorded
}

#[cfg(feature = "a23-credential-test")]
fn a23_lifecycle_state() -> &'static str {
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let Some(path) = std::env::var_os("PIUI_A23_RESULT_PATH") else {
        return "failed";
    };
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return "pending",
        Err(_) => return "failed",
    };
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return "failed",
    };
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.size() > 512
    {
        return "failed";
    }
    // A hard-link count of two is the bounded publication instant before the
    // private staging name is removed. It is not yet an accepted result.
    if metadata.nlink() != 1 {
        return if metadata.nlink() == 2 {
            "pending"
        } else {
            "failed"
        };
    }
    let mut bytes = Vec::with_capacity(metadata.size() as usize);
    if file.read_to_end(&mut bytes).is_err() || bytes.len() as u64 != metadata.size() {
        return "failed";
    }
    let expected = serde_json::json!({
        "schemaVersion": 1,
        "status": "pass",
        "initialGet": 1,
        "refreshReads": 1,
        "refreshWrites": 1,
        "postRefreshGet": 1,
        "logoutDelete": 1,
        "postDeleteMiss": 1,
        "privateChannelQuiesced": true
    });
    let failed = serde_json::json!({ "schemaVersion": 1, "status": "fail" });
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(value) if value == expected && bytes.ends_with(b"\n") => "passed",
        Ok(value) if value == failed && bytes.ends_with(b"\n") => "failed",
        _ => "failed",
    }
}

#[cfg(feature = "a23-credential-test")]
fn signal_a23_credential_saved() -> Result<(), &'static str> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let path = std::env::var_os("PIUI_A23_TRIGGER_PATH").ok_or("credential-store-unavailable")?;
    let mut trigger = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "credential-store-unavailable")?;
    trigger
        .write_all(b"ready\n")
        .and_then(|()| trigger.sync_all())
        .map_err(|_| "credential-store-unavailable")
}

#[cfg(feature = "a23-credential-test")]
fn record_a23_command_result<T: serde::Serialize>(
    app: &AppHandle,
    command: &str,
    result: &Result<T, String>,
) -> Result<(), String> {
    use tauri::Manager;
    let state = app
        .try_state::<super::a23_native_evidence::A23NativeEvidenceState>()
        .ok_or_else(|| "a23-native-evidence-unavailable".to_string())?;
    match result {
        Ok(value) => state.record_invoke_result(command, value),
        Err(_) => state.record_invoke_error(command, "command-failed"),
    }
}

enum CredentialCompletion {
    Complete(CredentialSheetResult),
    Persist {
        account_label: String,
        secret: SecretMaterial,
    },
}

fn prepare_credential_completion(
    decision: CredentialSheetDecision,
    account_label: String,
) -> CredentialCompletion {
    match decision {
        CredentialSheetDecision::Cancel => {
            CredentialCompletion::Complete(CredentialSheetResult::cancelled(account_label))
        }
        CredentialSheetDecision::Save(secret) => CredentialCompletion::Persist {
            account_label,
            secret,
        },
    }
}

#[doc(hidden)]
pub fn store_credential(
    repository: &KeychainRepository,
    account_label: &str,
    secret: SecretMaterial,
) -> Result<CredentialSheetResult, String> {
    repository
        .create(account_label, secret)
        .map(map_created_credential)
        .map_err(|error| error.code().to_string())
}

fn map_created_credential(metadata: CredentialMetadata) -> CredentialSheetResult {
    CredentialSheetResult::saved(metadata.credential_id, metadata.account_label)
}

fn normalise_provider_label(provider_label: &str) -> Result<String, String> {
    let provider_label = provider_label.trim();
    if provider_label.is_empty()
        || provider_label.chars().count() > MAX_PROVIDER_LABEL_CHARS
        || provider_label.chars().any(char::is_control)
    {
        Err(INVALID_CREDENTIAL_INPUT.to_string())
    } else {
        Ok(provider_label.to_owned())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "a23-credential-test")]
    use super::publish_a23_native_failure_to;
    use super::{
        CredentialCompletion, CredentialSheetState, map_created_credential,
        normalise_provider_label, prepare_credential_completion,
    };
    use crate::credentials::{CredentialMetadata, CredentialProxy, KeychainRepository};
    use crate::platform::{CREDENTIAL_SHEET_BUSY, CredentialSheetDecision};

    #[cfg(feature = "a23-credential-test")]
    struct PrivateTestDirectory(std::path::PathBuf);

    #[cfg(feature = "a23-credential-test")]
    impl Drop for PrivateTestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(feature = "a23-credential-test")]
    fn private_test_directory() -> PrivateTestDirectory {
        use std::os::unix::fs::DirBuilderExt;
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "piui-a23-native-failure-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("private A.23 test directory should be created");
        PrivateTestDirectory(
            std::fs::canonicalize(path).expect("private A.23 test directory should resolve"),
        )
    }

    #[test]
    fn credential_sheet_provider_label_is_bounded_and_normalised() {
        assert_eq!(
            normalise_provider_label("  Example provider  ").unwrap(),
            "Example provider"
        );
        assert!(normalise_provider_label("").is_err());
        assert!(normalise_provider_label("provider\nlabel").is_err());
        assert!(normalise_provider_label(&"p".repeat(81)).is_err());
    }

    #[test]
    fn credential_sheet_provider_id_uses_proxy_bounds() {
        assert_eq!(
            crate::credentials::proxy::normalise_provider_id("example-provider").unwrap(),
            "example-provider"
        );
        assert!(crate::credentials::proxy::normalise_provider_id("").is_err());
        assert!(crate::credentials::proxy::normalise_provider_id("provider\nname").is_err());
        assert!(crate::credentials::proxy::normalise_provider_id(&"p".repeat(129)).is_err());
    }

    #[test]
    fn credential_sheet_account_label_uses_keychain_bounds() {
        assert_eq!(
            KeychainRepository::normalise_account_label("  Work account  ").unwrap(),
            "Work account"
        );
        assert!(KeychainRepository::normalise_account_label("").is_err());
        assert!(KeychainRepository::normalise_account_label("account\nlabel").is_err());
        assert!(KeychainRepository::normalise_account_label(&"a".repeat(129)).is_err());
    }

    #[test]
    fn credential_sheet_guard_rejects_concurrency_and_releases_on_drop() {
        let state = CredentialSheetState::new(CredentialProxy::default());
        let permit = state.try_acquire().unwrap();
        let error = match state.try_acquire() {
            Ok(_) => panic!("concurrent credential sheet was accepted"),
            Err(error) => error,
        };
        assert_eq!(error, CREDENTIAL_SHEET_BUSY);
        drop(permit);
        assert!(state.try_acquire().is_ok());
    }

    #[test]
    fn credential_sheet_cancel_completes_without_requesting_storage() {
        let completion =
            prepare_credential_completion(CredentialSheetDecision::Cancel, "Work account".into());
        let CredentialCompletion::Complete(result) = completion else {
            panic!("cancelled credential sheet requested persistence");
        };
        assert_eq!(
            serde_json::to_value(result).unwrap(),
            serde_json::json!({
                "credentialReference": null,
                "savedState": "cancelled",
                "validationState": "not-run",
                "accountLabel": "Work account"
            })
        );
    }

    #[test]
    fn credential_sheet_saved_result_reports_no_provider_validation() {
        let result = map_created_credential(CredentialMetadata {
            credential_id: "credential-0123456789abcdef0123456789abcdef".into(),
            account_label: "Work account".into(),
        });
        assert_eq!(
            serde_json::to_value(result).unwrap(),
            serde_json::json!({
                "credentialReference": "credential-0123456789abcdef0123456789abcdef",
                "savedState": "saved",
                "validationState": "saved-not-validated",
                "accountLabel": "Work account"
            })
        );
    }

    #[cfg(feature = "a23-credential-test")]
    #[test]
    fn native_failure_publication_is_private_atomic_and_no_replace() {
        use std::os::unix::fs::MetadataExt;

        let directory = private_test_directory();
        let target = directory.0.join("lifecycle-result.json");
        assert!(publish_a23_native_failure_to(&target).is_ok());
        let metadata = std::fs::metadata(&target).expect("published result metadata should exist");
        assert!(metadata.is_file());
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(
            std::fs::read(&target).expect("published failure should be readable"),
            b"{\"schemaVersion\":1,\"status\":\"fail\"}\n"
        );
        assert!(publish_a23_native_failure_to(&target).is_err());
        assert!(
            !directory
                .0
                .join("lifecycle-result.json.native-pending")
                .exists()
        );
    }
}
