use crate::credentials::{CredentialMetadata, KeychainRepository, SecretMaterial};
use crate::platform::{
    CREDENTIAL_SHEET_BUSY, CredentialSheetDecision, CredentialSheetRequest, CredentialSheetResult,
    INVALID_CREDENTIAL_INPUT, present_native_credential_sheet,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tauri::{State, WebviewWindow};

const MAX_PROVIDER_LABEL_CHARS: usize = 80;

#[derive(Clone, Default)]
pub struct CredentialSheetState {
    active: Arc<AtomicBool>,
}

impl CredentialSheetState {
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
    window: WebviewWindow,
    state: State<'_, CredentialSheetState>,
    request: CredentialSheetRequest,
) -> Result<CredentialSheetResult, String> {
    let provider_label = normalise_provider_label(&request.provider_label)?;
    let account_label = KeychainRepository::normalise_account_label(&request.account_label)
        .map_err(|error| error.code().to_string())?;
    let _permit = state.try_acquire()?;

    let decision = present_native_credential_sheet(window, provider_label)
        .await
        .map_err(|error| error.code().to_string())?;
    match prepare_credential_completion(decision, account_label) {
        CredentialCompletion::Complete(result) => Ok(result),
        CredentialCompletion::Persist {
            account_label,
            secret,
        } => {
            let repository = KeychainRepository::new();
            tauri::async_runtime::spawn_blocking(move || {
                store_credential(&repository, &account_label, secret)
            })
            .await
            .map_err(|_| "keychain-unavailable".to_string())?
        }
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
    use super::{
        CredentialCompletion, CredentialSheetState, map_created_credential,
        normalise_provider_label, prepare_credential_completion,
    };
    use crate::credentials::{CredentialMetadata, KeychainRepository};
    use crate::platform::{CREDENTIAL_SHEET_BUSY, CredentialSheetDecision};

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
        let state = CredentialSheetState::default();
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
}
