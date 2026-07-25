use super::CredentialError;
use keyring::Entry;
use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroize;

const SERVICE_NAMESPACE: &str = "au.com.piui.desktop.credentials";
const LABEL_NAMESPACE: &str = "au.com.piui.desktop.credential-labels";
const MAX_SECRET_BYTES: usize = 65_536;
const MAX_LABEL_CHARS: usize = 128;
const CREATE_ROLLBACK_ATTEMPTS: usize = 3;
const CREATE_ROLLBACK_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(10);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialMetadata {
    pub credential_id: String,
    pub account_label: String,
}

pub struct SecretMaterial(Vec<u8>);

impl SecretMaterial {
    pub(crate) const MAX_BYTES: usize = MAX_SECRET_BYTES;

    pub fn new(mut bytes: Vec<u8>) -> Result<Self, CredentialError> {
        if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES {
            bytes.zeroize();
            return Err(CredentialError::invalid_input());
        }
        Ok(Self(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretMaterial {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone)]
pub struct KeychainRepository {
    service: String,
    labels: String,
}

trait KeychainEntry {
    fn set_password(&self, password: &str) -> keyring::Result<()>;
    fn set_secret(&self, secret: &[u8]) -> keyring::Result<()>;
    fn delete_credential(&self) -> keyring::Result<()>;
}

impl KeychainEntry for Entry {
    fn set_password(&self, password: &str) -> keyring::Result<()> {
        Entry::set_password(self, password)
    }

    fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
        Entry::set_secret(self, secret)
    }

    fn delete_credential(&self) -> keyring::Result<()> {
        Entry::delete_credential(self)
    }
}

impl Default for KeychainRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl KeychainRepository {
    pub fn new() -> Self {
        Self {
            service: SERVICE_NAMESPACE.into(),
            labels: LABEL_NAMESPACE.into(),
        }
    }

    pub(crate) fn normalise_account_label(account_label: &str) -> Result<String, CredentialError> {
        validate_label(account_label).map(str::to_owned)
    }

    /// Creates an isolated test-only service namespace that cannot address
    /// production credentials, including in release-mode test binaries.
    #[doc(hidden)]
    pub fn for_tests(namespace: &str) -> Result<Self, CredentialError> {
        if namespace.is_empty()
            || namespace.len() > 96
            || !namespace
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        {
            return Err(CredentialError::invalid_input());
        }
        Ok(Self {
            service: format!("{SERVICE_NAMESPACE}.test.{namespace}"),
            labels: format!("{LABEL_NAMESPACE}.test.{namespace}"),
        })
    }

    pub fn create(
        &self,
        account_label: &str,
        secret: SecretMaterial,
    ) -> Result<CredentialMetadata, CredentialError> {
        self.create_with_entry_factory(account_label, secret, |service, credential_id| {
            Entry::new(service, credential_id).map_err(|_| CredentialError::unavailable())
        })
    }

    fn create_with_entry_factory<E>(
        &self,
        account_label: &str,
        secret: SecretMaterial,
        mut make_entry: impl FnMut(&str, &str) -> Result<E, CredentialError>,
    ) -> Result<CredentialMetadata, CredentialError>
    where
        E: KeychainEntry,
    {
        let account_label = validate_label(account_label)?;
        let credential_id = format!("credential-{}", Uuid::new_v4().simple());

        // Construct both handles before writing anything. Persist the
        // non-secret label first so no later label failure can orphan secret
        // material under an identifier the application never received.
        let secret_entry = make_entry(&self.service, &credential_id)?;
        let label_entry = make_entry(&self.labels, &credential_id)?;
        label_entry
            .set_password(account_label)
            .map_err(|_| CredentialError::unavailable())?;
        if secret_entry.set_secret(secret.expose()).is_err() {
            // A backend can persist a write before reporting an error. Keep
            // both identifier-bound handles alive while reconciling both
            // entries, without ever reflecting backend errors to the caller.
            reconcile_failed_create(&secret_entry, &label_entry);
            return Err(CredentialError::unavailable());
        }

        Ok(CredentialMetadata {
            credential_id,
            account_label: account_label.into(),
        })
    }

    pub fn read(&self, credential_id: &str) -> Result<SecretMaterial, CredentialError> {
        validate_reference(credential_id)?;
        let bytes = self
            .secret_entry(credential_id)?
            .get_secret()
            .map_err(map_read_error)?;
        SecretMaterial::new(bytes)
    }

    pub fn metadata(&self, credential_id: &str) -> Result<CredentialMetadata, CredentialError> {
        validate_reference(credential_id)?;
        let account_label = self
            .label_entry(credential_id)?
            .get_password()
            .map_err(map_read_error)?;
        Ok(CredentialMetadata {
            credential_id: credential_id.into(),
            account_label,
        })
    }

    pub fn delete(&self, credential_id: &str) -> Result<(), CredentialError> {
        validate_reference(credential_id)?;
        let secret = self.secret_entry(credential_id)?.delete_credential();
        let label = self.label_entry(credential_id)?.delete_credential();
        let secret_missing = secret
            .as_ref()
            .err()
            .is_some_and(|error| matches!(error, keyring::Error::NoEntry));
        let label_missing = label
            .as_ref()
            .err()
            .is_some_and(|error| matches!(error, keyring::Error::NoEntry));
        if secret_missing && label_missing {
            return Err(CredentialError::not_found());
        }
        if secret.is_err() && !secret_missing || label.is_err() && !label_missing {
            return Err(CredentialError::unavailable());
        }
        Ok(())
    }

    fn secret_entry(&self, credential_id: &str) -> Result<Entry, CredentialError> {
        Entry::new(&self.service, credential_id).map_err(|_| CredentialError::unavailable())
    }

    fn label_entry(&self, credential_id: &str) -> Result<Entry, CredentialError> {
        Entry::new(&self.labels, credential_id).map_err(|_| CredentialError::unavailable())
    }
}

fn reconcile_failed_create<E: KeychainEntry>(secret_entry: &E, label_entry: &E) {
    let mut secret_pending = true;
    let mut label_pending = true;

    for attempt in 0..CREATE_ROLLBACK_ATTEMPTS {
        if secret_pending {
            secret_pending = !cleanup_succeeded(secret_entry.delete_credential());
        }
        if label_pending {
            label_pending = !cleanup_succeeded(label_entry.delete_credential());
        }
        if !secret_pending && !label_pending {
            return;
        }
        if attempt + 1 < CREATE_ROLLBACK_ATTEMPTS {
            std::thread::sleep(CREATE_ROLLBACK_RETRY_DELAY);
        }
    }
}

fn cleanup_succeeded(result: keyring::Result<()>) -> bool {
    matches!(result, Ok(()) | Err(keyring::Error::NoEntry))
}

fn validate_label(account_label: &str) -> Result<&str, CredentialError> {
    let account_label = account_label.trim();
    if account_label.is_empty()
        || account_label.chars().count() > MAX_LABEL_CHARS
        || account_label.chars().any(char::is_control)
    {
        Err(CredentialError::invalid_input())
    } else {
        Ok(account_label)
    }
}

fn validate_reference(credential_id: &str) -> Result<(), CredentialError> {
    let Some(uuid) = credential_id.strip_prefix("credential-") else {
        return Err(CredentialError::invalid_reference());
    };
    if uuid.len() != 32 || Uuid::parse_str(uuid).is_err() {
        Err(CredentialError::invalid_reference())
    } else {
        Ok(())
    }
}

fn map_read_error(error: keyring::Error) -> CredentialError {
    if matches!(error, keyring::Error::NoEntry) {
        CredentialError::not_found()
    } else {
        CredentialError::unavailable()
    }
}

#[cfg(test)]
mod tests {
    use super::{CredentialError, KeychainEntry, KeychainRepository, SecretMaterial};
    use std::{cell::RefCell, rc::Rc};

    const FAILURE_SENTINEL: &str = "PIUI_CREDENTIAL_SHEET_FAILURE_SENTINEL";

    #[derive(Clone, Copy)]
    enum EntryKind {
        Secret,
        Label,
    }

    #[derive(Default)]
    struct FakeState {
        calls: Vec<&'static str>,
        credential_id: Option<String>,
        label_stored: bool,
        secret_stored: bool,
        secret_cleanup_failures_remaining: usize,
    }

    struct FakeEntry {
        kind: EntryKind,
        state: Rc<RefCell<FakeState>>,
    }

    impl KeychainEntry for FakeEntry {
        fn set_password(&self, _password: &str) -> keyring::Result<()> {
            let mut state = self.state.borrow_mut();
            match self.kind {
                EntryKind::Label => {
                    state.calls.push("write-label");
                    state.label_stored = true;
                    Ok(())
                }
                EntryKind::Secret => Err(keyring::Error::Invalid(
                    "entry-kind".into(),
                    "invalid test operation".into(),
                )),
            }
        }

        fn set_secret(&self, _secret: &[u8]) -> keyring::Result<()> {
            let mut state = self.state.borrow_mut();
            match self.kind {
                EntryKind::Secret => {
                    state.calls.push("write-secret");
                    // Model an ambiguous backend result: the secret reached
                    // storage before the backend reported failure.
                    state.secret_stored = true;
                    Err(keyring::Error::Invalid(
                        "secret-write".into(),
                        FAILURE_SENTINEL.into(),
                    ))
                }
                EntryKind::Label => Err(keyring::Error::Invalid(
                    "entry-kind".into(),
                    "invalid test operation".into(),
                )),
            }
        }

        fn delete_credential(&self) -> keyring::Result<()> {
            let mut state = self.state.borrow_mut();
            match self.kind {
                EntryKind::Label => {
                    state.calls.push("rollback-label");
                    state.label_stored = false;
                    // NoEntry is a successful reconciliation outcome: the
                    // entry is absent regardless of which operation removed it.
                    Err(keyring::Error::NoEntry)
                }
                EntryKind::Secret => {
                    state.calls.push("rollback-secret");
                    if state.secret_cleanup_failures_remaining > 0 {
                        state.secret_cleanup_failures_remaining -= 1;
                        Err(keyring::Error::Invalid(
                            "secret-delete".into(),
                            FAILURE_SENTINEL.into(),
                        ))
                    } else {
                        state.secret_stored = false;
                        Ok(())
                    }
                }
            }
        }
    }

    #[test]
    fn credential_sheet_keychain_failure_reconciles_both_entries_and_excludes_sentinel() {
        let repository = KeychainRepository::for_tests("failure-regression").unwrap();
        let state = Rc::new(RefCell::new(FakeState {
            secret_cleanup_failures_remaining: 1,
            ..FakeState::default()
        }));
        let factory_state = Rc::clone(&state);
        let secret_service = repository.service.clone();
        let label_service = repository.labels.clone();

        let result = repository.create_with_entry_factory(
            "Test account",
            SecretMaterial::new(b"bounded-test-secret".to_vec()).unwrap(),
            move |service, credential_id| {
                let (kind, call) = if service == secret_service {
                    (EntryKind::Secret, "construct-secret")
                } else if service == label_service {
                    (EntryKind::Label, "construct-label")
                } else {
                    return Err(CredentialError::unavailable());
                };
                let mut state = factory_state.borrow_mut();
                match &state.credential_id {
                    Some(existing) => assert_eq!(existing, credential_id),
                    None => state.credential_id = Some(credential_id.to_owned()),
                }
                state.calls.push(call);
                drop(state);
                Ok(FakeEntry {
                    kind,
                    state: Rc::clone(&factory_state),
                })
            },
        );
        let error = match result {
            Ok(_) => panic!("failed secret storage was reported as successful"),
            Err(error) => error,
        };

        assert_eq!(error.code(), "keychain-unavailable");
        assert!(!error.to_string().contains(FAILURE_SENTINEL));
        assert!(!format!("{error:?}").contains(FAILURE_SENTINEL));
        let state = state.borrow();
        let credential_id = state
            .credential_id
            .as_deref()
            .expect("fake received the opaque identifier");
        assert!(!error.to_string().contains(credential_id));
        assert!(!format!("{error:?}").contains(credential_id));
        assert_eq!(
            state.calls,
            [
                "construct-secret",
                "construct-label",
                "write-label",
                "write-secret",
                "rollback-secret",
                "rollback-label",
                "rollback-secret"
            ]
        );
        assert!(!state.label_stored);
        assert!(!state.secret_stored);
        assert_eq!(state.secret_cleanup_failures_remaining, 0);
    }
}
