use super::CredentialError;
use keyring::Entry;
use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroize;

const SERVICE_NAMESPACE: &str = "au.com.piui.desktop.credentials";
const LABEL_NAMESPACE: &str = "au.com.piui.desktop.credential-labels";
const INDEX_NAMESPACE: &str = "au.com.piui.desktop.credential-index";
const INDEX_ACCOUNT: &str = "provider-index-v1";
const MAX_SECRET_BYTES: usize = 65_536;
const MAX_INDEX_BYTES: usize = 262_144;
const MAX_LABEL_CHARS: usize = 128;
const RECONCILIATION_ATTEMPTS: usize = 3;
const RECONCILIATION_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(10);

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

pub(crate) struct IndexMaterial(Vec<u8>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialPairStatus {
    Complete,
    Incomplete,
}

impl IndexMaterial {
    pub(crate) fn new(mut bytes: Vec<u8>) -> Result<Self, CredentialError> {
        if bytes.is_empty() || bytes.len() > MAX_INDEX_BYTES {
            bytes.zeroize();
            return Err(CredentialError::invalid_input());
        }
        Ok(Self(bytes))
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for IndexMaterial {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone)]
pub struct KeychainRepository {
    service: String,
    labels: String,
    index: String,
    test_only: bool,
}

trait KeychainEntry {
    fn get_password(&self) -> keyring::Result<String>;
    fn get_secret(&self) -> keyring::Result<Vec<u8>>;
    fn set_password(&self, password: &str) -> keyring::Result<()>;
    fn set_secret(&self, secret: &[u8]) -> keyring::Result<()>;
    fn delete_credential(&self) -> keyring::Result<()>;
}

impl KeychainEntry for Entry {
    fn get_password(&self) -> keyring::Result<String> {
        Entry::get_password(self)
    }

    fn get_secret(&self) -> keyring::Result<Vec<u8>> {
        Entry::get_secret(self)
    }

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
            index: INDEX_NAMESPACE.into(),
            test_only: false,
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
            index: format!("{INDEX_NAMESPACE}.test.{namespace}"),
            test_only: true,
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
        make_entry: impl FnMut(&str, &str) -> Result<E, CredentialError>,
    ) -> Result<CredentialMetadata, CredentialError>
    where
        E: KeychainEntry,
    {
        let credential_id = format!("credential-{}", Uuid::new_v4().simple());
        self.create_at_with_entry_factory(
            &credential_id,
            account_label,
            secret,
            false,
            make_entry,
        )?;
        Ok(CredentialMetadata {
            credential_id,
            account_label: validate_label(account_label)?.into(),
        })
    }

    /// Creates the complete label/secret pair at a caller-reserved opaque
    /// reference. The proxy persists that reference before calling this API,
    /// so every possible secret write remains reachable for reconciliation.
    pub(crate) fn create_at_reference(
        &self,
        credential_id: &str,
        account_label: &str,
        secret: SecretMaterial,
    ) -> Result<(), CredentialError> {
        self.create_at_with_entry_factory(
            credential_id,
            account_label,
            secret,
            true,
            |service, credential_id| {
                Entry::new(service, credential_id).map_err(|_| CredentialError::unavailable())
            },
        )
    }

    fn create_at_with_entry_factory<E>(
        &self,
        credential_id: &str,
        account_label: &str,
        secret: SecretMaterial,
        accept_identical_ambiguous_commit: bool,
        mut make_entry: impl FnMut(&str, &str) -> Result<E, CredentialError>,
    ) -> Result<(), CredentialError>
    where
        E: KeychainEntry,
    {
        validate_reference(credential_id)?;
        let account_label = validate_label(account_label)?;

        // Construct both handles before writing anything. Persist the
        // non-secret label first so a label error cannot create secret-only
        // state. A proxy-created reference is already present in the index.
        let secret_entry = make_entry(&self.service, credential_id)?;
        let label_entry = make_entry(&self.labels, credential_id)?;
        label_entry
            .set_password(account_label)
            .map_err(|_| CredentialError::unavailable())?;
        if secret_entry.set_secret(secret.expose()).is_err() {
            // A create-at-reference write that committed before reporting an
            // error is a successful transaction only when both authoritative
            // entries read back byte-for-byte as requested.
            if accept_identical_ambiguous_commit
                && pair_matches(&secret_entry, &label_entry, secret.expose(), account_label)
            {
                return Ok(());
            }
            // Keep both identifier-bound handles alive while reconciling each
            // entry independently. If the backend remains unavailable, the
            // pre-persisted index entry is the durable recovery reference.
            let _ = reconcile_entries(&secret_entry, &label_entry);
            return Err(CredentialError::unavailable());
        }
        Ok(())
    }

    pub fn read(&self, credential_id: &str) -> Result<SecretMaterial, CredentialError> {
        validate_reference(credential_id)?;
        let bytes = self
            .secret_entry(credential_id)?
            .get_secret()
            .map_err(map_read_error)?;
        SecretMaterial::new(bytes)
    }

    /// Replaces secret material in place. The opaque reference and its label
    /// remain unchanged. The complete pair is checked again immediately before
    /// the upserting Keychain call, preventing a stale reference from being
    /// recreated as secret-only state. An ambiguous write is never retried.
    pub(crate) fn overwrite(
        &self,
        credential_id: &str,
        secret: &SecretMaterial,
    ) -> Result<(), CredentialError> {
        self.overwrite_with_entry_factory(credential_id, secret, |service, credential_id| {
            Entry::new(service, credential_id).map_err(|_| CredentialError::unavailable())
        })
    }

    fn overwrite_with_entry_factory<E>(
        &self,
        credential_id: &str,
        secret: &SecretMaterial,
        mut make_entry: impl FnMut(&str, &str) -> Result<E, CredentialError>,
    ) -> Result<(), CredentialError>
    where
        E: KeychainEntry,
    {
        validate_reference(credential_id)?;
        let secret_entry = make_entry(&self.service, credential_id)?;
        let label_entry = make_entry(&self.labels, credential_id)?;
        if pair_status_entries(&secret_entry, &label_entry)? != CredentialPairStatus::Complete {
            return Err(CredentialError::not_found());
        }
        secret_entry
            .set_secret(secret.expose())
            .map_err(|_| CredentialError::unavailable())
    }

    /// Reads secret and label independently using the same Keychain APIs used
    /// by production reads. Any backend uncertainty fails closed.
    pub(crate) fn pair_status(
        &self,
        credential_id: &str,
    ) -> Result<CredentialPairStatus, CredentialError> {
        validate_reference(credential_id)?;
        let secret = self.secret_entry(credential_id)?;
        let label = self.label_entry(credential_id)?;
        pair_status_entries(&secret, &label)
    }

    /// Independently and boundedly reconciles the secret and label to proven
    /// absence. Success means both delete operations returned either success or
    /// `NoEntry`; failure retains the caller's indexed recovery reference.
    pub(crate) fn reconcile_delete(&self, credential_id: &str) -> Result<(), CredentialError> {
        validate_reference(credential_id)?;
        let secret = self.secret_entry(credential_id)?;
        let label = self.label_entry(credential_id)?;
        if reconcile_entries(&secret, &label) {
            Ok(())
        } else {
            Err(CredentialError::unavailable())
        }
    }

    pub(crate) fn read_index(&self) -> Result<Option<IndexMaterial>, CredentialError> {
        let bytes = match self.index_entry()?.get_secret() {
            Ok(bytes) => bytes,
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(_) => return Err(CredentialError::unavailable()),
        };
        IndexMaterial::new(bytes).map(Some)
    }

    pub(crate) fn write_index(&self, index: IndexMaterial) -> Result<(), CredentialError> {
        self.index_entry()?
            .set_secret(index.expose())
            .map_err(|_| CredentialError::unavailable())
    }

    pub(crate) fn delete_index(&self) -> Result<(), CredentialError> {
        match self.index_entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(CredentialError::unavailable()),
        }
    }

    /// Removes every reference journalled by an isolated `.test.` repository
    /// and then removes its provider index. Production repositories can never
    /// enter this release-capable cleanup path.
    pub fn cleanup_test_repository(&self) -> Result<(), CredentialError> {
        if !self.test_only {
            return Err(CredentialError::invalid_input());
        }
        let Some(index) = self.read_index()? else {
            return Ok(());
        };
        let document: serde_json::Value =
            serde_json::from_slice(index.expose()).map_err(|_| CredentialError::invalid_input())?;
        let object = document
            .as_object()
            .ok_or_else(CredentialError::invalid_input)?;
        if object.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
            return Err(CredentialError::invalid_input());
        }
        let mut references = std::collections::BTreeSet::new();
        for key in ["entries", "pending"] {
            let values = object
                .get(key)
                .and_then(serde_json::Value::as_array)
                .ok_or_else(CredentialError::invalid_input)?;
            if values.len() > 256 {
                return Err(CredentialError::invalid_input());
            }
            for value in values {
                let reference = value
                    .get("credentialId")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(CredentialError::invalid_input)?;
                validate_reference(reference)?;
                references.insert(reference.to_owned());
            }
        }
        for reference in references {
            self.reconcile_delete(&reference)?;
        }
        self.delete_index()
    }

    pub fn test_repository_index_is_absent(&self) -> Result<bool, CredentialError> {
        if !self.test_only {
            return Err(CredentialError::invalid_input());
        }
        self.read_index().map(|index| index.is_none())
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

    fn index_entry(&self) -> Result<Entry, CredentialError> {
        Entry::new(&self.index, INDEX_ACCOUNT).map_err(|_| CredentialError::unavailable())
    }
}

fn pair_matches<E: KeychainEntry>(
    secret_entry: &E,
    label_entry: &E,
    expected_secret: &[u8],
    expected_label: &str,
) -> bool {
    let secret_matches = match secret_entry.get_secret() {
        Ok(mut stored) => {
            let matches = stored == expected_secret;
            stored.zeroize();
            matches
        }
        Err(_) => false,
    };
    let label_matches = match label_entry.get_password() {
        Ok(mut stored) => {
            let matches = stored == expected_label;
            stored.zeroize();
            matches
        }
        Err(_) => false,
    };
    secret_matches && label_matches
}

fn pair_status_entries<E: KeychainEntry>(
    secret_entry: &E,
    label_entry: &E,
) -> Result<CredentialPairStatus, CredentialError> {
    let secret = secret_entry.get_secret();
    let label = label_entry.get_password();
    let secret_present = classify_presence(secret.map(|mut bytes| {
        bytes.zeroize();
    }))?;
    let label_present = classify_presence(label.map(|mut text| {
        text.zeroize();
    }))?;
    if secret_present && label_present {
        Ok(CredentialPairStatus::Complete)
    } else {
        Ok(CredentialPairStatus::Incomplete)
    }
}

fn classify_presence<T>(result: keyring::Result<T>) -> Result<bool, CredentialError> {
    match result {
        Ok(_) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(_) => Err(CredentialError::unavailable()),
    }
}

fn reconcile_entries<E: KeychainEntry>(secret_entry: &E, label_entry: &E) -> bool {
    let mut secret_pending = true;
    let mut label_pending = true;

    for attempt in 0..RECONCILIATION_ATTEMPTS {
        if secret_pending {
            secret_pending = !cleanup_succeeded(secret_entry.delete_credential());
        }
        if label_pending {
            label_pending = !cleanup_succeeded(label_entry.delete_credential());
        }
        if !secret_pending && !label_pending {
            return true;
        }
        if attempt + 1 < RECONCILIATION_ATTEMPTS {
            std::thread::sleep(RECONCILIATION_RETRY_DELAY);
        }
    }
    false
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
    use super::{
        CredentialError, KeychainEntry, KeychainRepository, LABEL_NAMESPACE, SERVICE_NAMESPACE,
        SecretMaterial,
    };
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
        fn get_password(&self) -> keyring::Result<String> {
            let mut state = self.state.borrow_mut();
            state.calls.push("read-label");
            match self.kind {
                EntryKind::Label if state.label_stored => Ok("Test account".into()),
                EntryKind::Label => Err(keyring::Error::NoEntry),
                EntryKind::Secret => Err(keyring::Error::Invalid(
                    "entry-kind".into(),
                    "invalid test operation".into(),
                )),
            }
        }

        fn get_secret(&self) -> keyring::Result<Vec<u8>> {
            let mut state = self.state.borrow_mut();
            state.calls.push("read-secret");
            match self.kind {
                EntryKind::Secret if state.secret_stored => Ok(b"bounded-test-secret".to_vec()),
                EntryKind::Secret => Err(keyring::Error::NoEntry),
                EntryKind::Label => Err(keyring::Error::Invalid(
                    "entry-kind".into(),
                    "invalid test operation".into(),
                )),
            }
        }

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
    fn credential_proxy_test_namespaces_cannot_address_production_entries() {
        let production = KeychainRepository::new();
        let isolated = KeychainRepository::for_tests("namespace-check").unwrap();
        assert_eq!(production.service, SERVICE_NAMESPACE);
        assert_eq!(production.labels, LABEL_NAMESPACE);
        assert_eq!(production.index, super::INDEX_NAMESPACE);
        assert_eq!(
            isolated.service,
            format!("{SERVICE_NAMESPACE}.test.namespace-check")
        );
        assert_eq!(
            isolated.labels,
            format!("{LABEL_NAMESPACE}.test.namespace-check")
        );
        assert_eq!(
            isolated.index,
            format!("{}.test.namespace-check", super::INDEX_NAMESPACE)
        );
        assert_ne!(isolated.service, production.service);
        assert_ne!(isolated.labels, production.labels);
        assert_ne!(isolated.index, production.index);
    }

    #[test]
    fn release_cleanup_helper_cannot_operate_on_production_repository() {
        let production = KeychainRepository::new();
        assert_eq!(
            production
                .cleanup_test_repository()
                .expect_err("production cleanup must be refused")
                .code(),
            CredentialError::invalid_input().code()
        );
        assert_eq!(
            production
                .test_repository_index_is_absent()
                .expect_err("production inspection must be refused")
                .code(),
            CredentialError::invalid_input().code()
        );
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

    #[test]
    fn proxy_create_at_accepts_only_an_exact_pair_after_ambiguous_secret_write() {
        let repository = KeychainRepository::for_tests("create-readback").unwrap();
        let state = Rc::new(RefCell::new(FakeState::default()));
        let factory_state = Rc::clone(&state);
        let secret_service = repository.service.clone();
        let label_service = repository.labels.clone();
        let credential_id = "credential-00000000000000000000000000000001";

        let result = repository.create_at_with_entry_factory(
            credential_id,
            "Test account",
            SecretMaterial::new(b"bounded-test-secret".to_vec()).unwrap(),
            true,
            move |service, received_id| {
                assert_eq!(received_id, credential_id);
                let (kind, call) = if service == secret_service {
                    (EntryKind::Secret, "construct-secret")
                } else if service == label_service {
                    (EntryKind::Label, "construct-label")
                } else {
                    return Err(CredentialError::unavailable());
                };
                factory_state.borrow_mut().calls.push(call);
                Ok(FakeEntry {
                    kind,
                    state: Rc::clone(&factory_state),
                })
            },
        );

        assert!(result.is_ok());
        let state = state.borrow();
        assert!(state.secret_stored);
        assert!(state.label_stored);
        assert_eq!(
            state.calls,
            [
                "construct-secret",
                "construct-label",
                "write-label",
                "write-secret",
                "read-secret",
                "read-label"
            ]
        );
        assert!(!state.calls.iter().any(|call| call.starts_with("rollback")));
    }

    #[test]
    fn proxy_overwrite_rechecks_complete_pair_before_upserting_secret() {
        let repository = KeychainRepository::for_tests("overwrite-guard").unwrap();
        let state = Rc::new(RefCell::new(FakeState {
            secret_stored: true,
            label_stored: false,
            ..FakeState::default()
        }));
        let factory_state = Rc::clone(&state);
        let secret_service = repository.service.clone();
        let label_service = repository.labels.clone();
        let credential_id = "credential-00000000000000000000000000000002";
        let secret = SecretMaterial::new(b"replacement-secret".to_vec()).unwrap();

        let result = repository.overwrite_with_entry_factory(
            credential_id,
            &secret,
            move |service, received_id| {
                assert_eq!(received_id, credential_id);
                let (kind, call) = if service == secret_service {
                    (EntryKind::Secret, "construct-secret")
                } else if service == label_service {
                    (EntryKind::Label, "construct-label")
                } else {
                    return Err(CredentialError::unavailable());
                };
                factory_state.borrow_mut().calls.push(call);
                Ok(FakeEntry {
                    kind,
                    state: Rc::clone(&factory_state),
                })
            },
        );

        let error = result.expect_err("incomplete pair must prevent overwrite upsert");
        assert_eq!(error.code(), CredentialError::not_found().code());
        let state = state.borrow();
        assert_eq!(
            state.calls,
            [
                "construct-secret",
                "construct-label",
                "read-secret",
                "read-label"
            ]
        );
        assert!(!state.calls.contains(&"write-secret"));
    }
}
