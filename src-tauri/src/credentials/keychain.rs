use super::CredentialError;
use keyring::Entry;
use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroize;

const SERVICE_NAMESPACE: &str = "au.com.piui.desktop.credentials";
const LABEL_NAMESPACE: &str = "au.com.piui.desktop.credential-labels";
const MAX_SECRET_BYTES: usize = 65_536;
const MAX_LABEL_CHARS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialMetadata {
    pub credential_id: String,
    pub account_label: String,
}

pub struct SecretMaterial(Vec<u8>);

impl SecretMaterial {
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
        let account_label = validate_label(account_label)?;
        let credential_id = format!("credential-{}", Uuid::new_v4().simple());
        let secret_entry = self.secret_entry(&credential_id)?;
        secret_entry
            .set_secret(secret.expose())
            .map_err(|_| CredentialError::unavailable())?;
        let label_entry = self.label_entry(&credential_id)?;
        if label_entry.set_password(account_label).is_err() {
            let _ = secret_entry.delete_credential();
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
