use crate::credentials::SecretMaterial;
use serde::{Deserialize, Deserializer, Serialize, de};
use std::fmt::Formatter;
use tauri::WebviewWindow;

#[cfg(target_os = "macos")]
mod macos;

pub const INVALID_CREDENTIAL_INPUT: &str = "invalid-credential-input";
pub const CREDENTIAL_SHEET_BUSY: &str = "credential-sheet-busy";
pub const CREDENTIAL_SHEET_UNAVAILABLE: &str = "credential-sheet-unavailable";
pub const NATIVE_CREDENTIAL_SHEET_UNSUPPORTED: &str = "native-credential-sheet-unsupported";

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialSecretValidation {
    Empty,
    Ready,
    TooLong,
}

#[cfg(any(target_os = "macos", test))]
pub(crate) const fn credential_secret_validation(
    utf8_byte_length: usize,
) -> CredentialSecretValidation {
    if utf8_byte_length == 0 {
        CredentialSecretValidation::Empty
    } else if utf8_byte_length > SecretMaterial::MAX_BYTES {
        CredentialSecretValidation::TooLong
    } else {
        CredentialSecretValidation::Ready
    }
}

pub struct CredentialSheetRequest {
    pub provider_label: String,
    pub account_label: String,
}

impl<'de> Deserialize<'de> for CredentialSheetRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "CredentialSheetRequest",
            &["providerLabel", "accountLabel"],
            CredentialSheetRequestVisitor,
        )
    }
}

struct CredentialSheetRequestVisitor;

impl<'de> de::Visitor<'de> for CredentialSheetRequestVisitor {
    type Value = CredentialSheetRequest;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(INVALID_CREDENTIAL_INPUT)
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: de::MapAccess<'de>,
    {
        let mut provider_label = None;
        let mut account_label = None;
        while let Some(field) = map.next_key::<CredentialSheetRequestField>()? {
            match field {
                CredentialSheetRequestField::ProviderLabel if provider_label.is_none() => {
                    provider_label = Some(map.next_value::<CredentialMetadataValue>()?.0);
                }
                CredentialSheetRequestField::AccountLabel if account_label.is_none() => {
                    account_label = Some(map.next_value::<CredentialMetadataValue>()?.0);
                }
                _ => return Err(de::Error::custom(INVALID_CREDENTIAL_INPUT)),
            }
        }
        match (provider_label, account_label) {
            (Some(provider_label), Some(account_label)) => Ok(CredentialSheetRequest {
                provider_label,
                account_label,
            }),
            _ => Err(de::Error::custom(INVALID_CREDENTIAL_INPUT)),
        }
    }
}

struct CredentialMetadataValue(String);

impl<'de> Deserialize<'de> for CredentialMetadataValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(CredentialMetadataValueVisitor)
    }
}

struct CredentialMetadataValueVisitor;

impl<'de> de::Visitor<'de> for CredentialMetadataValueVisitor {
    type Value = CredentialMetadataValue;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(INVALID_CREDENTIAL_INPUT)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(CredentialMetadataValue(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(CredentialMetadataValue(value))
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom(INVALID_CREDENTIAL_INPUT))
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom(INVALID_CREDENTIAL_INPUT))
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom(INVALID_CREDENTIAL_INPUT))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom(INVALID_CREDENTIAL_INPUT))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom(INVALID_CREDENTIAL_INPUT))
    }

    fn visit_seq<A>(self, _sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        Err(de::Error::custom(INVALID_CREDENTIAL_INPUT))
    }

    fn visit_map<A>(self, _map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        Err(de::Error::custom(INVALID_CREDENTIAL_INPUT))
    }
}

enum CredentialSheetRequestField {
    ProviderLabel,
    AccountLabel,
}

impl<'de> Deserialize<'de> for CredentialSheetRequestField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_identifier(CredentialSheetRequestFieldVisitor)
    }
}

struct CredentialSheetRequestFieldVisitor;

impl de::Visitor<'_> for CredentialSheetRequestFieldVisitor {
    type Value = CredentialSheetRequestField;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(INVALID_CREDENTIAL_INPUT)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match value {
            "providerLabel" => Ok(CredentialSheetRequestField::ProviderLabel),
            "accountLabel" => Ok(CredentialSheetRequestField::AccountLabel),
            _ => Err(E::custom(INVALID_CREDENTIAL_INPUT)),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialSavedState {
    Saved,
    Cancelled,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialValidationState {
    SavedNotValidated,
    NotRun,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSheetResult {
    pub credential_reference: Option<String>,
    pub saved_state: CredentialSavedState,
    pub validation_state: CredentialValidationState,
    pub account_label: String,
}

impl CredentialSheetResult {
    pub fn cancelled(account_label: String) -> Self {
        Self {
            credential_reference: None,
            saved_state: CredentialSavedState::Cancelled,
            validation_state: CredentialValidationState::NotRun,
            account_label,
        }
    }

    pub(crate) fn saved(credential_reference: String, account_label: String) -> Self {
        Self {
            credential_reference: Some(credential_reference),
            saved_state: CredentialSavedState::Saved,
            validation_state: CredentialValidationState::SavedNotValidated,
            account_label,
        }
    }
}

pub(crate) enum CredentialSheetDecision {
    Save(SecretMaterial),
    Cancel,
}

#[derive(Clone, Copy)]
pub(crate) struct NativeCredentialSheetError(&'static str);

impl NativeCredentialSheetError {
    #[cfg(target_os = "macos")]
    pub(crate) const fn invalid_input() -> Self {
        Self(INVALID_CREDENTIAL_INPUT)
    }

    pub(crate) const fn unavailable() -> Self {
        Self(CREDENTIAL_SHEET_UNAVAILABLE)
    }

    #[cfg(not(target_os = "macos"))]
    const fn unsupported() -> Self {
        Self(NATIVE_CREDENTIAL_SHEET_UNSUPPORTED)
    }

    pub(crate) const fn code(self) -> &'static str {
        self.0
    }
}

#[cfg(target_os = "macos")]
pub(crate) async fn present_native_credential_sheet(
    window: WebviewWindow,
    provider_label: String,
) -> Result<CredentialSheetDecision, NativeCredentialSheetError> {
    macos::credential_sheet::present(window, provider_label).await
}

#[cfg(not(target_os = "macos"))]
pub(crate) async fn present_native_credential_sheet(
    _window: WebviewWindow,
    _provider_label: String,
) -> Result<CredentialSheetDecision, NativeCredentialSheetError> {
    Err(NativeCredentialSheetError::unsupported())
}

#[cfg(test)]
mod tests {
    use super::{
        CredentialSecretValidation, CredentialSheetRequest, CredentialSheetResult,
        INVALID_CREDENTIAL_INPUT, credential_secret_validation,
    };
    use crate::credentials::SecretMaterial;

    #[test]
    fn credential_sheet_request_accepts_only_two_safe_fields() {
        let request: CredentialSheetRequest = serde_json::from_value(serde_json::json!({
            "providerLabel": "Example provider",
            "accountLabel": "Work account"
        }))
        .unwrap();
        assert_eq!(request.provider_label, "Example provider");
        assert_eq!(request.account_label, "Work account");

        for rejected in [
            serde_json::json!({
                "providerLabel": "Example provider",
                "accountLabel": "Work account",
                "unexpected": "value"
            }),
            serde_json::json!({"providerLabel": "Example provider"}),
        ] {
            let error = match serde_json::from_value::<CredentialSheetRequest>(rejected) {
                Ok(_) => panic!("credential sheet request was unexpectedly accepted"),
                Err(error) => error,
            };
            let message = error.to_string();
            assert!(message.contains(INVALID_CREDENTIAL_INPUT));
            assert!(!message.contains("unexpected"));
            assert!(!message.contains("value"));
        }

        let duplicate = serde_json::from_str::<CredentialSheetRequest>(
            r#"{"providerLabel":"First","providerLabel":"Second","accountLabel":"Work"}"#,
        );
        let error = match duplicate {
            Ok(_) => panic!("duplicate credential sheet field was unexpectedly accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(INVALID_CREDENTIAL_INPUT));
    }

    #[test]
    fn credential_sheet_request_rejects_malformed_known_values_with_exact_stable_code() {
        for field in ["providerLabel", "accountLabel"] {
            for malformed in [
                serde_json::json!(42),
                serde_json::json!(true),
                serde_json::Value::Null,
                serde_json::json!(["not", "metadata"]),
                serde_json::json!({"not": "metadata"}),
            ] {
                let mut request = serde_json::json!({
                    "providerLabel": "Example provider",
                    "accountLabel": "Work account"
                });
                request[field] = malformed;
                let error = match serde_json::from_value::<CredentialSheetRequest>(request) {
                    Ok(_) => panic!("malformed credential metadata was unexpectedly accepted"),
                    Err(error) => error,
                };
                assert_eq!(error.to_string(), INVALID_CREDENTIAL_INPUT);
            }
        }
    }

    #[test]
    fn credential_secret_validation_uses_utf8_byte_boundaries() {
        let exact = "é".repeat(SecretMaterial::MAX_BYTES / "é".len());
        let over_limit = format!("{exact}é");

        assert_eq!(
            credential_secret_validation("".len()),
            CredentialSecretValidation::Empty
        );
        assert_eq!(exact.len(), SecretMaterial::MAX_BYTES);
        assert_eq!(
            credential_secret_validation(exact.len()),
            CredentialSecretValidation::Ready
        );
        assert!(over_limit.len() > SecretMaterial::MAX_BYTES);
        assert_eq!(
            credential_secret_validation(over_limit.len()),
            CredentialSecretValidation::TooLong
        );
    }

    #[test]
    fn credential_sheet_cancel_contract_has_exact_safe_fields() {
        let result = CredentialSheetResult::cancelled("Work account".into());
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
}
