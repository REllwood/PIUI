use piui_lib::commands::credentials::store_credential;
use piui_lib::credentials::{KeychainRepository, SecretMaterial};
use piui_lib::platform::{CredentialSheetRequest, CredentialSheetResult};

#[test]
fn credential_sheet_contract_rejects_unknown_request_fields() {
    let rejected = serde_json::from_value::<CredentialSheetRequest>(serde_json::json!({
        "providerLabel": "Example provider",
        "accountLabel": "Work account",
        "unexpected": "value"
    }));
    assert!(rejected.is_err());

    let cancelled = CredentialSheetResult::cancelled("Work account".into());
    let object = serde_json::to_value(cancelled).unwrap();
    let keys: Vec<_> = object.as_object().unwrap().keys().cloned().collect();
    assert_eq!(
        keys,
        [
            "accountLabel",
            "credentialReference",
            "savedState",
            "validationState"
        ]
    );
}

#[test]
#[ignore = "requires an interactive macOS login Keychain"]
fn credential_sheet_save_uses_keychain_and_returns_only_safe_metadata() {
    let namespace = format!(
        "sheet-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let repository = KeychainRepository::for_tests(&namespace).expect("test namespace");
    let sentinel = format!("PIUI_CREDENTIAL_SHEET_SENTINEL_{namespace}").into_bytes();
    let result = store_credential(
        &repository,
        "Test account",
        SecretMaterial::new(sentinel.clone()).unwrap(),
    )
    .expect("Keychain write");
    let credential_reference = result
        .credential_reference
        .clone()
        .expect("saved reference");
    let mut cleanup = Cleanup {
        repository: repository.clone(),
        credential_reference: Some(credential_reference.clone()),
    };

    let json = serde_json::to_vec(&result).unwrap();
    assert!(
        !json
            .windows(sentinel.len())
            .any(|window| window == sentinel),
        "credential result contained protected material"
    );
    assert!(
        !format!("{result:?}").contains("PIUI_CREDENTIAL_SHEET_SENTINEL"),
        "credential debug surface contained protected material"
    );
    let object = serde_json::from_slice::<serde_json::Value>(&json).unwrap();
    let keys: Vec<_> = object.as_object().unwrap().keys().cloned().collect();
    assert_eq!(
        keys,
        [
            "accountLabel",
            "credentialReference",
            "savedState",
            "validationState"
        ]
    );
    assert_eq!(object["savedState"], "saved");
    assert_eq!(object["validationState"], "saved-not-validated");

    let recovered = repository
        .read(&credential_reference)
        .expect("Keychain read");
    assert!(
        recovered.expose() == sentinel.as_slice(),
        "Keychain round trip changed protected material"
    );
    drop(recovered);

    repository
        .delete(&credential_reference)
        .expect("Keychain delete");
    cleanup.credential_reference = None;
}

struct Cleanup {
    repository: KeychainRepository,
    credential_reference: Option<String>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(credential_reference) = self.credential_reference.take() {
            let _ = self.repository.delete(&credential_reference);
        }
    }
}
