use piui_lib::credentials::{KeychainRepository, SecretMaterial};

#[test]
#[ignore = "requires an interactive macOS login Keychain"]
fn keychain_round_trip_delete_and_redacted_surfaces() {
    let namespace = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let repository = KeychainRepository::for_tests(&namespace).expect("test namespace");
    let sentinel = format!("PIUI_KEYCHAIN_SENTINEL_{namespace}").into_bytes();
    let metadata = repository
        .create(
            "Test provider account",
            SecretMaterial::new(sentinel.clone()).unwrap(),
        )
        .expect("Keychain write");
    let mut cleanup = Cleanup {
        repository: repository.clone(),
        credential_id: Some(metadata.credential_id.clone()),
    };

    let response = serde_json::to_string(&metadata).unwrap();
    assert!(
        !response
            .as_bytes()
            .windows(sentinel.len())
            .any(|window| window == sentinel)
    );
    assert!(!format!("{metadata:?}").contains("PIUI_KEYCHAIN_SENTINEL"));
    assert_eq!(
        repository
            .metadata(&metadata.credential_id)
            .unwrap()
            .account_label,
        "Test provider account"
    );
    let recovered = repository
        .read(&metadata.credential_id)
        .expect("Keychain read");
    assert!(
        recovered.expose() == sentinel,
        "recovered Keychain secret did not match"
    );
    drop(recovered);

    repository
        .delete(&metadata.credential_id)
        .expect("Keychain delete");
    cleanup.credential_id = None;
    let missing = match repository.read(&metadata.credential_id) {
        Err(error) => error,
        Ok(_) => panic!("deleted credential remained readable"),
    };
    assert_eq!(missing.code(), "credential-not-found");
    assert!(!format!("{missing:?}").contains("PIUI_KEYCHAIN_SENTINEL"));
    assert!(!missing.to_string().contains("PIUI_KEYCHAIN_SENTINEL"));
}

struct Cleanup {
    repository: KeychainRepository,
    credential_id: Option<String>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(credential_id) = self.credential_id.take() {
            let _ = self.repository.delete(&credential_id);
        }
    }
}
