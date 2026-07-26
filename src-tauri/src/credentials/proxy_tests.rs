
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ProtocolDecoder;
    use serde_json::json;
    use std::collections::{HashMap, HashSet};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex as StdMutex};
    use std::thread;
    use std::time::Duration;

    #[derive(Default)]
    struct FakeVault {
        index: Option<Vec<u8>>,
        secrets: HashMap<String, Vec<u8>>,
        labels: HashSet<String>,
        secret_reads: usize,
        pair_checks: usize,
        overwrite_calls: usize,
        create_at_calls: usize,
        reconcile_calls: usize,
        index_reads: usize,
        index_writes: usize,
        index_write_failures_before: usize,
        index_write_failures_after: usize,
        index_write_failure_before_on_call: Option<usize>,
        overwrite_failures_before: usize,
        overwrite_failures_after: usize,
        create_failures_before_secret: usize,
        secret_cleanup_failures: usize,
        label_cleanup_failures: usize,
        persistent_secret_cleanup_failure: bool,
        persistent_label_cleanup_failure: bool,
    }

    #[derive(Clone, Default)]
    struct FakeRepository {
        vault: Arc<Mutex<FakeVault>>,
    }

    impl FakeRepository {
        fn new() -> Self {
            Self::default()
        }

        fn state(&self) -> MutexGuard<'_, FakeVault> {
            self.vault.lock().unwrap()
        }
    }

    impl CredentialRepository for FakeRepository {
        fn create_at_reference(
            &mut self,
            credential_id: &str,
            _account_label: &str,
            secret: SecretMaterial,
        ) -> Result<(), CredentialError> {
            let mut vault = self.vault.lock().unwrap();
            vault.create_at_calls += 1;
            vault.labels.insert(credential_id.into());
            if vault.create_failures_before_secret > 0 {
                vault.create_failures_before_secret -= 1;
                return Err(CredentialError::unavailable());
            }
            vault
                .secrets
                .insert(credential_id.into(), secret.expose().to_vec());
            Ok(())
        }

        fn overwrite(
            &mut self,
            credential_id: &str,
            secret: &SecretMaterial,
        ) -> Result<(), CredentialError> {
            let mut vault = self.vault.lock().unwrap();
            vault.overwrite_calls += 1;
            if vault.overwrite_failures_before > 0 {
                vault.overwrite_failures_before -= 1;
                return Err(CredentialError::unavailable());
            }
            // Match Keychain `set_secret` upsert semantics deliberately. The
            // proxy must prevent this call for an incomplete pair.
            vault
                .secrets
                .insert(credential_id.into(), secret.expose().to_vec());
            if vault.overwrite_failures_after > 0 {
                vault.overwrite_failures_after -= 1;
                return Err(CredentialError::unavailable());
            }
            Ok(())
        }

        fn pair_status(
            &mut self,
            credential_id: &str,
        ) -> Result<CredentialPairStatus, CredentialError> {
            let mut vault = self.vault.lock().unwrap();
            vault.pair_checks += 1;
            if vault.secrets.contains_key(credential_id) && vault.labels.contains(credential_id) {
                Ok(CredentialPairStatus::Complete)
            } else {
                Ok(CredentialPairStatus::Incomplete)
            }
        }

        fn read(&mut self, credential_id: &str) -> Result<SecretMaterial, CredentialError> {
            let mut vault = self.vault.lock().unwrap();
            vault.secret_reads += 1;
            let bytes = vault
                .secrets
                .get(credential_id)
                .cloned()
                .ok_or_else(CredentialError::not_found)?;
            SecretMaterial::new(bytes)
        }

        fn reconcile_delete(&mut self, credential_id: &str) -> Result<(), CredentialError> {
            let mut vault = self.vault.lock().unwrap();
            vault.reconcile_calls += 1;
            let mut secret_pending = vault.secrets.contains_key(credential_id);
            let mut label_pending = vault.labels.contains(credential_id);
            for _ in 0..3 {
                if secret_pending {
                    if vault.persistent_secret_cleanup_failure {
                        // Retain the indexed secret for a later reconciliation.
                    } else if vault.secret_cleanup_failures > 0 {
                        vault.secret_cleanup_failures -= 1;
                    } else {
                        vault.secrets.remove(credential_id);
                        secret_pending = false;
                    }
                }
                if label_pending {
                    if vault.persistent_label_cleanup_failure {
                        // Retain the indexed label for a later reconciliation.
                    } else if vault.label_cleanup_failures > 0 {
                        vault.label_cleanup_failures -= 1;
                    } else {
                        vault.labels.remove(credential_id);
                        label_pending = false;
                    }
                }
                if !secret_pending && !label_pending {
                    return Ok(());
                }
            }
            Err(CredentialError::unavailable())
        }

        fn read_index(&mut self) -> Result<Option<IndexMaterial>, CredentialError> {
            let mut vault = self.vault.lock().unwrap();
            vault.index_reads += 1;
            vault.index.clone().map(IndexMaterial::new).transpose()
        }

        fn write_index(&mut self, index: IndexMaterial) -> Result<(), CredentialError> {
            let mut vault = self.vault.lock().unwrap();
            vault.index_writes += 1;
            if vault.index_write_failure_before_on_call == Some(vault.index_writes) {
                vault.index_write_failure_before_on_call = None;
                return Err(CredentialError::unavailable());
            }
            if vault.index_write_failures_before > 0 {
                vault.index_write_failures_before -= 1;
                return Err(CredentialError::unavailable());
            }
            vault.index = Some(index.expose().to_vec());
            if vault.index_write_failures_after > 0 {
                vault.index_write_failures_after -= 1;
                return Err(CredentialError::unavailable());
            }
            Ok(())
        }
    }

    static MESSAGE_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn request_with_id(id: String, payload: Value) -> Envelope {
        serde_json::from_value(json!({
            "version": 1,
            "kind": "host-request",
            "id": id,
            "sequence": 1,
            "payload": payload
        }))
        .unwrap()
    }

    fn request(payload: Value) -> Envelope {
        let number = MESSAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
        request_with_id(format!("credential-request-{number}"), payload)
    }

    fn response_envelope(response: &PrivateHostResponse) -> &Envelope {
        response.envelope_for_test()
    }

    fn call(proxy: &CredentialProxy, payload: Value) -> PrivateHostResponse {
        let number = MESSAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let request_id = format!("credential-request-{number}");
        proxy
            .dispatch(
                request_with_id(request_id, payload),
                format!("credential-response-{number}"),
                number,
            )
            .unwrap()
    }

    fn assert_success(response: &PrivateHostResponse) {
        let response = response_envelope(response);
        assert_eq!(response.kind, ProtocolKind::HostResponse);
        assert!(response.correlation_id.is_some());
        assert!(response.error.is_none());
    }

    fn assert_protocol_error(
        response: &PrivateHostResponse,
        category: ErrorCategory,
        message: &str,
        retryable: bool,
    ) {
        let response = response_envelope(response);
        assert_eq!(response.kind, ProtocolKind::HostResponse);
        assert!(response.payload.is_empty());
        let error = response.error.as_ref().expect("fixed protocol error");
        assert_eq!(error.category, category);
        assert_eq!(error.message, message);
        assert_eq!(error.retryable, Some(retryable));
        assert!(error.diagnostic_id.is_none());
    }

    fn set(proxy: &CredentialProxy, provider_id: &str, credential: Value) -> PrivateHostResponse {
        call(
            proxy,
            json!({
                "method": "credential.set",
                "providerId": provider_id,
                "credential": credential
            }),
        )
    }

    fn get(proxy: &CredentialProxy, provider_id: &str) -> PrivateHostResponse {
        call(
            proxy,
            json!({"method": "credential.get", "providerId": provider_id}),
        )
    }

    fn list(proxy: &CredentialProxy) -> PrivateHostResponse {
        call(proxy, json!({"method": "credential.list"}))
    }

    fn remove(proxy: &CredentialProxy, provider_id: &str) -> PrivateHostResponse {
        call(
            proxy,
            json!({"method": "credential.remove", "providerId": provider_id}),
        )
    }

    fn index_from_fake(repository: &FakeRepository) -> IndexDocument {
        let bytes = repository
            .state()
            .index
            .clone()
            .expect("persisted test index");
        serde_json::from_slice(&bytes).unwrap()
    }

    fn nested_array(depth: usize) -> Value {
        let mut value = Value::Null;
        for _ in 0..depth {
            value = Value::Array(vec![value]);
        }
        value
    }

    fn decode_json_line(value: &Value) -> Result<Envelope, String> {
        let mut line = serde_json::to_vec(value).unwrap();
        line.push(b'\n');
        ProtocolDecoder::default()
            .decode(&line)
            .map_err(|error| error.to_string())
    }

    fn decode_raw_line(raw: &str) -> Result<Envelope, String> {
        let mut line = raw.as_bytes().to_vec();
        line.push(b'\n');
        ProtocolDecoder::default()
            .decode(&line)
            .map_err(|error| error.to_string())
    }

    #[test]
    fn credential_proxy_validator_parity_and_all_bounds() {
        let repository = FakeRepository::new();
        let proxy = CredentialProxy::with_repository(repository);

        let valid_provider = "🦀".repeat(128);
        assert_success(&get(&proxy, &valid_provider));
        for invalid_provider in [String::new(), "x\n".into(), "🦀".repeat(129)] {
            assert_protocol_error(
                &get(&proxy, &invalid_provider),
                ErrorCategory::InvalidRequest,
                "Credential request rejected",
                false,
            );
        }

        for payload in [
            json!({"method": "credential.unknown"}),
            json!({"method": "credential.list", "extra": true}),
            json!({"method": "credential.get", "providerId": "p", "extra": true}),
            json!({"method": "credential.remove"}),
            json!({"method": "credential.set", "providerId": "p"}),
        ] {
            assert_protocol_error(
                &call(&proxy, payload),
                ErrorCategory::InvalidRequest,
                "Credential request rejected",
                false,
            );
        }

        for credential in [
            json!(null),
            json!({"type": "api_key", "unknown": "x"}),
            json!({"type": "api_key", "key": 1}),
            json!({"type": "api_key", "env": []}),
            json!({"type": "api_key", "env": {"A": 1}}),
            json!({"type": "oauth", "access": "a", "refresh": "r"}),
            json!({"type": "oauth", "access": "a", "refresh": "r", "expires": 1.5}),
            json!({"type": "oauth", "access": "a", "refresh": "r", "expires": 9_007_199_254_740_992_u64}),
            json!({"type": "other"}),
        ] {
            assert_protocol_error(
                &set(&proxy, "invalid-shape", credential),
                ErrorCategory::InvalidRequest,
                "Credential request rejected",
                false,
            );
        }

        for expires in [
            Value::from(9_007_199_254_740_991_i64),
            Value::from(-9_007_199_254_740_991_i64),
        ] {
            assert_success(&set(
                &proxy,
                "safe-integer",
                json!({"type": "oauth", "access": "", "refresh": "", "expires": expires}),
            ));
        }

        let mut properties_ok = Map::from_iter([
            ("type".into(), Value::String("oauth".into())),
            ("access".into(), Value::String("a".into())),
            ("refresh".into(), Value::String("r".into())),
            ("expires".into(), Value::from(1)),
        ]);
        for index in 0..124 {
            properties_ok.insert(format!("extra{index}"), Value::Null);
        }
        assert_success(&set(
            &proxy,
            "properties-ok",
            Value::Object(properties_ok.clone()),
        ));
        properties_ok.insert("overflow".into(), Value::Null);
        assert_protocol_error(
            &set(&proxy, "properties-bad", Value::Object(properties_ok)),
            ErrorCategory::InvalidRequest,
            "Credential request rejected",
            false,
        );

        assert_success(&set(
            &proxy,
            "array-ok",
            json!({
                "type": "oauth", "access": "a", "refresh": "r", "expires": 1,
                "extra": Value::Array(vec![Value::Null; 256])
            }),
        ));
        assert_protocol_error(
            &set(
                &proxy,
                "array-bad",
                json!({
                    "type": "oauth", "access": "a", "refresh": "r", "expires": 1,
                    "extra": Value::Array(vec![Value::Null; 257])
                }),
            ),
            ErrorCategory::InvalidRequest,
            "Credential request rejected",
            false,
        );

        for (key, valid) in [("🦀".repeat(64), true), ("🦀".repeat(65), false), ("bad\nkey".into(), false)] {
            let mut credential = json!({
                "type": "oauth", "access": "a", "refresh": "r", "expires": 1
            });
            credential.as_object_mut().unwrap().insert(key, Value::Null);
            let response = set(&proxy, "key-bound", credential);
            if valid {
                assert_success(&response);
            } else {
                assert_protocol_error(
                    &response,
                    ErrorCategory::InvalidRequest,
                    "Credential request rejected",
                    false,
                );
            }
        }

        let empty_key = json!({"type": "api_key", "key": ""});
        let empty_size = serde_json::to_vec(&empty_key).unwrap().len();
        let exact = json!({
            "type": "api_key",
            "key": "x".repeat(MAX_CREDENTIAL_BYTES - empty_size)
        });
        assert_eq!(serde_json::to_vec(&exact).unwrap().len(), MAX_CREDENTIAL_BYTES);
        assert!(validate_credential(&exact).is_ok());
        let oversized = json!({
            "type": "api_key",
            "key": "x".repeat(MAX_CREDENTIAL_BYTES - empty_size + 1)
        });
        assert!(validate_credential(&oversized).is_err());
    }

    #[test]
    fn credential_proxy_raw_lf_depth_and_javascript_number_parity() {
        let repository = FakeRepository::new();
        let proxy = CredentialProxy::with_repository(repository);

        let mut accepted_credential = json!({
            "type": "oauth", "access": "a", "refresh": "r", "expires": 1
        });
        accepted_credential["extra"] = nested_array(31);
        let accepted = json!({
            "version": 1,
            "kind": "host-request",
            "id": "wire-depth-accepted",
            "sequence": 1,
            "payload": {
                "method": "credential.set",
                "providerId": "depth-accepted",
                "credential": accepted_credential
            }
        });
        let accepted = decode_json_line(&accepted).expect("credential-local depth 32 decoded");
        assert_success(
            &proxy
                .dispatch(accepted, "wire-depth-response-a".into(), 1)
                .unwrap(),
        );

        let mut rejected_credential = json!({
            "type": "oauth", "access": "a", "refresh": "r", "expires": 1
        });
        rejected_credential["extra"] = nested_array(32);
        let rejected = json!({
            "version": 1,
            "kind": "host-request",
            "id": "wire-depth-rejected",
            "sequence": 1,
            "payload": {
                "method": "credential.set",
                "providerId": "depth-rejected",
                "credential": rejected_credential
            }
        });
        assert_eq!(
            decode_json_line(&rejected).unwrap_err(),
            "depth limit exceeded"
        );

        let ordinary_accepted = json!({
            "version": 1, "kind": "request", "id": "ordinary-depth-a", "sequence": 1,
            "payload": {"method": "status", "extra": nested_array(30)}
        });
        assert!(decode_json_line(&ordinary_accepted).is_ok());
        let ordinary_rejected = json!({
            "version": 1, "kind": "request", "id": "ordinary-depth-b", "sequence": 1,
            "payload": {"method": "status", "extra": nested_array(31)}
        });
        assert_eq!(
            decode_json_line(&ordinary_rejected).unwrap_err(),
            "depth limit exceeded"
        );

        for (suffix, raw_version, raw_sequence, expected_sequence) in [
            ("version-float-min", "1.0", "0", 0_u64),
            ("version-exponent", "1e0", "1.0", 1_u64),
            ("sequence-exponent", "1", "1e3", 1_000_u64),
            ("sequence-negative-zero", "1", "-0", 0_u64),
            (
                "sequence-safe-max",
                "1",
                "9007199254740991",
                9_007_199_254_740_991_u64,
            ),
            (
                "sequence-safe-max-exponent",
                "1",
                "9.007199254740991e15",
                9_007_199_254_740_991_u64,
            ),
        ] {
            let raw = r#"{"version":VERSION,"kind":"host-request","id":"envelope-SUFFIX","sequence":SEQUENCE,"payload":{"method":"credential.list"}}"#
                .replace("VERSION", raw_version)
                .replace("SUFFIX", suffix)
                .replace("SEQUENCE", raw_sequence);
            let decoded = decode_raw_line(&raw).expect("safe raw envelope number decoded");
            assert_eq!(decoded.version, 1);
            assert_eq!(decoded.sequence, expected_sequence);
            assert_success(
                &proxy
                    .dispatch(decoded, format!("envelope-response-{suffix}"), 2)
                    .unwrap(),
            );
        }

        for (suffix, raw_version, raw_sequence) in [
            ("version-fraction", "1.5", "1"),
            ("version-negative", "-1", "1"),
            ("sequence-fraction", "1", "1.5"),
            ("sequence-negative", "1", "-1"),
            ("sequence-unsafe", "1", "9007199254740992"),
            (
                "sequence-unsafe-rounded",
                "1",
                "9007199254740993.0",
            ),
            (
                "sequence-unsafe-exponent",
                "1",
                "9.007199254740993e15",
            ),
        ] {
            let raw = r#"{"version":VERSION,"kind":"host-request","id":"envelope-bad-SUFFIX","sequence":SEQUENCE,"payload":{"method":"credential.list"}}"#
                .replace("VERSION", raw_version)
                .replace("SUFFIX", suffix)
                .replace("SEQUENCE", raw_sequence);
            assert!(decode_raw_line(&raw).is_err());
        }

        for (suffix, raw_number) in [
            ("one-point-zero", "1.0"),
            ("exponent", "1e3"),
            ("negative-zero", "-0"),
            ("safe-edge-exponent", "9.007199254740991e15"),
        ] {
            let raw = r#"{"version":1,"kind":"host-request","id":"raw-SUFFIX","sequence":1,"payload":{"method":"credential.set","providerId":"raw-SUFFIX","credential":{"type":"oauth","access":"a","refresh":"r","expires":NUMBER}}}"#
                .replace("SUFFIX", suffix)
                .replace("NUMBER", raw_number);
            let decoded = decode_raw_line(&raw).expect("safe raw number decoded");
            assert_success(
                &proxy
                    .dispatch(decoded, format!("raw-response-{suffix}"), 2)
                    .unwrap(),
            );
        }

        for (suffix, raw_number) in [
            ("fraction", "1.5"),
            ("unsafe-positive", "9007199254740992"),
            ("unsafe-negative", "-9007199254740992"),
            ("unsafe-rounded", "9007199254740993.0"),
            ("unsafe-rounded-exponent", "9.007199254740993e15"),
        ] {
            let raw = r#"{"version":1,"kind":"host-request","id":"raw-bad-SUFFIX","sequence":1,"payload":{"method":"credential.set","providerId":"raw-bad-SUFFIX","credential":{"type":"oauth","access":"a","refresh":"r","expires":NUMBER}}}"#
                .replace("SUFFIX", suffix)
                .replace("NUMBER", raw_number);
            let decoded = decode_raw_line(&raw).expect("schema-valid raw number decoded");
            assert_protocol_error(
                &proxy
                    .dispatch(decoded, format!("raw-bad-response-{suffix}"), 3)
                    .unwrap(),
                ErrorCategory::InvalidRequest,
                "Credential request rejected",
                false,
            );
        }
    }

    #[test]
    fn credential_proxy_round_trip_metadata_only_list_and_non_secret_diagnostics() {
        let repository = FakeRepository::new();
        let proxy = CredentialProxy::with_repository(repository.clone());
        let missing = get(&proxy, "provider");
        assert_success(&missing);
        assert_eq!(
            response_envelope(&missing).payload.get("found"),
            Some(&Value::Bool(false))
        );

        let canary = format!("runtime-canary-{}", Uuid::new_v4().simple());
        assert_success(&set(
            &proxy,
            "provider",
            json!({"type": "api_key", "key": canary, "env": {"REGION": "au"}}),
        ));
        let first_reference = index_from_fake(&repository).entries[0]
            .credential_id
            .clone();
        let found = get(&proxy, "provider");
        assert_success(&found);
        let found_key = response_envelope(&found)
            .payload
            .get("credential")
            .and_then(Value::as_object)
            .and_then(|value| value.get("key"))
            .and_then(Value::as_str);
        assert!(found_key.is_some_and(|value| value == canary));

        let reads_before = repository.state().secret_reads;
        let listed = list(&proxy);
        assert_success(&listed);
        assert_eq!(repository.state().secret_reads, reads_before);
        assert_eq!(
            response_envelope(&listed)
                .payload
                .get("entries")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
        let wire = listed.into_lf_json().unwrap();
        assert!(!wire
            .windows(canary.len())
            .any(|window| window == canary.as_bytes()));

        let oauth = json!({
            "type": "oauth",
            "access": canary,
            "refresh": "",
            "expires": 123,
            "accountId": "account",
            "scope": ["models:read", "profile"],
            "providerData": {"region": "au", "enabled": true}
        });
        assert_success(&set(&proxy, "provider", oauth));
        assert_eq!(
            first_reference,
            index_from_fake(&repository).entries[0].credential_id
        );
        let found = get(&proxy, "provider");
        let credential = response_envelope(&found).payload.get("credential");
        assert!(credential.is_some_and(|value| {
            value.get("type").and_then(Value::as_str) == Some("oauth")
                && value.get("access").and_then(Value::as_str) == Some(canary.as_str())
                && value.get("expires").and_then(Value::as_i64) == Some(123)
                && value.get("scope").and_then(Value::as_array).map(Vec::len) == Some(2)
        }));

        let debug = format!("{found:?}");
        assert!(!debug
            .as_bytes()
            .windows(canary.len())
            .any(|window| window == canary.as_bytes()));
        let panic = catch_unwind(AssertUnwindSafe(|| {
            assert!(canary.as_bytes().is_empty(), "credential predicate failed")
        }))
        .expect_err("generated canary assertion intentionally failed");
        let panic_text = panic
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("");
        assert!(!panic_text
            .as_bytes()
            .windows(canary.len())
            .any(|window| window == canary.as_bytes()));
    }

    #[test]
    fn credential_proxy_reserves_index_before_create_and_reconciles_ambiguous_index_writes() {
        let failed_repository = FakeRepository::new();
        failed_repository.state().index_write_failures_before = 1;
        let failed_proxy = CredentialProxy::with_repository(failed_repository.clone());
        assert_protocol_error(
            &set(
                &failed_proxy,
                "provider",
                json!({"type": "api_key", "key": "value"}),
            ),
            ErrorCategory::Unavailable,
            "Credential store unavailable",
            true,
        );
        let state = failed_repository.state();
        assert!(state.secrets.is_empty());
        assert!(state.labels.is_empty());
        assert!(state.index.is_none());
        assert_eq!(state.create_at_calls, 0);
        drop(state);

        let committed_repository = FakeRepository::new();
        committed_repository.state().index_write_failures_after = 1;
        let committed_proxy = CredentialProxy::with_repository(committed_repository.clone());
        assert_success(&set(
            &committed_proxy,
            "provider",
            json!({"type": "api_key", "key": "value"}),
        ));
        let state = committed_repository.state();
        assert_eq!(state.secrets.len(), 1);
        assert_eq!(state.labels.len(), 1);
        assert_eq!(state.create_at_calls, 1);
        drop(state);

        let dangling_repository = FakeRepository::new();
        dangling_repository.state().create_failures_before_secret = 1;
        let dangling_proxy = CredentialProxy::with_repository(dangling_repository.clone());
        assert_protocol_error(
            &set(
                &dangling_proxy,
                "provider",
                json!({"type": "api_key", "key": "first"}),
            ),
            ErrorCategory::Unavailable,
            "Credential store unavailable",
            true,
        );
        let failed_index = index_from_fake(&dangling_repository);
        assert!(failed_index.entries.is_empty());
        assert_eq!(failed_index.pending.len(), 1);
        let failed_reference = failed_index.pending[0].credential_id.clone();
        let reads_before = dangling_repository.state().secret_reads;
        let before_restart = list(&dangling_proxy);
        assert!(response_envelope(&before_restart).payload["entries"]
            .as_array()
            .is_some_and(Vec::is_empty));
        assert_eq!(dangling_repository.state().secret_reads, reads_before);
        {
            let state = dangling_repository.state();
            assert!(state.secrets.is_empty());
            assert!(state.labels.contains(&failed_reference));
        }

        let recreated_proxy = CredentialProxy::with_repository(dangling_repository.clone());
        let after_restart = list(&recreated_proxy);
        assert!(response_envelope(&after_restart).payload["entries"]
            .as_array()
            .is_some_and(Vec::is_empty));
        assert_eq!(dangling_repository.state().secret_reads, reads_before);
        let reconciled = get(&recreated_proxy, "provider");
        assert_eq!(
            response_envelope(&reconciled).payload.get("found"),
            Some(&Value::Bool(false))
        );
        let reconciled_index = index_from_fake(&dangling_repository);
        assert!(reconciled_index.entries.is_empty());
        assert!(reconciled_index.pending.is_empty());

        assert_success(&set(
            &recreated_proxy,
            "provider",
            json!({"type": "api_key", "key": "second"}),
        ));
        let recovered_reference = index_from_fake(&dangling_repository).entries[0]
            .credential_id
            .clone();
        assert_ne!(failed_reference, recovered_reference);
        let state = dangling_repository.state();
        assert!(!state.labels.contains(&failed_reference));
        assert!(state.labels.contains(&recovered_reference));
        assert!(state.secrets.contains_key(&recovered_reference));
        drop(state);

        let promotion_repository = FakeRepository::new();
        promotion_repository
            .state()
            .index_write_failure_before_on_call = Some(2);
        let promotion_proxy = CredentialProxy::with_repository(promotion_repository.clone());
        assert_protocol_error(
            &set(
                &promotion_proxy,
                "provider",
                json!({"type": "api_key", "key": "committed-secret"}),
            ),
            ErrorCategory::Unavailable,
            "Credential store unavailable",
            true,
        );
        let promotion_index = index_from_fake(&promotion_repository);
        assert!(promotion_index.entries.is_empty());
        assert_eq!(promotion_index.pending.len(), 1);
        assert!(response_envelope(&list(&promotion_proxy)).payload["entries"]
            .as_array()
            .is_some_and(Vec::is_empty));
        let promotion_recreated =
            CredentialProxy::with_repository(promotion_repository.clone());
        let recovered = get(&promotion_recreated, "provider");
        assert_success(&recovered);
        assert_eq!(
            response_envelope(&recovered).payload.get("found"),
            Some(&Value::Bool(true))
        );
        let promoted_index = index_from_fake(&promotion_repository);
        assert_eq!(promoted_index.entries.len(), 1);
        assert!(promoted_index.pending.is_empty());
    }

    #[test]
    fn credential_proxy_incomplete_pairs_are_cleaned_before_production_like_upsert() {
        let repository = FakeRepository::new();
        let proxy = CredentialProxy::with_repository(repository.clone());
        assert_success(&set(
            &proxy,
            "provider",
            json!({"type": "api_key", "key": "first"}),
        ));
        let first_reference = index_from_fake(&repository).entries[0]
            .credential_id
            .clone();
        repository.state().labels.remove(&first_reference);
        repository.state().secret_cleanup_failures = 2;
        assert_success(&set(
            &proxy,
            "provider",
            json!({"type": "api_key", "key": "second"}),
        ));
        let second_reference = index_from_fake(&repository).entries[0]
            .credential_id
            .clone();
        assert_ne!(first_reference, second_reference);
        let state = repository.state();
        assert_eq!(state.overwrite_calls, 0);
        assert!(!state.secrets.contains_key(&first_reference));
        assert!(state.secrets.contains_key(&second_reference));
        drop(state);

        let blocked_repository = FakeRepository::new();
        let blocked_proxy = CredentialProxy::with_repository(blocked_repository.clone());
        assert_success(&set(
            &blocked_proxy,
            "provider",
            json!({"type": "api_key", "key": "first"}),
        ));
        let reference = index_from_fake(&blocked_repository).entries[0]
            .credential_id
            .clone();
        blocked_repository.state().labels.remove(&reference);
        blocked_repository
            .state()
            .persistent_secret_cleanup_failure = true;
        assert_protocol_error(
            &set(
                &blocked_proxy,
                "provider",
                json!({"type": "api_key", "key": "second"}),
            ),
            ErrorCategory::Unavailable,
            "Credential store unavailable",
            true,
        );
        let state = blocked_repository.state();
        assert!(state.secrets.contains_key(&reference));
        assert_eq!(state.overwrite_calls, 0);
        assert_eq!(state.create_at_calls, 1);
        drop(state);
        assert_eq!(
            index_from_fake(&blocked_repository).entries[0].credential_id,
            reference
        );
    }

    #[test]
    fn credential_proxy_type_change_is_ordered_non_replayed_and_get_reconciles_actual_type() {
        let repository = FakeRepository::new();
        let proxy = CredentialProxy::with_repository(repository.clone());
        assert_success(&set(
            &proxy,
            "provider",
            json!({"type": "api_key", "key": "old"}),
        ));
        repository.state().index_write_failures_before = 1;
        assert_protocol_error(
            &set(
                &proxy,
                "provider",
                json!({"type": "oauth", "access": "new", "refresh": "", "expires": 1}),
            ),
            ErrorCategory::Unavailable,
            "Credential store unavailable",
            true,
        );
        assert_eq!(repository.state().overwrite_calls, 0);
        let unchanged_index = index_from_fake(&repository);
        assert_eq!(
            unchanged_index.entries[0].credential_type,
            CredentialType::ApiKey
        );
        assert!(unchanged_index.pending.is_empty());

        repository.state().index_write_failures_after = 1;
        assert_success(&set(
            &proxy,
            "provider",
            json!({"type": "oauth", "access": "new", "refresh": "", "expires": 1}),
        ));
        assert_eq!(repository.state().overwrite_calls, 1);

        let before_repository = FakeRepository::new();
        let before_proxy = CredentialProxy::with_repository(before_repository.clone());
        assert_success(&set(
            &before_proxy,
            "provider",
            json!({"type": "api_key", "key": "old"}),
        ));
        before_repository.state().overwrite_failures_before = 1;
        assert_protocol_error(
            &set(
                &before_proxy,
                "provider",
                json!({"type": "oauth", "access": "new", "refresh": "", "expires": 1}),
            ),
            ErrorCategory::Unavailable,
            "Credential store unavailable",
            true,
        );
        assert_eq!(before_repository.state().overwrite_calls, 1);
        let failed_index = index_from_fake(&before_repository);
        assert_eq!(
            failed_index.entries[0].credential_type,
            CredentialType::ApiKey
        );
        assert_eq!(failed_index.pending.len(), 1);
        assert_eq!(
            failed_index.pending[0].desired_type,
            CredentialType::Oauth
        );
        let reads_before_list = before_repository.state().secret_reads;
        let transient_list = list(&before_proxy);
        assert_eq!(
            response_envelope(&transient_list).payload["entries"][0]["type"].as_str(),
            Some("api_key")
        );
        assert_eq!(before_repository.state().secret_reads, reads_before_list);

        let before_recreated = CredentialProxy::with_repository(before_repository.clone());
        let restarted_list = list(&before_recreated);
        assert_eq!(
            response_envelope(&restarted_list).payload["entries"][0]["type"].as_str(),
            Some("api_key")
        );
        assert_eq!(before_repository.state().secret_reads, reads_before_list);

        before_repository.state().index_write_failures_before = 1;
        assert_protocol_error(
            &get(&before_recreated, "provider"),
            ErrorCategory::Unavailable,
            "Credential store unavailable",
            true,
        );
        let still_pending = index_from_fake(&before_repository);
        assert_eq!(
            still_pending.entries[0].credential_type,
            CredentialType::ApiKey
        );
        assert_eq!(still_pending.pending.len(), 1);
        let recovered = get(&before_recreated, "provider");
        assert_success(&recovered);
        assert_eq!(
            response_envelope(&recovered).payload["credential"]["type"].as_str(),
            Some("api_key")
        );
        let recovered_index = index_from_fake(&before_repository);
        assert_eq!(
            recovered_index.entries[0].credential_type,
            CredentialType::ApiKey
        );
        assert!(recovered_index.pending.is_empty());
        assert_eq!(before_repository.state().overwrite_calls, 1);

        let after_repository = FakeRepository::new();
        let after_proxy = CredentialProxy::with_repository(after_repository.clone());
        assert_success(&set(
            &after_proxy,
            "provider",
            json!({"type": "api_key", "key": "old"}),
        ));
        after_repository.state().overwrite_failures_after = 1;
        assert_protocol_error(
            &set(
                &after_proxy,
                "provider",
                json!({"type": "oauth", "access": "new", "refresh": "", "expires": 1}),
            ),
            ErrorCategory::Unavailable,
            "Credential store unavailable",
            true,
        );
        let applied_pending = index_from_fake(&after_repository);
        assert_eq!(
            applied_pending.entries[0].credential_type,
            CredentialType::ApiKey
        );
        assert_eq!(applied_pending.pending.len(), 1);
        assert_eq!(
            response_envelope(&list(&after_proxy)).payload["entries"][0]["type"].as_str(),
            Some("api_key")
        );
        let after_recreated = CredentialProxy::with_repository(after_repository.clone());
        assert_eq!(
            response_envelope(&list(&after_recreated)).payload["entries"][0]["type"].as_str(),
            Some("api_key")
        );
        after_repository.state().index_write_failures_after = 1;
        let recovered = get(&after_recreated, "provider");
        assert_success(&recovered);
        assert_eq!(
            response_envelope(&recovered).payload["credential"]["type"].as_str(),
            Some("oauth")
        );
        assert_eq!(after_repository.state().overwrite_calls, 1);
        let applied_recovered = index_from_fake(&after_repository);
        assert_eq!(
            applied_recovered.entries[0].credential_type,
            CredentialType::Oauth
        );
        assert!(applied_recovered.pending.is_empty());
    }

    #[test]
    fn credential_proxy_remove_failure_leaves_only_healable_indexed_state() {
        let repository = FakeRepository::new();
        let proxy = CredentialProxy::with_repository(repository.clone());
        assert_success(&set(
            &proxy,
            "provider",
            json!({"type": "api_key", "key": "first"}),
        ));
        let first_reference = index_from_fake(&repository).entries[0]
            .credential_id
            .clone();
        repository.state().index_write_failures_before = 1;
        assert_protocol_error(
            &remove(&proxy, "provider"),
            ErrorCategory::Unavailable,
            "Credential store unavailable",
            true,
        );
        {
            let state = repository.state();
            assert!(state.secrets.is_empty());
            assert!(state.labels.is_empty());
        }
        assert_eq!(
            index_from_fake(&repository).entries[0].credential_id,
            first_reference
        );

        assert_success(&set(
            &proxy,
            "provider",
            json!({"type": "api_key", "key": "second"}),
        ));
        let second_reference = index_from_fake(&repository).entries[0]
            .credential_id
            .clone();
        assert_ne!(first_reference, second_reference);
        let state = repository.state();
        assert_eq!(state.secrets.len(), 1);
        assert_eq!(state.labels.len(), 1);
        assert!(state.secrets.contains_key(&second_reference));
    }

    #[test]
    fn credential_proxy_secret_owners_zeroise_invalid_set_and_stored_values() {
        let repository = FakeRepository::new();
        let proxy = CredentialProxy::with_repository(repository.clone());
        let canary = format!("secret-owner-{}", Uuid::new_v4().simple());
        let before = private_zeroised_bytes_for_test();
        assert_protocol_error(
            &set(
                &proxy,
                "provider",
                json!({"type": "api_key", "key": canary, "unknown": true}),
            ),
            ErrorCategory::InvalidRequest,
            "Credential request rejected",
            false,
        );
        assert!(private_zeroised_bytes_for_test() >= before + canary.len());

        assert_success(&set(
            &proxy,
            "provider",
            json!({"type": "api_key", "key": "valid"}),
        ));
        let credential_id = index_from_fake(&repository).entries[0]
            .credential_id
            .clone();
        repository.state().secrets.insert(
            credential_id,
            serde_json::to_vec(&json!({"type": "api_key", "key": canary, "bad": true})).unwrap(),
        );
        let before = private_zeroised_bytes_for_test();
        assert_protocol_error(
            &get(&proxy, "provider"),
            ErrorCategory::Internal,
            "Credential operation failed",
            false,
        );
        assert!(private_zeroised_bytes_for_test() >= before + canary.len());
    }

    #[test]
    fn credential_proxy_cancellation_validates_request_and_never_touches_storage() {
        let repository = FakeRepository::new();
        let proxy = CredentialProxy::with_repository(repository.clone());

        let mut wrong_kind = request(json!({"method": "credential.list"}));
        wrong_kind.kind = ProtocolKind::Request;
        let mut forbidden = request(json!({"method": "credential.list"}));
        forbidden.correlation_id = Some("forbidden-correlation".into());
        let invalid_requests = [
            wrong_kind,
            forbidden,
            request(json!({"method": "credential.unknown"})),
            request(json!({
                "method": "credential.set",
                "providerId": "provider",
                "credential": {"type": "api_key", "key": 42}
            })),
        ];
        for (index, request) in invalid_requests.into_iter().enumerate() {
            let response = proxy
                .dispatch_cancelled(request, format!("cancel-invalid-{index}"), 10 + index as u64)
                .unwrap();
            assert_protocol_error(
                &response,
                ErrorCategory::InvalidRequest,
                "Credential request rejected",
                false,
            );
        }

        let valid = proxy
            .dispatch_cancelled(
                request(json!({
                    "method": "credential.set",
                    "providerId": "provider",
                    "credential": {"type": "api_key", "key": "private"}
                })),
                "cancel-valid".into(),
                20,
            )
            .unwrap();
        assert_protocol_error(
            &valid,
            ErrorCategory::Cancelled,
            "Credential request cancelled",
            true,
        );
        let state = repository.state();
        assert_eq!(state.index_reads, 0);
        assert_eq!(state.create_at_calls, 0);
        assert_eq!(state.overwrite_calls, 0);
    }

    #[test]
    fn private_response_writer_is_move_only_bounded_lf_and_erases_source() {
        let canary = format!("writer-canary-{}", Uuid::new_v4().simple());
        let response = success_response(
            "private-response-a".into(),
            "private-request-a".into(),
            1,
            OperationOutcome::Get(Some(PrivateValue::new(json!({
                "type": "api_key", "key": canary
            })))),
        );
        let wire = response.into_lf_json().unwrap();
        assert!(wire.ends_with(b"\n"));
        assert!(wire
            .windows(canary.len())
            .any(|window| window == canary.as_bytes()));
        drop(wire);

        let mut exact = success_response(
            "private-response-b".into(),
            "private-request-b".into(),
            2,
            OperationOutcome::Set,
        );
        let encoded_len = serde_json::to_vec(exact.envelope_for_test()).unwrap().len();
        let accepted = exact
            .serialise_with_limit_for_test(encoded_len + 1)
            .unwrap();
        assert_eq!(accepted.len(), encoded_len + 1);
        assert!(exact.envelope_for_test().payload.is_empty());
        assert!(exact.envelope_for_test().id.is_empty());

        let mut rejected = success_response(
            "private-response-c".into(),
            "private-request-c".into(),
            3,
            OperationOutcome::Get(Some(PrivateValue::new(json!({
                "type": "api_key", "key": canary
            })))),
        );
        let rejected_len = serde_json::to_vec(rejected.envelope_for_test()).unwrap().len();
        assert!(rejected
            .serialise_with_limit_for_test(rejected_len)
            .is_err());
        assert!(rejected.envelope_for_test().payload.is_empty());
        assert!(rejected.envelope_for_test().error.is_none());
        assert!(rejected.envelope_for_test().id.is_empty());
    }

    #[test]
    fn credential_proxy_index_bound_corruption_and_poisoning_fail_closed() {
        let bounded_repository = FakeRepository::new();
        let entries = (1..=MAX_INDEX_ENTRIES)
            .map(|index| IndexEntry {
                provider_id: format!("provider-{index}"),
                credential_id: format!("credential-{index:032x}"),
                credential_type: CredentialType::ApiKey,
            })
            .collect();
        bounded_repository.state().index = Some(
            serde_json::to_vec(&IndexDocument {
                version: INDEX_VERSION,
                entries,
                pending: Vec::new(),
            })
            .unwrap(),
        );
        let bounded_proxy = CredentialProxy::with_repository(bounded_repository.clone());
        assert_eq!(
            response_envelope(&list(&bounded_proxy))
                .payload
                .get("entries")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(MAX_INDEX_ENTRIES)
        );
        assert_protocol_error(
            &set(
                &bounded_proxy,
                "one-more-provider",
                json!({"type": "api_key", "key": "value"}),
            ),
            ErrorCategory::Unavailable,
            "Credential store unavailable",
            true,
        );
        assert_eq!(bounded_repository.state().create_at_calls, 0);

        bounded_repository.state().index = Some(
            br#"{"version":1,"entries":[],"unexpected":true}"#.to_vec(),
        );
        assert_protocol_error(
            &list(&bounded_proxy),
            ErrorCategory::Internal,
            "Credential operation failed",
            false,
        );

        for corrupt in [
            br#"{"version":1,"entries":[],"pending":[{"operation":"create","providerId":"provider","credentialId":"credential-00000000000000000000000000000001","desiredType":"api_key","unexpected":true}]}"#.as_slice(),
            br#"{"version":1,"entries":[],"pending":[{"operation":"create","providerId":"provider","credentialId":"credential-00000000000000000000000000000001","desiredType":"api_key"},{"operation":"create","providerId":"provider","credentialId":"credential-00000000000000000000000000000002","desiredType":"oauth"}]}"#.as_slice(),
            br#"{"version":1,"entries":[{"providerId":"provider","credentialId":"credential-00000000000000000000000000000001","type":"api_key"}],"pending":[{"operation":"create","providerId":"provider","credentialId":"credential-00000000000000000000000000000002","desiredType":"oauth"}]}"#.as_slice(),
            br#"{"version":1,"entries":[],"pending":[{"operation":"type_change","providerId":"provider","credentialId":"credential-00000000000000000000000000000001","desiredType":"oauth"}]}"#.as_slice(),
        ] {
            bounded_repository.state().index = Some(corrupt.to_vec());
            assert_protocol_error(
                &list(&bounded_proxy),
                ErrorCategory::Internal,
                "Credential operation failed",
                false,
            );
        }

        let oversized_pending = (0..=MAX_PENDING_INDEX_ENTRIES)
            .map(|index| PendingIndexEntry {
                operation: PendingOperation::Create,
                provider_id: format!("pending-{index}"),
                credential_id: format!("credential-{:032x}", index + 1),
                desired_type: CredentialType::ApiKey,
            })
            .collect();
        bounded_repository.state().index =
            Some(serde_json::to_vec(&IndexDocument {
                version: INDEX_VERSION,
                entries: Vec::new(),
                pending: oversized_pending,
            }).unwrap());
        assert_protocol_error(
            &list(&bounded_proxy),
            ErrorCategory::Internal,
            "Credential operation failed",
            false,
        );

        let maximal_providers: Vec<String> = (0..MAX_INDEX_ENTRIES)
            .map(|index| format!("{}-{index:03}", "🦀".repeat(124)))
            .collect();
        let mut byte_heavy_index = IndexDocument {
            version: INDEX_VERSION,
            entries: maximal_providers
                .iter()
                .enumerate()
                .map(|(index, provider_id)| IndexEntry {
                    provider_id: provider_id.clone(),
                    credential_id: format!("credential-{:032x}", index + 1),
                    credential_type: CredentialType::ApiKey,
                })
                .collect(),
            pending: maximal_providers
                .into_iter()
                .enumerate()
                .map(|(index, provider_id)| PendingIndexEntry {
                    operation: PendingOperation::TypeChange,
                    provider_id,
                    credential_id: format!("credential-{:032x}", index + 1),
                    desired_type: CredentialType::Oauth,
                })
                .collect(),
        };
        assert!(validate_index(&byte_heavy_index).is_ok());
        let byte_heavy_repository = FakeRepository::new();
        let mut byte_heavy_repository_box: Box<dyn CredentialRepository> =
            Box::new(byte_heavy_repository.clone());
        assert!(matches!(
            persist_index(
                byte_heavy_repository_box.as_mut(),
                &mut byte_heavy_index,
            ),
            Err(OperationError::Unavailable)
        ));
        assert_eq!(byte_heavy_repository.state().index_writes, 0);

        let poisoned_repository = FakeRepository::new();
        let poisoned_proxy = CredentialProxy::with_repository(poisoned_repository.clone());
        let poison_target = poisoned_proxy.clone();
        let _ = catch_unwind(AssertUnwindSafe(move || {
            let _guard = poison_target.inner.lock().unwrap();
            panic!("poison repository lock for policy test");
        }));
        for _ in 0..2 {
            assert_protocol_error(
                &list(&poisoned_proxy),
                ErrorCategory::Internal,
                "Credential operation failed",
                false,
            );
        }
        assert_eq!(poisoned_repository.state().index_reads, 0);
    }

    #[derive(Default)]
    struct OperationGate {
        entered: AtomicUsize,
        state: StdMutex<bool>,
        changed: Condvar,
    }

    impl OperationGate {
        fn enter_and_wait(&self) {
            self.entered.fetch_add(1, Ordering::SeqCst);
            self.changed.notify_all();
            let mut released = self.state.lock().unwrap();
            while !*released {
                released = self.changed.wait(released).unwrap();
            }
        }

        fn wait_for_first(&self) {
            let mut released = self.state.lock().unwrap();
            while self.entered.load(Ordering::SeqCst) == 0 {
                let result = self
                    .changed
                    .wait_timeout(released, Duration::from_secs(2))
                    .unwrap();
                released = result.0;
                assert!(!result.1.timed_out(), "first repository operation entered");
            }
        }

        fn release(&self) {
            *self.state.lock().unwrap() = true;
            self.changed.notify_all();
        }
    }

    struct GateRepository {
        gate: Arc<OperationGate>,
    }

    impl CredentialRepository for GateRepository {
        fn create_at_reference(
            &mut self,
            _credential_id: &str,
            _account_label: &str,
            _secret: SecretMaterial,
        ) -> Result<(), CredentialError> {
            unreachable!()
        }

        fn overwrite(
            &mut self,
            _credential_id: &str,
            _secret: &SecretMaterial,
        ) -> Result<(), CredentialError> {
            unreachable!()
        }

        fn pair_status(
            &mut self,
            _credential_id: &str,
        ) -> Result<CredentialPairStatus, CredentialError> {
            unreachable!()
        }

        fn read(&mut self, _credential_id: &str) -> Result<SecretMaterial, CredentialError> {
            unreachable!()
        }

        fn reconcile_delete(&mut self, _credential_id: &str) -> Result<(), CredentialError> {
            unreachable!()
        }

        fn read_index(&mut self) -> Result<Option<IndexMaterial>, CredentialError> {
            self.gate.enter_and_wait();
            Ok(None)
        }

        fn write_index(&mut self, _index: IndexMaterial) -> Result<(), CredentialError> {
            unreachable!()
        }
    }

    #[test]
    fn cloned_application_proxy_serialises_repository_operations_across_generations() {
        let gate = Arc::new(OperationGate::default());
        let proxy = CredentialProxy::with_repository(GateRepository {
            gate: Arc::clone(&gate),
        });
        let generation_one = proxy.clone();
        let generation_two = proxy.clone();

        let first = thread::spawn(move || list(&generation_one));
        gate.wait_for_first();
        let second = thread::spawn(move || list(&generation_two));
        thread::sleep(Duration::from_millis(50));
        assert_eq!(gate.entered.load(Ordering::SeqCst), 1);
        gate.release();
        assert_success(&first.join().unwrap());
        assert_success(&second.join().unwrap());
        assert_eq!(gate.entered.load(Ordering::SeqCst), 2);
    }

    #[cfg(target_os = "macos")]
    struct RealKeychainCleanup {
        repository: KeychainRepository,
        credential_ids: HashSet<String>,
        active: bool,
    }

    #[cfg(target_os = "macos")]
    impl RealKeychainCleanup {
        fn new(repository: KeychainRepository) -> Self {
            Self {
                repository,
                credential_ids: HashSet::new(),
                active: true,
            }
        }

        fn capture_index(&mut self) {
            let Ok(Some(index)) = self.repository.read_index() else {
                return;
            };
            let Ok(index) = serde_json::from_slice::<IndexDocument>(index.expose()) else {
                return;
            };
            self.credential_ids.extend(
                index
                    .entries
                    .into_iter()
                    .map(|entry| entry.credential_id)
                    .chain(
                        index
                            .pending
                            .into_iter()
                            .map(|pending| pending.credential_id),
                    ),
            );
        }

        fn clean(&mut self) {
            self.capture_index();
            for credential_id in self.credential_ids.drain() {
                let _ = self.repository.reconcile_delete(&credential_id);
            }
            let _ = self.repository.delete_index();
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for RealKeychainCleanup {
        fn drop(&mut self) {
            if self.active {
                self.clean();
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires an interactive macOS login Keychain; run serially"]
    fn credential_proxy_real_macos_keychain_restart_lifecycle() {
        let namespace = format!("proxy-{}", Uuid::new_v4().simple());
        let repository = KeychainRepository::for_tests(&namespace).expect("isolated namespace");
        let mut cleanup = RealKeychainCleanup::new(repository.clone());
        let canary = format!("disposable-{}", Uuid::new_v4().simple());
        let provider_id = "integration.provider";

        let first_proxy = CredentialProxy::new(repository.clone());
        assert_success(&set(
            &first_proxy,
            provider_id,
            json!({"type": "api_key", "key": canary, "env": {"MODE": "test"}}),
        ));
        cleanup.capture_index();
        let first_reference = cleanup
            .credential_ids
            .iter()
            .next()
            .cloned()
            .expect("opaque reference captured");
        let found = get(&first_proxy, provider_id);
        let found_key = response_envelope(&found).payload["credential"]["key"].as_str();
        assert!(found_key.is_some_and(|key| key == canary));

        assert_success(&set(
            &first_proxy,
            provider_id,
            json!({
                "type": "oauth",
                "access": canary,
                "refresh": "",
                "expires": 123,
                "integration": {"bounded": true}
            }),
        ));
        cleanup.capture_index();
        assert_eq!(cleanup.credential_ids.len(), 1);
        assert!(cleanup.credential_ids.contains(&first_reference));

        drop(first_proxy);
        let recreated_proxy = CredentialProxy::new(repository.clone());
        let recovered = get(&recreated_proxy, provider_id);
        let recovered_access =
            response_envelope(&recovered).payload["credential"]["access"].as_str();
        assert!(recovered_access.is_some_and(|access| access == canary));
        assert_success(&remove(&recreated_proxy, provider_id));
        assert_eq!(
            response_envelope(&get(&recreated_proxy, provider_id))
                .payload
                .get("found"),
            Some(&Value::Bool(false))
        );

        cleanup.clean();
        assert!(repository.read_index().expect("index cleanup read").is_none());
        let missing_secret = match repository.read(&first_reference) {
            Err(error) => error,
            Ok(_) => panic!("secret entry was not cleaned"),
        };
        assert_eq!(missing_secret.code(), CredentialError::not_found().code());
        assert_eq!(
            repository
                .metadata(&first_reference)
                .expect_err("label entry cleaned")
                .code(),
            CredentialError::not_found().code()
        );
        cleanup.active = false;
    }
}
