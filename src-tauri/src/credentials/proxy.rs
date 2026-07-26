use super::keychain::{CredentialPairStatus, IndexMaterial};
use super::{CredentialError, KeychainRepository, SecretMaterial};
use crate::protocol::{
    Envelope, EnvelopeError, ErrorCategory, MAX_LINE_BYTES, ProtocolKind, validate_envelope,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};
#[cfg(test)]
use std::sync::MutexGuard;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

const INDEX_VERSION: u8 = 1;
const MAX_INDEX_ENTRIES: usize = 256;
const MAX_PENDING_INDEX_ENTRIES: usize = 256;
const MAX_PROVIDER_SCALARS: usize = 128;
const MAX_CREDENTIAL_BYTES: usize = 65_536;
const MAX_JSON_DEPTH: usize = 32;
const MAX_OBJECT_PROPERTIES: usize = 128;
const MAX_ARRAY_ITEMS: usize = 256;
const MAX_OBJECT_KEY_UTF16_UNITS: usize = 128;
const MAX_JS_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const ACCOUNT_LABEL: &str = "PIUI provider credential";

#[cfg(test)]
static PRIVATE_ZEROISED_BYTES: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
pub(crate) fn private_zeroised_bytes_for_test() -> usize {
    PRIVATE_ZEROISED_BYTES.load(Ordering::Relaxed)
}

fn zeroise_string(value: &mut String) {
    #[cfg(test)]
    PRIVATE_ZEROISED_BYTES.fetch_add(value.len(), Ordering::Relaxed);
    value.zeroize();
}

#[derive(Clone)]
pub struct CredentialProxy {
    // A poisoned repository mutex is deliberately permanent fail-closed for
    // this application-owned proxy. Continuing with possibly interrupted
    // repository state would silently weaken transaction ordering; restart
    // creates a fresh proxy and reloads the authoritative Keychain index.
    inner: Arc<Mutex<Box<dyn CredentialRepository>>>,
}

impl CredentialProxy {
    pub fn new(repository: KeychainRepository) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Box::new(repository))),
        }
    }

    /// Executes a decoded private request without reserving wire coordinates.
    /// This blocking seam is retained for the accepted A.15b-1 tests and
    /// non-supervisor callers.
    #[cfg(test)]
    pub(crate) fn execute_request(&self, request: Envelope) -> PendingHostResponse {
        self.prepare_request(request, ExecutionMode::Blocking)
    }

    /// Supervisor execution fails promptly as unavailable if another stale
    /// generation still owns the shared repository mutex.
    pub(crate) fn try_execute_request(&self, request: Envelope) -> PendingHostResponse {
        self.prepare_request(request, ExecutionMode::Try)
    }

    /// Fully validates a queued request after generation cancellation without
    /// acquiring the repository lock or performing a mutation.
    pub(crate) fn cancel_request(&self, request: Envelope) -> PendingHostResponse {
        self.prepare_request(request, ExecutionMode::Cancelled)
    }

    fn prepare_request(&self, request: Envelope, mode: ExecutionMode) -> PendingHostResponse {
        let mut request = PrivateEnvelope::new(request);
        let correlation_id = request.envelope().id.clone();

        // Parsing always precedes cancellation so invalid or secret-malformed
        // requests cannot be reclassified as valid cancellations.
        let result = parse_operation(request.envelope_mut()).and_then(|operation| match mode {
            ExecutionMode::Cancelled => {
                drop(operation);
                Err(OperationError::Cancelled)
            }
            #[cfg(test)]
            ExecutionMode::Blocking => self.execute(operation),
            ExecutionMode::Try => self.try_execute(operation),
        });
        PendingHostResponse::new(correlation_id, result)
    }

    /// Backwards-compatible focused-test seam. Production dispatch first calls
    /// `execute_request`, then binds coordinates only while holding the sole
    /// generation writer.
    #[cfg(test)]
    pub(crate) fn dispatch(
        &self,
        request: Envelope,
        response_id: String,
        response_sequence: u64,
    ) -> Result<PrivateHostResponse, CredentialDispatchError> {
        self.execute_request(request)
            .bind(response_id, response_sequence)
    }

    /// Backwards-compatible cancellation seam with the same deferred binding.
    #[cfg(test)]
    pub(crate) fn dispatch_cancelled(
        &self,
        request: Envelope,
        response_id: String,
        response_sequence: u64,
    ) -> Result<PrivateHostResponse, CredentialDispatchError> {
        self.cancel_request(request)
            .bind(response_id, response_sequence)
    }

    #[cfg(test)]
    fn execute(&self, operation: Operation) -> Result<OperationOutcome, OperationError> {
        let mut repository = self.lock_repository()?;
        execute_with_repository(repository.as_mut(), operation)
    }

    fn try_execute(&self, operation: Operation) -> Result<OperationOutcome, OperationError> {
        let mut repository = match self.inner.try_lock() {
            Ok(repository) => repository,
            Err(std::sync::TryLockError::WouldBlock) => {
                drop(operation);
                return Err(OperationError::Unavailable);
            }
            Err(std::sync::TryLockError::Poisoned(_)) => {
                drop(operation);
                return Err(OperationError::Internal);
            }
        };
        execute_with_repository(repository.as_mut(), operation)
    }

    #[cfg(test)]
    fn lock_repository(
        &self,
    ) -> Result<MutexGuard<'_, Box<dyn CredentialRepository>>, OperationError> {
        self.inner.lock().map_err(|_| OperationError::Internal)
    }

    #[cfg(test)]
    fn with_repository(repository: impl CredentialRepository + 'static) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Box::new(repository))),
        }
    }

    #[cfg(test)]
    pub(crate) fn in_memory_for_dispatcher_test() -> Self {
        Self::with_repository(DispatcherMemoryRepository::default())
    }

    #[cfg(test)]
    pub(crate) fn in_memory_with_dispatcher_gate_for_test() -> (Self, DispatcherTestGate) {
        let gate = DispatcherTestGate::default();
        (
            Self::with_repository(DispatcherMemoryRepository {
                gate: Some(gate.clone()),
                ..DispatcherMemoryRepository::default()
            }),
            gate,
        )
    }
}

impl Default for CredentialProxy {
    fn default() -> Self {
        Self::new(KeychainRepository::new())
    }
}

impl Debug for CredentialProxy {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CredentialProxy { repository: <redacted> }")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CredentialDispatchError;

impl Display for CredentialDispatchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("credential-dispatch-build-failed")
    }
}

impl Debug for CredentialDispatchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CredentialDispatchError")
    }
}

impl std::error::Error for CredentialDispatchError {}

/// Move-only execution result awaiting wire coordinates. It cannot be cloned,
/// serialised or inspected outside this module; dropping it erases any owned
/// credential through `PrivateValue` and its correlation identifier here.
pub(crate) struct PendingHostResponse {
    correlation_id: String,
    result: Option<Result<OperationOutcome, OperationError>>,
}

impl PendingHostResponse {
    fn new(correlation_id: String, result: Result<OperationOutcome, OperationError>) -> Self {
        Self {
            correlation_id,
            result: Some(result),
        }
    }

    pub(crate) fn bind(
        mut self,
        response_id: String,
        response_sequence: u64,
    ) -> Result<PrivateHostResponse, CredentialDispatchError> {
        validate_response_coordinates(&self.correlation_id, &response_id, response_sequence)?;
        let correlation_id = std::mem::take(&mut self.correlation_id);
        let result = self.result.take().ok_or(CredentialDispatchError)?;
        let response = match result {
            Ok(outcome) => {
                success_response(response_id, correlation_id, response_sequence, outcome)
            }
            Err(error) => error_response(response_id, correlation_id, response_sequence, error),
        };
        debug_assert!(validate_envelope(response.envelope()).is_ok());
        Ok(response)
    }
}

impl Drop for PendingHostResponse {
    fn drop(&mut self) {
        zeroise_string(&mut self.correlation_id);
        // The optional result drops here. Secret-bearing `PrivateValue`
        // allocations recursively erase themselves.
        self.result.take();
    }
}

impl Debug for PendingHostResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PendingHostResponse { payload: <redacted> }")
    }
}

/// Move-only private host response. It is crate-private, is not `Clone` or
/// `Serialize`, and does not expose its secret-bearing envelope in production.
pub(crate) struct PrivateHostResponse {
    envelope: Envelope,
}

impl PrivateHostResponse {
    fn new(envelope: Envelope) -> Self {
        Self { envelope }
    }

    fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    /// The sole production output API. Serialisation is LF-delimited and
    /// bounded, the returned allocation zeroises on drop, and all source
    /// private strings are recursively erased whether serialisation succeeds
    /// or fails.
    pub(crate) fn into_lf_json(mut self) -> Result<Zeroizing<Vec<u8>>, CredentialDispatchError> {
        self.serialise_with_limit(MAX_LINE_BYTES)
    }

    fn serialise_with_limit(
        &mut self,
        max_line_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialDispatchError> {
        let result = if self.envelope.kind != ProtocolKind::HostResponse
            || validate_envelope(&self.envelope).is_err()
        {
            Err(CredentialDispatchError)
        } else {
            serde_json::to_vec(&self.envelope)
                .map(Zeroizing::new)
                .map_err(|_| CredentialDispatchError)
                .and_then(|mut bytes| {
                    // The decoder's maximum includes the terminating LF.
                    if bytes.len() >= max_line_bytes {
                        return Err(CredentialDispatchError);
                    }
                    bytes.push(b'\n');
                    Ok(bytes)
                })
        };
        zeroise_private_envelope(&mut self.envelope);
        result
    }

    #[cfg(test)]
    fn envelope_for_test(&self) -> &Envelope {
        &self.envelope
    }

    #[cfg(test)]
    fn serialise_with_limit_for_test(
        &mut self,
        max_line_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialDispatchError> {
        self.serialise_with_limit(max_line_bytes)
    }
}

impl Drop for PrivateHostResponse {
    fn drop(&mut self) {
        zeroise_private_envelope(&mut self.envelope);
    }
}

impl Debug for PrivateHostResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PrivateHostResponse { payload: <redacted> }")
    }
}

pub(crate) fn discard_private_envelope(envelope: Envelope) {
    debug_assert!(matches!(
        envelope.kind,
        ProtocolKind::HostRequest | ProtocolKind::HostResponse
    ));
    drop(PrivateEnvelope::new(envelope));
}

struct PrivateEnvelope {
    envelope: Envelope,
}

impl PrivateEnvelope {
    fn new(envelope: Envelope) -> Self {
        Self { envelope }
    }

    fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    fn envelope_mut(&mut self) -> &mut Envelope {
        &mut self.envelope
    }
}

impl Drop for PrivateEnvelope {
    fn drop(&mut self) {
        zeroise_private_envelope(&mut self.envelope);
    }
}

impl Debug for PrivateEnvelope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PrivateEnvelope { payload: <redacted> }")
    }
}

struct PrivateValue(Value);

impl PrivateValue {
    fn new(value: Value) -> Self {
        Self(value)
    }

    fn value(&self) -> &Value {
        &self.0
    }

    fn into_value(mut self) -> Value {
        std::mem::take(&mut self.0)
    }

    fn zeroise_now(&mut self) {
        zeroise_value(&mut self.0);
    }
}

impl Drop for PrivateValue {
    fn drop(&mut self) {
        self.zeroise_now();
    }
}

impl Debug for PrivateValue {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PrivateValue(<redacted>)")
    }
}

fn zeroise_private_envelope(envelope: &mut Envelope) {
    zeroise_string(&mut envelope.id);
    if let Some(value) = envelope.correlation_id.as_mut() {
        zeroise_string(value);
    }
    envelope.correlation_id = None;
    if let Some(value) = envelope.decision_id.as_mut() {
        zeroise_string(value);
    }
    envelope.decision_id = None;
    let payload = std::mem::take(&mut envelope.payload);
    zeroise_map(payload);
    if let Some(error) = envelope.error.as_mut() {
        zeroise_string(&mut error.message);
        if let Some(diagnostic_id) = error.diagnostic_id.as_mut() {
            zeroise_string(diagnostic_id);
        }
        error.diagnostic_id = None;
    }
    envelope.error = None;
}

fn zeroise_map(map: Map<String, Value>) {
    for (mut key, mut value) in map {
        zeroise_string(&mut key);
        zeroise_value(&mut value);
    }
}

fn zeroise_value(value: &mut Value) {
    match value {
        Value::String(text) => zeroise_string(text),
        Value::Array(values) => {
            for value in &mut *values {
                zeroise_value(value);
            }
            values.clear();
        }
        Value::Object(map) => {
            let map = std::mem::take(map);
            zeroise_map(map);
        }
        _ => {}
    }
    *value = Value::Null;
}

trait CredentialRepository: Send + Sync {
    fn create_at_reference(
        &mut self,
        credential_id: &str,
        account_label: &str,
        secret: SecretMaterial,
    ) -> Result<(), CredentialError>;
    fn overwrite(
        &mut self,
        credential_id: &str,
        secret: &SecretMaterial,
    ) -> Result<(), CredentialError>;
    fn pair_status(&mut self, credential_id: &str)
    -> Result<CredentialPairStatus, CredentialError>;
    fn read(&mut self, credential_id: &str) -> Result<SecretMaterial, CredentialError>;
    fn reconcile_delete(&mut self, credential_id: &str) -> Result<(), CredentialError>;
    fn read_index(&mut self) -> Result<Option<IndexMaterial>, CredentialError>;
    fn write_index(&mut self, index: IndexMaterial) -> Result<(), CredentialError>;
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct DispatcherTestGate {
    state: Arc<(std::sync::Mutex<(bool, bool)>, std::sync::Condvar)>,
}

#[cfg(test)]
impl DispatcherTestGate {
    fn enter_and_wait(&self) {
        let (lock, condition) = &*self.state;
        let mut state = lock.lock().expect("dispatcher test gate poisoned");
        state.0 = true;
        condition.notify_all();
        while !state.1 {
            state = condition
                .wait(state)
                .expect("dispatcher test gate poisoned");
        }
    }

    pub(crate) fn wait_until_entered(&self) {
        let (lock, condition) = &*self.state;
        let state = lock.lock().expect("dispatcher test gate poisoned");
        let (state, timeout) = condition
            .wait_timeout_while(state, std::time::Duration::from_secs(2), |state| !state.0)
            .expect("dispatcher test gate poisoned");
        assert!(
            state.0 && !timeout.timed_out(),
            "credential test gate was not entered"
        );
    }

    pub(crate) fn release(&self) {
        let (lock, condition) = &*self.state;
        let mut state = lock.lock().expect("dispatcher test gate poisoned");
        state.1 = true;
        condition.notify_all();
    }
}

#[cfg(test)]
#[derive(Default)]
struct DispatcherMemoryRepository {
    credentials: std::collections::HashMap<String, Vec<u8>>,
    index: Option<Vec<u8>>,
    gate: Option<DispatcherTestGate>,
}

#[cfg(test)]
impl CredentialRepository for DispatcherMemoryRepository {
    fn create_at_reference(
        &mut self,
        credential_id: &str,
        _account_label: &str,
        secret: SecretMaterial,
    ) -> Result<(), CredentialError> {
        if self.credentials.contains_key(credential_id) {
            return Err(CredentialError::unavailable());
        }
        if let Some(gate) = self.gate.as_ref() {
            gate.enter_and_wait();
        }
        self.credentials
            .insert(credential_id.to_string(), secret.expose().to_vec());
        Ok(())
    }

    fn overwrite(
        &mut self,
        credential_id: &str,
        secret: &SecretMaterial,
    ) -> Result<(), CredentialError> {
        let stored = self
            .credentials
            .get_mut(credential_id)
            .ok_or_else(CredentialError::not_found)?;
        *stored = secret.expose().to_vec();
        Ok(())
    }

    fn pair_status(
        &mut self,
        credential_id: &str,
    ) -> Result<CredentialPairStatus, CredentialError> {
        if self.credentials.contains_key(credential_id) {
            Ok(CredentialPairStatus::Complete)
        } else {
            Err(CredentialError::not_found())
        }
    }

    fn read(&mut self, credential_id: &str) -> Result<SecretMaterial, CredentialError> {
        SecretMaterial::new(
            self.credentials
                .get(credential_id)
                .cloned()
                .ok_or_else(CredentialError::not_found)?,
        )
    }

    fn reconcile_delete(&mut self, credential_id: &str) -> Result<(), CredentialError> {
        self.credentials.remove(credential_id);
        Ok(())
    }

    fn read_index(&mut self) -> Result<Option<IndexMaterial>, CredentialError> {
        self.index.clone().map(IndexMaterial::new).transpose()
    }

    fn write_index(&mut self, index: IndexMaterial) -> Result<(), CredentialError> {
        self.index = Some(index.expose().to_vec());
        Ok(())
    }
}

impl CredentialRepository for KeychainRepository {
    fn create_at_reference(
        &mut self,
        credential_id: &str,
        account_label: &str,
        secret: SecretMaterial,
    ) -> Result<(), CredentialError> {
        KeychainRepository::create_at_reference(self, credential_id, account_label, secret)
    }

    fn overwrite(
        &mut self,
        credential_id: &str,
        secret: &SecretMaterial,
    ) -> Result<(), CredentialError> {
        KeychainRepository::overwrite(self, credential_id, secret)
    }

    fn pair_status(
        &mut self,
        credential_id: &str,
    ) -> Result<CredentialPairStatus, CredentialError> {
        KeychainRepository::pair_status(self, credential_id)
    }

    fn read(&mut self, credential_id: &str) -> Result<SecretMaterial, CredentialError> {
        KeychainRepository::read(self, credential_id)
    }

    fn reconcile_delete(&mut self, credential_id: &str) -> Result<(), CredentialError> {
        KeychainRepository::reconcile_delete(self, credential_id)
    }

    fn read_index(&mut self) -> Result<Option<IndexMaterial>, CredentialError> {
        KeychainRepository::read_index(self)
    }

    fn write_index(&mut self, index: IndexMaterial) -> Result<(), CredentialError> {
        KeychainRepository::write_index(self, index)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CredentialType {
    ApiKey,
    Oauth,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndexEntry {
    provider_id: String,
    credential_id: String,
    #[serde(rename = "type")]
    credential_type: CredentialType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PendingOperation {
    Create,
    TypeChange,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingIndexEntry {
    operation: PendingOperation,
    provider_id: String,
    credential_id: String,
    desired_type: CredentialType,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndexDocument {
    version: u8,
    entries: Vec<IndexEntry>,
    #[serde(default)]
    pending: Vec<PendingIndexEntry>,
}

impl IndexDocument {
    fn empty() -> Self {
        Self {
            version: INDEX_VERSION,
            entries: Vec::new(),
            pending: Vec::new(),
        }
    }
}

#[derive(Clone, Copy)]
enum ExecutionMode {
    #[cfg(test)]
    Blocking,
    Try,
    Cancelled,
}

enum Operation {
    Get(String),
    List,
    Set {
        provider_id: String,
        credential: PrivateValue,
    },
    Remove(String),
}

fn execute_with_repository(
    repository: &mut dyn CredentialRepository,
    operation: Operation,
) -> Result<OperationOutcome, OperationError> {
    match operation {
        Operation::Get(provider_id) => {
            let credential = get_credential(repository, &provider_id)?;
            Ok(OperationOutcome::Get(credential))
        }
        Operation::List => {
            let entries = list_credentials(repository)?;
            Ok(OperationOutcome::List(entries))
        }
        Operation::Set {
            provider_id,
            credential,
        } => {
            let (credential_type, material) =
                validate_and_serialise_credential(credential.value())?;
            set_credential(repository, provider_id, credential_type, material)?;
            Ok(OperationOutcome::Set)
        }
        Operation::Remove(provider_id) => {
            remove_credential(repository, &provider_id)?;
            Ok(OperationOutcome::Remove)
        }
    }
}

enum OperationOutcome {
    Get(Option<PrivateValue>),
    List(Vec<CredentialInfo>),
    Set,
    Remove,
}

struct CredentialInfo {
    provider_id: String,
    credential_type: CredentialType,
}

#[derive(Clone, Copy)]
enum OperationError {
    InvalidRequest,
    Unavailable,
    Cancelled,
    Internal,
}

fn parse_operation(envelope: &mut Envelope) -> Result<Operation, OperationError> {
    if validate_envelope(envelope).is_err()
        || envelope.kind != ProtocolKind::HostRequest
        || envelope.correlation_id.is_some()
        || envelope.decision_id.is_some()
        || envelope.error.is_some()
    {
        return Err(OperationError::InvalidRequest);
    }

    let method = envelope
        .payload
        .get("method")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(OperationError::InvalidRequest)?;
    match method.as_str() {
        "credential.list" if has_exact_keys(&envelope.payload, &["method"]) => Ok(Operation::List),
        "credential.get" | "credential.remove"
            if has_exact_keys(&envelope.payload, &["method", "providerId"]) =>
        {
            let provider_id = take_string(&mut envelope.payload, "providerId")?;
            validate_provider_id(&provider_id)?;
            if method == "credential.get" {
                Ok(Operation::Get(provider_id))
            } else {
                Ok(Operation::Remove(provider_id))
            }
        }
        "credential.set"
            if has_exact_keys(&envelope.payload, &["method", "providerId", "credential"]) =>
        {
            let provider_id = take_string(&mut envelope.payload, "providerId")?;
            validate_provider_id(&provider_id)?;
            // Establish recursive zeroising ownership immediately after the
            // secret-bearing value leaves the request envelope.
            let credential = PrivateValue::new(
                envelope
                    .payload
                    .remove("credential")
                    .ok_or(OperationError::InvalidRequest)?,
            );
            validate_credential(credential.value())?;
            Ok(Operation::Set {
                provider_id,
                credential,
            })
        }
        _ => Err(OperationError::InvalidRequest),
    }
}

fn has_exact_keys(payload: &Map<String, Value>, keys: &[&str]) -> bool {
    payload.len() == keys.len() && keys.iter().all(|key| payload.contains_key(*key))
}

fn take_string(payload: &mut Map<String, Value>, key: &str) -> Result<String, OperationError> {
    match payload.remove(key) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(OperationError::InvalidRequest),
    }
}

fn validate_provider_id(provider_id: &str) -> Result<(), OperationError> {
    let mut count = 0;
    for character in provider_id.chars() {
        count += 1;
        if count > MAX_PROVIDER_SCALARS || character.is_control() {
            return Err(OperationError::InvalidRequest);
        }
    }
    if count == 0 {
        Err(OperationError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn validate_credential(credential: &Value) -> Result<CredentialType, OperationError> {
    validate_json_value(credential, 0)?;
    let object = credential
        .as_object()
        .ok_or(OperationError::InvalidRequest)?;
    let credential_type = match object.get("type").and_then(Value::as_str) {
        Some("api_key") => {
            if !object
                .keys()
                .all(|key| matches!(key.as_str(), "type" | "key" | "env"))
                || object.get("key").is_some_and(|value| !value.is_string())
            {
                return Err(OperationError::InvalidRequest);
            }
            if let Some(environment) = object.get("env") {
                let environment = environment
                    .as_object()
                    .ok_or(OperationError::InvalidRequest)?;
                if environment.values().any(|value| !value.is_string()) {
                    return Err(OperationError::InvalidRequest);
                }
            }
            CredentialType::ApiKey
        }
        Some("oauth") => {
            if !object.get("access").is_some_and(Value::is_string)
                || !object.get("refresh").is_some_and(Value::is_string)
                || !object
                    .get("expires")
                    .is_some_and(is_javascript_safe_integer)
            {
                return Err(OperationError::InvalidRequest);
            }
            CredentialType::Oauth
        }
        _ => return Err(OperationError::InvalidRequest),
    };

    let encoded =
        Zeroizing::new(serde_json::to_vec(credential).map_err(|_| OperationError::InvalidRequest)?);
    if encoded.len() > MAX_CREDENTIAL_BYTES {
        Err(OperationError::InvalidRequest)
    } else {
        Ok(credential_type)
    }
}

fn validate_and_serialise_credential(
    credential: &Value,
) -> Result<(CredentialType, SecretMaterial), OperationError> {
    let credential_type = validate_credential(credential)?;
    let mut encoded =
        Zeroizing::new(serde_json::to_vec(credential).map_err(|_| OperationError::InvalidRequest)?);
    if encoded.len() > MAX_CREDENTIAL_BYTES {
        return Err(OperationError::InvalidRequest);
    }
    let material = SecretMaterial::new(std::mem::take(&mut *encoded))
        .map_err(|_| OperationError::InvalidRequest)?;
    Ok((credential_type, material))
}

fn validate_json_value(value: &Value, depth: usize) -> Result<(), OperationError> {
    if depth > MAX_JSON_DEPTH {
        return Err(OperationError::InvalidRequest);
    }
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) if is_javascript_safe_number(number) => Ok(()),
        Value::Number(_) => Err(OperationError::InvalidRequest),
        Value::Array(values) => {
            if values.len() > MAX_ARRAY_ITEMS {
                return Err(OperationError::InvalidRequest);
            }
            for value in values {
                validate_json_value(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            if object.len() > MAX_OBJECT_PROPERTIES {
                return Err(OperationError::InvalidRequest);
            }
            for (key, value) in object {
                if key.encode_utf16().count() > MAX_OBJECT_KEY_UTF16_UNITS
                    || key.chars().any(char::is_control)
                {
                    return Err(OperationError::InvalidRequest);
                }
                validate_json_value(value, depth + 1)?;
            }
            Ok(())
        }
    }
}

fn is_javascript_safe_integer(value: &Value) -> bool {
    value.as_number().is_some_and(is_javascript_safe_number)
}

fn is_javascript_safe_number(number: &serde_json::Number) -> bool {
    if let Some(value) = number.as_i64() {
        return (-MAX_JS_SAFE_INTEGER..=MAX_JS_SAFE_INTEGER).contains(&value);
    }
    if let Some(value) = number.as_u64() {
        return value <= MAX_JS_SAFE_INTEGER as u64;
    }
    number.as_f64().is_some_and(|value| {
        value.is_finite() && value.fract() == 0.0 && value.abs() <= MAX_JS_SAFE_INTEGER as f64
    })
}

fn load_index(repository: &mut dyn CredentialRepository) -> Result<IndexDocument, OperationError> {
    let Some(index) = repository.read_index().map_err(map_repository_error)? else {
        return Ok(IndexDocument::empty());
    };
    let index: IndexDocument =
        serde_json::from_slice(index.expose()).map_err(|_| OperationError::Internal)?;
    validate_index(&index)?;
    Ok(index)
}

fn validate_index(index: &IndexDocument) -> Result<(), OperationError> {
    if index.version != INDEX_VERSION
        || index.entries.len() > MAX_INDEX_ENTRIES
        || index.pending.len() > MAX_PENDING_INDEX_ENTRIES
    {
        return Err(OperationError::Internal);
    }
    let mut providers = HashSet::with_capacity(index.entries.len());
    let mut references = HashSet::with_capacity(index.entries.len());
    for entry in &index.entries {
        validate_provider_id(&entry.provider_id).map_err(|_| OperationError::Internal)?;
        validate_credential_reference(&entry.credential_id)?;
        if !providers.insert(entry.provider_id.as_str())
            || !references.insert(entry.credential_id.as_str())
        {
            return Err(OperationError::Internal);
        }
    }

    let mut pending_providers = HashSet::with_capacity(index.pending.len());
    let mut pending_references = HashSet::with_capacity(index.pending.len());
    let mut pending_creates = 0;
    for pending in &index.pending {
        validate_provider_id(&pending.provider_id).map_err(|_| OperationError::Internal)?;
        validate_credential_reference(&pending.credential_id)?;
        if !pending_providers.insert(pending.provider_id.as_str())
            || !pending_references.insert(pending.credential_id.as_str())
        {
            return Err(OperationError::Internal);
        }
        match pending.operation {
            PendingOperation::Create => {
                pending_creates += 1;
                if providers.contains(pending.provider_id.as_str())
                    || references.contains(pending.credential_id.as_str())
                {
                    return Err(OperationError::Internal);
                }
            }
            PendingOperation::TypeChange => {
                let Some(committed) = index.entries.iter().find(|entry| {
                    entry.provider_id == pending.provider_id
                        && entry.credential_id == pending.credential_id
                }) else {
                    return Err(OperationError::Internal);
                };
                if committed.credential_type == pending.desired_type {
                    return Err(OperationError::Internal);
                }
            }
        }
    }
    if index.entries.len() + pending_creates > MAX_INDEX_ENTRIES {
        return Err(OperationError::Internal);
    }
    Ok(())
}

fn validate_credential_reference(credential_id: &str) -> Result<(), OperationError> {
    let Some(uuid) = credential_id.strip_prefix("credential-") else {
        return Err(OperationError::Internal);
    };
    if uuid.len() == 32 && Uuid::parse_str(uuid).is_ok() {
        Ok(())
    } else {
        Err(OperationError::Internal)
    }
}

/// Persists one exact canonical index state. A write error is ambiguous, so an
/// authoritative byte-identical readback is treated as committed. No caller is
/// permitted to perform a dependent secret mutation until this returns `Ok`.
fn persist_index(
    repository: &mut dyn CredentialRepository,
    index: &mut IndexDocument,
) -> Result<(), OperationError> {
    index
        .entries
        .sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
    index
        .pending
        .sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
    validate_index(index)?;
    let expected = serde_json::to_vec(index).map_err(|_| OperationError::Internal)?;
    // Structurally valid metadata can still exceed the fixed Keychain item
    // budget when many maximal Unicode provider IDs are journalled. Reject
    // that preflight as retryable capacity before any storage write or secret
    // mutation rather than misclassifying it as corrupt persisted state.
    let material = IndexMaterial::new(expected.clone()).map_err(|_| OperationError::Unavailable)?;
    let Err(write_error) = repository.write_index(material) else {
        return Ok(());
    };

    let committed = repository
        .read_index()
        .ok()
        .flatten()
        .is_some_and(|stored| stored.expose() == expected);
    if committed {
        Ok(())
    } else {
        Err(map_repository_error(write_error))
    }
}

fn reserve_credential_reference() -> String {
    format!("credential-{}", Uuid::new_v4().simple())
}

fn create_new_credential(
    repository: &mut dyn CredentialRepository,
    index: &mut IndexDocument,
    provider_id: String,
    credential_type: CredentialType,
    material: SecretMaterial,
) -> Result<(), OperationError> {
    let pending_creates = index
        .pending
        .iter()
        .filter(|entry| entry.operation == PendingOperation::Create)
        .count();
    if index.entries.len() + pending_creates >= MAX_INDEX_ENTRIES
        || index.pending.len() >= MAX_PENDING_INDEX_ENTRIES
    {
        return Err(OperationError::Unavailable);
    }

    // Reserve an opaque reference in an explicitly pending journal before any
    // secret can exist. Pending reservations are excluded from list and remain
    // durable recovery authority across proxy/application recreation.
    let credential_id = reserve_credential_reference();
    index.pending.push(PendingIndexEntry {
        operation: PendingOperation::Create,
        provider_id: provider_id.clone(),
        credential_id: credential_id.clone(),
        desired_type: credential_type,
    });
    persist_index(repository, index)?;
    repository
        .create_at_reference(&credential_id, ACCOUNT_LABEL, material)
        .map_err(map_repository_error)?;

    // Promotion is one exact, ambiguously reconciled index state change. A
    // failure leaves only the pending journal state in authoritative storage.
    let pending_position = index
        .pending
        .iter()
        .position(|entry| {
            entry.operation == PendingOperation::Create
                && entry.provider_id == provider_id
                && entry.credential_id == credential_id
        })
        .ok_or(OperationError::Internal)?;
    index.pending.remove(pending_position);
    index.entries.push(IndexEntry {
        provider_id,
        credential_id,
        credential_type,
    });
    persist_index(repository, index)
}

fn material_credential_type(material: &SecretMaterial) -> Option<CredentialType> {
    let credential = PrivateValue::new(serde_json::from_slice(material.expose()).ok()?);
    validate_credential(credential.value()).ok()
}

fn clear_pending_create(
    repository: &mut dyn CredentialRepository,
    index: &mut IndexDocument,
    pending_position: usize,
    credential_id: &str,
) -> Result<(), OperationError> {
    repository
        .reconcile_delete(credential_id)
        .map_err(map_repository_error)?;
    index.pending.remove(pending_position);
    persist_index(repository, index)
}

/// Reconciles one provider's explicit journal state without replaying a secret
/// mutation. A pending create is promoted only after validating the stored
/// credential at the reserved reference. A pending type change is resolved to
/// the authoritative stored type, whether the prior overwrite applied or not.
fn reconcile_pending_provider(
    repository: &mut dyn CredentialRepository,
    index: &mut IndexDocument,
    provider_id: &str,
) -> Result<(), OperationError> {
    let Some(pending_position) = index
        .pending
        .iter()
        .position(|entry| entry.provider_id == provider_id)
    else {
        return Ok(());
    };
    let operation = index.pending[pending_position].operation;
    let credential_id = index.pending[pending_position].credential_id.clone();
    let desired_type = index.pending[pending_position].desired_type;

    if repository
        .pair_status(&credential_id)
        .map_err(map_repository_error)?
        == CredentialPairStatus::Incomplete
    {
        if operation == PendingOperation::Create {
            return clear_pending_create(repository, index, pending_position, &credential_id);
        }
        repository
            .reconcile_delete(&credential_id)
            .map_err(map_repository_error)?;
        index.pending.remove(pending_position);
        let committed_position = index
            .entries
            .iter()
            .position(|entry| {
                entry.provider_id == provider_id && entry.credential_id == credential_id
            })
            .ok_or(OperationError::Internal)?;
        index.entries.remove(committed_position);
        return persist_index(repository, index);
    }

    let material = match repository.read(&credential_id) {
        Ok(material) => material,
        Err(error) if error.code() == CredentialError::not_found().code() => {
            if operation == PendingOperation::Create {
                return clear_pending_create(repository, index, pending_position, &credential_id);
            }
            repository
                .reconcile_delete(&credential_id)
                .map_err(map_repository_error)?;
            index.pending.remove(pending_position);
            let committed_position = index
                .entries
                .iter()
                .position(|entry| {
                    entry.provider_id == provider_id && entry.credential_id == credential_id
                })
                .ok_or(OperationError::Internal)?;
            index.entries.remove(committed_position);
            return persist_index(repository, index);
        }
        Err(error) => return Err(map_repository_error(error)),
    };
    let Some(actual_type) = material_credential_type(&material) else {
        if operation == PendingOperation::Create {
            return clear_pending_create(repository, index, pending_position, &credential_id);
        }
        return Err(OperationError::Internal);
    };

    match operation {
        PendingOperation::Create => {
            if actual_type != desired_type {
                return clear_pending_create(repository, index, pending_position, &credential_id);
            }
            index.pending.remove(pending_position);
            index.entries.push(IndexEntry {
                provider_id: provider_id.into(),
                credential_id,
                credential_type: actual_type,
            });
        }
        PendingOperation::TypeChange => {
            let committed_position = index
                .entries
                .iter()
                .position(|entry| {
                    entry.provider_id == provider_id && entry.credential_id == credential_id
                })
                .ok_or(OperationError::Internal)?;
            index.entries[committed_position].credential_type = actual_type;
            index.pending.remove(pending_position);
        }
    }
    persist_index(repository, index)
}

fn reconcile_stale_entry(
    repository: &mut dyn CredentialRepository,
    index: &mut IndexDocument,
    position: usize,
) -> Result<(), OperationError> {
    let provider_id = index.entries[position].provider_id.clone();
    let credential_id = index.entries[position].credential_id.clone();
    // Prove both old entries absent before removing their durable recovery
    // reference. Persistent cleanup failure therefore remains indexed.
    repository
        .reconcile_delete(&credential_id)
        .map_err(map_repository_error)?;
    index.pending.retain(|pending| {
        pending.provider_id != provider_id && pending.credential_id != credential_id
    });
    index.entries.remove(position);
    persist_index(repository, index)
}

fn set_credential(
    repository: &mut dyn CredentialRepository,
    provider_id: String,
    credential_type: CredentialType,
    material: SecretMaterial,
) -> Result<(), OperationError> {
    let mut index = load_index(repository)?;
    reconcile_pending_provider(repository, &mut index, &provider_id)?;
    if let Some(position) = index
        .entries
        .iter()
        .position(|entry| entry.provider_id == provider_id)
    {
        let credential_id = index.entries[position].credential_id.clone();
        match repository
            .pair_status(&credential_id)
            .map_err(map_repository_error)?
        {
            CredentialPairStatus::Complete => {
                let type_changes = index.entries[position].credential_type != credential_type;
                if type_changes {
                    if index.pending.len() >= MAX_PENDING_INDEX_ENTRIES {
                        return Err(OperationError::Unavailable);
                    }
                    // Keep committed metadata unchanged while journalling the
                    // desired type before the single non-replayed overwrite.
                    index.pending.push(PendingIndexEntry {
                        operation: PendingOperation::TypeChange,
                        provider_id: provider_id.clone(),
                        credential_id: credential_id.clone(),
                        desired_type: credential_type,
                    });
                    persist_index(repository, &mut index)?;
                }
                match repository.overwrite(&credential_id, &material) {
                    Ok(()) => {
                        if type_changes {
                            index.entries[position].credential_type = credential_type;
                            index.pending.retain(|pending| {
                                pending.provider_id != provider_id
                                    && pending.credential_id != credential_id
                            });
                            persist_index(repository, &mut index)?;
                        }
                        return Ok(());
                    }
                    Err(error) if error.code() != CredentialError::not_found().code() => {
                        // An unavailable overwrite is ambiguous and must never
                        // be retried. Committed list metadata remains old while
                        // get resolves and clears the pending transition.
                        return Err(map_repository_error(error));
                    }
                    Err(_) => {
                        // The production repository performs a second pair
                        // check immediately before its upsert. A definite
                        // incomplete result is safe to reconcile and rotate.
                    }
                }
            }
            CredentialPairStatus::Incomplete => {}
        }

        reconcile_stale_entry(repository, &mut index, position)?;
        return create_new_credential(
            repository,
            &mut index,
            provider_id,
            credential_type,
            material,
        );
    }

    create_new_credential(
        repository,
        &mut index,
        provider_id,
        credential_type,
        material,
    )
}

fn get_credential(
    repository: &mut dyn CredentialRepository,
    provider_id: &str,
) -> Result<Option<PrivateValue>, OperationError> {
    let mut index = load_index(repository)?;
    reconcile_pending_provider(repository, &mut index, provider_id)?;
    let Some(position) = index
        .entries
        .iter()
        .position(|entry| entry.provider_id == provider_id)
    else {
        return Ok(None);
    };
    let credential_id = index.entries[position].credential_id.clone();

    if repository
        .pair_status(&credential_id)
        .map_err(map_repository_error)?
        == CredentialPairStatus::Incomplete
    {
        reconcile_stale_entry(repository, &mut index, position)?;
        return Ok(None);
    }

    let material = match repository.read(&credential_id) {
        Ok(material) => material,
        Err(error) if error.code() == CredentialError::not_found().code() => {
            reconcile_stale_entry(repository, &mut index, position)?;
            return Ok(None);
        }
        Err(error) => return Err(map_repository_error(error)),
    };
    // Establish recursive zeroising ownership immediately after successful
    // deserialisation, before shape/type validation or any error return.
    let credential = PrivateValue::new(
        serde_json::from_slice(material.expose()).map_err(|_| OperationError::Internal)?,
    );
    let actual_type =
        validate_credential(credential.value()).map_err(|_| OperationError::Internal)?;
    if actual_type != index.entries[position].credential_type {
        index.entries[position].credential_type = actual_type;
        persist_index(repository, &mut index)?;
    }
    Ok(Some(credential))
}

/// List is strictly metadata-only: it returns committed entries and neither
/// reads secrets nor exposes pending create/type-change journal records.
fn list_credentials(
    repository: &mut dyn CredentialRepository,
) -> Result<Vec<CredentialInfo>, OperationError> {
    let index = load_index(repository)?;
    Ok(index
        .entries
        .into_iter()
        .map(|entry| CredentialInfo {
            provider_id: entry.provider_id,
            credential_type: entry.credential_type,
        })
        .collect())
}

fn remove_credential(
    repository: &mut dyn CredentialRepository,
    provider_id: &str,
) -> Result<(), OperationError> {
    let mut index = load_index(repository)?;
    if let Some(pending_position) = index
        .pending
        .iter()
        .position(|entry| entry.provider_id == provider_id)
    {
        let credential_id = index.pending[pending_position].credential_id.clone();
        repository
            .reconcile_delete(&credential_id)
            .map_err(map_repository_error)?;
        index.pending.remove(pending_position);
        index.entries.retain(|entry| {
            entry.provider_id != provider_id && entry.credential_id != credential_id
        });
        return persist_index(repository, &mut index);
    }

    let Some(position) = index
        .entries
        .iter()
        .position(|entry| entry.provider_id == provider_id)
    else {
        return Ok(());
    };
    let credential_id = index.entries[position].credential_id.clone();
    repository
        .reconcile_delete(&credential_id)
        .map_err(map_repository_error)?;
    index.entries.remove(position);
    persist_index(repository, &mut index)
}

fn map_repository_error(error: CredentialError) -> OperationError {
    if error.code() == CredentialError::unavailable().code() {
        OperationError::Unavailable
    } else {
        OperationError::Internal
    }
}

fn validate_response_coordinates(
    correlation_id: &str,
    response_id: &str,
    response_sequence: u64,
) -> Result<(), CredentialDispatchError> {
    if response_id == correlation_id {
        return Err(CredentialDispatchError);
    }
    let candidate = Envelope {
        version: 1,
        kind: ProtocolKind::HostResponse,
        id: response_id.into(),
        correlation_id: Some(correlation_id.into()),
        decision_id: None,
        sequence: response_sequence,
        payload: Map::new(),
        error: Some(protocol_error(OperationError::Internal)),
    };
    validate_envelope(&candidate).map_err(|_| CredentialDispatchError)
}

fn success_response(
    id: String,
    correlation_id: String,
    sequence: u64,
    outcome: OperationOutcome,
) -> PrivateHostResponse {
    let payload = match outcome {
        OperationOutcome::Get(None) => Map::from_iter([("found".into(), Value::Bool(false))]),
        OperationOutcome::Get(Some(credential)) => Map::from_iter([
            ("found".into(), Value::Bool(true)),
            ("credential".into(), credential.into_value()),
        ]),
        OperationOutcome::List(entries) => Map::from_iter([(
            "entries".into(),
            Value::Array(
                entries
                    .into_iter()
                    .map(|entry| {
                        Value::Object(Map::from_iter([
                            ("providerId".into(), Value::String(entry.provider_id)),
                            (
                                "type".into(),
                                Value::String(match entry.credential_type {
                                    CredentialType::ApiKey => "api_key".into(),
                                    CredentialType::Oauth => "oauth".into(),
                                }),
                            ),
                        ]))
                    })
                    .collect(),
            ),
        )]),
        OperationOutcome::Set => Map::from_iter([("stored".into(), Value::Bool(true))]),
        OperationOutcome::Remove => Map::from_iter([("removed".into(), Value::Bool(true))]),
    };
    PrivateHostResponse::new(Envelope {
        version: 1,
        kind: ProtocolKind::HostResponse,
        id,
        correlation_id: Some(correlation_id),
        decision_id: None,
        sequence,
        payload,
        error: None,
    })
}

fn error_response(
    id: String,
    correlation_id: String,
    sequence: u64,
    error: OperationError,
) -> PrivateHostResponse {
    PrivateHostResponse::new(Envelope {
        version: 1,
        kind: ProtocolKind::HostResponse,
        id,
        correlation_id: Some(correlation_id),
        decision_id: None,
        sequence,
        payload: Map::new(),
        error: Some(protocol_error(error)),
    })
}

fn protocol_error(error: OperationError) -> EnvelopeError {
    let (category, message, retryable) = match error {
        OperationError::InvalidRequest => (
            ErrorCategory::InvalidRequest,
            "Credential request rejected",
            false,
        ),
        OperationError::Unavailable => (
            ErrorCategory::Unavailable,
            "Credential store unavailable",
            true,
        ),
        OperationError::Cancelled => (
            ErrorCategory::Cancelled,
            "Credential request cancelled",
            true,
        ),
        OperationError::Internal => (
            ErrorCategory::Internal,
            "Credential operation failed",
            false,
        ),
    };
    EnvelopeError {
        category,
        message: message.into(),
        retryable: Some(retryable),
        diagnostic_id: None,
    }
}

#[cfg(test)]
include!("proxy_tests.rs");
