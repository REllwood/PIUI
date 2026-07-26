use super::workspace::WorkspaceApprovalBinding;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroize;

const MAX_JS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_ACTIVE: usize = 128;
const MAX_PER_GENERATION: usize = 64;
const MAX_PER_SESSION: usize = 32;
const MAX_TERMINALS: usize = 512;
const MAX_INPUT_BYTES: usize = 65_536;
const MAX_DEPTH: usize = 16;
const MAX_NODES: usize = 256;
const MAX_STRING_BYTES: usize = 16_384;
const DEFAULT_TTL: Duration = Duration::from_secs(120);

pub(crate) trait ApprovalClock: Send + Sync {
    fn now(&self) -> Instant;
}

struct SystemClock;
impl ApprovalClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

pub(crate) trait ApprovalIdSource: Send + Sync {
    fn next(&self, prefix: &str) -> String;
}

struct RandomIds;
impl ApprovalIdSource for RandomIds {
    fn next(&self, prefix: &str) -> String {
        format!("{prefix}-{}", Uuid::new_v4().simple())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalRisk {
    Routine,
    Sensitive,
    Destructive,
    External,
    DenyOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalState {
    PolicyCheck,
    Awaiting,
    Submitting,
    Approved,
    Denied,
    Expired,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalChoice {
    ApproveOnce,
    Deny,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalScopeView {
    pub scope_id: String,
    pub label: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalView {
    pub approval_id: String,
    pub decision_id: String,
    pub revision: u64,
    pub state: ApprovalState,
    pub verb: &'static str,
    pub target: &'static str,
    pub risk: ApprovalRisk,
    pub scopes: Vec<ApprovalScopeView>,
    pub expires_in_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalSubmission {
    pub approval_id: String,
    pub decision_id: String,
    pub scope_ids: Vec<String>,
    pub choice: ApprovalChoice,
}

#[derive(Clone)]
pub(crate) struct ApprovalRequest {
    pub generation: u64,
    pub correlation_id: String,
    pub session_id: String,
    pub workspace_id: String,
    pub workspace_revision: u64,
    pub invocation_id: String,
    pub tool_name: String,
    pub group_id: Option<String>,
    pub input: Value,
    pub input_digest: String,
}

pub(crate) struct ApprovalResponseJob {
    pub response_token: String,
    pub binding: WorkspaceApprovalBinding,
    pub correlation_id: String,
    pub decision_id: String,
    pub approval_id: String,
    pub invocation_id: String,
    pub input_digest: String,
    pub decision: &'static str,
    pub scope_ids: Vec<String>,
}

impl Drop for ApprovalResponseJob {
    fn drop(&mut self) {
        self.response_token.zeroize();
        self.correlation_id.zeroize();
        self.decision_id.zeroize();
        self.approval_id.zeroize();
        self.invocation_id.zeroize();
        self.input_digest.zeroize();
        for scope in &mut self.scope_ids {
            scope.zeroize();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Classification {
    risk: ApprovalRisk,
    verb: &'static str,
    target: &'static str,
    scope_label: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Resolution {
    choice: ApprovalChoice,
}

struct Record {
    approval_id: String,
    decision_id: String,
    generation: u64,
    correlation_id: String,
    session_id: String,
    workspace_id: String,
    workspace_revision: u64,
    workspace_binding: WorkspaceApprovalBinding,
    invocation_id: String,
    tool_name: String,
    group_id: Option<String>,
    digest: String,
    canonical_input: Vec<u8>,
    classification: Classification,
    scope_ids: Vec<String>,
    phase: ApprovalState,
    revision: u64,
    expires_at: Instant,
    resolution: Option<Resolution>,
    pending_outcome: Option<ApprovalState>,
    response_token: Option<String>,
}

impl Drop for Record {
    fn drop(&mut self) {
        self.correlation_id.zeroize();
        self.session_id.zeroize();
        self.workspace_id.zeroize();
        self.invocation_id.zeroize();
        self.tool_name.zeroize();
        if let Some(group) = self.group_id.as_mut() {
            group.zeroize();
        }
        self.digest.zeroize();
        self.canonical_input.zeroize();
    }
}

struct RetiredIds {
    bits: Box<[u64]>,
}
impl Default for RetiredIds {
    fn default() -> Self {
        Self {
            bits: vec![0; 4_096].into_boxed_slice(),
        }
    }
}
impl RetiredIds {
    fn positions(&self, value: &str) -> [usize; 4] {
        let mut output = [0; 4];
        for (index, seed) in [0x9e37u64, 0x85ebu64, 0xc2b2u64, 0x27d4u64]
            .into_iter()
            .enumerate()
        {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            seed.hash(&mut hasher);
            value.hash(&mut hasher);
            output[index] = (hasher.finish() as usize) % (self.bits.len() * 64);
        }
        output
    }
    fn contains(&self, value: &str) -> bool {
        self.positions(value)
            .into_iter()
            .all(|position| self.bits[position / 64] & (1u64 << (position % 64)) != 0)
    }
    fn insert(&mut self, value: &str) {
        for position in self.positions(value) {
            self.bits[position / 64] |= 1u64 << (position % 64);
        }
    }
}

#[derive(Default)]
struct Inner {
    records: HashMap<String, Record>,
    order: VecDeque<String>,
    retired_ids: RetiredIds,
}

pub struct ApprovalRegistry {
    inner: Mutex<Inner>,
    clock: Arc<dyn ApprovalClock>,
    ids: Arc<dyn ApprovalIdSource>,
    ttl: Duration,
}

impl Default for ApprovalRegistry {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            clock: Arc::new(SystemClock),
            ids: Arc::new(RandomIds),
            ttl: DEFAULT_TTL,
        }
    }
}

impl ApprovalRegistry {
    #[cfg(test)]
    fn with_test_authorities(
        clock: Arc<dyn ApprovalClock>,
        ids: Arc<dyn ApprovalIdSource>,
        ttl: Duration,
    ) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            clock,
            ids,
            ttl,
        }
    }

    pub(crate) fn register(&self, request: ApprovalRequest, workspace_binding: WorkspaceApprovalBinding) -> Result<ApprovalView, String> {
        validate_private_correlation(&request.correlation_id)?;
        validate_prefixed_id(&request.session_id, "session-")?;
        validate_prefixed_id(&request.workspace_id, "workspace-")?;
        validate_prefixed_id(&request.invocation_id, "invocation-")?;
        if request.workspace_revision > MAX_JS_SAFE_INTEGER
            || request.generation == 0
            || request.generation > MAX_JS_SAFE_INTEGER
        {
            return Err("approval request rejected".into());
        }
        if let Some(group) = request.group_id.as_deref() {
            validate_prefixed_id(group, "group-")?;
        }
        if request.tool_name.is_empty()
            || request.tool_name.len() > 96
            || request.tool_name.chars().any(char::is_control)
        {
            return Err("approval request rejected".into());
        }
        let canonical_input = canonical_json_bytes(&request.input)?;
        let digest = format!("{:x}", Sha256::digest(&canonical_input));
        if request.input_digest != digest {
            return Err("approval input digest rejected".into());
        }
        let classification = classify(&request.tool_name, &request.input);
        let now = self.clock.now();
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "approval state unavailable".to_string())?;
        self.expire_locked(&mut inner, now)?;
        let active = inner
            .records
            .values()
            .filter(|record| !terminal(record.phase))
            .count();
        let generation_count = inner
            .records
            .values()
            .filter(|record| record.generation == request.generation && !terminal(record.phase))
            .count();
        let session_count = inner
            .records
            .values()
            .filter(|record| record.session_id == request.session_id && !terminal(record.phase))
            .count();
        if active >= MAX_ACTIVE
            || generation_count >= MAX_PER_GENERATION
            || session_count >= MAX_PER_SESSION
        {
            return Err("approval capacity exceeded".into());
        }
        if inner.retired_ids.contains(&request.invocation_id) || inner.records.values().any(|record| record.generation == request.generation && record.invocation_id == request.invocation_id) {
            return Err("approval invocation already registered".into());
        }
        let approval_id = self.fresh_id(&inner, "approval")?;
        let decision_id = self.fresh_id(&inner, "decision")?;
        let scope_id = self.fresh_id(&inner, "scope")?;
        let expires_at = now
            .checked_add(self.ttl)
            .ok_or_else(|| "approval clock exhausted".to_string())?;
        let mut record = Record {
            approval_id: approval_id.clone(),
            decision_id,
            generation: request.generation,
            correlation_id: request.correlation_id,
            session_id: request.session_id,
            workspace_id: request.workspace_id,
            workspace_revision: request.workspace_revision,
            workspace_binding,
            invocation_id: request.invocation_id,
            tool_name: request.tool_name,
            group_id: request.group_id,
            digest,
            canonical_input,
            classification,
            scope_ids: vec![scope_id],
            phase: ApprovalState::PolicyCheck,
            revision: 0,
            expires_at,
            resolution: None,
            pending_outcome: None,
            response_token: None,
        };
        transition(&mut record, ApprovalState::Awaiting)?;
        if classification.risk == ApprovalRisk::DenyOnly {
            transition(&mut record, ApprovalState::Submitting)?;
            record.resolution = Some(Resolution { choice: ApprovalChoice::Deny });
            record.pending_outcome = Some(ApprovalState::Denied);
        }
        let view = view(&record, now);
        inner.order.push_back(approval_id.clone());
        inner.records.insert(approval_id, record);
        self.prune_locked(&mut inner);
        Ok(view)
    }

    pub fn pending(&self) -> Result<Vec<ApprovalView>, String> {
        let now = self.clock.now();
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "approval state unavailable".to_string())?;
        self.expire_locked(&mut inner, now)?;
        Ok(inner
            .order
            .iter()
            .filter_map(|id| inner.records.get(id))
            .filter(|record| record.phase == ApprovalState::Awaiting)
            .map(|record| view(record, now))
            .collect())
    }

    pub fn submit(&self, submission: ApprovalSubmission) -> Result<(), String> {
        validate_prefixed_id(&submission.approval_id, "approval-")?;
        validate_prefixed_id(&submission.decision_id, "decision-")?;
        if submission.scope_ids.len() > 1 || has_duplicates(&submission.scope_ids) {
            return Err("approval submission rejected".into());
        }
        for scope in &submission.scope_ids {
            validate_prefixed_id(scope, "scope-")?;
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "approval state unavailable".to_string())?;
        self.expire_locked(&mut inner, self.clock.now())?;
        let mut record = inner
            .records
            .remove(&submission.approval_id)
            .ok_or_else(|| "approval submission rejected".to_string())?;
        let result = (|| {
            if record.decision_id != submission.decision_id {
                return Err("approval submission rejected".into());
            }
            let expected: &[String] = if submission.choice == ApprovalChoice::ApproveOnce {
                &record.scope_ids
            } else {
                &[]
            };
            if submission.scope_ids.as_slice() != expected {
                return Err("approval submission rejected".into());
            }
            let resolution = Resolution {
                choice: submission.choice,
            };
            if record.phase == ApprovalState::Submitting {
                return if record.resolution == Some(resolution) { Ok(()) } else { Err("approval already settled".into()) };
            }
            if terminal(record.phase) {
                return if matches!(record.phase, ApprovalState::Approved | ApprovalState::Denied)
                    && record.resolution == Some(resolution) { Ok(()) } else { Err("approval already settled".into()) };
            }
            if record.phase != ApprovalState::Awaiting {
                return Err("approval submission rejected".into());
            }
            transition(&mut record, ApprovalState::Submitting)?;
            record.resolution = Some(resolution);
            record.pending_outcome = Some(if submission.choice == ApprovalChoice::ApproveOnce { ApprovalState::Approved } else { ApprovalState::Denied });
            Ok(())
        })();
        inner.records.insert(submission.approval_id, record);
        result
    }

    pub(crate) fn take_response_job(&self, generation: u64) -> Result<Option<ApprovalResponseJob>, String> {
        let mut inner = self.inner.lock().map_err(|_| "approval state unavailable".to_string())?;
        self.expire_locked(&mut inner, self.clock.now())?;
        let Some(record) = inner.records.values_mut().find(|record| record.generation == generation && record.phase == ApprovalState::Submitting && record.response_token.is_none()) else { return Ok(None); };
        let outcome = record.pending_outcome.ok_or_else(|| "approval response unavailable".to_string())?;
        let response_token = self.ids.next("response");
        validate_prefixed_id(&response_token, "response-")?;
        record.response_token = Some(response_token.clone());
        Ok(Some(ApprovalResponseJob {
            response_token,
            binding: record.workspace_binding.clone(),
            correlation_id: record.correlation_id.clone(), decision_id: record.decision_id.clone(),
            approval_id: record.approval_id.clone(), invocation_id: record.invocation_id.clone(), input_digest: record.digest.clone(),
            decision: match outcome { ApprovalState::Approved => "approved", ApprovalState::Denied => "denied", ApprovalState::Expired => "expired", _ => "cancelled" },
            scope_ids: if outcome == ApprovalState::Approved { record.scope_ids.clone() } else { Vec::new() },
        }))
    }

    pub(crate) fn commit_response(&self, response_token: &str) -> Result<(), String> {
        let mut inner = self.inner.lock().map_err(|_| "approval state unavailable".to_string())?;
        let record = inner.records.values_mut().find(|record| record.response_token.as_deref() == Some(response_token)).ok_or_else(|| "approval response stale".to_string())?;
        let outcome = record.pending_outcome.ok_or_else(|| "approval response stale".to_string())?;
        transition(record, outcome)
    }

    pub(crate) fn fail_response(&self, response_token: &str) {
        let Ok(mut inner) = self.inner.lock() else { return; };
        if let Some(record) = inner.records.values_mut().find(|record| record.response_token.as_deref() == Some(response_token)) {
            if record.phase == ApprovalState::Submitting { let _ = transition(record, ApprovalState::Cancelled); record.pending_outcome = Some(ApprovalState::Cancelled); }
        }
    }

    pub(crate) fn invalidate_generation(&self, generation: u64) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let ids: Vec<String> = inner
            .records
            .values()
            .filter(|record| record.generation == generation && !terminal(record.phase))
            .map(|record| record.approval_id.clone())
            .collect();
        for id in ids {
            if let Some(mut record) = inner.records.remove(&id) {
                if record.phase == ApprovalState::Awaiting { let _ = transition(&mut record, ApprovalState::Submitting); }
                if record.phase == ApprovalState::Submitting { record.resolution = Some(Resolution { choice: ApprovalChoice::Deny }); record.pending_outcome = Some(ApprovalState::Cancelled); let _ = transition(&mut record, ApprovalState::Cancelled); }
                inner.records.insert(id, record);
            }
        }
    }

    fn expire_locked(&self, inner: &mut Inner, now: Instant) -> Result<(), String> {
        let ids: Vec<String> = inner
            .records
            .values()
            .filter(|record| record.phase == ApprovalState::Awaiting && record.expires_at <= now)
            .map(|record| record.approval_id.clone())
            .collect();
        for id in ids {
            if let Some(mut record) = inner.records.remove(&id) {
                transition(&mut record, ApprovalState::Submitting)?;
                record.resolution = Some(Resolution { choice: ApprovalChoice::Deny });
                record.pending_outcome = Some(ApprovalState::Expired);
                inner.records.insert(id, record);
            }
        }
        Ok(())
    }

    fn fresh_id(&self, inner: &Inner, prefix: &str) -> Result<String, String> {
        for _ in 0..8 {
            let id = self.ids.next(prefix);
            validate_prefixed_id(&id, &format!("{prefix}-"))?;
            if !inner.records.contains_key(&id) && !inner.retired_ids.contains(&id) {
                return Ok(id);
            }
        }
        Err("approval identifier unavailable".into())
    }

    fn prune_locked(&self, inner: &mut Inner) {
        while inner.records.values().filter(|record| terminal(record.phase)).count() > MAX_TERMINALS {
            let Some(position) = inner.order.iter().position(|id| inner.records.get(id).is_some_and(|record| terminal(record.phase))) else { break; };
            let id = inner.order.remove(position).expect("position exists");
            if let Some(record) = inner.records.remove(&id) {
                inner.retired_ids.insert(&record.approval_id); inner.retired_ids.insert(&record.decision_id); inner.retired_ids.insert(&record.invocation_id);
                for scope in &record.scope_ids { inner.retired_ids.insert(scope); }
            }
        }
    }
}

fn transition(record: &mut Record, next: ApprovalState) -> Result<(), String> {
    let legal = matches!(
        (record.phase, next),
        (
            ApprovalState::PolicyCheck,
            ApprovalState::Awaiting | ApprovalState::Submitting
        ) | (ApprovalState::Awaiting, ApprovalState::Submitting)
            | (
                ApprovalState::Submitting,
                ApprovalState::Approved
                    | ApprovalState::Denied
                    | ApprovalState::Expired
                    | ApprovalState::Cancelled
            )
    );
    if !legal {
        return Err("approval transition rejected".into());
    }
    record.revision = record
        .revision
        .checked_add(1)
        .filter(|value| *value <= MAX_JS_SAFE_INTEGER)
        .ok_or_else(|| "approval revision exhausted".to_string())?;
    record.phase = next;
    Ok(())
}

fn terminal(state: ApprovalState) -> bool {
    matches!(
        state,
        ApprovalState::Approved
            | ApprovalState::Denied
            | ApprovalState::Expired
            | ApprovalState::Cancelled
    )
}

fn view(record: &Record, now: Instant) -> ApprovalView {
    debug_assert!(record.workspace_revision <= MAX_JS_SAFE_INTEGER);
    let expires_in_ms = record
        .expires_at
        .saturating_duration_since(now)
        .as_millis()
        .min(MAX_JS_SAFE_INTEGER as u128) as u64;
    ApprovalView {
        approval_id: record.approval_id.clone(),
        decision_id: record.decision_id.clone(),
        revision: record.revision,
        state: record.phase,
        verb: record.classification.verb,
        target: record.classification.target,
        risk: record.classification.risk,
        scopes: record
            .scope_ids
            .iter()
            .cloned()
            .map(|scope_id| ApprovalScopeView {
                scope_id,
                label: record.classification.scope_label,
            })
            .collect(),
        expires_in_ms,
    }
}

fn classify(tool: &str, _input: &Value) -> Classification {
    match tool {
        "read" | "grep" | "find" | "ls" => Classification {
            risk: ApprovalRisk::Routine,
            verb: "Inspect",
            target: "Selected workspace",
            scope_label: "Allow this read once",
        },
        "edit" | "write" => Classification {
            risk: ApprovalRisk::Sensitive,
            verb: "Change",
            target: "Selected workspace",
            scope_label: "Allow this change once",
        },
        "bash" | "delete" => Classification {
            risk: ApprovalRisk::Destructive,
            verb: "Run",
            target: "Local process",
            scope_label: "Allow this action once",
        },
        "web_fetch" | "web_search" => Classification {
            risk: ApprovalRisk::External,
            verb: "Contact",
            target: "External service",
            scope_label: "Allow this request once",
        },
        _ => Classification {
            risk: ApprovalRisk::DenyOnly,
            verb: "Blocked",
            target: "Unsupported action",
            scope_label: "Unavailable",
        },
    }
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, String> {
    let mut nodes = 0usize;
    fn visit(value: &Value, depth: usize, nodes: &mut usize) -> Result<Value, String> {
        if depth > MAX_DEPTH || *nodes >= MAX_NODES {
            return Err("approval input rejected".into());
        }
        *nodes += 1;
        match value {
            Value::Null | Value::Bool(_) => Ok(value.clone()),
            Value::String(value)
                if value.len() <= MAX_STRING_BYTES
                    && !value.chars().any(|character| character == '\0') =>
            {
                Ok(Value::String(value.clone()))
            }
            Value::String(_) => Err("approval input rejected".into()),
            Value::Number(number) => {
                if number.as_i64().is_some() || number.as_u64().is_some() {
                    Ok(Value::Number(number.clone()))
                } else if number.as_f64().is_some_and(|value| {
                    value.is_finite() && !(value == 0.0 && value.is_sign_negative())
                }) {
                    Ok(Value::Number(number.clone()))
                } else {
                    Err("approval input rejected".into())
                }
            }
            Value::Array(values) if values.len() <= MAX_NODES => Ok(Value::Array(
                values
                    .iter()
                    .map(|value| visit(value, depth + 1, nodes))
                    .collect::<Result<_, _>>()?,
            )),
            Value::Object(values) if values.len() <= 128 => {
                let mut keys: Vec<&String> = values.keys().collect();
                keys.sort();
                let mut output = Map::new();
                for key in keys {
                    if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
                        return Err("approval input rejected".into());
                    }
                    output.insert(key.clone(), visit(&values[key], depth + 1, nodes)?);
                }
                Ok(Value::Object(output))
            }
            _ => Err("approval input rejected".into()),
        }
    }
    let canonical = visit(value, 0, &mut nodes)?;
    let bytes =
        serde_json::to_vec(&canonical).map_err(|_| "approval input rejected".to_string())?;
    if bytes.len() > MAX_INPUT_BYTES {
        Err("approval input rejected".into())
    } else {
        Ok(bytes)
    }
}

fn validate_private_correlation(value: &str) -> Result<(), String> {
    if value.starts_with("sidecar-")
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        Ok(())
    } else {
        Err("approval identifier rejected".into())
    }
}
fn validate_prefixed_id(value: &str, prefix: &str) -> Result<(), String> {
    if value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }) {
        Ok(())
    } else {
        Err("approval identifier rejected".into())
    }
}
fn has_duplicates(values: &[String]) -> bool {
    let mut seen = HashSet::new();
    values.iter().any(|value| !seen.insert(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    struct ManualClock {
        base: Instant,
        millis: AtomicU64,
    }
    impl ApprovalClock for ManualClock {
        fn now(&self) -> Instant {
            self.base + Duration::from_millis(self.millis.load(Ordering::SeqCst))
        }
    }
    struct SequenceIds(AtomicU64);
    impl ApprovalIdSource for SequenceIds {
        fn next(&self, prefix: &str) -> String {
            format!("{prefix}-{:032x}", self.0.fetch_add(1, Ordering::SeqCst))
        }
    }
    fn registry() -> (ApprovalRegistry, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock {
            base: Instant::now(),
            millis: AtomicU64::new(0),
        });
        (
            ApprovalRegistry::with_test_authorities(
                clock.clone(),
                Arc::new(SequenceIds(AtomicU64::new(1))),
                Duration::from_millis(100),
            ),
            clock,
        )
    }
    fn request(invocation: u64, tool: &str) -> ApprovalRequest {
        ApprovalRequest {
            generation: 1,
            correlation_id: format!("sidecar-{invocation:032x}"),
            session_id: format!("session-{:032x}", 1),
            workspace_id: format!("workspace-{:032x}", 2),
            workspace_revision: 1,
            invocation_id: format!("invocation-{invocation:032x}"),
            tool_name: tool.into(),
            group_id: None,
            input: serde_json::json!({"z": 1, "a": [true, "safe"]}),
        }
    }

    #[test]
    fn exact_submission_is_single_winner_and_sibling_scope_cannot_authorise() {
        let (registry, _) = registry();
        let first = registry.register(request(1, "write")).unwrap();
        let sibling = registry.register(request(2, "write")).unwrap();
        let exact = ApprovalSubmission {
            approval_id: first.approval_id.clone(),
            decision_id: first.decision_id.clone(),
            scope_ids: vec![first.scopes[0].scope_id.clone()],
            choice: ApprovalChoice::ApproveOnce,
        };
        registry.submit(exact).unwrap();
        registry
            .submit(ApprovalSubmission {
                approval_id: first.approval_id.clone(),
                decision_id: first.decision_id.clone(),
                scope_ids: vec![first.scopes[0].scope_id.clone()],
                choice: ApprovalChoice::ApproveOnce,
            })
            .unwrap();
        assert!(
            registry
                .submit(ApprovalSubmission {
                    approval_id: sibling.approval_id,
                    decision_id: sibling.decision_id,
                    scope_ids: vec![first.scopes[0].scope_id.clone()],
                    choice: ApprovalChoice::ApproveOnce
                })
                .is_err()
        );
        assert_eq!(
            registry.take_response_job(1).unwrap().unwrap().decision,
            "approved"
        );
        assert!(registry.take_response_job(1).unwrap().is_none());
    }

    #[test]
    fn concurrent_duplicate_decisions_have_one_response_owner() {
        let (registry, _) = registry();
        let registry = Arc::new(registry);
        let view = registry.register(request(1, "read")).unwrap();
        let mut threads = Vec::new();
        for _ in 0..32 {
            let registry = Arc::clone(&registry);
            let approval_id = view.approval_id.clone();
            let decision_id = view.decision_id.clone();
            let scope_id = view.scopes[0].scope_id.clone();
            threads.push(std::thread::spawn(move || {
                registry.submit(ApprovalSubmission {
                    approval_id,
                    decision_id,
                    scope_ids: vec![scope_id],
                    choice: ApprovalChoice::ApproveOnce,
                })
            }));
        }
        assert!(
            threads
                .into_iter()
                .all(|thread| thread.join().unwrap().is_ok())
        );
        assert_eq!(
            registry.take_response_job(1).unwrap().unwrap().decision,
            "approved"
        );
        assert!(registry.take_response_job(1).unwrap().is_none());
    }

    #[test]
    fn session_capacity_is_bounded_and_released_by_terminal_records() {
        let (registry, _) = registry();
        for invocation in 1..=MAX_PER_SESSION as u64 {
            registry.register(request(invocation, "read")).unwrap();
        }
        assert_eq!(
            registry.register(request(100, "read")).unwrap_err(),
            "approval capacity exceeded"
        );
        let pending = registry.pending().unwrap();
        let first = &pending[0];
        registry
            .submit(ApprovalSubmission {
                approval_id: first.approval_id.clone(),
                decision_id: first.decision_id.clone(),
                scope_ids: Vec::new(),
                choice: ApprovalChoice::Deny,
            })
            .unwrap();
        registry.register(request(100, "read")).unwrap();
    }

    #[test]
    fn timeout_and_generation_cutoff_are_non_approved_and_terminal() {
        let (registry, clock) = registry();
        registry.register(request(1, "read")).unwrap();
        clock.millis.store(101, Ordering::SeqCst);
        assert!(registry.pending().unwrap().is_empty());
        assert_eq!(
            registry.take_response_job(1).unwrap().unwrap().decision,
            "expired"
        );
        registry.register(request(2, "bash")).unwrap();
        registry.invalidate_generation(1);
        assert_eq!(
            registry.take_response_job(1).unwrap().unwrap().decision,
            "cancelled"
        );
    }

    #[test]
    fn unknown_and_malformed_inputs_fail_closed() {
        let (registry, _) = registry();
        let view = registry.register(request(1, "invented")).unwrap();
        assert_eq!(view.risk, ApprovalRisk::DenyOnly);
        assert_eq!(
            registry.take_response_job(1).unwrap().unwrap().decision,
            "denied"
        );
        let mut malformed = request(2, "read");
        malformed.input = serde_json::json!({"value": "x".repeat(MAX_STRING_BYTES + 1)});
        assert!(registry.register(malformed).is_err());
    }

    #[test]
    fn public_view_contains_no_private_coordinates_or_input() {
        let (registry, _) = registry();
        let view = registry.register(request(1, "bash")).unwrap();
        let encoded = serde_json::to_string(&view).unwrap();
        for forbidden in [
            "sidecar-",
            "session-",
            "workspace-",
            "invocation-",
            "digest",
            "generation",
            "command",
            "path",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "leaked {forbidden}: {encoded}"
            );
        }
    }
}
