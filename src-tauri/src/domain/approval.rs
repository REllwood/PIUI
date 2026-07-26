use super::workspace::WorkspaceApprovalBinding;
use crate::protocol::approval::{canonical_json_bytes, valid_approval_tool_name};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
const MAX_GROUPS: usize = 64;
const MAX_GROUP_MEMBERS: usize = 32;
const MAX_GROUP_DECISION_TOMBSTONES: usize = 128;
const DEFAULT_TTL: Duration = Duration::from_secs(120);
const RETIRED_ID_BLOOM_BYTES: usize = 2 * 1024 * 1024;
const RETIRED_ID_HASH_SEEDS: [u64; 8] = [
    0x9e37_79b9_7f4a_7c15,
    0xbf58_476d_1ce4_e5b9,
    0x94d0_49bb_1331_11eb,
    0xd6e8_feb8_6659_fd93,
    0xa076_1d64_78bd_642f,
    0xe703_7ed1_a0b4_28db,
    0x8ebc_6af0_9c88_c6e3,
    0x5899_65cc_7537_4cc3,
];

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

pub(crate) trait ApprovalResponseTokenSource: Send + Sync {
    fn next(&self) -> String;
}

struct RandomIds;
impl ApprovalIdSource for RandomIds {
    fn next(&self, prefix: &str) -> String {
        format!("{prefix}-{}", Uuid::new_v4().simple())
    }
}

struct RandomResponseTokens;
impl ApprovalResponseTokenSource for RandomResponseTokens {
    fn next(&self) -> String {
        format!("response-{}", Uuid::new_v4().simple())
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_status: Option<ApprovalDeliveryStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_action: Option<ApprovalGroupActionView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_reason: Option<ApprovalTerminalReason>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalGroupActionView {
    pub group_id: String,
    pub decision_id: String,
    pub scope_id: String,
    pub label: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalTerminalReason {
    UserDenied,
    TimedOut,
    GenerationLost,
    WorkspaceRevoked,
    ExtensionError,
    WriterFailed,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalDeliveryStatus {
    /// The complete LF was written, but A.18 has no authenticated sidecar receipt.
    Uncertain,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalSnapshot {
    pub change_sequence: u64,
    pub records: Vec<ApprovalView>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalGroupSubmission {
    pub group_id: String,
    pub decision_id: String,
    pub scope_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalSubmission {
    pub approval_id: String,
    pub decision_id: String,
    pub scope_ids: Vec<String>,
    pub choice: ApprovalChoice,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovalCohortMember {
    pub ordinal: usize,
    pub tool_call_id: String,
    pub tool_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovalCohort {
    pub assistant_entry_id: String,
    pub cohort_digest: String,
    pub ordered_members: Vec<ApprovalCohortMember>,
}

#[derive(Clone)]
pub(crate) struct ApprovalRequest {
    pub generation: u64,
    pub correlation_id: String,
    pub session_id: String,
    pub workspace_id: String,
    pub workspace_revision: u64,
    pub invocation_id: String,
    pub tool_call_id: Option<String>,
    pub tool_name: String,
    pub cohort: Option<ApprovalCohort>,
    pub input: Value,
    pub input_digest: String,
}

pub(crate) struct ApprovalReadyRequest {
    pub generation: u64,
    pub correlation_id: String,
    pub invocation_id: String,
    pub tool_call_id: String,
    pub input_digest: String,
    pub cohort_digest: String,
}

pub(crate) struct ApprovalAbandonRequest {
    pub generation: u64,
    pub correlation_id: String,
    pub session_id: String,
    pub workspace_id: String,
    pub workspace_revision: u64,
    pub assistant_entry_id: String,
    pub cohort_digest: String,
}

pub(crate) struct ApprovalResponseJob {
    pub response_token: String,
    pub binding: WorkspaceApprovalBinding,
    pub correlation_id: String,
    pub decision_id: String,
    pub approval_id: String,
    pub transaction_id: String,
    pub invocation_id: String,
    pub tool_call_id: Option<String>,
    pub cohort_digest: Option<String>,
    pub input_digest: String,
    pub decision: &'static str,
    pub scope_ids: Vec<String>,
}

pub(crate) struct ApprovalReadyAck {
    pub correlation_id: String,
    pub invocation_id: String,
}

pub(crate) struct ApprovalAbandonAck {
    pub correlation_id: String,
    pub cohort_digest: String,
}

pub(crate) struct GroupApprovalMemberJob {
    pub correlation_id: String,
    pub approval_id: String,
    pub decision_id: String,
    pub invocation_id: String,
    pub tool_call_id: String,
    pub input_digest: String,
    pub scope_id: String,
}

pub(crate) struct GroupApprovalResponseJob {
    pub response_token: String,
    pub binding: WorkspaceApprovalBinding,
    pub generation: u64,
    pub session_id: String,
    pub workspace_id: String,
    pub workspace_revision: u64,
    pub assistant_entry_id: String,
    pub group_id: String,
    pub decision_id: String,
    pub transaction_id: String,
    pub cohort_digest: String,
    pub members: Vec<GroupApprovalMemberJob>,
}

impl Drop for ApprovalResponseJob {
    fn drop(&mut self) {
        self.response_token.zeroize();
        self.correlation_id.zeroize();
        self.decision_id.zeroize();
        self.approval_id.zeroize();
        self.transaction_id.zeroize();
        self.invocation_id.zeroize();
        if let Some(tool_call_id) = self.tool_call_id.as_mut() {
            tool_call_id.zeroize();
        }
        if let Some(cohort_digest) = self.cohort_digest.as_mut() {
            cohort_digest.zeroize();
        }
        self.input_digest.zeroize();
        for scope in &mut self.scope_ids {
            scope.zeroize();
        }
    }
}

impl Drop for GroupApprovalResponseJob {
    fn drop(&mut self) {
        self.response_token.zeroize();
        self.session_id.zeroize();
        self.workspace_id.zeroize();
        self.assistant_entry_id.zeroize();
        self.group_id.zeroize();
        self.decision_id.zeroize();
        self.transaction_id.zeroize();
        self.cohort_digest.zeroize();
        for member in &mut self.members {
            member.correlation_id.zeroize();
            member.approval_id.zeroize();
            member.decision_id.zeroize();
            member.invocation_id.zeroize();
            member.tool_call_id.zeroize();
            member.input_digest.zeroize();
            member.scope_id.zeroize();
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
enum ResolutionSource {
    Ui,
    System,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Resolution {
    choice: ApprovalChoice,
    source: ResolutionSource,
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
    tool_call_id: Option<String>,
    group_key: Option<String>,
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
    response_claimed: bool,
    transaction_id: Option<String>,
    ready: bool,
    terminal_reason: Option<ApprovalTerminalReason>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GroupPhase {
    Collecting,
    Eligible,
    Dissolved,
    Submitting,
    Approved,
    Cancelled,
}

#[derive(Clone)]
struct GroupDecisionTombstone {
    group_id: String,
    decision_id: String,
    scope_id: String,
}

struct GroupRecord {
    group_id: String,
    decision_id: String,
    scope_id: String,
    generation: u64,
    session_id: String,
    workspace_id: String,
    workspace_revision: u64,
    binding: WorkspaceApprovalBinding,
    cohort: ApprovalCohort,
    members: Vec<Option<String>>,
    phase: GroupPhase,
    transaction_id: Option<String>,
    response_token: Option<String>,
    response_claimed: bool,
}

impl Drop for Record {
    fn drop(&mut self) {
        self.correlation_id.zeroize();
        self.session_id.zeroize();
        self.workspace_id.zeroize();
        self.invocation_id.zeroize();
        self.tool_name.zeroize();
        if let Some(group) = self.group_key.as_mut() {
            group.zeroize();
        }
        if let Some(tool_call_id) = self.tool_call_id.as_mut() {
            tool_call_id.zeroize();
        }
        if let Some(transaction_id) = self.transaction_id.as_mut() {
            transaction_id.zeroize();
        }
        self.digest.zeroize();
        self.canonical_input.zeroize();
    }
}

/// Fixed application-lifetime authority: it is never reset and identifiers
/// are never removed. False positives remain fail-closed availability events.
struct RetiredIds {
    bits: Box<[u64]>,
}
impl Default for RetiredIds {
    fn default() -> Self {
        Self {
            bits: vec![0; RETIRED_ID_BLOOM_BYTES / std::mem::size_of::<u64>()].into_boxed_slice(),
        }
    }
}
impl RetiredIds {
    fn positions(&self, value: &str) -> [usize; 8] {
        let mut output = [0; 8];
        for (index, seed) in RETIRED_ID_HASH_SEEDS.into_iter().enumerate() {
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
    groups: HashMap<String, GroupRecord>,
    group_decision_tombstones: VecDeque<GroupDecisionTombstone>,
    change_sequence: u64,
    retired_ids: RetiredIds,
}

pub struct ApprovalRegistry {
    inner: Mutex<Inner>,
    clock: Arc<dyn ApprovalClock>,
    ids: Arc<dyn ApprovalIdSource>,
    response_tokens: Arc<dyn ApprovalResponseTokenSource>,
    ttl: Duration,
}

impl Default for ApprovalRegistry {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            clock: Arc::new(SystemClock),
            ids: Arc::new(RandomIds),
            response_tokens: Arc::new(RandomResponseTokens),
            ttl: DEFAULT_TTL,
        }
    }
}

impl ApprovalRegistry {
    #[cfg(test)]
    fn with_test_authorities(
        clock: Arc<dyn ApprovalClock>,
        ids: Arc<dyn ApprovalIdSource>,
        response_tokens: Arc<dyn ApprovalResponseTokenSource>,
        ttl: Duration,
    ) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            clock,
            ids,
            response_tokens,
            ttl,
        }
    }

    pub(crate) fn register(
        &self,
        request: ApprovalRequest,
        workspace_binding: WorkspaceApprovalBinding,
    ) -> Result<ApprovalView, String> {
        validate_private_correlation(&request.correlation_id)?;
        validate_prefixed_id(&request.session_id, "session-")?;
        validate_prefixed_id(&request.workspace_id, "workspace-")?;
        validate_prefixed_id(&request.invocation_id, "invocation-")?;
        if request.workspace_revision > MAX_JS_SAFE_INTEGER
            || request.generation == 0
            || request.generation > MAX_JS_SAFE_INTEGER
            || !valid_approval_tool_name(&request.tool_name)
        {
            return Err("approval request rejected".into());
        }
        let cohort_ordinal = validate_request_cohort(&request)?;
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
        if inner.retired_ids.contains(&request.invocation_id)
            || inner
                .records
                .values()
                .any(|record| record.invocation_id == request.invocation_id)
        {
            return Err("approval invocation already registered".into());
        }

        let group_key = request
            .cohort
            .as_ref()
            .map(|cohort| cohort_key(&request, cohort));
        let new_group = group_key
            .as_ref()
            .is_some_and(|key| !inner.groups.contains_key(key));
        self.prune_locked(&mut inner);
        if new_group && inner.groups.len() >= MAX_GROUPS {
            return Err("approval group capacity exceeded".into());
        }
        if let Some(key) = group_key.as_ref()
            && let Some(group) = inner.groups.get(key)
        {
            if group.phase != GroupPhase::Collecting
                || group.cohort != *request.cohort.as_ref().unwrap()
                || group.generation != request.generation
                || group.session_id != request.session_id
                || group.workspace_id != request.workspace_id
                || group.workspace_revision != request.workspace_revision
                || cohort_ordinal.is_none_or(|ordinal| group.members[ordinal].is_some())
            {
                return Err("approval cohort rejected".into());
            }
        }

        let mut reserved = HashSet::new();
        let approval_id = self.fresh_id_excluding(&inner, "approval", &reserved)?;
        reserved.insert(approval_id.clone());
        let decision_id = self.fresh_id_excluding(&inner, "decision", &reserved)?;
        reserved.insert(decision_id.clone());
        let scope_id = self.fresh_id_excluding(&inner, "scope", &reserved)?;
        reserved.insert(scope_id.clone());
        let group_coordinates = if new_group {
            let group_id = self.fresh_id_excluding(&inner, "group", &reserved)?;
            reserved.insert(group_id.clone());
            let group_decision_id = self.fresh_id_excluding(&inner, "decision", &reserved)?;
            reserved.insert(group_decision_id.clone());
            let group_scope_id = self.fresh_id_excluding(&inner, "scope", &reserved)?;
            Some((group_id, group_decision_id, group_scope_id))
        } else {
            None
        };
        let deny_coordinates = if classification.risk == ApprovalRisk::DenyOnly {
            Some((
                self.fresh_response_token(&inner)?,
                self.fresh_id_excluding(&inner, "transaction", &reserved)?,
            ))
        } else {
            None
        };
        let expires_at = now
            .checked_add(self.ttl)
            .ok_or_else(|| "approval clock exhausted".to_string())?;
        let mut record = Record {
            approval_id: approval_id.clone(),
            decision_id,
            generation: request.generation,
            correlation_id: request.correlation_id,
            session_id: request.session_id.clone(),
            workspace_id: request.workspace_id.clone(),
            workspace_revision: request.workspace_revision,
            workspace_binding: workspace_binding.clone(),
            invocation_id: request.invocation_id,
            tool_name: request.tool_name,
            tool_call_id: request.tool_call_id,
            group_key: group_key.clone(),
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
            response_claimed: false,
            transaction_id: None,
            ready: false,
            terminal_reason: None,
        };
        transition(&mut record, ApprovalState::Awaiting)?;
        if let Some((response_token, transaction_id)) = deny_coordinates {
            transition(&mut record, ApprovalState::Submitting)?;
            record.resolution = Some(Resolution {
                choice: ApprovalChoice::Deny,
                source: ResolutionSource::System,
            });
            record.pending_outcome = Some(ApprovalState::Denied);
            record.response_token = Some(response_token);
            record.transaction_id = Some(transaction_id);
            record.terminal_reason = Some(ApprovalTerminalReason::Unsupported);
        }

        if let (Some(key), Some(cohort), Some((group_id, decision_id, scope_id))) = (
            group_key.as_ref(),
            request.cohort.clone(),
            group_coordinates,
        ) {
            inner.groups.insert(
                key.clone(),
                GroupRecord {
                    group_id,
                    decision_id,
                    scope_id,
                    generation: request.generation,
                    session_id: request.session_id,
                    workspace_id: request.workspace_id,
                    workspace_revision: request.workspace_revision,
                    binding: workspace_binding,
                    members: vec![None; cohort.ordered_members.len()],
                    cohort,
                    phase: GroupPhase::Collecting,
                    transaction_id: None,
                    response_token: None,
                    response_claimed: false,
                },
            );
        }
        inner.order.push_back(approval_id.clone());
        inner.records.insert(approval_id.clone(), record);
        if let (Some(key), Some(ordinal)) = (group_key.as_ref(), cohort_ordinal) {
            let complete_ids = {
                let group = inner
                    .groups
                    .get_mut(key)
                    .ok_or_else(|| "approval cohort rejected".to_string())?;
                group.members[ordinal] = Some(approval_id.clone());
                group
                    .members
                    .iter()
                    .all(Option::is_some)
                    .then(|| group.members.iter().flatten().cloned().collect::<Vec<_>>())
            };
            if let Some(ids) = complete_ids {
                let routine_only = ids.iter().all(|id| {
                    inner
                        .records
                        .get(id)
                        .is_some_and(|record| record.classification.risk == ApprovalRisk::Routine)
                });
                if let Some(group) = inner.groups.get_mut(key) {
                    group.phase = if routine_only {
                        GroupPhase::Eligible
                    } else {
                        GroupPhase::Dissolved
                    };
                }
            }
        }
        bump_change(&mut inner)?;
        self.prune_locked(&mut inner);
        let record = inner
            .records
            .get(&approval_id)
            .ok_or_else(|| "approval state unavailable".to_string())?;
        Ok(view(record, &inner, now))
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
            .map(|record| view(record, &inner, now))
            .collect())
    }

    pub fn snapshot(&self) -> Result<ApprovalSnapshot, String> {
        let now = self.clock.now();
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "approval state unavailable".to_string())?;
        self.expire_locked(&mut inner, now)?;
        Ok(ApprovalSnapshot {
            change_sequence: inner.change_sequence,
            records: inner
                .order
                .iter()
                .filter_map(|id| inner.records.get(id))
                .map(|record| view(record, &inner, now))
                .collect(),
        })
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
        let record = inner
            .records
            .get(&submission.approval_id)
            .ok_or_else(|| "approval submission rejected".to_string())?;
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
            source: ResolutionSource::Ui,
        };
        if record.phase == ApprovalState::Submitting {
            return if record.resolution == Some(resolution) {
                Ok(())
            } else {
                Err("approval already settled".into())
            };
        }
        if terminal(record.phase) {
            return if matches!(
                record.phase,
                ApprovalState::Approved | ApprovalState::Denied
            ) && record.resolution == Some(resolution)
            {
                Ok(())
            } else {
                Err("approval already settled".into())
            };
        }
        if record.phase != ApprovalState::Awaiting {
            return Err("approval submission rejected".into());
        }

        let mut reserved = HashSet::new();
        let response_token = self.fresh_response_token(&inner)?;
        let transaction_id = self.fresh_id_excluding(&inner, "transaction", &reserved)?;
        reserved.insert(transaction_id.clone());
        let group_key = record.group_key.clone();
        if let Some(key) = group_key.as_ref()
            && let Some(group) = inner.groups.get_mut(key)
        {
            if matches!(group.phase, GroupPhase::Submitting | GroupPhase::Approved) {
                return Err("approval group already settled".into());
            }
            group.phase = GroupPhase::Dissolved;
        }
        let record = inner
            .records
            .get_mut(&submission.approval_id)
            .ok_or_else(|| "approval submission rejected".to_string())?;
        transition(record, ApprovalState::Submitting)?;
        record.resolution = Some(resolution);
        record.pending_outcome = Some(if submission.choice == ApprovalChoice::ApproveOnce {
            ApprovalState::Approved
        } else {
            ApprovalState::Denied
        });
        record.response_token = Some(response_token);
        record.transaction_id = Some(transaction_id);
        if submission.choice == ApprovalChoice::Deny {
            record.terminal_reason = Some(ApprovalTerminalReason::UserDenied);
        }
        bump_change(&mut inner)?;
        Ok(())
    }

    pub fn submit_group(&self, submission: ApprovalGroupSubmission) -> Result<(), String> {
        validate_prefixed_id(&submission.group_id, "group-")?;
        validate_prefixed_id(&submission.decision_id, "decision-")?;
        validate_prefixed_id(&submission.scope_id, "scope-")?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "approval state unavailable".to_string())?;
        self.expire_locked(&mut inner, self.clock.now())?;
        if let Some(tombstone) = inner
            .group_decision_tombstones
            .iter()
            .find(|tombstone| tombstone.group_id == submission.group_id)
        {
            return if tombstone.decision_id == submission.decision_id
                && tombstone.scope_id == submission.scope_id
            {
                Ok(())
            } else {
                Err("approval group rejected".into())
            };
        }
        let key = inner
            .groups
            .iter()
            .find_map(|(key, group)| (group.group_id == submission.group_id).then(|| key.clone()))
            .ok_or_else(|| "approval group rejected".to_string())?;
        let group = inner
            .groups
            .get(&key)
            .ok_or_else(|| "approval group rejected".to_string())?;
        if group.decision_id != submission.decision_id || group.scope_id != submission.scope_id {
            return Err("approval group rejected".into());
        }
        if matches!(group.phase, GroupPhase::Submitting | GroupPhase::Approved) {
            return Ok(());
        }
        if group.phase != GroupPhase::Eligible
            || group.members.len() < 2
            || group.members.len() > MAX_GROUP_MEMBERS
            || group.members.iter().any(Option::is_none)
        {
            return Err("approval group rejected".into());
        }
        let member_ids: Vec<String> = group.members.iter().flatten().cloned().collect();
        if !member_ids.iter().all(|id| {
            inner.records.get(id).is_some_and(|record| {
                record.phase == ApprovalState::Awaiting
                    && record.ready
                    && record.classification.risk == ApprovalRisk::Routine
                    && record.generation == group.generation
                    && record.session_id == group.session_id
                    && record.workspace_id == group.workspace_id
                    && record.workspace_revision == group.workspace_revision
            })
        }) {
            return Err("approval group rejected".into());
        }

        let response_token = self.fresh_response_token(&inner)?;
        let transaction_id = self.fresh_id(&inner, "transaction")?;
        for id in &member_ids {
            let record = inner
                .records
                .get_mut(id)
                .ok_or_else(|| "approval group rejected".to_string())?;
            transition(record, ApprovalState::Submitting)?;
            record.resolution = Some(Resolution {
                choice: ApprovalChoice::ApproveOnce,
                source: ResolutionSource::Ui,
            });
            record.pending_outcome = Some(ApprovalState::Approved);
            record.transaction_id = Some(transaction_id.clone());
            record.response_token = None;
            record.response_claimed = false;
        }
        let group = inner
            .groups
            .get_mut(&key)
            .ok_or_else(|| "approval group rejected".to_string())?;
        group.phase = GroupPhase::Submitting;
        group.transaction_id = Some(transaction_id);
        group.response_token = Some(response_token);
        group.response_claimed = false;
        bump_change(&mut inner)?;
        Ok(())
    }

    pub(crate) fn mark_ready(
        &self,
        request: ApprovalReadyRequest,
    ) -> Result<ApprovalReadyAck, String> {
        validate_private_correlation(&request.correlation_id)?;
        validate_prefixed_id(&request.invocation_id, "invocation-")?;
        validate_wire_coordinate(&request.tool_call_id)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "approval state unavailable".to_string())?;
        self.expire_locked(&mut inner, self.clock.now())?;
        let record = inner
            .records
            .values_mut()
            .find(|record| {
                record.generation == request.generation
                    && record.invocation_id == request.invocation_id
            })
            .ok_or_else(|| "approval ready rejected".to_string())?;
        if record.ready
            || terminal(record.phase)
            || record.tool_call_id.as_deref() != Some(request.tool_call_id.as_str())
            || record.digest != request.input_digest
            || record
                .group_key
                .as_ref()
                .is_none_or(|key| !key.ends_with(&request.cohort_digest))
        {
            return Err("approval ready rejected".into());
        }
        record.ready = true;
        bump_change(&mut inner)?;
        Ok(ApprovalReadyAck {
            correlation_id: request.correlation_id,
            invocation_id: request.invocation_id,
        })
    }

    pub(crate) fn abandon(
        &self,
        request: ApprovalAbandonRequest,
    ) -> Result<ApprovalAbandonAck, String> {
        validate_private_correlation(&request.correlation_id)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "approval state unavailable".to_string())?;
        let keys: Vec<String> = inner
            .groups
            .iter()
            .filter(|(_, group)| {
                group.generation == request.generation
                    && group.session_id == request.session_id
                    && group.workspace_id == request.workspace_id
                    && group.workspace_revision == request.workspace_revision
                    && group.cohort.assistant_entry_id == request.assistant_entry_id
                    && group.cohort.cohort_digest == request.cohort_digest
            })
            .map(|(key, _)| key.clone())
            .collect();
        if keys.is_empty() {
            return Err("approval abandon rejected".into());
        }
        let member_ids: Vec<String> = keys
            .iter()
            .flat_map(|key| inner.groups[key].members.iter().flatten().cloned())
            .collect();
        self.plan_nonapproved_locked(
            &mut inner,
            &member_ids,
            ApprovalState::Cancelled,
            ApprovalTerminalReason::ExtensionError,
        )?;
        for key in keys {
            if let Some(group) = inner.groups.get_mut(&key) {
                group.phase = GroupPhase::Cancelled;
                group.response_token = None;
                group.response_claimed = false;
            }
        }
        bump_change(&mut inner)?;
        Ok(ApprovalAbandonAck {
            correlation_id: request.correlation_id,
            cohort_digest: request.cohort_digest,
        })
    }

    pub(crate) fn take_response_job(
        &self,
        generation: u64,
    ) -> Result<Option<ApprovalResponseJob>, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "approval state unavailable".to_string())?;
        self.expire_locked(&mut inner, self.clock.now())?;
        let id = inner
            .order
            .iter()
            .find(|id| {
                inner.records.get(*id).is_some_and(|record| {
                    record.generation == generation
                        && record.phase == ApprovalState::Submitting
                        && record.response_token.is_some()
                        && !record.response_claimed
                        && (record.pending_outcome != Some(ApprovalState::Approved)
                            || record.ready
                            || record.tool_call_id.is_none())
                })
            })
            .cloned();
        let Some(id) = id else {
            return Ok(None);
        };
        let record = inner
            .records
            .get_mut(&id)
            .ok_or_else(|| "approval response unavailable".to_string())?;
        let outcome = record
            .pending_outcome
            .ok_or_else(|| "approval response unavailable".to_string())?;
        let response_token = record
            .response_token
            .clone()
            .ok_or_else(|| "approval response unavailable".to_string())?;
        let transaction_id = record
            .transaction_id
            .clone()
            .ok_or_else(|| "approval response unavailable".to_string())?;
        record.response_claimed = true;
        Ok(Some(ApprovalResponseJob {
            response_token,
            binding: record.workspace_binding.clone(),
            correlation_id: record.correlation_id.clone(),
            decision_id: record.decision_id.clone(),
            approval_id: record.approval_id.clone(),
            transaction_id,
            invocation_id: record.invocation_id.clone(),
            tool_call_id: record.tool_call_id.clone(),
            cohort_digest: record
                .group_key
                .as_ref()
                .and_then(|key| key.rsplit('|').next().map(str::to_string)),
            input_digest: record.digest.clone(),
            decision: match outcome {
                ApprovalState::Approved => "approved",
                ApprovalState::Denied => "denied",
                ApprovalState::Expired => "expired",
                _ => "cancelled",
            },
            scope_ids: if outcome == ApprovalState::Approved {
                record.scope_ids.clone()
            } else {
                Vec::new()
            },
        }))
    }

    pub(crate) fn take_group_response_job(
        &self,
        generation: u64,
    ) -> Result<Option<GroupApprovalResponseJob>, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "approval state unavailable".to_string())?;
        self.expire_locked(&mut inner, self.clock.now())?;
        let key = inner.groups.iter().find_map(|(key, group)| {
            (group.generation == generation
                && group.phase == GroupPhase::Submitting
                && group.response_token.is_some()
                && !group.response_claimed)
                .then(|| key.clone())
        });
        let Some(key) = key else {
            return Ok(None);
        };
        let group = inner
            .groups
            .get(&key)
            .ok_or_else(|| "approval group response unavailable".to_string())?;
        let ids: Vec<String> = group.members.iter().flatten().cloned().collect();
        if ids.len() != group.cohort.ordered_members.len()
            || !ids.iter().all(|id| {
                inner.records.get(id).is_some_and(|record| {
                    record.phase == ApprovalState::Submitting
                        && record.pending_outcome == Some(ApprovalState::Approved)
                        && record.ready
                        && !record.response_claimed
                })
            })
        {
            return Err("approval group response unavailable".into());
        }
        let members = ids
            .iter()
            .map(|id| {
                let record = &inner.records[id];
                Ok(GroupApprovalMemberJob {
                    correlation_id: record.correlation_id.clone(),
                    approval_id: record.approval_id.clone(),
                    decision_id: record.decision_id.clone(),
                    invocation_id: record.invocation_id.clone(),
                    tool_call_id: record
                        .tool_call_id
                        .clone()
                        .ok_or_else(|| "approval group response unavailable".to_string())?,
                    input_digest: record.digest.clone(),
                    scope_id: record
                        .scope_ids
                        .first()
                        .cloned()
                        .ok_or_else(|| "approval group response unavailable".to_string())?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let (response_token, binding, group_id, decision_id, transaction_id, cohort_digest) = {
            let group = inner
                .groups
                .get_mut(&key)
                .ok_or_else(|| "approval group response unavailable".to_string())?;
            group.response_claimed = true;
            (
                group
                    .response_token
                    .clone()
                    .ok_or_else(|| "approval group response unavailable".to_string())?,
                group.binding.clone(),
                group.group_id.clone(),
                group.decision_id.clone(),
                group
                    .transaction_id
                    .clone()
                    .ok_or_else(|| "approval group response unavailable".to_string())?,
                group.cohort.cohort_digest.clone(),
            )
        };
        for id in &ids {
            if let Some(record) = inner.records.get_mut(id) {
                record.response_claimed = true;
            }
        }
        let group = inner
            .groups
            .get(&key)
            .ok_or_else(|| "approval group response unavailable".to_string())?;
        Ok(Some(GroupApprovalResponseJob {
            response_token,
            binding,
            generation: group.generation,
            session_id: group.session_id.clone(),
            workspace_id: group.workspace_id.clone(),
            workspace_revision: group.workspace_revision,
            assistant_entry_id: group.cohort.assistant_entry_id.clone(),
            group_id,
            decision_id,
            transaction_id,
            cohort_digest,
            members,
        }))
    }

    pub(crate) fn complete_group_response(
        &self,
        response_token: &str,
        write: impl FnOnce(Duration) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "approval state unavailable".to_string())?;
        let key = inner
            .groups
            .iter()
            .find_map(|(key, group)| {
                (group.response_token.as_deref() == Some(response_token)
                    && group.phase == GroupPhase::Submitting
                    && group.response_claimed)
                    .then(|| key.clone())
            })
            .ok_or_else(|| "approval group response stale".to_string())?;
        let ids: Vec<String> = inner.groups[&key]
            .members
            .iter()
            .flatten()
            .cloned()
            .collect();
        let earliest_expiry = ids
            .iter()
            .filter_map(|id| inner.records.get(id).map(|record| record.expires_at))
            .min()
            .ok_or_else(|| "approval group response stale".to_string())?;
        let now = self.clock.now();
        if now >= earliest_expiry {
            self.expire_locked(&mut inner, now)?;
            self.prune_locked(&mut inner);
            return Ok(());
        }
        let budget = earliest_expiry.saturating_duration_since(now);
        if let Err(error) = write(budget) {
            for id in &ids {
                if let Some(record) = inner.records.get_mut(id) {
                    record.pending_outcome = Some(ApprovalState::Cancelled);
                    record.terminal_reason = Some(ApprovalTerminalReason::WriterFailed);
                    transition(record, ApprovalState::Cancelled)?;
                }
            }
            if let Some(group) = inner.groups.get_mut(&key) {
                group.phase = GroupPhase::Cancelled;
            }
            bump_change(&mut inner)?;
            self.prune_locked(&mut inner);
            return Err(error);
        }
        // A successful writer return means the complete LF was published before
        // its absolute monotonic deadline. A later domain-clock observation must
        // not retroactively rewrite that authorisation.
        for id in &ids {
            let record = inner
                .records
                .get_mut(id)
                .ok_or_else(|| "approval group response stale".to_string())?;
            transition(record, ApprovalState::Approved)?;
        }
        if let Some(group) = inner.groups.get_mut(&key) {
            group.phase = GroupPhase::Approved;
        }
        bump_change(&mut inner)?;
        self.prune_locked(&mut inner);
        Ok(())
    }

    /// Runs the private generation writer while holding the response claim.
    /// The terminal decision is committed only after that checked write succeeds.
    pub(crate) fn complete_response(
        &self,
        response_token: &str,
        write: impl FnOnce(Duration) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "approval state unavailable".to_string())?;
        let id = inner
            .records
            .values()
            .find(|record| {
                record.response_token.as_deref() == Some(response_token)
                    && record.phase == ApprovalState::Submitting
                    && record.response_claimed
            })
            .map(|record| record.approval_id.clone())
            .ok_or_else(|| "approval response stale".to_string())?;
        let (outcome, expires_at) = inner
            .records
            .get(&id)
            .and_then(|record| {
                record
                    .pending_outcome
                    .map(|outcome| (outcome, record.expires_at))
            })
            .ok_or_else(|| "approval response stale".to_string())?;
        let now = self.clock.now();
        if outcome == ApprovalState::Approved && now >= expires_at {
            self.plan_nonapproved_locked(
                &mut inner,
                &[id],
                ApprovalState::Expired,
                ApprovalTerminalReason::TimedOut,
            )?;
            bump_change(&mut inner)?;
            return Ok(());
        }
        let budget = if outcome == ApprovalState::Approved {
            expires_at.saturating_duration_since(now)
        } else {
            self.ttl
        };
        if let Err(error) = write(budget) {
            let record = inner
                .records
                .get_mut(&id)
                .ok_or_else(|| "approval response stale".to_string())?;
            record.pending_outcome = Some(ApprovalState::Cancelled);
            record.terminal_reason = Some(ApprovalTerminalReason::WriterFailed);
            transition(record, ApprovalState::Cancelled)?;
            bump_change(&mut inner)?;
            self.prune_locked(&mut inner);
            return Err(error);
        }
        let record = inner
            .records
            .get_mut(&id)
            .ok_or_else(|| "approval response stale".to_string())?;
        // The writer alone owns the complete-LF deadline. Its success is the
        // publication fact even if a manual/domain clock advances afterwards.
        transition(record, outcome)?;
        bump_change(&mut inner)?;
        self.prune_locked(&mut inner);
        Ok(())
    }

    pub(crate) fn cancel_response(&self, response_token: &str) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        if let Some(record) = inner.records.values_mut().find(|record| {
            record.response_token.as_deref() == Some(response_token)
                && record.phase == ApprovalState::Submitting
        }) {
            record.resolution = Some(Resolution {
                choice: ApprovalChoice::Deny,
                source: ResolutionSource::System,
            });
            record.pending_outcome = Some(ApprovalState::Cancelled);
            record.terminal_reason = Some(ApprovalTerminalReason::WriterFailed);
            let _ = transition(record, ApprovalState::Cancelled);
            let _ = bump_change(&mut inner);
        }
        self.prune_locked(&mut inner);
    }

    pub(crate) fn cancel_workspace(&self, workspace_id: &str) -> Result<(), String> {
        validate_prefixed_id(workspace_id, "workspace-")?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "approval state unavailable".to_string())?;
        let ids: Vec<String> = inner
            .records
            .values()
            .filter(|record| record.workspace_id == workspace_id && !terminal(record.phase))
            .map(|record| record.approval_id.clone())
            .collect();
        if ids.is_empty() {
            return Ok(());
        }
        self.plan_nonapproved_locked(
            &mut inner,
            &ids,
            ApprovalState::Cancelled,
            ApprovalTerminalReason::WorkspaceRevoked,
        )?;
        let keys: HashSet<String> = ids
            .iter()
            .filter_map(|id| inner.records.get(id)?.group_key.clone())
            .collect();
        for key in keys {
            if let Some(group) = inner.groups.get_mut(&key) {
                group.phase = GroupPhase::Cancelled;
                group.response_token = None;
                group.response_claimed = false;
            }
        }
        bump_change(&mut inner)?;
        Ok(())
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
            if let Some(record) = inner.records.get_mut(&id) {
                if record.phase == ApprovalState::Awaiting {
                    let _ = transition(record, ApprovalState::Submitting);
                }
                if record.phase == ApprovalState::Submitting {
                    record.resolution = Some(Resolution {
                        choice: ApprovalChoice::Deny,
                        source: ResolutionSource::System,
                    });
                    record.pending_outcome = Some(ApprovalState::Cancelled);
                    record.terminal_reason = Some(ApprovalTerminalReason::GenerationLost);
                    let _ = transition(record, ApprovalState::Cancelled);
                }
            }
        }
        for group in inner
            .groups
            .values_mut()
            .filter(|group| group.generation == generation)
        {
            if !matches!(group.phase, GroupPhase::Approved | GroupPhase::Cancelled) {
                group.phase = GroupPhase::Cancelled;
            }
        }
        let _ = bump_change(&mut inner);
        self.prune_locked(&mut inner);
    }

    fn expire_locked(&self, inner: &mut Inner, now: Instant) -> Result<(), String> {
        let ids: Vec<String> = inner
            .records
            .values()
            .filter(|record| {
                record.expires_at <= now
                    && (record.phase == ApprovalState::Awaiting
                        || (record.phase == ApprovalState::Submitting
                            && record.pending_outcome == Some(ApprovalState::Approved)))
            })
            .map(|record| record.approval_id.clone())
            .collect();
        if ids.is_empty() {
            return Ok(());
        }
        self.plan_nonapproved_locked(
            inner,
            &ids,
            ApprovalState::Expired,
            ApprovalTerminalReason::TimedOut,
        )?;
        let affected: HashSet<String> = ids
            .iter()
            .filter_map(|id| inner.records.get(id)?.group_key.clone())
            .collect();
        for key in affected {
            if let Some(group) = inner.groups.get_mut(&key) {
                if group.phase != GroupPhase::Approved {
                    group.phase = GroupPhase::Cancelled;
                }
                group.response_token = None;
                group.response_claimed = false;
            }
        }
        bump_change(inner)?;
        Ok(())
    }

    fn plan_nonapproved_locked(
        &self,
        inner: &mut Inner,
        ids: &[String],
        outcome: ApprovalState,
        reason: ApprovalTerminalReason,
    ) -> Result<(), String> {
        let live: Vec<String> = ids
            .iter()
            .filter(|id| {
                inner
                    .records
                    .get(*id)
                    .is_some_and(|record| !terminal(record.phase))
            })
            .cloned()
            .collect();
        let mut reserved_tokens = HashSet::new();
        let mut reserved_ids = HashSet::new();
        let mut planned = Vec::with_capacity(live.len());
        for id in live {
            let response_token = self.fresh_response_token_excluding(inner, &reserved_tokens)?;
            reserved_tokens.insert(response_token.clone());
            let transaction_id = self.fresh_id_excluding(inner, "transaction", &reserved_ids)?;
            reserved_ids.insert(transaction_id.clone());
            planned.push((id, response_token, transaction_id));
        }
        for (id, response_token, transaction_id) in planned {
            let record = inner
                .records
                .get_mut(&id)
                .ok_or_else(|| "approval state unavailable".to_string())?;
            if record.phase == ApprovalState::Awaiting {
                transition(record, ApprovalState::Submitting)?;
            }
            record.resolution = Some(Resolution {
                choice: ApprovalChoice::Deny,
                source: ResolutionSource::System,
            });
            record.pending_outcome = Some(outcome);
            record.response_token = Some(response_token);
            record.response_claimed = false;
            record.transaction_id = Some(transaction_id);
            record.terminal_reason = Some(reason);
        }
        Ok(())
    }

    fn fresh_response_token(&self, inner: &Inner) -> Result<String, String> {
        self.fresh_response_token_excluding(inner, &HashSet::new())
    }

    fn fresh_response_token_excluding(
        &self,
        inner: &Inner,
        reserved: &HashSet<String>,
    ) -> Result<String, String> {
        for _ in 0..8 {
            let token = self.response_tokens.next();
            validate_prefixed_id(&token, "response-")?;
            if !reserved.contains(&token)
                && !inner
                    .records
                    .values()
                    .any(|record| record.response_token.as_deref() == Some(token.as_str()))
                && !inner
                    .groups
                    .values()
                    .any(|group| group.response_token.as_deref() == Some(token.as_str()))
            {
                return Ok(token);
            }
        }
        Err("approval response unavailable".into())
    }

    fn fresh_id(&self, inner: &Inner, prefix: &str) -> Result<String, String> {
        self.fresh_id_excluding(inner, prefix, &HashSet::new())
    }

    fn fresh_id_excluding(
        &self,
        inner: &Inner,
        prefix: &str,
        reserved: &HashSet<String>,
    ) -> Result<String, String> {
        for _ in 0..8 {
            let id = self.ids.next(prefix);
            validate_prefixed_id(&id, &format!("{prefix}-"))?;
            let retained_collision = match prefix {
                "approval" => inner
                    .records
                    .values()
                    .any(|record| record.approval_id == id),
                "decision" => {
                    inner
                        .records
                        .values()
                        .any(|record| record.decision_id == id)
                        || inner.groups.values().any(|group| group.decision_id == id)
                }
                "scope" => {
                    inner
                        .records
                        .values()
                        .any(|record| record.scope_ids.iter().any(|scope| scope == &id))
                        || inner.groups.values().any(|group| group.scope_id == id)
                }
                "group" => inner.groups.values().any(|group| group.group_id == id),
                "transaction" => {
                    inner
                        .records
                        .values()
                        .any(|record| record.transaction_id.as_deref() == Some(id.as_str()))
                        || inner
                            .groups
                            .values()
                            .any(|group| group.transaction_id.as_deref() == Some(id.as_str()))
                }
                _ => return Err("approval identifier unavailable".into()),
            };
            if !reserved.contains(&id) && !retained_collision && !inner.retired_ids.contains(&id) {
                return Ok(id);
            }
        }
        Err("approval identifier unavailable".into())
    }

    fn prune_locked(&self, inner: &mut Inner) {
        let completed_groups: Vec<String> = inner
            .groups
            .iter()
            .filter(|(_, group)| {
                matches!(
                    group.phase,
                    GroupPhase::Approved | GroupPhase::Cancelled | GroupPhase::Dissolved
                ) && group.members.iter().flatten().all(|id| {
                    inner
                        .records
                        .get(id)
                        .is_none_or(|record| terminal(record.phase))
                })
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in completed_groups {
            if let Some(group) = inner.groups.remove(&key) {
                if group.phase == GroupPhase::Approved {
                    inner
                        .group_decision_tombstones
                        .push_back(GroupDecisionTombstone {
                            group_id: group.group_id.clone(),
                            decision_id: group.decision_id.clone(),
                            scope_id: group.scope_id.clone(),
                        });
                    while inner.group_decision_tombstones.len() > MAX_GROUP_DECISION_TOMBSTONES {
                        inner.group_decision_tombstones.pop_front();
                    }
                }
                inner.retired_ids.insert(&group.group_id);
                inner.retired_ids.insert(&group.decision_id);
                inner.retired_ids.insert(&group.scope_id);
                if let Some(transaction_id) = group.transaction_id {
                    inner.retired_ids.insert(&transaction_id);
                }
            }
        }
        while inner
            .records
            .values()
            .filter(|record| terminal(record.phase))
            .count()
            > MAX_TERMINALS
        {
            let Some(position) = inner.order.iter().position(|id| {
                inner
                    .records
                    .get(id)
                    .is_some_and(|record| terminal(record.phase))
            }) else {
                break;
            };
            let id = inner.order[position].clone();
            let Some(record) = inner.records.remove(&id) else {
                break;
            };
            inner.order.remove(position);
            inner.retired_ids.insert(&record.approval_id);
            inner.retired_ids.insert(&record.decision_id);
            inner.retired_ids.insert(&record.invocation_id);
            if let Some(transaction_id) = &record.transaction_id {
                inner.retired_ids.insert(transaction_id);
            }
            for scope in &record.scope_ids {
                inner.retired_ids.insert(scope);
            }
        }
        let retained_keys: HashSet<String> = inner
            .records
            .values()
            .filter_map(|record| record.group_key.clone())
            .collect();
        let removed: Vec<String> = inner
            .groups
            .keys()
            .filter(|key| !retained_keys.contains(*key))
            .cloned()
            .collect();
        for key in removed {
            if let Some(group) = inner.groups.remove(&key) {
                inner.retired_ids.insert(&group.group_id);
                inner.retired_ids.insert(&group.decision_id);
                inner.retired_ids.insert(&group.scope_id);
                if let Some(transaction_id) = group.transaction_id {
                    inner.retired_ids.insert(&transaction_id);
                }
            }
        }
    }
}

fn transition(record: &mut Record, next: ApprovalState) -> Result<(), String> {
    let legal = matches!(
        (record.phase, next),
        (ApprovalState::PolicyCheck, ApprovalState::Awaiting)
            | (ApprovalState::Awaiting, ApprovalState::Submitting)
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

fn view(record: &Record, inner: &Inner, now: Instant) -> ApprovalView {
    debug_assert!(record.workspace_revision <= MAX_JS_SAFE_INTEGER);
    let expires_in_ms = record
        .expires_at
        .saturating_duration_since(now)
        .as_millis()
        .min(MAX_JS_SAFE_INTEGER as u128) as u64;
    let group_action = record
        .group_key
        .as_ref()
        .and_then(|key| inner.groups.get(key))
        .and_then(|group| {
            let all_ready = group.members.iter().flatten().all(|id| {
                inner.records.get(id).is_some_and(|member| {
                    member.phase == ApprovalState::Awaiting
                        && member.ready
                        && member.classification.risk == ApprovalRisk::Routine
                })
            });
            (group.phase == GroupPhase::Eligible
                && all_ready
                && group.members.iter().all(Option::is_some))
            .then(|| ApprovalGroupActionView {
                group_id: group.group_id.clone(),
                decision_id: group.decision_id.clone(),
                scope_id: group.scope_id.clone(),
                label: "Allow this safe group once",
            })
        });
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
        delivery_status: (record.phase == ApprovalState::Approved)
            .then_some(ApprovalDeliveryStatus::Uncertain),
        group_action,
        terminal_reason: record.terminal_reason,
    }
}

fn bump_change(inner: &mut Inner) -> Result<(), String> {
    inner.change_sequence = inner
        .change_sequence
        .checked_add(1)
        .filter(|value| *value <= MAX_JS_SAFE_INTEGER)
        .ok_or_else(|| "approval change sequence exhausted".to_string())?;
    Ok(())
}

fn cohort_key(request: &ApprovalRequest, cohort: &ApprovalCohort) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        request.generation,
        request.session_id,
        request.workspace_id,
        request.workspace_revision,
        cohort.assistant_entry_id,
        cohort.cohort_digest
    )
}

fn validate_wire_coordinate(value: &str) -> Result<(), String> {
    if !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
    {
        Ok(())
    } else {
        Err("approval identifier rejected".into())
    }
}

fn validate_request_cohort(request: &ApprovalRequest) -> Result<Option<usize>, String> {
    match (&request.tool_call_id, &request.cohort) {
        (None, None) => Ok(None),
        (Some(tool_call_id), Some(cohort)) => {
            validate_wire_coordinate(tool_call_id)?;
            validate_wire_coordinate(&cohort.assistant_entry_id)?;
            if cohort.ordered_members.is_empty()
                || cohort.ordered_members.len() > MAX_GROUP_MEMBERS
                || cohort.cohort_digest.len() != 64
                || !cohort
                    .cohort_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err("approval cohort rejected".into());
            }
            let mut seen = HashSet::new();
            for (index, member) in cohort.ordered_members.iter().enumerate() {
                if member.ordinal != index
                    || !valid_approval_tool_name(&member.tool_name)
                    || validate_wire_coordinate(&member.tool_call_id).is_err()
                    || !seen.insert(member.tool_call_id.clone())
                {
                    return Err("approval cohort rejected".into());
                }
            }
            let descriptor = serde_json::json!({
                "assistantEntryId": cohort.assistant_entry_id,
                "orderedMembers": cohort.ordered_members.iter().map(|member| serde_json::json!({
                    "ordinal": member.ordinal, "toolCallId": member.tool_call_id, "toolName": member.tool_name
                })).collect::<Vec<_>>()
            });
            let digest = format!("{:x}", Sha256::digest(canonical_json_bytes(&descriptor)?));
            if digest != cohort.cohort_digest {
                return Err("approval cohort rejected".into());
            }
            let matches: Vec<usize> = cohort
                .ordered_members
                .iter()
                .filter(|member| {
                    member.tool_call_id == *tool_call_id && member.tool_name == request.tool_name
                })
                .map(|member| member.ordinal)
                .collect();
            if matches.len() != 1 {
                return Err("approval cohort rejected".into());
            }
            Ok(matches.first().copied())
        }
        _ => Err("approval cohort rejected".into()),
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
    use crate::domain::workspace::{WorkspaceRegistry, WorkspaceSummary};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    struct SequenceResponseTokens(AtomicU64);
    impl ApprovalResponseTokenSource for SequenceResponseTokens {
        fn next(&self) -> String {
            format!("response-{:032x}", self.0.fetch_add(1, Ordering::SeqCst))
        }
    }
    struct ReplayIds {
        next_id: AtomicU64,
        replay_exposed: AtomicBool,
    }
    impl ApprovalIdSource for ReplayIds {
        fn next(&self, prefix: &str) -> String {
            let value = if self.replay_exposed.load(Ordering::SeqCst) {
                match prefix {
                    "approval" => 5,
                    "decision" => 6,
                    "scope" => 7,
                    _ => 0,
                }
            } else {
                self.next_id.fetch_add(1, Ordering::SeqCst)
            };
            format!("{prefix}-{value:032x}")
        }
    }
    struct ExhaustibleResponseTokens {
        allow_unique: AtomicBool,
        calls: AtomicU64,
    }
    impl ApprovalResponseTokenSource for ExhaustibleResponseTokens {
        fn next(&self) -> String {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let value = if self.allow_unique.load(Ordering::SeqCst) {
                0xbeef
            } else {
                0xfeed
            };
            format!("response-{value:032x}")
        }
    }
    struct CollisionIds {
        target: &'static str,
        target_calls: AtomicU64,
        other_ids: AtomicU64,
    }
    impl ApprovalIdSource for CollisionIds {
        fn next(&self, prefix: &str) -> String {
            if prefix == self.target {
                self.target_calls.fetch_add(1, Ordering::SeqCst);
                format!("{prefix}-{:032x}", 0xfeed_u64)
            } else {
                format!(
                    "{prefix}-{:032x}",
                    self.other_ids.fetch_add(1, Ordering::SeqCst)
                )
            }
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
                Arc::new(SequenceResponseTokens(AtomicU64::new(1))),
                Duration::from_millis(100),
            ),
            clock,
        )
    }
    fn request(invocation: u64, tool: &str) -> ApprovalRequest {
        let input = serde_json::json!({"z": 1, "a": [true, "safe"]});
        let input_digest = format!(
            "{:x}",
            Sha256::digest(canonical_json_bytes(&input).unwrap())
        );
        ApprovalRequest {
            generation: 1,
            correlation_id: format!("sidecar-{invocation:032x}"),
            session_id: format!("session-{:032x}", 1),
            workspace_id: format!("workspace-{:032x}", 2),
            workspace_revision: 1,
            invocation_id: format!("invocation-{invocation:032x}"),
            tool_call_id: None,
            tool_name: tool.into(),
            cohort: None,
            input,
            input_digest,
        }
    }
    fn binding() -> WorkspaceApprovalBinding {
        WorkspaceApprovalBinding::for_test(format!("workspace-{:032x}", 2), 1)
    }
    fn cohort_request(invocation: u64, ordinal: usize, tools: &[&str]) -> ApprovalRequest {
        let mut request = request(invocation, tools[ordinal]);
        let assistant_entry_id = "assistant-entry-1".to_string();
        let ordered_members: Vec<ApprovalCohortMember> = tools
            .iter()
            .enumerate()
            .map(|(index, tool)| ApprovalCohortMember {
                ordinal: index,
                tool_call_id: format!("tool-call-{}", index + 1),
                tool_name: (*tool).into(),
            })
            .collect();
        let descriptor = serde_json::json!({
            "assistantEntryId": assistant_entry_id,
            "orderedMembers": ordered_members.iter().map(|member| serde_json::json!({
                "ordinal": member.ordinal, "toolCallId": member.tool_call_id, "toolName": member.tool_name
            })).collect::<Vec<_>>()
        });
        request.tool_call_id = Some(ordered_members[ordinal].tool_call_id.clone());
        request.cohort = Some(ApprovalCohort {
            assistant_entry_id,
            cohort_digest: format!(
                "{:x}",
                Sha256::digest(canonical_json_bytes(&descriptor).unwrap())
            ),
            ordered_members,
        });
        request
    }
    fn mark_ready(registry: &ApprovalRegistry, request: &ApprovalRequest, correlation: u64) {
        registry
            .mark_ready(ApprovalReadyRequest {
                generation: request.generation,
                correlation_id: format!("sidecar-ready-{correlation}"),
                invocation_id: request.invocation_id.clone(),
                tool_call_id: request.tool_call_id.clone().unwrap(),
                input_digest: request.input_digest.clone(),
                cohort_digest: request.cohort.as_ref().unwrap().cohort_digest.clone(),
            })
            .unwrap();
    }

    #[test]
    fn exact_submission_is_single_winner_and_sibling_scope_cannot_authorise() {
        let (registry, _) = registry();
        let first = registry.register(request(1, "write"), binding()).unwrap();
        let sibling = registry.register(request(2, "write"), binding()).unwrap();
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
        let job = registry.take_response_job(1).unwrap().unwrap();
        assert_eq!(job.decision, "approved");
        assert!(registry.take_response_job(1).unwrap().is_none());
        registry
            .complete_response(&job.response_token, |_| Ok(()))
            .unwrap();
        registry
            .submit(ApprovalSubmission {
                approval_id: first.approval_id,
                decision_id: first.decision_id,
                scope_ids: vec![first.scopes[0].scope_id.clone()],
                choice: ApprovalChoice::ApproveOnce,
            })
            .unwrap();
    }

    #[test]
    fn injected_id_collisions_scan_each_retained_field_and_retry_only_eight_times() {
        for target in ["approval", "decision", "scope"] {
            let clock = Arc::new(ManualClock {
                base: Instant::now(),
                millis: AtomicU64::new(0),
            });
            let ids = Arc::new(CollisionIds {
                target,
                target_calls: AtomicU64::new(0),
                other_ids: AtomicU64::new(100),
            });
            let registry = ApprovalRegistry::with_test_authorities(
                clock,
                ids.clone(),
                Arc::new(SequenceResponseTokens(AtomicU64::new(1))),
                Duration::from_millis(100),
            );
            registry.register(request(1, "read"), binding()).unwrap();
            assert_eq!(
                registry
                    .register(request(2, "read"), binding())
                    .unwrap_err(),
                "approval identifier unavailable",
                "retained {target} collision was accepted"
            );
            assert_eq!(
                ids.target_calls.load(Ordering::SeqCst),
                9,
                "{target} retries exceeded or did not exhaust the fixed bound"
            );
        }
    }

    #[test]
    fn retained_invocation_ids_are_unique_across_generations() {
        let (registry, _) = registry();
        registry.register(request(1, "read"), binding()).unwrap();
        let mut duplicate = request(1, "read");
        duplicate.generation = 2;
        duplicate.correlation_id = format!("sidecar-{:032x}", 2);
        assert_eq!(
            registry.register(duplicate, binding()).unwrap_err(),
            "approval invocation already registered"
        );
    }

    #[test]
    fn concurrent_duplicate_decisions_have_one_response_owner() {
        let (registry, _) = registry();
        let registry = Arc::new(registry);
        let view = registry.register(request(1, "read"), binding()).unwrap();
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
            registry
                .register(request(invocation, "read"), binding())
                .unwrap();
        }
        assert_eq!(
            registry
                .register(request(100, "read"), binding())
                .unwrap_err(),
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
        assert!(registry.register(request(100, "read"), binding()).is_err());
        let job = registry.take_response_job(1).unwrap().unwrap();
        registry
            .complete_response(&job.response_token, |_| Ok(()))
            .unwrap();
        registry.register(request(100, "read"), binding()).unwrap();
    }

    #[test]
    fn timeout_and_generation_cutoff_are_non_approved_and_terminal() {
        let (registry, clock) = registry();
        let expired = registry.register(request(1, "read"), binding()).unwrap();
        clock.millis.store(101, Ordering::SeqCst);
        assert!(registry.pending().unwrap().is_empty());
        assert!(
            registry
                .submit(ApprovalSubmission {
                    approval_id: expired.approval_id,
                    decision_id: expired.decision_id,
                    scope_ids: Vec::new(),
                    choice: ApprovalChoice::Deny,
                })
                .is_err()
        );
        let job = registry.take_response_job(1).unwrap().unwrap();
        assert_eq!(job.decision, "expired");
        registry
            .complete_response(&job.response_token, |_| Ok(()))
            .unwrap();
        let cancelled = registry.register(request(2, "bash"), binding()).unwrap();
        registry.invalidate_generation(1);
        assert!(registry.take_response_job(1).unwrap().is_none());
        let inner = registry.inner.lock().unwrap();
        assert_eq!(
            inner.records[&cancelled.approval_id].phase,
            ApprovalState::Cancelled
        );
    }

    #[test]
    fn response_token_exhaustion_leaves_exposed_expiry_transaction_unchanged() {
        let clock = Arc::new(ManualClock {
            base: Instant::now(),
            millis: AtomicU64::new(0),
        });
        let ids = Arc::new(ReplayIds {
            next_id: AtomicU64::new(1),
            replay_exposed: AtomicBool::new(false),
        });
        let response_tokens = Arc::new(ExhaustibleResponseTokens {
            allow_unique: AtomicBool::new(false),
            calls: AtomicU64::new(0),
        });
        let registry = ApprovalRegistry::with_test_authorities(
            clock.clone(),
            ids.clone(),
            response_tokens.clone(),
            Duration::from_millis(100),
        );

        registry
            .register(request(1, "unsupported"), binding())
            .unwrap();
        let awaiting = registry.register(request(2, "read"), binding()).unwrap();
        let (order_before, records_before, active_before, revision_before) = {
            let inner = registry.inner.lock().unwrap();
            let record = &inner.records[&awaiting.approval_id];
            (
                inner.order.clone(),
                inner.records.len(),
                inner
                    .records
                    .values()
                    .filter(|record| !terminal(record.phase))
                    .count(),
                record.revision,
            )
        };

        {
            let mut inner = registry.inner.lock().unwrap();
            assert_eq!(
                registry
                    .expire_locked(&mut inner, clock.base + Duration::from_millis(101))
                    .unwrap_err(),
                "approval response unavailable"
            );
        }
        assert_eq!(response_tokens.calls.load(Ordering::SeqCst), 9);

        ids.replay_exposed.store(true, Ordering::SeqCst);
        {
            let inner = registry.inner.lock().unwrap();
            let record = &inner.records[&awaiting.approval_id];
            assert_eq!(inner.order, order_before);
            assert_eq!(inner.records.len(), records_before);
            assert_eq!(
                inner
                    .records
                    .values()
                    .filter(|record| !terminal(record.phase))
                    .count(),
                active_before
            );
            assert_eq!(record.phase, ApprovalState::Awaiting);
            assert_eq!(record.revision, revision_before);
            assert!(record.resolution.is_none());
            assert!(record.pending_outcome.is_none());
            assert!(record.response_token.is_none());
            for prefix in ["approval", "decision", "scope"] {
                assert_eq!(
                    registry.fresh_id(&inner, prefix).unwrap_err(),
                    "approval identifier unavailable",
                    "exposed {prefix} ID became reusable"
                );
            }
        }
        ids.replay_exposed.store(false, Ordering::SeqCst);
        assert_eq!(
            registry
                .register(request(2, "read"), binding())
                .unwrap_err(),
            "approval invocation already registered"
        );

        response_tokens.allow_unique.store(true, Ordering::SeqCst);
        clock.millis.store(101, Ordering::SeqCst);
        assert!(registry.pending().unwrap().is_empty());
        let inner = registry.inner.lock().unwrap();
        let record = &inner.records[&awaiting.approval_id];
        assert_eq!(inner.order, order_before);
        assert_eq!(inner.records.len(), records_before);
        assert_eq!(record.phase, ApprovalState::Submitting);
        assert_eq!(record.pending_outcome, Some(ApprovalState::Expired));
        assert_eq!(
            record.response_token.as_deref(),
            Some("response-0000000000000000000000000000beef")
        );
    }

    #[test]
    fn unknown_and_malformed_inputs_fail_closed() {
        let (registry, _) = registry();
        let view = registry
            .register(request(1, "invented"), binding())
            .unwrap();
        assert_eq!(view.risk, ApprovalRisk::DenyOnly);
        assert_eq!(
            registry.take_response_job(1).unwrap().unwrap().decision,
            "denied"
        );
        let mut malformed = request(2, "read");
        malformed.input = serde_json::json!({"value": 1.5});
        assert!(registry.register(malformed, binding()).is_err());

        let valid_96 = format!("A{}", "a".repeat(95));
        assert!(registry.register(request(3, &valid_96), binding()).is_ok());
        for (invocation, invalid) in [(4, format!("A{}", "a".repeat(96))), (5, "réad".to_string())]
        {
            assert!(
                registry
                    .register(request(invocation, &invalid), binding())
                    .is_err()
            );
        }
    }

    #[test]
    fn writer_failure_cancels_and_late_matching_ui_resolution_conflicts() {
        let (registry, _) = registry();
        let view = registry.register(request(1, "write"), binding()).unwrap();
        let submission = ApprovalSubmission {
            approval_id: view.approval_id.clone(),
            decision_id: view.decision_id.clone(),
            scope_ids: vec![view.scopes[0].scope_id.clone()],
            choice: ApprovalChoice::ApproveOnce,
        };
        registry.submit(submission).unwrap();
        let job = registry.take_response_job(1).unwrap().unwrap();
        assert!(
            registry
                .complete_response(
                    &job.response_token,
                    |_| Err("expected write failure".into())
                )
                .is_err()
        );
        assert!(
            registry
                .submit(ApprovalSubmission {
                    approval_id: view.approval_id.clone(),
                    decision_id: view.decision_id,
                    scope_ids: vec![view.scopes[0].scope_id.clone()],
                    choice: ApprovalChoice::ApproveOnce,
                })
                .is_err()
        );
        assert_eq!(
            registry.inner.lock().unwrap().records[&view.approval_id].phase,
            ApprovalState::Cancelled
        );
    }

    #[test]
    fn retired_id_authority_is_fixed_two_mebibytes_with_eight_positions() {
        let mut retired = RetiredIds::default();
        assert_eq!(
            retired.bits.len() * std::mem::size_of::<u64>(),
            RETIRED_ID_BLOOM_BYTES
        );
        assert_eq!(retired.positions("invocation-test").len(), 8);
        assert!(!retired.contains("invocation-test"));
        retired.insert("invocation-test");
        assert!(retired.contains("invocation-test"));
    }

    #[test]
    fn terminal_cap_prunes_behind_awaiting_and_retires_invocations() {
        let (registry, _) = registry();
        registry.register(request(1, "read"), binding()).unwrap();
        for invocation in 2..=(MAX_TERMINALS as u64 + 3) {
            registry
                .register(request(invocation, "unsupported"), binding())
                .unwrap();
            let job = registry.take_response_job(1).unwrap().unwrap();
            registry
                .complete_response(&job.response_token, |_| Ok(()))
                .unwrap();
        }
        let inner = registry.inner.lock().unwrap();
        assert_eq!(
            inner
                .records
                .values()
                .filter(|record| terminal(record.phase))
                .count(),
            MAX_TERMINALS
        );
        assert_eq!(
            inner
                .records
                .values()
                .filter(|record| record.phase == ApprovalState::Awaiting)
                .count(),
            1
        );
        drop(inner);
        assert_eq!(
            registry
                .register(request(2, "read"), binding())
                .unwrap_err(),
            "approval invocation already registered"
        );
    }

    #[test]
    fn workspace_revocation_and_decision_linearise_in_both_orders() {
        fn trusted_workspace() -> (WorkspaceRegistry, std::path::PathBuf, WorkspaceSummary) {
            let root =
                std::env::temp_dir().join(format!("piui-approval-workspace-{}", Uuid::new_v4()));
            std::fs::create_dir(&root).unwrap();
            let workspace = WorkspaceRegistry::default();
            let acquired = workspace.acquire_selected_directory(&root).unwrap();
            workspace.inspect_metadata(&acquired.workspace_id).unwrap();
            workspace.open_untrusted(&acquired.workspace_id, 0).unwrap();
            let (trusted, _) = workspace.authorise(&acquired.workspace_id, 0).unwrap();
            (workspace, root, trusted)
        }
        fn bound_request(invocation: u64, trusted: &WorkspaceSummary) -> ApprovalRequest {
            let mut request = request(invocation, "write");
            request.workspace_id = trusted.workspace_id.clone();
            request.workspace_revision = trusted.revision;
            request
        }

        let (registry, _) = registry();
        let (workspace, root, trusted) = trusted_workspace();
        let view = workspace
            .with_approval_binding(&trusted.workspace_id, trusted.revision, |binding| {
                registry.register(bound_request(1, &trusted), binding)
            })
            .unwrap();
        registry
            .submit(ApprovalSubmission {
                approval_id: view.approval_id.clone(),
                decision_id: view.decision_id,
                scope_ids: vec![view.scopes[0].scope_id.clone()],
                choice: ApprovalChoice::ApproveOnce,
            })
            .unwrap();
        let job = registry.take_response_job(1).unwrap().unwrap();
        workspace
            .with_valid_approval_binding(&job.binding, || {
                registry.complete_response(&job.response_token, |_| Ok(()))
            })
            .unwrap();
        workspace
            .revoke(&trusted.workspace_id, trusted.revision)
            .unwrap();
        assert_eq!(
            registry.inner.lock().unwrap().records[&view.approval_id].phase,
            ApprovalState::Approved
        );
        let _ = std::fs::remove_dir_all(root);

        let (second_registry, _) = self::registry();
        let (workspace, root, trusted) = trusted_workspace();
        let view = workspace
            .with_approval_binding(&trusted.workspace_id, trusted.revision, |binding| {
                second_registry.register(bound_request(2, &trusted), binding)
            })
            .unwrap();
        second_registry
            .submit(ApprovalSubmission {
                approval_id: view.approval_id.clone(),
                decision_id: view.decision_id,
                scope_ids: vec![view.scopes[0].scope_id.clone()],
                choice: ApprovalChoice::ApproveOnce,
            })
            .unwrap();
        let job = second_registry.take_response_job(1).unwrap().unwrap();
        workspace
            .revoke(&trusted.workspace_id, trusted.revision)
            .unwrap();
        assert!(
            workspace
                .with_valid_approval_binding(&job.binding, || Ok(()))
                .is_err()
        );
        second_registry.cancel_response(&job.response_token);
        assert_eq!(
            second_registry.inner.lock().unwrap().records[&view.approval_id].phase,
            ApprovalState::Cancelled
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn exact_routine_group_is_ready_gated_and_commits_all_members_atomically() {
        let (registry, _) = registry();
        let tools = ["read", "grep", "find"];
        let requests: Vec<ApprovalRequest> = (0..3)
            .map(|ordinal| cohort_request((ordinal + 1) as u64, ordinal, &tools))
            .collect();
        let views: Vec<ApprovalView> = requests
            .iter()
            .cloned()
            .map(|request| registry.register(request, binding()).unwrap())
            .collect();
        assert!(
            registry
                .pending()
                .unwrap()
                .iter()
                .all(|view| view.group_action.is_none())
        );
        for (index, request) in requests.iter().enumerate() {
            mark_ready(&registry, request, index as u64 + 1);
        }
        let pending = registry.pending().unwrap();
        assert_eq!(pending.len(), 3);
        let action = pending[0].group_action.clone().unwrap();
        assert!(pending.iter().all(|view| {
            view.group_action
                .as_ref()
                .is_some_and(|candidate| candidate.group_id == action.group_id)
        }));
        registry
            .submit_group(ApprovalGroupSubmission {
                group_id: action.group_id.clone(),
                decision_id: action.decision_id.clone(),
                scope_id: action.scope_id.clone(),
            })
            .unwrap();
        assert!(registry.take_response_job(1).unwrap().is_none());
        let job = registry.take_group_response_job(1).unwrap().unwrap();
        assert_eq!(job.members.len(), 3);
        assert_eq!(
            job.members
                .iter()
                .map(|member| member.tool_call_id.as_str())
                .collect::<Vec<_>>(),
            vec!["tool-call-1", "tool-call-2", "tool-call-3"]
        );
        registry
            .complete_group_response(&job.response_token, |_| Ok(()))
            .unwrap();
        let snapshot = registry.snapshot().unwrap();
        assert!(snapshot.records.iter().all(|view| {
            view.state == ApprovalState::Approved
                && view.delivery_status == Some(ApprovalDeliveryStatus::Uncertain)
        }));
        assert!(registry.take_group_response_job(1).unwrap().is_none());
        assert_eq!(views.len(), 3);
        registry
            .submit_group(ApprovalGroupSubmission {
                group_id: action.group_id.clone(),
                decision_id: action.decision_id.clone(),
                scope_id: action.scope_id.clone(),
            })
            .expect("lost command acknowledgement retry remains exact and idempotent");
        assert!(
            registry
                .submit_group(ApprovalGroupSubmission {
                    group_id: action.group_id,
                    decision_id: action.decision_id,
                    scope_id: format!("scope-{:032x}", 0xdead),
                })
                .is_err()
        );
        assert_eq!(
            registry
                .inner
                .lock()
                .unwrap()
                .group_decision_tombstones
                .len(),
            1
        );
    }

    #[test]
    fn group_decision_tombstones_are_bounded_and_keep_newest_exact_retry() {
        let (registry, _) = registry();
        let tools = ["read", "grep"];
        let mut first: Option<ApprovalGroupActionView> = None;
        let mut latest: Option<ApprovalGroupActionView> = None;
        for turn in 0..=MAX_GROUP_DECISION_TOMBSTONES {
            let mut requests: Vec<_> = (0..2)
                .map(|ordinal| cohort_request((turn * 2 + ordinal + 1) as u64, ordinal, &tools))
                .collect();
            let assistant_entry_id = format!("assistant-entry-{}", turn + 1);
            for request in &mut requests {
                let cohort = request.cohort.as_mut().unwrap();
                cohort.assistant_entry_id = assistant_entry_id.clone();
                let descriptor = serde_json::json!({
                    "assistantEntryId": cohort.assistant_entry_id,
                    "orderedMembers": cohort.ordered_members.iter().map(|member| serde_json::json!({
                        "ordinal": member.ordinal,
                        "toolCallId": member.tool_call_id,
                        "toolName": member.tool_name,
                    })).collect::<Vec<_>>()
                });
                cohort.cohort_digest = format!(
                    "{:x}",
                    Sha256::digest(canonical_json_bytes(&descriptor).unwrap())
                );
            }
            for request in requests.iter().cloned() {
                registry.register(request, binding()).unwrap();
            }
            for (index, request) in requests.iter().enumerate() {
                mark_ready(&registry, request, (turn * 2 + index + 1) as u64);
            }
            let action = registry
                .pending()
                .unwrap()
                .iter()
                .find_map(|view| view.group_action.clone())
                .unwrap();
            first.get_or_insert_with(|| action.clone());
            latest = Some(action.clone());
            registry
                .submit_group(ApprovalGroupSubmission {
                    group_id: action.group_id,
                    decision_id: action.decision_id,
                    scope_id: action.scope_id,
                })
                .unwrap();
            let job = registry.take_group_response_job(1).unwrap().unwrap();
            registry
                .complete_group_response(&job.response_token, |_| Ok(()))
                .unwrap();
        }
        assert_eq!(
            registry
                .inner
                .lock()
                .unwrap()
                .group_decision_tombstones
                .len(),
            MAX_GROUP_DECISION_TOMBSTONES
        );
        let first = first.unwrap();
        assert!(
            registry
                .submit_group(ApprovalGroupSubmission {
                    group_id: first.group_id,
                    decision_id: first.decision_id,
                    scope_id: first.scope_id,
                })
                .is_err()
        );
        let latest = latest.unwrap();
        registry
            .submit_group(ApprovalGroupSubmission {
                group_id: latest.group_id.clone(),
                decision_id: latest.decision_id.clone(),
                scope_id: latest.scope_id.clone(),
            })
            .unwrap();
        assert!(
            registry
                .submit_group(ApprovalGroupSubmission {
                    group_id: latest.group_id,
                    decision_id: latest.decision_id,
                    scope_id: format!("scope-{:032x}", 0xf00d),
                })
                .is_err()
        );
    }

    #[test]
    fn claimed_individual_and_group_approval_cannot_publish_at_or_after_expiry() {
        let (individual, clock) = registry();
        let view = individual.register(request(1, "read"), binding()).unwrap();
        individual
            .submit(ApprovalSubmission {
                approval_id: view.approval_id,
                decision_id: view.decision_id,
                scope_ids: view
                    .scopes
                    .into_iter()
                    .map(|scope| scope.scope_id)
                    .collect(),
                choice: ApprovalChoice::ApproveOnce,
            })
            .unwrap();
        let claimed = individual.take_response_job(1).unwrap().unwrap();
        clock.millis.store(100, Ordering::SeqCst);
        let mut wrote = false;
        individual
            .complete_response(&claimed.response_token, |_| {
                wrote = true;
                Ok(())
            })
            .unwrap();
        assert!(!wrote);
        let expired = individual.take_response_job(1).unwrap().unwrap();
        assert_eq!(expired.decision, "expired");
        individual
            .complete_response(&expired.response_token, |_| Ok(()))
            .unwrap();
        assert_eq!(
            individual.snapshot().unwrap().records[0].state,
            ApprovalState::Expired
        );

        let (group, group_clock) = registry();
        let tools = ["read", "grep", "find"];
        let requests: Vec<_> = (0..3)
            .map(|ordinal| cohort_request((ordinal + 1) as u64, ordinal, &tools))
            .collect();
        for request in requests.iter().cloned() {
            group.register(request, binding()).unwrap();
        }
        for (index, request) in requests.iter().enumerate() {
            mark_ready(&group, request, index as u64 + 1);
        }
        let action = group.pending().unwrap()[0].group_action.clone().unwrap();
        group
            .submit_group(ApprovalGroupSubmission {
                group_id: action.group_id,
                decision_id: action.decision_id,
                scope_id: action.scope_id,
            })
            .unwrap();
        let claimed = group.take_group_response_job(1).unwrap().unwrap();
        group_clock.millis.store(100, Ordering::SeqCst);
        let mut wrote = false;
        group
            .complete_group_response(&claimed.response_token, |_| {
                wrote = true;
                Ok(())
            })
            .unwrap();
        assert!(!wrote);
        let mut expired = 0;
        while let Some(job) = group.take_response_job(1).unwrap() {
            assert_eq!(job.decision, "expired");
            group
                .complete_response(&job.response_token, |_| Ok(()))
                .unwrap();
            expired += 1;
        }
        assert_eq!(expired, 3);
        assert!(
            group
                .snapshot()
                .unwrap()
                .records
                .iter()
                .all(|record| record.state == ApprovalState::Expired)
        );
    }

    #[test]
    fn complete_lf_success_is_not_rewritten_by_a_later_manual_clock_observation() {
        let (registry, clock) = registry();
        let view = registry.register(request(1, "read"), binding()).unwrap();
        registry
            .submit(ApprovalSubmission {
                approval_id: view.approval_id,
                decision_id: view.decision_id,
                scope_ids: view
                    .scopes
                    .into_iter()
                    .map(|scope| scope.scope_id)
                    .collect(),
                choice: ApprovalChoice::ApproveOnce,
            })
            .unwrap();
        let job = registry.take_response_job(1).unwrap().unwrap();
        registry
            .complete_response(&job.response_token, |budget| {
                assert_eq!(budget, Duration::from_millis(100));
                // Ok models a complete LF published before the writer's absolute
                // deadline; this later independent clock move is not publication.
                clock.millis.store(100, Ordering::SeqCst);
                Ok(())
            })
            .unwrap();
        let record = &registry.snapshot().unwrap().records[0];
        assert_eq!(record.state, ApprovalState::Approved);
        assert_eq!(
            record.delivery_status,
            Some(ApprovalDeliveryStatus::Uncertain)
        );

        let (group, group_clock) = self::registry();
        let tools = ["read", "grep", "find"];
        let requests: Vec<_> = (0..3)
            .map(|ordinal| cohort_request((ordinal + 1) as u64, ordinal, &tools))
            .collect();
        for request in requests.iter().cloned() {
            group.register(request, binding()).unwrap();
        }
        for (index, request) in requests.iter().enumerate() {
            mark_ready(&group, request, index as u64 + 1);
        }
        let action = group.pending().unwrap()[0].group_action.clone().unwrap();
        group
            .submit_group(ApprovalGroupSubmission {
                group_id: action.group_id,
                decision_id: action.decision_id,
                scope_id: action.scope_id,
            })
            .unwrap();
        let job = group.take_group_response_job(1).unwrap().unwrap();
        group
            .complete_group_response(&job.response_token, |budget| {
                assert_eq!(budget, Duration::from_millis(100));
                group_clock.millis.store(100, Ordering::SeqCst);
                Ok(())
            })
            .unwrap();
        assert!(group.snapshot().unwrap().records.iter().all(|record| {
            record.state == ApprovalState::Approved
                && record.delivery_status == Some(ApprovalDeliveryStatus::Uncertain)
        }));
    }

    #[test]
    fn incomplete_mixed_and_non_routine_cohorts_never_expose_group_action() {
        for tools in [
            ["read", "grep", "bash"],
            ["read", "web_fetch", "find"],
            ["read", "invented", "find"],
            ["read", "write", "find"],
        ] {
            let (registry, _) = registry();
            let requests: Vec<ApprovalRequest> = (0..3)
                .map(|ordinal| cohort_request((ordinal + 1) as u64, ordinal, &tools))
                .collect();
            for request in requests.iter().cloned() {
                registry.register(request, binding()).unwrap();
            }
            for (index, request) in requests.iter().enumerate() {
                if tools[index] != "invented" {
                    let _ = registry.mark_ready(ApprovalReadyRequest {
                        generation: 1,
                        correlation_id: format!("sidecar-ready-{}", index + 1),
                        invocation_id: request.invocation_id.clone(),
                        tool_call_id: request.tool_call_id.clone().unwrap(),
                        input_digest: request.input_digest.clone(),
                        cohort_digest: request.cohort.as_ref().unwrap().cohort_digest.clone(),
                    });
                }
            }
            assert!(
                registry
                    .pending()
                    .unwrap()
                    .iter()
                    .all(|view| view.group_action.is_none())
            );
            assert!(
                registry
                    .submit_group(ApprovalGroupSubmission {
                        group_id: format!("group-{:032x}", 999),
                        decision_id: format!("decision-{:032x}", 999),
                        scope_id: format!("scope-{:032x}", 999),
                    })
                    .is_err()
            );
        }

        let (registry, _) = registry();
        let tools = ["read", "grep", "find"];
        let first = cohort_request(1, 0, &tools);
        registry.register(first.clone(), binding()).unwrap();
        mark_ready(&registry, &first, 1);
        assert!(
            registry
                .pending()
                .unwrap()
                .iter()
                .all(|view| view.group_action.is_none())
        );
    }

    #[test]
    fn workspace_revoke_and_generation_stop_cancel_claimed_group_members_exactly() {
        fn claimed_group() -> (ApprovalRegistry, GroupApprovalResponseJob) {
            let (registry, _) = registry();
            let tools = ["read", "grep", "find"];
            let requests: Vec<_> = (0..3)
                .map(|ordinal| cohort_request((ordinal + 1) as u64, ordinal, &tools))
                .collect();
            for request in requests.iter().cloned() {
                registry.register(request, binding()).unwrap();
            }
            for (index, request) in requests.iter().enumerate() {
                mark_ready(&registry, request, index as u64 + 1);
            }
            let action = registry.pending().unwrap()[0].group_action.clone().unwrap();
            registry
                .submit_group(ApprovalGroupSubmission {
                    group_id: action.group_id,
                    decision_id: action.decision_id,
                    scope_id: action.scope_id,
                })
                .unwrap();
            let job = registry.take_group_response_job(1).unwrap().unwrap();
            (registry, job)
        }

        let (revoked, old_claim) = claimed_group();
        revoked
            .cancel_workspace(&format!("workspace-{:032x}", 2))
            .unwrap();
        assert!(
            revoked
                .complete_group_response(&old_claim.response_token, |_| Ok(()))
                .is_err()
        );
        let mut cancelled = 0;
        while let Some(job) = revoked.take_response_job(1).unwrap() {
            assert_eq!(job.decision, "cancelled");
            revoked
                .complete_response(&job.response_token, |_| Ok(()))
                .unwrap();
            cancelled += 1;
        }
        assert_eq!(cancelled, 3);
        assert!(
            revoked
                .snapshot()
                .unwrap()
                .records
                .iter()
                .all(|record| record.state == ApprovalState::Cancelled
                    && record.terminal_reason == Some(ApprovalTerminalReason::WorkspaceRevoked))
        );

        let (stopped, old_claim) = claimed_group();
        stopped.invalidate_generation(1);
        assert!(
            stopped
                .complete_group_response(&old_claim.response_token, |_| Ok(()))
                .is_err()
        );
        assert!(
            stopped
                .snapshot()
                .unwrap()
                .records
                .iter()
                .all(|record| record.state == ApprovalState::Cancelled
                    && record.terminal_reason == Some(ApprovalTerminalReason::GenerationLost))
        );
    }

    #[test]
    fn identical_digest_abandonment_is_isolated_by_complete_private_context() {
        let (registry, _) = registry();
        let tools = ["read", "grep"];
        let first: Vec<_> = (0..2)
            .map(|ordinal| cohort_request((ordinal + 1) as u64, ordinal, &tools))
            .collect();
        let mut second: Vec<_> = (0..2)
            .map(|ordinal| cohort_request((ordinal + 11) as u64, ordinal, &tools))
            .collect();
        for request in &mut second {
            request.session_id = format!("session-{:032x}", 9);
        }
        for request in first.iter().chain(second.iter()).cloned() {
            registry.register(request, binding()).unwrap();
        }
        registry
            .abandon(ApprovalAbandonRequest {
                generation: first[0].generation,
                correlation_id: "sidecar-abandon-isolated".into(),
                session_id: first[0].session_id.clone(),
                workspace_id: first[0].workspace_id.clone(),
                workspace_revision: first[0].workspace_revision,
                assistant_entry_id: first[0].cohort.as_ref().unwrap().assistant_entry_id.clone(),
                cohort_digest: first[0].cohort.as_ref().unwrap().cohort_digest.clone(),
            })
            .unwrap();
        let snapshot = registry.snapshot().unwrap();
        assert_eq!(
            snapshot
                .records
                .iter()
                .filter(|record| record.state == ApprovalState::Submitting)
                .count(),
            2
        );
        assert_eq!(
            snapshot
                .records
                .iter()
                .filter(|record| record.state == ApprovalState::Awaiting)
                .count(),
            2
        );
    }

    #[test]
    fn cohort_abandon_and_timeout_settle_every_registered_member_nonapproved() {
        let (registry, clock) = registry();
        let tools = ["read", "grep", "find"];
        let requests: Vec<ApprovalRequest> = (0..3)
            .map(|ordinal| cohort_request((ordinal + 1) as u64, ordinal, &tools))
            .collect();
        for request in requests.iter().cloned() {
            registry.register(request, binding()).unwrap();
        }
        registry
            .abandon(ApprovalAbandonRequest {
                generation: 1,
                correlation_id: "sidecar-abandon-1".into(),
                session_id: requests[0].session_id.clone(),
                workspace_id: requests[0].workspace_id.clone(),
                workspace_revision: requests[0].workspace_revision,
                assistant_entry_id: requests[0]
                    .cohort
                    .as_ref()
                    .unwrap()
                    .assistant_entry_id
                    .clone(),
                cohort_digest: requests[0].cohort.as_ref().unwrap().cohort_digest.clone(),
            })
            .unwrap();
        let mut cancelled = 0;
        while let Some(job) = registry.take_response_job(1).unwrap() {
            assert_eq!(job.decision, "cancelled");
            registry
                .complete_response(&job.response_token, |_| Ok(()))
                .unwrap();
            cancelled += 1;
        }
        assert_eq!(cancelled, 3);
        assert!(
            registry
                .snapshot()
                .unwrap()
                .records
                .iter()
                .all(|view| view.state == ApprovalState::Cancelled)
        );

        let (registry, clock2) = self::registry();
        for ordinal in 0..3 {
            registry
                .register(
                    cohort_request((ordinal + 1) as u64, ordinal, &tools),
                    binding(),
                )
                .unwrap();
        }
        clock2.millis.store(101, Ordering::SeqCst);
        assert!(registry.pending().unwrap().is_empty());
        let mut expired = 0;
        while let Some(job) = registry.take_response_job(1).unwrap() {
            assert_eq!(job.decision, "expired");
            registry
                .complete_response(&job.response_token, |_| Ok(()))
                .unwrap();
            expired += 1;
        }
        assert_eq!(expired, 3);
        assert!(
            registry
                .snapshot()
                .unwrap()
                .records
                .iter()
                .all(|view| view.state == ApprovalState::Expired)
        );
        assert_eq!(clock.millis.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn public_view_contains_no_private_coordinates_or_input() {
        let (registry, _) = registry();
        let view = registry.register(request(1, "bash"), binding()).unwrap();
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
