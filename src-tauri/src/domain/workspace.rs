use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uuid::Uuid;

const MAX_WORKSPACES: usize = 32;
const MAX_SNAPSHOT_ENTRIES: usize = 256;
const MAX_SNAPSHOT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_COMPONENT_BYTES: usize = 255;
const MAX_DISPLAY_SCALARS: usize = 128;
const MAX_JS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const FIXED_PROJECT_DIRS: [&str; 4] = ["extensions", "skills", "prompts", "themes"];

const WORKSPACE_UNAVAILABLE: &str = "workspace unavailable";
const WORKSPACE_REJECTED: &str = "workspace request rejected";
const WORKSPACE_CONFLICT: &str = "workspace state conflict";
const WORKSPACE_UNTRUSTED: &str = "workspace is not trusted";
const WORKSPACE_CAPACITY: &str = "workspace capacity unavailable";
const WORKSPACE_CONTAINMENT: &str = "workspace resources were rejected";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkspaceLifecycle {
    Acquired,
    Inspected,
    OpenUntrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustState {
    Untrusted,
    Trusted,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicResourceState {
    NotLoaded,
    Preparing,
    Loading,
    Loaded,
    FailedClosed,
    ExecutionUncertain,
    RevokedPriorEffects,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MetadataKind {
    Absent,
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceMetadata {
    pub pi_directory: MetadataKind,
    pub settings: MetadataKind,
    pub extensions: MetadataKind,
    pub skills: MetadataKind,
    pub prompts: MetadataKind,
    pub themes: MetadataKind,
    pub package_manifest: MetadataKind,
    pub agents_context: MetadataKind,
    pub claude_context: MetadataKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceCounts {
    pub extensions: u8,
    pub skills: u8,
    pub prompts: u8,
    pub themes: u8,
    pub packages: u8,
    pub truncated: bool,
}

impl ResourceCounts {
    pub fn validate(self) -> Result<Self, String> {
        if [
            self.extensions,
            self.skills,
            self.prompts,
            self.themes,
            self.packages,
        ]
        .into_iter()
        .any(|count| count > 64)
        {
            Err(WORKSPACE_REJECTED.into())
        } else {
            Ok(self)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSummary {
    pub workspace_id: String,
    pub display_label: String,
    pub lifecycle: WorkspaceLifecycle,
    pub trust_state: TrustState,
    pub revision: u64,
    pub resource_state: PublicResourceState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<WorkspaceMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counts: Option<ResourceCounts>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

struct DirectoryCapability {
    handle: File,
    canonical_path: PathBuf,
    identity: DirectoryIdentity,
}

struct Snapshot {
    base: PathBuf,
    project_root: PathBuf,
    agent_root: PathBuf,
}

impl Snapshot {
    fn remove(self) {
        let _ = set_tree_owner_writable(&self.base);
        let _ = fs::remove_dir_all(self.base);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InternalResourceState {
    NotLoaded,
    Preparing {
        generation: u64,
        revision: u64,
        operation: Uuid,
    },
    Loading {
        generation: u64,
        revision: u64,
        operation: Uuid,
    },
    Loaded {
        generation: u64,
        revision: u64,
        counts: ResourceCounts,
    },
    FailedClosed {
        generation: u64,
        revision: u64,
    },
    ExecutionUncertain {
        generation: u64,
        revision: u64,
    },
    RevokedPriorEffects,
}

#[derive(Clone, PartialEq, Eq)]
struct PendingAuthorisation {
    operation: Uuid,
    expected_revision: u64,
    revision: u64,
    lease_id: String,
}

struct WorkspaceRecord {
    id: String,
    display_label: String,
    capability: DirectoryCapability,
    lifecycle: WorkspaceLifecycle,
    trust_state: TrustState,
    revision: u64,
    lease_id: Option<String>,
    pending_authorisation: Option<PendingAuthorisation>,
    metadata: Option<WorkspaceMetadata>,
    resource: InternalResourceState,
    snapshot: Option<Snapshot>,
}

struct RegistryInner {
    records: HashMap<String, WorkspaceRecord>,
}

pub struct WorkspaceRegistry {
    inner: Mutex<RegistryInner>,
}

impl Default for WorkspaceRegistry {
    fn default() -> Self {
        Self {
            inner: Mutex::new(RegistryInner {
                records: HashMap::with_capacity(MAX_WORKSPACES),
            }),
        }
    }
}

pub(crate) struct TrustGrant {
    pub(crate) workspace_id: String,
    pub(crate) operation_id: String,
    pub(crate) expected_revision: u64,
    pub(crate) revision: u64,
    pub(crate) lease_id: String,
}

#[derive(Clone)]
pub(crate) struct WorkspaceApprovalBinding {
    workspace_id: String,
    revision: u64,
    lease_id: String,
}

impl WorkspaceApprovalBinding {
    #[cfg(test)]
    pub(crate) fn for_test(workspace_id: String, revision: u64) -> Self {
        Self {
            workspace_id,
            revision,
            lease_id: format!("trust-{}", Uuid::new_v4().simple()),
        }
    }
}

pub(crate) struct WorkspaceSync {
    pub(crate) workspace_id: String,
    pub(crate) revision: u64,
    pub(crate) trust_state: TrustState,
    pub(crate) lease_id: Option<String>,
}

pub enum LoadStart {
    Dispatch(LoadLease),
    Cached(WorkspaceSummary),
    InProgress(WorkspaceSummary),
}

pub struct LoadLease {
    pub(crate) workspace_id: String,
    pub(crate) revision: u64,
    pub(crate) generation: u64,
    pub(crate) operation_id: String,
    pub(crate) lease_id: String,
    pub(crate) snapshot_root: PathBuf,
    pub(crate) agent_root: PathBuf,
}

pub struct RevokeOutcome {
    pub summary: WorkspaceSummary,
    pub stop_generation: Option<u64>,
    pub(crate) lease_id: String,
    snapshot: Option<Snapshot>,
}

impl RevokeOutcome {
    pub fn cleanup(mut self) -> WorkspaceSummary {
        if let Some(snapshot) = self.snapshot.take() {
            snapshot.remove();
        }
        self.summary.clone()
    }
}

impl Drop for RevokeOutcome {
    fn drop(&mut self) {
        if let Some(snapshot) = self.snapshot.take() {
            snapshot.remove();
        }
    }
}

impl WorkspaceRegistry {
    pub(crate) fn with_approval_binding<T>(
        &self,
        workspace_id: &str,
        revision: u64,
        operation: impl FnOnce(WorkspaceApprovalBinding) -> Result<T, String>,
    ) -> Result<T, String> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        let record = inner
            .records
            .get(workspace_id)
            .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())?;
        if record.lifecycle != WorkspaceLifecycle::OpenUntrusted
            || record.trust_state != TrustState::Trusted
            || record.revision != revision
            || record.pending_authorisation.is_some()
        {
            return Err(WORKSPACE_UNTRUSTED.into());
        }
        let lease_id = record
            .lease_id
            .clone()
            .ok_or_else(|| WORKSPACE_UNTRUSTED.to_string())?;
        operation(WorkspaceApprovalBinding {
            workspace_id: record.id.clone(),
            revision,
            lease_id,
        })
    }

    pub(crate) fn with_valid_approval_binding<T>(
        &self,
        binding: &WorkspaceApprovalBinding,
        operation: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        let record = inner
            .records
            .get(&binding.workspace_id)
            .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())?;
        if record.lifecycle != WorkspaceLifecycle::OpenUntrusted
            || record.trust_state != TrustState::Trusted
            || record.revision != binding.revision
            || record.lease_id.as_deref() != Some(binding.lease_id.as_str())
            || record.pending_authorisation.is_some()
        {
            return Err(WORKSPACE_UNTRUSTED.into());
        }
        operation()
    }

    pub fn acquire_selected_directory(&self, selected: &Path) -> Result<WorkspaceSummary, String> {
        let metadata =
            fs::symlink_metadata(selected).map_err(|_| WORKSPACE_REJECTED.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() || !selected.is_absolute() {
            return Err(WORKSPACE_REJECTED.into());
        }
        let handle = open_directory_nofollow(selected)?;
        let identity = identity_for_fd(handle.as_raw_fd())?;
        let canonical_path =
            fs::canonicalize(selected).map_err(|_| WORKSPACE_REJECTED.to_string())?;
        let canonical_handle = open_directory_nofollow(&canonical_path)?;
        if identity_for_fd(canonical_handle.as_raw_fd())? != identity {
            return Err(WORKSPACE_REJECTED.into());
        }
        drop(canonical_handle);

        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        if let Some(existing) = inner
            .records
            .values()
            .find(|record| record.capability.identity == identity)
        {
            return Ok(summary(existing));
        }
        if inner.records.len() >= MAX_WORKSPACES {
            return Err(WORKSPACE_CAPACITY.into());
        }
        let id = format!("workspace-{}", Uuid::new_v4().simple());
        let display_label = safe_display_label(&canonical_path);
        let record = WorkspaceRecord {
            id: id.clone(),
            display_label,
            capability: DirectoryCapability {
                handle,
                canonical_path,
                identity,
            },
            lifecycle: WorkspaceLifecycle::Acquired,
            trust_state: TrustState::Untrusted,
            revision: 0,
            lease_id: None,
            pending_authorisation: None,
            metadata: None,
            resource: InternalResourceState::NotLoaded,
            snapshot: None,
        };
        let result = summary(&record);
        inner.records.insert(id, record);
        Ok(result)
    }

    pub fn inspect_metadata(&self, workspace_id: &str) -> Result<WorkspaceSummary, String> {
        let (root_fd, path, identity) = {
            let inner = self
                .inner
                .lock()
                .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
            let record = inner
                .records
                .get(workspace_id)
                .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())?;
            (
                duplicate_fd(record.capability.handle.as_raw_fd())?,
                record.capability.canonical_path.clone(),
                record.capability.identity,
            )
        };
        revalidate_path_identity(&path, identity)?;
        let metadata = inspect_fixed_entries(root_fd.as_raw_fd())?;
        revalidate_path_identity(&path, identity)?;

        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        let record = inner
            .records
            .get_mut(workspace_id)
            .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())?;
        if record.capability.identity != identity
            || !matches!(
                record.lifecycle,
                WorkspaceLifecycle::Acquired | WorkspaceLifecycle::Inspected
            )
        {
            return Err(WORKSPACE_CONFLICT.into());
        }
        record.metadata = Some(metadata);
        record.lifecycle = WorkspaceLifecycle::Inspected;
        Ok(summary(record))
    }

    pub fn open_untrusted(
        &self,
        workspace_id: &str,
        expected_revision: u64,
    ) -> Result<WorkspaceSummary, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        let record = inner
            .records
            .get_mut(workspace_id)
            .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())?;
        if record.revision != expected_revision
            || record.lifecycle != WorkspaceLifecycle::Inspected
            || record.trust_state != TrustState::Untrusted
            || record.resource != InternalResourceState::NotLoaded
        {
            return Err(WORKSPACE_CONFLICT.into());
        }
        record.lifecycle = WorkspaceLifecycle::OpenUntrusted;
        Ok(summary(record))
    }

    pub(crate) fn reserve_authorise(
        &self,
        workspace_id: &str,
        expected_revision: u64,
    ) -> Result<TrustGrant, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        let record = inner
            .records
            .get_mut(workspace_id)
            .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())?;
        if record.lifecycle != WorkspaceLifecycle::OpenUntrusted
            || record.revision != expected_revision
            || record.pending_authorisation.is_some()
            || !matches!(
                record.trust_state,
                TrustState::Untrusted | TrustState::Revoked
            )
            || !matches!(
                record.resource,
                InternalResourceState::NotLoaded | InternalResourceState::RevokedPriorEffects
            )
        {
            return Err(WORKSPACE_CONFLICT.into());
        }
        let revision = expected_revision
            .checked_add(1)
            .filter(|revision| *revision <= MAX_JS_SAFE_INTEGER)
            .ok_or_else(|| WORKSPACE_CONFLICT.to_string())?;
        let operation = Uuid::new_v4();
        let lease_id = format!("trust-{}", Uuid::new_v4().simple());
        record.pending_authorisation = Some(PendingAuthorisation {
            operation,
            expected_revision,
            revision,
            lease_id: lease_id.clone(),
        });
        Ok(TrustGrant {
            workspace_id: workspace_id.to_string(),
            operation_id: format!("operation-{}", operation.simple()),
            expected_revision,
            revision,
            lease_id,
        })
    }

    pub(crate) fn commit_authorise(&self, grant: &TrustGrant) -> Result<WorkspaceSummary, String> {
        let operation = parse_operation_id(&grant.operation_id)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        let record = inner
            .records
            .get_mut(&grant.workspace_id)
            .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())?;
        let expected = PendingAuthorisation {
            operation,
            expected_revision: grant.expected_revision,
            revision: grant.revision,
            lease_id: grant.lease_id.clone(),
        };
        if record.pending_authorisation.as_ref() != Some(&expected)
            || record.revision != grant.expected_revision
            || !matches!(
                record.trust_state,
                TrustState::Untrusted | TrustState::Revoked
            )
        {
            return Err(WORKSPACE_CONFLICT.into());
        }
        record.pending_authorisation = None;
        record.revision = grant.revision;
        record.trust_state = TrustState::Trusted;
        record.resource = InternalResourceState::NotLoaded;
        record.lease_id = Some(grant.lease_id.clone());
        Ok(summary(record))
    }

    pub(crate) fn rollback_authorise(&self, grant: &TrustGrant) {
        let Ok(operation) = parse_operation_id(&grant.operation_id) else {
            return;
        };
        if let Ok(mut inner) = self.inner.lock()
            && let Some(record) = inner.records.get_mut(&grant.workspace_id)
            && record
                .pending_authorisation
                .as_ref()
                .is_some_and(|pending| {
                    pending.operation == operation
                        && pending.expected_revision == grant.expected_revision
                        && pending.revision == grant.revision
                        && pending.lease_id == grant.lease_id
                })
        {
            record.pending_authorisation = None;
        }
    }

    pub fn authorise(
        &self,
        workspace_id: &str,
        expected_revision: u64,
    ) -> Result<(WorkspaceSummary, String), String> {
        let grant = self.reserve_authorise(workspace_id, expected_revision)?;
        let summary = self.commit_authorise(&grant)?;
        Ok((summary, grant.lease_id))
    }

    pub(crate) fn sync_state(&self, workspace_id: &str) -> Result<WorkspaceSync, String> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        let record = inner
            .records
            .get(workspace_id)
            .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())?;
        if record.lifecycle != WorkspaceLifecycle::OpenUntrusted {
            return Err(WORKSPACE_CONFLICT.into());
        }
        Ok(WorkspaceSync {
            workspace_id: record.id.clone(),
            revision: record.revision,
            trust_state: record.trust_state,
            lease_id: record.lease_id.clone(),
        })
    }

    pub(crate) fn existing_load(
        &self,
        workspace_id: &str,
        expected_revision: u64,
        generation: u64,
    ) -> Result<Option<LoadStart>, String> {
        if generation == 0 || generation > MAX_JS_SAFE_INTEGER {
            return Err(WORKSPACE_REJECTED.into());
        }
        let inner = self
            .inner
            .lock()
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        let record = inner
            .records
            .get(workspace_id)
            .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())?;
        if record.revision != expected_revision || record.trust_state != TrustState::Trusted {
            return Err(WORKSPACE_UNTRUSTED.into());
        }
        Ok(match record.resource {
            InternalResourceState::Loaded {
                generation: owner, ..
            } if owner == generation => Some(LoadStart::Cached(summary(record))),
            InternalResourceState::Preparing {
                generation: owner, ..
            }
            | InternalResourceState::Loading {
                generation: owner, ..
            } if owner == generation => Some(LoadStart::InProgress(summary(record))),
            _ => None,
        })
    }

    pub fn begin_load(
        &self,
        workspace_id: &str,
        expected_revision: u64,
        generation: u64,
    ) -> Result<LoadStart, String> {
        if generation == 0 || generation > MAX_JS_SAFE_INTEGER {
            return Err(WORKSPACE_REJECTED.into());
        }
        let operation = Uuid::new_v4();
        let (root_fd, path, identity, lease_id) = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
            let record = inner
                .records
                .get_mut(workspace_id)
                .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())?;
            if record.revision != expected_revision || record.trust_state != TrustState::Trusted {
                return Err(WORKSPACE_UNTRUSTED.into());
            }
            match record.resource {
                InternalResourceState::Loaded {
                    generation: owner, ..
                } if owner == generation => {
                    return Ok(LoadStart::Cached(summary(record)));
                }
                InternalResourceState::Preparing {
                    generation: owner, ..
                }
                | InternalResourceState::Loading {
                    generation: owner, ..
                } if owner == generation => {
                    return Ok(LoadStart::InProgress(summary(record)));
                }
                InternalResourceState::Loaded { .. }
                | InternalResourceState::Preparing { .. }
                | InternalResourceState::Loading { .. } => {
                    return Err(WORKSPACE_CONFLICT.into());
                }
                InternalResourceState::NotLoaded => {}
                InternalResourceState::FailedClosed { .. }
                | InternalResourceState::ExecutionUncertain { .. }
                | InternalResourceState::RevokedPriorEffects => {
                    return Err(WORKSPACE_CONFLICT.into());
                }
            }
            let lease_id = record
                .lease_id
                .clone()
                .ok_or_else(|| WORKSPACE_UNTRUSTED.to_string())?;
            record.resource = InternalResourceState::Preparing {
                generation,
                revision: expected_revision,
                operation,
            };
            (
                duplicate_fd(record.capability.handle.as_raw_fd())?,
                record.capability.canonical_path.clone(),
                record.capability.identity,
                lease_id,
            )
        };

        let snapshot = match revalidate_path_identity(&path, identity)
            .and_then(|_| build_snapshot(root_fd.as_raw_fd()))
            .and_then(|snapshot| {
                revalidate_path_identity(&path, identity)?;
                Ok(snapshot)
            }) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.fail_preparing(workspace_id, expected_revision, generation, operation);
                return Err(error);
            }
        };

        let snapshot_root = snapshot.project_root.clone();
        let agent_root = snapshot.agent_root.clone();
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        let record = inner
            .records
            .get_mut(workspace_id)
            .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())?;
        if record.resource
            != (InternalResourceState::Preparing {
                generation,
                revision: expected_revision,
                operation,
            })
            || record.trust_state != TrustState::Trusted
            || record.revision != expected_revision
        {
            drop(inner);
            snapshot.remove();
            return Err(WORKSPACE_CONFLICT.into());
        }
        record.resource = InternalResourceState::Loading {
            generation,
            revision: expected_revision,
            operation,
        };
        record.snapshot = Some(snapshot);
        Ok(LoadStart::Dispatch(LoadLease {
            workspace_id: workspace_id.to_string(),
            revision: expected_revision,
            generation,
            operation_id: format!("operation-{}", operation.simple()),
            lease_id,
            snapshot_root,
            agent_root,
        }))
    }

    pub fn complete_load(
        &self,
        lease: &LoadLease,
        counts: ResourceCounts,
    ) -> Result<WorkspaceSummary, String> {
        let counts = counts.validate()?;
        let operation = parse_operation_id(&lease.operation_id)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        let record = inner
            .records
            .get_mut(&lease.workspace_id)
            .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())?;
        if record.resource
            != (InternalResourceState::Loading {
                generation: lease.generation,
                revision: lease.revision,
                operation,
            })
            || record.revision != lease.revision
            || record.lease_id.as_deref() != Some(lease.lease_id.as_str())
            || record.trust_state != TrustState::Trusted
        {
            return Err(WORKSPACE_CONFLICT.into());
        }
        record.resource = InternalResourceState::Loaded {
            generation: lease.generation,
            revision: lease.revision,
            counts,
        };
        Ok(summary(record))
    }

    pub fn mark_load_failed(
        &self,
        lease: &LoadLease,
        uncertain: bool,
    ) -> Result<WorkspaceSummary, String> {
        let operation = parse_operation_id(&lease.operation_id)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        let record = inner
            .records
            .get_mut(&lease.workspace_id)
            .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())?;
        if record.resource
            != (InternalResourceState::Loading {
                generation: lease.generation,
                revision: lease.revision,
                operation,
            })
        {
            return Err(WORKSPACE_CONFLICT.into());
        }
        record.resource = if uncertain {
            InternalResourceState::ExecutionUncertain {
                generation: lease.generation,
                revision: lease.revision,
            }
        } else {
            InternalResourceState::FailedClosed {
                generation: lease.generation,
                revision: lease.revision,
            }
        };
        Ok(summary(record))
    }

    pub fn revoke(
        &self,
        workspace_id: &str,
        expected_revision: u64,
    ) -> Result<RevokeOutcome, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        let record = inner
            .records
            .get_mut(workspace_id)
            .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())?;
        if record.revision != expected_revision
            || record.trust_state != TrustState::Trusted
            || record.lifecycle != WorkspaceLifecycle::OpenUntrusted
            || record.pending_authorisation.is_some()
        {
            return Err(WORKSPACE_CONFLICT.into());
        }
        let stop_generation = resource_generation(record.resource);
        let prior_effects = !matches!(record.resource, InternalResourceState::NotLoaded);
        let lease_id = record
            .lease_id
            .clone()
            .ok_or_else(|| WORKSPACE_UNTRUSTED.to_string())?;
        record.revision = record
            .revision
            .checked_add(1)
            .filter(|revision| *revision <= MAX_JS_SAFE_INTEGER)
            .ok_or_else(|| WORKSPACE_CONFLICT.to_string())?;
        record.trust_state = TrustState::Revoked;
        record.lease_id = None;
        record.resource = if prior_effects {
            InternalResourceState::RevokedPriorEffects
        } else {
            InternalResourceState::NotLoaded
        };
        let snapshot = record.snapshot.take();
        Ok(RevokeOutcome {
            summary: summary(record),
            stop_generation,
            lease_id,
            snapshot,
        })
    }

    pub fn invalidate_generation(&self, generation: u64) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        for record in inner.records.values_mut() {
            if resource_generation(record.resource) == Some(generation) {
                record.resource = InternalResourceState::ExecutionUncertain {
                    generation,
                    revision: record.revision,
                };
            }
        }
    }

    pub(crate) fn snapshot_probe_observation(
        &self,
        workspace_id: &str,
    ) -> Result<SnapshotProbeObservation, String> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        let record = inner
            .records
            .get(workspace_id)
            .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())?;
        let root = &record
            .snapshot
            .as_ref()
            .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())?
            .project_root;
        let marker = fs::read(root.join("import-marker.log"))
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        if marker.len() > 64 {
            return Err(WORKSPACE_CONTAINMENT.into());
        }
        Ok(SnapshotProbeObservation {
            marker_bytes: marker.len(),
            marker_lines: marker
                .split(|byte| *byte == b'\n')
                .count()
                .saturating_sub(1),
            exact_marker: marker == b"imported\n",
            skill_canary_absent: path_is_absent(&root.join("skill-marker.log"))?,
            package_canary_absent: path_is_absent(&root.join("package-marker.log"))?,
            settings_canary_absent: path_is_absent(&root.join(".pi/settings.json"))?,
            package_manifest_absent: path_is_absent(&root.join("package.json"))?,
            ancestor_canary_absent: path_is_absent(&root.join("AGENTS.md"))?,
        })
    }

    pub(crate) fn snapshot_is_absent(&self, workspace_id: &str) -> Result<bool, String> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        inner
            .records
            .get(workspace_id)
            .map(|record| record.snapshot.is_none())
            .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())
    }

    #[cfg(test)]
    pub(crate) fn snapshot_marker_lines(&self, workspace_id: &str) -> Result<usize, String> {
        self.snapshot_probe_observation(workspace_id)
            .map(|observation| observation.marker_lines)
    }

    pub fn summary(&self, workspace_id: &str) -> Result<WorkspaceSummary, String> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        inner
            .records
            .get(workspace_id)
            .map(summary)
            .ok_or_else(|| WORKSPACE_UNAVAILABLE.to_string())
    }

    fn fail_preparing(&self, workspace_id: &str, revision: u64, generation: u64, operation: Uuid) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(record) = inner.records.get_mut(workspace_id)
            && record.resource
                == (InternalResourceState::Preparing {
                    generation,
                    revision,
                    operation,
                })
        {
            record.resource = InternalResourceState::FailedClosed {
                generation,
                revision,
            };
        }
    }
}

impl Drop for WorkspaceRegistry {
    fn drop(&mut self) {
        let Ok(inner) = self.inner.get_mut() else {
            return;
        };
        for record in inner.records.values_mut() {
            if let Some(snapshot) = record.snapshot.take() {
                snapshot.remove();
            }
        }
    }
}

pub(crate) struct SnapshotProbeObservation {
    pub(crate) marker_bytes: usize,
    pub(crate) marker_lines: usize,
    pub(crate) exact_marker: bool,
    pub(crate) skill_canary_absent: bool,
    pub(crate) package_canary_absent: bool,
    pub(crate) settings_canary_absent: bool,
    pub(crate) package_manifest_absent: bool,
    pub(crate) ancestor_canary_absent: bool,
}

fn path_is_absent(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(_) => Err(WORKSPACE_UNAVAILABLE.into()),
        Ok(_) => Ok(false),
    }
}

fn summary(record: &WorkspaceRecord) -> WorkspaceSummary {
    let (resource_state, counts) = match record.resource {
        InternalResourceState::NotLoaded => (PublicResourceState::NotLoaded, None),
        InternalResourceState::Preparing { .. } => (PublicResourceState::Preparing, None),
        InternalResourceState::Loading { .. } => (PublicResourceState::Loading, None),
        InternalResourceState::Loaded { counts, .. } => (PublicResourceState::Loaded, Some(counts)),
        InternalResourceState::FailedClosed { .. } => (PublicResourceState::FailedClosed, None),
        InternalResourceState::ExecutionUncertain { .. } => {
            (PublicResourceState::ExecutionUncertain, None)
        }
        InternalResourceState::RevokedPriorEffects => {
            (PublicResourceState::RevokedPriorEffects, None)
        }
    };
    WorkspaceSummary {
        workspace_id: record.id.clone(),
        display_label: record.display_label.clone(),
        lifecycle: record.lifecycle,
        trust_state: record.trust_state,
        revision: record.revision,
        resource_state,
        metadata: record.metadata.clone(),
        counts,
    }
}

fn resource_generation(state: InternalResourceState) -> Option<u64> {
    match state {
        InternalResourceState::Preparing { generation, .. }
        | InternalResourceState::Loading { generation, .. }
        | InternalResourceState::Loaded { generation, .. }
        | InternalResourceState::FailedClosed { generation, .. }
        | InternalResourceState::ExecutionUncertain { generation, .. } => Some(generation),
        InternalResourceState::NotLoaded | InternalResourceState::RevokedPriorEffects => None,
    }
}

fn safe_display_label(path: &Path) -> String {
    let label = path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("Workspace")
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_DISPLAY_SCALARS)
        .collect::<String>();
    if label.is_empty() {
        "Workspace".into()
    } else {
        label
    }
}

fn open_directory_nofollow(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| WORKSPACE_REJECTED.into())
}

fn duplicate_fd(fd: RawFd) -> Result<OwnedFd, String> {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        Err(WORKSPACE_UNAVAILABLE.into())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
    }
}

fn identity_for_fd(fd: RawFd) -> Result<DirectoryIdentity, String> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(WORKSPACE_REJECTED.into());
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(WORKSPACE_REJECTED.into());
    }
    Ok(DirectoryIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
    })
}

fn revalidate_path_identity(path: &Path, expected: DirectoryIdentity) -> Result<(), String> {
    let handle = open_directory_nofollow(path).map_err(|_| WORKSPACE_CONFLICT.to_string())?;
    if identity_for_fd(handle.as_raw_fd())? == expected {
        Ok(())
    } else {
        Err(WORKSPACE_CONFLICT.into())
    }
}

fn c_name(name: &str) -> Result<CString, String> {
    CString::new(name).map_err(|_| WORKSPACE_REJECTED.into())
}

fn kind_at(fd: RawFd, name: &str) -> Result<MetadataKind, String> {
    let name = c_name(name)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            fd,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ENOENT) => Ok(MetadataKind::Absent),
            _ => Err(WORKSPACE_REJECTED.into()),
        };
    }
    let mode = unsafe { stat.assume_init() }.st_mode & libc::S_IFMT;
    Ok(match mode {
        libc::S_IFREG => MetadataKind::File,
        libc::S_IFDIR => MetadataKind::Directory,
        libc::S_IFLNK => MetadataKind::Symlink,
        _ => MetadataKind::Other,
    })
}

fn open_dir_at(fd: RawFd, name: &str) -> Result<Option<OwnedFd>, String> {
    let kind = kind_at(fd, name)?;
    if kind == MetadataKind::Absent {
        return Ok(None);
    }
    if kind != MetadataKind::Directory {
        return Err(WORKSPACE_CONTAINMENT.into());
    }
    let name = c_name(name)?;
    let child = unsafe {
        libc::openat(
            fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if child < 0 {
        Err(WORKSPACE_CONTAINMENT.into())
    } else {
        Ok(Some(unsafe { OwnedFd::from_raw_fd(child) }))
    }
}

fn inspect_fixed_entries(root_fd: RawFd) -> Result<WorkspaceMetadata, String> {
    let pi_directory = kind_at(root_fd, ".pi")?;
    let mut settings = MetadataKind::Absent;
    let mut extensions = MetadataKind::Absent;
    let mut skills = MetadataKind::Absent;
    let mut prompts = MetadataKind::Absent;
    let mut themes = MetadataKind::Absent;
    if pi_directory == MetadataKind::Directory
        && let Some(pi) = open_dir_at(root_fd, ".pi")?
    {
        settings = kind_at(pi.as_raw_fd(), "settings.json")?;
        extensions = kind_at(pi.as_raw_fd(), "extensions")?;
        skills = kind_at(pi.as_raw_fd(), "skills")?;
        prompts = kind_at(pi.as_raw_fd(), "prompts")?;
        themes = kind_at(pi.as_raw_fd(), "themes")?;
    }
    Ok(WorkspaceMetadata {
        pi_directory,
        settings,
        extensions,
        skills,
        prompts,
        themes,
        package_manifest: kind_at(root_fd, "package.json")?,
        agents_context: kind_at(root_fd, "AGENTS.md")?,
        claude_context: kind_at(root_fd, "CLAUDE.md")?,
    })
}

struct SnapshotBudget {
    entries: usize,
    bytes: u64,
}

fn build_snapshot(root_fd: RawFd) -> Result<Snapshot, String> {
    let base = std::env::temp_dir().join(format!("piui-workspace-{}", Uuid::new_v4().simple()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&base)
        .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
    let project_root = base.join("project");
    let agent_root = base.join("agent");
    let result = (|| {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&project_root)
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&agent_root)
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        let pi_destination = project_root.join(".pi");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&pi_destination)
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        let Some(pi_source) = open_dir_at(root_fd, ".pi")? else {
            make_read_only(&pi_destination, true)?;
            return Ok(());
        };
        let mut budget = SnapshotBudget {
            entries: 0,
            bytes: 0,
        };
        for name in FIXED_PROJECT_DIRS {
            if let Some(source) = open_dir_at(pi_source.as_raw_fd(), name)? {
                let destination = pi_destination.join(name);
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&destination)
                    .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
                copy_directory(
                    source.as_raw_fd(),
                    &destination,
                    &mut budget,
                    name == "extensions",
                )?;
                make_read_only(&destination, true)?;
            }
        }
        make_read_only(&pi_destination, true)?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = set_tree_owner_writable(&base);
        let _ = fs::remove_dir_all(&base);
        return Err(error);
    }
    Ok(Snapshot {
        base,
        project_root,
        agent_root,
    })
}

fn directory_names(fd: RawFd) -> Result<Vec<String>, String> {
    let duplicate = unsafe { libc::dup(fd) };
    if duplicate < 0 {
        return Err(WORKSPACE_UNAVAILABLE.into());
    }
    let directory = unsafe { libc::fdopendir(duplicate) };
    if directory.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(WORKSPACE_UNAVAILABLE.into());
    }
    let mut names = Vec::new();
    loop {
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            break;
        }
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let name = std::str::from_utf8(bytes).map_err(|_| WORKSPACE_CONTAINMENT.to_string())?;
        if bytes.len() > MAX_COMPONENT_BYTES || name.chars().any(char::is_control) {
            unsafe { libc::closedir(directory) };
            return Err(WORKSPACE_CONTAINMENT.into());
        }
        names.push(name.to_string());
        if names.len() > MAX_SNAPSHOT_ENTRIES {
            unsafe { libc::closedir(directory) };
            return Err(WORKSPACE_CAPACITY.into());
        }
    }
    unsafe { libc::closedir(directory) };
    names.sort();
    Ok(names)
}

fn copy_directory(
    source_fd: RawFd,
    destination: &Path,
    budget: &mut SnapshotBudget,
    extension_tree: bool,
) -> Result<(), String> {
    for name in directory_names(source_fd)? {
        budget.entries += 1;
        if budget.entries > MAX_SNAPSHOT_ENTRIES {
            return Err(WORKSPACE_CAPACITY.into());
        }
        let c_name = c_name(&name)?;
        let child = unsafe {
            libc::openat(
                source_fd,
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if child < 0 {
            return Err(WORKSPACE_CONTAINMENT.into());
        }
        let owned = unsafe { OwnedFd::from_raw_fd(child) };
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(owned.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(WORKSPACE_CONTAINMENT.into());
        }
        let stat = unsafe { stat.assume_init() };
        let target_name =
            if extension_tree && Path::new(&name).extension() == Some(OsStr::new("mjs")) {
                let stem = Path::new(&name)
                    .file_stem()
                    .and_then(OsStr::to_str)
                    .ok_or_else(|| WORKSPACE_CONTAINMENT.to_string())?;
                format!("{stem}.js")
            } else {
                name.clone()
            };
        let target = destination.join(target_name);
        if target.exists() {
            return Err(WORKSPACE_CONTAINMENT.into());
        }
        match stat.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&target)
                    .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
                copy_directory(owned.as_raw_fd(), &target, budget, extension_tree)?;
                make_read_only(&target, true)?;
            }
            libc::S_IFREG => {
                let size =
                    u64::try_from(stat.st_size).map_err(|_| WORKSPACE_CONTAINMENT.to_string())?;
                budget.bytes = budget
                    .bytes
                    .checked_add(size)
                    .ok_or_else(|| WORKSPACE_CAPACITY.to_string())?;
                if budget.bytes > MAX_SNAPSHOT_BYTES {
                    return Err(WORKSPACE_CAPACITY.into());
                }
                let mut input = File::from(owned);
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&target)
                    .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
                let copied = copy_bounded(&mut input, &mut output, size)?;
                if copied != size {
                    return Err(WORKSPACE_CONTAINMENT.into());
                }
                output
                    .flush()
                    .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
                make_read_only(&target, false)?;
            }
            _ => return Err(WORKSPACE_CONTAINMENT.into()),
        }
    }
    Ok(())
}

fn copy_bounded(input: &mut File, output: &mut File, expected: u64) -> Result<u64, String> {
    let mut remaining = expected;
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = input
            .read(&mut buffer[..requested])
            .map_err(|_| WORKSPACE_CONTAINMENT.to_string())?;
        if read == 0 {
            break;
        }
        output
            .write_all(&buffer[..read])
            .map_err(|_| WORKSPACE_UNAVAILABLE.to_string())?;
        remaining -= read as u64;
        copied += read as u64;
    }
    let mut extra = [0_u8; 1];
    if input
        .read(&mut extra)
        .map_err(|_| WORKSPACE_CONTAINMENT.to_string())?
        != 0
    {
        return Err(WORKSPACE_CONTAINMENT.into());
    }
    Ok(copied)
}

fn make_read_only(path: &Path, directory: bool) -> Result<(), String> {
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if directory { 0o500 } else { 0o400 }),
    )
    .map_err(|_| WORKSPACE_UNAVAILABLE.into())
}

fn set_tree_owner_writable(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        for entry in fs::read_dir(path)? {
            set_tree_owner_writable(&entry?.path())?;
        }
    } else {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn parse_operation_id(value: &str) -> Result<Uuid, String> {
    value
        .strip_prefix("operation-")
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| WORKSPACE_REJECTED.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fixture() -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("piui-workspace-test-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(root.join(".pi/extensions")).unwrap();
        fs::write(
            root.join(".pi/extensions/probe.mjs"),
            "export default () => {};",
        )
        .unwrap();
        fs::write(
            root.join(".pi/settings.json"),
            "{\"defaultProjectTrust\":\"always\"}",
        )
        .unwrap();
        fs::write(root.join("AGENTS.md"), "hostile context").unwrap();
        root
    }

    #[test]
    fn separates_capability_inspection_open_trust_load_and_revoke_without_paths() {
        let root = fixture();
        let registry = WorkspaceRegistry::default();
        let acquired = registry.acquire_selected_directory(&root).unwrap();
        assert_eq!(acquired.lifecycle, WorkspaceLifecycle::Acquired);
        assert_eq!(acquired.revision, 0);
        let encoded = serde_json::to_string(&acquired).unwrap();
        assert!(!encoded.contains(root.to_str().unwrap()));

        let inspected = registry.inspect_metadata(&acquired.workspace_id).unwrap();
        assert_eq!(inspected.lifecycle, WorkspaceLifecycle::Inspected);
        assert_eq!(
            inspected.metadata.as_ref().unwrap().settings,
            MetadataKind::File
        );
        assert!(matches!(
            registry.begin_load(&acquired.workspace_id, 0, 1),
            Err(_)
        ));
        let opened = registry.open_untrusted(&acquired.workspace_id, 0).unwrap();
        assert_eq!(opened.trust_state, TrustState::Untrusted);
        let (trusted, _lease_id) = registry.authorise(&acquired.workspace_id, 0).unwrap();
        assert_eq!(trusted.revision, 1);
        assert_eq!(trusted.resource_state, PublicResourceState::NotLoaded);

        let lease = match registry.begin_load(&acquired.workspace_id, 1, 7).unwrap() {
            LoadStart::Dispatch(lease) => lease,
            _ => panic!("first load was not dispatched"),
        };
        assert!(
            lease
                .snapshot_root
                .join(".pi/extensions/probe.js")
                .is_file()
        );
        assert!(!lease.snapshot_root.join("AGENTS.md").exists());
        assert!(!lease.snapshot_root.join(".pi/settings.json").exists());
        assert!(matches!(
            registry
                .existing_load(&acquired.workspace_id, 1, 7)
                .unwrap(),
            Some(LoadStart::InProgress(_))
        ));
        assert!(
            registry
                .existing_load(&acquired.workspace_id, 1, 8)
                .unwrap()
                .is_none()
        );
        std::thread::scope(|scope| {
            let scheduled: Vec<_> = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        matches!(
                            registry.existing_load(&acquired.workspace_id, 1, 7),
                            Ok(Some(LoadStart::InProgress(_)))
                        )
                    })
                })
                .collect();
            assert!(scheduled.into_iter().all(|result| result.join().unwrap()));
        });
        assert!(matches!(
            registry.begin_load(&acquired.workspace_id, 1, 7).unwrap(),
            LoadStart::InProgress(_)
        ));
        let loaded = registry
            .complete_load(
                &lease,
                ResourceCounts {
                    extensions: 1,
                    skills: 0,
                    prompts: 0,
                    themes: 0,
                    packages: 0,
                    truncated: false,
                },
            )
            .unwrap();
        assert_eq!(loaded.resource_state, PublicResourceState::Loaded);
        assert!(matches!(
            registry
                .existing_load(&acquired.workspace_id, 1, 7)
                .unwrap(),
            Some(LoadStart::Cached(_))
        ));
        std::thread::scope(|scope| {
            let cached: Vec<_> = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        matches!(
                            registry.existing_load(&acquired.workspace_id, 1, 7),
                            Ok(Some(LoadStart::Cached(_)))
                        )
                    })
                })
                .collect();
            assert!(cached.into_iter().all(|result| result.join().unwrap()));
        });
        assert!(matches!(
            registry.begin_load(&acquired.workspace_id, 1, 7).unwrap(),
            LoadStart::Cached(_)
        ));

        let revoked = registry.revoke(&acquired.workspace_id, 1).unwrap();
        assert_eq!(revoked.stop_generation, Some(7));
        let summary = revoked.cleanup();
        assert_eq!(summary.trust_state, TrustState::Revoked);
        assert_eq!(summary.revision, 2);
        assert_eq!(
            summary.resource_state,
            PublicResourceState::RevokedPriorEffects
        );
        assert!(matches!(
            registry.begin_load(&acquired.workspace_id, 2, 8),
            Err(_)
        ));
        let (retrusted, _) = registry.authorise(&acquired.workspace_id, 2).unwrap();
        assert_eq!(retrusted.revision, 3);
        let second_lease = match registry.begin_load(&acquired.workspace_id, 3, 8).unwrap() {
            LoadStart::Dispatch(lease) => lease,
            _ => panic!("re-trusted revision did not receive one new load attempt"),
        };
        registry
            .complete_load(
                &second_lease,
                ResourceCounts {
                    extensions: 1,
                    skills: 0,
                    prompts: 0,
                    themes: 0,
                    packages: 0,
                    truncated: false,
                },
            )
            .unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fixed_metadata_does_not_follow_links_and_snapshot_rejects_escape() {
        let root = fixture();
        let external =
            std::env::temp_dir().join(format!("piui-external-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(&external).unwrap();
        fs::write(external.join("outside.mjs"), "outside").unwrap();
        symlink(
            external.join("outside.mjs"),
            root.join(".pi/extensions/outside.mjs"),
        )
        .unwrap();
        let registry = WorkspaceRegistry::default();
        let acquired = registry.acquire_selected_directory(&root).unwrap();
        registry.inspect_metadata(&acquired.workspace_id).unwrap();
        registry.open_untrusted(&acquired.workspace_id, 0).unwrap();
        registry.authorise(&acquired.workspace_id, 0).unwrap();
        assert!(registry.begin_load(&acquired.workspace_id, 1, 1).is_err());
        assert_eq!(
            registry
                .summary(&acquired.workspace_id)
                .unwrap()
                .resource_state,
            PublicResourceState::FailedClosed
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(external).unwrap();
    }

    #[test]
    fn rejects_root_symlinks_replacement_stale_and_skipped_revisions_and_deduplicates_identity() {
        let root = fixture();
        let alias = root.with_extension("alias");
        symlink(&root, &alias).unwrap();
        let registry = WorkspaceRegistry::default();
        assert!(registry.acquire_selected_directory(&alias).is_err());
        let first = registry.acquire_selected_directory(&root).unwrap();
        let duplicate = registry.acquire_selected_directory(&root).unwrap();
        assert_eq!(first.workspace_id, duplicate.workspace_id);
        registry.inspect_metadata(&first.workspace_id).unwrap();
        assert!(registry.open_untrusted(&first.workspace_id, 1).is_err());
        registry.open_untrusted(&first.workspace_id, 0).unwrap();
        assert!(registry.authorise(&first.workspace_id, 1).is_err());
        registry.authorise(&first.workspace_id, 0).unwrap();

        let moved = root.with_extension("moved");
        fs::rename(&root, &moved).unwrap();
        fs::create_dir_all(&root).unwrap();
        assert!(registry.begin_load(&first.workspace_id, 1, 1).is_err());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(moved).unwrap();
        fs::remove_file(alias).unwrap();
    }

    #[test]
    fn generation_loss_is_uncertain_and_never_replayable() {
        let root = fixture();
        let registry = WorkspaceRegistry::default();
        let acquired = registry.acquire_selected_directory(&root).unwrap();
        registry.inspect_metadata(&acquired.workspace_id).unwrap();
        registry.open_untrusted(&acquired.workspace_id, 0).unwrap();
        registry.authorise(&acquired.workspace_id, 0).unwrap();
        let _lease = match registry.begin_load(&acquired.workspace_id, 1, 9).unwrap() {
            LoadStart::Dispatch(lease) => lease,
            _ => unreachable!(),
        };
        registry.invalidate_generation(9);
        assert_eq!(
            registry
                .summary(&acquired.workspace_id)
                .unwrap()
                .resource_state,
            PublicResourceState::ExecutionUncertain
        );
        assert!(registry.begin_load(&acquired.workspace_id, 1, 10).is_err());
        drop(registry);
        fs::remove_dir_all(root).unwrap();
    }
}
