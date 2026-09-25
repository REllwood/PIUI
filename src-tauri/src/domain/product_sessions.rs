//! Host-side record of which workspace, at which trust revision, each Pi
//! product session belongs to, and which workspaces have a live product
//! runtime in the current sidecar generation.
//!
//! Session-scoped product commands only carry a session ID. Without this
//! binding the host could not refuse to run or mutate a session whose
//! workspace has since been revoked, and a revoke could not reach a runtime
//! that was started without a resource load.

use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};

const MAX_BOUND_SESSIONS: usize = 16_384;
pub(crate) const SESSION_WORKSPACE_UNTRUSTED: &str = "session-workspace-untrusted";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionBinding {
    pub(crate) workspace_id: String,
    pub(crate) workspace_revision: u64,
}

#[derive(Default)]
struct Inner {
    sessions: HashMap<String, SessionBinding>,
    order: VecDeque<String>,
    live_runtimes: HashMap<String, u64>,
}

#[derive(Default)]
pub(crate) struct ProductSessionRegistry {
    inner: Mutex<Inner>,
}

impl ProductSessionRegistry {
    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn bind(&self, session_id: &str, workspace_id: &str, workspace_revision: u64) {
        if !valid_session_id(session_id) {
            return;
        }
        let mut inner = self.inner();
        let binding = SessionBinding {
            workspace_id: workspace_id.to_owned(),
            workspace_revision,
        };
        if inner
            .sessions
            .insert(session_id.to_owned(), binding)
            .is_none()
        {
            inner.order.push_back(session_id.to_owned());
            while inner.order.len() > MAX_BOUND_SESSIONS {
                if let Some(oldest) = inner.order.pop_front() {
                    inner.sessions.remove(&oldest);
                }
            }
        }
    }

    /// Binds every session in a `product.sessions.list` answer that the
    /// sidecar attributes to the workspace the host asked about.
    pub(crate) fn bind_listed(
        &self,
        response: &Value,
        workspace_id: &str,
        workspace_revision: u64,
    ) {
        for session in response
            .get("sessions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if session.get("workspaceId").and_then(Value::as_str) == Some(workspace_id)
                && let Some(id) = session.get("id").and_then(Value::as_str)
            {
                self.bind(id, workspace_id, workspace_revision);
            }
        }
    }

    /// Binds the single session a create, resume or fork answer describes.
    pub(crate) fn bind_answered(&self, response: &Value, binding: &SessionBinding) {
        if let Some(session) = response.get("session")
            && session.get("workspaceId").and_then(Value::as_str)
                == Some(binding.workspace_id.as_str())
            && let Some(id) = session.get("id").and_then(Value::as_str)
        {
            self.bind(id, &binding.workspace_id, binding.workspace_revision);
        }
    }

    pub(crate) fn binding(&self, session_id: &str) -> Option<SessionBinding> {
        self.inner().sessions.get(session_id).cloned()
    }

    pub(crate) fn mark_live(&self, workspace_id: &str, generation: u64) {
        self.inner()
            .live_runtimes
            .insert(workspace_id.to_owned(), generation);
    }

    /// The generation holding a live product runtime for the workspace,
    /// forgotten as it is returned so a revoke acts on it once.
    pub(crate) fn take_live_generation(&self, workspace_id: &str) -> Option<u64> {
        self.inner().live_runtimes.remove(workspace_id)
    }

    /// A stopped generation takes every runtime it held with it.
    pub(crate) fn forget_generation(&self, generation: u64) {
        self.inner()
            .live_runtimes
            .retain(|_, live| *live != generation);
    }
}

fn valid_session_id(value: &str) -> bool {
    value.strip_prefix("session-").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const WORKSPACE: &str = "workspace-0123456789abcdef0123456789abcdef";
    const OTHER: &str = "workspace-fedcba9876543210fedcba9876543210";

    fn session(index: u64) -> String {
        format!("session-{index:032x}")
    }

    #[test]
    fn listed_and_answered_sessions_bind_only_to_the_requested_workspace() {
        let registry = ProductSessionRegistry::default();
        registry.bind_listed(
            &json!({"schemaVersion":1,"sessions":[
                {"id":session(1),"workspaceId":WORKSPACE},
                {"id":session(2),"workspaceId":OTHER},
                {"id":"session-NOT-OPAQUE","workspaceId":WORKSPACE}
            ]}),
            WORKSPACE,
            3,
        );
        assert_eq!(
            registry.binding(&session(1)),
            Some(SessionBinding {
                workspace_id: WORKSPACE.into(),
                workspace_revision: 3,
            })
        );
        assert_eq!(registry.binding(&session(2)), None);
        assert_eq!(registry.binding("session-NOT-OPAQUE"), None);

        let parent = registry.binding(&session(1)).unwrap();
        registry.bind_answered(
            &json!({"schemaVersion":1,"session":{"id":session(4),"workspaceId":WORKSPACE}}),
            &parent,
        );
        registry.bind_answered(
            &json!({"schemaVersion":1,"session":{"id":session(5),"workspaceId":OTHER}}),
            &parent,
        );
        assert_eq!(registry.binding(&session(4)), Some(parent));
        assert_eq!(registry.binding(&session(5)), None);
    }

    #[test]
    fn bindings_are_bounded_and_live_runtimes_are_taken_once() {
        let registry = ProductSessionRegistry::default();
        for index in 0..(MAX_BOUND_SESSIONS as u64 + 1) {
            registry.bind(&session(index), WORKSPACE, 1);
        }
        assert_eq!(registry.binding(&session(0)), None);
        assert!(
            registry
                .binding(&session(MAX_BOUND_SESSIONS as u64))
                .is_some()
        );

        registry.mark_live(WORKSPACE, 4);
        registry.mark_live(OTHER, 4);
        assert_eq!(registry.take_live_generation(WORKSPACE), Some(4));
        assert_eq!(registry.take_live_generation(WORKSPACE), None);
        registry.forget_generation(4);
        assert_eq!(registry.take_live_generation(OTHER), None);
    }
}
