mod dispatcher;
mod handshake;
mod login_path;
mod process;
mod public_router;
mod redact;
mod restart;
mod router;
mod stdio;

pub use handshake::{
    HandshakeExpectation, NODE_VERSION, PI_VERSION, PROTOCOL_VERSION, validate_handshake,
};
pub use process::{SidecarStatus, SidecarSupervisor, SupervisorPaths};
pub(crate) use process::{TEST_METHODS_ENABLED, pi_agent_dir_within};
pub(crate) use public_router::{PublicRoute, RECEIVE_TIMED_OUT};
pub use redact::StderrRedactor;
pub use restart::{RESTART_HALTED_REPORT, RestartController};
pub use router::{SequenceOutcome, SequenceRouter};
pub(crate) use stdio::report_sidecar_failure;
