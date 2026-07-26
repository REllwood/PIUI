mod envelope;
pub(crate) mod workspace;

pub(crate) const AUTHENTICATED_INTERNAL_SNAPSHOT_CORRELATION: &str =
    "piui-authenticated-internal-snapshot";

pub use envelope::{
    Envelope, EnvelopeError, ErrorCategory, MAX_LINE_BYTES, ProtocolDecoder, ProtocolError,
    ProtocolKind, validate_envelope,
};
