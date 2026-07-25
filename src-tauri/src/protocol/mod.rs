mod envelope;

pub use envelope::{
    Envelope, MAX_LINE_BYTES, ProtocolDecoder, ProtocolError, ProtocolKind, validate_envelope,
};
