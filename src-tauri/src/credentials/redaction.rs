use std::fmt::{Debug, Display, Formatter};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CredentialError {
    code: &'static str,
}

impl CredentialError {
    pub const fn invalid_reference() -> Self {
        Self {
            code: "invalid-credential-reference",
        }
    }

    pub const fn invalid_input() -> Self {
        Self {
            code: "invalid-credential-input",
        }
    }

    pub const fn unavailable() -> Self {
        Self {
            code: "keychain-unavailable",
        }
    }

    pub const fn not_found() -> Self {
        Self {
            code: "credential-not-found",
        }
    }

    pub const fn code(self) -> &'static str {
        self.code
    }
}

impl Display for CredentialError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code)
    }
}

impl Debug for CredentialError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialError")
            .field("code", &self.code)
            .finish()
    }
}

impl std::error::Error for CredentialError {}
