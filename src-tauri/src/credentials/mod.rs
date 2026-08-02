mod keychain;
pub mod proxy;
mod redaction;

#[cfg(feature = "a23-credential-test")]
pub(crate) use keychain::IndexMaterial;
pub use keychain::{CredentialMetadata, KeychainRepository, SecretMaterial};
pub use proxy::{CredentialDispatchError, CredentialProxy};
pub use redaction::CredentialError;
