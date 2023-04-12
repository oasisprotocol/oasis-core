//! Key manager secret provider.
mod interface;
mod mock;
mod provider;

// Re-exports.
pub use self::{
    interface::SecretProvider, mock::MockSecretProvider, provider::KeyManagerSecretProvider,
};
