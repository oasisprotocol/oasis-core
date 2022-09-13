//! Key manager client.
mod interface;
mod mock;
mod remote;

// Re-exports.
pub use self::{interface::KeyManagerClient, mock::MockClient, remote::RemoteClient};
