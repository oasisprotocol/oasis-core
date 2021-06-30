//! Enclave RPC client.

pub mod client;
mod transport;

// Re-exports.
pub use self::client::RpcClient;
