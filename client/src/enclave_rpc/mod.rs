//! Enclave RPC client.

#[cfg(not(target_env = "sgx"))]
mod api;
pub mod client;
mod transport;

// Re-exports.
pub use self::client::RpcClient;
