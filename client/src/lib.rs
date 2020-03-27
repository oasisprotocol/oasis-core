//! Oasis Core client library.

#[cfg(not(target_env = "sgx"))]
#[macro_use]
pub mod grpc;
#[cfg(not(target_env = "sgx"))]
pub mod node;
// TODO: Rename "rpc" module to "enclave_rpc" or similar.
pub mod rpc;
#[cfg(not(target_env = "sgx"))]
pub mod transaction;

/// Boxed future type.
pub type BoxFuture<T> = Box<dyn futures::Future<Item = T, Error = failure::Error> + Send>;

// Re-exports.
pub use self::rpc::RpcClient;
#[cfg(not(target_env = "sgx"))]
pub use self::{node::Node, transaction::TxnClient};
