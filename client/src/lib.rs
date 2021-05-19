//! Oasis Core client library.

// Allow until oasis-core#3572.
#![allow(deprecated)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
pub mod grpc;
pub mod enclave_rpc;
#[cfg(not(target_env = "sgx"))]
pub mod node;
#[cfg(not(target_env = "sgx"))]
#[deprecated(note = "see oasis-core#3572")]
pub mod transaction;

// Re-exports.
pub use self::enclave_rpc::RpcClient;
#[cfg(not(target_env = "sgx"))]
pub use self::{node::Node, transaction::TxnClient};
