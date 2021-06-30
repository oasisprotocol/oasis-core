//! Oasis Core client library.

// Allow until oasis-core#3572.
#![allow(deprecated)]

pub mod enclave_rpc;

// Re-exports.
pub use self::enclave_rpc::RpcClient;
