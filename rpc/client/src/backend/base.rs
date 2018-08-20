#[cfg(not(target_env = "sgx"))]
use std::sync::Arc;

#[cfg(not(target_env = "sgx"))]
use ekiden_common::environment::Environment;
use ekiden_common::futures::prelude::*;
use ekiden_rpc_common::api;

/// RPC client backend.
pub trait RpcClientBackend: Send + Sync {
    /// Return backend execution environment.
    #[cfg(not(target_env = "sgx"))]
    fn get_environment(&self) -> Arc<Environment>;

    /// Call enclave.
    fn call(&self, client_request: api::ClientRequest) -> BoxFuture<api::ClientResponse>;

    /// Call enclave with raw data.
    fn call_raw(&self, request: Vec<u8>) -> BoxFuture<Vec<u8>>;

    /// Get credentials.
    ///
    /// This method should return `None` to connect anonymously.
    fn get_credentials(&self) -> Option<super::RpcClientCredentials>;
}
