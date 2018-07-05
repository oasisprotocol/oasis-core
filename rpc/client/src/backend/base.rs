use futures::Future;

use ekiden_common::bytes::H256;
use ekiden_rpc_common::api;

use super::super::future::ClientFuture;

/// Contract client backend.
pub trait RpcClientBackend: Send + Sync {
    /// Spawn future using an executor.
    fn spawn<F: Future<Item = (), Error = ()> + Send + 'static>(&self, future: F);

    /// Call contract.
    fn call(&self, client_request: api::ClientRequest) -> ClientFuture<api::ClientResponse>;

    /// Call contract with raw data.
    fn call_raw(&self, request: Vec<u8>) -> ClientFuture<Vec<u8>>;

    /// Wait for given contract call outputs to become available.
    /// Deprecated: We're moving this functionality into the client.
    fn wait_contract_call(&self, call_id: H256) -> ClientFuture<Vec<u8>>;

    /// Get credentials.
    ///
    /// This method should return `None` to connect anonymously.
    fn get_credentials(&self) -> Option<super::RpcClientCredentials>;
}
