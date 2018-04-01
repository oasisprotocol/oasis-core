use futures::Future;

use ekiden_rpc_common::api;

use super::super::future::ClientFuture;

/// Contract client backend.
pub trait ContractClientBackend: Send {
    /// Spawn future using an executor.
    fn spawn<F: Future<Item = (), Error = ()> + Send + 'static>(&self, future: F);

    /// Call contract.
    fn call(&self, client_request: api::ClientRequest) -> ClientFuture<api::ClientResponse>;

    /// Call contract with raw data.
    fn call_raw(&self, request: Vec<u8>) -> ClientFuture<Vec<u8>>;

    /// Get credentials.
    ///
    /// This method should return `None` to connect anonymously.
    fn get_credentials(&self) -> Option<super::ContractClientCredentials>;
}
