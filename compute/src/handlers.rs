//! Handlers for the endpoints available to be called from inside the enclave,
//! which are registered using RpcRouter.

use futures::Future;
use grpcio;

use std::sync::Arc;

use ekiden_core::error::{Error, Result};
use ekiden_core::rpc::client::ClientEndpoint;
use ekiden_untrusted::rpc::router::Handler;

use ekiden_rpc_client::backend::{ContractClientBackend, Web3ContractClientBackend};

/// Generic contract endpoint.
///
/// This endpoint can be used to forward requests to an arbitrary destination
/// contract, defined by the `hostname` and `port` of the compute node that is
/// running the contract.
pub struct ContractForwarder {
    /// Client endpoint identifier.
    endpoint: ClientEndpoint,
    /// Client backend.
    client: Web3ContractClientBackend,
}

impl ContractForwarder {
    pub fn new(
        endpoint: ClientEndpoint,
        environment: Arc<grpcio::Environment>,
        host: String,
        port: u16,
    ) -> Self {
        ContractForwarder {
            endpoint: endpoint,
            client: Web3ContractClientBackend::new(environment, &host, port).unwrap(),
        }
    }
}

impl Handler for ContractForwarder {
    /// Return a list of endpoints that the handler can handle.
    fn get_endpoints(&self) -> Vec<ClientEndpoint> {
        vec![self.endpoint.clone()]
    }

    /// Handle a request and return a response.
    fn handle(&self, _endpoint: &ClientEndpoint, request: Vec<u8>) -> Result<Vec<u8>> {
        // Currently all OCALLs are blocking so this handler is blocking as well.
        match self.client.call_raw(request).wait() {
            Ok(response) => Ok(response),
            _ => Err(Error::new("RPC call failed")),
        }
    }
}
