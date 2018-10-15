//! Handlers for the endpoints available to be called from inside the enclave,
//! which are registered using RpcRouter.
use std::sync::Arc;
use std::time::Duration;

use ekiden_core::environment::Environment;
use ekiden_core::error::{Error, Result};
use ekiden_core::futures::Future;
use ekiden_core::rpc::client::ClientEndpoint;
use ekiden_core::x509::Certificate;
use ekiden_untrusted::rpc::router::Handler;

use ekiden_rpc_client::backend::{NetworkRpcClientBackend, RpcClientBackend};

/// Generic enclave endpoint.
///
/// This endpoint can be used to forward requests to an arbitrary destination
/// enclave, defined by the `hostname` and `port` of the node that is running
/// the enclave.
pub struct EnclaveForwarder {
    /// Client endpoint identifier.
    endpoint: ClientEndpoint,
    /// Client backend.
    client: NetworkRpcClientBackend,
}

impl EnclaveForwarder {
    pub fn new(
        endpoint: ClientEndpoint,
        environment: Arc<Environment>,
        timeout: Option<Duration>,
        host: String,
        port: u16,
        certificate: Certificate,
    ) -> Self {
        EnclaveForwarder {
            endpoint: endpoint,
            client: NetworkRpcClientBackend::new(environment, timeout, &host, port, certificate)
                .unwrap(),
        }
    }
}

impl Handler for EnclaveForwarder {
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
