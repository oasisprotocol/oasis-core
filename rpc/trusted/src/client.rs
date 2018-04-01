//! OCALL-based RPC client backend used inside enclaves.

use futures::future::{self, Future};

use ekiden_common::error::Result;
use ekiden_enclave_trusted::identity;
use ekiden_rpc_client::ClientFuture;
use ekiden_rpc_client::backend::{ContractClientBackend, ContractClientCredentials};
use ekiden_rpc_common::api;
use ekiden_rpc_common::client::ClientEndpoint;

use super::untrusted;

/// Contract client that can be used inside enclaves.
///
/// It relays contract calls via an OCALL to the untrusted world which may then
/// dispatch the calls to other compute nodes.
pub struct OcallContractClientBackend {
    /// Endpoint that the client is connecting to.
    endpoint: ClientEndpoint,
}

impl OcallContractClientBackend {
    /// Construct new OCALL contract client backend.
    pub fn new(endpoint: ClientEndpoint) -> Result<Self> {
        Ok(OcallContractClientBackend { endpoint: endpoint })
    }
}

impl ContractClientBackend for OcallContractClientBackend {
    /// Spawn future using an executor.
    fn spawn<F: Future + Send + 'static>(&self, _future: F) {
        panic!("Attempted to spawn future using OCALL backend");
    }

    /// Call contract.
    fn call(&self, client_request: api::ClientRequest) -> ClientFuture<api::ClientResponse> {
        let endpoint = self.endpoint.clone();

        Box::new(future::lazy(move || {
            Ok(untrusted::untrusted_call_endpoint(
                &endpoint,
                client_request,
            )?)
        }))
    }

    /// Call contract with raw data.
    fn call_raw(&self, client_request: Vec<u8>) -> ClientFuture<Vec<u8>> {
        let endpoint = self.endpoint.clone();

        Box::new(future::lazy(move || {
            Ok(untrusted::untrusted_call_endpoint_raw(
                &endpoint,
                client_request,
            )?)
        }))
    }

    /// Get credentials.
    fn get_credentials(&self) -> Option<ContractClientCredentials> {
        Some(ContractClientCredentials {
            long_term_private_key: identity::get_identity().rpc_key_e_priv,
            identity_proof: identity::get_proof(),
        })
    }
}
