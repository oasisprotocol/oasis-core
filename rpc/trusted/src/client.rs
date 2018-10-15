//! OCALL-based RPC client backend used inside enclaves.
use ekiden_common::error::Result;
use ekiden_common::futures::prelude::*;
use ekiden_enclave_trusted::identity;
use ekiden_rpc_client::backend::{RpcClientBackend, RpcClientCredentials};
use ekiden_rpc_common::api;
use ekiden_rpc_common::client::ClientEndpoint;

use super::untrusted;

/// Enclave client that can be used inside enclaves.
///
/// It relays enclave calls via an OCALL to the untrusted world which may then
/// dispatch the calls to other compute nodes.
pub struct OcallRpcClientBackend {
    /// Endpoint that the client is connecting to.
    endpoint: ClientEndpoint,
}

impl OcallRpcClientBackend {
    /// Construct new OCALL enclave client backend.
    pub fn new(endpoint: ClientEndpoint) -> Result<Self> {
        Ok(OcallRpcClientBackend { endpoint: endpoint })
    }
}

impl RpcClientBackend for OcallRpcClientBackend {
    fn call(&self, client_request: api::ClientRequest) -> BoxFuture<api::ClientResponse> {
        let endpoint = self.endpoint.clone();

        Box::new(future::lazy(move || {
            Ok(untrusted::untrusted_call_endpoint(
                &endpoint,
                client_request,
            )?)
        }))
    }

    fn call_raw(&self, client_request: Vec<u8>) -> BoxFuture<Vec<u8>> {
        let endpoint = self.endpoint.clone();

        Box::new(future::lazy(move || {
            Ok(untrusted::untrusted_call_endpoint_raw(
                &endpoint,
                client_request,
            )?)
        }))
    }

    fn get_credentials(&self) -> Option<RpcClientCredentials> {
        Some(RpcClientCredentials {
            long_term_private_key: identity::get_identity().rpc_key_e_priv,
            identity_proof: identity::get_proof(),
        })
    }
}
