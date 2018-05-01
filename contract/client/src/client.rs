use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_cbor;

use ekiden_common::bytes::H256;
use ekiden_common::error::Error;
use ekiden_common::futures::{BoxFuture, Future};
use ekiden_common::signature::Signer;
use ekiden_contract_common::call::{ContractOutput, SignedContractCall};
use ekiden_contract_common::protocol;
use ekiden_enclave_common::quote::MrEnclave;
use ekiden_rpc_client::RpcClient;
use ekiden_rpc_client::backend::RpcClientBackend;

/// Contract client.
pub struct ContractClient<Backend: RpcClientBackend + 'static> {
    /// RPC backend.
    backend: Arc<Backend>,
    /// Underlying RPC client.
    rpc: RpcClient<Backend>,
    /// Signer used for signing contract calls.
    signer: Arc<Signer + Send + Sync>,
}

impl<Backend> ContractClient<Backend>
where
    Backend: RpcClientBackend + 'static,
{
    /// Create new client instance.
    pub fn new(
        backend: Arc<Backend>,
        mr_enclave: MrEnclave,
        signer: Arc<Signer + Send + Sync>,
    ) -> Self {
        ContractClient {
            backend: backend.clone(),
            rpc: RpcClient::new(backend, mr_enclave, false),
            signer,
        }
    }

    /// Queue a contract call.
    pub fn call<C, O>(&self, method: &str, arguments: C) -> BoxFuture<O>
    where
        C: Serialize,
        O: DeserializeOwned + Send + 'static,
    {
        let backend = self.backend.clone();
        let call = SignedContractCall::sign(&self.signer, method, arguments);

        Box::new(
            self.rpc
                .call(protocol::METHOD_CONTRACT_SUBMIT, call)
                .and_then(move |call_id: H256| {
                    // Subscribe to contract call so we will know when the call is done.
                    backend.wait_contract_call(call_id).and_then(|output| {
                        // TODO: Submit proof of publication, get decryption.

                        let output: ContractOutput<O> = serde_cbor::from_slice(&output)?;
                        match output {
                            ContractOutput::Success(data) => Ok(data),
                            ContractOutput::Error(error) => Err(Error::new(error)),
                        }
                    })
                }),
        )
    }
}
