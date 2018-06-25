use std::sync::{Arc, Mutex};

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_cbor;

use ekiden_common::bytes::H256;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::sync::oneshot;
use ekiden_common::futures::{future, BoxFuture, Future, FutureExt};
use ekiden_common::signature::Signer;
use ekiden_contract_common::call::{ContractOutput, SignedContractCall};
use ekiden_contract_common::protocol;
use ekiden_enclave_common::quote::MrEnclave;
use ekiden_rpc_client::backend::RpcClientBackend;
use ekiden_rpc_client::RpcClient;

/// Contract client.
pub struct ContractClient<Backend: RpcClientBackend + 'static> {
    /// RPC backend.
    backend: Arc<Backend>,
    /// Underlying RPC client.
    rpc: RpcClient<Backend>,
    /// Signer used for signing contract calls.
    signer: Arc<Signer>,
    /// Shutdown signal (receiver).
    shutdown_receiver: future::Shared<oneshot::Receiver<()>>,
    /// Shutdown signal (sender).
    shutdown_sender: Mutex<Option<oneshot::Sender<()>>>,
}

impl<Backend> ContractClient<Backend>
where
    Backend: RpcClientBackend + 'static,
{
    /// Create new client instance.
    pub fn new(backend: Arc<Backend>, mr_enclave: MrEnclave, signer: Arc<Signer>) -> Self {
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();

        ContractClient {
            backend: backend.clone(),
            rpc: RpcClient::new(backend, mr_enclave, false),
            signer,
            shutdown_receiver: shutdown_receiver.shared(),
            shutdown_sender: Mutex::new(Some(shutdown_sender)),
        }
    }

    /// Queue a raw contract call.
    pub fn call_raw<C>(&self, signed_call: C) -> BoxFuture<Vec<u8>>
    where
        C: Serialize,
    {
        let backend = self.backend.clone();

        self.rpc
            .call(protocol::METHOD_CONTRACT_SUBMIT, signed_call)
            .and_then(move |call_id: H256| {
                // Subscribe to contract call so we will know when the call is done.
                backend.wait_contract_call(call_id).and_then(|output| {
                    // TODO: Submit proof of publication, get decryption.
                    Ok(output)
                })
            })
            .select(
                self.shutdown_receiver
                    .clone()
                    .then(|_result| -> BoxFuture<Vec<u8>> {
                        // However the shutdown receiver future completes, we need to abort as
                        // it has either been dropped or an explicit shutdown signal was sent.
                        future::err(Error::new("contract client closed")).into_box()
                    }),
            )
            .map(|(result, _)| result)
            .map_err(|(error, _)| error)
            .into_box()
    }

    /// Queue a contract call.
    pub fn call<C, O>(&self, method: &str, arguments: C) -> BoxFuture<O>
    where
        C: Serialize,
        O: DeserializeOwned + Send + 'static,
    {
        let call = SignedContractCall::sign(&self.signer, method, arguments);

        self.call_raw(call)
            .and_then(|output| parse_call_output(output))
            .into_box()
    }

    /// Cancel all pending contract calls.
    pub fn shutdown(&self) {
        let shutdown_sender = self.shutdown_sender
            .lock()
            .unwrap()
            .take()
            .expect("shutdown already called");
        drop(shutdown_sender.send(()));
    }
}

/// Parse contract call output.
pub fn parse_call_output<O>(output: Vec<u8>) -> Result<O>
where
    O: DeserializeOwned,
{
    let output: ContractOutput<O> = serde_cbor::from_slice(&output)?;
    match output {
        ContractOutput::Success(data) => Ok(data),
        ContractOutput::Error(error) => Err(Error::new(error)),
    }
}
