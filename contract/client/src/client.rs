use std::sync::{Arc, Mutex};
use std::time::Duration;

use grpcio;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_cbor;

use ekiden_common::bytes::B256;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::prelude::*;
use ekiden_common::futures::sync::oneshot;
use ekiden_common::hash::EncodedHash;
use ekiden_compute_api;
use ekiden_contract_common::call::{ContractCall, ContractOutput};

/// Contract client.
pub struct ContractClient {
    /// Underlying gRPC client.
    rpc: ekiden_compute_api::ContractClient,
    /// Shared service for waiting for contract calls.
    call_wait_manager: Arc<super::callwait::Manager>,
    /// Optional call timeout.
    timeout: Option<Duration>,
    /// Shutdown signal (receiver).
    shutdown_receiver: future::Shared<oneshot::Receiver<()>>,
    /// Shutdown signal (sender).
    shutdown_sender: Mutex<Option<oneshot::Sender<()>>>,
}

impl ContractClient {
    /// Create new client instance.
    pub fn new(
        rpc: ekiden_compute_api::ContractClient,
        call_wait_manager: Arc<super::callwait::Manager>,
        timeout: Option<Duration>,
    ) -> Self {
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();

        ContractClient {
            rpc,
            call_wait_manager,
            timeout,
            shutdown_receiver: shutdown_receiver.shared(),
            shutdown_sender: Mutex::new(Some(shutdown_sender)),
        }
    }

    /// Queue a raw contract call.
    pub fn call_raw<C>(&self, call: C) -> BoxFuture<Vec<u8>>
    where
        C: Serialize,
    {
        let mut request = ekiden_compute_api::SubmitTxRequest::new();
        match serde_cbor::to_vec(&call) {
            Ok(data) => request.set_data(data),
            Err(_) => return future::err(Error::new("call serialize failed")).into_box(),
        }

        // Subscribe to contract call so we will know when the call is done.
        let call_wait = self.call_wait_manager.create_wait();
        let call_id = request.get_data().get_encoded_hash();

        // Set timeout if configured.
        let mut options = grpcio::CallOption::default();
        if let Some(timeout) = self.timeout {
            options = options.timeout(timeout);
        }

        match self.rpc.submit_tx_async_opt(&request, options) {
            Ok(call) => {
                call.map_err(|error| error.into())
                    .and_then(move |_| {
                        call_wait.wait_for(call_id).and_then(|output| {
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
            Err(error) => future::err(error.into()).into_box(),
        }
    }

    /// Queue a contract call.
    pub fn call<C, O>(&self, method: &str, arguments: C) -> BoxFuture<O>
    where
        C: Serialize,
        O: DeserializeOwned + Send + 'static,
    {
        // TODO: Handle encrypted calls.
        let call = ContractCall {
            id: B256::random(),
            method: method.to_owned(),
            arguments,
        };

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
