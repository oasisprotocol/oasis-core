use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use grpcio::{self, RpcStatus, RpcStatusCode};
use rustracing::tag;
use rustracing_jaeger::span::SpanHandle;
use serde::{de::DeserializeOwned, Serialize};
use serde_cbor;

use ekiden_common::{
    bytes::B256,
    environment::Environment,
    error::{Error, Result},
    futures::{prelude::*, retry_until_ok, sync::oneshot},
    hash::EncodedHash,
};
use ekiden_runtime_common::call::{RuntimeCall, RuntimeOutput};
use ekiden_tracing::inject_to_options;

mod api {
    pub use crate::generated::{runtime::*, runtime_grpc::*};
}

/// Runtime client.
pub struct RuntimeClient {
    /// Underlying gRPC client.
    rpc: Arc<api::RuntimeClient>,
    /// Shared service for waiting for runtime calls.
    call_wait_manager: Arc<super::callwait::Manager>,
    /// Optional call timeout.
    timeout: Option<Duration>,
    /// Shutdown signal (receiver).
    shutdown_receiver: future::Shared<oneshot::Receiver<&'static str>>,
    /// Shutdown signal (sender).
    shutdown_sender: Mutex<Option<oneshot::Sender<&'static str>>>,
    /// Environment.
    environment: Arc<Environment>,
    /// Runtime identifier.
    runtime_id: B256,
}

impl RuntimeClient {
    pub const SHUTDOWN_REASON_TRANSITION: &'static str = "transitioning to new leader";

    /// Create new client instance.
    pub fn new(
        environment: Arc<Environment>,
        rpc: api::RuntimeClient,
        call_wait_manager: Arc<super::callwait::Manager>,
        timeout: Option<Duration>,
        runtime_id: B256,
    ) -> Self {
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();

        RuntimeClient {
            rpc: Arc::new(rpc),
            call_wait_manager,
            timeout,
            shutdown_receiver: shutdown_receiver.shared(),
            shutdown_sender: Mutex::new(Some(shutdown_sender)),
            environment,
            runtime_id,
        }
    }

    /// Queue a raw runtime call.
    pub fn call_raw<C>(&self, call: C, sh: SpanHandle) -> BoxFuture<Vec<u8>>
    where
        C: Serialize,
    {
        let mut request = api::SubmitTxRequest::new();
        request.set_runtime_id(self.runtime_id.to_vec());
        match serde_cbor::to_vec(&call) {
            Ok(data) => request.set_data(data),
            Err(_) => return future::err(Error::new("call serialize failed")).into_box(),
        }

        // Subscribe to runtime call so we will know when the call is done.
        let call_wait = self.call_wait_manager.create_wait();
        let call_id = request.get_data().get_encoded_hash();

        let rpc_timeout = self.timeout.clone();
        let rpc = self.rpc.clone();
        let rpc_call = retry_until_ok(
            "RuntimeClient submit_tx",
            move || {
                // Set timeout if configured.
                let mut options = grpcio::CallOption::default();
                if let Some(timeout) = rpc_timeout {
                    options = options.timeout(timeout);
                }

                let span = sh.child("submit_tx_async_opt", |opts| {
                    opts.tag(tag::StdTag::span_kind("client")).start()
                });
                options = inject_to_options(options, span.context());

                match rpc.submit_tx_async_opt(&request.clone(), options) {
                    Ok(call) => call
                        .then(|result| {
                            drop(span);
                            result
                        })
                        .into_box(),
                    Err(error) => future::err(error.into()).into_box(),
                }
            },
            |error| {
                match error {
                    // If the compute node returns that it is Unavailable, this may be because it
                    // does not yet consider itself leader. In this case, we need to retry.
                    grpcio::Error::RpcFailure(RpcStatus {
                        status: RpcStatusCode::Unavailable,
                        ..
                    }) => false,
                    // Consider all other errors permanent.
                    _ => true,
                }
            },
        )
        .map_err(|error| error.into())
        .and_then(move |_| {
            call_wait.wait_for(call_id).and_then(|output| {
                // TODO: Submit proof of publication, get decryption.
                Ok(output)
            })
        })
        .select(
            self.shutdown_receiver
                .clone()
                .then(|result| -> BoxFuture<Vec<u8>> {
                    let reason = match result {
                        Ok(reason_shared) => *reason_shared,
                        Err(_canceled) => "client is being dropped",
                    };
                    // However the shutdown receiver future completes, we need to abort as
                    // it has either been dropped or an explicit shutdown signal was sent.
                    future::err(Error::new(reason)).into_box()
                }),
        )
        .map(|(result, _)| result)
        .map_err(|(error, _)| error)
        .into_box();

        // Spawn background task which handles the call.
        let (response_tx, response_rx) = oneshot::channel();
        self.environment
            .spawn(rpc_call.then(|result| response_tx.send(result)).discard());

        response_rx
            .map_err(|error| error.into())
            .and_then(|result| result)
            .into_box()
    }

    /// Queue a runtime call.
    pub fn call<C, O>(&self, method: &str, arguments: C, sh: SpanHandle) -> BoxFuture<O>
    where
        C: Serialize,
        O: DeserializeOwned + Send + 'static,
    {
        let call = RuntimeCall {
            method: method.to_owned(),
            arguments,
        };

        self.call_raw(call, sh)
            .and_then(|output| parse_call_output(output))
            .into_box()
    }

    /// Cancel all pending runtime calls.
    pub fn shutdown(&self, reason: &'static str) {
        let shutdown_sender = self
            .shutdown_sender
            .lock()
            .unwrap()
            .take()
            .expect("shutdown already called");
        drop(shutdown_sender.send(reason));
    }
}

/// Parse runtime call output.
pub fn parse_call_output<O>(output: Vec<u8>) -> Result<O>
where
    O: DeserializeOwned,
{
    let output: RuntimeOutput<O> = serde_cbor::from_slice(&output)?;
    match output {
        RuntimeOutput::Success(data) => Ok(data),
        RuntimeOutput::Error(error) => Err(Error::new(error)),
    }
}
