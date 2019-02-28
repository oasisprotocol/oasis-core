use std::{error::Error as StdError, time::Duration};

use grpcio::Channel;
use rustracing::tag;
use rustracing_jaeger::span::SpanHandle;
use serde::{de::DeserializeOwned, Serialize};
use serde_cbor;

use ekiden_common::{
    bytes::B256,
    error::{Error, Result},
    futures::prelude::*,
};
use ekiden_runtime_common::call::{RuntimeCall, RuntimeOutput};
use ekiden_tracing::inject_to_options;

mod api {
    pub use crate::generated::{client::*, client_grpc::*};
}

/// Interface for the node's client interface.
pub struct RuntimeClient {
    /// The underlying RPC interface.
    client: api::RuntimeClient,
    /// Runtime identifier.
    runtime_id: B256,
    /// RPC timeout
    timeout: Option<Duration>,
}

impl RuntimeClient {
    /// Create a new client interface.
    pub fn new(channel: Channel, runtime_id: B256, timeout: Option<Duration>) -> Self {
        RuntimeClient {
            client: api::RuntimeClient::new(channel),
            runtime_id: runtime_id.clone(),
            timeout: timeout,
        }
    }

    /// Call a remote method.
    pub fn call<C, O>(&self, method: &'static str, arguments: C) -> BoxFuture<O>
    where
        C: Serialize,
        O: DeserializeOwned + Send + 'static,
    {
        let span = ekiden_tracing::get_tracer()
            .span("client_call")
            .tag(tag::Tag::new("ekiden.runtime_method", method))
            .tag(tag::StdTag::span_kind("client"))
            .start();

        let call = RuntimeCall {
            method: method.to_owned(),
            arguments,
        };

        self.submit_tx_raw(&call, span.handle())
            .and_then(|out| {
                drop(span);
                parse_call_output(out)
            })
            .into_box()
    }

    /// Dispatch a raw call to the node.
    pub fn submit_tx_raw<C>(&self, call: C, sh: SpanHandle) -> BoxFuture<Vec<u8>>
    where
        C: Serialize,
    {
        let mut options = grpcio::CallOption::default();
        if let Some(timeout) = self.timeout {
            options = options.timeout(timeout);
        }

        let mut request = api::SubmitTxRequest::new();
        request.set_runtime_id(self.runtime_id.to_vec());
        match serde_cbor::to_vec(&call) {
            Ok(data) => request.set_data(data),
            Err(_) => return future::err(Error::new("call serialize failed")).into_box(),
        }

        let span = sh.child("submit_tx_async_opt", |opts| {
            opts.tag(tag::StdTag::span_kind("client")).start()
        });
        options = inject_to_options(options, span.context());

        match self.client.submit_tx_async_opt(&request, options) {
            Ok(resp) => Box::new(
                resp.map(|r| {
                    drop(span);
                    r.result
                })
                .map_err(|err| Error::new(err.description())),
            ),
            Err(e) => Box::new(future::err(Error::new(e.description()))),
        }
    }

    /// Wait for the node to finish syncing.
    pub fn wait_sync(&self) -> BoxFuture<()> {
        let span = ekiden_tracing::get_tracer()
            .span("client_wait_sync")
            .tag(tag::StdTag::span_kind("client"))
            .start();

        let mut options = grpcio::CallOption::default();
        if let Some(timeout) = self.timeout {
            options = options.timeout(timeout);
        }

        let request = api::WaitSyncRequest::new();
        options = inject_to_options(options, span.context());

        let result = match self.client.wait_sync_async_opt(&request, options) {
            Ok(_) => Box::new(future::ok(())),
            Err(e) => Box::new(future::err(Error::new(e.description()))),
        };
        drop(span);
        result
    }

    /// Check if the node is finished syncing.
    pub fn is_synced(&self) -> BoxFuture<bool> {
        let span = ekiden_tracing::get_tracer()
            .span("client_is_synced")
            .tag(tag::StdTag::span_kind("client"))
            .start();

        let mut options = grpcio::CallOption::default();
        if let Some(timeout) = self.timeout {
            options = options.timeout(timeout);
        }

        let request = api::IsSyncedRequest::new();
        options = inject_to_options(options, span.context());

        let result = match self.client.is_synced_async_opt(&request, options) {
            Ok(resp) => resp
                .map(|r| r.synced)
                .map_err(|e| Error::new(e.description()))
                .into_box(),
            Err(e) => future::err(Error::new(e.description())).into_box(),
        };
        drop(span);
        result
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
