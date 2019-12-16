//! Transaction client.
use std::time::Duration;

use failure::{Error, Fallible};
use futures::{future, prelude::*};
use grpcio::{Channel, Error::RpcFailure, RpcStatus, RpcStatusCode};
use rustracing::{sampler::AllSampler, tag};
use rustracing_jaeger::{span::Span, Tracer};
use serde::{de::DeserializeOwned, Serialize};

use oasis_core_runtime::{
    common::{cbor, crypto::hash::Hash, runtime::RuntimeId},
    transaction::types::{TxnBatch, TxnCall, TxnOutput},
};

use super::{
    api,
    block_watcher::BlockWatcher,
    snapshot::{BlockSnapshot, TransactionSnapshot},
};
use crate::BoxFuture;

/// Transaction client error.
#[derive(Debug, Fail)]
pub enum TxnClientError {
    #[fail(display = "node call failed: {}", 0)]
    CallFailed(String),
    #[fail(display = "block watcher closed")]
    WatcherClosed,
    #[fail(display = "transaction failed: {}", 0)]
    TxnFailed(String),
}

/// Interface for the node's client interface.
pub struct TxnClient {
    /// The underlying client gRPC interface.
    client: api::client::RuntimeClient,
    /// The underlying node controller gRPC interface.
    node_controller: api::control::NodeControllerClient,
    /// The underlying storage gRPC interface.
    storage_client: api::storage::StorageClient,
    /// Runtime identifier.
    runtime_id: RuntimeId,
    /// RPC timeout.
    timeout: Option<Duration>,
    /// Block watcher for `get_latest_block` call.
    block_watcher: BlockWatcher,
}

impl TxnClient {
    /// Create a new transaction client.
    pub fn new(channel: Channel, runtime_id: RuntimeId, timeout: Option<Duration>) -> Self {
        Self {
            client: api::client::RuntimeClient::new(channel.clone()),
            node_controller: api::control::NodeControllerClient::new(channel.clone()),
            storage_client: api::storage::StorageClient::new(channel),
            runtime_id: runtime_id.clone(),
            timeout: timeout,
            block_watcher: BlockWatcher::new(),
        }
    }

    /// Call a remote method.
    pub fn call<C, O>(&self, method: &'static str, args: C) -> BoxFuture<O>
    where
        C: Serialize,
        O: DeserializeOwned + Send + 'static,
    {
        let call = TxnCall {
            method: method.to_owned(),
            args: cbor::to_value(args),
        };

        Box::new(
            self.submit_tx_raw(&call)
                .and_then(|out| parse_call_output(out)),
        )
    }

    /// Dispatch a raw call to the node.
    pub fn submit_tx_raw<C>(&self, call: C) -> BoxFuture<Vec<u8>>
    where
        C: Serialize,
    {
        let (span, options) = self.prepare_options("TxnClient::submit_tx_raw");
        let request = api::client::SubmitTxRequest {
            runtime_id: self.runtime_id,
            data: cbor::to_vec(&call),
        };

        match self.client.submit_tx(&request, options) {
            Ok(resp) => Box::new(
                resp.map(|r| {
                    drop(span);
                    r.into()
                })
                .map_err(|error| TxnClientError::CallFailed(format!("{}", error)).into()),
            ),
            Err(error) => Box::new(future::err(
                TxnClientError::CallFailed(format!("{}", error)).into(),
            )),
        }
    }

    /// Wait for the node to finish syncing.
    pub fn wait_sync(&self) -> BoxFuture<()> {
        let (span, options) = self.prepare_options("TxnClient::wait_sync");

        let result: BoxFuture<()> = match self.node_controller.wait_sync(options) {
            Ok(resp) => Box::new(
                resp.map_err(|error| TxnClientError::CallFailed(format!("{}", error)).into()),
            ),
            Err(error) => Box::new(future::err(
                TxnClientError::CallFailed(format!("{}", error)).into(),
            )),
        };
        drop(span);
        result
    }

    /// Check if the node is finished syncing.
    pub fn is_synced(&self) -> BoxFuture<bool> {
        let (span, options) = self.prepare_options("TxnClient::is_synced");

        let result: BoxFuture<bool> = match self.node_controller.is_synced(options) {
            Ok(resp) => Box::new(
                resp.map_err(|error| TxnClientError::CallFailed(format!("{}", error)).into()),
            ),
            Err(error) => Box::new(future::err(
                TxnClientError::CallFailed(format!("{}", error)).into(),
            )),
        };
        drop(span);
        result
    }

    /// Retrieve the latest block snapshot.
    pub fn get_latest_block(&self) -> BoxFuture<BlockSnapshot> {
        let block_watcher = self.block_watcher.clone();
        let runtime_id = self.runtime_id.clone();
        let client = self.client.clone();
        let storage_client = self.storage_client.clone();

        Box::new(future::lazy(move || -> BoxFuture<BlockSnapshot> {
            // Spawn block watcher if not running yet.
            if block_watcher.start_spawn() {
                let block_watcher = block_watcher.clone();
                match client.watch_blocks(runtime_id) {
                    Ok(blocks) => {
                        block_watcher.spawn(
                            blocks
                                .map_err(|err| -> Error { err.into() })
                                .and_then(move |rsp| {
                                    Ok(BlockSnapshot::new(storage_client.clone(), rsp.block))
                                }),
                        );
                    }
                    Err(error) => {
                        // Failed to start watching blocks, retry on next attempt.
                        block_watcher.cancel_spawn();
                        return Box::new(future::err(
                            TxnClientError::CallFailed(format!("{}", error)).into(),
                        ));
                    }
                }
            }

            Box::new(block_watcher.get_latest_block().map_err(|err| err.into()))
        }))
    }

    /// Retrieve block snapshot at specified round.
    pub fn get_block(&self, round: u64) -> BoxFuture<Option<BlockSnapshot>> {
        let (span, options) = self.prepare_options("TxnClient::get_block");
        let request = api::client::GetBlockRequest {
            runtime_id: self.runtime_id,
            round: round,
        };

        let result: BoxFuture<Option<BlockSnapshot>> =
            match self.client.get_block(&request, options) {
                Ok(resp) => {
                    let storage_client = self.storage_client.clone();
                    Box::new(resp.then(move |result| match result {
                        Err(RpcFailure(RpcStatus {
                            status: RpcStatusCode::NotFound,
                            ..
                        })) => Ok(None),
                        Err(error) => Err(TxnClientError::CallFailed(format!("{}", error)).into()),
                        Ok(rsp) => Ok(Some(BlockSnapshot::new(storage_client, rsp))),
                    }))
                }
                Err(error) => Box::new(future::err(
                    TxnClientError::CallFailed(format!("{}", error)).into(),
                )),
            };
        drop(span);
        result
    }

    /// Retrieve transaction at specified block round and index.
    pub fn get_tx(&self, round: u64, index: u32) -> BoxFuture<Option<TransactionSnapshot>> {
        let (span, options) = self.prepare_options("TxnClient::get_tx");
        let request = api::client::GetTxRequest {
            runtime_id: self.runtime_id,
            round,
            index,
        };

        let result: BoxFuture<Option<TransactionSnapshot>> =
            match self.client.get_tx(&request, options) {
                Ok(resp) => {
                    let storage_client = self.storage_client.clone();
                    Box::new(resp.then(move |result| match result {
                        Err(RpcFailure(RpcStatus {
                            status: RpcStatusCode::NotFound,
                            ..
                        })) => Ok(None),
                        Err(error) => Err(TxnClientError::CallFailed(format!("{}", error)).into()),
                        Ok(rsp) => Ok(Some(TransactionSnapshot::new(
                            storage_client,
                            rsp.block,
                            index,
                            rsp.input,
                            rsp.output,
                        )?)),
                    }))
                }
                Err(error) => Box::new(future::err(
                    TxnClientError::CallFailed(format!("{}", error)).into(),
                )),
            };
        drop(span);
        result
    }

    /// Retrieve transaction at specified block hash and index.
    pub fn get_tx_by_block_hash(
        &self,
        block_hash: Hash,
        index: u32,
    ) -> BoxFuture<Option<TransactionSnapshot>> {
        let (span, options) = self.prepare_options("TxnClient::get_tx_by_block_hash");
        let request = api::client::GetTxByBlockHashRequest {
            runtime_id: self.runtime_id,
            block_hash,
            index,
        };

        let result: BoxFuture<Option<TransactionSnapshot>> =
            match self.client.get_tx_by_block_hash(&request, options) {
                Ok(resp) => {
                    let storage_client = self.storage_client.clone();
                    Box::new(resp.then(move |result| match result {
                        Err(RpcFailure(RpcStatus {
                            status: RpcStatusCode::NotFound,
                            ..
                        })) => Ok(None),
                        Err(error) => Err(TxnClientError::CallFailed(format!("{}", error)).into()),
                        Ok(rsp) => Ok(Some(TransactionSnapshot::new(
                            storage_client,
                            rsp.block,
                            index,
                            rsp.input,
                            rsp.output,
                        )?)),
                    }))
                }
                Err(error) => Box::new(future::err(
                    TxnClientError::CallFailed(format!("{}", error)).into(),
                )),
            };
        drop(span);
        result
    }

    /// Retrieve transactions at specific I/O root.
    pub fn get_txs(&self, round: u64, io_root: Hash) -> BoxFuture<TxnBatch> {
        let (span, options) = self.prepare_options("TxnClient::get_txs");
        let request = api::client::GetTxsRequest {
            runtime_id: self.runtime_id,
            round,
            io_root,
        };

        let result: BoxFuture<TxnBatch> = match self.client.get_txs(&request, options) {
            Ok(resp) => Box::new(
                resp.map_err(|error| TxnClientError::CallFailed(format!("{}", error)).into()),
            ),
            Err(error) => Box::new(future::err(
                TxnClientError::CallFailed(format!("{}", error)).into(),
            )),
        };
        drop(span);
        result
    }

    /// Retrieve a block by its hash.
    pub fn get_block_by_hash(&self, block_hash: Hash) -> BoxFuture<Option<BlockSnapshot>> {
        let (span, options) = self.prepare_options("TxnClient::get_block_by_hash");
        let request = api::client::GetBlockByHashRequest {
            runtime_id: self.runtime_id,
            block_hash,
        };

        let result: BoxFuture<Option<BlockSnapshot>> =
            match self.client.get_block_by_hash(&request, options) {
                Ok(resp) => {
                    let storage_client = self.storage_client.clone();
                    Box::new(resp.then(move |result| match result {
                        Err(RpcFailure(RpcStatus {
                            status: RpcStatusCode::NotFound,
                            ..
                        })) => Ok(None),
                        Err(error) => Err(TxnClientError::CallFailed(format!("{}", error)).into()),
                        Ok(rsp) => Ok(Some(BlockSnapshot::new(storage_client, rsp))),
                    }))
                }
                Err(error) => Box::new(future::err(
                    TxnClientError::CallFailed(format!("{}", error)).into(),
                )),
            };
        drop(span);
        result
    }

    /// Query the transaction index.
    pub fn query_tx<K, V>(&self, key: K, value: V) -> BoxFuture<Option<TransactionSnapshot>>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let (span, options) = self.prepare_options("TxnClient::query_tx");
        let request = api::client::QueryTxRequest {
            runtime_id: self.runtime_id,
            key: key.as_ref().into(),
            value: value.as_ref().into(),
        };

        let result: BoxFuture<Option<TransactionSnapshot>> =
            match self.client.query_tx(&request, options) {
                Ok(resp) => {
                    let storage_client = self.storage_client.clone();
                    Box::new(resp.then(move |result| match result {
                        Err(RpcFailure(RpcStatus {
                            status: RpcStatusCode::NotFound,
                            ..
                        })) => Ok(None),
                        Err(error) => Err(TxnClientError::CallFailed(format!("{}", error)).into()),
                        Ok(rsp) => Ok(Some(TransactionSnapshot::new(
                            storage_client,
                            rsp.block,
                            rsp.index,
                            rsp.input,
                            rsp.output,
                        )?)),
                    }))
                }
                Err(error) => Box::new(future::err(
                    TxnClientError::CallFailed(format!("{}", error)).into(),
                )),
            };
        drop(span);
        result
    }

    /// Query the transaction index with a complex query and returns multiple results.
    pub fn query_txs(&self, query: api::client::Query) -> BoxFuture<Vec<TransactionSnapshot>> {
        let (span, options) = self.prepare_options("TxnClient::query_txs");
        let request = api::client::QueryTxsRequest {
            runtime_id: self.runtime_id,
            query,
        };

        let result: BoxFuture<Vec<TransactionSnapshot>> = match self
            .client
            .query_txs(&request, options)
        {
            Ok(resp) => {
                let storage_client = self.storage_client.clone();
                Box::new(
                    resp.map_err(|error| TxnClientError::CallFailed(format!("{}", error)).into())
                        .and_then(move |rsp| {
                            rsp.into_iter()
                                .map(|tx| {
                                    TransactionSnapshot::new(
                                        storage_client.clone(),
                                        tx.block,
                                        tx.index,
                                        tx.input,
                                        tx.output,
                                    )
                                })
                                .collect::<Result<_, _>>()
                        }),
                )
            }
            Err(error) => Box::new(future::err(
                TxnClientError::CallFailed(format!("{}", error)).into(),
            )),
        };
        drop(span);
        result
    }

    /// Wait for a block to be indexed by the indexer.
    pub fn wait_block_indexed(&self, round: u64) -> BoxFuture<()> {
        let (span, options) = self.prepare_options("TxnClient::wait_block_indexed");
        let request = api::client::WaitBlockIndexedRequest {
            runtime_id: self.runtime_id,
            round: round,
        };

        let result: BoxFuture<()> = match self.client.wait_block_indexed(&request, options) {
            Ok(resp) => Box::new(
                resp.map_err(|error| TxnClientError::CallFailed(format!("{}", error)).into()),
            ),
            Err(error) => Box::new(future::err(
                TxnClientError::CallFailed(format!("{}", error)).into(),
            )),
        };
        drop(span);
        result
    }

    fn prepare_options(&self, span_name: &'static str) -> (Span, grpcio::CallOption) {
        // TODO: Use oasis_core_tracing to get the tracer.
        let (tracer, _) = Tracer::new(AllSampler);

        let span = tracer
            .span(span_name)
            .tag(tag::StdTag::span_kind("client"))
            .start();

        let mut options = grpcio::CallOption::default().wait_for_ready(true);
        if let Some(timeout) = self.timeout {
            options = options.timeout(timeout);
        }

        // TODO: Inject to options.
        // options = inject_to_options(options, span.context());

        (span, options)
    }
}

/// Parse runtime call output.
pub fn parse_call_output<O>(output: Vec<u8>) -> Fallible<O>
where
    O: DeserializeOwned,
{
    let output: TxnOutput = cbor::from_slice(&output)?;
    match output {
        TxnOutput::Success(data) => Ok(cbor::from_value(data)?),
        TxnOutput::Error(error) => Err(TxnClientError::TxnFailed(error).into()),
    }
}
