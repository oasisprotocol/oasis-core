//! Transaction client.
use std::time::Duration;

use futures::prelude::*;
use grpcio::{Channel, Error::RpcFailure, RpcStatusCode};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use oasis_core_runtime::{
    common::{cbor, crypto::hash::Hash, namespace::Namespace},
    transaction::types::{TxnBatch, TxnCall, TxnOutput},
};

use super::{
    api,
    block_watcher::{BlockWatcher, WatchError},
    snapshot::{BlockSnapshot, TransactionSnapshot},
};

/// Transaction client error.
#[derive(Error, Debug)]
pub enum TxnClientError {
    #[error("node call failed: {0}")]
    CallFailed(String),
    #[error("block watcher closed")]
    WatcherClosed,
    #[error("transaction failed: {0}")]
    TxnFailed(String),
    #[error("malformed transaction output")]
    MalformedOutput,
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
    runtime_id: Namespace,
    /// RPC timeout.
    timeout: Option<Duration>,
    /// Block watcher for `get_latest_block` call.
    block_watcher: BlockWatcher,
}

impl TxnClient {
    /// Create a new transaction client.
    pub fn new(channel: Channel, runtime_id: Namespace, timeout: Option<Duration>) -> Self {
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
    pub async fn call<C, O>(&self, method: &'static str, args: C) -> Result<O, TxnClientError>
    where
        C: Serialize,
        O: DeserializeOwned + Send + 'static,
    {
        let call = TxnCall {
            method: method.to_owned(),
            args: cbor::to_value(args),
        };

        parse_call_output(self.submit_tx_raw(&call).await?)
    }

    /// Dispatch a raw call to the node.
    pub async fn submit_tx_raw<C>(&self, call: C) -> Result<Vec<u8>, TxnClientError>
    where
        C: Serialize,
    {
        let options = self.prepare_options();
        let request = api::client::SubmitTxRequest {
            runtime_id: self.runtime_id,
            data: cbor::to_vec(&call),
        };

        let rsp = self
            .client
            .submit_tx(&request, options)
            .map_err(|err| TxnClientError::CallFailed(format!("{}", err)))?
            .await
            .map_err(|err| TxnClientError::CallFailed(format!("{}", err)))?;

        Ok(rsp.into_vec())
    }

    /// Wait for the node to finish syncing.
    pub async fn wait_sync(&self) -> Result<(), TxnClientError> {
        let options = self.prepare_options();

        self.node_controller
            .wait_sync(options)
            .map_err(|err| TxnClientError::CallFailed(format!("{}", err)))?
            .await
            .map_err(|err| TxnClientError::CallFailed(format!("{}", err)))?;

        Ok(())
    }

    /// Check if the node is finished syncing.
    pub async fn is_synced(&self) -> Result<bool, TxnClientError> {
        let options = self.prepare_options();

        Ok(self
            .node_controller
            .is_synced(options)
            .map_err(|err| TxnClientError::CallFailed(format!("{}", err)))?
            .await
            .map_err(|err| TxnClientError::CallFailed(format!("{}", err)))?)
    }

    /// Retrieve the latest block snapshot.
    pub async fn get_latest_block(&self) -> Result<BlockSnapshot, TxnClientError> {
        let block_watcher = self.block_watcher.clone();
        let runtime_id = self.runtime_id.clone();
        let storage_client = self.storage_client.clone();

        // Spawn block watcher if not running yet.
        if block_watcher.start_spawn() {
            let block_watcher = block_watcher.clone();
            match self.client.watch_blocks(runtime_id) {
                Ok(blocks) => {
                    block_watcher.spawn(
                        blocks
                            .map_err(|_| WatchError::BlockStreamClosed)
                            .map_ok(move |rsp| {
                                BlockSnapshot::new(storage_client.clone(), rsp.block)
                            }),
                    );
                }
                Err(err) => {
                    // Failed to start watching blocks, retry on next attempt.
                    block_watcher.cancel_spawn();
                    return Err(TxnClientError::CallFailed(format!("{}", err)));
                }
            }
        }

        block_watcher
            .get_latest_block()
            .await
            .map_err(|_| TxnClientError::WatcherClosed)
    }

    /// Retrieve block snapshot at specified round.
    pub async fn get_block(&self, round: u64) -> Result<Option<BlockSnapshot>, TxnClientError> {
        let options = self.prepare_options();
        let request = api::client::GetBlockRequest {
            runtime_id: self.runtime_id,
            round: round,
        };

        let storage_client = self.storage_client.clone();
        let rsp = self
            .client
            .get_block(&request, options)
            .map_err(|err| TxnClientError::CallFailed(format!("{}", err)))?
            .await;

        match rsp {
            Err(RpcFailure(s)) if s.code() == RpcStatusCode::NOT_FOUND => Ok(None),
            Err(err) => Err(TxnClientError::CallFailed(format!("{}", err))),
            Ok(rsp) => Ok(Some(BlockSnapshot::new(storage_client, rsp))),
        }
    }

    /// Retrieve transaction at specified block round and index.
    pub async fn get_tx(
        &self,
        round: u64,
        index: u32,
    ) -> Result<Option<TransactionSnapshot>, TxnClientError> {
        let options = self.prepare_options();
        let request = api::client::GetTxRequest {
            runtime_id: self.runtime_id,
            round,
            index,
        };

        let storage_client = self.storage_client.clone();
        let rsp = self
            .client
            .get_tx(&request, options)
            .map_err(|err| TxnClientError::CallFailed(format!("{}", err)))?
            .await;

        match rsp {
            Err(RpcFailure(s)) if s.code() == RpcStatusCode::NOT_FOUND => Ok(None),
            Err(err) => Err(TxnClientError::CallFailed(format!("{}", err))),
            Ok(rsp) => Ok(Some(
                TransactionSnapshot::new(storage_client, rsp.block, index, rsp.input, rsp.output)
                    .map_err(|_| TxnClientError::MalformedOutput)?,
            )),
        }
    }

    /// Retrieve transaction at specified block hash and index.
    pub async fn get_tx_by_block_hash(
        &self,
        block_hash: Hash,
        index: u32,
    ) -> Result<Option<TransactionSnapshot>, TxnClientError> {
        let options = self.prepare_options();
        let request = api::client::GetTxByBlockHashRequest {
            runtime_id: self.runtime_id,
            block_hash,
            index,
        };

        let storage_client = self.storage_client.clone();
        let rsp = self
            .client
            .get_tx_by_block_hash(&request, options)
            .map_err(|err| TxnClientError::CallFailed(format!("{}", err)))?
            .await;

        match rsp {
            Err(RpcFailure(s)) if s.code() == RpcStatusCode::NOT_FOUND => Ok(None),
            Err(err) => Err(TxnClientError::CallFailed(format!("{}", err))),
            Ok(rsp) => Ok(Some(
                TransactionSnapshot::new(storage_client, rsp.block, index, rsp.input, rsp.output)
                    .map_err(|_| TxnClientError::MalformedOutput)?,
            )),
        }
    }

    /// Retrieve transactions at specific I/O root.
    pub async fn get_txs(&self, round: u64, io_root: Hash) -> Result<TxnBatch, TxnClientError> {
        let options = self.prepare_options();
        let request = api::client::GetTxsRequest {
            runtime_id: self.runtime_id,
            round,
            io_root,
        };

        Ok(self
            .client
            .get_txs(&request, options)
            .map_err(|err| TxnClientError::CallFailed(format!("{}", err)))?
            .await
            .map_err(|err| TxnClientError::CallFailed(format!("{}", err)))?)
    }

    /// Retrieve a block by its hash.
    pub async fn get_block_by_hash(
        &self,
        block_hash: Hash,
    ) -> Result<Option<BlockSnapshot>, TxnClientError> {
        let options = self.prepare_options();
        let request = api::client::GetBlockByHashRequest {
            runtime_id: self.runtime_id,
            block_hash,
        };

        let storage_client = self.storage_client.clone();
        let rsp = self
            .client
            .get_block_by_hash(&request, options)
            .map_err(|err| TxnClientError::CallFailed(format!("{}", err)))?
            .await;

        match rsp {
            Err(RpcFailure(s)) if s.code() == RpcStatusCode::NOT_FOUND => Ok(None),
            Err(err) => Err(TxnClientError::CallFailed(format!("{}", err))),
            Ok(rsp) => Ok(Some(BlockSnapshot::new(storage_client, rsp))),
        }
    }

    /// Query the transaction index.
    pub async fn query_tx<K, V>(
        &self,
        key: K,
        value: V,
    ) -> Result<Option<TransactionSnapshot>, TxnClientError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let options = self.prepare_options();
        let request = api::client::QueryTxRequest {
            runtime_id: self.runtime_id,
            key: key.as_ref().into(),
            value: value.as_ref().into(),
        };

        let storage_client = self.storage_client.clone();
        let rsp = self
            .client
            .query_tx(&request, options)
            .map_err(|err| TxnClientError::CallFailed(format!("{}", err)))?
            .await;

        match rsp {
            Err(RpcFailure(s)) if s.code() == RpcStatusCode::NOT_FOUND => Ok(None),
            Err(err) => Err(TxnClientError::CallFailed(format!("{}", err))),
            Ok(rsp) => Ok(Some(
                TransactionSnapshot::new(
                    storage_client,
                    rsp.block,
                    rsp.index,
                    rsp.input,
                    rsp.output,
                )
                .map_err(|_| TxnClientError::MalformedOutput)?,
            )),
        }
    }

    /// Query the transaction index with a complex query and returns multiple results.
    pub async fn query_txs(
        &self,
        query: api::client::Query,
    ) -> Result<Vec<TransactionSnapshot>, TxnClientError> {
        let options = self.prepare_options();
        let request = api::client::QueryTxsRequest {
            runtime_id: self.runtime_id,
            query,
        };

        let storage_client = self.storage_client.clone();
        let rsp = self
            .client
            .query_txs(&request, options)
            .map_err(|err| TxnClientError::CallFailed(format!("{}", err)))?
            .await
            .map_err(|err| TxnClientError::CallFailed(format!("{}", err)))?;

        rsp.into_iter()
            .map(|tx| {
                TransactionSnapshot::new(
                    storage_client.clone(),
                    tx.block,
                    tx.index,
                    tx.input,
                    tx.output,
                )
                .map_err(|_| TxnClientError::MalformedOutput)
            })
            .collect::<Result<_, _>>()
    }

    /// Wait for a block to be indexed by the indexer.
    pub async fn wait_block_indexed(&self, round: u64) -> Result<(), TxnClientError> {
        let options = self.prepare_options();
        let request = api::client::WaitBlockIndexedRequest {
            runtime_id: self.runtime_id,
            round: round,
        };

        self.client
            .wait_block_indexed(&request, options)
            .map_err(|err| TxnClientError::CallFailed(format!("{}", err)))?
            .await
            .map_err(|err| TxnClientError::CallFailed(format!("{}", err)))?;

        Ok(())
    }

    fn prepare_options(&self) -> grpcio::CallOption {
        let mut options = grpcio::CallOption::default().wait_for_ready(true);
        if let Some(timeout) = self.timeout {
            options = options.timeout(timeout);
        }

        options
    }
}

/// Parse runtime call output.
pub fn parse_call_output<O>(output: Vec<u8>) -> Result<O, TxnClientError>
where
    O: DeserializeOwned,
{
    let output: TxnOutput =
        cbor::from_slice(&output).map_err(|_| TxnClientError::MalformedOutput)?;
    match output {
        TxnOutput::Success(data) => {
            Ok(cbor::from_value(data).map_err(|_| TxnClientError::MalformedOutput)?)
        }
        TxnOutput::Error(err) => Err(TxnClientError::TxnFailed(err)),
    }
}
