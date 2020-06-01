//! A block snapshot.
use std::any::Any;

use failure::{Fallible, ResultExt};
use grpcio::CallOption;
use io_context::Context;
use oasis_core_runtime::{
    common::{
        cbor,
        crypto::hash::Hash,
        roothash::{Block, Namespace},
    },
    storage::{
        mkvs::{sync::*, Prefix, Root, Tree, WriteLog},
        MKVS,
    },
    transaction::types::{TxnCall, TxnOutput},
};

use super::{api, client::TxnClientError};

/// A transaction snapshot.
#[derive(Clone)]
pub struct TransactionSnapshot {
    /// Block snapshot for this transaction.
    pub block_snapshot: BlockSnapshot,
    /// Transaction index in the list of transactions.
    pub index: u32,
    /// Transaction input.
    pub input: TxnCall,
    /// Transaction output.
    pub output: TxnOutput,
}

impl TransactionSnapshot {
    pub(super) fn new(
        storage_client: api::storage::StorageClient,
        block: Block,
        index: u32,
        input: Vec<u8>,
        output: Vec<u8>,
    ) -> Fallible<Self> {
        Ok(Self {
            block_snapshot: BlockSnapshot::new(storage_client, block),
            index,
            input: cbor::from_slice(&input).context("input is malformed")?,
            output: cbor::from_slice(&output).context("output is malformed")?,
        })
    }
}

/// A partial block snapshot exposing the storage root.
pub struct BlockSnapshot {
    /// The (partial) block this snapshot is based on.
    pub block: Block,
    /// Block header hash.
    pub block_hash: Hash,

    read_syncer: RemoteReadSync,
    mkvs: Tree,
}

impl Clone for BlockSnapshot {
    fn clone(&self) -> Self {
        let block = self.block.clone();
        let block_hash = self.block_hash;
        let read_syncer = self.read_syncer.clone();
        let mkvs = Tree::make()
            .with_root(Root {
                namespace: self.block.header.namespace,
                version: self.block.header.round,
                hash: self.block.header.state_root,
            })
            .new(Box::new(read_syncer.clone()));

        Self {
            block,
            block_hash,
            read_syncer,
            mkvs,
        }
    }
}

impl BlockSnapshot {
    pub(super) fn new(storage_client: api::storage::StorageClient, block: Block) -> Self {
        let read_syncer = RemoteReadSync(storage_client);
        let mkvs = Tree::make()
            .with_root(Root {
                namespace: block.header.namespace,
                version: block.header.round,
                hash: block.header.state_root,
            })
            .new(Box::new(read_syncer.clone()));

        Self {
            block_hash: block.header.encoded_hash(),
            block,
            read_syncer,
            mkvs,
        }
    }
}

impl MKVS for BlockSnapshot {
    fn get(&self, ctx: Context, key: &[u8]) -> Option<Vec<u8>> {
        MKVS::get(&self.mkvs, ctx, key)
    }

    fn cache_contains_key(&self, ctx: Context, key: &[u8]) -> bool {
        MKVS::cache_contains_key(&self.mkvs, ctx, key)
    }

    fn insert(&mut self, _ctx: Context, _key: &[u8], _value: &[u8]) -> Option<Vec<u8>> {
        unimplemented!("block snapshot is read-only");
    }

    fn remove(&mut self, _ctx: Context, _key: &[u8]) -> Option<Vec<u8>> {
        unimplemented!("block snapshot is read-only");
    }

    fn prefetch_prefixes(&self, ctx: Context, prefixes: &Vec<Prefix>, limit: u16) {
        MKVS::prefetch_prefixes(&self.mkvs, ctx, prefixes, limit)
    }

    fn commit(
        &mut self,
        _ctx: Context,
        _namespace: Namespace,
        _round: u64,
    ) -> Fallible<(WriteLog, Hash)> {
        unimplemented!("block snapshot is read-only");
    }

    fn rollback(&mut self) {
        unimplemented!("block snapshot is read-only");
    }
}

#[derive(Clone)]
struct RemoteReadSync(api::storage::StorageClient);

impl ReadSync for RemoteReadSync {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn sync_get(&mut self, _ctx: Context, request: GetRequest) -> Fallible<ProofResponse> {
        Ok(self
            .0
            .sync_get(&request, CallOption::default().wait_for_ready(true))
            .map_err(|error| TxnClientError::CallFailed(format!("{}", error)))?)
    }

    fn sync_get_prefixes(
        &mut self,
        _ctx: Context,
        request: GetPrefixesRequest,
    ) -> Fallible<ProofResponse> {
        Ok(self
            .0
            .sync_get_prefixes(&request, CallOption::default().wait_for_ready(true))
            .map_err(|error| TxnClientError::CallFailed(format!("{}", error)))?)
    }

    fn sync_iterate(&mut self, _ctx: Context, request: IterateRequest) -> Fallible<ProofResponse> {
        Ok(self
            .0
            .sync_iterate(&request, CallOption::default().wait_for_ready(true))
            .map_err(|error| TxnClientError::CallFailed(format!("{}", error)))?)
    }
}
