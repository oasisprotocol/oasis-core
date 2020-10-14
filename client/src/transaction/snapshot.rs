//! A block snapshot.
use std::{any::Any, sync::Mutex};

use anyhow::{Context as AnyContext, Result};
use grpcio::CallOption;
use io_context::Context;
use oasis_core_runtime::{
    common::{cbor, crypto::hash::Hash, namespace::Namespace},
    consensus::roothash::Block,
    storage::{
        mkvs::{sync::*, Iterator, Prefix, Root, RootType, Tree, WriteLog},
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
    ) -> Result<Self> {
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
    mkvs: Mutex<Tree>,
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
                root_type: RootType::State,
                hash: self.block.header.state_root,
            })
            .new(Box::new(read_syncer.clone()));

        Self {
            block,
            block_hash,
            read_syncer,
            mkvs: Mutex::new(mkvs),
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
                root_type: RootType::State,
                hash: block.header.state_root,
            })
            .new(Box::new(read_syncer.clone()));

        Self {
            block_hash: block.header.encoded_hash(),
            block,
            read_syncer,
            mkvs: Mutex::new(mkvs),
        }
    }
}

impl MKVS for BlockSnapshot {
    fn get(&self, ctx: Context, key: &[u8]) -> Option<Vec<u8>> {
        let mkvs = self.mkvs.lock().unwrap();
        mkvs.get(ctx, key).unwrap()
    }

    fn cache_contains_key(&self, ctx: Context, key: &[u8]) -> bool {
        let mkvs = self.mkvs.lock().unwrap();
        mkvs.cache_contains_key(ctx, key)
    }

    fn insert(&mut self, _ctx: Context, _key: &[u8], _value: &[u8]) -> Option<Vec<u8>> {
        unimplemented!("block snapshot is read-only");
    }

    fn remove(&mut self, _ctx: Context, _key: &[u8]) -> Option<Vec<u8>> {
        unimplemented!("block snapshot is read-only");
    }

    fn prefetch_prefixes(&self, ctx: Context, prefixes: &Vec<Prefix>, limit: u16) {
        let mkvs = self.mkvs.lock().unwrap();
        mkvs.prefetch_prefixes(ctx, prefixes, limit).unwrap()
    }

    fn iter(&self, _ctx: Context) -> Box<dyn Iterator + '_> {
        unimplemented!("block snapshot doesn't support iterators");
    }

    fn commit(
        &mut self,
        _ctx: Context,
        _namespace: Namespace,
        _round: u64,
    ) -> Result<(WriteLog, Hash)> {
        unimplemented!("block snapshot is read-only");
    }
}

#[derive(Clone)]
struct RemoteReadSync(api::storage::StorageClient);

impl ReadSync for RemoteReadSync {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn sync_get(&mut self, _ctx: Context, request: GetRequest) -> Result<ProofResponse> {
        Ok(self
            .0
            .sync_get(&request, CallOption::default().wait_for_ready(true))
            .map_err(|error| TxnClientError::CallFailed(format!("{}", error)))?)
    }

    fn sync_get_prefixes(
        &mut self,
        _ctx: Context,
        request: GetPrefixesRequest,
    ) -> Result<ProofResponse> {
        Ok(self
            .0
            .sync_get_prefixes(&request, CallOption::default().wait_for_ready(true))
            .map_err(|error| TxnClientError::CallFailed(format!("{}", error)))?)
    }

    fn sync_iterate(&mut self, _ctx: Context, request: IterateRequest) -> Result<ProofResponse> {
        Ok(self
            .0
            .sync_iterate(&request, CallOption::default().wait_for_ready(true))
            .map_err(|error| TxnClientError::CallFailed(format!("{}", error)))?)
    }
}
