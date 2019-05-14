//! A block snapshot.
use std::{any::Any, cell::RefCell, rc::Rc, sync::Arc};

use ekiden_runtime::{
    common::{crypto::hash::Hash, roothash::Block},
    storage::{
        mkvs::{
            urkel::{
                marshal::Marshal,
                sync::{NodeBox, NodeID, NodeRef, ReadSync, Subtree, Value},
            },
            UrkelTree, WriteLog,
        },
        CAS, MKVS,
    },
    transaction::types::{TxnCall, TxnOutput},
};
use failure::{Fallible, ResultExt};
use io_context::Context;
use serde_cbor;

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
        block_hash: Hash,
        index: u32,
        input: Vec<u8>,
        output: Vec<u8>,
    ) -> Fallible<Self> {
        Ok(Self {
            block_snapshot: BlockSnapshot::new(storage_client, block, block_hash),
            index,
            input: serde_cbor::from_slice(&input).context("input is malformed")?,
            output: serde_cbor::from_slice(&output).context("output is malformed")?,
        })
    }
}

/// A partial block snapshot exposing the storage root.
pub struct BlockSnapshot {
    /// The (partial) block this snapshot is based on.
    pub block: Block,
    /// Block header hash.
    pub block_hash: Hash,

    cas: Arc<CAS>,
    read_syncer: RemoteReadSync,
    mkvs: UrkelTree,
}

impl Clone for BlockSnapshot {
    fn clone(&self) -> Self {
        let block = self.block.clone();
        let block_hash = self.block_hash.clone();
        let cas = self.cas.clone();
        let read_syncer = self.read_syncer.clone();
        let mkvs = UrkelTree::make()
            .with_root(self.block.header.state_root)
            .new(Context::background(), Box::new(read_syncer.clone()))
            .expect("prefetching disabled so new must always succeed");

        Self {
            block,
            block_hash,
            cas,
            read_syncer,
            mkvs,
        }
    }
}

impl BlockSnapshot {
    pub(super) fn new(
        storage_client: api::storage::StorageClient,
        block: Block,
        block_hash: Hash,
    ) -> Self {
        let cas = Arc::new(RemoteCAS(storage_client.clone()));
        let read_syncer = RemoteReadSync(storage_client);
        let mkvs = UrkelTree::make()
            .with_root(block.header.state_root)
            .new(Context::background(), Box::new(read_syncer.clone()))
            .expect("prefetching disabled so new must always succeed");

        Self {
            block,
            block_hash,
            cas,
            read_syncer,
            mkvs,
        }
    }
}

impl CAS for BlockSnapshot {
    fn get(&self, key: Hash) -> Fallible<Vec<u8>> {
        self.cas.get(key)
    }

    fn insert(&self, _value: Vec<u8>, _expiry: u64) -> Fallible<Hash> {
        unimplemented!("block snapshot is read-only");
    }
}

impl MKVS for BlockSnapshot {
    fn get(&self, ctx: Context, key: &[u8]) -> Option<Vec<u8>> {
        MKVS::get(&self.mkvs, ctx, key)
    }

    fn insert(&mut self, _ctx: Context, _key: &[u8], _value: &[u8]) -> Option<Vec<u8>> {
        unimplemented!("block snapshot is read-only");
    }

    fn remove(&mut self, _ctx: Context, _key: &[u8]) -> Option<Vec<u8>> {
        unimplemented!("block snapshot is read-only");
    }

    fn commit(&mut self, _ctx: Context) -> Fallible<(WriteLog, Hash)> {
        unimplemented!("block snapshot is read-only");
    }

    fn rollback(&mut self) {
        unimplemented!("block snapshot is read-only");
    }

    fn set_encryption_key(&mut self, key: Option<&[u8]>) {
        MKVS::set_encryption_key(&mut self.mkvs, key)
    }
}

#[derive(Clone)]
struct RemoteCAS(api::storage::StorageClient);

impl CAS for RemoteCAS {
    fn get(&self, key: Hash) -> Fallible<Vec<u8>> {
        // TODO: Tracing.

        let mut request = api::storage::GetRequest::new();
        request.set_id(key.as_ref().to_vec());

        let response = self
            .0
            .get(&request)
            .map_err(|error| TxnClientError::CallFailed(format!("{}", error)))?;

        Ok(response.data)
    }

    fn insert(&self, _value: Vec<u8>, _expiry: u64) -> Fallible<Hash> {
        unimplemented!("block snapshot is read-only");
    }
}

#[derive(Clone)]
struct RemoteReadSync(api::storage::StorageClient);

impl ReadSync for RemoteReadSync {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn get_subtree(
        &mut self,
        _ctx: Context,
        root_hash: Hash,
        id: NodeID,
        max_depth: u8,
    ) -> Fallible<Subtree> {
        let mut request = api::storage::GetSubtreeRequest::new();
        request.set_root(root_hash.as_ref().to_vec());
        request.set_id({
            let mut nid = api::storage::NodeID::new();
            nid.set_path(id.path.as_ref().to_vec());
            nid.set_depth(id.depth.into());
            nid
        });
        request.set_max_depth(max_depth.into());

        let response = self
            .0
            .get_subtree(&request)
            .map_err(|error| TxnClientError::CallFailed(format!("{}", error)))?;

        let mut st = Subtree::new();
        st.unmarshal_binary(response.get_subtree())?;
        Ok(st)
    }

    fn get_path(
        &mut self,
        _ctx: Context,
        root_hash: Hash,
        key: Hash,
        start_depth: u8,
    ) -> Fallible<Subtree> {
        let mut request = api::storage::GetPathRequest::new();
        request.set_root(root_hash.as_ref().to_vec());
        request.set_key(key.as_ref().to_vec());
        request.set_start_depth(start_depth.into());

        let response = self
            .0
            .get_path(&request)
            .map_err(|error| TxnClientError::CallFailed(format!("{}", error)))?;

        let mut st = Subtree::new();
        st.unmarshal_binary(response.get_subtree())?;
        Ok(st)
    }

    fn get_node(&mut self, _ctx: Context, root_hash: Hash, id: NodeID) -> Fallible<NodeRef> {
        let mut request = api::storage::GetNodeRequest::new();
        request.set_root(root_hash.as_ref().to_vec());
        request.set_id({
            let mut nid = api::storage::NodeID::new();
            nid.set_path(id.path.as_ref().to_vec());
            nid.set_depth(id.depth.into());
            nid
        });

        let response = self
            .0
            .get_node(&request)
            .map_err(|error| TxnClientError::CallFailed(format!("{}", error)))?;

        let mut node = NodeBox::default();
        node.unmarshal_binary(response.get_node())?;
        Ok(Rc::new(RefCell::new(node)))
    }

    fn get_value(&mut self, _ctx: Context, root_hash: Hash, id: Hash) -> Fallible<Option<Value>> {
        let mut request = api::storage::GetValueRequest::new();
        request.set_root(root_hash.as_ref().to_vec());
        request.set_id(id.as_ref().to_vec());

        let mut response = self
            .0
            .get_value(&request)
            .map_err(|error| TxnClientError::CallFailed(format!("{}", error)))?;

        let value = response.take_value();
        if value.is_empty() {
            Ok(None)
        } else {
            Ok(Some(value))
        }
    }
}
