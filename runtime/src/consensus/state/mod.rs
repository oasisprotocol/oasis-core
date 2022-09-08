//! Consensus state wrappers.
use std::sync::Arc;

use anyhow::{Error, Result};
use io_context::Context;
use thiserror::Error;

use crate::{
    protocol::Protocol,
    storage::mkvs::{sync::HostReadSyncer, ImmutableMKVS, Root, Tree},
    types::{self, HostStorageEndpoint},
};

pub mod beacon;
pub mod keymanager;
pub mod registry;
pub mod roothash;
pub mod staking;

#[derive(Error, Debug)]
pub enum StateError {
    #[error("consensus state: unavailable/corrupted state")]
    Unavailable(#[from] Error),
}

impl From<StateError> for types::Error {
    fn from(e: StateError) -> Self {
        Self {
            module: "consensus".to_string(),
            code: 1,
            message: e.to_string(),
        }
    }
}

/// Provides consensus state tree from the host.
pub struct ConsensusState {
    // An explicit height field is needed because the relationship between the underlying consensus
    // height and the corresponding state root is a consensus backend implementation detail.
    height: u64,
    mkvs: Tree,
}

impl ConsensusState {
    /// Creates a consensus state wrapping the provided tree.
    pub fn new(height: u64, tree: Tree) -> Self {
        Self { height, mkvs: tree }
    }

    /// Creates consensus state using host protocol.
    pub fn from_protocol(protocol: Arc<Protocol>, height: u64, root: Root) -> Self {
        let read_syncer = HostReadSyncer::new(protocol, HostStorageEndpoint::Consensus);
        Self {
            height,
            mkvs: Tree::builder()
                .with_capacity(100_000, 10_000_000)
                .with_root(root)
                .build(Box::new(read_syncer)),
        }
    }

    /// Consensus layer height that this data is for.
    pub fn height(&self) -> u64 {
        self.height
    }
}

impl ImmutableMKVS for ConsensusState {
    fn get(&self, ctx: Context, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.mkvs.get(ctx, key)
    }

    fn prefetch_prefixes(
        &self,
        ctx: Context,
        prefixes: &[crate::storage::mkvs::Prefix],
        limit: u16,
    ) -> Result<()> {
        self.mkvs.prefetch_prefixes(ctx, prefixes, limit)
    }

    fn iter(&self, ctx: Context) -> Box<dyn crate::storage::mkvs::Iterator + '_> {
        Box::new(self.mkvs.iter(ctx))
    }
}

impl ImmutableMKVS for &ConsensusState {
    fn get(&self, ctx: Context, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.mkvs.get(ctx, key)
    }

    fn prefetch_prefixes(
        &self,
        ctx: Context,
        prefixes: &[crate::storage::mkvs::Prefix],
        limit: u16,
    ) -> Result<()> {
        self.mkvs.prefetch_prefixes(ctx, prefixes, limit)
    }

    fn iter(&self, ctx: Context) -> Box<dyn crate::storage::mkvs::Iterator + '_> {
        Box::new(self.mkvs.iter(ctx))
    }
}
