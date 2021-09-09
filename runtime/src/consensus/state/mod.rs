//! Consensus state wrappers.
use std::sync::Arc;

use anyhow::{Error, Result};
use io_context::Context;
use thiserror::Error;

use crate::{
    protocol::Protocol,
    storage::mkvs::{sync::HostReadSyncer, ImmutableMKVS, Root, Tree},
    types::HostStorageEndpoint,
};

pub mod roothash;
pub mod staking;

#[derive(Error, Debug)]
pub enum StateError {
    #[error("consensus state: unavailable/corrupted state")]
    Unavailable(#[from] Error),
}

/// Provides consensus state tree from the host.
pub struct ConsensusState {
    mkvs: Tree,
}

impl ConsensusState {
    /// Creates a consensus state wrapping the provided tree.
    pub fn new(tree: Tree) -> Self {
        Self { mkvs: tree }
    }

    /// Creates consensus state using host protocol.
    pub fn from_protocol(protocol: Arc<Protocol>, root: Root) -> Self {
        let read_syncer = HostReadSyncer::new(protocol, HostStorageEndpoint::Consensus);
        Self {
            mkvs: Tree::make()
                .with_capacity(100_000, 10_000_000)
                .with_root(root)
                .new(Box::new(read_syncer)),
        }
    }
}

impl ImmutableMKVS for ConsensusState {
    fn get(&self, ctx: Context, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.mkvs.get(ctx, key)
    }

    fn prefetch_prefixes(
        &self,
        ctx: Context,
        prefixes: &Vec<crate::storage::mkvs::Prefix>,
        limit: u16,
    ) -> Result<()> {
        self.mkvs.prefetch_prefixes(ctx, prefixes, limit)
    }

    fn iter(&self, ctx: Context) -> Box<dyn crate::storage::mkvs::Iterator + '_> {
        Box::new(self.mkvs.iter(ctx))
    }
}
