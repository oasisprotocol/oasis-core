use std::any::Any;

use failure::Fallible;
use io_context::Context;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{sync::*, tree::*},
};

/// A proxy read syncer which keeps track of call statistics.
pub struct StatsCollector {
    /// Count of `get_subtree` calls made to the underlying read syncer.
    pub subtree_fetches: usize,
    /// Count of `get_path` calls made to the underlying read syncer.
    pub path_fetches: usize,
    /// Count of `get_node` calls made to the underlying read syncer.
    pub node_fetches: usize,
    /// Count of `get_value` calls made to the underlying read syncer.
    pub value_fetches: usize,

    rs: Box<dyn ReadSync>,
}

impl StatsCollector {
    /// Construct a new instance, proxying to the given backing read syncer.
    pub fn new(rs: Box<dyn ReadSync>) -> StatsCollector {
        StatsCollector {
            subtree_fetches: 0,
            path_fetches: 0,
            node_fetches: 0,
            value_fetches: 0,
            rs: rs,
        }
    }
}

impl ReadSync for StatsCollector {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn get_subtree(
        &mut self,
        ctx: Context,
        root_hash: Hash,
        id: NodeID,
        max_depth: u8,
    ) -> Fallible<Subtree> {
        self.subtree_fetches += 1;
        self.rs.get_subtree(ctx, root_hash, id, max_depth)
    }

    fn get_path(
        &mut self,
        ctx: Context,
        root_hash: Hash,
        key: &Key,
        start_depth: u8,
    ) -> Fallible<Subtree> {
        self.path_fetches += 1;
        self.rs.get_path(ctx, root_hash, key, start_depth)
    }

    fn get_node(&mut self, ctx: Context, root_hash: Hash, id: NodeID) -> Fallible<NodeRef> {
        self.node_fetches += 1;
        self.rs.get_node(ctx, root_hash, id)
    }

    fn get_value(&mut self, ctx: Context, root_hash: Hash, id: Hash) -> Fallible<Option<Value>> {
        self.value_fetches += 1;
        self.rs.get_value(ctx, root_hash, id)
    }
}
