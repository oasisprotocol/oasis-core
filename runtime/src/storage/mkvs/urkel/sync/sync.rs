use std::any::Any;

use failure::Fallible;
use io_context::Context;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{sync::*, tree::*},
};

/// ReadSync is the interface for synchronizing the in-memory cache
/// with another (potentially untrusted) MKVS.
pub trait ReadSync {
    /// Return `self` as an `Any` object, useful for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Retrieve a compressed subtree summary of the given node
    /// under the given root up to the specified depth.
    ///
    /// It is the responsibility of the caller to validate that the subtree
    /// is correct and consistent.
    fn get_subtree(
        &mut self,
        ctx: Context,
        root_hash: Hash,
        id: NodeID,
        max_depth: u8,
    ) -> Fallible<Subtree>;

    /// Retrieve a compressed path summary for the given key under
    /// the given root, starting at the given depth.
    ///
    /// It is the responsibility of the caller to validate that the subtree
    /// is correct and consistent.
    fn get_path(
        &mut self,
        ctx: Context,
        root_hash: Hash,
        key: Hash,
        start_depth: u8,
    ) -> Fallible<Subtree>;

    /// Retrieve a specific node under the given root.
    ///
    /// It is the responsibility of the caller to validate that the node
    /// is consistent. The node's cached hash should be considered invalid
    /// and must be recomputed locally.
    fn get_node(&mut self, ctx: Context, root_hash: Hash, id: NodeID) -> Fallible<NodeRef>;

    /// Retrieve a specific value under the given root.
    ///
    /// It is the responsibility of the caller to validate that the value
    /// is consistent.
    fn get_value(&mut self, ctx: Context, root_hash: Hash, id: Hash) -> Fallible<Option<Value>>;
}
