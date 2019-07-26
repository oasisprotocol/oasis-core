use std::any::Any;

use failure::Fallible;
use io_context::Context;

use crate::storage::mkvs::urkel::{sync::*, tree::*};

/// ReadSync is the interface for synchronizing the in-memory cache
/// with another (potentially untrusted) MKVS.
pub trait ReadSync {
    /// Return `self` as an `Any` object, useful for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Retrieve a subtree rooted at the node uniquely identified by the
    /// passed node ID. The maxDepth specifies the maximum node depth up
    /// to which the subtree will be traversed.
    ///
    /// It is the responsibility of the caller to validate that the subtree
    /// is correct and consistent.
    fn get_subtree(
        &mut self,
        ctx: Context,
        root: Root,
        id: NodeID,
        max_depth: Depth,
    ) -> Fallible<Subtree>;

    /// Retrieve a path of nodes rooted at the node uniquely identified by
    /// the passed node ID and advancing towards the specified key.
    ///
    /// It is the responsibility of the caller to validate that the subtree
    /// is correct and consistent.
    fn get_path(&mut self, ctx: Context, root: Root, id: NodeID, key: &Key) -> Fallible<Subtree>;

    /// Retrieve a specific node under the given root.
    ///
    /// It is the responsibility of the caller to validate that the node
    /// is consistent. The node's cached hash should be considered invalid
    /// and must be recomputed locally.
    fn get_node(&mut self, ctx: Context, root: Root, id: NodeID) -> Fallible<NodeRef>;
}
