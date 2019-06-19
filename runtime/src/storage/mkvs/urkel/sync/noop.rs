use std::any::Any;

use failure::Fallible;
use io_context::Context;

use crate::storage::mkvs::urkel::{sync::*, tree::*};

/// A no-op read syncer which doesn't support any of the required operations.
pub struct NoopReadSyncer {}

impl ReadSync for NoopReadSyncer {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn get_subtree(
        &mut self,
        _ctx: Context,
        _root: Root,
        _id: NodeID,
        _max_depth: Depth,
    ) -> Fallible<Subtree> {
        Err(SyncerError::Unsupported.into())
    }

    fn get_path(
        &mut self,
        _ctx: Context,
        _root: Root,
        _key: &Key,
        _start_depth: Depth,
    ) -> Fallible<Subtree> {
        Err(SyncerError::Unsupported.into())
    }

    fn get_node(&mut self, _ctx: Context, _root: Root, _id: NodeID) -> Fallible<NodeRef> {
        Err(SyncerError::Unsupported.into())
    }
}
