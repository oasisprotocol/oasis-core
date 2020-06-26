use std::any::Any;

use anyhow::Result;
use io_context::Context;

use crate::storage::mkvs::sync::*;

/// A no-op read syncer which doesn't support any of the required operations.
pub struct NoopReadSyncer;

impl ReadSync for NoopReadSyncer {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn sync_get(&mut self, _ctx: Context, _request: GetRequest) -> Result<ProofResponse> {
        Err(SyncerError::Unsupported.into())
    }

    fn sync_get_prefixes(
        &mut self,
        _ctx: Context,
        _request: GetPrefixesRequest,
    ) -> Result<ProofResponse> {
        Err(SyncerError::Unsupported.into())
    }

    fn sync_iterate(&mut self, _ctx: Context, _request: IterateRequest) -> Result<ProofResponse> {
        Err(SyncerError::Unsupported.into())
    }
}
