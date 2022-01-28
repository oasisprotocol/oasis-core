use std::any::Any;

use anyhow::Result;
use io_context::Context;

use crate::storage::mkvs::sync::*;

/// A proxy read syncer which keeps track of call statistics.
pub struct StatsCollector {
    /// Count of `sync_get` calls made to the underlying read syncer.
    pub sync_get_count: usize,
    /// Count of `sync_get_prefixes` calls made to the underlying read syncer.
    pub sync_get_prefixes_count: usize,
    /// Count of `sync_iterate` calls made to the underlying read syncer.
    pub sync_iterate_count: usize,

    rs: Box<dyn ReadSync>,
}

impl StatsCollector {
    /// Construct a new instance, proxying to the given backing read syncer.
    pub fn new(rs: Box<dyn ReadSync>) -> StatsCollector {
        StatsCollector {
            sync_get_count: 0,
            sync_get_prefixes_count: 0,
            sync_iterate_count: 0,
            rs,
        }
    }
}

impl ReadSync for StatsCollector {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn sync_get(&mut self, ctx: Context, request: GetRequest) -> Result<ProofResponse> {
        self.sync_get_count += 1;
        self.rs.sync_get(ctx, request)
    }

    fn sync_get_prefixes(
        &mut self,
        ctx: Context,
        request: GetPrefixesRequest,
    ) -> Result<ProofResponse> {
        self.sync_get_prefixes_count += 1;
        self.rs.sync_get_prefixes(ctx, request)
    }

    fn sync_iterate(&mut self, ctx: Context, request: IterateRequest) -> Result<ProofResponse> {
        self.sync_iterate_count += 1;
        self.rs.sync_iterate(ctx, request)
    }
}
