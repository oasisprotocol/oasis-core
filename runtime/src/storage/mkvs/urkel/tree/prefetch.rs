use failure::Fallible;
use io_context::Context;

use crate::storage::mkvs::urkel::{cache::*, sync::*, tree::*};

pub(super) struct FetcherSyncGetPrefixes<'a> {
    prefixes: &'a Vec<Prefix>,
    limit: u16,
}

impl<'a> FetcherSyncGetPrefixes<'a> {
    pub(super) fn new(prefixes: &'a Vec<Prefix>, limit: u16) -> Self {
        Self { prefixes, limit }
    }
}

impl<'a> ReadSyncFetcher for FetcherSyncGetPrefixes<'a> {
    fn fetch(
        &self,
        ctx: Context,
        root: Root,
        ptr: NodePtrRef,
        rs: &mut Box<dyn ReadSync>,
    ) -> Fallible<Proof> {
        let rsp = rs.sync_get_prefixes(
            ctx,
            GetPrefixesRequest {
                tree: TreeID {
                    root,
                    position: ptr.borrow().hash,
                },
                prefixes: self.prefixes.clone(),
                limit: self.limit,
            },
        )?;
        Ok(rsp.proof)
    }
}

impl UrkelTree {
    /// Populate the in-memory tree with nodes for keys starting with given prefixes.
    pub fn prefetch_prefixes(
        &self,
        ctx: Context,
        prefixes: &Vec<Prefix>,
        limit: u16,
    ) -> Fallible<()> {
        let ctx = ctx.freeze();
        let pending_root = self.cache.borrow().get_pending_root();
        self.cache.borrow_mut().remote_sync(
            &ctx,
            pending_root,
            FetcherSyncGetPrefixes::new(prefixes, limit),
        )
    }
}
