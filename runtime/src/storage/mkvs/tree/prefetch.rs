use anyhow::Result;

use crate::storage::mkvs::{
    cache::{Cache, ReadSyncFetcher},
    sync::{GetPrefixesRequest, Proof, ReadSync, TreeID},
    tree::{NodePtrRef, Root, Tree},
    Prefix,
};

pub(super) struct FetcherSyncGetPrefixes<'a> {
    prefixes: &'a [Prefix],
    limit: u16,
}

impl<'a> FetcherSyncGetPrefixes<'a> {
    pub(super) fn new(prefixes: &'a [Prefix], limit: u16) -> Self {
        Self { prefixes, limit }
    }
}

impl<'a> ReadSyncFetcher for FetcherSyncGetPrefixes<'a> {
    fn fetch(&self, root: Root, ptr: NodePtrRef, rs: &mut Box<dyn ReadSync>) -> Result<Proof> {
        let rsp = rs.sync_get_prefixes(GetPrefixesRequest {
            tree: TreeID {
                root,
                position: ptr.borrow().hash,
            },
            prefixes: self.prefixes.to_vec(),
            limit: self.limit,
        })?;
        Ok(rsp.proof)
    }
}

impl Tree {
    /// Populate the in-memory tree with nodes for keys starting with given prefixes.
    pub fn prefetch_prefixes(&self, prefixes: &[Prefix], limit: u16) -> Result<()> {
        let pending_root = self.cache.borrow().get_pending_root();
        self.cache
            .borrow_mut()
            .remote_sync(pending_root, FetcherSyncGetPrefixes::new(prefixes, limit))
    }
}
