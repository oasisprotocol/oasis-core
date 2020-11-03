use anyhow::Result;
use io_context::Context;

use crate::{
    common::{crypto::hash::Hash, roothash::Namespace},
    storage::mkvs::{tree::*, Iterator, Prefix, WriteLog, MKVS},
};

// TODO: We should likely change the MKVS interface to propagate errors instead of unwrapping.

impl MKVS for Tree {
    fn get(&self, ctx: Context, key: &[u8]) -> Option<Vec<u8>> {
        self.get(ctx, key).unwrap()
    }

    fn cache_contains_key(&self, ctx: Context, key: &[u8]) -> bool {
        self.cache_contains_key(ctx, key)
    }

    fn insert(&mut self, ctx: Context, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
        self.insert(ctx, key, value).unwrap()
    }

    fn remove(&mut self, ctx: Context, key: &[u8]) -> Option<Vec<u8>> {
        self.remove(ctx, key).unwrap()
    }

    fn prefetch_prefixes(&self, ctx: Context, prefixes: &Vec<Prefix>, limit: u16) {
        self.prefetch_prefixes(ctx, prefixes, limit).unwrap()
    }

    fn iter(&self, ctx: Context) -> Box<dyn Iterator + '_> {
        Box::new(self.iter(ctx))
    }

    fn commit(
        &mut self,
        ctx: Context,
        namespace: Namespace,
        version: u64,
    ) -> Result<(WriteLog, Hash)> {
        Tree::commit(self, ctx, namespace, version)
    }

    fn rollback(&mut self) {
        self.pending_write_log.clear();
    }
}
