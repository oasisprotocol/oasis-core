use failure::Fallible;
use io_context::Context;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::{urkel::tree::*, WriteLog, MKVS},
};

unsafe impl Send for UrkelTree {}
unsafe impl Sync for UrkelTree {}

// TODO: We should likely change the MKVS interface to propagate errors instead of unwrapping.

impl MKVS for UrkelTree {
    fn get(&self, ctx: Context, key: &[u8]) -> Option<Vec<u8>> {
        let _lock = self.lock.lock().unwrap();
        self.get(ctx, key).unwrap()
    }

    fn insert(&mut self, ctx: Context, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
        let lock = self.lock.clone();
        let _guard = lock.lock().unwrap();
        self.insert(ctx, key, value).unwrap()
    }

    fn remove(&mut self, ctx: Context, key: &[u8]) -> Option<Vec<u8>> {
        let lock = self.lock.clone();
        let _guard = lock.lock().unwrap();
        self.remove(ctx, key).unwrap()
    }

    fn commit(&mut self, ctx: Context) -> Fallible<(WriteLog, Hash)> {
        let lock = self.lock.clone();
        let _guard = lock.lock().unwrap();
        UrkelTree::commit(self, ctx)
    }

    fn rollback(&mut self) {
        let lock = self.lock.clone();
        let _guard = lock.lock().unwrap();
        self.pending_write_log.clear();
    }

    fn set_encryption_key(&mut self, _key: Option<&[u8]>, _nonce: Option<&[u8]>) {
        let _lock = self.lock.lock().unwrap();
        // XXX: This should probably panic or something?
    }
}
