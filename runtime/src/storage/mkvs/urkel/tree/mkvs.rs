use failure::Fallible;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::{urkel::tree::*, WriteLog, MKVS},
};

unsafe impl Send for UrkelTree {}
unsafe impl Sync for UrkelTree {}

// TODO: We should likely change the MKVS interface to propagate errors instead of unwrapping.

impl MKVS for UrkelTree {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let _lock = self.lock.lock().unwrap();
        self.get(key).unwrap()
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
        let lock = self.lock.clone();
        let _guard = lock.lock().unwrap();
        self.insert(key, value).unwrap()
    }

    fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let lock = self.lock.clone();
        let _guard = lock.lock().unwrap();
        self.remove(key).unwrap()
    }

    fn commit(&mut self) -> Fallible<(WriteLog, Hash)> {
        let lock = self.lock.clone();
        let _guard = lock.lock().unwrap();
        UrkelTree::commit(self)
    }

    fn rollback(&mut self) {
        let lock = self.lock.clone();
        let _guard = lock.lock().unwrap();
        self.pending_write_log.clear();
    }

    fn set_encryption_key(&mut self, _key: Option<&[u8]>) {
        let _lock = self.lock.lock().unwrap();
    }
}
