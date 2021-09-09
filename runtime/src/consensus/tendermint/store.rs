//! An in-memory LRU store for the light client.
use std::sync::{Mutex, MutexGuard};

use tendermint_light_client::{
    store::LightStore,
    types::{Height, LightBlock, Status},
};

/// In-memory LRU store.
pub struct LruStore {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for LruStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "LruStore")
    }
}

struct Inner {
    unverified: lru::LruCache<Height, LightBlock>,
    verified: lru::LruCache<Height, LightBlock>,
    trusted: lru::LruCache<Height, LightBlock>,
    failed: lru::LruCache<Height, LightBlock>,
}

impl Inner {
    fn store(&mut self, status: Status) -> &mut lru::LruCache<Height, LightBlock> {
        match status {
            Status::Unverified => &mut self.unverified,
            Status::Verified => &mut self.verified,
            Status::Trusted => &mut self.trusted,
            Status::Failed => &mut self.failed,
        }
    }
}

impl LruStore {
    /// Create a new, empty, in-memory LRU store of the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                unverified: lru::LruCache::new(capacity),
                verified: lru::LruCache::new(capacity),
                trusted: lru::LruCache::new(capacity),
                failed: lru::LruCache::new(capacity),
            }),
        }
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap()
    }

    fn inner_mut(&mut self) -> &mut Inner {
        self.inner.get_mut().unwrap()
    }
}

impl LightStore for LruStore {
    fn get(&self, height: Height, status: Status) -> Option<LightBlock> {
        self.inner().store(status).get(&height).cloned()
    }

    fn insert(&mut self, light_block: LightBlock, status: Status) {
        self.inner_mut()
            .store(status)
            .put(light_block.height(), light_block);
    }

    fn remove(&mut self, height: Height, status: Status) {
        self.inner_mut().store(status).pop(&height);
    }

    fn update(&mut self, light_block: &LightBlock, status: Status) {
        self.inner_mut()
            .store(status)
            .put(light_block.height(), light_block.clone());
    }

    fn highest(&self, status: Status) -> Option<LightBlock> {
        self.inner()
            .store(status)
            .iter()
            .max_by_key(|(&height, _)| height)
            .map(|(_, lb)| lb.clone())
    }

    fn lowest(&self, status: Status) -> Option<LightBlock> {
        self.inner()
            .store(status)
            .iter()
            .min_by_key(|(&height, _)| height)
            .map(|(_, lb)| lb.clone())
    }

    #[allow(clippy::needless_collect)]
    fn all(&self, status: Status) -> Box<dyn Iterator<Item = LightBlock>> {
        let light_blocks: Vec<_> = self
            .inner()
            .store(status)
            .iter()
            .map(|(_, lb)| lb.clone())
            .collect();

        Box::new(light_blocks.into_iter())
    }
}
