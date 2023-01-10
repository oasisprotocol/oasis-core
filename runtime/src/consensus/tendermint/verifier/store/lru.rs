//! An in-memory LRU store for the light client.
use std::{
    num::NonZeroUsize,
    sync::{Mutex, MutexGuard},
};

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

struct SubStore {
    lowest_height: Option<Height>,
    blocks: lru::LruCache<Height, LightBlock>,
}

impl SubStore {
    fn new(capacity: usize) -> Self {
        Self {
            lowest_height: None,
            blocks: lru::LruCache::new(NonZeroUsize::new(capacity).unwrap()),
        }
    }
}

struct Inner {
    unverified: SubStore,
    verified: SubStore,
    trusted: SubStore,
    failed: SubStore,
}

impl Inner {
    fn store(&mut self, status: Status) -> &mut SubStore {
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
                unverified: SubStore::new(capacity),
                verified: SubStore::new(capacity),
                trusted: SubStore::new(capacity),
                failed: SubStore::new(capacity),
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
        self.inner().store(status).blocks.get(&height).cloned()
    }

    fn insert(&mut self, light_block: LightBlock, status: Status) {
        let mut store = self.inner_mut().store(status);

        // Promote lowest to prevent it from being evicted.
        let height = light_block.height();
        if let Some(lowest_height) = store.lowest_height {
            if height < lowest_height {
                store.lowest_height = Some(height);
            } else {
                store.blocks.promote(&lowest_height);
            }
        } else {
            store.lowest_height = Some(height);
        }

        store.blocks.put(height, light_block);
    }

    fn remove(&mut self, height: Height, status: Status) {
        let mut store = self.inner_mut().store(status);

        store.blocks.pop(&height);

        // Check if this is the lowest height being explicitly removed.
        if store.lowest_height.map(|lh| height == lh).unwrap_or(false) {
            store.lowest_height = store.blocks.iter().map(|(height, _)| *height).min();
        }
    }

    fn update(&mut self, light_block: &LightBlock, status: Status) {
        self.insert(light_block.clone(), status)
    }

    fn highest(&self, status: Status) -> Option<LightBlock> {
        self.inner()
            .store(status)
            .blocks
            .iter()
            .max_by_key(|(&height, _)| height)
            .map(|(_, lb)| lb.clone())
    }

    fn highest_before(&self, height: Height, status: Status) -> Option<LightBlock> {
        self.inner()
            .store(status)
            .blocks
            .iter()
            .filter(|(h, _)| h <= &&height)
            .max_by_key(|(&height, _)| height)
            .map(|(_, lb)| lb.clone())
    }

    fn lowest(&self, status: Status) -> Option<LightBlock> {
        let mut inner = self.inner();
        let store = inner.store(status);

        store
            .lowest_height
            .and_then(|lowest_height| store.blocks.get(&lowest_height).cloned())
    }

    #[allow(clippy::needless_collect)]
    fn all(&self, status: Status) -> Box<dyn Iterator<Item = LightBlock>> {
        let light_blocks: Vec<_> = self
            .inner()
            .store(status)
            .blocks
            .iter()
            .map(|(_, lb)| lb.clone())
            .collect();

        Box::new(light_blocks.into_iter())
    }
}

#[cfg(test)]
mod test {
    use tendermint_light_client::{
        store::LightStore,
        types::{LightBlock, Status},
    };
    use tendermint_testgen::{Generator, LightChain};

    use super::LruStore;

    fn generate_blocks(count: u64) -> Vec<LightBlock> {
        LightChain::default_with_length(count)
            .light_blocks
            .into_iter()
            .map(|lb| lb.generate().unwrap())
            .map(|lb| LightBlock {
                signed_header: lb.signed_header,
                validators: lb.validators,
                next_validators: lb.next_validators,
                provider: lb.provider,
            })
            .collect()
    }

    #[test]
    fn test_lowest_height_retained() {
        let blocks = generate_blocks(10);
        let mut store = LruStore::new(2); // Only storing two blocks.
        store.insert(blocks[0].clone(), Status::Trusted);
        store.insert(blocks[1].clone(), Status::Trusted);
        store.insert(blocks[2].clone(), Status::Trusted);
        store.insert(blocks[3].clone(), Status::Trusted);

        let lowest = store
            .lowest(Status::Trusted)
            .expect("there should be a lowest block");
        assert_eq!(lowest, blocks[0]);
    }

    #[test]
    fn test_basic() {
        let blocks = generate_blocks(10);
        let mut store = LruStore::new(10);
        for block in &blocks {
            store.insert(block.clone(), Status::Trusted);

            // Block should be stored.
            let stored_block = store.get(block.height(), Status::Trusted);
            assert_eq!(stored_block.as_ref(), Some(block));

            // Highest and lowest blocks should be correct.
            let highest = store
                .highest(Status::Trusted)
                .expect("there should be a highest block");
            let lowest = store
                .lowest(Status::Trusted)
                .expect("there should be a lowest block");
            assert_eq!(&highest, block);
            assert_eq!(lowest, blocks[0]);

            // Highest before should work.
            let highest_before = store.highest_before(block.height(), Status::Trusted);
            assert_eq!(highest_before.as_ref(), Some(block));

            let highest_before = store.highest_before(block.height().increment(), Status::Trusted);
            assert_eq!(highest_before.as_ref(), Some(block));
        }

        // Test removal of lowest block.
        store.remove(blocks[0].height(), Status::Trusted);

        let block_zero = store.get(blocks[0].height(), Status::Trusted);
        assert!(block_zero.is_none());

        let lowest = store
            .lowest(Status::Trusted)
            .expect("there should be a lowest block");
        assert_eq!(lowest, blocks[1]);
    }
}
