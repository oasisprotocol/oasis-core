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

#[derive(Clone, Debug, PartialEq)]
struct StoreEntry {
    light_block: LightBlock,
    status: Status,
}

impl StoreEntry {
    fn new(light_block: LightBlock, status: Status) -> Self {
        Self {
            light_block,
            status,
        }
    }
}

struct Inner {
    trust_root_height: Height,
    blocks: lru::LruCache<Height, StoreEntry>,
}

impl LruStore {
    /// Create a new, empty, in-memory LRU store of the given capacity and trust root height.
    pub fn new(capacity: usize, trust_root_height: Height) -> Self {
        Self {
            inner: Mutex::new(Inner {
                trust_root_height,
                blocks: lru::LruCache::new(NonZeroUsize::new(capacity).unwrap()),
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
        self.inner()
            .blocks
            .get(&height)
            .filter(|e| e.status == status)
            .map(|e| e.light_block.clone())
    }

    fn insert(&mut self, light_block: LightBlock, status: Status) {
        let store = self.inner_mut();

        // Promote trust root to prevent it from being evicted.
        store.blocks.promote(&store.trust_root_height);

        store
            .blocks
            .put(light_block.height(), StoreEntry::new(light_block, status));
    }

    fn remove(&mut self, height: Height, status: Status) {
        let store = self.inner_mut();

        // Prevent removal of trust root.
        if height == store.trust_root_height {
            return;
        }

        if store
            .blocks
            .get(&height)
            .map(|e| e.status != status)
            .unwrap_or(true)
        {
            return;
        }
        store.blocks.pop(&height);
    }

    fn update(&mut self, light_block: &LightBlock, status: Status) {
        self.insert(light_block.clone(), status)
    }

    fn highest(&self, status: Status) -> Option<LightBlock> {
        self.inner()
            .blocks
            .iter()
            .filter(|(_, e)| e.status == status)
            .max_by_key(|(&height, _)| height)
            .map(|(_, e)| e.light_block.clone())
    }

    fn lowest(&self, status: Status) -> Option<LightBlock> {
        self.inner()
            .blocks
            .iter()
            .filter(|(_, e)| e.status == status)
            .min_by_key(|(&height, _)| height)
            .map(|(_, e)| e.light_block.clone())
    }

    #[allow(clippy::needless_collect)]
    fn all(&self, status: Status) -> Box<dyn Iterator<Item = LightBlock>> {
        let light_blocks: Vec<_> = self
            .inner()
            .blocks
            .iter()
            .filter(|(_, e)| e.status == status)
            .map(|(_, e)| e.light_block.clone())
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
    fn test_trust_root_height_retained() {
        let blocks = generate_blocks(10);
        let mut store = LruStore::new(2, blocks[0].height()); // Only storing two blocks.
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
        let mut store = LruStore::new(10, blocks[0].height());
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
        }

        // Test removal of trust root block.
        store.remove(blocks[0].height(), Status::Trusted);

        let block_zero = store.get(blocks[0].height(), Status::Trusted);
        assert_eq!(block_zero.as_ref(), Some(&blocks[0]));

        let lowest = store
            .lowest(Status::Trusted)
            .expect("there should be a lowest block");
        assert_eq!(lowest, blocks[0]);
    }
}
