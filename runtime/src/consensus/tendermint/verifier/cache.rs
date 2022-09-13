use tendermint::block::Height;
use tendermint_light_client::types::LightBlock as TMLightBlock;

use crate::common::crypto::{hash::Hash, signature::PublicKey};

pub struct Cache {
    pub last_verified_height: u64,
    pub last_verified_round: u64,
    pub last_verified_epoch: u64,
    pub last_verified_block: TMLightBlock,
    pub verified_state_roots: lru::LruCache<u64, Hash>,
    pub verified_state_roots_queries: lru::LruCache<u64, (Hash, u64)>,
    pub node_id: Option<PublicKey>,
}

impl Cache {
    pub fn new(verified_block: TMLightBlock) -> Self {
        Self {
            last_verified_height: 0,
            last_verified_round: 0,
            last_verified_epoch: 0,
            last_verified_block: verified_block,
            verified_state_roots: lru::LruCache::new(128),
            verified_state_roots_queries: lru::LruCache::new(128),
            node_id: None,
        }
    }
}

impl Cache {
    /// Latest known and verified consensus layer height.
    pub fn latest_known_height(&self) -> u64 {
        self.last_verified_block.signed_header.header.height.value()
    }

    /// Process a new verified consensus layer block and update the cache if needed.
    pub fn update_verified_block(&mut self, verified_block: TMLightBlock) {
        let h = |b: &TMLightBlock| -> Height { b.signed_header.header.height };
        if h(&verified_block) > h(&self.last_verified_block) {
            self.last_verified_block = verified_block
        }
    }
}
