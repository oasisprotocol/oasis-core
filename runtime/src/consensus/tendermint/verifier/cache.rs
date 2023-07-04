use std::num::NonZeroUsize;

use tendermint::block::Height;
use tendermint_light_client::types::LightBlock as TMLightBlock;

use crate::common::crypto::{hash::Hash, signature::PublicKey};

/// Verifier cache.
pub struct Cache {
    pub last_verified_height: u64,
    pub last_verified_round: u64,
    pub last_verified_epoch: u64,
    pub last_verified_block: Option<TMLightBlock>,
    pub verified_state_roots: lru::LruCache<u64, (Hash, u64)>,
    pub host_node_id: PublicKey,
}

impl Cache {
    /// Latest known and verified consensus layer height.
    pub fn latest_known_height(&self) -> Option<u64> {
        self.last_verified_block
            .as_ref()
            .map(|b| b.signed_header.header.height.value())
    }

    /// Process a new verified consensus layer block and update the cache if needed.
    pub fn update_verified_block(&mut self, verified_block: &TMLightBlock) {
        let h = |b: &TMLightBlock| -> Height { b.signed_header.header.height };
        if let Some(last_verified_block) = self.last_verified_block.as_ref() {
            if h(verified_block) <= h(last_verified_block) {
                return;
            }
        }
        self.last_verified_block = Some(verified_block.clone())
    }
}

impl Cache {
    /// Construct a new verifier cache.
    pub fn new(host_node_id: PublicKey) -> Self {
        Self {
            last_verified_height: 0,
            last_verified_round: 0,
            last_verified_epoch: 0,
            last_verified_block: None,
            verified_state_roots: lru::LruCache::new(NonZeroUsize::new(128).unwrap()),
            host_node_id,
        }
    }
}
