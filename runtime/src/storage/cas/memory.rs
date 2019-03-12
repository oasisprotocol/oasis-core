//! An in-memory CAS implementation.
use std::{collections::HashMap, sync::RwLock};

use failure::Fallible;

use super::CAS;
use crate::common::crypto::hash::Hash;

/// A in-memory CAS implementation.
pub struct MemoryCAS {
    items: RwLock<HashMap<Hash, (Vec<u8>, u64)>>,
}

impl MemoryCAS {
    /// Create a new in-memory CAS implementation.
    pub fn new() -> Self {
        Self {
            items: RwLock::new(HashMap::new()),
        }
    }
}

impl CAS for MemoryCAS {
    fn get(&self, key: Hash) -> Fallible<Vec<u8>> {
        let items = self.items.read().unwrap();
        if let Some(value) = items.get(&key) {
            return Ok(value.0.clone());
        }

        bail!("key not found");
    }

    fn insert(&self, value: Vec<u8>, expiry: u64) -> Fallible<Hash> {
        let mut items = self.items.write().unwrap();
        let hash = Hash::digest_bytes(&value);
        items.insert(hash.clone(), (value, expiry));
        Ok(hash)
    }
}
