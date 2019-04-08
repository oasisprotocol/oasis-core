//! A pass-through CAS implementation.
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use failure::Fallible;
use serde_bytes::ByteBuf;

use super::CAS;
use crate::common::crypto::hash::Hash;

/// A CAS implementation which forwards all get requests to the
/// provided backend, stores all inserts in-memory and allows them
/// to be retrieved later.
pub struct PassthroughCAS {
    backend: Arc<CAS>,
    inserts: RwLock<HashMap<Hash, (ByteBuf, u64)>>,
}

impl PassthroughCAS {
    /// Create a new pass-through CAS implementation.
    pub fn new(backend: Arc<CAS>) -> Self {
        Self {
            backend,
            inserts: RwLock::new(HashMap::new()),
        }
    }

    /// Take all recorded insert operations and return them.
    pub fn take_inserts(&self) -> Vec<(ByteBuf, u64)> {
        let mut inserts = self.inserts.write().unwrap();
        inserts
            .drain()
            .map(|(_, value)| (value.0.into(), value.1))
            .collect()
    }
}

impl CAS for PassthroughCAS {
    fn get(&self, key: Hash) -> Fallible<Vec<u8>> {
        {
            let inserts = self.inserts.read().unwrap();
            if let Some(value) = inserts.get(&key) {
                return Ok(value.0.clone().into());
            }
        }

        self.backend.get(key)
    }

    fn insert(&self, value: Vec<u8>, expiry: u64) -> Fallible<Hash> {
        let mut inserts = self.inserts.write().unwrap();
        let hash = Hash::digest_bytes(&value);
        inserts.insert(hash.clone(), (value.into(), expiry));
        Ok(hash)
    }
}
