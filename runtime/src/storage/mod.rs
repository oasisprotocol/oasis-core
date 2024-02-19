//! Runtime storage interfaces and implementations.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::types::Error;

pub mod mkvs;

// Re-exports.
pub use self::mkvs::MKVS;

/// Trivial key/value storage.
pub trait KeyValue: Send + Sync {
    /// Fetch the value for a specific key.
    fn get(&self, key: Vec<u8>) -> Result<Vec<u8>, Error>;

    /// Store a specific key/value into storage.
    fn insert(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Error>;
}

impl<T: ?Sized + KeyValue> KeyValue for Arc<T> {
    fn get(&self, key: Vec<u8>) -> Result<Vec<u8>, Error> {
        KeyValue::get(&**self, key)
    }

    fn insert(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Error> {
        KeyValue::insert(&**self, key, value)
    }
}

/// Untrusted key/value storage which stores arbitrary binary key/value pairs
/// in memory.
pub struct UntrustedInMemoryStorage {
    store: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}

impl UntrustedInMemoryStorage {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

impl KeyValue for UntrustedInMemoryStorage {
    fn get(&self, key: Vec<u8>) -> Result<Vec<u8>, Error> {
        // Return an empty vector if the key is not found.
        let cache = self.store.lock().unwrap();
        let value = cache.get(&key).cloned().unwrap_or_default();
        Ok(value)
    }

    fn insert(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Error> {
        let mut cache = self.store.lock().unwrap();
        cache.insert(key, value);
        Ok(())
    }
}

impl Default for UntrustedInMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}
