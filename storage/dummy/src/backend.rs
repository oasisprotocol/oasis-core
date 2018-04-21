//! Storage backend interface.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::H256;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, BoxFuture};
use ekiden_common::ring::digest;
use ekiden_storage_base::StorageBackend;

struct DummyStorageBackendInner {
    /// In-memory storage.
    storage: HashMap<H256, Vec<u8>>,
}

/// Dummy in-memory storage backend.
pub struct DummyStorageBackend {
    inner: Arc<Mutex<DummyStorageBackendInner>>,
}

impl DummyStorageBackend {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(DummyStorageBackendInner {
                storage: HashMap::new(),
            })),
        }
    }
}

impl StorageBackend for DummyStorageBackend {
    fn get(&self, key: &[u8]) -> BoxFuture<Vec<u8>> {
        let inner = self.inner.clone();
        let key = H256::from(key);

        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();

            match inner.storage.get(&key) {
                Some(value) => Ok(value.clone()),
                None => Err(Error::new("key not found")),
            }
        }))
    }

    fn insert(&self, value: &[u8]) -> BoxFuture<()> {
        let inner = self.inner.clone();
        let key = H256::from(digest::digest(&digest::SHA512_256, &value).as_ref());
        let value_owned = value.to_owned();

        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();

            inner.storage.insert(key, value_owned);

            Ok(())
        }))
    }
}
