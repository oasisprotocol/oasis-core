//! Storage backend interface.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::H256;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, BoxFuture};
use ekiden_storage_base::{hash_storage_key, StorageBackend};

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
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        let inner = self.inner.clone();

        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();

            match inner.storage.get(&key) {
                Some(value) => Ok(value.clone()),
                None => Err(Error::new("key not found")),
            }
        }))
    }

    fn insert(&self, value: Vec<u8>, _expiry: u64) -> BoxFuture<()> {
        let inner = self.inner.clone();
        let key = hash_storage_key(&value);

        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();

            inner.storage.insert(key, value);

            Ok(())
        }))
    }

    fn get_keys(&self) -> BoxFuture<Arc<Vec<(H256, u64)>>> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            let mut keys = Vec::new();
            for key in inner.storage.keys() {
                keys.push((key.clone(), 0))
            }
            Ok(Arc::new(keys))
        }))
    }
}

// Register for dependency injection.
create_component!(
    dummy,
    "storage-backend",
    DummyStorageBackend,
    StorageBackend,
    []
);
