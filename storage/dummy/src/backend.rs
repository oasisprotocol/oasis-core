//! Storage backend interface.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use ekiden_common::{
    bytes::H256,
    error::Error,
    futures::{future, stream, BoxFuture, BoxStream, StreamExt},
};
use ekiden_storage_base::{hash_storage_key, InsertOptions, StorageBackend};

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

    fn get_batch(&self, keys: Vec<H256>) -> BoxFuture<Vec<Option<Vec<u8>>>> {
        let inner = self.inner.clone();

        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            let mut results = vec![];

            for key in keys {
                results.push(inner.storage.get(&key).cloned());
            }

            Ok(results)
        }))
    }

    fn insert(&self, value: Vec<u8>, _expiry: u64, _opts: InsertOptions) -> BoxFuture<()> {
        let inner = self.inner.clone();
        let key = hash_storage_key(&value);

        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();

            inner.storage.insert(key, value);

            Ok(())
        }))
    }

    fn insert_batch(&self, values: Vec<(Vec<u8>, u64)>, _opts: InsertOptions) -> BoxFuture<()> {
        let inner = self.inner.clone();

        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();

            for (value, _expiry) in values {
                let key = hash_storage_key(&value);
                inner.storage.insert(key, value);
            }

            Ok(())
        }))
    }

    fn get_keys(&self) -> BoxStream<(H256, u64)> {
        stream::once(Err(Error::new("Not implemented"))).into_box()
    }
}
