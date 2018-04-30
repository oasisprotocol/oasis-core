//! Storage backend interface.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::H256;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, BoxFuture};
use ekiden_common::hash::EncodedHash;
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

    /// Hash namespace and key.
    fn get_namespaced_key(namespace: &[u8], key: &[u8]) -> H256 {
        vec![namespace, key].get_encoded_hash()
    }
}

impl StorageBackend for DummyStorageBackend {
    fn get(&self, namespace: &[u8], key: &[u8]) -> BoxFuture<Vec<u8>> {
        let inner = self.inner.clone();
        let raw_key = Self::get_namespaced_key(namespace, key);

        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();

            match inner.storage.get(&raw_key) {
                Some(value) => Ok(value.clone()),
                None => Err(Error::new("key not found")),
            }
        }))
    }

    fn insert(&self, namespace: &[u8], key: &[u8], value: &[u8]) -> BoxFuture<()> {
        let inner = self.inner.clone();
        let raw_key = Self::get_namespaced_key(namespace, key);
        let value_owned = value.to_owned();

        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();

            inner.storage.insert(raw_key, value_owned);

            Ok(())
        }))
    }

    fn remove(&self, namespace: &[u8], key: &[u8]) -> BoxFuture<()> {
        let inner = self.inner.clone();
        let raw_key = Self::get_namespaced_key(namespace, key);

        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();

            match inner.storage.remove(&raw_key) {
                Some(_) => Ok(()),
                None => Err(Error::new("key not found")),
            }
        }))
    }
}
