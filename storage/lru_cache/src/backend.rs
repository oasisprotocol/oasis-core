//! Storage backend interface.
use std::sync::{Arc, Mutex};

use lru_cache::LruCache;

use ekiden_common::bytes::H256;
use ekiden_common::futures::{future, BoxFuture, BoxStream, Future, FutureExt};
use ekiden_storage_base::{hash_storage_key, InsertOptions, StorageBackend};

struct Inner {
    /// Backend.
    backend: Arc<StorageBackend>,
    /// In-memory cache.
    cache: Mutex<LruCache<H256, Vec<u8>>>,
}

/// LRU in-memory cache storage backend.
pub struct LruCacheStorageBackend {
    inner: Arc<Inner>,
}

impl LruCacheStorageBackend {
    pub fn new(backend: Arc<StorageBackend>, cache_size: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                backend,
                cache: Mutex::new(LruCache::new(cache_size)),
            }),
        }
    }
}

impl StorageBackend for LruCacheStorageBackend {
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        let inner = self.inner.clone();

        future::lazy(move || {
            let mut cache = inner.cache.lock().unwrap();

            // Check if key is in cache.
            if cache.contains_key(&key) {
                // Return cached value.
                future::ok(cache.get_mut(&key).unwrap().clone()).into_box()
            } else {
                // Fetch key via backend and insert it into cache.
                let inner = inner.clone();

                inner
                    .backend
                    .get(key.clone())
                    .and_then(move |value| {
                        let mut cache = inner.cache.lock().unwrap();
                        cache.insert(key, value.clone());

                        Ok(value)
                    })
                    .into_box()
            }
        }).into_box()
    }

    fn get_batch(&self, _keys: Vec<H256>) -> BoxFuture<Vec<Option<Vec<u8>>>> {
        unimplemented!();
    }

    fn insert(&self, value: Vec<u8>, expiry: u64, opts: InsertOptions) -> BoxFuture<()> {
        let inner = self.inner.clone();
        let key = hash_storage_key(&value);

        // Insert into backend and if that succeeds, inseroptst into cache.
        inner
            .backend
            .insert(value.clone(), expiry, opts)
            .and_then(move |_| {
                let mut cache = inner.cache.lock().unwrap();
                cache.insert(key, value);

                Ok(())
            })
            .into_box()
    }

    fn insert_batch(&self, _values: Vec<(Vec<u8>, u64)>, _opts: InsertOptions) -> BoxFuture<()> {
        unimplemented!();
    }

    fn get_keys(&self) -> BoxStream<(H256, u64)> {
        self.inner.backend.get_keys()
    }
}

#[cfg(test)]
mod test {
    extern crate ekiden_storage_dummy;

    use std::sync::Arc;

    use self::ekiden_storage_dummy::DummyStorageBackend;

    use super::*;

    #[test]
    fn test_lru_cache() {
        let backend = Arc::new(DummyStorageBackend::new());
        let cache = LruCacheStorageBackend::new(backend.clone(), 10);

        // Test insert/get operations over the cache.
        let key = hash_storage_key(b"value");

        assert!(cache.get(key).wait().is_err());
        cache
            .insert(b"value".to_vec(), 10, InsertOptions::default())
            .wait()
            .unwrap();
        assert_eq!(cache.get(key).wait(), Ok(b"value".to_vec()));
        // Test that key has been inserted into underlying backend.
        assert_eq!(backend.get(key).wait(), Ok(b"value".to_vec()));

        // Insert directly to backend and expect the cache to find it.
        let key = hash_storage_key(b"another");
        backend
            .insert(b"another".to_vec(), 10, InsertOptions::default())
            .wait()
            .unwrap();
        assert_eq!(cache.get(key).wait(), Ok(b"another".to_vec()));
    }
}
