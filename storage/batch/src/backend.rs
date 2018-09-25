//! Batch storage backend.
use std;
use std::collections::HashMap;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex, RwLock};

use ekiden_common::bytes::H256;
use ekiden_common::futures::prelude::*;
use ekiden_storage_base::{hash_storage_key, StorageBackend};

struct Inner {
    /// This map lets us answer consistently when we insert an item and try to get it before it is
    /// persisted.
    writeback: Arc<Mutex<HashMap<H256, (Vec<u8>, u64)>>>,
    /// Forward requests to this.
    delegate: Arc<StorageBackend>,
}

/// This storage backend forwards calls to a delegate and makes inserts return successfully
/// immediately and performs them as an atomic batch when `commit` is called.
pub struct BatchStorageBackend {
    /// We cut this off when we commit, simulating the disposal of this object. We can't actually
    /// consume this backend because many consumers have an Arc of the backend instead of owning
    /// it.
    inner: RwLock<Option<Inner>>,
}

impl BatchStorageBackend {
    pub fn new(delegate: Arc<StorageBackend>) -> Self {
        BatchStorageBackend {
            inner: RwLock::new(Some(Inner {
                writeback: Arc::new(Mutex::new(HashMap::new())),
                delegate,
            })),
        }
    }

    /// Commit batch to delegate backend.
    pub fn commit(&self) -> BoxFuture<()> {
        let inner = self.inner
            .write()
            .unwrap()
            .take()
            .expect("BatchStorageBackend access after commit");
        let mut writeback_guard = inner.writeback.lock().unwrap();
        let values = std::mem::replace(writeback_guard.deref_mut(), HashMap::new())
            .into_iter()
            .map(|(_key, value)| value)
            .collect();

        inner.delegate.insert_batch(values)
    }
}

impl StorageBackend for BatchStorageBackend {
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        let inner_guard = self.inner.read().unwrap();
        let inner = inner_guard
            .as_ref()
            .expect("BatchStorageBackend access after commit");
        if let Some(value) = inner.writeback.lock().unwrap().get(&key) {
            return future::ok(value.0.clone()).into_box();
        }
        inner.delegate.get(key)
    }

    fn get_batch(&self, _keys: Vec<H256>) -> BoxFuture<Vec<Option<Vec<u8>>>> {
        unimplemented!();
    }

    fn insert(&self, value: Vec<u8>, expiry: u64) -> BoxFuture<()> {
        let key = hash_storage_key(&value);
        let inner_guard = self.inner.read().unwrap();
        let inner = inner_guard
            .as_ref()
            .expect("BatchStorageBackend access after commit");
        let mut writeback_guard = inner.writeback.lock().unwrap();
        writeback_guard.insert(key, (value, expiry));

        future::ok(()).into_box()
    }

    fn insert_batch(&self, _values: Vec<(Vec<u8>, u64)>) -> BoxFuture<()> {
        unimplemented!();
    }

    fn get_keys(&self) -> BoxFuture<Arc<Vec<(H256, u64)>>> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use ekiden_common;
    use ekiden_common::futures::Future;
    use ekiden_storage_base::{hash_storage_key, StorageBackend};
    use ekiden_storage_dummy::DummyStorageBackend;
    extern crate grpcio;

    use BatchStorageBackend;

    #[test]
    fn test_batch() {
        ekiden_common::testing::try_init_logging();

        let delegate = Arc::new(DummyStorageBackend::new());

        {
            let batch = Arc::new(BatchStorageBackend::new(delegate.clone()));
            let storage: Arc<StorageBackend> = batch.clone();

            let key = hash_storage_key(b"value");
            assert!(storage.get(key).wait().is_err());

            // Test that key is available immediately from same interface.
            storage.insert(b"value".to_vec(), 10).wait().unwrap();
            assert_eq!(storage.get(key).wait(), Ok(b"value".to_vec()));

            // Commit.
            batch.commit().wait().unwrap();

            // Test that key is available in delegate after committing.
            assert_eq!(delegate.get(key).wait(), Ok(b"value".to_vec()));
        }

        {
            let batch = Arc::new(BatchStorageBackend::new(delegate.clone()));

            // Insert directly to delegate and expect to find it in this interface.
            let key = hash_storage_key(b"another");
            delegate.insert(b"another".to_vec(), 10).wait().unwrap();
            assert_eq!(batch.get(key).wait(), Ok(b"another".to_vec()));
        }
    }
}
