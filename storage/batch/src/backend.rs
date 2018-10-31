//! Batch storage backend.
use std;
use std::collections::HashMap;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex, RwLock};

use ekiden_common::bytes::H256;
use ekiden_common::futures::prelude::*;
use ekiden_storage_base::{hash_storage_key, InsertOptions, StorageBackend};

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

    /// Return the number of items in this batch.
    pub fn get_batch_size(&self) -> usize {
        let inner_guard = self.inner.read().unwrap();
        let inner = inner_guard
            .as_ref()
            .expect("BatchStorageBackend access after commit");
        let size = inner.writeback.lock().unwrap().len();

        size
    }

    /// Commit batch to delegate backend.
    ///
    /// Batches will contain a maximum of `max_chunk_size` elements. If set to zero,
    /// all elements will be inserted in one batch.
    pub fn commit(&self, max_chunk_size: usize, opts: InsertOptions) -> BoxFuture<()> {
        let inner = self.inner
            .write()
            .unwrap()
            .take()
            .expect("BatchStorageBackend access after commit");
        let mut writeback_guard = inner.writeback.lock().unwrap();
        let values = std::mem::replace(writeback_guard.deref_mut(), HashMap::new())
            .into_iter()
            .map(|(_key, value)| value);

        if max_chunk_size == 0 {
            // Insert the whole batch at once.
            inner.delegate.insert_batch(values.collect(), opts)
        } else {
            // Insert batch in chunks.
            let delegate = inner.delegate;

            stream::iter_ok(values)
                .chunks(max_chunk_size)
                .for_each(move |chunk| delegate.insert_batch(chunk, opts.clone()))
                .into_box()
        }
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

    fn insert(&self, value: Vec<u8>, expiry: u64, _opts: InsertOptions) -> BoxFuture<()> {
        let key = hash_storage_key(&value);
        let inner_guard = self.inner.read().unwrap();
        let inner = inner_guard
            .as_ref()
            .expect("BatchStorageBackend access after commit");
        let mut writeback_guard = inner.writeback.lock().unwrap();
        writeback_guard.insert(key, (value, expiry));

        future::ok(()).into_box()
    }

    fn insert_batch(&self, _values: Vec<(Vec<u8>, u64)>, _opts: InsertOptions) -> BoxFuture<()> {
        unimplemented!();
    }

    fn get_keys(&self) -> BoxStream<(H256, u64)> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use ekiden_common;
    use ekiden_common::futures::Future;
    use ekiden_storage_base::{hash_storage_key, InsertOptions, StorageBackend};
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
            storage
                .insert(b"value".to_vec(), 10, InsertOptions::default())
                .wait()
                .unwrap();
            assert_eq!(storage.get(key).wait(), Ok(b"value".to_vec()));

            // Commit.
            batch.commit(0, InsertOptions::default()).wait().unwrap();

            // Test that key is available in delegate after committing.
            assert_eq!(delegate.get(key).wait(), Ok(b"value".to_vec()));
        }

        {
            let batch = Arc::new(BatchStorageBackend::new(delegate.clone()));

            // Insert directly to delegate and expect to find it in this interface.
            let key = hash_storage_key(b"another");
            delegate
                .insert(b"another".to_vec(), 10, InsertOptions::default())
                .wait()
                .unwrap();
            assert_eq!(batch.get(key).wait(), Ok(b"another".to_vec()));
        }
    }

    #[test]
    fn test_chunks() {
        ekiden_common::testing::try_init_logging();

        let delegate = Arc::new(DummyStorageBackend::new());
        let batch = Arc::new(BatchStorageBackend::new(delegate.clone()));
        let storage: Arc<StorageBackend> = batch.clone();

        let values = vec![
            b"No longer be! Arise! obtain renown! destroy thy foes!".to_vec(),
            b"Fight for the kingdom waiting thee when thou hast vanquished those.".to_vec(),
            b"By Me they fall- not thee! the stroke of death is dealt them now,".to_vec(),
            b"Even as they show thus gallantly; My instrument art thou!".to_vec(),
        ];

        for value in &values {
            storage
                .insert(value.clone(), 10, InsertOptions::default())
                .wait()
                .unwrap();
            let key = hash_storage_key(value);
            assert_eq!(storage.get(key).wait(), Ok(value.clone()));
        }

        // Commit.
        batch.commit(2, InsertOptions::default()).wait().unwrap();

        // Test that keys are available in delegate after committing.
        for value in &values {
            let key = hash_storage_key(value);
            assert_eq!(delegate.get(key).wait(), Ok(value.clone()));
        }
    }
}
