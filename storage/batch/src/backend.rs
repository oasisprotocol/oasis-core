//! Batch storage backend.
use std;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::H256;
use ekiden_common::futures::{self, stream, BoxFuture, Future, FutureExt, Stream};
use ekiden_storage_base::{hash_storage_key, StorageBackend};
use ekiden_storage_dummy::DummyStorageBackend;

struct Inner {
    /// Always-available backend to store uncommitted data.
    always_available: Arc<StorageBackend>,
    /// Storage backend for committed data.
    committed: Arc<StorageBackend>,
    /// Items inserted during the last transaction.
    inserts: Mutex<Vec<(H256, u64)>>,
    /// Maximum number of retries.
    retries: usize,
}

/// Virtual storage backend which processes a batch of inserts.
///
/// This storage backend uses two actual storage backends:
/// * The first is an always-available backend which is used to queue all inserts until
///   a `commit` is issued. Currently, this uses an in-memory storage backend.
/// * The second is backend is the actual backend where data should be committed to
///   after the batch has been processed and a `commit` issued.
///
/// All gets first hit the always-available backend and in case of missing keys, they
/// hit the committed backend.
pub struct BatchStorageBackend {
    inner: Arc<Inner>,
}

impl BatchStorageBackend {
    pub fn new(committed: Arc<StorageBackend>, retries: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                // TODO: Should we use persistent storage instead of holding a batch in memory?
                always_available: Arc::new(DummyStorageBackend::new()),
                committed,
                inserts: Mutex::new(vec![]),
                retries,
            }),
        }
    }

    /// Commit all inserts to the committed backend.
    pub fn commit(&self) -> BoxFuture<()> {
        // Get insert log.
        let inserts = {
            let mut inserts = self.inner.inserts.lock().unwrap();
            std::mem::replace(&mut *inserts, vec![])
        };

        // Iterate over log and insert all values, with retry.
        let retries = self.inner.retries;
        let always_available = self.inner.always_available.clone();
        let committed = self.inner.committed.clone();

        stream::iter_ok(inserts.into_iter())
            .for_each(move |(key, expiry)| {
                let committed = committed.clone();

                always_available.get(key).and_then(move |value| {
                    futures::retry(retries, move || committed.insert(value.clone(), expiry))
                        .or_else(|error| {
                            warn!("Failed to commit to storage: {:?}", error);

                            Err(error)
                        })
                })
            })
            .into_box()
    }
}

impl StorageBackend for BatchStorageBackend {
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        let committed = self.inner.committed.clone();
        let retries = self.inner.retries;

        self.inner
            .always_available
            .get(key)
            .or_else(move |_error| futures::retry(retries, move || committed.get(key)))
            .into_box()
    }

    fn insert(&self, value: Vec<u8>, expiry: u64) -> BoxFuture<()> {
        let inner = self.inner.clone();
        let key = hash_storage_key(&value);

        self.inner
            .always_available
            .insert(value, expiry)
            .and_then(move |_| {
                let mut inserts = inner.inserts.lock().unwrap();
                inserts.push((key, expiry));
                Ok(())
            })
            .into_box()
    }

    fn get_key_list(&self) -> Vec<(H256, u64)> {
        let inner = self.inner.clone();
        let inserts = inner.inserts.lock().unwrap();
        println!("Get Key List is: {:?}", *inserts);
        let key_list = inserts.to_owned();
        return key_list;
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn test_batch() {
        let committed = Arc::new(DummyStorageBackend::new());
        let batch = BatchStorageBackend::new(committed.clone(), 1);

        let key = hash_storage_key(b"value");
        let key2 = hash_storage_key(b"value2");

        assert!(batch.get(key).wait().is_err());
        batch.insert(b"value".to_vec(), 10).wait().unwrap();
        batch.insert(b"value2".to_vec(), 5).wait().unwrap();
        assert_eq!(batch.get(key).wait(), Ok(b"value".to_vec()));
        assert_eq!(batch.get(key2).wait(), Ok(b"value2".to_vec()));
        // Get key list.
        batch.get_key_list();
        // Test that key has not been inserted into committed backend.
        assert!(committed.get(key).wait().is_err());
        // Commit.
        batch.commit().wait().unwrap();
        assert_eq!(committed.get(key).wait(), Ok(b"value".to_vec()));

        // Insert directly to committed and expect the backend to find it.
        let key = hash_storage_key(b"another");
        committed.insert(b"another".to_vec(), 10).wait().unwrap();
        assert_eq!(batch.get(key).wait(), Ok(b"another".to_vec()));
    }
}
